"""
OSINT Feed Collectors & Background Stream Worker
================================================
Ingests live indicators from public OSINT feeds (Feodo Tracker, ThreatFox,
URLhaus, CINS Score) as well as user-configured custom feeds, and streams
real-time attack events to connected WebSocket clients.
"""

import asyncio
import json
import random
import time
from typing import Dict, List
import httpx

from config import COMMON_PORTS, CUSTOM_USER_AGENT, IPV4_REGEX, OSINT_USER_AGENT, logger
from database import get_user_custom_locations, get_user_custom_sources
from services.geolocation import fetch_dynamic_target_pool, geolocate_raw_pool
from services.taxonomy import build_attack_event
from ws_manager import manager


async def fetch_custom_user_pool(user_id: int, enabled_custom_sources: List[Dict]) -> List[Dict]:
    """
    Fetches and geolocates IPs from the user's enabled non-default custom_sources.
    Supports both remote feed URLs (plain text, JSON, CSV) and direct IPv4 entries.
    """
    if not enabled_custom_sources:
        return []

    sources_hash = json.dumps(enabled_custom_sources, sort_keys=True)
    cached = manager.user_custom_pools.get(user_id)
    now = time.time()
    if cached and cached["hash"] == sources_hash and (now - cached["ts"] < 300):
        return cached["pool"]

    raw_by_ip: Dict[str, Dict] = {}
    headers = {"User-Agent": CUSTOM_USER_AGENT}
    custom_ports = [22, 80, 443, 445, 3389, 8080]

    async with httpx.AsyncClient(timeout=10.0, headers=headers, follow_redirects=True) as client:
        for src in enabled_custom_sources:
            feed_name = (src.get("name") or "CUSTOM_FEED").upper().replace(" ", "_")[:16]
            feed_url = (src.get("url") or "").strip()
            if not feed_url:
                continue

            # Direct IPv4 or IP:Port entry
            direct_match = IPV4_REGEX.fullmatch(feed_url)
            if direct_match:
                ip_part = direct_match.group(1)
                port_part = direct_match.group(2)
                raw_by_ip[ip_part] = {
                    "ip": ip_part,
                    "port": int(port_part) if (port_part and port_part.isdigit()) else 443,
                    "raw_name": feed_name,
                    "feed_id": src.get("id") or "custom",
                }
                continue

            # Remote feed URL
            fetch_url = (
                feed_url
                if feed_url.startswith(("http://", "https://"))
                else f"https://{feed_url}"
            )
            try:
                resp = await client.get(fetch_url)
                if resp.status_code == 200:
                    lines = resp.text.splitlines()
                    random.shuffle(lines)
                    for line in lines:
                        if line.startswith("#") or not line.strip():
                            continue
                        for match in IPV4_REGEX.finditer(line):
                            ip_part = match.group(1)
                            port_part = match.group(2)
                            if ip_part not in raw_by_ip:
                                raw_by_ip[ip_part] = {
                                    "ip": ip_part,
                                    "port": int(port_part)
                                    if (port_part and port_part.isdigit())
                                    else random.choice(custom_ports),
                                    "raw_name": feed_name,
                                    "feed_id": src.get("id") or "custom",
                                }
                            if len(raw_by_ip) >= 100:
                                break
                        if len(raw_by_ip) >= 100:
                            break
            except Exception as e:
                logger.warning(f"Custom feed '{feed_name}' ({fetch_url}) fetch warning: {e}")

        raw_pool = list(raw_by_ip.values())
        random.shuffle(raw_pool)
        enriched = await geolocate_raw_pool(client, raw_pool, max_ips=100) if raw_pool else []

    manager.user_custom_pools[user_id] = {
        "pool": enriched,
        "ts": now,
        "hash": sources_hash,
    }
    logger.info(f"Loaded {len(enriched)} custom indicators for user_id={user_id}.")
    return enriched


async def fetch_public_osint_pool() -> List[Dict]:
    """Ingests active threat indicators from Feodo Tracker, ThreatFox, URLhaus, and CINS."""
    raw_by_ip: Dict[str, Dict] = {}
    headers = {"User-Agent": OSINT_USER_AGENT}

    async with httpx.AsyncClient(timeout=15.0, headers=headers, follow_redirects=True) as client:
        # 1. Feodo Tracker
        try:
            resp = await client.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
            if resp.status_code == 200:
                feodo_data = resp.json()
                if isinstance(feodo_data, list):
                    for entry in feodo_data:
                        ip = entry.get("ip_address")
                        if ip:
                            raw_by_ip[ip] = {
                                "ip": ip,
                                "port": int(entry.get("port") or 443),
                                "raw_name": str(entry.get("malware") or "BOTNET_C2"),
                                "feed_id": "feodo_tracker",
                            }
        except Exception as e:
            logger.warning(f"Feodo Tracker fetch warning: {e}")

        # 2. ThreatFox Public Export
        try:
            resp = await client.get("https://threatfox.abuse.ch/export/json/recent/")
            if resp.status_code == 200:
                tf_data = resp.json()
                if isinstance(tf_data, dict):
                    for _, items in tf_data.items():
                        if not isinstance(items, list) or not items:
                            continue
                        ioc_obj = items[0]
                        ioc_val = str(ioc_obj.get("ioc_value", ""))
                        match = IPV4_REGEX.search(ioc_val)
                        if match:
                            ip_part = match.group(1)
                            port_part = match.group(2)
                            malware = (
                                ioc_obj.get("malware_printable")
                                or ioc_obj.get("threat_type")
                                or "MALWARE"
                            )
                            if str(malware).lower() in ("unknown", "none", ""):
                                malware = "PAYLOAD_HOST"
                            raw_by_ip[ip_part] = {
                                "ip": ip_part,
                                "port": int(port_part)
                                if (port_part and port_part.isdigit())
                                else 80,
                                "raw_name": str(malware),
                                "feed_id": "threatfox",
                            }
        except Exception as e:
            logger.warning(f"ThreatFox fetch warning: {e}")

        # 3. URLhaus Live Online Servers
        try:
            resp = await client.get("https://urlhaus.abuse.ch/downloads/text_online/")
            if resp.status_code == 200:
                lines = [
                    l for l in resp.text.splitlines() if not l.startswith("#") and l.strip()
                ]
                random.shuffle(lines)
                for line in lines[:150]:
                    match = IPV4_REGEX.search(line)
                    if match:
                        ip_part = match.group(1)
                        port_part = match.group(2)
                        if ip_part not in raw_by_ip:
                            lower_url = line.lower()
                            family = "MALWARE_DROP"
                            if "mozi" in lower_url:
                                family = "MOZI_BOTNET"
                            elif "mirai" in lower_url:
                                family = "MIRAI"
                            elif "gafgyt" in lower_url or "bashlite" in lower_url:
                                family = "GAFGYT"
                            raw_by_ip[ip_part] = {
                                "ip": ip_part,
                                "port": int(port_part)
                                if (port_part and port_part.isdigit())
                                else 80,
                                "raw_name": family,
                                "feed_id": "urlhaus",
                            }
        except Exception as e:
            logger.warning(f"URLhaus fetch warning: {e}")

        # 4. CINS Active Badguys
        try:
            resp = await client.get("https://cinsscore.com/list/ci-badguys.txt")
            if resp.status_code == 200:
                ip_lines = [
                    l.strip()
                    for l in resp.text.splitlines()
                    if l.strip() and not l.startswith("#")
                ]
                random.shuffle(ip_lines)
                for ip_str in ip_lines[:100]:
                    if ip_str not in raw_by_ip:
                        raw_by_ip[ip_str] = {
                            "ip": ip_str,
                            "port": random.choice(COMMON_PORTS),
                            "raw_name": "SCANNER",
                            "feed_id": "cins_army",
                        }
        except Exception as e:
            logger.warning(f"CINS feed fetch warning: {e}")

        raw_pool = list(raw_by_ip.values())
        random.shuffle(raw_pool)
        logger.info(
            f"Collected {len(raw_pool)} unique active threat IPs across global OSINT feeds."
        )

        enriched_pool = await geolocate_raw_pool(client, raw_pool, max_ips=200)
        distinct_countries = len({i["srcCode"] for i in enriched_pool})
        logger.info(
            f"Verified {len(enriched_pool)} real threats across {distinct_countries} distinct countries."
        )

    return enriched_pool


def build_user_target_pool(user_id: int, global_targets: List[Dict]) -> List[Dict]:
    """
    Combines the user's configured custom locations (where is_target is enabled)
    with the global target pool so custom mode can target monitored assets by IP.
    """
    user_locs = get_user_custom_locations(user_id)
    custom_targets = [
        {
            "ip": (loc.get("ip") or "").strip(),
            "country": loc.get("country") or "Monitored Asset",
            "code": (loc.get("code") or "un").lower(),
            "city": loc.get("name") or loc.get("city") or "Asset",
            "lat": float(loc.get("lat", 0.0)),
            "lon": float(loc.get("lon", 0.0)),
        }
        for loc in user_locs
        if loc.get("is_target", True)
        and loc.get("ip")
        and loc.get("lat") is not None
        and loc.get("lon") is not None
    ]
    if custom_targets:
        # Weight custom monitored locations so they are frequently targeted in custom mode
        return custom_targets * 3 + global_targets
    return global_targets


async def osint_worker() -> None:
    """Background worker loop that refreshes OSINT pools and streams events to clients."""
    logger.info("Starting OSINT Intelligence Collector...")
    ioc_pool: List[Dict] = []
    target_pool: List[Dict] = []
    last_fetch_time = 0.0

    while True:
        now = asyncio.get_event_loop().time()

        # Refresh both the live attacker pool and dynamic global target cities every 10 minutes
        if not ioc_pool or not target_pool or (now - last_fetch_time > 600):
            fresh_iocs = await fetch_public_osint_pool()
            await asyncio.sleep(1.2)
            fresh_targets = await fetch_dynamic_target_pool()

            if fresh_iocs:
                ioc_pool = fresh_iocs
            if fresh_targets:
                target_pool = fresh_targets
            elif fresh_iocs and not target_pool:
                # Fallback to geolocated nodes from the IOC pool if ip-api rate-limits target batch
                target_pool = [
                    {
                        "ip": x.get("ip", "N/A"),
                        "country": x["srcCountry"],
                        "code": x["srcCode"],
                        "city": x["srcCity"],
                        "lat": x["srcLat"],
                        "lon": x["srcLon"],
                    }
                    for x in fresh_iocs
                ]

            if ioc_pool and target_pool:
                last_fetch_time = now
            else:
                last_fetch_time = now - 570

        # Stream unified threat intelligence to all connected clients:
        # - Unauthenticated guests receive all 4 built-in Default Feeds
        # - Authenticated operators receive their enabled Default Feeds + enabled Custom Feeds
        if target_pool:
            default_guest_event = (
                build_attack_event(random.choice(ioc_pool), target_pool, feed_mode="unified")
                if ioc_pool
                else None
            )

            for ws, meta in list(manager.clients.items()):
                uid = meta.get("user_id")
                if uid is None:
                    if default_guest_event:
                        await manager.send_to_client(ws, default_guest_event)
                    continue

                user_sources = get_user_custom_sources(uid)
                enabled_default_ids = {
                    s["id"]
                    for s in user_sources
                    if s.get("is_default") and s.get("enabled", True)
                }
                enabled_custom_sources = [
                    s
                    for s in user_sources
                    if not s.get("is_default") and s.get("enabled", True)
                ]

                active_pool: List[Dict] = []
                if ioc_pool and enabled_default_ids:
                    active_pool.extend(
                        item
                        for item in ioc_pool
                        if item.get("feed_id", "feodo_tracker") in enabled_default_ids
                    )

                if enabled_custom_sources:
                    custom_pool = await fetch_custom_user_pool(uid, enabled_custom_sources)
                    if custom_pool:
                        # Weight custom indicators so user-added feeds are well represented
                        active_pool.extend(custom_pool * 2 if active_pool else custom_pool)

                if active_pool:
                    effective_targets = build_user_target_pool(uid, target_pool)
                    chosen_item = random.choice(active_pool)
                    await manager.send_to_client(
                        ws, build_attack_event(chosen_item, effective_targets, feed_mode="unified")
                    )

        await asyncio.sleep(random.uniform(0.8, 1.7))
