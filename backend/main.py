"""
SOC Threat Matrix - High-Volume OSINT Ingestion & WebSocket Streamer
====================================================================
- Ingests live indicators from:
  1. abuse.ch Feodo Tracker (Botnet C2s)
  2. abuse.ch ThreatFox (ip:port & URL-based malware hosts)
  3. abuse.ch URLhaus Online Payloads (Global malware distribution servers)
  4. CINS Score / Active Scanner Intelligence
- Geocodes up to 200 unique IPs per cycle to exact city-level coordinates.
"""

import asyncio
import json
import logging
import os
import random
import re
from contextlib import asynccontextmanager
from typing import Dict, List
import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("OSINT_ENGINE")

# Regex to extract IPv4 and optional port from raw IOCs and URLs
IPV4_REGEX = re.compile(r"(?:https?://)?(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?")

# Exact Destination Sensor Nodes
GLOBAL_SENSOR_NODES = [
    {"country": "United States", "code": "us", "city": "Ashburn", "lat": 39.0438, "lon": -77.4874},
    {"country": "United States", "code": "us", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194},
    {"country": "Germany", "code": "de", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
    {"country": "Netherlands", "code": "nl", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
    {"country": "Belgium", "code": "be", "city": "Brussels", "lat": 50.8503, "lon": 4.3517},
    {"country": "Japan", "code": "jp", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503},
    {"country": "Singapore", "code": "sg", "city": "Singapore", "lat": 1.3521, "lon": 103.8198},
    {"country": "United Kingdom", "code": "gb", "city": "London", "lat": 51.5074, "lon": -0.1278},
    {"country": "Australia", "code": "au", "city": "Sydney", "lat": -33.8688, "lon": 151.2093},
    {"country": "France", "code": "fr", "city": "Paris", "lat": 48.8566, "lon": 2.3522},
    {"country": "Canada", "code": "ca", "city": "Toronto", "lat": 43.6532, "lon": -79.3832},
    {"country": "Sweden", "code": "se", "city": "Stockholm", "lat": 59.3293, "lon": 18.0686},
    {"country": "Brazil", "code": "br", "city": "São Paulo", "lat": -23.5505, "lon": -46.6333},
    {"country": "South Korea", "code": "kr", "city": "Seoul", "lat": 37.5665, "lon": 126.9780},
]

THREAT_TAXONOMY = {
    "COBALT_STRIKE": {"category": "C2_BEACON", "mitre": "T1071.001", "cve": "CVE-2022-30190", "severity": "CRITICAL"},
    "LUMMA": {"category": "INFOSTEALER", "mitre": "T1555", "cve": "CVE-2023-38831", "severity": "HIGH"},
    "REDLINE": {"category": "INFOSTEALER", "mitre": "T1555.003", "cve": "CVE-2023-36025", "severity": "HIGH"},
    "VIDAR": {"category": "INFOSTEALER", "mitre": "T1005", "cve": "CVE-2023-28252", "severity": "HIGH"},
    "PIKABOT": {"category": "LOADER", "mitre": "T1059.001", "cve": "CVE-2023-36884", "severity": "CRITICAL"},
    "QAKBOT": {"category": "BOTNET_C2", "mitre": "T1055", "cve": "CVE-2023-23397", "severity": "CRITICAL"},
    "EMOTET": {"category": "BOTNET_C2", "mitre": "T1566.001", "cve": "CVE-2021-40444", "severity": "CRITICAL"},
    "MIRAI": {"category": "IOT_BOTNET", "mitre": "T1110.001", "cve": "CVE-2023-1389", "severity": "HIGH"},
    "MOZI": {"category": "IOT_BOTNET", "mitre": "T1190", "cve": "CVE-2022-30525", "severity": "HIGH"},
    "GAFGYT": {"category": "IOT_BOTNET", "mitre": "T1110", "cve": "CVE-2021-35394", "severity": "HIGH"},
    "METASPLOIT": {"category": "EXPLOIT_KIT", "mitre": "T1190", "cve": "CVE-2024-3400", "severity": "CRITICAL"},
    "HAVOC": {"category": "C2_BEACON", "mitre": "T1071.001", "cve": "CVE-2023-3519", "severity": "HIGH"},
    "LOCKBIT": {"category": "RANSOMWARE", "mitre": "T1486", "cve": "CVE-2023-4966", "severity": "CRITICAL"},
    "ASYNC_RAT": {"category": "RAT_TROJAN", "mitre": "T1219", "cve": "CVE-2023-38831", "severity": "HIGH"},
    "REMCOM": {"category": "RAT_TROJAN", "mitre": "T1059", "cve": "CVE-2022-30190", "severity": "HIGH"},
}

PORT_SIGNATURES = {
    22: {"category": "BRUTE_FORCE", "mitre": "T1110.001", "cve": "CVE-2024-6387", "name": "OPENSSH_SCAN", "severity": "HIGH"},
    23: {"category": "IOT_PROBE", "mitre": "T1110.001", "cve": "CVE-2022-26134", "name": "TELNET_BRUTE", "severity": "MEDIUM"},
    80: {"category": "WEB_EXPLOIT", "mitre": "T1190", "cve": "CVE-2021-44228", "name": "HTTP_PAYLOAD", "severity": "HIGH"},
    443: {"category": "C2_TUNNEL", "mitre": "T1071.001", "cve": "CVE-2024-3400", "name": "SSL_C2_BEACON", "severity": "CRITICAL"},
    445: {"category": "SMB_LATERAL", "mitre": "T1021.002", "cve": "CVE-2017-0144", "name": "ETERNALBLUE", "severity": "CRITICAL"},
    3389: {"category": "REMOTE_ACCESS", "mitre": "T1021.001", "cve": "CVE-2019-0708", "name": "BLUEKEEP_PROBE", "severity": "HIGH"},
    8080: {"category": "PROXY_SCAN", "mitre": "T1190", "cve": "CVE-2023-34362", "name": "HTTP_PROXY_EXP", "severity": "HIGH"},
}


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Client connected. Active listeners: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"Client disconnected. Active listeners: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        if not self.active_connections:
            return
        payload = json.dumps(message)
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception:
                self.disconnect(connection)


manager = ConnectionManager()


def enrich_threat_metadata(raw_name: str, port: int) -> Dict:
    upper_name = raw_name.upper().replace(" ", "_")
    for key, data in THREAT_TAXONOMY.items():
        if key in upper_name:
            return {
                "malware": upper_name[:16],
                "category": data["category"],
                "mitre": data["mitre"],
                "cve": data["cve"],
                "severity": data["severity"],
            }

    if port in PORT_SIGNATURES:
        sig = PORT_SIGNATURES[port]
        return {
            "malware": upper_name[:16] if upper_name not in ("BOTNET_C2", "MALWARE", "SCANNER") else sig["name"],
            "category": sig["category"],
            "mitre": sig["mitre"],
            "cve": sig["cve"],
            "severity": sig["severity"],
        }

    return {
        "malware": upper_name[:16] if upper_name else "MALICIOUS_HOST",
        "category": "MALWARE_DROP",
        "mitre": "T1190",
        "cve": "CVE-2023-1389",
        "severity": "HIGH",
    }


async def fetch_public_osint_pool() -> List[Dict]:
    """
    Collects active malicious IPs from 4 unauthenticated public OSINT feeds
    and geolocates up to 200 unique IPs across the globe.
    """
    raw_by_ip: Dict[str, Dict] = {}
    headers = {"User-Agent": "SOC-ThreatMap-OSINT/2.0"}

    async with httpx.AsyncClient(timeout=15.0, headers=headers, follow_redirects=True) as client:
        # 1. abuse.ch Feodo Tracker (Active Botnet C2s)
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
                            }
        except Exception as e:
            logger.warning(f"Feodo Tracker fetch warning: {e}")

        # 2. abuse.ch ThreatFox Public Export (Extracts IPs from both ip:port AND url IOCs)
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
                            malware = ioc_obj.get("malware_printable") or ioc_obj.get("threat_type") or "MALWARE"
                            if str(malware).lower() in ("unknown", "none", ""):
                                malware = "PAYLOAD_HOST"
                            raw_by_ip[ip_part] = {
                                "ip": ip_part,
                                "port": int(port_part) if (port_part and port_part.isdigit()) else 80,
                                "raw_name": str(malware),
                            }
        except Exception as e:
            logger.warning(f"ThreatFox fetch warning: {e}")

        # 3. abuse.ch URLhaus Live Online Malware Distribution Servers
        try:
            resp = await client.get("https://urlhaus.abuse.ch/downloads/text_online/")
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                uh_Simple = [l for l in lines if not l.startswith("#") and l.strip()]
                random.shuffle(uh_Simple)
                for line in uh_Simple[:150]:
                    match = IPV4_REGEX.search(line)
                    if match:
                        ip_part = match.group(1)
                        port_part = match.group(2)
                        if ip_part not in raw_by_ip:
                            # Infer malware family if present in URL path
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
                                "port": int(port_part) if (port_part and port_part.isdigit()) else 80,
                                "raw_name": family,
                            }
        except Exception as e:
            logger.warning(f"URLhaus fetch warning: {e}")

        # 4. CINS Active Badguys / Global Intrusion Sensors
        try:
            resp = await client.get("https://cinsscore.com/list/ci-badguys.txt")
            if resp.status_code == 200:
                ip_lines = [l.strip() for l in resp.text.splitlines() if l.strip() and not l.startswith("#")]
                random.shuffle(ip_lines)
                common_ports = [22, 23, 80, 443, 445, 3389, 8080]
                for ip_str in ip_lines[:100]:
                    if ip_str not in raw_by_ip:
                        raw_by_ip[ip_str] = {
                            "ip": ip_str,
                            "port": random.choice(common_ports),
                            "raw_name": "SCANNER",
                        }
        except Exception as e:
            logger.warning(f"CINS feed fetch warning: {e}")

        raw_pool = list(raw_by_ip.values())
        random.shuffle(raw_pool)
        logger.info(f"Collected {len(raw_pool)} unique active threat IPs across global OSINT feeds.")

        # Batch Geolocation Enrichment (Up to 200 unique IPs in 2 batches of 100)
        enriched_pool: List[Dict] = []
        for batch_start in (0, 100):
            batch_slice = raw_pool[batch_start : batch_start + 100]
            if not batch_slice:
                break
            ips_to_query = [item["ip"] for item in batch_slice]
            try:
                geo_resp = await client.post("http://ip-api.com/batch", json=ips_to_query)
                if geo_resp.status_code == 200:
                    geo_map = {
                        g["query"]: g
                        for g in geo_resp.json()
                        if g.get("status") == "success" and g.get("lat") is not None and g.get("lon") is not None
                    }
                    for item in batch_slice:
                        g = geo_map.get(item["ip"])
                        if g:
                            item["srcCountry"] = g.get("country", "Unknown")
                            item["srcCode"] = g.get("countryCode", "un").lower()
                            item["srcCity"] = g.get("city") or g.get("regionName") or "Host"
                            item["srcAsn"] = (g.get("as") or "AS_EDGE").split(" ")[0]
                            item["srcLat"] = float(g.get("lat"))
                            item["srcLon"] = float(g.get("lon"))
                            enriched_pool.append(item)
            except Exception as e:
                logger.warning(f"Batch geolocation warning: {e}")
            await asyncio.sleep(1.0)

        distinct_countries = len({i["srcCode"] for i in enriched_pool})
        logger.info(
            f"Verified {len(enriched_pool)} real threats across {distinct_countries} distinct countries."
        )

    return enriched_pool


async def osint_worker():
    logger.info("Starting OSINT Intelligence Collector...")
    ioc_pool: List[Dict] = []
    last_fetch_time = 0.0

    while True:
        now = asyncio.get_event_loop().time()

        if not ioc_pool or (now - last_fetch_time > 600):
            fresh_pool = await fetch_public_osint_pool()
            if fresh_pool:
                ioc_pool = fresh_pool
                last_fetch_time = now
            else:
                last_fetch_time = now - 570

        if ioc_pool:
            item = random.choice(ioc_pool)

            src_country = item["srcCountry"]
            src_code = item["srcCode"]
            src_city = item["srcCity"]
            src_asn = item["srcAsn"]
            src_lat = item["srcLat"]
            src_lon = item["srcLon"]

            targets = [n for n in GLOBAL_SENSOR_NODES if n["code"] != src_code]
            dst = random.choice(targets if targets else GLOBAL_SENSOR_NODES)

            port = item.get("port", 443)
            intel = enrich_threat_metadata(item.get("raw_name", ""), port)

            event = {
                "srcCountry": src_country,
                "srcCode": src_code,
                "srcCity": src_city,
                "srcAsn": src_asn,
                "srcLat": src_lat,
                "srcLon": src_lon,
                "dstCountry": dst["country"],
                "dstCode": dst["code"],
                "dstCity": dst["city"],
                "dstLat": dst["lat"],
                "dstLon": dst["lon"],
                "malware": intel["malware"],
                "category": intel["category"],
                "mitre": intel["mitre"],
                "cve": intel["cve"],
                "severity": intel["severity"],
                "port": port,
                "proto": "TCP",
            }
            await manager.broadcast(event)

        await asyncio.sleep(random.uniform(0.8, 1.7))


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(osint_worker())
    yield
    task.cancel()


app = FastAPI(title="SOC Threat Matrix OSINT Server", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")