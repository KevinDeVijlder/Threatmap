"""
Geolocation & Dynamic Target Discovery Service
==============================================
Batch geolocates raw IP pools via ip-api.com and dynamically discovers real
cities and countries worldwide without hardcoded target lists.
"""

import asyncio
import random
from typing import Dict, List
import httpx

from config import OSINT_USER_AGENT, logger


async def geolocate_raw_pool(
    client: httpx.AsyncClient, raw_pool: List[Dict], max_ips: int = 100
) -> List[Dict]:
    """Batch geolocates a list of raw IP dictionaries using ip-api.com."""
    enriched_pool: List[Dict] = []
    for batch_start in range(0, min(len(raw_pool), max_ips), 100):
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
                    if g.get("status") == "success"
                    and g.get("lat") is not None
                    and g.get("lon") is not None
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
        if max_ips > 100:
            await asyncio.sleep(1.0)
    return enriched_pool


def generate_random_public_ips(count: int = 100) -> List[str]:
    """Generates random routable public IPv4 addresses across global RIR blocks."""
    ips = []
    excluded_first = {0, 10, 100, 127, 169, 172, 192, 198, 203, 224, 240, 255}
    while len(ips) < count:
        o1 = random.randint(1, 223)
        if o1 in excluded_first:
            continue
        ips.append(
            f"{o1}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        )
    return ips


async def fetch_dynamic_target_pool() -> List[Dict]:
    """
    Dynamically resolves real cities and countries worldwide via ip-api.com
    so target destinations cover the entire globe with zero hardcoded cities.
    """
    raw_targets = [{"ip": ip} for ip in generate_random_public_ips(100)]
    headers = {"User-Agent": OSINT_USER_AGENT}
    async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
        enriched = await geolocate_raw_pool(client, raw_targets, max_ips=100)
        target_nodes = [
            {
                "country": item["srcCountry"],
                "code": item["srcCode"],
                "city": item["srcCity"],
                "lat": item["srcLat"],
                "lon": item["srcLon"],
            }
            for item in enriched
            if item.get("srcCountry") != "Unknown"
        ]
        logger.info(
            f"Resolved {len(target_nodes)} dynamic target cities across "
            f"{len({t['code'] for t in target_nodes})} countries."
        )
        return target_nodes
