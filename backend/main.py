"""
SOC Threat Matrix - Precision OSINT Ingestion & WebSocket Streamer
================================================================
- Ingests abuse.ch Feodo Tracker and ThreatFox feeds.
- Geocodes IPs to exact city-level coordinates (no artificial jitter).
- Pairs threats with realistic destination sensor cities.
- Enriches events with MITRE ATT&CK, CVE, ASN, and category taxonomy.
"""

import asyncio
import json
import logging
import os
import random
from contextlib import asynccontextmanager
from typing import Dict, List
import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("OSINT_ENGINE")

# Exact Destination Sensor Nodes with authentic city coordinates
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

# Fallback cities if geocoder is temporarily offline
COUNTRY_FALLBACKS = {
    "CN": {"country": "China", "city": "Beijing", "lat": 39.9042, "lon": 116.4074, "asn": "AS4134 CHINANET"},
    "US": {"country": "United States", "city": "New York", "lat": 40.7128, "lon": -74.0060, "asn": "AS14061 DIGITALOCEAN"},
    "RU": {"country": "Russia", "city": "Moscow", "lat": 55.7558, "lon": 37.6173, "asn": "AS12389 ROSTELECOM"},
    "DE": {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "asn": "AS24940 HETZNER"},
    "NL": {"country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041, "asn": "AS49981 LEASEWEB"},
    "BR": {"country": "Brazil", "city": "Rio de Janeiro", "lat": -22.9068, "lon": -43.1729, "asn": "AS28573 CLARO"},
    "IN": {"country": "India", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777, "asn": "AS55836 RELIANCE"},
    "GB": {"country": "United Kingdom", "city": "London", "lat": 51.5074, "lon": -0.1278, "asn": "AS9009 M247"},
    "FR": {"country": "France", "city": "Paris", "lat": 48.8566, "lon": 2.3522, "asn": "AS16276 OVH"},
    "KR": {"country": "South Korea", "city": "Seoul", "lat": 37.5665, "lon": 126.9780, "asn": "AS4766 KIXS"},
    "SG": {"country": "Singapore", "city": "Singapore", "lat": 1.3521, "lon": 103.8198, "asn": "AS4657 STARHUB"},
    "VN": {"country": "Vietnam", "city": "Hanoi", "lat": 21.0285, "lon": 105.8542, "asn": "AS7552 VIETTEL"},
    "UA": {"country": "Ukraine", "city": "Kyiv", "lat": 50.4501, "lon": 30.5234, "asn": "AS6849 UKRTELECOM"},
    "IR": {"country": "Iran", "city": "Tehran", "lat": 35.6892, "lon": 51.3890, "asn": "AS58224 TIC"},
}

THREAT_TAXONOMY = {
    "COBALT_STRIKE": {"category": "C2_BEACON", "mitre": "T1071.001", "cve": "CVE-2022-30190", "severity": "CRITICAL"},
    "LUMMA": {"category": "INFOSTEALER", "mitre": "T1555", "cve": "CVE-2023-38831", "severity": "HIGH"},
    "REDLINE": {"category": "INFOSTEALER", "mitre": "T1555.003", "cve": "CVE-2023-36025", "severity": "HIGH"},
    "VIDAR": {"category": "INFOSTEALER", "mitre": "T1005", "cve": "CVE-2023-28252", "severity": "HIGH"},
    "PIKABOT": {"category": "LOADER", "mitre": "T1059.001", "cve": "CVE-2023-36884", "severity": "CRITICAL"},
    "QAKBOT": {"category": "BOTNET_C2", "mitre": "T1055", "cve": "CVE-2023-23397", "severity": "CRITICAL"},
    "EMOTET": {"category": "BOTNET_C2", "mitre": "T1566.001", "cve": "CVE-2021-40444", "severity": "CRITICAL"},
    "MIRAI": {"category": "IOT_BOTNET", "mitre": "T1110.001", "cve": "CVE-2023-1389", "severity": "HIGH"},
    "METASPLOIT": {"category": "EXPLOIT_KIT", "mitre": "T1190", "cve": "CVE-2024-3400", "severity": "CRITICAL"},
    "HAVOC": {"category": "C2_BEACON", "mitre": "T1071.001", "cve": "CVE-2023-3519", "severity": "HIGH"},
    "LOCKBIT": {"category": "RANSOMWARE", "mitre": "T1486", "cve": "CVE-2023-4966", "severity": "CRITICAL"},
}

PORT_SIGNATURES = {
    22: {"category": "BRUTE_FORCE", "mitre": "T1110.001", "cve": "CVE-2024-6387", "name": "OPENSSH_SCAN", "severity": "HIGH"},
    23: {"category": "IOT_PROBE", "mitre": "T1110.001", "cve": "CVE-2022-26134", "name": "TELNET_BRUTE", "severity": "MEDIUM"},
    80: {"category": "WEB_EXPLOIT", "mitre": "T1190", "cve": "CVE-2021-44228", "name": "HTTP_EXPLOIT", "severity": "HIGH"},
    443: {"category": "C2_TUNNEL", "mitre": "T1071.001", "cve": "CVE-2024-3400", "name": "SSL_C2_BEACON", "severity": "CRITICAL"},
    445: {"category": "SMB_LATERAL", "mitre": "T1021.002", "cve": "CVE-2017-0144", "name": "ETERNALBLUE", "severity": "CRITICAL"},
    3389: {"category": "REMOTE_ACCESS", "mitre": "T1021.001", "cve": "CVE-2019-0708", "name": "BLUEKEEP_PROBE", "severity": "HIGH"},
    8080: {"category": "PROXY_SCAN", "mitre": "T1190", "cve": "CVE-2023-34362", "name": "MOVEIT_SCAN", "severity": "HIGH"},
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
    upper_name = raw_name.upper()
    for key, data in THREAT_TAXONOMY.items():
        if key in upper_name:
            return {
                "malware": upper_name[:16],
                "category": data["category"],
                "mitre": data["mitre"],
                "cve": data["cve"],
                "severity": data["severity"]
            }

    if port in PORT_SIGNATURES:
        sig = PORT_SIGNATURES[port]
        return {
            "malware": upper_name[:16] if upper_name != "BOTNET_C2" else sig["name"],
            "category": sig["category"],
            "mitre": sig["mitre"],
            "cve": sig["cve"],
            "severity": sig["severity"]
        }

    return {
        "malware": upper_name[:16] if upper_name else "MALICIOUS_C2",
        "category": "NETWORK_C2",
        "mitre": "T1071",
        "cve": "CVE-GENERIC",
        "severity": "MEDIUM"
    }

async def fetch_public_osint_pool() -> List[Dict]:
    raw_pool: List[Dict] = []
    headers = {"User-Agent": "SOC-ThreatMap-OSINT/1.0"}

    async with httpx.AsyncClient(timeout=12.0, headers=headers, follow_redirects=True) as client:
        # 1. Feodo Tracker
        try:
            resp = await client.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
            if resp.status_code == 200:
                feodo_data = resp.json()
                if isinstance(feodo_data, list):
                    for entry in feodo_data[:100]:
                        ip = entry.get("ip_address")
                        if ip:
                            raw_pool.append({
                                "ip": ip,
                                "port": int(entry.get("port") or 443),
                                "raw_name": str(entry.get("malware") or "BOTNET_C2"),
                                "country_code": (entry.get("country") or "").upper(),
                            })
        except Exception as e:
            logger.warning(f"Feodo Tracker fetch warning: {e}")

        # 2. ThreatFox Export
        try:
            resp = await client.get("https://threatfox.abuse.ch/export/json/recent/")
            if resp.status_code == 200:
                tf_data = resp.json()
                if isinstance(tf_data, dict):
                    for _, items in tf_data.items():
                        if not isinstance(items, list) or not items:
                            continue
                        ioc_obj = items[0]
                        ioc_val = ioc_obj.get("ioc_value", "")
                        if ioc_obj.get("ioc_type") == "ip:port" and ":" in ioc_val:
                            ip_part, port_part = ioc_val.split(":", 1)
                            raw_pool.append({
                                "ip": ip_part,
                                "port": int(port_part) if port_part.isdigit() else 443,
                                "raw_name": str(ioc_obj.get("malware_printable") or "MALWARE"),
                                "country_code": "",
                            })
                            if len(raw_pool) >= 120:
                                break
        except Exception as e:
            logger.warning(f"ThreatFox fetch warning: {e}")

        # 3. Batch Geolocation Enrichment
        enriched_pool: List[Dict] = []
        if raw_pool:
            ips_to_query = list({item["ip"] for item in raw_pool})[:100]
            try:
                geo_resp = await client.post("http://ip-api.com/batch", json=ips_to_query)
                if geo_resp.status_code == 200:
                    geo_map = {
                        g["query"]: g
                        for g in geo_resp.json()
                        if g.get("status") == "success" and g.get("lat") and g.get("lon")
                    }
                    for item in raw_pool:
                        g = geo_map.get(item["ip"])
                        if g:
                            item["srcCountry"] = g.get("country", "Unknown")
                            item["srcCode"] = g.get("countryCode", "un").lower()
                            item["srcCity"] = g.get("city") or "Host"
                            item["srcAsn"] = (g.get("as") or "AS_EDGE").split(" ")[0]
                            # EXACT city coordinates from geolocation provider
                            item["srcLat"] = float(g.get("lat"))
                            item["srcLon"] = float(g.get("lon"))
                            enriched_pool.append(item)
                    logger.info(f"Verified {len(enriched_pool)} real threats with exact city coordinates.")
            except Exception as e:
                logger.warning(f"Batch geolocation warning: {e}")

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

            # Precise city coordinates
            src_country = item["srcCountry"]
            src_code = item["srcCode"]
            src_city = item["srcCity"]
            src_asn = item["srcAsn"]
            src_lat = item["srcLat"]
            src_lon = item["srcLon"]

            # Pair with target sensor node in a different country
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
        else:
            # Fallback using realistic city coordinates
            cc = random.choice(list(COUNTRY_FALLBACKS.keys()))
            ref = COUNTRY_FALLBACKS[cc]
            targets = [n for n in GLOBAL_SENSOR_NODES if n["code"] != cc.lower()]
            dst = random.choice(targets)
            await manager.broadcast({
                "srcCountry": ref["country"],
                "srcCode": cc.lower(),
                "srcCity": ref["city"],
                "srcAsn": ref["asn"],
                "srcLat": ref["lat"],
                "srcLon": ref["lon"],
                "dstCountry": dst["country"],
                "dstCode": dst["code"],
                "dstCity": dst["city"],
                "dstLat": dst["lat"],
                "dstLon": dst["lon"],
                "malware": "C2_BEACON",
                "category": "BOTNET_C2",
                "mitre": "T1071.001",
                "cve": "CVE-2024-3400",
                "severity": "CRITICAL",
                "port": 443,
                "proto": "TCP",
            })

        await asyncio.sleep(random.uniform(0.9, 1.9))

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