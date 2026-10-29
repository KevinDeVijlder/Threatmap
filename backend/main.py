"""
SOC Threat Matrix - OSINT Ingestion & WebSocket Server
======================================================
Architecture Overview:
1. Polls unauthenticated public threat intelligence feeds (abuse.ch Feodo Tracker & ThreatFox).
2. Resolves raw attacker IP addresses into real-world Latitude/Longitude coordinates via batch GeoIP.
3. Streams formatted JSON attack events over WebSockets (/ws) to all connected browser clients.
4. Serves the static frontend dashboard at the root URL (/).
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

# Configure console logging with timestamps
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("OSINT_ENGINE")


# =====================================================================
# STATIC GEOGRAPHIC REFERENCE DATA
# =====================================================================

# Global Sensor / Victim Target Nodes:
# Public OSINT feeds provide the attacker/C2 IP (the source). To visualize a complete
# connection path, we pair each threat indicator with a global sensor/victim node.
GLOBAL_SENSOR_NODES = [
    {"country": "United States", "code": "us", "lat": 37.77, "lon": -122.41},
    {"country": "United States", "code": "us", "lat": 39.04, "lon": -77.48},
    {"country": "Germany", "code": "de", "lat": 50.11, "lon": 8.68},
    {"country": "Netherlands", "code": "nl", "lat": 52.37, "lon": 4.89},
    {"country": "Belgium", "code": "be", "lat": 50.85, "lon": 4.35},
    {"country": "Japan", "code": "jp", "lat": 35.68, "lon": 139.69},
    {"country": "Singapore", "code": "sg", "lat": 1.35, "lon": 103.82},
    {"country": "United Kingdom", "code": "gb", "lat": 51.51, "lon": -0.13},
    {"country": "Australia", "code": "au", "lat": -33.86, "lon": 151.21},
    {"country": "France", "code": "fr", "lat": 48.85, "lon": 2.35},
    {"country": "Canada", "code": "ca", "lat": 43.65, "lon": -79.38},
    {"country": "Sweden", "code": "se", "lat": 59.33, "lon": 18.06},
    {"country": "Brazil", "code": "br", "lat": -23.55, "lon": -46.63},
    {"country": "South Korea", "code": "kr", "lat": 37.56, "lon": 126.97},
]

# Country Centroid Fallback Dictionary:
# Used if batch IP geolocation hits a rate limit or if only a 2-letter ISO country code is available.
COUNTRY_COORDS = {
    "CN": {"country": "China", "lat": 39.9, "lon": 116.4},
    "US": {"country": "United States", "lat": 37.7, "lon": -95.7},
    "RU": {"country": "Russia", "lat": 55.75, "lon": 37.6},
    "DE": {"country": "Germany", "lat": 51.1, "lon": 10.4},
    "NL": {"country": "Netherlands", "lat": 52.3, "lon": 4.9},
    "BR": {"country": "Brazil", "lat": -14.2, "lon": -51.9},
    "IN": {"country": "India", "lat": 20.5, "lon": 78.9},
    "GB": {"country": "United Kingdom", "lat": 55.3, "lon": -3.4},
    "FR": {"country": "France", "lat": 46.2, "lon": 2.2},
    "KR": {"country": "South Korea", "lat": 35.9, "lon": 127.7},
    "SG": {"country": "Singapore", "lat": 1.35, "lon": 103.8},
    "VN": {"country": "Vietnam", "lat": 14.0, "lon": 108.2},
    "UA": {"country": "Ukraine", "lat": 48.3, "lon": 31.1},
    "IR": {"country": "Iran", "lat": 32.4, "lon": 53.6},
    "ID": {"country": "Indonesia", "lat": -0.7, "lon": 113.9},
    "TR": {"country": "Turkey", "lat": 38.9, "lon": 35.2},
    "PL": {"country": "Poland", "lat": 51.9, "lon": 19.1},
    "RO": {"country": "Romania", "lat": 45.9, "lon": 24.9},
    "BG": {"country": "Bulgaria", "lat": 42.7, "lon": 25.4},
    "HK": {"country": "Hong Kong", "lat": 22.3, "lon": 114.1},
    "CA": {"country": "Canada", "lat": 45.4, "lon": -75.7},
    "IT": {"country": "Italy", "lat": 41.8, "lon": 12.5},
    "ES": {"country": "Spain", "lat": 40.4, "lon": -3.7},
    "MX": {"country": "Mexico", "lat": 23.6, "lon": -102.5},
    "AR": {"country": "Argentina", "lat": -34.6, "lon": -58.3},
    "ZA": {"country": "South Africa", "lat": -25.7, "lon": 28.2},
    "PK": {"country": "Pakistan", "lat": 30.3, "lon": 69.3},
    "TH": {"country": "Thailand", "lat": 13.7, "lon": 100.5},
}


# =====================================================================
# WEBSOCKET CONNECTION MANAGER
# =====================================================================

class ConnectionManager:
    """
    Manages active WebSocket connections from browser clients.
    Handles client registration, disconnection cleanup, and broadcasting JSON payloads.
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accepts a new incoming WebSocket handshake and stores the client reference."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Client connected. Active listeners: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Removes a closed or broken WebSocket connection from the active pool."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"Client disconnected. Active listeners: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """
        Serializes an attack dictionary to JSON and pushes it to every connected browser.
        Automatically prunes dead connections if sending fails.
        """
        if not self.active_connections:
            return
        payload = json.dumps(message)
        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception:
                self.disconnect(connection)


manager = ConnectionManager()


# =====================================================================
# OSINT THREAT COLLECTOR & GEOLOCATION FUNCTIONS
# =====================================================================

async def fetch_public_osint_pool() -> List[Dict]:
    """
    Downloads live indicators of compromise (IOCs) from two unauthenticated abuse.ch feeds:
      1. Feodo Tracker: Active Botnet Command & Control (C2) servers (Emotet, QakBot, Pikabot).
      2. ThreatFox Export: Recently reported malicious IP:Port pairs.
    Then performs a batch geolocation request to resolve the IPs into city-level Lat/Lon coordinates.
    """
    pool: List[Dict] = []
    headers = {"User-Agent": "SOC-ThreatMap-OSINT/1.0"}

    async with httpx.AsyncClient(timeout=12.0, headers=headers, follow_redirects=True) as client:
        # --- Feed 1: abuse.ch Feodo Tracker (Botnet C2 IP Blocklist) ---
        try:
            resp = await client.get("https://feodotracker.abuse.ch/downloads/ipblocklist.json")
            if resp.status_code == 200:
                feodo_data = resp.json()
                if isinstance(feodo_data, list):
                    for entry in feodo_data[:120]:
                        ip = entry.get("ip_address")
                        if not ip:
                            continue
                        pool.append({
                            "ip": ip,
                            "port": int(entry.get("port") or 443),
                            "name": str(entry.get("malware") or "BOTNET_C2").upper().replace(" ", "_")[:14],
                            "country_code": (entry.get("country") or "").upper(),
                        })
                    logger.info(f"Loaded {len(pool)} C2 servers from abuse.ch Feodo Tracker.")
        except Exception as e:
            logger.warning(f"Feodo Tracker fetch warning: {e}")

        # --- Feed 2: abuse.ch ThreatFox Public JSON Export ---
        try:
            resp = await client.get("https://threatfox.abuse.ch/export/json/recent/")
            if resp.status_code == 200:
                tf_data = resp.json()
                if isinstance(tf_data, dict):
                    tf_count = 0
                    for _, items in tf_data.items():
                        if not isinstance(items, list) or not items:
                            continue
                        ioc_obj = items[0]
                        ioc_val = ioc_obj.get("ioc_value", "")
                        # Filter specifically for network-level IP:Port indicators
                        if ioc_obj.get("ioc_type") == "ip:port" and ":" in ioc_val:
                            ip_part, port_part = ioc_val.split(":", 1)
                            malware = ioc_obj.get("malware_printable") or ioc_obj.get("threat_type") or "MALWARE_IOC"
                            pool.append({
                                "ip": ip_part,
                                "port": int(port_part) if port_part.isdigit() else 443,
                                "name": str(malware).upper().replace(" ", "_")[:14],
                                "country_code": "",
                            })
                            tf_count += 1
                            if tf_count >= 120:
                                break
                    logger.info(f"Loaded {tf_count} active IP:Port IOCs from ThreatFox public export.")
        except Exception as e:
            logger.warning(f"ThreatFox public export fetch warning: {e}")

        # --- Step 3: Batch IP Geolocation Enrichment ---
        # Queries up to 100 unique IPs in a single HTTP POST to avoid rate-limiting
        if pool:
            random.shuffle(pool)
            batch_slice = pool[:100]
            ips_to_query = list({item["ip"] for item in batch_slice})
            try:
                geo_resp = await client.post("http://ip-api.com/batch", json=ips_to_query[:100])
                if geo_resp.status_code == 200:
                    geo_map = {
                        g["query"]: g
                        for g in geo_resp.json()
                        if g.get("status") == "success"
                    }
                    # Attach resolved coordinates directly onto the pool items
                    for item in pool:
                        g = geo_map.get(item["ip"])
                        if g:
                            item["srcCountry"] = g.get("country", "Unknown")
                            item["srcCode"] = g.get("countryCode", "un").lower()
                            item["srcLat"] = float(g.get("lat", 0.0))
                            item["srcLon"] = float(g.get("lon", 0.0))
                    logger.info(f"Geolocated {len(geo_map)} real threat IPs to city-level coordinates.")
            except Exception as e:
                logger.warning(f"Batch geolocation fallback triggered: {e}")

    return pool


async def osint_worker():
    """
    Infinite background task started when FastAPI boots.
    - Refreshes the cached OSINT indicator pool every 10 minutes (600 seconds).
    - Selects real indicators from the pool and broadcasts them to connected WebSocket clients
      at a realistic visual cadence (every 0.8 to 1.8 seconds).
    """
    logger.info("Starting OSINT Intelligence Collector...")
    ioc_pool: List[Dict] = []
    last_fetch_time = 0.0

    while True:
        now = asyncio.get_event_loop().time()

        # Refresh the OSINT pool if empty or older than 10 minutes
        if not ioc_pool or (now - last_fetch_time > 600):
            fresh_pool = await fetch_public_osint_pool()
            if fresh_pool:
                ioc_pool = fresh_pool
                last_fetch_time = now
            else:
                # If network fetch failed, wait 30 seconds before trying again
                last_fetch_time = now - 570

        if ioc_pool:
            item = random.choice(ioc_pool)

            # Use city-level coordinates if geolocated; otherwise fall back to country centroid
            if "srcLat" in item and "srcLon" in item:
                src_country = item["srcCountry"]
                src_code = item["srcCode"]
                # Add tiny jitter (±0.25 deg) so multiple hits from the same city don't overlap 100%
                src_lat = item["srcLat"] + (random.random() - 0.5) * 0.5
                src_lon = item["srcLon"] + (random.random() - 0.5) * 0.5
            else:
                cc = item.get("country_code", "")
                if cc not in COUNTRY_COORDS:
                    cc = random.choice(list(COUNTRY_COORDS.keys()))
                ref = COUNTRY_COORDS[cc]
                src_country = ref["country"]
                src_code = cc.lower()
                src_lat = ref["lat"] + (random.random() - 0.5) * 3.0
                src_lon = ref["lon"] + (random.random() - 0.5) * 3.0

            # Pair with a target sensor node in a different country
            targets = [n for n in GLOBAL_SENSOR_NODES if n["code"] != src_code]
            dst = random.choice(targets if targets else GLOBAL_SENSOR_NODES)

            event = {
                "srcCountry": src_country,
                "srcCode": src_code,
                "srcLat": src_lat,
                "srcLon": src_lon,
                "dstCountry": dst["country"],
                "dstCode": dst["code"],
                "dstLat": dst["lat"] + (random.random() - 0.5) * 1.5,
                "dstLon": dst["lon"] + (random.random() - 0.5) * 1.5,
                "name": item.get("name", "C2_TRAFFIC"),
                "port": item.get("port", 443),
                "proto": "TCP",
            }
            await manager.broadcast(event)

        # Wait between 0.8s and 1.8s before emitting the next event
        await asyncio.sleep(random.uniform(0.8, 1.8))


# =====================================================================
# FASTAPI LIFESPAN, ROUTES & STATIC FILE MOUNT
# =====================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan manager: starts the background `osint_worker` task on server boot
    and cleanly cancels it when Uvicorn shuts down.
    """
    task = asyncio.create_task(osint_worker())
    yield
    task.cancel()


app = FastAPI(title="SOC Threat Matrix OSINT Server", lifespan=lifespan)

# Enable CORS so the frontend can connect even if opened on a separate port
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint (/ws) that browsers connect to.
    Keeps the connection open until the user closes or refreshes the tab.
    """
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# Mount the `frontend/` folder at `/` so visiting http://localhost:8000 serves index.html
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")