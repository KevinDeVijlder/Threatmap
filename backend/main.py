"""
SOC Threat Matrix - OSINT Streamer, Dynamic Target Resolver & SQLite Auth Backend
=================================================================================
- SQLite Database (soc_matrix.db): Stores users, PBKDF2 password hashes,
  uploaded profile avatars (Base64), session tokens, and custom SOC intel feeds.
- Dynamic Global Target Discovery: Resolves real cities and countries worldwide
  via ip-api.com batch geolocation with zero hardcoded destination lists.
- Per-Client WebSocket Routing:
  * "live" mode streams global public OSINT feeds (Feodo, ThreatFox, URLhaus, CINS).
  * "custom" mode streams only indicators parsed from the logged-in user's custom feeds.
"""

import asyncio
import hashlib
import json
import logging
import os
import random
import re
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
from typing import Dict, List, Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("OSINT_ENGINE")

DB_PATH = os.path.join(os.path.dirname(__file__), "soc_matrix.db")
IPV4_REGEX = re.compile(r"(?:https?://)?(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?")


# =====================================================================
# SQLITE DATABASE INITIALIZATION & HELPERS
# =====================================================================

def init_db():
    """Creates the SQLite database tables for users and sessions if they do not exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            avatar TEXT DEFAULT '',
            custom_sources TEXT DEFAULT '[]',
            created_at REAL NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at REAL NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()
    logger.info(f"SQLite database initialized at {DB_PATH}")


def hash_password(password: str, salt: str) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    ).hex()


def get_user_by_raw_token(token: Optional[str]) -> Optional[Dict]:
    """Resolves a raw session token into a user dictionary."""
    if not token:
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.username, u.avatar, u.custom_sources
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
    """, (token.strip(),))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "avatar": row["avatar"] or "",
        "custom_sources": json.loads(row["custom_sources"] or "[]"),
    }


def get_user_by_token(authorization: Optional[str]) -> Optional[Dict]:
    """Resolves a Bearer token from the HTTP Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    return get_user_by_raw_token(token)


def get_user_custom_sources(user_id: int) -> List[Dict]:
    """Fetches the latest custom_sources list for a specific user_id from SQLite."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT custom_sources FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return []
    return json.loads(row["custom_sources"] or "[]")


# =====================================================================
# PYDANTIC REQUEST MODELS
# =====================================================================

class AuthRequest(BaseModel):
    username: str
    password: str
    avatar: Optional[str] = ""


class AvatarUpdateRequest(BaseModel):
    avatar: str


class CustomSourcesUpdateRequest(BaseModel):
    custom_sources: List[Dict[str, str]]


# =====================================================================
# OSINT THREAT TAXONOMY & SIGNATURES
# =====================================================================

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
    22: {"category": "BRUTE_FORCE", "mitre": "T1110.001", "cve": "CVE-2024-6387", "name": "OPENSSH_SCAN", "severity": "LOW"},
    23: {"category": "IOT_PROBE", "mitre": "T1110.001", "cve": "CVE-2022-26134", "name": "TELNET_BRUTE", "severity": "LOW"},
    80: {"category": "WEB_EXPLOIT", "mitre": "T1190", "cve": "CVE-2021-44228", "name": "HTTP_PAYLOAD", "severity": "MEDIUM"},
    443: {"category": "C2_TUNNEL", "mitre": "T1071.001", "cve": "CVE-2024-3400", "name": "SSL_C2_BEACON", "severity": "CRITICAL"},
    445: {"category": "SMB_LATERAL", "mitre": "T1021.002", "cve": "CVE-2017-0144", "name": "ETERNALBLUE", "severity": "CRITICAL"},
    3389: {"category": "REMOTE_ACCESS", "mitre": "T1021.001", "cve": "CVE-2019-0708", "name": "BLUEKEEP_PROBE", "severity": "HIGH"},
    8080: {"category": "PROXY_SCAN", "mitre": "T1190", "cve": "CVE-2023-34362", "name": "HTTP_PROXY_EXP", "severity": "MEDIUM"},
}


# =====================================================================
# WEBSOCKET CONNECTION & MODE MANAGER
# =====================================================================

class ConnectionManager:
    def __init__(self):
        # Maps WebSocket -> {"mode": "live" | "custom", "user_id": Optional[int]}
        self.clients: Dict[WebSocket, Dict] = {}
        # Cache of geolocated custom pools per user_id: {user_id: {"pool": [...], "ts": float, "hash": str}}
        self.user_custom_pools: Dict[int, Dict] = {}

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.clients[websocket] = {"mode": "live", "user_id": None}
        logger.info(f"Client connected. Active listeners: {len(self.clients)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.clients:
            del self.clients[websocket]
            logger.info(f"Client disconnected. Active listeners: {len(self.clients)}")

    def set_client_mode(self, websocket: WebSocket, mode: str, token: Optional[str]):
        if websocket not in self.clients:
            return
        user = get_user_by_raw_token(token) if token else None
        if mode == "custom" and user:
            self.clients[websocket] = {"mode": "custom", "user_id": user["id"]}
            logger.info(f"User '{user['username']}' switched WebSocket to CUSTOM INTEL mode.")
        else:
            self.clients[websocket] = {"mode": "live", "user_id": user["id"] if user else None}
            logger.info("Client switched WebSocket to LIVE INTEL mode.")

    def invalidate_user_cache(self, user_id: int):
        if user_id in self.user_custom_pools:
            del self.user_custom_pools[user_id]

    async def broadcast_live(self, message: dict):
        """Sends live OSINT events ONLY to clients currently in 'live' mode."""
        payload = json.dumps(message)
        for ws, meta in list(self.clients.items()):
            if meta.get("mode") == "live":
                try:
                    await ws.send_text(payload)
                except Exception:
                    self.disconnect(ws)

    async def send_to_client(self, ws: WebSocket, message: dict):
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            self.disconnect(ws)


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
        "malware": upper_name[:16] if upper_name else "CUSTOM_IOC",
        "category": "CUSTOM_INTEL",
        "mitre": "T1071",
        "cve": "CVE-CUSTOM",
        "severity": "HIGH",
    }


async def geolocate_raw_pool(client: httpx.AsyncClient, raw_pool: List[Dict], max_ips: int = 100) -> List[Dict]:
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
        ips.append(f"{o1}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}")
    return ips


async def fetch_dynamic_target_pool() -> List[Dict]:
    """
    Dynamically resolves real cities and countries worldwide via ip-api.com
    so target destinations cover the entire globe with zero hardcoded cities.
    """
    raw_targets = [{"ip": ip} for ip in generate_random_public_ips(100)]
    headers = {"User-Agent": "SOC-ThreatMap-OSINT/2.0"}
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


async def fetch_custom_user_pool(user_id: int) -> List[Dict]:
    """
    Fetches and geolocates IPs from the user's configured custom_sources.
    Supports both remote feed URLs (plain text, JSON, CSV) and direct IPv4 entries.
    """
    sources = get_user_custom_sources(user_id)
    if not sources:
        return []

    sources_hash = json.dumps(sources, sort_keys=True)
    cached = manager.user_custom_pools.get(user_id)
    now = time.time()
    if cached and cached["hash"] == sources_hash and (now - cached["ts"] < 300):
        return cached["pool"]

    raw_by_ip: Dict[str, Dict] = {}
    headers = {"User-Agent": "SOC-ThreatMap-Custom/2.0"}
    common_ports = [22, 80, 443, 445, 3389, 8080]

    async with httpx.AsyncClient(timeout=10.0, headers=headers, follow_redirects=True) as client:
        for src in sources:
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
                }
                continue

            # Remote feed URL
            fetch_url = feed_url if feed_url.startswith(("http://", "https://")) else f"https://{feed_url}"
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
                                    "port": int(port_part) if (port_part and port_part.isdigit()) else random.choice(common_ports),
                                    "raw_name": feed_name,
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
    raw_by_ip: Dict[str, Dict] = {}
    headers = {"User-Agent": "SOC-ThreatMap-OSINT/2.0"}

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

        # 3. URLhaus Live Online Servers
        try:
            resp = await client.get("https://urlhaus.abuse.ch/downloads/text_online/")
            if resp.status_code == 200:
                lines = [l for l in resp.text.splitlines() if not l.startswith("#") and l.strip()]
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
                                "port": int(port_part) if (port_part and port_part.isdigit()) else 80,
                                "raw_name": family,
                            }
        except Exception as e:
            logger.warning(f"URLhaus fetch warning: {e}")

        # 4. CINS Active Badguys
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

        enriched_pool = await geolocate_raw_pool(client, raw_pool, max_ips=200)
        distinct_countries = len({i["srcCode"] for i in enriched_pool})
        logger.info(
            f"Verified {len(enriched_pool)} real threats across {distinct_countries} distinct countries."
        )

    return enriched_pool


def build_attack_event(item: Dict, target_pool: List[Dict], feed_mode: str = "live") -> Dict:
    src_country = item["srcCountry"]
    src_code = item["srcCode"]
    src_city = item["srcCity"]
    src_asn = item["srcAsn"]
    src_lat = item["srcLat"]
    src_lon = item["srcLon"]

    candidates = [n for n in target_pool if n["code"] != src_code]
    dst = random.choice(candidates if candidates else target_pool)

    port = item.get("port", 443)
    intel = enrich_threat_metadata(item.get("raw_name", ""), port)

    return {
        "feedMode": feed_mode,
        "srcIp": item.get("ip", "N/A"),
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


async def osint_worker():
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

        # Broadcast to clients in LIVE mode
        if ioc_pool and target_pool:
            live_item = random.choice(ioc_pool)
            await manager.broadcast_live(build_attack_event(live_item, target_pool, feed_mode="live"))

        # Stream custom feed events to authenticated clients in CUSTOM mode
        custom_clients = [
            (ws, meta["user_id"])
            for ws, meta in list(manager.clients.items())
            if meta.get("mode") == "custom" and meta.get("user_id") is not None
        ]
        for ws, user_id in custom_clients:
            user_pool = await fetch_custom_user_pool(user_id)
            if user_pool and target_pool:
                custom_item = random.choice(user_pool)
                await manager.send_to_client(
                    ws, build_attack_event(custom_item, target_pool, feed_mode="custom")
                )

        await asyncio.sleep(random.uniform(0.8, 1.7))


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
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


# =====================================================================
# AUTHENTICATION & USER PROFILE API ROUTES
# =====================================================================

@app.post("/api/register")
async def register_user(req: AuthRequest):
    username = req.username.strip()
    if len(username) < 3 or len(req.password) < 4:
        raise HTTPException(status_code=400, detail="Username (min 3) and password (min 4) required.")

    salt = secrets.token_hex(16)
    pwd_hash = hash_password(req.password, salt)
    now = time.time()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, avatar, custom_sources, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (username, pwd_hash, salt, req.avatar or "", "[]", now),
        )
        user_id = cursor.lastrowid
        token = secrets.token_urlsafe(32)
        cursor.execute(
            "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
            (token, user_id, now),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="Username already exists.")
    conn.close()

    return {
        "token": token,
        "user": {
            "id": user_id,
            "username": username,
            "avatar": req.avatar or "",
            "custom_sources": [],
        },
    }


@app.post("/api/login")
async def login_user(req: AuthRequest):
    username = req.username.strip()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()

    if not row or hash_password(req.password, row["salt"]) != row["password_hash"]:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = secrets.token_urlsafe(32)
    cursor.execute(
        "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
        (token, row["id"], time.time()),
    )
    conn.commit()
    conn.close()

    return {
        "token": token,
        "user": {
            "id": row["id"],
            "username": row["username"],
            "avatar": row["avatar"] or "",
            "custom_sources": json.loads(row["custom_sources"] or "[]"),
        },
    }


@app.get("/api/me")
async def get_current_user(authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return {"user": user}


@app.post("/api/profile/avatar")
async def update_avatar(req: AvatarUpdateRequest, authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET avatar = ? WHERE id = ?", (req.avatar, user["id"]))
    conn.commit()
    conn.close()

    user["avatar"] = req.avatar
    return {"user": user}


@app.post("/api/profile/sources")
async def update_custom_sources(req: CustomSourcesUpdateRequest, authorization: Optional[str] = Header(None)):
    user = get_user_by_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")

    sources_json = json.dumps(req.custom_sources)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET custom_sources = ? WHERE id = ?", (sources_json, user["id"]))
    conn.commit()
    conn.close()

    manager.invalidate_user_cache(user["id"])
    user["custom_sources"] = req.custom_sources
    return {"user": user}


@app.post("/api/logout")
async def logout_user(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1].strip()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            raw_msg = await websocket.receive_text()
            try:
                msg = json.loads(raw_msg)
                if msg.get("action") == "set_mode":
                    manager.set_client_mode(
                        websocket,
                        mode=msg.get("mode", "live"),
                        token=msg.get("token"),
                    )
            except Exception:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)


frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")