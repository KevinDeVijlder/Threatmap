"""
Backend Configuration & Constants
=================================
Centralizes file paths, regular expressions, HTTP headers, and logging configuration.
"""

import logging
import os
import re

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("OSINT_ENGINE")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "soc_matrix.db")
FRONTEND_PATH = os.path.join(BASE_DIR, "..", "frontend")

IPV4_REGEX = re.compile(r"(?:https?://)?(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?")

OSINT_USER_AGENT = "SOC-ThreatMap-OSINT/2.0"
CUSTOM_USER_AGENT = "SOC-ThreatMap-Custom/2.0"
COMMON_PORTS = [22, 23, 80, 443, 445, 3389, 8080]

# Built-in Default OSINT Feeds (Always active for guests; individually toggleable for authenticated operators)
DEFAULT_OSINT_FEEDS = [
    {
        "id": "feodo_tracker",
        "name": "FEODO TRACKER C2",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        "description": "Abuse.ch Botnet Command & Control (C2) Server Blocklist",
        "is_default": True,
        "enabled": True,
    },
    {
        "id": "threatfox",
        "name": "ABUSE.CH THREATFOX",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "description": "Recent Malware & Payload Host IOCs from Abuse.ch ThreatFox",
        "is_default": True,
        "enabled": True,
    },
    {
        "id": "urlhaus",
        "name": "ABUSE.CH URLHAUS",
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "description": "Active Malware Distribution & Botnet Dropper Servers",
        "is_default": True,
        "enabled": True,
    },
    {
        "id": "cins_army",
        "name": "CINS ARMY BADGUYS",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "description": "Verified Active Reconnaissance Scanners & Brute-Force Hosts",
        "is_default": True,
        "enabled": True,
    },
]
DEFAULT_FEED_IDS = {f["id"] for f in DEFAULT_OSINT_FEEDS}
DEFAULT_FEED_URLS = {f["url"] for f in DEFAULT_OSINT_FEEDS}
