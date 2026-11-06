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
