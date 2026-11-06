"""
OSINT Threat Taxonomy & Event Builder
=====================================
Maps raw malware names and TCP/UDP port numbers to MITRE ATT&CK techniques,
CVEs, categories, and severity levels, and constructs normalized attack events.
"""

import random
from typing import Dict, List

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


def enrich_threat_metadata(raw_name: str, port: int) -> Dict:
    """Enriches raw malware/feed names and destination ports with MITRE, CVE, and severity metadata."""
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


def build_attack_event(item: Dict, target_pool: List[Dict], feed_mode: str = "live") -> Dict:
    """Pairs an enriched attacker IOC with a random global destination and returns a telemetry payload."""
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
        "dstIp": dst.get("ip", "N/A"),
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
