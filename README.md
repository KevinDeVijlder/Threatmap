
<div align="center">

# ⚡ Threat map // 2D OSINT ATTACK MAP

**A real-time, hardware-accelerated 2D global cyber threat visualizer powered by live Open-Source Intelligence (OSINT).**

![Python](https://img.shields.io/badge/Python-3.11%2B-006FFF?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-Async_WS-006FFF?style=for-the-badge&logo=fastapi&logoColor=white)
![D3.js](https://img.shields.io/badge/D3.js-Geo_Vector-006FFF?style=for-the-badge&logo=d3.js&logoColor=white)
![HTML5 Canvas](https://img.shields.io/badge/HTML5-60FPS_Canvas-006FFF?style=for-the-badge&logo=html5&logoColor=white)
![OSINT](https://img.shields.io/badge/OSINT-abuse.ch_Live-00F0FF?style=for-the-badge)

</div>

---

### Overview
**Threat map** is a dark-themed, tactical 2D cyber threat map built for Security Operations Center (SOC) wallboards, homelab displays, and public threat monitoring. 

Unlike static mockups or synthetic "pew-pew" toys, this application ingests **live, unauthenticated Open-Source Intelligence (OSINT)** from **abuse.ch Feodo Tracker** and **ThreatFox**, geolocates active Botnet Command & Control (C2) servers and malware distribution hosts, and streams real-time ballistic trajectory arcs to connected browsers over WebSockets.

---

### Project Structure

``` bash
soc-threat-map/
├── backend/
│   ├── data/
│   │   └── GeoLite2-City.mmdb    # Optional local MaxMind GeoIP binary
│   ├── main.py                   # FastAPI OSINT collector & WebSocket server
│   └── requirements.txt          # Python dependencies
├── frontend/
│   ├── css/
│   │   └── style.css             # Tactical HUD & Electric Blue theme
│   ├── data/
│   │   └── countries-110m.json   # Natural Earth TopoJSON vector dataset
│   ├── js/
│   │   └── main.js               # Vector map, hit-mask & ballistic arc engine
│   └── index.html                # Main SOC dashboard layout
├── .gitignore
└── README.md
```

### Quick Start

#### 1. Clone the Repository
```Bash
git clone https://github.com/KevinDeVijlder/Threatmap.git
cd soc-threat-map
```

#### 2. Set Up the Python Backend
```Bash
cd backend
python3 -m venv venv
```

**Activate the virtual environment:**
Linux / macOS:

```Bash
source venv/bin/activate
```

Windows (Git Bash / UCRT64):

```Bash
source venv/Scripts/activate
```

Windows (PowerShell):
```PowerShell
.\venv\Scripts\Activate.ps1
```

**Install the dependencies:**

```Bash
pip install -r requirements.txt
```

#### 3. Launch the SOC Server
```Bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload --reload-exclude "venv"
```

Open http://localhost:8000/ in your browser. The top-left status indicator will lock to LIVE OSINT FEED CONNECTED and real-time global threat arcs will begin streaming immediately.

### Roadmap
[x] 2D Smooth Vector World Map with #006FFF hover illumination

[x] Ballistic Bézier trajectory arcs & impact shockwaves

[x] Live unauthenticated OSINT ingestion (abuse.ch Feodo Tracker & ThreatFox)

[x] Top 10 Attacking Nations leaderboard with client-side persistence

[ ] Server-Side Persistence: SQLite database for long-term historical attack metrics

[ ] Self-Hosted Firewall / SIEM Mode: Toggleable mode to ingest live WAN drops & IDS/IPS alerts via remote Syslog/CEF (UniFi Dream Machine, pfSense, OPNsense, Suricata)

[ ] Honeypot Integration: Native webhook/socket listener for Cowrie & T-Pot instances

[ ] Containerization: Single-command docker-compose.yml deployment with Nginx reverse proxy support

### License
Distributed under the MIT License. Built for cybersecurity enthusiasts, homelabbers, and SOC analysts.