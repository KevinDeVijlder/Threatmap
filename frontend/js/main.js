/**
 * SOC Threat Matrix - Persistent OSINT Attack Map Engine
 * - Live WebSocket ingestion from FastAPI backend
 * - Persistent stats via localStorage (survives page reloads)
 * - Pure real-world OSINT traffic visualization
 */

const CONFIG = {
  leftReservedWidth: 360,
  rightReservedWidth: 360,
  topReservedHeight: 70,
  paddingBottom: 30,

  primaryColor: "#006FFF",
  primaryGlow: "rgba(0, 111, 255, 0.65)",

  landFill: "#0b1424",
  landStroke: "rgba(0, 111, 255, 0.32)",
  landStrokeWidth: 0.75,

  hoverFill: "#006FFF",
  hoverStroke: "#00F0FF",
  hoverStrokeWidth: 1.5,
  hoverGlowBlur: 18,

  gridStroke: "rgba(0, 111, 255, 0.08)",

  arcSpeedMin: 0.003,
  arcSpeedMax: 0.0055,

  wsUrl: `ws://${window.location.hostname || "localhost"}:8000/ws`,
};

const COUNTRY_LOOKUP = {
  4: { name: "Afghanistan", code: "af" },
  8: { name: "Albania", code: "al" },
  12: { name: "Algeria", code: "dz" },
  24: { name: "Angola", code: "ao" },
  32: { name: "Argentina", code: "ar" },
  36: { name: "Australia", code: "au" },
  40: { name: "Austria", code: "at" },
  50: { name: "Bangladesh", code: "bd" },
  56: { name: "Belgium", code: "be" },
  68: { name: "Bolivia", code: "bo" },
  76: { name: "Brazil", code: "br" },
  100: { name: "Bulgaria", code: "bg" },
  124: { name: "Canada", code: "ca" },
  152: { name: "Chile", code: "cl" },
  156: { name: "China", code: "cn" },
  170: { name: "Colombia", code: "co" },
  188: { name: "Costa Rica", code: "cr" },
  191: { name: "Croatia", code: "hr" },
  192: { name: "Cuba", code: "cu" },
  203: { name: "Czech Republic", code: "cz" },
  208: { name: "Denmark", code: "dk" },
  218: { name: "Ecuador", code: "ec" },
  818: { name: "Egypt", code: "eg" },
  233: { name: "Estonia", code: "ee" },
  231: { name: "Ethiopia", code: "et" },
  246: { name: "Finland", code: "fi" },
  250: { name: "France", code: "fr" },
  266: { name: "Gabon", code: "ga" },
  268: { name: "Georgia", code: "ge" },
  276: { name: "Germany", code: "de" },
  288: { name: "Ghana", code: "gh" },
  300: { name: "Greece", code: "gr" },
  320: { name: "Guatemala", code: "gt" },
  348: { name: "Hungary", code: "hu" },
  352: { name: "Iceland", code: "is" },
  356: { name: "India", code: "in" },
  360: { name: "Indonesia", code: "id" },
  364: { name: "Iran", code: "ir" },
  368: { name: "Iraq", code: "iq" },
  372: { name: "Ireland", code: "ie" },
  376: { name: "Israel", code: "il" },
  380: { name: "Italy", code: "it" },
  392: { name: "Japan", code: "jp" },
  400: { name: "Jordan", code: "jo" },
  398: { name: "Kazakhstan", code: "kz" },
  404: { name: "Kenya", code: "ke" },
  410: { name: "South Korea", code: "kr" },
  414: { name: "Kuwait", code: "kw" },
  428: { name: "Latvia", code: "lv" },
  434: { name: "Libya", code: "ly" },
  440: { name: "Lithuania", code: "lt" },
  442: { name: "Luxembourg", code: "lu" },
  458: { name: "Malaysia", code: "my" },
  484: { name: "Mexico", code: "mx" },
  504: { name: "Morocco", code: "ma" },
  528: { name: "Netherlands", code: "nl" },
  554: { name: "New Zealand", code: "nz" },
  566: { name: "Nigeria", code: "ng" },
  578: { name: "Norway", code: "no" },
  586: { name: "Pakistan", code: "pk" },
  604: { name: "Peru", code: "pe" },
  608: { name: "Philippines", code: "ph" },
  616: { name: "Poland", code: "pl" },
  620: { name: "Portugal", code: "pt" },
  642: { name: "Romania", code: "ro" },
  643: { name: "Russia", code: "ru" },
  682: { name: "Saudi Arabia", code: "sa" },
  702: { name: "Singapore", code: "sg" },
  703: { name: "Slovakia", code: "sk" },
  705: { name: "Slovenia", code: "si" },
  710: { name: "South Africa", code: "za" },
  724: { name: "Spain", code: "es" },
  752: { name: "Sweden", code: "se" },
  756: { name: "Switzerland", code: "ch" },
  764: { name: "Thailand", code: "th" },
  788: { name: "Tunisia", code: "tn" },
  792: { name: "Turkey", code: "tr" },
  804: { name: "Ukraine", code: "ua" },
  784: { name: "United Arab Emirates", code: "ae" },
  826: { name: "United Kingdom", code: "gb" },
  840: { name: "United States", code: "us" },
  858: { name: "Uruguay", code: "uy" },
  860: { name: "Uzbekistan", code: "uz" },
  862: { name: "Venezuela", code: "ve" },
  704: { name: "Vietnam", code: "vn" }
};

class ThreatMap {
  constructor() {
    this.canvas = document.getElementById("threat-map");
    this.ctx = this.canvas.getContext("2d");

    this.coordsHud = document.getElementById("coords-hud");
    this.hudAttacksTotal = document.getElementById("hud-attacks-total");
    this.hudActiveOrigins = document.getElementById("hud-active-origins");
    this.hudClock = document.getElementById("hud-clock");
    this.connStatus = document.getElementById("conn-status");
    this.connLabel = document.getElementById("conn-label");

    this.countryIntelPanel = document.getElementById("country-intel");
    this.countryNameEl = document.getElementById("country-name");
    this.countryCodeEl = document.getElementById("country-code");
    this.countryFlagEl = document.getElementById("country-flag");
    this.flagPlaceholderEl = document.getElementById("flag-placeholder");
    this.attackTicker = document.getElementById("attack-ticker");
    this.leaderboardList = document.getElementById("leaderboard-list");
    this.leaderboardTotalHits = document.getElementById("leaderboard-total-hits");

    this.countryFeatures = [];
    this.featureCollection = null;
    this.pixelRatio = window.devicePixelRatio || 1;

    this.projection = null;
    this.geoPath = null;
    this.graticule = d3.geoGraticule().extent([[-180, -60], [180, 85]]).step([15, 15]);

    this.maskData = null;
    this.maskW = 0;
    this.maskH = 0;
    this.hoveredCountryIndex = null;

    this.attacks = [];
    this.ripples = [];

    // Load persistent stats from localStorage
    this.totalAttacksCount = parseInt(localStorage.getItem("soc_total_attacks") || "0", 10);
    const savedStats = localStorage.getItem("soc_country_stats");
    this.countryStats = savedStats ? new Map(JSON.parse(savedStats)) : new Map();

    this.ws = null;
    this.isWsConnected = false;

    this.init();
  }

  async init() {
    this.startClock();
    this.bindEvents();

    // Render initial saved stats immediately on load
    this.hudAttacksTotal.textContent = this.totalAttacksCount.toLocaleString();
    this.hudActiveOrigins.textContent = `${this.countryStats.size} REGIONS`;
    this.updateLeaderboard();

    await this.loadCartography();
    this.resize();

    this.animate();
    this.connectWebSocket();
  }

  async loadCartography() {
    try {
      let data;
      try {
        const localRes = await fetch("data/countries-110m.json");
        if (!localRes.ok) throw new Error("Local file not found");
        data = await localRes.json();
      } catch {
        const cdnRes = await fetch("https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json");
        data = await cdnRes.json();
      }

      const allFeatures = topojson.feature(data, data.objects.countries).features;
      this.countryFeatures = allFeatures.filter(feature => parseInt(feature.id, 10) !== 10);

      this.featureCollection = {
        type: "FeatureCollection",
        features: this.countryFeatures
      };
    } catch (e) {
      console.error("Failed to load map topology data:", e);
    }
  }

  resize() {
    const width = window.innerWidth;
    const height = window.innerHeight;
    this.pixelRatio = window.devicePixelRatio || 1;

    this.canvas.width = Math.round(width * this.pixelRatio);
    this.canvas.height = Math.round(height * this.pixelRatio);
    this.canvas.style.width = `${width}px`;
    this.canvas.style.height = `${height}px`;

    const mapX = CONFIG.leftReservedWidth;
    const mapY = CONFIG.topReservedHeight;
    const mapW = Math.max(300, width - CONFIG.leftReservedWidth - CONFIG.rightReservedWidth);
    const mapH = Math.max(200, height - mapY - CONFIG.paddingBottom);

    if (this.featureCollection) {
      this.projection = d3.geoEquirectangular()
        .fitExtent([[mapX, mapY], [mapX + mapW, mapY + mapH]], this.featureCollection);

      this.geoPath = d3.geoPath(this.projection, this.ctx);
      this.generateHitMask(width, height);
    }
  }

  generateHitMask(width, height) {
    this.maskW = Math.round(width);
    this.maskH = Math.round(height);

    const offscreen = document.createElement("canvas");
    offscreen.width = this.maskW;
    offscreen.height = this.maskH;
    const offCtx = offscreen.getContext("2d");
    offCtx.imageSmoothingEnabled = false;

    const maskPath = d3.geoPath(this.projection, offCtx);
    offCtx.clearRect(0, 0, this.maskW, this.maskH);

    for (let i = 0; i < this.countryFeatures.length; i++) {
      const countryIdx = i + 1;
      const r = (countryIdx >> 16) & 255;
      const g = (countryIdx >> 8) & 255;
      const b = countryIdx & 255;

      offCtx.fillStyle = `rgb(${r},${g},${b})`;
      offCtx.beginPath();
      maskPath(this.countryFeatures[i]);
      offCtx.fill();
    }

    this.maskData = offCtx.getImageData(0, 0, this.maskW, this.maskH).data;
  }

  connectWebSocket() {
    try {
      this.ws = new WebSocket(CONFIG.wsUrl);

      this.ws.onopen = () => {
        this.isWsConnected = true;
        this.connStatus.style.backgroundColor = "var(--color-primary)";
        this.connLabel.textContent = "LIVE OSINT FEED CONNECTED";
      };

      this.ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          this.triggerAttack(payload);
        } catch (err) {
          console.error("Failed to parse event:", err);
        }
      };

      this.ws.onclose = () => {
        this.isWsConnected = false;
        this.connStatus.style.backgroundColor = "rgba(255, 170, 0, 0.8)";
        this.connLabel.textContent = "RECONNECTING TO STREAM...";
        setTimeout(() => this.connectWebSocket(), 4000);
      };

      this.ws.onerror = () => {
        if (this.ws) this.ws.close();
      };
    } catch {
      setTimeout(() => this.connectWebSocket(), 4000);
    }
  }

  triggerAttack(data) {
    if (!this.projection) return;

    const srcScreen = this.projection([data.srcLon, data.srcLat]);
    const dstScreen = this.projection([data.dstLon, data.dstLat]);

    if (!srcScreen || !dstScreen) return;

    const dx = dstScreen[0] - srcScreen[0];
    const dy = dstScreen[1] - srcScreen[1];
    const dist = Math.sqrt(dx * dx + dy * dy);

    const midX = (srcScreen[0] + dstScreen[0]) / 2;
    const midY = (srcScreen[1] + dstScreen[1]) / 2;
    const archAltitude = Math.min(180, Math.max(35, dist * 0.28));
    const controlPoint = { x: midX, y: midY - archAltitude };

    const speed = CONFIG.arcSpeedMin + Math.random() * (CONFIG.arcSpeedMax - CONFIG.arcSpeedMin);

    const attackObj = {
      id: Math.random().toString(36).substr(2, 9),
      start: { x: srcScreen[0], y: srcScreen[1] },
      control: controlPoint,
      end: { x: dstScreen[0], y: dstScreen[1] },
      progress: 0,
      speed: speed,
      color: CONFIG.primaryColor,
      trailLength: 0.16,
      data: data,
    };

    this.attacks.push(attackObj);
    this.totalAttacksCount++;

    this.addRipple(srcScreen[0], srcScreen[1], CONFIG.primaryColor, 14, 0.85);
    this.recordCountryHit(data.srcCode, data.srcCountry);

    // Persist to localStorage
    localStorage.setItem("soc_total_attacks", this.totalAttacksCount.toString());

    this.hudAttacksTotal.textContent = this.totalAttacksCount.toLocaleString();
    this.appendTickerRow(data);
  }

  recordCountryHit(code, name) {
    if (!this.countryStats.has(code)) {
      this.countryStats.set(code, { code, name, count: 0 });
    }
    this.countryStats.get(code).count++;

    // Save Map state to localStorage
    localStorage.setItem("soc_country_stats", JSON.stringify(Array.from(this.countryStats.entries())));

    this.hudActiveOrigins.textContent = `${this.countryStats.size} REGIONS`;
    this.updateLeaderboard();
  }

  updateLeaderboard() {
    const sorted = Array.from(this.countryStats.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const maxHits = sorted.length > 0 ? sorted[0].count : 1;
    this.leaderboardTotalHits.textContent = `${this.totalAttacksCount.toLocaleString()} HITS`;

    this.leaderboardList.innerHTML = sorted.map((item, index) => {
      const pct = Math.round((item.count / maxHits) * 100);
      return `
        <div class="leaderboard-row">
          <div class="leaderboard-main">
            <div class="leaderboard-left">
              <span class="leaderboard-rank">#${index + 1}</span>
              <img class="leaderboard-flag" src="https://flagcdn.com/w40/${item.code.toLowerCase()}.png" alt="${item.name}" />
              <span class="leaderboard-name">${item.name}</span>
            </div>
            <span class="leaderboard-hits">${item.count}</span>
          </div>
          <div class="leaderboard-bar-track">
            <div class="leaderboard-bar-fill" style="width: ${pct}%"></div>
          </div>
        </div>
      `;
    }).join("");
  }

  addRipple(x, y, color, maxRadius = 24, maxOpacity = 0.8) {
    this.ripples.push({ x, y, radius: 2, maxRadius, opacity: maxOpacity, color });
  }

  appendTickerRow(data) {
    const row = document.createElement("div");
    row.className = "ticker-row";
    row.innerHTML = `
      <div class="ticker-left">
        <span class="ticker-badge">${data.name}</span>
        <span class="ticker-origin">${data.srcCountry} → ${data.dstCountry}</span>
      </div>
      <div class="ticker-right">
        <span>PORT: <span class="ticker-port">${data.port}</span></span>
        <span>${data.proto}</span>
      </div>
    `;

    const empty = this.attackTicker.querySelector(".ticker-empty");
    if (empty) empty.remove();

    this.attackTicker.insertBefore(row, this.attackTicker.firstChild);
    while (this.attackTicker.children.length > 5) {
      this.attackTicker.removeChild(this.attackTicker.lastChild);
    }
  }

  getBezierPoint(t, p0, p1, p2) {
    const inv = 1 - t;
    return {
      x: inv * inv * p0.x + 2 * inv * t * p1.x + t * t * p2.x,
      y: inv * inv * p0.y + 2 * inv * t * p1.y + t * t * p2.y,
    };
  }

  renderAttacks() {
    const ctx = this.ctx;

    for (let i = this.ripples.length - 1; i >= 0; i--) {
      const rip = this.ripples[i];
      rip.radius += 0.55;
      rip.opacity -= 0.015;

      if (rip.opacity <= 0 || rip.radius >= rip.maxRadius) {
        this.ripples.splice(i, 1);
        continue;
      }

      ctx.save();
      ctx.strokeStyle = rip.color;
      ctx.globalAlpha = Math.max(0, rip.opacity);
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.arc(rip.x, rip.y, rip.radius, 0, Math.PI * 2);
      ctx.stroke();
      ctx.restore();
    }

    for (let i = this.attacks.length - 1; i >= 0; i--) {
      const atk = this.attacks[i];
      atk.progress += atk.speed;

      if (atk.progress >= 1) {
        this.addRipple(atk.end.x, atk.end.y, CONFIG.primaryColor, 32, 1.0);
        this.attacks.splice(i, 1);
        continue;
      }

      ctx.save();

      ctx.strokeStyle = CONFIG.primaryColor;
      ctx.globalAlpha = 0.32;
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.moveTo(atk.start.x, atk.start.y);
      ctx.quadraticCurveTo(atk.control.x, atk.control.y, atk.end.x, atk.end.y);
      ctx.stroke();

      const tailT = Math.max(0, atk.progress - atk.trailLength);
      const headT = atk.progress;
      const segments = 12;

      for (let s = 0; s < segments; s++) {
        const t1 = tailT + (s / segments) * (headT - tailT);
        const t2 = tailT + ((s + 1) / segments) * (headT - tailT);

        const pt1 = this.getBezierPoint(t1, atk.start, atk.control, atk.end);
        const pt2 = this.getBezierPoint(t2, atk.start, atk.control, atk.end);
        const segAlpha = (s + 1) / segments;

        ctx.strokeStyle = CONFIG.primaryColor;
        ctx.globalAlpha = segAlpha * 0.95;
        ctx.lineWidth = 1.4 + segAlpha * 2.2;
        ctx.beginPath();
        ctx.moveTo(pt1.x, pt1.y);
        ctx.lineTo(pt2.x, pt2.y);
        ctx.stroke();
      }

      const headPt = this.getBezierPoint(headT, atk.start, atk.control, atk.end);
      ctx.shadowColor = CONFIG.primaryColor;
      ctx.shadowBlur = 14;
      ctx.fillStyle = "#FFFFFF";
      ctx.globalAlpha = 1.0;
      ctx.beginPath();
      ctx.arc(headPt.x, headPt.y, 2.6, 0, Math.PI * 2);
      ctx.fill();

      ctx.restore();
    }
  }

  render() {
    const ctx = this.ctx;
    ctx.setTransform(this.pixelRatio, 0, 0, this.pixelRatio, 0, 0);
    ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);

    if (!this.geoPath) return;

    ctx.save();
    ctx.strokeStyle = CONFIG.gridStroke;
    ctx.lineWidth = 0.75;
    ctx.setLineDash([2, 4]);
    ctx.beginPath();
    this.geoPath(this.graticule);
    ctx.stroke();
    ctx.restore();

    ctx.save();
    ctx.fillStyle = CONFIG.landFill;
    ctx.strokeStyle = CONFIG.landStroke;
    ctx.lineWidth = CONFIG.landStrokeWidth;

    for (let i = 0; i < this.countryFeatures.length; i++) {
      if (i + 1 === this.hoveredCountryIndex) continue;
      ctx.beginPath();
      this.geoPath(this.countryFeatures[i]);
      ctx.fill();
      ctx.stroke();
    }
    ctx.restore();

    if (this.hoveredCountryIndex !== null) {
      const feature = this.countryFeatures[this.hoveredCountryIndex - 1];
      if (feature) {
        ctx.save();
        ctx.fillStyle = CONFIG.hoverFill;
        ctx.strokeStyle = CONFIG.hoverStroke;
        ctx.lineWidth = CONFIG.hoverStrokeWidth;
        ctx.shadowColor = CONFIG.hoverFill;
        ctx.shadowBlur = CONFIG.hoverGlowBlur;

        ctx.beginPath();
        this.geoPath(feature);
        ctx.fill();
        ctx.stroke();
        ctx.restore();
      }
    }

    this.renderAttacks();
  }

  animate() {
    this.render();
    requestAnimationFrame(() => this.animate());
  }

  updateIntelPanel(countryIndex) {
    if (!countryIndex || countryIndex <= 0 || countryIndex > this.countryFeatures.length) {
      this.countryIntelPanel.classList.remove("active");
      this.countryIntelPanel.classList.add("idle");
      this.countryNameEl.textContent = "STANDBY";
      this.countryCodeEl.textContent = "GEO // NONE";
      this.countryFlagEl.style.display = "none";
      this.flagPlaceholderEl.style.display = "block";
      return;
    }

    const feature = this.countryFeatures[countryIndex - 1];
    const numericId = parseInt(feature.id, 10);
    const meta = COUNTRY_LOOKUP[numericId];

    this.countryIntelPanel.classList.add("active");
    this.countryIntelPanel.classList.remove("idle");

    if (meta) {
      this.countryNameEl.textContent = meta.name.toUpperCase();
      this.countryCodeEl.textContent = `ISO: ${meta.code.toUpperCase()} // ID: ${numericId}`;
      
      this.countryFlagEl.src = `https://flagcdn.com/w80/${meta.code.toLowerCase()}.png`;
      this.countryFlagEl.onload = () => {
        this.countryFlagEl.style.display = "block";
        this.flagPlaceholderEl.style.display = "none";
      };
      this.countryFlagEl.onerror = () => {
        this.countryFlagEl.style.display = "none";
        this.flagPlaceholderEl.style.display = "block";
      };
    } else {
      this.countryNameEl.textContent = `TERRITORY [${numericId}]`;
      this.countryCodeEl.textContent = `GEO_ID: ${numericId}`;
      this.countryFlagEl.style.display = "none";
      this.flagPlaceholderEl.style.display = "block";
    }
  }

  bindEvents() {
    window.addEventListener("resize", () => {
      this.resize();
    });

    // Handle background tab throttling: clear backlog on return to prevent burst rendering
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") {
        this.attacks = [];
        this.ripples = [];
      }
    });

    this.canvas.addEventListener("mousemove", (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      let detectedCountryIdx = null;

      if (this.projection) {
        const coords = this.projection.invert([mouseX, mouseY]);
        if (coords && coords[0] >= -180 && coords[0] <= 180 && coords[1] >= -60 && coords[1] <= 85) {
          const [lon, lat] = coords;
          const latDir = lat >= 0 ? "N" : "S";
          const lonDir = lon >= 0 ? "E" : "W";
          this.coordsHud.textContent = `LAT: ${Math.abs(lat).toFixed(2)}° ${latDir} | LON: ${Math.abs(lon).toFixed(2)}° ${lonDir}`;
        } else {
          this.coordsHud.textContent = "LAT: --.--° | LON: --.--°";
        }
      }

      const px = Math.floor(mouseX);
      const py = Math.floor(mouseY);
      if (this.maskData && px >= 0 && px < this.maskW && py >= 0 && py < this.maskH) {
        const idx = (py * this.maskW + px) * 4;
        const alpha = this.maskData[idx + 3];

        if (alpha > 64) {
          const r = this.maskData[idx];
          const g = this.maskData[idx + 1];
          const b = this.maskData[idx + 2];
          const candidate = (r << 16) | (g << 8) | b;
          if (candidate >= 1 && candidate <= this.countryFeatures.length) {
            detectedCountryIdx = candidate;
          }
        }
      }

      if (detectedCountryIdx !== this.hoveredCountryIndex) {
        this.hoveredCountryIndex = detectedCountryIdx;
        this.updateIntelPanel(detectedCountryIdx);
      }
    });

    this.canvas.addEventListener("mouseleave", () => {
      if (this.hoveredCountryIndex !== null) {
        this.hoveredCountryIndex = null;
        this.updateIntelPanel(null);
      }
    });
  }

  startClock() {
    const update = () => {
      const now = new Date();
      this.hudClock.textContent = now.toTimeString().split(" ")[0] + " UTC";
    };
    update();
    setInterval(update, 1000);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  window.threatMap = new ThreatMap();
});