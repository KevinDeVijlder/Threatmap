/**
 * SOC Threat Matrix - Symmetrical Ballistic Attack Arc Engine
 * - Symmetrical map bounds (left and right columns reserved equally at 360px)
 * - Trajectory arcs in electric blue (#006FFF)
 * - Trajectory lines stay fully drawn until the projectile arrives at the destination
 * - Projectile speed reduced ~2.5x so travel takes 3-5 seconds
 * - Header stats: TOTAL ATTACKS COUNTED and ACTIVE ORIGINS
 * - Real-time Top 10 Attacking Nations leaderboard with dynamic sorting
 */

const CONFIG = {
  // Homelab SOC Target Coordinates [Longitude, Latitude] (Bertem, Belgium)
  targetCoords: [4.63, 50.86],

  // Symmetrical Layout Margins
  leftReservedWidth: 360,
  rightReservedWidth: 360,
  topReservedHeight: 70,
  paddingBottom: 30,

  // Unified Primary Palette
  primaryColor: "#006FFF",
  primaryGlow: "rgba(0, 111, 255, 0.65)",

  // Land Styling
  landFill: "#0b1424",
  landStroke: "rgba(0, 111, 255, 0.32)",
  landStrokeWidth: 0.75,

  // Hover Highlight
  hoverFill: "#006FFF",
  hoverStroke: "#00F0FF",
  hoverStrokeWidth: 1.5,
  hoverGlowBlur: 18,

  // Grid
  gridStroke: "rgba(0, 111, 255, 0.08)",

  // Slower projectile speeds (~3-5 seconds in flight at 60 FPS)
  arcSpeedMin: 0.003,
  arcSpeedMax: 0.0055,
};

// Attack Categorization
const ATTACK_TYPES = [
  { name: "SSH_BRUTE", port: 22, proto: "TCP" },
  { name: "HTTPS_EXPLOIT", port: 443, proto: "TCP" },
  { name: "PORT_SCAN", port: 8080, proto: "TCP" },
  { name: "RDP_PROBE", port: 3389, proto: "TCP" },
  { name: "DNS_AMP", port: 53, proto: "UDP" },
  { name: "SMB_SWEEP", port: 445, proto: "TCP" },
];

// Attacker Origins for Simulation
const SAMPLE_ORIGINS = [
  { country: "China", code: "cn", lat: 39.9, lon: 116.4 },
  { country: "United States", code: "us", lat: 37.7, lon: -122.4 },
  { country: "Russia", code: "ru", lat: 55.75, lon: 37.6 },
  { country: "Brazil", code: "br", lat: -23.5, lon: -46.6 },
  { country: "Germany", code: "de", lat: 52.5, lon: 13.4 },
  { country: "Netherlands", code: "nl", lat: 52.3, lon: 4.9 },
  { country: "India", code: "in", lat: 28.6, lon: 77.2 },
  { country: "Singapore", code: "sg", lat: 1.35, lon: 103.8 },
  { country: "South Korea", code: "kr", lat: 37.5, lon: 126.9 },
  { country: "United Kingdom", code: "gb", lat: 51.5, lon: -0.12 },
  { country: "France", code: "fr", lat: 48.8, lon: 2.35 },
  { country: "Canada", code: "ca", lat: 45.4, lon: -75.7 },
  { country: "Vietnam", code: "vn", lat: 21.0, lon: 105.8 },
  { country: "Australia", code: "au", lat: -33.8, lon: 151.2 }
];

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

    // Header HUD
    this.coordsHud = document.getElementById("coords-hud");
    this.hudAttacksTotal = document.getElementById("hud-attacks-total");
    this.hudActiveOrigins = document.getElementById("hud-active-origins");
    this.hudClock = document.getElementById("hud-clock");
    this.btnSimulation = document.getElementById("btn-simulation");
    this.btnSalvo = document.getElementById("btn-salvo");

    // Panels
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

    // D3 Projections
    this.projection = null;
    this.geoPath = null;
    this.graticule = d3.geoGraticule().extent([[-180, -60], [180, 85]]).step([15, 15]);

    // Offscreen Hit-Testing Mask
    this.maskData = null;
    this.maskW = 0;
    this.maskH = 0;
    this.hoveredCountryIndex = null;

    // Attacks & Stats
    this.attacks = [];
    this.ripples = [];
    this.totalAttacksCount = 0;
    this.countryStats = new Map(); // countryCode -> { name, code, count }

    // Simulation
    this.simulationActive = true;
    this.simInterval = null;

    this.init();
  }

  async init() {
    this.startClock();
    this.bindEvents();

    await this.loadCartography();
    this.resize();

    this.animate();
    this.startSimulation();
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
      // Filter out Antarctica
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

    // Symmetrical positioning: map is centered between left and right sidebars
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

    // Slower speed for comfortable observation
    const speed = CONFIG.arcSpeedMin + Math.random() * (CONFIG.arcSpeedMax - CONFIG.arcSpeedMin);

    const attackObj = {
      id: Math.random().toString(36).substr(2, 9),
      start: { x: srcScreen[0], y: srcScreen[1] },
      control: controlPoint,
      end: { x: dstScreen[0], y: dstScreen[1] },
      progress: 0,
      speed: speed,
      color: CONFIG.primaryColor, // Uniform #006FFF
      trailLength: 0.16,
      data: data,
    };

    this.attacks.push(attackObj);
    this.totalAttacksCount++;

    // Origin shockwave
    this.addRipple(srcScreen[0], srcScreen[1], CONFIG.primaryColor, 14, 0.85);

    // Track origin country statistics
    this.recordCountryHit(data.srcCode, data.srcCountry);

    // Update Telemetry Header & Intrusion Ticker
    this.hudAttacksTotal.textContent = this.totalAttacksCount.toLocaleString();
    this.appendTickerRow(data);
  }

  recordCountryHit(code, name) {
    if (!this.countryStats.has(code)) {
      this.countryStats.set(code, { code, name, count: 0 });
    }
    this.countryStats.get(code).count++;

    // Update active origins count in header
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
    this.ripples.push({
      x,
      y,
      radius: 2,
      maxRadius,
      opacity: maxOpacity,
      color,
    });
  }

  appendTickerRow(data) {
    const row = document.createElement("div");
    row.className = "ticker-row";
    row.innerHTML = `
      <div class="ticker-left">
        <span class="ticker-badge">${data.name}</span>
        <span class="ticker-origin">${data.srcCountry}</span>
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

    // 1. Target Homelab Beacon (Belgium)
    if (this.projection) {
      const tgt = this.projection(CONFIG.targetCoords);
      if (tgt) {
        ctx.save();
        ctx.strokeStyle = "rgba(0, 111, 255, 0.6)";
        ctx.fillStyle = CONFIG.primaryColor;
        ctx.lineWidth = 1.2;

        ctx.beginPath();
        ctx.arc(tgt[0], tgt[1], 3.5, 0, Math.PI * 2);
        ctx.fill();

        const time = performance.now() * 0.002;
        const ring1 = (time % 1) * 22;
        const ring2 = ((time + 0.5) % 1) * 22;

        ctx.beginPath();
        ctx.arc(tgt[0], tgt[1], ring1, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(0, 111, 255, ${1 - ring1 / 22})`;
        ctx.stroke();

        ctx.beginPath();
        ctx.arc(tgt[0], tgt[1], ring2, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(0, 111, 255, ${1 - ring2 / 22})`;
        ctx.stroke();

        ctx.restore();
      }
    }

    // 2. Shockwave Ripples
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

    // 3. Persistent Trajectory Lines & Flying Projectiles
    for (let i = this.attacks.length - 1; i >= 0; i--) {
      const atk = this.attacks[i];
      atk.progress += atk.speed;

      // Upon Impact
      if (atk.progress >= 1) {
        this.addRipple(atk.end.x, atk.end.y, CONFIG.primaryColor, 32, 1.0);
        this.attacks.splice(i, 1);
        continue;
      }

      ctx.save();

      // FULL Persistent Trajectory Line (stays fully visible for the entire flight)
      ctx.strokeStyle = CONFIG.primaryColor;
      ctx.globalAlpha = 0.32;
      ctx.lineWidth = 1.2;
      ctx.beginPath();
      ctx.moveTo(atk.start.x, atk.start.y);
      ctx.quadraticCurveTo(atk.control.x, atk.control.y, atk.end.x, atk.end.y);
      ctx.stroke();

      // Traveling Photon Tail
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

      // Projectile Core (Bright White Head with Electric Blue Bloom)
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

    // Graticule Lines
    ctx.save();
    ctx.strokeStyle = CONFIG.gridStroke;
    ctx.lineWidth = 0.75;
    ctx.setLineDash([2, 4]);
    ctx.beginPath();
    this.geoPath(this.graticule);
    ctx.stroke();
    ctx.restore();

    // Base Landmasses
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

    // Hovered Country
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

    // Attacks & Impact Ripples
    this.renderAttacks();
  }

  animate() {
    this.render();
    requestAnimationFrame(() => this.animate());
  }

  spawnRandomAttack() {
    const origin = SAMPLE_ORIGINS[Math.floor(Math.random() * SAMPLE_ORIGINS.length)];
    const type = ATTACK_TYPES[Math.floor(Math.random() * ATTACK_TYPES.length)];

    this.triggerAttack({
      srcCountry: origin.country,
      srcCode: origin.code,
      srcLat: origin.lat + (Math.random() - 0.5) * 4,
      srcLon: origin.lon + (Math.random() - 0.5) * 4,
      dstLat: CONFIG.targetCoords[1],
      dstLon: CONFIG.targetCoords[0],
      name: type.name,
      port: type.port,
      proto: type.proto,
    });
  }

  startSimulation() {
    const scheduleNext = () => {
      if (!this.simulationActive) return;
      this.spawnRandomAttack();
      const delay = Math.floor(Math.random() * 1400) + 700;
      this.simInterval = setTimeout(scheduleNext, delay);
    };
    scheduleNext();
  }

  triggerSalvo() {
    for (let i = 0; i < 6; i++) {
      setTimeout(() => this.spawnRandomAttack(), i * 160);
    }
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

    this.btnSimulation.addEventListener("click", () => {
      this.simulationActive = !this.simulationActive;
      if (this.simulationActive) {
        this.btnSimulation.classList.add("active");
        this.btnSimulation.textContent = "SIMULATION: ON";
        this.startSimulation();
      } else {
        this.btnSimulation.classList.remove("active");
        this.btnSimulation.textContent = "SIMULATION: OFF";
        clearTimeout(this.simInterval);
      }
    });

    this.btnSalvo.addEventListener("click", () => {
      this.triggerSalvo();
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