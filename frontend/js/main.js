/**
 * SOC Threat Matrix - Smooth Vector World Map Engine
 * - Antarctica removed (ISO 010 filtered)
 * - Map bounds offset to x ≥ 360px so the left panel never overlaps landmasses
 * - D3 native projection inversion for pixel-perfect hover and coordinate reticle
 * - Hover: UniFi Electric Blue (#006FFF) + Neon Cyan border (#00F0FF)
 */

const CONFIG = {
  // Base Land Styling
  landFill: "#0b1424",
  landStroke: "rgba(0, 111, 255, 0.32)",
  landStrokeWidth: 0.75,

  // Hover Highlight Styling
  hoverFill: "#006FFF",
  hoverStroke: "#00F0FF",
  hoverStrokeWidth: 1.5,
  hoverGlowBlur: 18,

  // Graticule / Reference Lines
  gridStroke: "rgba(0, 111, 255, 0.08)",

  // Layout Spacing (leaves the left column open for the HUD panel)
  leftReservedWidth: 360,
  topReservedHeight: 70,
  paddingRight: 40,
  paddingBottom: 30,
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

    // HUD Elements
    this.coordsHud = document.getElementById("coords-hud");
    this.hudTerritories = document.getElementById("hud-territories");
    this.hudClock = document.getElementById("hud-clock");

    // Intel Panel Elements
    this.intelPanel = document.getElementById("country-intel");
    this.countryNameEl = document.getElementById("country-name");
    this.countryCodeEl = document.getElementById("country-code");
    this.countryFlagEl = document.getElementById("country-flag");
    this.flagPlaceholderEl = document.getElementById("flag-placeholder");
    this.intelStatusEl = document.getElementById("intel-status");

    this.countryFeatures = [];
    this.featureCollection = null;
    this.pixelRatio = window.devicePixelRatio || 1;

    // D3 Projections
    this.projection = null;
    this.geoPath = null;
    // Bounded graticule (excluding southern polar extremes)
    this.graticule = d3.geoGraticule().extent([[-180, -60], [180, 85]]).step([15, 15]);

    // Offscreen Hit-Testing Mask
    this.maskData = null;
    this.maskW = 0;
    this.maskH = 0;

    this.hoveredCountryIndex = null;

    this.init();
  }

  async init() {
    this.startClock();
    this.bindEvents();

    await this.loadCartography();
    this.resize();
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

      // Filter out Antarctica (ISO 3166-1 numeric 010 / 10)
      const allFeatures = topojson.feature(data, data.objects.countries).features;
      this.countryFeatures = allFeatures.filter(feature => parseInt(feature.id, 10) !== 10);

      this.featureCollection = {
        type: "FeatureCollection",
        features: this.countryFeatures
      };

      if (this.hudTerritories) {
        this.hudTerritories.textContent = this.countryFeatures.length;
      }
    } catch (e) {
      console.error("Failed to load map topology data:", e);
      if (this.hudTerritories) this.hudTerritories.textContent = "ERR_DATA";
    }
  }

  resize() {
    const width = window.innerWidth;
    const height = window.innerHeight;
    this.pixelRatio = window.devicePixelRatio || 1;

    // Update main display canvas dimensions
    this.canvas.width = Math.round(width * this.pixelRatio);
    this.canvas.height = Math.round(height * this.pixelRatio);
    this.canvas.style.width = `${width}px`;
    this.canvas.style.height = `${height}px`;

    // Calculate map bounds shifted to the right of the left Intel panel
    const mapX = CONFIG.leftReservedWidth;
    const mapY = CONFIG.topReservedHeight;
    const mapW = Math.max(300, width - mapX - CONFIG.paddingRight);
    const mapH = Math.max(200, height - mapY - CONFIG.paddingBottom);

    // Fit the non-Antarctic continents into the reserved display viewport
    if (this.featureCollection) {
      this.projection = d3.geoEquirectangular()
        .fitExtent([[mapX, mapY], [mapX + mapW, mapY + mapH]], this.featureCollection);

      this.geoPath = d3.geoPath(this.projection, this.ctx);

      this.generateHitMask(width, height);
      this.render();
    }
  }

  // 1:1 screen-resolution offscreen hit mask for pixel-perfect hover detection
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
      const countryIdx = i + 1; // 1-based index
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

  render() {
    const ctx = this.ctx;
    ctx.setTransform(this.pixelRatio, 0, 0, this.pixelRatio, 0, 0);
    ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);

    if (!this.geoPath) return;

    // 1. Graticule Lat/Lon Reference Lines
    ctx.save();
    ctx.strokeStyle = CONFIG.gridStroke;
    ctx.lineWidth = 0.75;
    ctx.setLineDash([2, 4]);
    ctx.beginPath();
    this.geoPath(this.graticule);
    ctx.stroke();
    ctx.restore();

    // 2. Base Landmasses
    ctx.save();
    ctx.fillStyle = CONFIG.landFill;
    ctx.strokeStyle = CONFIG.landStroke;
    ctx.lineWidth = CONFIG.landStrokeWidth;

    for (let i = 0; i < this.countryFeatures.length; i++) {
      if (i + 1 === this.hoveredCountryIndex) continue; // Drawn in elevated pass

      ctx.beginPath();
      this.geoPath(this.countryFeatures[i]);
      ctx.fill();
      ctx.stroke();
    }
    ctx.restore();

    // 3. Hovered Country (Elevated in UniFi Electric Blue + Neon Glow)
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
  }

  updateIntelPanel(countryIndex) {
    if (!countryIndex || countryIndex <= 0 || countryIndex > this.countryFeatures.length) {
      this.intelPanel.classList.remove("active");
      this.intelPanel.classList.add("idle");
      this.intelStatusEl.textContent = "SCANNING...";
      this.countryNameEl.textContent = "STANDBY";
      this.countryCodeEl.textContent = "GEO // NONE";
      this.countryFlagEl.style.display = "none";
      this.flagPlaceholderEl.style.display = "block";
      return;
    }

    const feature = this.countryFeatures[countryIndex - 1];
    const numericId = parseInt(feature.id, 10);
    const meta = COUNTRY_LOOKUP[numericId];

    this.intelPanel.classList.add("active");
    this.intelPanel.classList.remove("idle");
    this.intelStatusEl.textContent = "TARGET LOCKED";

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

    this.canvas.addEventListener("mousemove", (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      let detectedCountryIdx = null;

      // Coordinate reticle via D3 mathematical inversion
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

      // Hit-mask country detection
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
        this.render();
      }
    });

    this.canvas.addEventListener("mouseleave", () => {
      if (this.hoveredCountryIndex !== null) {
        this.hoveredCountryIndex = null;
        this.updateIntelPanel(null);
        this.render();
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