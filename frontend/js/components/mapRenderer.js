/**
 * 2D Vector Map & Ballistic Trajectory Renderer
 * =============================================
 * Handles TopoJSON cartography loading, D3 Equirectangular projection,
 * offscreen RGB hit-mask country picking, ocean grid backdrop, country
 * illumination, shockwave ripples, and quadratic Bezier attack trajectories.
 */

import { CONFIG } from "../config.js";
import { getBezierPoint, getBucketColor } from "../utils/helpers.js";

export class MapRenderer {
  constructor(app) {
    this.app = app;
  }

  async loadCartography() {
    try {
      let data;
      try {
        const localRes = await fetch("data/countries-110m.json");
        if (!localRes.ok) throw new Error("Local file not found");
        data = await localRes.json();
      } catch {
        const cdnRes = await fetch(
          "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json"
        );
        data = await cdnRes.json();
      }

      const allFeatures = topojson.feature(data, data.objects.countries).features;
      this.app.countryFeatures = allFeatures.filter(
        (feature) => parseInt(feature.id, 10) !== 10
      );

      this.app.featureCollection = {
        type: "FeatureCollection",
        features: this.app.countryFeatures,
      };

      const nonAntarcticGeoms = data.objects.countries.geometries.filter(
        (g) => parseInt(g.id, 10) !== 10
      );
      this.app.mergedLandGeo = topojson.merge(data, nonAntarcticGeoms);

      this.app.coastlineMesh = topojson.mesh(
        data,
        data.objects.countries,
        (a, b) => {
          const idA = parseInt(a.id, 10);
          const idB = parseInt(b.id, 10);
          return a === b && idA !== 10 && idB !== 10;
        }
      );
    } catch (e) {
      console.error("Failed to load map topology data:", e);
    }
  }

  resize() {
    const width = window.innerWidth;
    const height = window.innerHeight;
    this.app.pixelRatio = window.devicePixelRatio || 1;

    this.app.canvas.width = Math.round(width * this.app.pixelRatio);
    this.app.canvas.height = Math.round(height * this.app.pixelRatio);
    this.app.canvas.style.width = `${width}px`;
    this.app.canvas.style.height = `${height}px`;

    const mapX = CONFIG.horizontalMargin;
    const mapY = CONFIG.topReservedHeight;
    const mapW = Math.max(300, width - CONFIG.horizontalMargin * 2);
    const mapH = Math.max(200, height - mapY - CONFIG.bottomMargin);

    if (this.app.featureCollection) {
      this.app.projection = d3
        .geoEquirectangular()
        .fitExtent(
          [
            [mapX, mapY],
            [mapX + mapW, mapY + mapH],
          ],
          this.app.featureCollection
        );

      this.app.geoPath = d3.geoPath(this.app.projection, this.app.ctx);
      this.generateHitMask(width, height);
    }
  }

  generateHitMask(width, height) {
    this.app.maskW = Math.round(width);
    this.app.maskH = Math.round(height);

    const offscreen = document.createElement("canvas");
    offscreen.width = this.app.maskW;
    offscreen.height = this.app.maskH;
    const offCtx = offscreen.getContext("2d");
    offCtx.imageSmoothingEnabled = false;

    const maskPath = d3.geoPath(this.app.projection, offCtx);
    offCtx.clearRect(0, 0, this.app.maskW, this.app.maskH);

    for (let i = 0; i < this.app.countryFeatures.length; i++) {
      const countryIdx = i + 1;
      const r = (countryIdx >> 16) & 255;
      const g = (countryIdx >> 8) & 255;
      const b = countryIdx & 255;

      offCtx.fillStyle = `rgb(${r},${g},${b})`;
      offCtx.beginPath();
      maskPath(this.app.countryFeatures[i]);
      offCtx.fill();
    }

    this.app.maskData = offCtx.getImageData(
      0,
      0,
      this.app.maskW,
      this.app.maskH
    ).data;
  }

  detectCountryAtPoint(mouseX, mouseY) {
    const px = Math.floor(mouseX);
    const py = Math.floor(mouseY);
    if (
      this.app.maskData &&
      px >= 0 &&
      px < this.app.maskW &&
      py >= 0 &&
      py < this.app.maskH
    ) {
      const idx = (py * this.app.maskW + px) * 4;
      const alpha = this.app.maskData[idx + 3];
      if (alpha > 64) {
        const r = this.app.maskData[idx];
        const g = this.app.maskData[idx + 1];
        const b = this.app.maskData[idx + 2];
        const candidate = (r << 16) | (g << 8) | b;
        if (candidate >= 1 && candidate <= this.app.countryFeatures.length) {
          return candidate;
        }
      }
    }
    return null;
  }

  addRipple(x, y, color, maxRadius = 24, maxOpacity = 0.8, data = null) {
    this.app.ripples.push({
      x,
      y,
      radius: 2,
      maxRadius,
      opacity: maxOpacity,
      color,
      data,
    });
  }

  drawCityBadge(
    x,
    y,
    text,
    borderColor = "rgba(0, 111, 255, 0.45)",
    dotColor = "#006FFF"
  ) {
    const ctx = this.app.ctx;
    const labelText = text.toUpperCase();
    ctx.font = "700 13px JetBrains Mono, monospace";
    const textMetrics = ctx.measureText(labelText);
    const labelW = textMetrics.width + 24;
    const labelH = 24;
    const labelX = x + 8;
    const labelY = y - 28;

    ctx.fillStyle = "rgba(5, 13, 28, 0.94)";
    ctx.strokeStyle = borderColor;
    ctx.lineWidth = 1.3;
    ctx.shadowColor = "rgba(0, 0, 0, 0.5)";
    ctx.shadowBlur = 8;
    ctx.beginPath();
    ctx.roundRect(labelX, labelY, labelW, labelH, 4);
    ctx.fill();
    ctx.stroke();

    ctx.fillStyle = dotColor;
    ctx.beginPath();
    ctx.arc(labelX + 9, labelY + labelH / 2, 3.2, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = "#ffffff";
    ctx.shadowBlur = 0;
    ctx.textBaseline = "middle";
    ctx.fillText(labelText, labelX + 17, labelY + labelH / 2 + 0.5);
  }

  drawCyberOceanBackdrop(width, height) {
    const ctx = this.app.ctx;
    const minorStep = 36;
    const majorStep = 144;

    ctx.save();

    ctx.strokeStyle = CONFIG.minorGridStroke;
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let x = 0; x <= width; x += minorStep) {
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
    }
    for (let y = 0; y <= height; y += minorStep) {
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
    }
    ctx.stroke();

    ctx.strokeStyle = CONFIG.majorGridStroke;
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let x = 0; x <= width; x += majorStep) {
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
    }
    for (let y = 0; y <= height; y += majorStep) {
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
    }
    ctx.stroke();

    ctx.strokeStyle = CONFIG.crosshairStroke;
    ctx.lineWidth = 1.2;
    ctx.beginPath();
    for (let x = majorStep; x < width; x += majorStep) {
      for (let y = majorStep; y < height; y += majorStep) {
        ctx.moveTo(x - 4, y);
        ctx.lineTo(x + 4, y);
        ctx.moveTo(x, y - 4);
        ctx.lineTo(x, y + 4);
      }
    }
    ctx.stroke();

    const cx = width / 2;
    const cy = height / 2;
    ctx.strokeStyle = CONFIG.radarRingStroke;
    ctx.lineWidth = 1;
    for (const radius of [220, 420, 620]) {
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.stroke();
    }

    ctx.restore();
  }

  renderSelectedAttack() {
    if (!this.app.selectedAttack || !this.app.projection) return;
    const data = this.app.selectedAttack;
    const srcScreen = this.app.projection([data.srcLon, data.srcLat]);
    const dstScreen = this.app.projection([data.dstLon, data.dstLat]);
    if (!srcScreen || !dstScreen) return;

    const start = { x: srcScreen[0], y: srcScreen[1] };
    const end = { x: dstScreen[0], y: dstScreen[1] };
    const dx = end.x - start.x;
    const dy = end.y - start.y;
    const dist = Math.hypot(dx, dy);
    const archAltitude = Math.min(180, Math.max(35, dist * 0.28));
    const control = {
      x: (start.x + end.x) / 2,
      y: (start.y + end.y) / 2 - archAltitude,
    };

    const color = getBucketColor(data._bucket || "LOW");
    const ctx = this.app.ctx;

    ctx.save();

    ctx.strokeStyle = color;
    ctx.shadowColor = color;
    ctx.shadowBlur = 16;
    ctx.globalAlpha = 0.95;
    ctx.lineWidth = 2.8;
    ctx.beginPath();
    ctx.moveTo(start.x, start.y);
    ctx.quadraticCurveTo(control.x, control.y, end.x, end.y);
    ctx.stroke();

    ctx.strokeStyle = "#ffffff";
    ctx.globalAlpha = 0.65;
    ctx.lineWidth = 1.0;
    ctx.beginPath();
    ctx.moveTo(start.x, start.y);
    ctx.quadraticCurveTo(control.x, control.y, end.x, end.y);
    ctx.stroke();

    const t = (performance.now() * 0.00045) % 1;
    const pulsePt = getBezierPoint(t, start, control, end);
    ctx.shadowColor = "#00F0FF";
    ctx.shadowBlur = 16;
    ctx.fillStyle = "#ffffff";
    ctx.globalAlpha = 1.0;
    ctx.beginPath();
    ctx.arc(pulsePt.x, pulsePt.y, 4.2, 0, Math.PI * 2);
    ctx.fill();

    const pulseRadius = 8 + Math.sin(performance.now() * 0.006) * 3;
    ctx.strokeStyle = "#00F0FF";
    ctx.lineWidth = 1.6;
    ctx.beginPath();
    ctx.arc(start.x, start.y, pulseRadius, 0, Math.PI * 2);
    ctx.stroke();

    ctx.strokeStyle = color;
    ctx.beginPath();
    ctx.arc(end.x, end.y, pulseRadius + 2, 0, Math.PI * 2);
    ctx.stroke();

    const originName =
      data.srcCity && data.srcCity !== "Unknown"
        ? data.srcCity
        : data.srcCountry;
    const targetName = data.dstCity ? data.dstCity : data.dstCountry;
    this.drawCityBadge(
      start.x,
      start.y,
      `${originName} (${data.srcCode.toUpperCase()})`,
      "#00F0FF",
      "#006FFF"
    );
    this.drawCityBadge(end.x, end.y, `TARGET: ${targetName}`, color, color);

    ctx.restore();
  }

  renderAttacks() {
    const ctx = this.app.ctx;
    const dimFactor = this.app.selectedAttack ? 0.35 : 1.0;

    // 1. Shockwaves (Filtered by severity + live search; frozen in place when stream is paused)
    for (let i = this.app.ripples.length - 1; i >= 0; i--) {
      const rip = this.app.ripples[i];
      if (!this.app.isStreamPaused) {
        rip.radius += 0.55;
        rip.opacity -= 0.015;
      }

      if (rip.opacity <= 0 || rip.radius >= rip.maxRadius) {
        this.app.ripples.splice(i, 1);
        continue;
      }

      if (rip.data && !this.app.matchesActiveFilters(rip.data)) continue;

      ctx.save();
      ctx.strokeStyle = rip.color;
      ctx.globalAlpha = Math.max(0, rip.opacity * dimFactor);
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.arc(rip.x, rip.y, rip.radius, 0, Math.PI * 2);
      ctx.stroke();
      ctx.restore();
    }

    // 2. Live Trajectories & City Nameplates (Filtered by severity + live search)
    for (let i = this.app.attacks.length - 1; i >= 0; i--) {
      const atk = this.app.attacks[i];
      if (!this.app.isStreamPaused) {
        atk.progress += atk.speed;
      }

      if (atk.progress >= 1) {
        this.addRipple(atk.end.x, atk.end.y, atk.color, 32, 1.0, atk.data);
        this.app.attacks.splice(i, 1);
        continue;
      }

      if (!this.app.matchesActiveFilters(atk.data)) continue;

      ctx.save();

      ctx.fillStyle = atk.color;
      ctx.shadowColor = atk.color;
      ctx.shadowBlur = 10;
      ctx.globalAlpha = dimFactor;
      ctx.beginPath();
      ctx.arc(atk.start.x, atk.start.y, 3.2, 0, Math.PI * 2);
      ctx.fill();

      if (!this.app.selectedAttack) {
        this.drawCityBadge(atk.start.x, atk.start.y, atk.cityName);
      }

      ctx.strokeStyle = atk.color;
      ctx.globalAlpha = 0.38 * dimFactor;
      ctx.lineWidth = 1.3;
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

        const pt1 = getBezierPoint(t1, atk.start, atk.control, atk.end);
        const pt2 = getBezierPoint(t2, atk.start, atk.control, atk.end);
        const segAlpha = (s + 1) / segments;

        ctx.strokeStyle = atk.color;
        ctx.globalAlpha = segAlpha * 0.95 * dimFactor;
        ctx.lineWidth = 1.4 + segAlpha * 2.2;
        ctx.beginPath();
        ctx.moveTo(pt1.x, pt1.y);
        ctx.lineTo(pt2.x, pt2.y);
        ctx.stroke();
      }

      const headPt = getBezierPoint(headT, atk.start, atk.control, atk.end);
      ctx.shadowColor = atk.color;
      ctx.shadowBlur = 14;
      ctx.fillStyle = "#FFFFFF";
      ctx.globalAlpha = 1.0 * dimFactor;
      ctx.beginPath();
      ctx.arc(headPt.x, headPt.y, 2.8, 0, Math.PI * 2);
      ctx.fill();

      ctx.restore();
    }

    // 3. Render Locked/Selected Feed Card Trajectory on Top
    this.renderSelectedAttack();
  }

  render() {
    const ctx = this.app.ctx;
    const width = window.innerWidth;
    const height = window.innerHeight;

    ctx.setTransform(this.app.pixelRatio, 0, 0, this.app.pixelRatio, 0, 0);
    ctx.clearRect(0, 0, width, height);

    if (!this.app.geoPath) return;

    this.drawCyberOceanBackdrop(width, height);

    if (this.app.mergedLandGeo) {
      ctx.save();
      ctx.fillStyle = CONFIG.landFill;
      ctx.beginPath();
      this.app.geoPath(this.app.mergedLandGeo);
      ctx.fill();
      ctx.restore();
    }

    if (this.app.coastlineMesh) {
      ctx.save();
      ctx.strokeStyle = CONFIG.coastlineStroke;
      ctx.lineWidth = CONFIG.coastlineWidth;
      ctx.shadowColor = CONFIG.coastlineGlow;
      ctx.shadowBlur = 8;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.beginPath();
      this.app.geoPath(this.app.coastlineMesh);
      ctx.stroke();
      ctx.restore();
    }

    if (
      this.app.hoveredCountryIndex !== null &&
      this.app.hoveredCountryIndex !== this.app.selectedCountryIndex
    ) {
      const feature = this.app.countryFeatures[this.app.hoveredCountryIndex - 1];
      if (feature) {
        ctx.save();
        ctx.fillStyle = CONFIG.hoverFill;
        ctx.strokeStyle = CONFIG.hoverStroke;
        ctx.lineWidth = CONFIG.hoverStrokeWidth;
        ctx.shadowColor = CONFIG.hoverFill;
        ctx.shadowBlur = CONFIG.hoverGlowBlur;
        ctx.lineCap = "round";
        ctx.lineJoin = "round";

        ctx.beginPath();
        this.app.geoPath(feature);
        ctx.fill();
        ctx.stroke();
        ctx.restore();
      }
    }

    if (this.app.selectedCountryIndex !== null) {
      const selFeature =
        this.app.countryFeatures[this.app.selectedCountryIndex - 1];
      if (selFeature) {
        ctx.save();
        ctx.fillStyle = CONFIG.selectedCountryFill;
        ctx.strokeStyle = CONFIG.selectedCountryStroke;
        ctx.lineWidth = CONFIG.selectedCountryStrokeWidth;
        ctx.shadowColor = CONFIG.selectedCountryStroke;
        ctx.shadowBlur = CONFIG.selectedCountryGlowBlur;
        ctx.lineCap = "round";
        ctx.lineJoin = "round";

        ctx.beginPath();
        this.app.geoPath(selFeature);
        ctx.fill();
        ctx.stroke();
        ctx.restore();
      }
    }

    this.renderAttacks();
  }

  bindMapEvents() {
    window.addEventListener("resize", () => {
      this.resize();
    });

    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") {
        this.app.attacks = [];
        this.app.ripples = [];
      }
    });

    // Click on Map Country to toggle Gold highlight & open/close Gold Dossier Card
    this.app.canvas.addEventListener("click", (e) => {
      const rect = this.app.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      const clickedCountryIdx = this.detectCountryAtPoint(mouseX, mouseY);

      if (clickedCountryIdx !== null) {
        if (this.app.selectedCountryIndex === clickedCountryIdx) {
          this.app.selectedCountryIndex = null;
        } else {
          this.app.selectedCountryIndex = clickedCountryIdx;
        }
        this.app.updateCountryDossier();
      }
    });

    this.app.canvas.addEventListener("mousemove", (e) => {
      const rect = this.app.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      if (this.app.projection) {
        const coords = this.app.projection.invert([mouseX, mouseY]);
        if (
          coords &&
          coords[0] >= -180 &&
          coords[0] <= 180 &&
          coords[1] >= -60 &&
          coords[1] <= 85
        ) {
          const [lon, lat] = coords;
          const latDir = lat >= 0 ? "N" : "S";
          const lonDir = lon >= 0 ? "E" : "W";
          this.app.coordsHud.textContent = `${Math.abs(lat).toFixed(1)}°${latDir} | ${Math.abs(lon).toFixed(1)}°${lonDir}`;
        } else {
          this.app.coordsHud.textContent = "--.-° | --.-°";
        }
      }

      const detectedCountryIdx = this.detectCountryAtPoint(mouseX, mouseY);
      this.app.hoveredCountryIndex = detectedCountryIdx;
      this.app.updateHoverIntel(detectedCountryIdx, e.clientX, e.clientY);
    });

    this.app.canvas.addEventListener("mouseleave", () => {
      this.app.hoveredCountryIndex = null;
      this.app.updateHoverIntel(null, 0, 0);
    });
  }
}
