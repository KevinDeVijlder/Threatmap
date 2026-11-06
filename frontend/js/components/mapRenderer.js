/**
 * 2D Vector Map, Monitored City Markers & Ballistic Trajectory Renderer
 * =====================================================================
 * Handles TopoJSON cartography loading, D3 Equirectangular projection,
 * offscreen RGB hit-mask country picking, ocean grid backdrop, country
 * illumination, pinned custom city icons with labels underneath,
 * shockwave ripples, and quadratic Bezier attack trajectories.
 */

import { CONFIG } from "../config.js";
import { buildSmallCountryFeatures } from "../data/countries.js";
import { getBezierPoint, getBucketColor, getPinTypeMeta } from "../utils/helpers.js";

export class MapRenderer {
  constructor(app) {
    this.app = app;
    this.lastMouseX = -1;
    this.lastMouseY = -1;
    this.lastAlarmSignature = "";

    // Map Zoom & Pan State (geography scales; pins, badges, and arcs remain 1:1)
    this.zoomScale = 1.0;
    this.minZoom = 1.0;
    this.maxZoom = 12.0;
    this.panX = 0;
    this.panY = 0;
    this.isPanning = false;
    this.panStartX = 0;
    this.panStartY = 0;
    this.panOriginX = 0;
    this.panOriginY = 0;
    this.didDrag = false;
  }

  baseToScreen(baseX, baseY) {
    return [
      baseX * this.zoomScale + this.panX,
      baseY * this.zoomScale + this.panY,
    ];
  }

  screenToBase(screenX, screenY) {
    return [
      (screenX - this.panX) / this.zoomScale,
      (screenY - this.panY) / this.zoomScale,
    ];
  }

  projectToScreen(lonLat) {
    if (!this.app.projection) return null;
    const pt = this.app.projection(lonLat);
    if (!pt) return null;
    return this.baseToScreen(pt[0], pt[1]);
  }

  clampPan() {
    if (this.zoomScale <= 1.001) {
      this.zoomScale = 1.0;
      this.panX = 0;
      this.panY = 0;
      return;
    }
    const w = window.innerWidth;
    const h = window.innerHeight;
    const minX = w * (1 - this.zoomScale);
    const minY = h * (1 - this.zoomScale);
    this.panX = Math.min(0, Math.max(minX, this.panX));
    this.panY = Math.min(0, Math.max(minY, this.panY));
  }

  updateZoomHudDOM() {
    if (this.app.zoomLevelLabel) {
      this.app.zoomLevelLabel.textContent = `${this.zoomScale.toFixed(1)}x`;
    }
    if (this.app.canvas) {
      this.app.canvas.classList.toggle("is-zoomed", this.zoomScale > 1.01);
    }
  }

  zoomAtPoint(newScale, pivotX, pivotY) {
    const targetScale = Math.min(
      this.maxZoom,
      Math.max(this.minZoom, newScale)
    );
    const [baseX, baseY] = this.screenToBase(pivotX, pivotY);
    this.zoomScale = targetScale;
    this.panX = pivotX - baseX * this.zoomScale;
    this.panY = pivotY - baseY * this.zoomScale;
    this.clampPan();
    this.updateZoomHudDOM();
  }

  resetZoom() {
    this.zoomScale = 1.0;
    this.panX = 0;
    this.panY = 0;
    this.updateZoomHudDOM();
  }

  focusLocation(loc, targetScale = 4.0) {
    if (!loc || !this.app.projection) return;
    const lon = parseFloat(loc.lon);
    const lat = parseFloat(loc.lat);
    if (Number.isNaN(lon) || Number.isNaN(lat)) return;
    const basePt = this.app.projection([lon, lat]);
    if (!basePt) return;

    this.zoomScale = Math.min(this.maxZoom, Math.max(this.minZoom, targetScale));
    this.panX = window.innerWidth / 2 - basePt[0] * this.zoomScale;
    this.panY = window.innerHeight / 2 - basePt[1] * this.zoomScale;
    this.clampPan();
    this.updateZoomHudDOM();
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
      const baseFeatures = allFeatures.filter(
        (feature) => parseInt(feature.id, 10) !== 10
      );

      // Projection fitExtent uses the base 110m countries so initial framing stays identical
      this.app.featureCollection = {
        type: "FeatureCollection",
        features: baseFeatures,
      };

      const existingIds = new Set(
        baseFeatures
          .map((f) => parseInt(f.id, 10))
          .filter((id) => !Number.isNaN(id))
      );

      // Build smaller sovereign nations, microstates & islands omitted from 1:110m
      const smallFeatures = buildSmallCountryFeatures(existingIds);

      this.app.countryFeatures = [...baseFeatures, ...smallFeatures];
      this.app.countryFeatures.forEach((f, idx) => {
        f._countryIdx = idx + 1;
      });
      this.app.smallCountryFeatures = smallFeatures;

      const nonAntarcticGeoms = data.objects.countries.geometries.filter(
        (g) => parseInt(g.id, 10) !== 10
      );
      this.app.mergedLandGeo = topojson.merge(data, nonAntarcticGeoms);

      // Exterior coastlines (a === b)
      this.app.coastlineMesh = topojson.mesh(
        data,
        data.objects.countries,
        (a, b) => {
          const idA = parseInt(a.id, 10);
          const idB = parseInt(b.id, 10);
          return a === b && idA !== 10 && idB !== 10;
        }
      );

      // Interior country borders between adjacent nations (a !== b)
      this.app.bordersMesh = topojson.mesh(
        data,
        data.objects.countries,
        (a, b) => {
          const idA = parseInt(a.id, 10);
          const idB = parseInt(b.id, 10);
          return a !== b && idA !== 10 && idB !== 10;
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
      this.clampPan();
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
      const feature = this.app.countryFeatures[i];
      if (feature.isSmallCountry) continue;
      const countryIdx = i + 1;
      const r = (countryIdx >> 16) & 255;
      const g = (countryIdx >> 8) & 255;
      const b = countryIdx & 255;

      offCtx.fillStyle = `rgb(${r},${g},${b})`;
      offCtx.beginPath();
      maskPath(feature);
      offCtx.fill();
    }

    this.app.maskData = offCtx.getImageData(
      0,
      0,
      this.app.maskW,
      this.app.maskH
    ).data;
  }

  /**
   * Traces a small country's projected polygon ring directly onto the canvas
   * without spherical clipping/inversion artifacts.
   */
  traceSmallCountryPath(ctx, sf) {
    if (!sf || !sf.ring || !this.app.projection) return false;
    ctx.beginPath();
    for (let i = 0; i < sf.ring.length; i++) {
      const pt = this.app.projection(sf.ring[i]);
      if (!pt) continue;
      if (i === 0) ctx.moveTo(pt[0], pt[1]);
      else ctx.lineTo(pt[0], pt[1]);
    }
    ctx.closePath();
    return true;
  }

  detectCountryAtPoint(mouseX, mouseY) {
    const [baseX, baseY] = this.screenToBase(mouseX, mouseY);

    // When zoomed in, check smaller countries & microstates first so enclaves
    // (e.g. Monaco, San Marino, Vatican City, Singapore, Bahrain, Malta) are pickable
    if (
      this.zoomScale >= (CONFIG.smallCountryZoomThreshold || 1.45) &&
      this.app.smallCountryFeatures &&
      this.app.smallCountryFeatures.length > 0 &&
      this.app.projection
    ) {
      const coords = this.app.projection.invert([baseX, baseY]);
      for (const sf of this.app.smallCountryFeatures) {
        if (
          Number.isFinite(sf.centerLon) &&
          Number.isFinite(sf.centerLat)
        ) {
          const screenPt = this.projectToScreen([sf.centerLon, sf.centerLat]);
          if (
            screenPt &&
            Math.hypot(mouseX - screenPt[0], mouseY - screenPt[1]) <= 8
          ) {
            return sf._countryIdx;
          }
        }
        if (
          coords &&
          sf.rx &&
          sf.ry &&
          Math.hypot(
            (coords[0] - sf.centerLon) / sf.rx,
            (coords[1] - sf.centerLat) / sf.ry
          ) <= 1.15
        ) {
          return sf._countryIdx;
        }
      }
    }

    const px = Math.floor(baseX);
    const py = Math.floor(baseY);
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

  /**
   * Draws a minimalistic vector icon inside a map pin badge as a fallback
   * if the Font Awesome webfont is still loading.
   */
  drawFallbackPinGlyph(ctx, key, x, y) {
    ctx.beginPath();
    if (key === "SOC_CORE") {
      // Minimalistic Shield
      ctx.moveTo(x, y - 6);
      ctx.lineTo(x + 5, y - 4);
      ctx.lineTo(x + 5, y + 1);
      ctx.quadraticCurveTo(x + 4, y + 5, x, y + 6.5);
      ctx.quadraticCurveTo(x - 4, y + 5, x - 5, y + 1);
      ctx.lineTo(x - 5, y - 4);
      ctx.closePath();
      ctx.fill();
    } else if (key === "SENSOR") {
      // Minimalistic Satellite Dish / Radar Arc
      ctx.arc(x - 1, y + 1, 5, Math.PI * 0.75, Math.PI * 1.75);
      ctx.lineTo(x - 1, y + 1);
      ctx.closePath();
      ctx.fill();
      ctx.fillRect(x - 3, y + 4.5, 5, 1.5);
    } else if (key === "HIGH_VALUE") {
      // Minimalistic Crown
      ctx.moveTo(x - 5.5, y + 4);
      ctx.lineTo(x - 5.5, y - 3);
      ctx.lineTo(x - 2, y + 0.5);
      ctx.lineTo(x, y - 4.5);
      ctx.lineTo(x + 2, y + 0.5);
      ctx.lineTo(x + 5.5, y - 3);
      ctx.lineTo(x + 5.5, y + 4);
      ctx.closePath();
      ctx.fill();
    } else if (key === "HONEYPOT") {
      // Minimalistic Bug
      ctx.arc(x, y + 0.5, 3.8, 0, Math.PI * 2);
      ctx.fill();
      ctx.fillRect(x - 6, y - 1.5, 12, 1.2);
      ctx.fillRect(x - 6, y + 1.5, 12, 1.2);
    } else {
      // Default City Skyline
      ctx.fillRect(x - 6, y - 2, 3.5, 7);
      ctx.fillRect(x - 2, y - 6, 4.5, 11);
      ctx.fillRect(x + 3, y, 3.2, 5);
    }
  }

  /**
   * Checks whether a specific pinned location's IP address is currently
   * under attack by an in-flight trajectory or recent impact shockwave.
   */
  isLocationUnderAttack(loc, now = performance.now()) {
    if (!loc || !loc.ip) return false;
    const locIp = String(loc.ip || "")
      .trim()
      .split(":")[0];
    if (!locIp || locIp === "N/A") return false;

    if (loc._underAttackUntil && now < loc._underAttackUntil) {
      return true;
    }
    return this.app.attacks.some(
      (atk) => atk.targetIp && atk.targetIp === locIp
    );
  }

  /**
   * Renders the floating Pinned Locations Legend DOM list on the map.
   */
  renderPinnedNodesLegend() {
    if (!this.app.pinnedNodesList) return;

    if (!this.app.currentUser) {
      this.app.pinnedNodesList.innerHTML = `
        <div class="pinned-nodes-empty">
          Not signed in. <a href="login.html">Login to view your nodes →</a>
        </div>
      `;
      this.lastAlarmSignature = "";
      this.updatePinnedNodesAlarmDOM(performance.now());
      return;
    }

    const locations = this.app.customLocations || [];

    if (locations.length === 0) {
      this.app.pinnedNodesList.innerHTML = `
        <div class="pinned-nodes-empty">
          No nodes pinned. <a href="locations.html">Add in Map Locations →</a>
        </div>
      `;
      this.lastAlarmSignature = "";
      this.updatePinnedNodesAlarmDOM(performance.now());
      return;
    }

    this.app.pinnedNodesList.innerHTML = locations
      .map((loc, idx) => {
        const pinMeta = getPinTypeMeta(loc.color);
        const accent = pinMeta.color;
        const locKey = loc.id || loc.name || `node_${idx}`;
        const ipDisplay = loc.ip ? `${loc.ip} • ` : "";
        return `
          <div class="pinned-node-row" data-node-key="${locKey}" style="border-left-color: ${accent};">
            <div class="pinned-node-left">
              <div class="pinned-node-icon-box" style="color: ${accent}; border-color: ${accent};">
                <i class="fa-solid ${pinMeta.faClass}"></i>
              </div>
              <div class="pinned-node-meta">
                <span class="pinned-node-name">${(loc.name || "NODE").toUpperCase()}</span>
                <span class="pinned-node-type" style="color: ${accent};">${ipDisplay}${pinMeta.label}</span>
              </div>
            </div>
            <div class="pinned-node-status nominal">
              <span class="status-dot"></span>
              <span class="status-text">OK</span>
            </div>
          </div>
        `;
      })
      .join("");

    this.lastAlarmSignature = "";
    this.updatePinnedNodesAlarmDOM(performance.now());
  }

  /**
   * Synchronizes the flashing alarm indicator and per-node alert badges
   * whenever a pinned location enters or leaves the under-attack state.
   */
  updatePinnedNodesAlarmDOM(now = performance.now()) {
    if (!this.app.pinnedAlarmIndicator || !this.app.pinnedNodesHud) return;
    const locations = this.app.currentUser ? this.app.customLocations || [] : [];

    const attackedNodes = locations.filter((loc) =>
      this.isLocationUnderAttack(loc, now)
    );
    const sig = `${this.app.currentUser ? "auth" : "anon"}:${attackedNodes
      .map((l) => l.id || l.name)
      .join("|")}`;
    if (sig === this.lastAlarmSignature) return;
    this.lastAlarmSignature = sig;

    const isAnyUnderAttack = attackedNodes.length > 0;
    this.app.pinnedNodesHud.classList.toggle("under-attack", isAnyUnderAttack);
    this.app.pinnedAlarmIndicator.classList.toggle("alarm-active", isAnyUnderAttack);
    this.app.pinnedAlarmIndicator.classList.toggle("standby", !isAnyUnderAttack);

    if (isAnyUnderAttack) {
      const primaryName = (attackedNodes[0].name || "NODE").toUpperCase();
      const extraCount =
        attackedNodes.length > 1 ? ` +${attackedNodes.length - 1}` : "";
      this.app.pinnedAlarmText.textContent = `ALARM: ${primaryName}${extraCount}`;
    } else {
      this.app.pinnedAlarmText.textContent =
        locations.length > 0 ? "PERIMETER SECURE" : "STANDBY";
    }

    if (this.app.pinnedNodesList) {
      const attackedKeys = new Set(attackedNodes.map((l) => l.id || l.name));
      this.app.pinnedNodesList
        .querySelectorAll(".pinned-node-row")
        .forEach((row) => {
          const key = row.dataset.nodeKey;
          const underAtk = attackedKeys.has(key);
          row.classList.toggle("node-under-attack", underAtk);
          const statusEl = row.querySelector(".pinned-node-status");
          if (statusEl) {
            if (underAtk) {
              statusEl.className = "pinned-node-status alert";
              statusEl.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i><span>HIT</span>`;
            } else {
              statusEl.className = "pinned-node-status nominal";
              statusEl.innerHTML = `<span class="status-dot"></span><span class="status-text">OK</span>`;
            }
          }
        });
    }
  }

  /**
   * Renders operator-configured custom locations onto the map with a
   * category-specific Font Awesome icon and the configured Name underneath.
   */
  renderCustomLocations() {
    const now = performance.now();
    this.updatePinnedNodesAlarmDOM(now);

    if (
      !this.app.currentUser ||
      !this.app.projection ||
      !this.app.customLocations ||
      this.app.customLocations.length === 0
    ) {
      return;
    }

    const ctx = this.app.ctx;
    const faLoaded =
      document.fonts &&
      document.fonts.check('900 12px "Font Awesome 6 Free"');

    for (const loc of this.app.customLocations) {
      const lon = parseFloat(loc.lon);
      const lat = parseFloat(loc.lat);
      if (Number.isNaN(lon) || Number.isNaN(lat)) continue;

      const pt = this.projectToScreen([lon, lat]);
      if (!pt) continue;

      const [x, y] = pt;
      const pinMeta = getPinTypeMeta(loc.color);
      const underAttack = this.isLocationUnderAttack(loc, now);
      const accent = underAttack ? CONFIG.colorHigh : pinMeta.color;
      const labelText = (loc.name || "CITY NODE").toUpperCase();
      const isHovered =
        Math.hypot(this.lastMouseX - x, this.lastMouseY - y) <= 22;

      ctx.save();

      // 1. Subtle breathing radar ring (or rapid flashing red alarm ring if under attack)
      if (underAttack) {
        const alarmPulse = 16 + ((now * 0.025) % 14);
        ctx.strokeStyle = CONFIG.colorHigh;
        ctx.globalAlpha = 0.85;
        ctx.lineWidth = 2.0;
        ctx.beginPath();
        ctx.arc(x, y, alarmPulse, 0, Math.PI * 2);
        ctx.stroke();
      } else {
        const pulseRadius = 15 + Math.sin(now * 0.004) * 3;
        ctx.strokeStyle = accent;
        ctx.globalAlpha = isHovered ? 0.65 : 0.35;
        ctx.lineWidth = 1.2;
        ctx.beginPath();
        ctx.arc(x, y, pulseRadius, 0, Math.PI * 2);
        ctx.stroke();
      }

      // 2. Dark-glass circular badge housing the category icon
      const iconBoxRadius = 12;
      ctx.globalAlpha = 0.96;
      ctx.fillStyle = "rgba(5, 13, 28, 0.94)";
      ctx.strokeStyle = accent;
      ctx.lineWidth = isHovered ? 2.0 : 1.5;
      ctx.shadowColor = accent;
      ctx.shadowBlur = isHovered ? 16 : 10;
      ctx.beginPath();
      ctx.arc(x, y, iconBoxRadius, 0, Math.PI * 2);
      ctx.fill();
      ctx.stroke();

      // 3. Category-Specific Font Awesome Icon inside the badge
      ctx.shadowBlur = 0;
      ctx.fillStyle = accent;
      if (faLoaded) {
        ctx.font = '900 11.5px "Font Awesome 6 Free"';
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(pinMeta.unicode, x, y + 0.5);
      } else {
        this.drawFallbackPinGlyph(ctx, pinMeta.key, x, y);
      }

      // 4. Nameplate Label Centered Directly Underneath the Icon
      ctx.font = "700 10.5px JetBrains Mono, monospace";
      const nameMetrics = ctx.measureText(labelText);
      const pillW = nameMetrics.width + 14;
      const pillH = 18;
      const pillX = x - pillW / 2;
      const pillY = y + iconBoxRadius + 4;

      ctx.fillStyle = "rgba(5, 13, 28, 0.92)";
      ctx.strokeStyle = accent;
      ctx.lineWidth = 1.1;
      ctx.shadowColor = "rgba(0, 0, 0, 0.65)";
      ctx.shadowBlur = 6;
      ctx.beginPath();
      ctx.roundRect(pillX, pillY, pillW, pillH, 3);
      ctx.fill();
      ctx.stroke();

      ctx.fillStyle = "#ffffff";
      ctx.shadowBlur = 0;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";
      ctx.fillText(labelText, x, pillY + pillH / 2 + 0.5);

      // 5. Hover detail badge (Category + IP + City) underneath the name
      if (isHovered && loc.ip) {
        const subText = `${pinMeta.label} • IP: ${loc.ip}${
          loc.city ? ` • ${loc.city.toUpperCase()}` : ""
        }`;
        ctx.font = "600 9.5px JetBrains Mono, monospace";
        const subW = ctx.measureText(subText).width + 12;
        const subH = 16;
        const subX = x - subW / 2;
        const subY = pillY + pillH + 3;

        ctx.fillStyle = "rgba(3, 8, 20, 0.95)";
        ctx.strokeStyle = "rgba(255, 255, 255, 0.25)";
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.roundRect(subX, subY, subW, subH, 3);
        ctx.fill();
        ctx.stroke();

        ctx.fillStyle = accent;
        ctx.fillText(subText, x, subY + subH / 2 + 0.5);
      }

      ctx.restore();
    }
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
    const srcScreen = this.projectToScreen([data.srcLon, data.srcLat]);
    const dstScreen = this.projectToScreen([data.dstLon, data.dstLat]);
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

    const t = (performance.now() * 0.000225) % 1;
    const pulsePt = getBezierPoint(t, start, control, end);
    ctx.shadowColor = color;
    ctx.shadowBlur = 16;
    ctx.fillStyle = "#ffffff";
    ctx.globalAlpha = 1.0;
    ctx.beginPath();
    ctx.arc(pulsePt.x, pulsePt.y, 4.2, 0, Math.PI * 2);
    ctx.fill();

    const pulseRadius = 8 + Math.sin(performance.now() * 0.006) * 3;
    ctx.strokeStyle = color;
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
    const targetName =
      data.dstCity && data.dstCity !== "Unknown"
        ? data.dstCity
        : data.dstCountry;
    this.drawCityBadge(
      start.x,
      start.y,
      `SOURCE: ${originName} (${data.srcCode.toUpperCase()})`,
      color,
      color
    );
    this.drawCityBadge(
      end.x,
      end.y,
      `TARGET: ${targetName} (${data.dstCode.toUpperCase()})`,
      color,
      color
    );

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

      const [rx, ry] = this.baseToScreen(rip.x, rip.y);

      ctx.save();
      ctx.strokeStyle = rip.color;
      ctx.globalAlpha = Math.max(0, rip.opacity * dimFactor);
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.arc(rx, ry, rip.radius, 0, Math.PI * 2);
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

      const [sx, sy] = this.baseToScreen(atk.start.x, atk.start.y);
      const [ex, ey] = this.baseToScreen(atk.end.x, atk.end.y);
      const start = { x: sx, y: sy };
      const end = { x: ex, y: ey };
      const dist = Math.hypot(end.x - start.x, end.y - start.y);
      const archAltitude = Math.min(180, Math.max(35, dist * 0.28));
      const control = {
        x: (start.x + end.x) / 2,
        y: (start.y + end.y) / 2 - archAltitude,
      };

      ctx.save();

      ctx.fillStyle = atk.color;
      ctx.shadowColor = atk.color;
      ctx.shadowBlur = 10;
      ctx.globalAlpha = dimFactor;
      ctx.beginPath();
      ctx.arc(start.x, start.y, 3.2, 0, Math.PI * 2);
      ctx.arc(end.x, end.y, 3.0, 0, Math.PI * 2);
      ctx.fill();

      if (!this.app.selectedAttack) {
        this.drawCityBadge(
          start.x,
          start.y,
          `SOURCE: ${atk.cityName}`,
          atk.color,
          atk.color
        );
        if (atk.targetCityName) {
          this.drawCityBadge(
            end.x,
            end.y,
            `TARGET: ${atk.targetCityName}`,
            atk.color,
            atk.color
          );
        }
      }

      ctx.strokeStyle = atk.color;
      ctx.globalAlpha = 0.38 * dimFactor;
      ctx.lineWidth = 1.3;
      ctx.beginPath();
      ctx.moveTo(start.x, start.y);
      ctx.quadraticCurveTo(control.x, control.y, end.x, end.y);
      ctx.stroke();

      const tailT = Math.max(0, atk.progress - atk.trailLength);
      const headT = atk.progress;
      const segments = 12;

      for (let s = 0; s < segments; s++) {
        const t1 = tailT + (s / segments) * (headT - tailT);
        const t2 = tailT + ((s + 1) / segments) * (headT - tailT);

        const pt1 = getBezierPoint(t1, start, control, end);
        const pt2 = getBezierPoint(t2, start, control, end);
        const segAlpha = (s + 1) / segments;

        ctx.strokeStyle = atk.color;
        ctx.globalAlpha = segAlpha * 0.95 * dimFactor;
        ctx.lineWidth = 1.4 + segAlpha * 2.2;
        ctx.beginPath();
        ctx.moveTo(pt1.x, pt1.y);
        ctx.lineTo(pt2.x, pt2.y);
        ctx.stroke();
      }

      const headPt = getBezierPoint(headT, start, control, end);
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

    // Apply zoom & pan transform ONLY to the geographic map layers;
    // stroke widths are divided by zoomScale so coastlines stay crisp at 1:1 scale
    ctx.save();
    ctx.translate(this.panX, this.panY);
    ctx.scale(this.zoomScale, this.zoomScale);

    if (this.app.mergedLandGeo) {
      ctx.save();
      ctx.fillStyle = CONFIG.landFill;
      ctx.beginPath();
      this.app.geoPath(this.app.mergedLandGeo);
      ctx.fill();
      ctx.restore();
    }

    // Optional: All interior borders between countries (when toggled ON)
    if (this.app.showCountryBorders && this.app.bordersMesh) {
      ctx.save();
      ctx.strokeStyle = CONFIG.countryBorderStroke;
      ctx.lineWidth = (CONFIG.countryBorderWidth || 1.0) / this.zoomScale;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.beginPath();
      this.app.geoPath(this.app.bordersMesh);
      ctx.stroke();
      ctx.restore();
    }

    if (this.app.coastlineMesh) {
      ctx.save();
      ctx.strokeStyle = CONFIG.coastlineStroke;
      ctx.lineWidth = CONFIG.coastlineWidth / this.zoomScale;
      ctx.shadowColor = CONFIG.coastlineGlow;
      ctx.shadowBlur = 8;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.beginPath();
      this.app.geoPath(this.app.coastlineMesh);
      ctx.stroke();
      ctx.restore();
    }

    // Progressive Detail: Reveal smaller countries & microstates when zoomed in
    if (
      this.zoomScale >= (CONFIG.smallCountryZoomThreshold || 1.45) &&
      this.app.smallCountryFeatures &&
      this.app.smallCountryFeatures.length > 0
    ) {
      ctx.save();
      ctx.fillStyle = CONFIG.landFill;
      ctx.strokeStyle = CONFIG.coastlineStroke;
      ctx.lineWidth = 0.95 / this.zoomScale;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";

      for (const sf of this.app.smallCountryFeatures) {
        if (this.traceSmallCountryPath(ctx, sf)) {
          ctx.fill();
          ctx.stroke();
        }
      }
      ctx.restore();
    }

    if (
      this.app.hoveredCountryIndex !== null &&
      this.app.hoveredCountryIndex !== this.app.selectedCountryIndex
    ) {
      const feature = this.app.countryFeatures[this.app.hoveredCountryIndex - 1];
      if (
        feature &&
        (!feature.isSmallCountry ||
          this.zoomScale >= (CONFIG.smallCountryZoomThreshold || 1.45))
      ) {
        ctx.save();
        ctx.fillStyle = CONFIG.hoverFill;
        ctx.strokeStyle = CONFIG.hoverStroke;
        ctx.lineWidth = CONFIG.hoverStrokeWidth / this.zoomScale;
        ctx.shadowColor = CONFIG.hoverFill;
        ctx.shadowBlur = CONFIG.hoverGlowBlur;
        ctx.lineCap = "round";
        ctx.lineJoin = "round";

        if (feature.isSmallCountry) {
          this.traceSmallCountryPath(ctx, feature);
        } else {
          ctx.beginPath();
          this.app.geoPath(feature);
        }
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
        ctx.lineWidth = CONFIG.selectedCountryStrokeWidth / this.zoomScale;
        ctx.shadowColor = CONFIG.selectedCountryStroke;
        ctx.shadowBlur = CONFIG.selectedCountryGlowBlur;
        ctx.lineCap = "round";
        ctx.lineJoin = "round";

        if (selFeature.isSmallCountry) {
          this.traceSmallCountryPath(ctx, selFeature);
        } else {
          ctx.beginPath();
          this.app.geoPath(selFeature);
        }
        ctx.fill();
        ctx.stroke();
        ctx.restore();
      }
    }

    ctx.restore();

    // Render pinned custom locations & attack trajectories in 1:1 screen space
    this.renderCustomLocations();

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

    // Mouse Wheel Zoom (centered at cursor)
    this.app.canvas.addEventListener(
      "wheel",
      (e) => {
        e.preventDefault();
        const rect = this.app.canvas.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;
        const factor = e.deltaY < 0 ? 1.22 : 1 / 1.22;
        this.zoomAtPoint(this.zoomScale * factor, mouseX, mouseY);
      },
      { passive: false }
    );

    // Click-and-Drag Panning on the Map
    this.app.canvas.addEventListener("mousedown", (e) => {
      if (e.button !== 0) return;
      this.isPanning = true;
      this.didDrag = false;
      this.panStartX = e.clientX;
      this.panStartY = e.clientY;
      this.panOriginX = this.panX;
      this.panOriginY = this.panY;
    });

    window.addEventListener("mouseup", () => {
      if (this.isPanning) {
        this.isPanning = false;
        this.app.canvas.classList.remove("is-panning");
      }
    });

    // Zoom Control HUD Buttons (+ / - / Reset)
    if (this.app.btnZoomIn) {
      this.app.btnZoomIn.addEventListener("click", () => {
        this.zoomAtPoint(
          this.zoomScale * 1.35,
          window.innerWidth / 2,
          window.innerHeight / 2
        );
      });
    }
    if (this.app.btnZoomOut) {
      this.app.btnZoomOut.addEventListener("click", () => {
        this.zoomAtPoint(
          this.zoomScale / 1.35,
          window.innerWidth / 2,
          window.innerHeight / 2
        );
      });
    }
    if (this.app.btnZoomReset) {
      this.app.btnZoomReset.addEventListener("click", () => {
        this.resetZoom();
      });
    }

    // Country Borders Always-On Toggle Button
    if (this.app.btnToggleBorders) {
      this.app.btnToggleBorders.classList.toggle(
        "active",
        Boolean(this.app.showCountryBorders)
      );
      this.app.btnToggleBorders.addEventListener("click", () => {
        this.app.showCountryBorders = !this.app.showCountryBorders;
        localStorage.setItem(
          "soc_show_borders",
          String(this.app.showCountryBorders)
        );
        this.app.btnToggleBorders.classList.toggle(
          "active",
          this.app.showCountryBorders
        );
      });
    }

    // Click a pinned node row in the legend to center and zoom onto that node
    if (this.app.pinnedNodesList) {
      this.app.pinnedNodesList.addEventListener("click", (e) => {
        const row = e.target.closest(".pinned-node-row");
        if (!row || !this.app.customLocations) return;
        const key = row.dataset.nodeKey;
        const loc = this.app.customLocations.find(
          (l, idx) => (l.id || l.name || `node_${idx}`) === key
        );
        if (loc) {
          this.focusLocation(loc, Math.max(this.zoomScale, 4.0));
        }
      });
    }

    // Click on Map Country to toggle Gold highlight & open/close Gold Dossier Card
    this.app.canvas.addEventListener("click", (e) => {
      if (this.didDrag) {
        this.didDrag = false;
        return;
      }
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
      this.lastMouseX = mouseX;
      this.lastMouseY = mouseY;

      if (this.isPanning) {
        const dx = e.clientX - this.panStartX;
        const dy = e.clientY - this.panStartY;
        if (Math.hypot(dx, dy) > 4) {
          this.didDrag = true;
          this.app.canvas.classList.add("is-panning");
        }
        if (this.zoomScale > 1.0) {
          this.panX = this.panOriginX + dx;
          this.panY = this.panOriginY + dy;
          this.clampPan();
        }
        return;
      }

      if (this.app.projection) {
        const [baseX, baseY] = this.screenToBase(mouseX, mouseY);
        const coords = this.app.projection.invert([baseX, baseY]);
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
      this.lastMouseX = -1;
      this.lastMouseY = -1;
      this.app.hoveredCountryIndex = null;
      this.app.updateHoverIntel(null, 0, 0);
    });
  }
}
