/**
 * SOC Threat Matrix - Main Application Orchestrator
 * =================================================
 * Coordinates the modular MapRenderer, FeedController, LeaderboardController,
 * DossierController, AuthController, and SocketService while maintaining the
 * full ThreatMap public interface on `window.threatMap`.
 */

import { CONFIG } from "./config.js";
import { getCountryMeta } from "./data/countries.js";
import { loadHtmlPartials } from "./utils/partialLoader.js";
import {
  calculateDistanceKm,
  fileToDataUrl,
  getBezierPoint,
  getBucketColor,
  getTopKey,
  resolveSeverityBucket,
} from "./utils/helpers.js";
import { SocketService } from "./services/socketService.js";
import { MapRenderer } from "./components/mapRenderer.js";
import { FeedController } from "./components/feedController.js";
import { LeaderboardController } from "./components/leaderboardController.js";
import { DossierController } from "./components/dossierController.js";
import { AuthController } from "./components/authController.js";

export class ThreatMap {
  constructor() {
    this.canvas = document.getElementById("threat-map");
    this.ctx = this.canvas.getContext("2d");

    this.btnModeLive = document.getElementById("btn-mode-live");
    this.btnModeCustom = document.getElementById("btn-mode-custom");
    this.customModeWrapper = document.getElementById("custom-mode-wrapper");
    this.feedModeLabel = document.getElementById("feed-mode-label");
    this.activeFeedMode = "live";

    // Filter, Search & Stream Freeze States
    this.currentSeverityFilter = "ALL";
    this.onlyPinnedFilter = false;
    this.searchQuery = "";
    this.isStreamPaused = false;
    this.rawAttackBuffer = [];
    this.selectedAttack = null;

    // Stream Control & Search DOM References
    this.btnPauseStream = document.getElementById("btn-pause-stream");
    this.pauseIcon = document.getElementById("pause-icon");
    this.pauseLabel = document.getElementById("pause-label");
    this.btnExportJson = document.getElementById("btn-export-json");
    this.btnExportCsv = document.getElementById("btn-export-csv");
    this.feedSearchInput = document.getElementById("feed-search-input");
    this.btnClearSearch = document.getElementById("btn-clear-search");
    this.btnFilterPinned = document.getElementById("btn-filter-pinned");
    this.pinnedFilterBadge = document.getElementById("pinned-filter-badge");
    this.btnHudFilterPinned = document.getElementById("btn-hud-filter-pinned");

    this.coordsHud = document.getElementById("coords-hud");
    this.pinnedNodesHud = document.getElementById("pinned-nodes-hud");
    this.pinnedAlarmIndicator = document.getElementById("pinned-alarm-indicator");
    this.pinnedAlarmIcon = document.getElementById("pinned-alarm-icon");
    this.pinnedAlarmText = document.getElementById("pinned-alarm-text");
    this.pinnedNodesList = document.getElementById("pinned-nodes-list");

    this.hudAttacksTotal = document.getElementById("hud-attacks-total");
    this.hudActiveOrigins = document.getElementById("hud-active-origins");
    this.hudClock = document.getElementById("hud-clock");
    this.connStatus = document.getElementById("conn-status");

    this.btnUserProfile = document.getElementById("btn-user-profile");
    this.userAvatarImg = document.getElementById("user-avatar-img");
    this.userDefaultIcon = document.getElementById("user-default-icon");
    this.dropdownUserStatus = document.getElementById("dropdown-user-status");
    this.menuBtnAccount = document.getElementById("menu-btn-account");
    this.menuIconAccount = document.getElementById("menu-icon-account");
    this.menuTextAccount = document.getElementById("menu-text-account");
    this.menuBtnFeeds = document.getElementById("menu-btn-feeds");
    this.menuBtnLogout = document.getElementById("menu-btn-logout");

    this.authToken = localStorage.getItem("soc_auth_token") || null;
    this.currentUser = null;
    this.customLocations = [];

    this.cursorTooltip = document.getElementById("cursor-tooltip");
    this.cursorTooltipFlag = document.getElementById("cursor-tooltip-flag");
    this.cursorTooltipName = document.getElementById("cursor-tooltip-name");

    this.countryIntelBar = document.getElementById("country-intel");
    this.countryNameEl = document.getElementById("country-name");
    this.countryCodeEl = document.getElementById("country-code");
    this.countryFlagEl = document.getElementById("country-flag");
    this.flagPlaceholderEl = document.getElementById("flag-placeholder");
    this.attackTicker = document.getElementById("attack-ticker");

    this.leaderboardList = document.getElementById("leaderboard-list");
    this.leaderboardTotalHits = document.getElementById("leaderboard-total-hits");
    this.targetLeaderboardList = document.getElementById("target-leaderboard-list");
    this.targetTotalHits = document.getElementById("target-total-hits");

    // Gold Country Dossier DOM References
    this.countryDossierCard = document.getElementById("country-dossier-card");
    this.dossierHeaderTag = document.getElementById("dossier-header-tag");
    this.btnCloseDossier = document.getElementById("btn-close-dossier");
    this.dossierFlag = document.getElementById("dossier-flag");
    this.dossierCountryName = document.getElementById("dossier-country-name");
    this.dossierIsoSub = document.getElementById("dossier-iso-sub");
    this.dossierThreatBadge = document.getElementById("dossier-threat-badge");
    this.dossierOutboundVal = document.getElementById("dossier-outbound-val");
    this.dossierOutboundRank = document.getElementById("dossier-outbound-rank");
    this.dossierInboundVal = document.getElementById("dossier-inbound-val");
    this.dossierInboundRank = document.getElementById("dossier-inbound-rank");
    this.dossierTopMalware = document.getElementById("dossier-top-malware");
    this.dossierTopMitre = document.getElementById("dossier-top-mitre");
    this.dossierTopPort = document.getElementById("dossier-top-port");
    this.dossierTopAsn = document.getElementById("dossier-top-asn");
    this.dossierRatioOutLbl = document.getElementById("dossier-ratio-out-lbl");
    this.dossierRatioInLbl = document.getElementById("dossier-ratio-in-lbl");
    this.dossierRatioFill = document.getElementById("dossier-ratio-fill");

    // Detailed Attack Telemetry Dossier & Pivot DOM References
    this.attackDossierCard = document.getElementById("attack-dossier-card");
    this.atkDossierHeaderTag = document.getElementById("atk-dossier-header-tag");
    this.btnCloseAttackDossier = document.getElementById("btn-close-attack-dossier");
    this.atkDossierMalware = document.getElementById("atk-dossier-malware");
    this.atkDossierCategory = document.getElementById("atk-dossier-category");
    this.atkDossierSevBadge = document.getElementById("atk-dossier-sev-badge");
    this.atkDossierSrcIp = document.getElementById("atk-dossier-src-ip");
    this.atkDossierSrcFlag = document.getElementById("atk-dossier-src-flag");
    this.atkDossierSrcLoc = document.getElementById("atk-dossier-src-loc");
    this.atkDossierSrcCoords = document.getElementById("atk-dossier-src-coords");
    this.atkDossierDistance = document.getElementById("atk-dossier-distance");
    this.atkDossierDstPort = document.getElementById("atk-dossier-dst-port");
    this.atkDossierDstFlag = document.getElementById("atk-dossier-dst-flag");
    this.atkDossierDstLoc = document.getElementById("atk-dossier-dst-loc");
    this.atkDossierDstCoords = document.getElementById("atk-dossier-dst-coords");
    this.atkDossierCve = document.getElementById("atk-dossier-cve");
    this.atkDossierMitre = document.getElementById("atk-dossier-mitre");
    this.atkDossierAsn = document.getElementById("atk-dossier-asn");
    this.atkDossierTime = document.getElementById("atk-dossier-time");
    this.atkPivotVt = document.getElementById("atk-pivot-vt");
    this.atkPivotAbuse = document.getElementById("atk-pivot-abuse");
    this.atkPivotShodan = document.getElementById("atk-pivot-shodan");
    this.btnCopyIoc = document.getElementById("btn-copy-ioc");
    this.copyIocLabel = document.getElementById("copy-ioc-label");

    this.countryFeatures = [];
    this.featureCollection = null;
    this.mergedLandGeo = null;
    this.coastlineMesh = null;
    this.pixelRatio = window.devicePixelRatio || 1;

    this.projection = null;
    this.geoPath = null;

    this.maskData = null;
    this.maskW = 0;
    this.maskH = 0;
    this.hoveredCountryIndex = null;
    this.selectedCountryIndex = null;

    this.attacks = [];
    this.ripples = [];

    this.totalAttacksCount = parseInt(
      localStorage.getItem("soc_total_attacks") || "0",
      10
    );
    const savedOriginStats = localStorage.getItem("soc_country_stats");
    this.countryStats = savedOriginStats
      ? new Map(JSON.parse(savedOriginStats))
      : new Map();

    const savedTargetStats = localStorage.getItem("soc_target_stats");
    this.targetStats = savedTargetStats
      ? new Map(JSON.parse(savedTargetStats))
      : new Map();

    this.countryDetails = new Map();

    this.ws = null;
    this.isWsConnected = false;

    // Instantiate Modular Sub-Controllers
    this.mapRenderer = new MapRenderer(this);
    this.feedController = new FeedController(this);
    this.leaderboardController = new LeaderboardController(this);
    this.dossierController = new DossierController(this);
    this.authController = new AuthController(this);
    this.socketService = new SocketService(this);

    this.init();
  }

  async init() {
    this.startClock();
    this.bindEvents();
    this.bindAuthEvents();
    this.bindFilterEvents();

    this.hudAttacksTotal.textContent = this.totalAttacksCount.toLocaleString();
    this.hudActiveOrigins.textContent = `${this.countryStats.size} REGIONS`;
    this.updateLeaderboards();
    this.renderPinnedNodesLegend();

    await this.checkExistingSession();
    await this.loadCartography();
    this.resize();

    this.animate();
    this.connectWebSocket();
  }

  // =====================================================================
  // DELEGATED CONTROLLER METHODS (Preserving Full ThreatMap Interface)
  // =====================================================================

  resolveSeverityBucket(data) {
    return resolveSeverityBucket(data);
  }
  getBucketColor(bucket) {
    return getBucketColor(bucket);
  }
  getCountryMeta(feature) {
    return getCountryMeta(feature);
  }
  getTopKey(mapObj, fallback) {
    return getTopKey(mapObj, fallback);
  }
  calculateDistanceKm(lat1, lon1, lat2, lon2) {
    return calculateDistanceKm(lat1, lon1, lat2, lon2);
  }
  getBezierPoint(t, p0, p1, p2) {
    return getBezierPoint(t, p0, p1, p2);
  }
  fileToDataUrl(file) {
    return fileToDataUrl(file);
  }

  // Feed & Filter Delegation
  matchesFilterBucket(bucket) {
    return this.feedController.matchesFilterBucket(bucket);
  }
  matchesPinnedIp(data) {
    return this.feedController.matchesPinnedIp(data);
  }
  matchesSearchQuery(data) {
    return this.feedController.matchesSearchQuery(data);
  }
  matchesActiveFilters(data) {
    return this.feedController.matchesActiveFilters(data);
  }
  togglePinnedIpFilter() {
    this.feedController.togglePinnedIpFilter();
  }
  toggleStreamPause() {
    this.feedController.toggleStreamPause();
  }
  appendTickerRowDOM(data) {
    this.feedController.appendTickerRowDOM(data);
  }
  syncSelectedCardDOM() {
    this.feedController.syncSelectedCardDOM();
  }
  rebuildTickerFromBuffer() {
    this.feedController.rebuildTickerFromBuffer();
  }
  getFilteredBufferForExport() {
    return this.feedController.getFilteredBufferForExport();
  }
  exportSessionData(format) {
    this.feedController.exportSessionData(format);
  }
  bindFilterEvents() {
    this.feedController.bindFilterEvents();
  }

  // Leaderboard Delegation
  recordCountryDetail(code, data) {
    this.leaderboardController.recordCountryDetail(code, data);
  }
  recordStats(srcCode, srcName, dstCode, dstName) {
    this.leaderboardController.recordStats(srcCode, srcName, dstCode, dstName);
  }
  renderLeaderboardHTML(statsMap) {
    return this.leaderboardController.renderLeaderboardHTML(statsMap);
  }
  updateLeaderboards() {
    this.leaderboardController.updateLeaderboards();
  }

  // Dossier & Hover Delegation
  updateCountryDossier() {
    this.dossierController.updateCountryDossier();
  }
  updateAttackDossier() {
    this.dossierController.updateAttackDossier();
  }
  copySelectedIoc() {
    return this.dossierController.copySelectedIoc();
  }
  updateHoverIntel(countryIndex, clientX, clientY) {
    this.dossierController.updateHoverIntel(countryIndex, clientX, clientY);
  }

  // Auth & Profile Delegation
  switchFeedMode(mode) {
    this.authController.switchFeedMode(mode);
  }
  checkExistingSession() {
    return this.authController.checkExistingSession();
  }
  updateUserHeaderUI() {
    this.authController.updateUserHeaderUI();
  }
  bindAuthEvents() {
    this.authController.bindAuthEvents();
  }

  // Map & Canvas Delegation
  loadCartography() {
    return this.mapRenderer.loadCartography();
  }
  resize() {
    this.mapRenderer.resize();
  }
  generateHitMask(width, height) {
    this.mapRenderer.generateHitMask(width, height);
  }
  detectCountryAtPoint(mouseX, mouseY) {
    return this.mapRenderer.detectCountryAtPoint(mouseX, mouseY);
  }
  addRipple(x, y, color, maxRadius, maxOpacity, data) {
    this.mapRenderer.addRipple(x, y, color, maxRadius, maxOpacity, data);
  }
  drawCityBadge(x, y, text, borderColor, dotColor) {
    this.mapRenderer.drawCityBadge(x, y, text, borderColor, dotColor);
  }
  renderCustomLocations() {
    this.mapRenderer.renderCustomLocations();
  }
  renderPinnedNodesLegend() {
    this.mapRenderer.renderPinnedNodesLegend();
  }
  drawCyberOceanBackdrop(width, height) {
    this.mapRenderer.drawCyberOceanBackdrop(width, height);
  }
  renderSelectedAttack() {
    this.mapRenderer.renderSelectedAttack();
  }
  renderAttacks() {
    this.mapRenderer.renderAttacks();
  }
  render() {
    this.mapRenderer.render();
  }

  // WebSocket Delegation
  connectWebSocket() {
    this.socketService.connect();
  }

  // =====================================================================
  // CORE EVENT DISPATCH & ANIMATION LOOP
  // =====================================================================

  triggerAttack(data) {
    if (!this.projection) return;

    const attackId = Math.random().toString(36).substr(2, 9);
    const bucket = this.resolveSeverityBucket(data);
    data._id = attackId;
    data._bucket = bucket;
    data._timestamp = new Date().toTimeString().split(" ")[0] + " UTC";

    // Strict IP-based matching: a pinned node is under attack ONLY when its
    // configured IP address matches the attack telemetry's destination (or source) IP.
    const normalizeIp = (val) => String(val || "").trim().split(":")[0];
    const dstIp = normalizeIp(data.dstIp);
    const srcIp = normalizeIp(data.srcIp);

    let matchedLoc = null;
    if (
      this.currentUser &&
      this.customLocations &&
      this.customLocations.length > 0
    ) {
      const matchingLocs = this.customLocations.filter((loc) => {
        const locIp = normalizeIp(loc.ip);
        return (
          locIp &&
          locIp !== "N/A" &&
          (locIp === dstIp || locIp === srcIp)
        );
      });

      if (matchingLocs.length > 0) {
        matchedLoc = matchingLocs[0];
        data._matchesPinnedIp = true;
        const until = performance.now() + 6500;
        matchingLocs.forEach((loc) => {
          loc._underAttackUntil = until;
        });

        // If the pinned IP is the destination target, align the arc endpoint to the pin's coordinates
        if (
          normalizeIp(matchedLoc.ip) === dstIp &&
          Number.isFinite(Number(matchedLoc.lat)) &&
          Number.isFinite(Number(matchedLoc.lon))
        ) {
          data.dstLat = Number(matchedLoc.lat);
          data.dstLon = Number(matchedLoc.lon);
          data.dstCity = matchedLoc.name || data.dstCity;
          data.dstCountry = matchedLoc.country || data.dstCountry;
          if (matchedLoc.code && matchedLoc.code !== "un") {
            data.dstCode = matchedLoc.code;
          }
        }
      }
    }

    this.rawAttackBuffer.unshift(data);
    if (this.rawAttackBuffer.length > 250) this.rawAttackBuffer.pop();

    this.recordCountryDetail(data.srcCode, data);
    this.recordCountryDetail(data.dstCode, data);

    if (this.matchesActiveFilters(data)) {
      this.appendTickerRowDOM(data);
    }

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

    const speed =
      CONFIG.arcSpeedMin +
      Math.random() * (CONFIG.arcSpeedMax - CONFIG.arcSpeedMin);
    const arcColor = this.getBucketColor(bucket);

    this.attacks.push({
      id: attackId,
      start: { x: srcScreen[0], y: srcScreen[1] },
      control: controlPoint,
      end: { x: dstScreen[0], y: dstScreen[1] },
      progress: 0,
      speed: speed,
      color: arcColor,
      bucket: bucket,
      trailLength: 0.16,
      targetLocationKey: matchedLoc ? matchedLoc.id || matchedLoc.name : null,
      targetIp: matchedLoc ? normalizeIp(matchedLoc.ip) : null,
      cityName:
        data.srcCity && data.srcCity !== "Unknown"
          ? data.srcCity
          : data.srcCountry,
      data: data,
    });

    this.addRipple(srcScreen[0], srcScreen[1], arcColor, 16, 0.85, data);
    this.totalAttacksCount++;
    localStorage.setItem(
      "soc_total_attacks",
      this.totalAttacksCount.toString()
    );

    this.recordStats(
      data.srcCode,
      data.srcCountry,
      data.dstCode,
      data.dstCountry
    );
    this.hudAttacksTotal.textContent = this.totalAttacksCount.toLocaleString();

    if (this.selectedCountryIndex !== null) {
      this.updateCountryDossier();
    }
  }

  bindEvents() {
    this.mapRenderer.bindMapEvents();
    this.dossierController.bindDossierEvents();
  }

  animate() {
    this.render();
    requestAnimationFrame(() => this.animate());
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

document.addEventListener("DOMContentLoaded", async () => {
  await loadHtmlPartials();
  window.threatMap = new ThreatMap();
});
