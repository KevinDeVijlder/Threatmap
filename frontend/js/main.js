/**
 * SOC Threat Matrix - Complete Analyst Triage, OSINT Pivot & Export Engine
 * - External Threat Intel Pivot Links (VirusTotal, AbuseIPDB, Shodan, NIST NVD, MITRE ATT&CK)
 * - Stream Pause/Resume Freeze & Real-Time Search Filtering (Feed + Map)
 * - One-Click IOC Clipboard Copy & Session JSON/CSV Export
 * - Full ISO 3166-1 Country Lookup + Gold Country Dossier & Attack Dossier Cards
 */

const CONFIG = {
  horizontalMargin: 360,
  topReservedHeight: 75,
  bottomMargin: 45,

  landFill: "#122645",
  coastlineStroke: "#ffffff",
  coastlineWidth: 1.5,
  coastlineGlow: "rgba(0, 111, 255, 0.4)",

  hoverFill: "#006FFF",
  hoverStroke: "#00F0FF",
  hoverStrokeWidth: 1.8,
  hoverGlowBlur: 18,

  selectedCountryFill: "rgba(255, 196, 0, 0.36)",
  selectedCountryStroke: "#FFD000",
  selectedCountryStrokeWidth: 2.2,
  selectedCountryGlowBlur: 20,

  minorGridStroke: "rgba(0, 111, 255, 0.045)",
  majorGridStroke: "rgba(0, 111, 255, 0.11)",
  crosshairStroke: "rgba(0, 240, 255, 0.22)",
  radarRingStroke: "rgba(0, 111, 255, 0.08)",

  // Cohesive 3-Color Telemetry Palette
  colorHigh: "#FF5E36",   // Cyber Flame Coral
  colorMed: "#FFB800",    // Solar Amber Gold
  colorLow: "#00A3FF",    // Electric Azure Blue

  arcSpeedMin: 0.003,
  arcSpeedMax: 0.0055,

  wsUrl: `ws://${window.location.hostname || "localhost"}:8000/ws`,
  apiBase: `http://${window.location.hostname || "localhost"}:8000`,
};

const COUNTRY_LOOKUP = {
  4: { name: "Afghanistan", code: "af" },
  8: { name: "Albania", code: "al" },
  12: { name: "Algeria", code: "dz" },
  16: { name: "American Samoa", code: "as" },
  20: { name: "Andorra", code: "ad" },
  24: { name: "Angola", code: "ao" },
  28: { name: "Antigua and Barbuda", code: "ag" },
  31: { name: "Azerbaijan", code: "az" },
  32: { name: "Argentina", code: "ar" },
  36: { name: "Australia", code: "au" },
  40: { name: "Austria", code: "at" },
  44: { name: "Bahamas", code: "bs" },
  48: { name: "Bahrain", code: "bh" },
  50: { name: "Bangladesh", code: "bd" },
  51: { name: "Armenia", code: "am" },
  52: { name: "Barbados", code: "bb" },
  56: { name: "Belgium", code: "be" },
  60: { name: "Bermuda", code: "bm" },
  64: { name: "Bhutan", code: "bt" },
  68: { name: "Bolivia", code: "bo" },
  70: { name: "Bosnia and Herzegovina", code: "ba" },
  72: { name: "Botswana", code: "bw" },
  76: { name: "Brazil", code: "br" },
  84: { name: "Belize", code: "bz" },
  90: { name: "Solomon Islands", code: "sb" },
  96: { name: "Brunei", code: "bn" },
  100: { name: "Bulgaria", code: "bg" },
  104: { name: "Myanmar", code: "mm" },
  108: { name: "Burundi", code: "bi" },
  112: { name: "Belarus", code: "by" },
  116: { name: "Cambodia", code: "kh" },
  120: { name: "Cameroon", code: "cm" },
  124: { name: "Canada", code: "ca" },
  132: { name: "Cape Verde", code: "cv" },
  140: { name: "Central African Republic", code: "cf" },
  144: { name: "Sri Lanka", code: "lk" },
  148: { name: "Chad", code: "td" },
  152: { name: "Chile", code: "cl" },
  156: { name: "China", code: "cn" },
  158: { name: "Taiwan", code: "tw" },
  170: { name: "Colombia", code: "co" },
  174: { name: "Comoros", code: "km" },
  178: { name: "Republic of the Congo", code: "cg" },
  180: { name: "DR Congo", code: "cd" },
  188: { name: "Costa Rica", code: "cr" },
  191: { name: "Croatia", code: "hr" },
  192: { name: "Cuba", code: "cu" },
  196: { name: "Cyprus", code: "cy" },
  203: { name: "Czechia", code: "cz" },
  204: { name: "Benin", code: "bj" },
  208: { name: "Denmark", code: "dk" },
  212: { name: "Dominica", code: "dm" },
  214: { name: "Dominican Republic", code: "do" },
  218: { name: "Ecuador", code: "ec" },
  222: { name: "El Salvador", code: "sv" },
  226: { name: "Equatorial Guinea", code: "gq" },
  231: { name: "Ethiopia", code: "et" },
  232: { name: "Eritrea", code: "er" },
  233: { name: "Estonia", code: "ee" },
  238: { name: "Falkland Islands", code: "fk" },
  242: { name: "Fiji", code: "fj" },
  246: { name: "Finland", code: "fi" },
  250: { name: "France", code: "fr" },
  254: { name: "French Guiana", code: "gf" },
  258: { name: "French Polynesia", code: "pf" },
  260: { name: "French Southern Lands", code: "tf" },
  262: { name: "Djibouti", code: "dj" },
  266: { name: "Gabon", code: "ga" },
  268: { name: "Georgia", code: "ge" },
  270: { name: "Gambia", code: "gm" },
  275: { name: "Palestine", code: "ps" },
  276: { name: "Germany", code: "de" },
  288: { name: "Ghana", code: "gh" },
  300: { name: "Greece", code: "gr" },
  304: { name: "Greenland", code: "gl" },
  308: { name: "Grenada", code: "gd" },
  316: { name: "Guam", code: "gu" },
  320: { name: "Guatemala", code: "gt" },
  324: { name: "Guinea", code: "gn" },
  328: { name: "Guyana", code: "gy" },
  332: { name: "Haiti", code: "ht" },
  340: { name: "Honduras", code: "hn" },
  344: { name: "Hong Kong", code: "hk" },
  348: { name: "Hungary", code: "hu" },
  352: { name: "Iceland", code: "is" },
  356: { name: "India", code: "in" },
  360: { name: "Indonesia", code: "id" },
  364: { name: "Iran", code: "ir" },
  368: { name: "Iraq", code: "iq" },
  372: { name: "Ireland", code: "ie" },
  376: { name: "Israel", code: "il" },
  380: { name: "Italy", code: "it" },
  384: { name: "Ivory Coast", code: "ci" },
  388: { name: "Jamaica", code: "jm" },
  392: { name: "Japan", code: "jp" },
  398: { name: "Kazakhstan", code: "kz" },
  400: { name: "Jordan", code: "jo" },
  404: { name: "Kenya", code: "ke" },
  408: { name: "North Korea", code: "kp" },
  410: { name: "South Korea", code: "kr" },
  414: { name: "Kuwait", code: "kw" },
  417: { name: "Kyrgyzstan", code: "kg" },
  418: { name: "Laos", code: "la" },
  422: { name: "Lebanon", code: "lb" },
  426: { name: "Lesotho", code: "ls" },
  428: { name: "Latvia", code: "lv" },
  430: { name: "Liberia", code: "lr" },
  434: { name: "Libya", code: "ly" },
  440: { name: "Lithuania", code: "lt" },
  442: { name: "Luxembourg", code: "lu" },
  450: { name: "Madagascar", code: "mg" },
  454: { name: "Malawi", code: "mw" },
  458: { name: "Malaysia", code: "my" },
  462: { name: "Maldives", code: "mv" },
  466: { name: "Mali", code: "ml" },
  470: { name: "Malta", code: "mt" },
  478: { name: "Mauritania", code: "mr" },
  480: { name: "Mauritius", code: "mu" },
  484: { name: "Mexico", code: "mx" },
  496: { name: "Mongolia", code: "mn" },
  498: { name: "Moldova", code: "md" },
  499: { name: "Montenegro", code: "me" },
  504: { name: "Morocco", code: "ma" },
  508: { name: "Mozambique", code: "mz" },
  512: { name: "Oman", code: "om" },
  516: { name: "Namibia", code: "na" },
  524: { name: "Nepal", code: "np" },
  528: { name: "Netherlands", code: "nl" },
  540: { name: "New Caledonia", code: "nc" },
  548: { name: "Vanuatu", code: "vu" },
  554: { name: "New Zealand", code: "nz" },
  558: { name: "Nicaragua", code: "ni" },
  562: { name: "Niger", code: "ne" },
  566: { name: "Nigeria", code: "ng" },
  578: { name: "Norway", code: "no" },
  586: { name: "Pakistan", code: "pk" },
  591: { name: "Panama", code: "pa" },
  598: { name: "Papua New Guinea", code: "pg" },
  600: { name: "Paraguay", code: "py" },
  604: { name: "Peru", code: "pe" },
  608: { name: "Philippines", code: "ph" },
  616: { name: "Poland", code: "pl" },
  620: { name: "Portugal", code: "pt" },
  624: { name: "Guinea-Bissau", code: "gw" },
  626: { name: "Timor-Leste", code: "tl" },
  630: { name: "Puerto Rico", code: "pr" },
  634: { name: "Qatar", code: "qa" },
  642: { name: "Romania", code: "ro" },
  643: { name: "Russia", code: "ru" },
  646: { name: "Rwanda", code: "rw" },
  682: { name: "Saudi Arabia", code: "sa" },
  686: { name: "Senegal", code: "sn" },
  688: { name: "Serbia", code: "rs" },
  694: { name: "Sierra Leone", code: "sl" },
  702: { name: "Singapore", code: "sg" },
  703: { name: "Slovakia", code: "sk" },
  704: { name: "Vietnam", code: "vn" },
  705: { name: "Slovenia", code: "si" },
  706: { name: "Somalia", code: "so" },
  710: { name: "South Africa", code: "za" },
  716: { name: "Zimbabwe", code: "zw" },
  724: { name: "Spain", code: "es" },
  728: { name: "South Sudan", code: "ss" },
  729: { name: "Sudan", code: "sd" },
  732: { name: "Western Sahara", code: "eh" },
  740: { name: "Suriname", code: "sr" },
  748: { name: "Eswatini", code: "sz" },
  752: { name: "Sweden", code: "se" },
  756: { name: "Switzerland", code: "ch" },
  760: { name: "Syria", code: "sy" },
  762: { name: "Tajikistan", code: "tj" },
  764: { name: "Thailand", code: "th" },
  768: { name: "Togo", code: "tg" },
  780: { name: "Trinidad and Tobago", code: "tt" },
  784: { name: "United Arab Emirates", code: "ae" },
  788: { name: "Tunisia", code: "tn" },
  792: { name: "Turkey", code: "tr" },
  795: { name: "Turkmenistan", code: "tm" },
  800: { name: "Uganda", code: "ug" },
  804: { name: "Ukraine", code: "ua" },
  807: { name: "North Macedonia", code: "mk" },
  818: { name: "Egypt", code: "eg" },
  826: { name: "United Kingdom", code: "gb" },
  834: { name: "Tanzania", code: "tz" },
  840: { name: "United States", code: "us" },
  854: { name: "Burkina Faso", code: "bf" },
  858: { name: "Uruguay", code: "uy" },
  860: { name: "Uzbekistan", code: "uz" },
  862: { name: "Venezuela", code: "ve" },
  887: { name: "Yemen", code: "ye" },
  894: { name: "Zambia", code: "zm" }
};

const NAME_FALLBACK_LOOKUP = {
  "Kosovo": { name: "Kosovo", code: "xk" },
  "Somaliland": { name: "Somaliland", code: "so" },
  "N. Cyprus": { name: "Northern Cyprus", code: "cy" },
  "W. Sahara": { name: "Western Sahara", code: "eh" },
  "Falkland Is.": { name: "Falkland Islands", code: "fk" },
  "Fr. S. Antarctic Lands": { name: "French Southern Lands", code: "tf" }
};

class ThreatMap {
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

    this.coordsHud = document.getElementById("coords-hud");
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

    this.userModalBackdrop = document.getElementById("user-modal-backdrop");
    this.modalTitle = document.getElementById("modal-title");
    this.btnCloseModal = document.getElementById("btn-close-modal");
    this.modalAuthView = document.getElementById("modal-auth-view");
    this.modalAccountView = document.getElementById("modal-account-view");
    this.modalFeedsView = document.getElementById("modal-feeds-view");

    this.tabLogin = document.getElementById("tab-login");
    this.tabRegister = document.getElementById("tab-register");
    this.authForm = document.getElementById("auth-form");
    this.authUsername = document.getElementById("auth-username");
    this.authPassword = document.getElementById("auth-password");
    this.registerAvatarGroup = document.getElementById("register-avatar-group");
    this.regAvatarInput = document.getElementById("reg-avatar-input");
    this.regAvatarPreview = document.getElementById("reg-avatar-preview");
    this.regAvatarPlaceholder = document.getElementById("reg-avatar-placeholder");
    this.authError = document.getElementById("auth-error");
    this.btnAuthSubmit = document.getElementById("btn-auth-submit");

    this.profileAvatarPreview = document.getElementById("profile-avatar-preview");
    this.profileAvatarPlaceholder = document.getElementById("profile-avatar-placeholder");
    this.profileUsernameDisplay = document.getElementById("profile-username-display");
    this.profileAvatarInput = document.getElementById("profile-avatar-input");
    this.sourceNameInput = document.getElementById("source-name-input");
    this.sourceUrlInput = document.getElementById("source-url-input");
    this.btnAddSource = document.getElementById("btn-add-source");
    this.customSourcesList = document.getElementById("custom-sources-list");

    this.authMode = "login";
    this.pendingRegAvatar = "";
    this.authToken = localStorage.getItem("soc_auth_token") || null;
    this.currentUser = null;

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

    this.totalAttacksCount = parseInt(localStorage.getItem("soc_total_attacks") || "0", 10);
    const savedOriginStats = localStorage.getItem("soc_country_stats");
    this.countryStats = savedOriginStats ? new Map(JSON.parse(savedOriginStats)) : new Map();

    const savedTargetStats = localStorage.getItem("soc_target_stats");
    this.targetStats = savedTargetStats ? new Map(JSON.parse(savedTargetStats)) : new Map();

    this.countryDetails = new Map();

    this.ws = null;
    this.isWsConnected = false;

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

    await this.checkExistingSession();
    await this.loadCartography();
    this.resize();

    this.animate();
    this.connectWebSocket();
  }

  // =====================================================================
  // SEVERITY NORMALIZATION, SEARCH & FILTER MATCHING
  // =====================================================================

  resolveSeverityBucket(data) {
    const rawSev = (data.severity || "").toUpperCase();
    const malware = (data.malware || "").toUpperCase();
    const category = (data.category || "").toUpperCase();

    if (rawSev === "LOW" || rawSev === "INFO") return "LOW";
    if (rawSev === "MEDIUM") return "MEDIUM";

    if (malware.includes("SCAN") || malware.includes("BRUTE") || category.includes("PROBE") || category.includes("SCAN")) {
      return data.port === 22 || data.port === 23 ? "LOW" : "MEDIUM";
    }
    if (data.port === 80 || data.port === 8080) {
      return "MEDIUM";
    }
    if (rawSev === "CRITICAL" || rawSev === "HIGH") {
      return "HIGH";
    }
    return "LOW";
  }

  getBucketColor(bucket) {
    if (bucket === "HIGH") return CONFIG.colorHigh;     // #FF5E36 (Cyber Flame Coral)
    if (bucket === "MEDIUM") return CONFIG.colorMed;    // #FFB800 (Solar Amber Gold)
    return CONFIG.colorLow;                             // #00A3FF (Electric Azure Blue)
  }

  matchesFilterBucket(bucket) {
    if (this.currentSeverityFilter === "ALL") return true;
    return bucket === this.currentSeverityFilter;
  }

  matchesSearchQuery(data) {
    if (!this.searchQuery) return true;
    const q = this.searchQuery.toLowerCase();
    const haystack = [
      data.malware,
      data.category,
      data.srcIp,
      data.srcCity,
      data.srcCountry,
      data.srcCode,
      data.srcAsn,
      data.dstCity,
      data.dstCountry,
      data.dstCode,
      data.cve,
      data.mitre,
      String(data.port || ""),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();

    return haystack.includes(q);
  }

  matchesActiveFilters(data) {
    if (!data) return false;
    const bucket = data._bucket || this.resolveSeverityBucket(data);
    return this.matchesFilterBucket(bucket) && this.matchesSearchQuery(data);
  }

  // =====================================================================
  // COUNTRY METADATA & DOSSIER CARDS
  // =====================================================================

  getCountryMeta(feature) {
    if (!feature) return null;
    const numericId = parseInt(feature.id, 10);
    if (!Number.isNaN(numericId) && COUNTRY_LOOKUP[numericId]) {
      return {
        name: COUNTRY_LOOKUP[numericId].name,
        code: COUNTRY_LOOKUP[numericId].code,
        idLabel: numericId
      };
    }

    const propName = feature.properties && feature.properties.name ? feature.properties.name.trim() : "";
    if (propName && NAME_FALLBACK_LOOKUP[propName]) {
      return {
        name: NAME_FALLBACK_LOOKUP[propName].name,
        code: NAME_FALLBACK_LOOKUP[propName].code,
        idLabel: Number.isNaN(numericId) ? "EXT" : numericId
      };
    }

    if (propName) {
      return {
        name: propName,
        code: null,
        idLabel: Number.isNaN(numericId) ? "EXT" : numericId
      };
    }

    return null;
  }

  recordCountryDetail(code, data) {
    if (!code) return;
    const key = code.toLowerCase();
    if (!this.countryDetails.has(key)) {
      this.countryDetails.set(key, {
        malwareCounts: new Map(),
        portCounts: new Map(),
        lastMitre: data.mitre || "T1071.001",
        lastAsn: data.srcAsn || "AS_EDGE",
      });
    }
    const entry = this.countryDetails.get(key);
    const mw = data.malware || "C2_BEACON";
    const pt = `${data.port || 443}/${data.proto || "TCP"}`;
    entry.malwareCounts.set(mw, (entry.malwareCounts.get(mw) || 0) + 1);
    entry.portCounts.set(pt, (entry.portCounts.get(pt) || 0) + 1);
    if (data.mitre) entry.lastMitre = data.mitre;
    if (data.srcAsn && data.srcAsn !== "AS_EDGE") entry.lastAsn = data.srcAsn;
  }

  getTopKey(mapObj, fallback) {
    if (!mapObj || mapObj.size === 0) return fallback;
    let bestKey = fallback;
    let bestCount = -1;
    for (const [k, v] of mapObj.entries()) {
      if (v > bestCount) {
        bestCount = v;
        bestKey = k;
      }
    }
    return bestKey;
  }

  updateCountryDossier() {
    if (!this.selectedCountryIndex || this.selectedCountryIndex <= 0 || this.selectedCountryIndex > this.countryFeatures.length) {
      this.countryDossierCard.style.display = "none";
      return;
    }

    const feature = this.countryFeatures[this.selectedCountryIndex - 1];
    const meta = this.getCountryMeta(feature) || { name: "Unknown Sector", code: "un", idLabel: "--" };
    const code = (meta.code || "un").toLowerCase();

    const sortedOut = Array.from(this.countryStats.values()).sort((a, b) => b.count - a.count);
    const outIdx = sortedOut.findIndex(item => item.code.toLowerCase() === code);
    const outHits = outIdx !== -1 ? sortedOut[outIdx].count : 0;
    const outRankStr = outIdx !== -1 ? `RANK: #${outIdx + 1} GLOBAL` : "RANK: UNRANKED";

    const sortedIn = Array.from(this.targetStats.values()).sort((a, b) => b.count - a.count);
    const inIdx = sortedIn.findIndex(item => item.code.toLowerCase() === code);
    const inHits = inIdx !== -1 ? sortedIn[inIdx].count : 0;
    const inRankStr = inIdx !== -1 ? `RANK: #${inIdx + 1} TARGET` : "RANK: UNRANKED";

    const totalCountryHits = outHits + inHits;
    const globalShare = this.totalAttacksCount > 0
      ? ((totalCountryHits / (this.totalAttacksCount * 2)) * 100).toFixed(1)
      : "0.0";

    let threatLevel = "LOW ACTIVITY";
    if (outIdx >= 0 && outIdx < 3) threatLevel = "CRITICAL ORIGIN";
    else if (inIdx >= 0 && inIdx < 3) threatLevel = "PRIMARY TARGET";
    else if (totalCountryHits > 25) threatLevel = "ELEVATED";
    else if (totalCountryHits > 0) threatLevel = "ACTIVE NODE";

    const details = this.countryDetails.get(code);
    const topMalware = details ? this.getTopKey(details.malwareCounts, "SSL_C2_BEACON") : (totalCountryHits > 0 ? "SSL_C2_BEACON" : "NO SIGNATURES");
    const topPort = details ? this.getTopKey(details.portCounts, "443/TCP") : (totalCountryHits > 0 ? "443/TCP" : "--/TCP");
    const topMitre = details ? details.lastMitre : (totalCountryHits > 0 ? "T1071.001" : "N/A");
    const topAsn = details ? details.lastAsn : (totalCountryHits > 0 ? "AS_TRANSIT" : "N/A");

    this.dossierHeaderTag.textContent = `SECTOR INTELLIGENCE // ${code.toUpperCase()}`;
    if (meta.code) {
      this.dossierFlag.src = `https://flagcdn.com/w80/${code}.png`;
      this.dossierFlag.style.display = "block";
    } else {
      this.dossierFlag.style.display = "none";
    }
    this.dossierCountryName.textContent = meta.name.toUpperCase();
    this.dossierIsoSub.textContent = `ISO: ${code.toUpperCase()} // TRAFFIC SHARE: ${globalShare}%`;
    this.dossierThreatBadge.textContent = threatLevel;

    this.dossierOutboundVal.textContent = outHits.toLocaleString();
    this.dossierOutboundRank.textContent = outRankStr;
    this.dossierInboundVal.textContent = inHits.toLocaleString();
    this.dossierInboundRank.textContent = inRankStr;

    this.dossierTopMalware.textContent = topMalware;
    this.dossierTopMitre.textContent = `MITRE: ${topMitre}`;
    this.dossierTopPort.textContent = topPort;
    this.dossierTopAsn.textContent = `ASN: ${topAsn}`;

    const outPct = totalCountryHits > 0 ? Math.round((outHits / totalCountryHits) * 100) : 50;
    const inPct = totalCountryHits > 0 ? 100 - outPct : 50;
    this.dossierRatioOutLbl.textContent = `OUTBOUND: ${outPct}%`;
    this.dossierRatioInLbl.textContent = `INBOUND: ${inPct}%`;
    this.dossierRatioFill.style.width = `${outPct}%`;

    this.countryDossierCard.style.display = "flex";
  }

  calculateDistanceKm(lat1, lon1, lat2, lon2) {
    const toRad = deg => (deg * Math.PI) / 180;
    const R = 6371;
    const dLat = toRad(lat2 - lat1);
    const dLon = toRad(lon2 - lon1);
    const a =
      Math.sin(dLat / 2) * Math.sin(dLat / 2) +
      Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
      Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return Math.round(R * c);
  }

  updateAttackDossier() {
    if (!this.attackDossierCard) return;

    if (!this.selectedAttack) {
      this.attackDossierCard.style.display = "none";
      return;
    }

    const d = this.selectedAttack;
    const bucket = d._bucket || this.resolveSeverityBucket(d);

    this.attackDossierCard.classList.remove("sev-high", "sev-med", "sev-low");
    if (bucket === "HIGH") this.attackDossierCard.classList.add("sev-high");
    else if (bucket === "MEDIUM") this.attackDossierCard.classList.add("sev-med");
    else this.attackDossierCard.classList.add("sev-low");

    const srcCode = (d.srcCode || "un").toLowerCase();
    const dstCode = (d.dstCode || "un").toLowerCase();
    const srcCity = (d.srcCity && d.srcCity !== "Unknown") ? d.srcCity : d.srcCountry;
    const dstCity = d.dstCity || d.dstCountry;
    const distKm = this.calculateDistanceKm(d.srcLat, d.srcLon, d.dstLat, d.dstLon);
    const cveClean = (d.cve || "CVE-N/A").replace(/^CVE:\s*/i, "").trim();
    const mitreClean = (d.mitre || "T1071").trim();
    const ipClean = (d.srcIp && d.srcIp !== "N/A") ? d.srcIp.trim() : "";

    this.atkDossierHeaderTag.textContent = `INTRUSION TELEMETRY // ID #${d._id.toUpperCase()}`;
    this.atkDossierMalware.textContent = d.malware || "UNKNOWN_THREAT";
    this.atkDossierCategory.textContent = `${d.category || "C2_EVENT"} // ${(d.feedMode || "LIVE").toUpperCase()} FEED`;
    this.atkDossierSevBadge.textContent = `${bucket} (${(d.severity || bucket).toUpperCase()})`;

    this.atkDossierSrcIp.textContent = ipClean ? `IP: ${ipClean}` : `ASN: ${d.srcAsn || "AS_EDGE"}`;
    this.atkDossierSrcFlag.src = `https://flagcdn.com/w40/${srcCode}.png`;
    this.atkDossierSrcLoc.textContent = `${srcCity}, ${d.srcCountry} (${srcCode.toUpperCase()})`;
    this.atkDossierSrcCoords.textContent = `LAT: ${Number(d.srcLat).toFixed(4)}° | LON: ${Number(d.srcLon).toFixed(4)}°`;

    this.atkDossierDistance.textContent = `VECTOR DISTANCE: ${distKm.toLocaleString()} KM`;

    this.atkDossierDstPort.textContent = `PORT: ${d.port || 443} / ${d.proto || "TCP"}`;
    this.atkDossierDstFlag.src = `https://flagcdn.com/w40/${dstCode}.png`;
    this.atkDossierDstLoc.textContent = `${dstCity}, ${d.dstCountry} (${dstCode.toUpperCase()})`;
    this.atkDossierDstCoords.textContent = `LAT: ${Number(d.dstLat).toFixed(4)}° | LON: ${Number(d.dstLon).toFixed(4)}°`;

    // Clickable NIST NVD Link for CVE
    const cveSpan = this.atkDossierCve.querySelector("span");
    if (cveSpan) cveSpan.textContent = cveClean;
    this.atkDossierCve.href = /^CVE-\d{4}-\d+/i.test(cveClean)
      ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveClean)}`
      : `https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(d.malware || "")}`;

    // Clickable MITRE ATT&CK Link (converts T1071.001 -> T1071/001)
    const mitreSpan = this.atkDossierMitre.querySelector("span");
    if (mitreSpan) mitreSpan.textContent = mitreClean;
    const mitrePath = mitreClean.replace(".", "/");
    this.atkDossierMitre.href = `https://attack.mitre.org/techniques/${mitrePath}/`;

    this.atkDossierAsn.textContent = d.srcAsn || "AS_EDGE";
    this.atkDossierTime.textContent = d._timestamp || "LIVE";

    // External Threat Intel Pivot Links (VirusTotal, AbuseIPDB, Shodan)
    const queryTarget = ipClean || d.srcCountry || "";
    this.atkPivotVt.href = ipClean
      ? `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(ipClean)}`
      : `https://www.virustotal.com/gui/search/${encodeURIComponent(queryTarget)}`;
    this.atkPivotAbuse.href = ipClean
      ? `https://www.abuseipdb.com/check/${encodeURIComponent(ipClean)}`
      : `https://www.abuseipdb.com/`;
    this.atkPivotShodan.href = ipClean
      ? `https://www.shodan.io/host/${encodeURIComponent(ipClean)}`
      : `https://www.shodan.io/search?query=${encodeURIComponent(queryTarget)}`;

    this.attackDossierCard.style.display = "flex";
  }

  // =====================================================================
  // IOC COPY & SESSION EXPORT (JSON / CSV)
  // =====================================================================

  async copySelectedIoc() {
    if (!this.selectedAttack) return;
    const d = this.selectedAttack;
    const srcCity = (d.srcCity && d.srcCity !== "Unknown") ? d.srcCity : d.srcCountry;
    const dstCity = d.dstCity || d.dstCountry;
    const cveClean = (d.cve || "CVE-N/A").replace(/^CVE:\s*/i, "");

    const iocString = [
      `[SOC_THREAT_MATRIX_IOC]`,
      `Timestamp: ${d._timestamp || "LIVE"}`,
      `Threat: ${d.malware || "UNKNOWN"} (${d.category || "EVENT"})`,
      `Severity: ${d._bucket || d.severity}`,
      `Source_IP: ${d.srcIp || "N/A"}`,
      `ASN: ${d.srcAsn || "N/A"}`,
      `Origin: ${srcCity}, ${d.srcCountry} (${(d.srcCode || "").toUpperCase()})`,
      `Target: ${dstCity}, ${d.dstCountry} (${(d.dstCode || "").toUpperCase()})`,
      `Vector: ${d.port || 443}/${d.proto || "TCP"}`,
      `CVE: ${cveClean}`,
      `MITRE: ${d.mitre || "N/A"}`,
    ].join(" | ");

    try {
      await navigator.clipboard.writeText(iocString);
      this.btnCopyIoc.classList.add("copied");
      this.copyIocLabel.textContent = "COPIED!";
      setTimeout(() => {
        this.btnCopyIoc.classList.remove("copied");
        this.copyIocLabel.textContent = "COPY IOC";
      }, 1600);
    } catch (err) {
      console.error("Clipboard copy failed:", err);
    }
  }

  getFilteredBufferForExport() {
    return this.rawAttackBuffer.filter(d => this.matchesActiveFilters(d));
  }

  exportSessionData(format = "json") {
    const records = this.getFilteredBufferForExport();
    if (records.length === 0) return;

    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    let blob;
    let filename;

    if (format === "csv") {
      const headers = [
        "timestamp", "id", "severity", "malware", "category",
        "src_ip", "src_country", "src_code", "src_city", "src_asn", "src_lat", "src_lon",
        "dst_country", "dst_code", "dst_city", "dst_lat", "dst_lon",
        "port", "proto", "cve", "mitre", "feed_mode"
      ];
      const escapeCsv = val => `"${String(val ?? "").replace(/"/g, '""')}"`;
      const rows = records.map(d => [
        d._timestamp || "",
        d._id || "",
        d._bucket || d.severity || "",
        d.malware || "",
        d.category || "",
        d.srcIp || "",
        d.srcCountry || "",
        d.srcCode || "",
        d.srcCity || "",
        d.srcAsn || "",
        d.srcLat ?? "",
        d.srcLon ?? "",
        d.dstCountry || "",
        d.dstCode || "",
        d.dstCity || "",
        d.dstLat ?? "",
        d.dstLon ?? "",
        d.port ?? "",
        d.proto || "TCP",
        (d.cve || "").replace(/^CVE:\s*/i, ""),
        d.mitre || "",
        d.feedMode || "live"
      ].map(escapeCsv).join(","));

      const csvContent = [headers.join(","), ...rows].join("\n");
      blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
      filename = `soc_threat_capture_${stamp}.csv`;
    } else {
      const cleanJson = records.map(d => ({
        timestamp: d._timestamp,
        id: d._id,
        severity: d._bucket || d.severity,
        malware: d.malware,
        category: d.category,
        src_ip: d.srcIp,
        src_country: d.srcCountry,
        src_code: d.srcCode,
        src_city: d.srcCity,
        src_asn: d.srcAsn,
        src_lat: d.srcLat,
        src_lon: d.srcLon,
        dst_country: d.dstCountry,
        dst_code: d.dstCode,
        dst_city: d.dstCity,
        dst_lat: d.dstLat,
        dst_lon: d.dstLon,
        port: d.port,
        proto: d.proto,
        cve: (d.cve || "").replace(/^CVE:\s*/i, ""),
        mitre: d.mitre,
        feed_mode: d.feedMode || "live",
      }));
      blob = new Blob([JSON.stringify(cleanJson, null, 2)], { type: "application/json" });
      filename = `soc_threat_capture_${stamp}.json`;
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // =====================================================================
  // FEED MODE SWITCHING & AUTHENTICATION LOGIC
  // =====================================================================

  switchFeedMode(mode) {
    if (mode === "custom" && !this.currentUser) return;

    this.activeFeedMode = mode;
    this.attacks = [];
    this.ripples = [];
    this.rawAttackBuffer = [];
    this.selectedAttack = null;
    this.updateAttackDossier();

    if (mode === "live") {
      this.btnModeLive.classList.add("active");
      this.btnModeLive.classList.remove("inactive");
      this.btnModeCustom.classList.remove("active");
      this.btnModeCustom.classList.add("inactive");
      this.feedModeLabel.textContent = this.isStreamPaused ? "STREAM PAUSED" : "LIVE OSINT STREAM";
      this.attackTicker.innerHTML = `<div class="ticker-empty">LISTENING FOR LIVE OSINT INTRUSIONS...</div>`;
    } else {
      this.btnModeCustom.classList.add("active");
      this.btnModeCustom.classList.remove("inactive");
      this.btnModeLive.classList.remove("active");
      this.btnModeLive.classList.add("inactive");
      this.feedModeLabel.textContent = `CUSTOM // ${this.currentUser.username.toUpperCase()}`;

      const hasSources = (this.currentUser.custom_sources || []).length > 0;
      this.attackTicker.innerHTML = hasSources
        ? `<div class="ticker-empty">STREAMING FROM YOUR CUSTOM FEEDS...</div>`
        : `<div class="ticker-empty">NO CUSTOM FEEDS ADDED YET.<br/>OPEN CUSTOM FEED SETTINGS TO ADD SOURCES.</div>`;
    }

    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(
        JSON.stringify({
          action: "set_mode",
          mode: this.activeFeedMode,
          token: this.authToken,
        })
      );
    }
  }

  async checkExistingSession() {
    if (!this.authToken) {
      this.updateUserHeaderUI();
      return;
    }
    try {
      const res = await fetch(`${CONFIG.apiBase}/api/me`, {
        headers: { Authorization: `Bearer ${this.authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        this.currentUser = data.user;
      } else {
        this.authToken = null;
        localStorage.removeItem("soc_auth_token");
      }
    } catch {}
    this.updateUserHeaderUI();
  }

  updateUserHeaderUI() {
    if (this.currentUser) {
      this.customModeWrapper.classList.remove("locked");
      this.btnModeCustom.classList.remove("locked");
      this.btnModeCustom.disabled = false;

      this.btnUserProfile.classList.remove("logged-out");
      this.btnUserProfile.classList.add("logged-in");

      this.dropdownUserStatus.textContent = `OPERATOR // ${this.currentUser.username.toUpperCase()}`;
      this.menuIconAccount.className = "fa-solid fa-user-gear";
      this.menuTextAccount.textContent = "ACCOUNT SETTINGS";
      this.menuBtnFeeds.classList.remove("disabled");
      this.menuBtnLogout.classList.remove("disabled");

      if (this.currentUser.avatar) {
        this.userAvatarImg.src = this.currentUser.avatar;
        this.userAvatarImg.style.display = "block";
        this.userDefaultIcon.style.display = "none";

        this.profileAvatarPreview.src = this.currentUser.avatar;
        this.profileAvatarPreview.style.display = "block";
        this.profileAvatarPlaceholder.style.display = "none";
      } else {
        this.userAvatarImg.style.display = "none";
        this.userDefaultIcon.style.display = "block";

        this.profileAvatarPreview.style.display = "none";
        this.profileAvatarPlaceholder.style.display = "block";
      }

      this.profileUsernameDisplay.textContent = this.currentUser.username.toUpperCase();
      this.renderCustomSourcesList();
    } else {
      this.customModeWrapper.classList.add("locked");
      this.btnModeCustom.classList.add("locked");
      this.btnModeCustom.disabled = true;
      if (this.activeFeedMode === "custom") {
        this.switchFeedMode("live");
      }

      this.btnUserProfile.classList.add("logged-out");
      this.btnUserProfile.classList.remove("logged-in");
      this.userAvatarImg.style.display = "none";
      this.userDefaultIcon.style.display = "block";

      this.dropdownUserStatus.textContent = "UNAUTHENTICATED SESSION";
      this.menuIconAccount.className = "fa-solid fa-user-plus";
      this.menuTextAccount.textContent = "REGISTER / LOGIN";
      this.menuBtnFeeds.classList.add("disabled");
      this.menuBtnLogout.classList.add("disabled");
    }
  }

  openModalSection(section) {
    this.authError.style.display = "none";
    this.modalAuthView.style.display = "none";
    this.modalAccountView.style.display = "none";
    this.modalFeedsView.style.display = "none";

    if (!this.currentUser || section === "auth") {
      this.modalTitle.textContent = "SOC OPERATOR AUTHENTICATION";
      this.modalAuthView.style.display = "flex";
    } else if (section === "account") {
      this.modalTitle.textContent = "ACCOUNT SETTINGS";
      this.modalAccountView.style.display = "flex";
    } else if (section === "feeds") {
      this.modalTitle.textContent = "CUSTOM FEED SETTINGS";
      this.modalFeedsView.style.display = "flex";
    }
    this.userModalBackdrop.style.display = "flex";
  }

  fileToDataUrl(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const img = new Image();
        img.onload = () => {
          const canvas = document.createElement("canvas");
          const size = 128;
          canvas.width = size;
          canvas.height = size;
          const ctx = canvas.getContext("2d");
          const minDim = Math.min(img.width, img.height);
          const sx = (img.width - minDim) / 2;
          const sy = (img.height - minDim) / 2;
          ctx.drawImage(img, sx, sy, minDim, minDim, 0, 0, size, size);
          resolve(canvas.toDataURL("image/png"));
        };
        img.onerror = reject;
        img.src = e.target.result;
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });
  }

  renderCustomSourcesList() {
    if (!this.currentUser) return;
    const sources = this.currentUser.custom_sources || [];
    if (sources.length === 0) {
      this.customSourcesList.innerHTML = `<div class="ticker-empty">NO CUSTOM FEEDS CONFIGURED YET</div>`;
      return;
    }
    this.customSourcesList.innerHTML = sources
      .map(
        (s, idx) => `
        <div class="source-item">
          <div class="source-item-meta">
            <span class="source-item-name">${s.name}</span>
            <span class="source-item-url">${s.url}</span>
          </div>
          <button class="source-del-btn" data-idx="${idx}" type="button">✕</button>
        </div>
      `
      )
      .join("");
  }

  async saveCustomSources(sourcesArray) {
    if (!this.authToken) return;
    const res = await fetch(`${CONFIG.apiBase}/api/profile/sources`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.authToken}`,
      },
      body: JSON.stringify({ custom_sources: sourcesArray }),
    });
    if (res.ok) {
      const data = await res.json();
      this.currentUser = data.user;
      this.renderCustomSourcesList();
      if (this.activeFeedMode === "custom") {
        this.switchFeedMode("custom");
      }
    }
  }

  toggleStreamPause() {
    this.isStreamPaused = !this.isStreamPaused;
    this.btnPauseStream.classList.toggle("paused", this.isStreamPaused);
    if (this.isStreamPaused) {
      this.pauseIcon.className = "fa-solid fa-play";
      this.pauseLabel.textContent = "RESUME";
      this.feedModeLabel.textContent = "STREAM PAUSED";
    } else {
      this.pauseIcon.className = "fa-solid fa-pause";
      this.pauseLabel.textContent = "PAUSE";
      this.feedModeLabel.textContent = this.activeFeedMode === "live"
        ? "LIVE OSINT STREAM"
        : `CUSTOM // ${this.currentUser ? this.currentUser.username.toUpperCase() : "FEED"}`;
    }
  }

  bindFilterEvents() {
    const filterBar = document.querySelector(".feed-filter-bar");
    if (filterBar) {
      filterBar.addEventListener("click", (e) => {
        const chip = e.target.closest(".filter-chip");
        if (!chip) return;

        filterBar.querySelectorAll(".filter-chip").forEach(c => c.classList.remove("active"));
        chip.classList.add("active");
        this.currentSeverityFilter = chip.dataset.severity;

        if (this.selectedAttack && !this.matchesActiveFilters(this.selectedAttack)) {
          this.selectedAttack = null;
          this.updateAttackDossier();
        }

        this.rebuildTickerFromBuffer();
      });
    }

    // Stream Pause / Resume Button
    if (this.btnPauseStream) {
      this.btnPauseStream.addEventListener("click", () => {
        this.toggleStreamPause();
      });
    }

    // Export Session JSON & CSV Buttons
    if (this.btnExportJson) {
      this.btnExportJson.addEventListener("click", () => this.exportSessionData("json"));
    }
    if (this.btnExportCsv) {
      this.btnExportCsv.addEventListener("click", () => this.exportSessionData("csv"));
    }

    // Live Search Input & Clear Button
    if (this.feedSearchInput) {
      this.feedSearchInput.addEventListener("input", (e) => {
        this.searchQuery = e.target.value.trim();
        if (this.btnClearSearch) {
          this.btnClearSearch.style.display = this.searchQuery ? "block" : "none";
        }
        if (this.selectedAttack && !this.matchesActiveFilters(this.selectedAttack)) {
          this.selectedAttack = null;
          this.updateAttackDossier();
        }
        this.rebuildTickerFromBuffer();
      });
    }

    if (this.btnClearSearch) {
      this.btnClearSearch.addEventListener("click", () => {
        this.searchQuery = "";
        this.feedSearchInput.value = "";
        this.btnClearSearch.style.display = "none";
        this.rebuildTickerFromBuffer();
      });
    }

    // Click on a feed card to lock/unlock its trajectory & open/close the Attack Dossier Card
    this.attackTicker.addEventListener("click", (e) => {
      const row = e.target.closest(".ticker-row");
      if (!row) return;
      const attackId = row.dataset.attackId;
      const found = this.rawAttackBuffer.find(item => item._id === attackId);
      if (!found) return;

      if (this.selectedAttack && this.selectedAttack._id === attackId) {
        this.selectedAttack = null;
      } else {
        this.selectedAttack = found;
      }
      this.syncSelectedCardDOM();
      this.updateAttackDossier();
    });

    // Close button on the Attack Dossier Card
    if (this.btnCloseAttackDossier) {
      this.btnCloseAttackDossier.addEventListener("click", () => {
        this.selectedAttack = null;
        this.syncSelectedCardDOM();
        this.updateAttackDossier();
      });
    }

    // Copy IOC Button inside Attack Dossier Card
    if (this.btnCopyIoc) {
      this.btnCopyIoc.addEventListener("click", () => {
        this.copySelectedIoc();
      });
    }
  }

  syncSelectedCardDOM() {
    const rows = this.attackTicker.querySelectorAll(".ticker-row");
    rows.forEach(r => {
      const isSel = this.selectedAttack && r.dataset.attackId === this.selectedAttack._id;
      r.classList.toggle("selected", Boolean(isSel));
      const hint = r.querySelector(".ticker-lock-hint");
      if (hint) {
        hint.textContent = isSel ? "LOCKED ON MAP" : "CLICK TO TRACE";
      }
    });
  }

  rebuildTickerFromBuffer() {
    this.attackTicker.innerHTML = `<div class="ticker-empty">NO MATCHING INTRUSIONS IN BUFFER...</div>`;
    const filtered = this.rawAttackBuffer.filter(data => this.matchesActiveFilters(data));

    for (const data of filtered.slice(0, 20).reverse()) {
      this.appendTickerRowDOM(data);
    }
  }

  bindAuthEvents() {
    this.btnModeLive.addEventListener("click", () => { this.switchFeedMode("live"); });
    this.btnModeCustom.addEventListener("click", () => { if (this.currentUser) this.switchFeedMode("custom"); });
    this.btnUserProfile.addEventListener("click", () => { this.openModalSection(this.currentUser ? "account" : "auth"); });
    this.menuBtnAccount.addEventListener("click", () => { this.openModalSection(this.currentUser ? "account" : "auth"); });
    this.menuBtnFeeds.addEventListener("click", () => { if (this.currentUser) this.openModalSection("feeds"); });

    this.menuBtnLogout.addEventListener("click", async () => {
      if (!this.currentUser) return;
      if (this.authToken) {
        await fetch(`${CONFIG.apiBase}/api/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${this.authToken}` },
        }).catch(() => {});
      }
      this.authToken = null;
      this.currentUser = null;
      localStorage.removeItem("soc_auth_token");
      this.updateUserHeaderUI();
      this.userModalBackdrop.style.display = "none";
    });

    this.btnCloseModal.addEventListener("click", () => { this.userModalBackdrop.style.display = "none"; });
    this.userModalBackdrop.addEventListener("click", (e) => {
      if (e.target === this.userModalBackdrop) this.userModalBackdrop.style.display = "none";
    });

    this.tabLogin.addEventListener("click", () => {
      this.authMode = "login";
      this.tabLogin.classList.add("active");
      this.tabRegister.classList.remove("active");
      this.registerAvatarGroup.style.display = "none";
      this.btnAuthSubmit.textContent = "AUTHENTICATE";
      this.authError.style.display = "none";
    });

    this.tabRegister.addEventListener("click", () => {
      this.authMode = "register";
      this.tabRegister.classList.add("active");
      this.tabLogin.classList.remove("active");
      this.registerAvatarGroup.style.display = "flex";
      this.btnAuthSubmit.textContent = "REGISTER OPERATOR";
      this.authError.style.display = "none";
    });

    this.regAvatarInput.addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      this.pendingRegAvatar = await this.fileToDataUrl(file);
      this.regAvatarPreview.src = this.pendingRegAvatar;
      this.regAvatarPreview.style.display = "block";
      this.regAvatarPlaceholder.style.display = "none";
    });

    this.authForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      this.authError.style.display = "none";

      const endpoint = this.authMode === "register" ? "/api/register" : "/api/login";
      const payload = {
        username: this.authUsername.value.trim(),
        password: this.authPassword.value,
        avatar: this.authMode === "register" ? this.pendingRegAvatar : "",
      };

      try {
        const res = await fetch(`${CONFIG.apiBase}${endpoint}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
          this.authError.textContent = data.detail || "Authentication failed.";
          this.authError.style.display = "block";
          return;
        }

        this.authToken = data.token;
        this.currentUser = data.user;
        localStorage.setItem("soc_auth_token", this.authToken);
        this.authForm.reset();
        this.updateUserHeaderUI();
        this.userModalBackdrop.style.display = "none";
      } catch {
        this.authError.textContent = "Unable to reach authentication server.";
        this.authError.style.display = "block";
      }
    });

    this.profileAvatarInput.addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (!file || !this.authToken) return;
      const dataUrl = await this.fileToDataUrl(file);
      const res = await fetch(`${CONFIG.apiBase}/api/profile/avatar`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.authToken}`,
        },
        body: JSON.stringify({ avatar: dataUrl }),
      });
      if (res.ok) {
        const data = await res.json();
        this.currentUser = data.user;
        this.updateUserHeaderUI();
      }
    });

    this.btnAddSource.addEventListener("click", async () => {
      if (!this.currentUser) return;
      const name = this.sourceNameInput.value.trim();
      const url = this.sourceUrlInput.value.trim();
      if (!name || !url) return;

      const updated = [...(this.currentUser.custom_sources || []), { name, url }];
      await this.saveCustomSources(updated);
      this.sourceNameInput.value = "";
      this.sourceUrlInput.value = "";
    });

    this.customSourcesList.addEventListener("click", async (e) => {
      const btn = e.target.closest(".source-del-btn");
      if (!btn || !this.currentUser) return;
      const idx = parseInt(btn.dataset.idx, 10);
      const updated = (this.currentUser.custom_sources || []).filter((_, i) => i !== idx);
      await this.saveCustomSources(updated);
    });
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

      const nonAntarcticGeoms = data.objects.countries.geometries.filter(
        g => parseInt(g.id, 10) !== 10
      );
      this.mergedLandGeo = topojson.merge(data, nonAntarcticGeoms);

      this.coastlineMesh = topojson.mesh(data, data.objects.countries, (a, b) => {
        const idA = parseInt(a.id, 10);
        const idB = parseInt(b.id, 10);
        return (a === b) && (idA !== 10) && (idB !== 10);
      });
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

    const mapX = CONFIG.horizontalMargin;
    const mapY = CONFIG.topReservedHeight;
    const mapW = Math.max(300, width - CONFIG.horizontalMargin * 2);
    const mapH = Math.max(200, height - mapY - CONFIG.bottomMargin);

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
        this.connStatus.style.backgroundColor = "#006FFF";
        this.ws.send(
          JSON.stringify({
            action: "set_mode",
            mode: this.activeFeedMode,
            token: this.authToken,
          })
        );
      };

      this.ws.onmessage = (event) => {
        try {
          if (this.isStreamPaused) return;
          const payload = JSON.parse(event.data);
          if (payload.feedMode && payload.feedMode !== this.activeFeedMode) {
            return;
          }
          this.triggerAttack(payload);
        } catch (err) {
          console.error("Failed to parse event:", err);
        }
      };

      this.ws.onclose = () => {
        this.isWsConnected = false;
        this.connStatus.style.backgroundColor = "#FFB800";
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

    const attackId = Math.random().toString(36).substr(2, 9);
    const bucket = this.resolveSeverityBucket(data);
    data._id = attackId;
    data._bucket = bucket;
    data._timestamp = new Date().toTimeString().split(" ")[0] + " UTC";

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

    const speed = CONFIG.arcSpeedMin + Math.random() * (CONFIG.arcSpeedMax - CONFIG.arcSpeedMin);
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
      cityName: (data.srcCity && data.srcCity !== "Unknown") ? data.srcCity : data.srcCountry,
      data: data,
    });

    this.addRipple(srcScreen[0], srcScreen[1], arcColor, 16, 0.85, data);
    this.totalAttacksCount++;
    localStorage.setItem("soc_total_attacks", this.totalAttacksCount.toString());

    this.recordStats(data.srcCode, data.srcCountry, data.dstCode, data.dstCountry);
    this.hudAttacksTotal.textContent = this.totalAttacksCount.toLocaleString();

    if (this.selectedCountryIndex !== null) {
      this.updateCountryDossier();
    }
  }

  recordStats(srcCode, srcName, dstCode, dstName) {
    if (srcCode) {
      if (!this.countryStats.has(srcCode)) {
        this.countryStats.set(srcCode, { code: srcCode, name: srcName, count: 0 });
      }
      this.countryStats.get(srcCode).count++;
      localStorage.setItem("soc_country_stats", JSON.stringify(Array.from(this.countryStats.entries())));
    }

    if (dstCode) {
      if (!this.targetStats.has(dstCode)) {
        this.targetStats.set(dstCode, { code: dstCode, name: dstName, count: 0 });
      }
      this.targetStats.get(dstCode).count++;
      localStorage.setItem("soc_target_stats", JSON.stringify(Array.from(this.targetStats.entries())));
    }

    this.hudActiveOrigins.textContent = `${this.countryStats.size} REGIONS`;
    this.updateLeaderboards();
  }

  renderLeaderboardHTML(statsMap) {
    const sorted = Array.from(statsMap.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const maxHits = sorted.length > 0 ? sorted[0].count : 1;

    return sorted.map((item, index) => {
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

  updateLeaderboards() {
    const hitsLabel = `${this.totalAttacksCount.toLocaleString()} HITS`;
    this.leaderboardTotalHits.textContent = hitsLabel;
    this.targetTotalHits.textContent = hitsLabel;

    this.leaderboardList.innerHTML = this.renderLeaderboardHTML(this.countryStats);
    this.targetLeaderboardList.innerHTML = this.renderLeaderboardHTML(this.targetStats);
  }

  appendTickerRowDOM(data) {
    const row = document.createElement("div");
    const bucket = data._bucket || this.resolveSeverityBucket(data);

    let sevClass = "sev-low";
    if (bucket === "HIGH") sevClass = "sev-high";
    else if (bucket === "MEDIUM") sevClass = "sev-med";

    const isSelected = this.selectedAttack && this.selectedAttack._id === data._id;
    row.className = `ticker-row ${sevClass}${isSelected ? " selected" : ""}`;
    row.dataset.attackId = data._id;

    const originCity = data.srcCity && data.srcCity !== "Unknown" ? data.srcCity : data.srcCountry;
    const destCity = data.dstCity ? data.dstCity : data.dstCountry;
    const attackTitle = data.malware || "UNKNOWN_THREAT";
    const cveDisplay = (data.cve || "CVE-N/A").replace(/^CVE:\s*/i, "");

    row.innerHTML = `
      <div class="ticker-title-row">
        <div class="ticker-title">${attackTitle}</div>
        <span class="ticker-lock-hint">${isSelected ? "LOCKED ON MAP" : "CLICK TO TRACE"}</span>
      </div>
      <div class="ticker-meta">
        <span>${cveDisplay}</span>
        <span class="meta-dot">•</span>
        <span>MITRE: ${data.mitre || "T1071"}</span>
        <span class="meta-dot">•</span>
        <span>PORT: ${data.port}/${data.proto}</span>
      </div>
      <div class="ticker-vector-row">
        <span>${originCity} (${data.srcCode.toUpperCase()})</span>
        <span class="vector-arrow">→</span>
        <span>${destCity} (${data.dstCode.toUpperCase()})</span>
      </div>
    `;

    const empty = this.attackTicker.querySelector(".ticker-empty");
    if (empty) empty.remove();

    this.attackTicker.insertBefore(row, this.attackTicker.firstChild);
    while (this.attackTicker.children.length > 20) {
      this.attackTicker.removeChild(this.attackTicker.lastChild);
    }
  }

  addRipple(x, y, color, maxRadius = 24, maxOpacity = 0.8, data = null) {
    this.ripples.push({ x, y, radius: 2, maxRadius, opacity: maxOpacity, color, data });
  }

  getBezierPoint(t, p0, p1, p2) {
    const inv = 1 - t;
    return {
      x: inv * inv * p0.x + 2 * inv * t * p1.x + t * t * p2.x,
      y: inv * inv * p0.y + 2 * inv * t * p1.y + t * t * p2.y,
    };
  }

  drawCityBadge(x, y, text, borderColor = "rgba(0, 111, 255, 0.45)", dotColor = "#006FFF") {
    const ctx = this.ctx;
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

  renderSelectedAttack() {
    if (!this.selectedAttack || !this.projection) return;
    const data = this.selectedAttack;
    const srcScreen = this.projection([data.srcLon, data.srcLat]);
    const dstScreen = this.projection([data.dstLon, data.dstLat]);
    if (!srcScreen || !dstScreen) return;

    const start = { x: srcScreen[0], y: srcScreen[1] };
    const end = { x: dstScreen[0], y: dstScreen[1] };
    const dx = end.x - start.x;
    const dy = end.y - start.y;
    const dist = Math.hypot(dx, dy);
    const archAltitude = Math.min(180, Math.max(35, dist * 0.28));
    const control = { x: (start.x + end.x) / 2, y: (start.y + end.y) / 2 - archAltitude };

    const color = this.getBucketColor(data._bucket || "LOW");
    const ctx = this.ctx;

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
    const pulsePt = this.getBezierPoint(t, start, control, end);
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

    const originName = (data.srcCity && data.srcCity !== "Unknown") ? data.srcCity : data.srcCountry;
    const targetName = data.dstCity ? data.dstCity : data.dstCountry;
    this.drawCityBadge(start.x, start.y, `${originName} (${data.srcCode.toUpperCase()})`, "#00F0FF", "#006FFF");
    this.drawCityBadge(end.x, end.y, `TARGET: ${targetName}`, color, color);

    ctx.restore();
  }

  drawCyberOceanBackdrop(width, height) {
    const ctx = this.ctx;
    const minorStep = 36;
    const majorStep = 144;

    ctx.save();

    ctx.strokeStyle = CONFIG.minorGridStroke;
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let x = 0; x <= width; x += minorStep) {
      ctx.moveTo(x, 0); ctx.lineTo(x, height);
    }
    for (let y = 0; y <= height; y += minorStep) {
      ctx.moveTo(0, y); ctx.lineTo(width, y);
    }
    ctx.stroke();

    ctx.strokeStyle = CONFIG.majorGridStroke;
    ctx.lineWidth = 1;
    ctx.beginPath();
    for (let x = 0; x <= width; x += majorStep) {
      ctx.moveTo(x, 0); ctx.lineTo(x, height);
    }
    for (let y = 0; y <= height; y += majorStep) {
      ctx.moveTo(0, y); ctx.lineTo(width, y);
    }
    ctx.stroke();

    ctx.strokeStyle = CONFIG.crosshairStroke;
    ctx.lineWidth = 1.2;
    ctx.beginPath();
    for (let x = majorStep; x < width; x += majorStep) {
      for (let y = majorStep; y < height; y += majorStep) {
        ctx.moveTo(x - 4, y); ctx.lineTo(x + 4, y);
        ctx.moveTo(x, y - 4); ctx.lineTo(x, y + 4);
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

  renderAttacks() {
    const ctx = this.ctx;
    const dimFactor = this.selectedAttack ? 0.35 : 1.0;

    // 1. Shockwaves (Filtered by severity + live search; frozen in place when stream is paused)
    for (let i = this.ripples.length - 1; i >= 0; i--) {
      const rip = this.ripples[i];
      if (!this.isStreamPaused) {
        rip.radius += 0.55;
        rip.opacity -= 0.015;
      }

      if (rip.opacity <= 0 || rip.radius >= rip.maxRadius) {
        this.ripples.splice(i, 1);
        continue;
      }

      if (rip.data && !this.matchesActiveFilters(rip.data)) continue;

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
    for (let i = this.attacks.length - 1; i >= 0; i--) {
      const atk = this.attacks[i];
      if (!this.isStreamPaused) {
        atk.progress += atk.speed;
      }

      if (atk.progress >= 1) {
        this.addRipple(atk.end.x, atk.end.y, atk.color, 32, 1.0, atk.data);
        this.attacks.splice(i, 1);
        continue;
      }

      if (!this.matchesActiveFilters(atk.data)) continue;

      ctx.save();

      ctx.fillStyle = atk.color;
      ctx.shadowColor = atk.color;
      ctx.shadowBlur = 10;
      ctx.globalAlpha = dimFactor;
      ctx.beginPath();
      ctx.arc(atk.start.x, atk.start.y, 3.2, 0, Math.PI * 2);
      ctx.fill();

      if (!this.selectedAttack) {
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

        const pt1 = this.getBezierPoint(t1, atk.start, atk.control, atk.end);
        const pt2 = this.getBezierPoint(t2, atk.start, atk.control, atk.end);
        const segAlpha = (s + 1) / segments;

        ctx.strokeStyle = atk.color;
        ctx.globalAlpha = segAlpha * 0.95 * dimFactor;
        ctx.lineWidth = 1.4 + segAlpha * 2.2;
        ctx.beginPath();
        ctx.moveTo(pt1.x, pt1.y);
        ctx.lineTo(pt2.x, pt2.y);
        ctx.stroke();
      }

      const headPt = this.getBezierPoint(headT, atk.start, atk.control, atk.end);
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
    const ctx = this.ctx;
    const width = window.innerWidth;
    const height = window.innerHeight;

    ctx.setTransform(this.pixelRatio, 0, 0, this.pixelRatio, 0, 0);
    ctx.clearRect(0, 0, width, height);

    if (!this.geoPath) return;

    this.drawCyberOceanBackdrop(width, height);

    if (this.mergedLandGeo) {
      ctx.save();
      ctx.fillStyle = CONFIG.landFill;
      ctx.beginPath();
      this.geoPath(this.mergedLandGeo);
      ctx.fill();
      ctx.restore();
    }

    if (this.coastlineMesh) {
      ctx.save();
      ctx.strokeStyle = CONFIG.coastlineStroke;
      ctx.lineWidth = CONFIG.coastlineWidth;
      ctx.shadowColor = CONFIG.coastlineGlow;
      ctx.shadowBlur = 8;
      ctx.lineCap = "round";
      ctx.lineJoin = "round";
      ctx.beginPath();
      this.geoPath(this.coastlineMesh);
      ctx.stroke();
      ctx.restore();
    }

    if (this.hoveredCountryIndex !== null && this.hoveredCountryIndex !== this.selectedCountryIndex) {
      const feature = this.countryFeatures[this.hoveredCountryIndex - 1];
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
        this.geoPath(feature);
        ctx.fill();
        ctx.stroke();
        ctx.restore();
      }
    }

    if (this.selectedCountryIndex !== null) {
      const selFeature = this.countryFeatures[this.selectedCountryIndex - 1];
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
        this.geoPath(selFeature);
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

  updateHoverIntel(countryIndex, clientX, clientY) {
    if (!countryIndex || countryIndex <= 0 || countryIndex > this.countryFeatures.length) {
      this.cursorTooltip.style.display = "none";
      this.countryIntelBar.classList.remove("active");
      this.countryIntelBar.classList.add("idle");
      this.countryNameEl.textContent = "STANDBY";
      this.countryCodeEl.textContent = "ISO";
      this.countryFlagEl.style.display = "none";
      this.flagPlaceholderEl.style.display = "block";
      return;
    }

    const feature = this.countryFeatures[countryIndex - 1];
    const meta = this.getCountryMeta(feature);

    this.countryIntelBar.classList.add("active");
    this.countryIntelBar.classList.remove("idle");

    if (meta && meta.code) {
      const flagUrl = `https://flagcdn.com/w80/${meta.code.toLowerCase()}.png`;

      this.cursorTooltipFlag.style.display = "block";
      this.cursorTooltipFlag.src = flagUrl;
      this.cursorTooltipName.textContent = meta.name.toUpperCase();
      this.cursorTooltip.style.left = `${clientX}px`;
      this.cursorTooltip.style.top = `${clientY}px`;
      this.cursorTooltip.style.display = "flex";

      this.countryNameEl.textContent = meta.name.toUpperCase();
      this.countryCodeEl.textContent = `ISO: ${meta.code.toUpperCase()} // ID: ${meta.idLabel}`;
      this.countryFlagEl.src = flagUrl;
      this.countryFlagEl.onload = () => {
        this.countryFlagEl.style.display = "block";
        this.flagPlaceholderEl.style.display = "none";
      };
    } else if (meta) {
      this.cursorTooltipFlag.style.display = "none";
      this.cursorTooltipName.textContent = meta.name.toUpperCase();
      this.cursorTooltip.style.left = `${clientX}px`;
      this.cursorTooltip.style.top = `${clientY}px`;
      this.cursorTooltip.style.display = "flex";

      this.countryNameEl.textContent = meta.name.toUpperCase();
      this.countryCodeEl.textContent = `ID: ${meta.idLabel}`;
      this.countryFlagEl.style.display = "none";
      this.flagPlaceholderEl.style.display = "block";
    }
  }

  detectCountryAtPoint(mouseX, mouseY) {
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
          return candidate;
        }
      }
    }
    return null;
  }

  bindEvents() {
    window.addEventListener("resize", () => { this.resize(); });
    document.addEventListener("visibilitychange", () => {
      if (document.visibilityState === "visible") {
        this.attacks = [];
        this.ripples = [];
      }
    });

    // Close Gold Country Dossier Button
    this.btnCloseDossier.addEventListener("click", () => {
      this.selectedCountryIndex = null;
      this.updateCountryDossier();
    });

    // Click on Map Country to toggle Gold highlight & open/close Gold Dossier Card
    this.canvas.addEventListener("click", (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      const clickedCountryIdx = this.detectCountryAtPoint(mouseX, mouseY);

      if (clickedCountryIdx !== null) {
        if (this.selectedCountryIndex === clickedCountryIdx) {
          this.selectedCountryIndex = null;
        } else {
          this.selectedCountryIndex = clickedCountryIdx;
        }
        this.updateCountryDossier();
      }
    });

    this.canvas.addEventListener("mousemove", (e) => {
      const rect = this.canvas.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;

      if (this.projection) {
        const coords = this.projection.invert([mouseX, mouseY]);
        if (coords && coords[0] >= -180 && coords[0] <= 180 && coords[1] >= -60 && coords[1] <= 85) {
          const [lon, lat] = coords;
          const latDir = lat >= 0 ? "N" : "S";
          const lonDir = lon >= 0 ? "E" : "W";
          this.coordsHud.textContent = `${Math.abs(lat).toFixed(1)}°${latDir} | ${Math.abs(lon).toFixed(1)}°${lonDir}`;
        } else {
          this.coordsHud.textContent = "--.-° | --.-°";
        }
      }

      const detectedCountryIdx = this.detectCountryAtPoint(mouseX, mouseY);
      this.hoveredCountryIndex = detectedCountryIdx;
      this.updateHoverIntel(detectedCountryIdx, e.clientX, e.clientY);
    });

    this.canvas.addEventListener("mouseleave", () => {
      this.hoveredCountryIndex = null;
      this.updateHoverIntel(null, 0, 0);
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