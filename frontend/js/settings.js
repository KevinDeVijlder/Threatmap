/**
 * Standalone Subpage Controller (operator.html, locations.html, feeds.html)
 * =========================================================================
 * Powers the three dedicated SOC configuration pages:
 *   1. `operator.html`  — Operator Profile Avatar, Passkey Security & Map Preferences
 *   2. `locations.html` — Monitored Map Locations & Infrastructure IP Nodes CRUD
 *   3. `feeds.html`     — Built-in Default OSINT Feeds (Toggle ON/OFF) & Custom SOC Feeds CRUD
 */

import { CONFIG } from "./config.js";
import { fileToDataUrl, getPinTypeMeta } from "./utils/helpers.js";

const FALLBACK_DEFAULT_FEEDS = [
  {
    id: "feodo_tracker",
    name: "FEODO TRACKER C2",
    url: "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    description: "Abuse.ch Botnet Command & Control (C2) Server Blocklist",
    is_default: true,
    enabled: true,
  },
  {
    id: "threatfox",
    name: "ABUSE.CH THREATFOX",
    url: "https://threatfox.abuse.ch/export/json/recent/",
    description: "Recent Malware & Payload Host IOCs from Abuse.ch ThreatFox",
    is_default: true,
    enabled: true,
  },
  {
    id: "urlhaus",
    name: "ABUSE.CH URLHAUS",
    url: "https://urlhaus.abuse.ch/downloads/text_online/",
    description: "Active Malware Distribution & Botnet Dropper Servers",
    is_default: true,
    enabled: true,
  },
  {
    id: "cins_army",
    name: "CINS ARMY BADGUYS",
    url: "https://cinsscore.com/list/ci-badguys.txt",
    description: "Verified Active Reconnaissance Scanners & Brute-Force Hosts",
    is_default: true,
    enabled: true,
  },
];

class SubpageController {
  constructor() {
    this.authToken = localStorage.getItem("soc_auth_token") || null;
    this.currentUser = null;
    this.currentPage =
      document.body.dataset.page ||
      window.location.pathname.split("/").pop() ||
      "operator.html";

    // Shared Header & Profile Banner DOM
    this.btnSettingsLogout = document.getElementById("btn-settings-logout");
    this.profileAvatarPreview = document.getElementById("profile-avatar-preview");
    this.profileAvatarPlaceholder = document.getElementById("profile-avatar-placeholder");
    this.profileUsernameDisplay = document.getElementById("profile-username-display");

    // Top Summary Counters
    this.statLocationsCount = document.getElementById("stat-locations-count");
    this.statFeedsCount = document.getElementById("stat-feeds-count");
    this.statDefaultFeedsCount = document.getElementById("stat-default-feeds-count");
    this.statCustomFeedsCount = document.getElementById("stat-custom-feeds-count");
    this.statLocalHits = document.getElementById("stat-local-hits");

    // Operator Settings Page DOM (operator.html)
    this.profileAvatarInput = document.getElementById("profile-avatar-input");
    this.btnRemoveAvatar = document.getElementById("btn-remove-avatar");
    this.passwordForm = document.getElementById("password-form");
    this.currentPasswordInput = document.getElementById("current-password-input");
    this.newPasswordInput = document.getElementById("new-password-input");
    this.prefBordersCheckbox = document.getElementById("pref-borders-checkbox");
    this.btnResetLocalStats = document.getElementById("btn-reset-local-stats");
    this.operatorStatusToast = document.getElementById("operator-status-toast");

    // Monitored Map Locations Page DOM (locations.html)
    this.locationForm = document.getElementById("location-form");
    this.locNameInput = document.getElementById("loc-name-input");
    this.locIpInput = document.getElementById("loc-ip-input");
    this.btnAutoGeolocate = document.getElementById("btn-auto-geolocate");
    this.locLatInput = document.getElementById("loc-lat-input");
    this.locLonInput = document.getElementById("loc-lon-input");
    this.locColorInput = document.getElementById("loc-color-input");
    this.locTypePreview = document.getElementById("loc-type-preview");
    this.locTypePreviewIcon = document.getElementById("loc-type-preview-icon");
    this.locCityInput = document.getElementById("loc-city-input");
    this.locCountryInput = document.getElementById("loc-country-input");
    this.locCodeInput = document.getElementById("loc-code-input");
    this.locTargetCheckbox = document.getElementById("loc-target-checkbox");
    this.locStatusToast = document.getElementById("loc-status-toast");
    this.customLocationsList = document.getElementById("custom-locations-list");

    // Custom Feed Options Page DOM (feeds.html)
    this.defaultSourcesList = document.getElementById("default-sources-list");
    this.btnEnableAllDefaults = document.getElementById("btn-enable-all-defaults");
    this.btnDisableAllDefaults = document.getElementById("btn-disable-all-defaults");
    this.feedForm = document.getElementById("feed-form");
    this.sourceNameInput = document.getElementById("source-name-input");
    this.sourceUrlInput = document.getElementById("source-url-input");
    this.feedStatusToast = document.getElementById("feed-status-toast");
    this.customSourcesList = document.getElementById("custom-sources-list");

    this.init();
  }

  getRedirectFile() {
    const file = window.location.pathname.split("/").pop();
    return file && file.endsWith(".html") ? file : "operator.html";
  }

  async init() {
    const redirectFile = this.getRedirectFile();
    if (!this.authToken) {
      window.location.href = `login.html?redirect=${encodeURIComponent(redirectFile)}`;
      return;
    }

    try {
      const res = await fetch(`${CONFIG.apiBase}/api/me`, {
        headers: { Authorization: `Bearer ${this.authToken}` },
      });
      if (!res.ok) {
        localStorage.removeItem("soc_auth_token");
        localStorage.removeItem("soc_custom_locations");
        window.location.href = `login.html?redirect=${encodeURIComponent(redirectFile)}`;
        return;
      }
      const data = await res.json();
      this.currentUser = data.user;
    } catch {
      window.location.href = `login.html?redirect=${encodeURIComponent(redirectFile)}`;
      return;
    }

    this.ensureUserDefaultFeeds();
    this.bindEvents();
    this.renderAll();
  }

  ensureUserDefaultFeeds() {
    if (!this.currentUser) return;
    const raw = Array.isArray(this.currentUser.custom_sources)
      ? this.currentUser.custom_sources
      : [];
    const hasDefaults = raw.some((s) => s && s.is_default);
    if (!hasDefaults) {
      const customOnly = raw.map((s, idx) => ({
        id: s.id || `custom_${idx + 1}`,
        name: (s.name || "CUSTOM_FEED").toUpperCase(),
        url: s.url,
        description: s.description || "User-configured custom threat feed",
        is_default: false,
        enabled: s.enabled !== false,
      }));
      this.currentUser.custom_sources = [
        ...FALLBACK_DEFAULT_FEEDS.map((f) => ({ ...f })),
        ...customOnly,
      ];
    }
  }

  showToast(el, message, type = "success") {
    const targetEl =
      el || this.operatorStatusToast || this.locStatusToast || this.feedStatusToast;
    if (!targetEl) return;
    targetEl.textContent = message;
    targetEl.className = `status-toast ${type}`;
    clearTimeout(targetEl._timer);
    targetEl._timer = setTimeout(() => {
      targetEl.className = "status-toast";
    }, 3500);
  }

  renderAll() {
    if (!this.currentUser) return;
    this.ensureUserDefaultFeeds();

    if (this.profileUsernameDisplay) {
      this.profileUsernameDisplay.textContent =
        this.currentUser.username.toUpperCase();
    }

    if (this.profileAvatarPreview && this.profileAvatarPlaceholder) {
      if (this.currentUser.avatar) {
        this.profileAvatarPreview.src = this.currentUser.avatar;
        this.profileAvatarPreview.style.display = "block";
        this.profileAvatarPlaceholder.style.display = "none";
      } else {
        this.profileAvatarPreview.style.display = "none";
        this.profileAvatarPlaceholder.style.display = "block";
      }
    }

    const locations = this.currentUser.custom_locations || [];
    const allSources = this.currentUser.custom_sources || [];
    const defaultFeeds = allSources.filter((s) => s.is_default);
    const customFeeds = allSources.filter((s) => !s.is_default);

    const enabledDefaultCount = defaultFeeds.filter(
      (s) => s.enabled !== false
    ).length;
    const enabledCustomCount = customFeeds.filter(
      (s) => s.enabled !== false
    ).length;
    const totalEnabledFeeds = enabledDefaultCount + enabledCustomCount;

    const totalHits = parseInt(
      localStorage.getItem("soc_total_attacks") || "0",
      10
    );

    if (this.statLocationsCount) {
      this.statLocationsCount.textContent = `${locations.length} NODES`;
    }
    if (this.statFeedsCount) {
      this.statFeedsCount.textContent = `${totalEnabledFeeds} ACTIVE`;
    }
    if (this.statDefaultFeedsCount) {
      this.statDefaultFeedsCount.textContent = `${enabledDefaultCount} / ${defaultFeeds.length}`;
    }
    if (this.statCustomFeedsCount) {
      this.statCustomFeedsCount.textContent = `${enabledCustomCount} ACTIVE`;
    }
    if (this.statLocalHits) {
      this.statLocalHits.textContent = totalHits.toLocaleString();
    }

    if (this.prefBordersCheckbox) {
      this.prefBordersCheckbox.checked =
        localStorage.getItem("soc_show_borders") === "true";
    }

    // Keep localStorage synced so the map renders pinned locations immediately
    localStorage.setItem("soc_custom_locations", JSON.stringify(locations));

    if (this.customLocationsList) {
      this.renderLocationsList();
    }
    if (this.defaultSourcesList || this.customSourcesList) {
      this.renderFeedsLists();
    }
  }

  renderLocationsList() {
    if (!this.customLocationsList) return;
    const locations =
      (this.currentUser && this.currentUser.custom_locations) || [];
    if (locations.length === 0) {
      this.customLocationsList.innerHTML = `<div class="ticker-empty">NO MONITORED LOCATIONS PINNED YET.<br/>ADD AN IP ADDRESS TO DISPLAY A PIN ICON ON THE THREAT MAP.</div>`;
      return;
    }

    this.customLocationsList.innerHTML = locations
      .map((loc, idx) => {
        const pinMeta = getPinTypeMeta(loc.color);
        const accent = pinMeta.color;
        const code = (loc.code || "").toLowerCase();
        const flagHtml =
          code && code !== "un"
            ? `<img class="leaderboard-flag" src="https://flagcdn.com/w40/${code}.png" alt="${code}" />`
            : "";
        const placeStr =
          [loc.city, loc.country].filter(Boolean).join(", ") ||
          "Custom Coordinates";
        const targetBadge =
          loc.is_target !== false ? "TARGET ENABLED" : "DISPLAY ONLY";

        return `
          <div class="location-item-card" style="border-left-color: ${accent};">
            <div class="location-item-left">
              <div class="location-city-icon" style="color: ${accent}; border-color: ${accent};">
                <i class="fa-solid ${pinMeta.faClass}"></i>
              </div>
              <div class="location-item-details">
                <div class="location-item-title-row">
                  <span class="location-item-name">${loc.name}</span>
                  <span class="location-item-badge" style="color: ${accent}; border-color: ${accent};">${pinMeta.label}</span>
                  <span class="location-item-badge">${targetBadge}</span>
                </div>
                <div class="location-item-sub">
                  ${flagHtml}
                  <span>IP: <strong>${loc.ip}</strong></span>
                  <span>•</span>
                  <span>${placeStr}</span>
                </div>
                <span class="location-item-coords">
                  LAT: ${Number(loc.lat).toFixed(4)}° | LON: ${Number(loc.lon).toFixed(4)}°
                </span>
              </div>
            </div>
            <button class="source-del-btn loc-del-btn" data-idx="${idx}" type="button" title="Remove Location">✕</button>
          </div>
        `;
      })
      .join("");
  }

  renderFeedsLists() {
    const allSources =
      (this.currentUser && this.currentUser.custom_sources) || [];

    // 1. Render Built-in Default OSINT Feeds (with ON/OFF Toggle)
    if (this.defaultSourcesList) {
      const defaults = allSources
        .map((s, idx) => ({ ...s, _idx: idx }))
        .filter((s) => s.is_default);

      this.defaultSourcesList.innerHTML = defaults
        .map((s) => {
          const isEnabled = s.enabled !== false;
          const borderColor = isEnabled
            ? "var(--color-primary)"
            : "rgba(255, 255, 255, 0.15)";
          const iconColor = isEnabled
            ? "var(--color-primary)"
            : "rgba(255, 255, 255, 0.35)";
          const cardOpacity = isEnabled ? "1" : "0.62";

          return `
            <div class="location-item-card" style="border-left-color: ${borderColor}; opacity: ${cardOpacity};">
              <div class="location-item-left">
                <div class="location-city-icon" style="color: ${iconColor}; border-color: ${borderColor}; background: rgba(0, 111, 255, 0.1);">
                  <i class="fa-solid fa-globe"></i>
                </div>
                <div class="location-item-details">
                  <div class="location-item-title-row">
                    <span class="location-item-name">${s.name}</span>
                    <span class="location-item-badge">DEFAULT OSINT</span>
                  </div>
                  <div class="location-item-sub">
                    <span>${s.description || "Verified public OSINT threat feed"}</span>
                  </div>
                  <span class="source-item-url">${s.url}</span>
                </div>
              </div>
              <button class="feed-toggle-btn ${isEnabled ? "enabled" : "disabled"}" data-idx="${s._idx}" type="button" title="Toggle Default Feed On/Off">
                <i class="fa-solid ${isEnabled ? "fa-toggle-on" : "fa-toggle-off"}"></i>
                <span>${isEnabled ? "ENABLED" : "OFF"}</span>
              </button>
            </div>
          `;
        })
        .join("");
    }

    // 2. Render User-Added Custom SOC Feeds (with ON/OFF Toggle + Delete Button)
    if (this.customSourcesList) {
      const customs = allSources
        .map((s, idx) => ({ ...s, _idx: idx }))
        .filter((s) => !s.is_default);

      if (customs.length === 0) {
        this.customSourcesList.innerHTML = `<div class="ticker-empty">NO CUSTOM SOC FEEDS ADDED YET.<br/>ADD A FEED URL OR IP:PORT ABOVE OR CLICK A PRESET.</div>`;
        return;
      }

      this.customSourcesList.innerHTML = customs
        .map((s) => {
          const isEnabled = s.enabled !== false;
          const borderColor = isEnabled
            ? "#A855F7"
            : "rgba(255, 255, 255, 0.15)";
          const iconColor = isEnabled
            ? "#A855F7"
            : "rgba(255, 255, 255, 0.35)";
          const cardOpacity = isEnabled ? "1" : "0.62";

          return `
            <div class="location-item-card" style="border-left-color: ${borderColor}; opacity: ${cardOpacity};">
              <div class="location-item-left">
                <div class="location-city-icon" style="color: ${iconColor}; border-color: ${borderColor}; background: rgba(168, 85, 247, 0.12);">
                  <i class="fa-solid fa-satellite-dish"></i>
                </div>
                <div class="location-item-details">
                  <div class="location-item-title-row">
                    <span class="location-item-name" style="color: #ffffff;">${s.name}</span>
                    <span class="location-item-badge" style="color: #A855F7; border-color: rgba(168, 85, 247, 0.45); background: rgba(168, 85, 247, 0.15);">CUSTOM FEED</span>
                  </div>
                  <div class="location-item-sub">
                    <span class="source-item-url">${s.url}</span>
                  </div>
                </div>
              </div>
              <div style="display: flex; align-items: center; gap: 6px; flex-shrink: 0;">
                <button class="feed-toggle-btn ${isEnabled ? "enabled" : "disabled"}" data-idx="${s._idx}" type="button" title="Toggle Custom Feed On/Off">
                  <i class="fa-solid ${isEnabled ? "fa-toggle-on" : "fa-toggle-off"}"></i>
                  <span>${isEnabled ? "ENABLED" : "OFF"}</span>
                </button>
                <button class="source-del-btn feed-del-btn" data-idx="${s._idx}" type="button" title="Remove Custom Feed">✕</button>
              </div>
            </div>
          `;
        })
        .join("");
    }
  }

  async resolveIpGeolocation(ip) {
    const res = await fetch(`${CONFIG.apiBase}/api/geolocate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.detail || "Failed to geolocate IP address.");
    }
    return data;
  }

  async saveCustomLocations(locationsArray) {
    const res = await fetch(`${CONFIG.apiBase}/api/profile/locations`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.authToken}`,
      },
      body: JSON.stringify({ custom_locations: locationsArray }),
    });
    if (!res.ok) {
      throw new Error("Failed to save locations.");
    }
    const data = await res.json();
    this.currentUser = data.user;
    this.renderAll();
  }

  async saveCustomSources(sourcesArray) {
    const res = await fetch(`${CONFIG.apiBase}/api/profile/sources`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.authToken}`,
      },
      body: JSON.stringify({ custom_sources: sourcesArray }),
    });
    if (!res.ok) {
      throw new Error("Failed to save feed configuration.");
    }
    const data = await res.json();
    this.currentUser = data.user;
    this.renderAll();
  }

  bindEvents() {
    // Shared Logout Button
    if (this.btnSettingsLogout) {
      this.btnSettingsLogout.addEventListener("click", async () => {
        if (this.authToken) {
          await fetch(`${CONFIG.apiBase}/api/logout`, {
            method: "POST",
            headers: { Authorization: `Bearer ${this.authToken}` },
          }).catch(() => {});
        }
        localStorage.removeItem("soc_auth_token");
        localStorage.removeItem("soc_custom_locations");
        window.location.href = "index.html";
      });
    }

    // ===================================================================
    // 1. OPERATOR SETTINGS EVENTS (operator.html)
    // ===================================================================
    if (this.profileAvatarInput) {
      this.profileAvatarInput.addEventListener("change", async (e) => {
        const file = e.target.files[0];
        if (!file || !this.authToken) return;
        const dataUrl = await fileToDataUrl(file);
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
          this.renderAll();
          this.showToast(
            this.operatorStatusToast,
            "Operator profile avatar updated.",
            "success"
          );
        }
      });
    }

    if (this.btnRemoveAvatar) {
      this.btnRemoveAvatar.addEventListener("click", async () => {
        if (!this.authToken) return;
        const res = await fetch(`${CONFIG.apiBase}/api/profile/avatar`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${this.authToken}`,
          },
          body: JSON.stringify({ avatar: "" }),
        });
        if (res.ok) {
          const data = await res.json();
          this.currentUser = data.user;
          this.renderAll();
          this.showToast(
            this.operatorStatusToast,
            "Avatar reset to default astronaut icon.",
            "success"
          );
        }
      });
    }

    if (this.passwordForm) {
      this.passwordForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const currentPassword = this.currentPasswordInput.value;
        const newPassword = this.newPasswordInput.value;
        try {
          const res = await fetch(`${CONFIG.apiBase}/api/profile/password`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${this.authToken}`,
            },
            body: JSON.stringify({
              current_password: currentPassword,
              new_password: newPassword,
            }),
          });
          const data = await res.json();
          if (!res.ok) {
            this.showToast(
              this.operatorStatusToast,
              data.detail || "Failed to update passkey.",
              "error"
            );
            return;
          }
          this.passwordForm.reset();
          this.showToast(
            this.operatorStatusToast,
            "Security passkey updated!",
            "success"
          );
        } catch {
          this.showToast(
            this.operatorStatusToast,
            "Error communicating with server.",
            "error"
          );
        }
      });
    }

    if (this.prefBordersCheckbox) {
      this.prefBordersCheckbox.addEventListener("change", () => {
        localStorage.setItem(
          "soc_show_borders",
          this.prefBordersCheckbox.checked ? "true" : "false"
        );
        this.showToast(
          this.operatorStatusToast,
          `Interior country borders ${
            this.prefBordersCheckbox.checked ? "enabled" : "disabled"
          } by default on Threat Map.`,
          "success"
        );
      });
    }

    if (this.btnResetLocalStats) {
      this.btnResetLocalStats.addEventListener("click", () => {
        localStorage.removeItem("soc_total_attacks");
        localStorage.removeItem("soc_country_stats");
        localStorage.removeItem("soc_target_stats");
        this.renderAll();
        this.showToast(
          this.operatorStatusToast,
          "Local browser telemetry counters reset to zero.",
          "success"
        );
      });
    }

    // ===================================================================
    // 2. MAP LOCATIONS EVENTS (locations.html)
    // ===================================================================
    if (this.locColorInput) {
      const syncPinPreview = () => {
        const meta = getPinTypeMeta(this.locColorInput.value);
        if (this.locTypePreview) {
          this.locTypePreview.style.color = meta.color;
          this.locTypePreview.style.borderColor = meta.color;
        }
        if (this.locTypePreviewIcon) {
          this.locTypePreviewIcon.className = `fa-solid ${meta.faClass}`;
        }
      };
      this.locColorInput.addEventListener("change", syncPinPreview);
      syncPinPreview();
    }

    if (this.btnAutoGeolocate) {
      this.btnAutoGeolocate.addEventListener("click", async () => {
        const ip = this.locIpInput.value.trim();
        if (!ip) {
          this.showToast(
            this.locStatusToast,
            "Enter an IPv4 address or hostname first to auto-locate.",
            "error"
          );
          return;
        }

        this.btnAutoGeolocate.disabled = true;
        this.btnAutoGeolocate.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> LOCATING...`;
        try {
          const geo = await this.resolveIpGeolocation(ip);
          this.locIpInput.value = geo.ip;
          this.locLatInput.value = geo.lat;
          this.locLonInput.value = geo.lon;
          this.locCityInput.value = geo.city;
          this.locCountryInput.value = geo.country;
          this.locCodeInput.value = geo.code;
          if (!this.locNameInput.value.trim()) {
            this.locNameInput.value = `${geo.city.toUpperCase()} NODE`;
          }
          this.showToast(
            this.locStatusToast,
            `Resolved ${geo.ip} → ${geo.city}, ${geo.country} (${geo.lat.toFixed(4)}°, ${geo.lon.toFixed(4)}°)`,
            "success"
          );
        } catch (err) {
          this.showToast(this.locStatusToast, err.message, "error");
        } finally {
          this.btnAutoGeolocate.disabled = false;
          this.btnAutoGeolocate.innerHTML = `<i class="fa-solid fa-crosshairs"></i> AUTO-LOCATE IP`;
        }
      });
    }

    if (this.locationForm) {
      this.locationForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        let name = this.locNameInput.value.trim();
        let ip = this.locIpInput.value.trim();
        let latStr = this.locLatInput.value.trim();
        let lonStr = this.locLonInput.value.trim();
        let city = this.locCityInput.value.trim();
        let country = this.locCountryInput.value.trim();
        let code = this.locCodeInput.value.trim();
        const color = this.locColorInput.value || "#A855F7";
        const isTarget = this.locTargetCheckbox.checked;

        if (!name || !ip) {
          this.showToast(
            this.locStatusToast,
            "Please provide both a Location Name and an IP Address.",
            "error"
          );
          return;
        }

        try {
          if (latStr === "" || lonStr === "") {
            const geo = await this.resolveIpGeolocation(ip);
            ip = geo.ip;
            latStr = String(geo.lat);
            lonStr = String(geo.lon);
            city = geo.city;
            country = geo.country;
            code = geo.code;
          }

          const lat = parseFloat(latStr);
          const lon = parseFloat(lonStr);
          if (
            Number.isNaN(lat) ||
            Number.isNaN(lon) ||
            lat < -90 ||
            lat > 90 ||
            lon < -180 ||
            lon > 180
          ) {
            this.showToast(
              this.locStatusToast,
              "Invalid coordinates. Latitude must be -90..90 and Longitude -180..180.",
              "error"
            );
            return;
          }

          const newLoc = {
            id: Math.random().toString(36).slice(2, 10),
            name: name.toUpperCase(),
            ip,
            lat,
            lon,
            city: city || name,
            country: country || "Monitored Sector",
            code: (code || "un").toLowerCase(),
            color,
            is_target: isTarget,
          };

          const updated = [
            ...(this.currentUser.custom_locations || []),
            newLoc,
          ];
          await this.saveCustomLocations(updated);

          this.locationForm.reset();
          if (this.locColorInput) {
            this.locColorInput.dispatchEvent(new Event("change"));
          }
          this.locCityInput.value = "";
          this.locCountryInput.value = "";
          this.locCodeInput.value = "";
          this.locTargetCheckbox.checked = true;
          this.showToast(
            this.locStatusToast,
            `Pinned '${newLoc.name}' (${newLoc.ip}) to the Threat Map!`,
            "success"
          );
        } catch (err) {
          this.showToast(this.locStatusToast, err.message, "error");
        }
      });
    }

    document.querySelectorAll(".loc-preset-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const name = btn.dataset.name;
        const ip = btn.dataset.ip;
        const color = btn.dataset.color || "#A855F7";
        try {
          const geo = await this.resolveIpGeolocation(ip);
          const newLoc = {
            id: Math.random().toString(36).slice(2, 10),
            name,
            ip: geo.ip,
            lat: geo.lat,
            lon: geo.lon,
            city: geo.city,
            country: geo.country,
            code: geo.code,
            color,
            is_target: true,
          };
          const updated = [
            ...(this.currentUser.custom_locations || []),
            newLoc,
          ];
          await this.saveCustomLocations(updated);
          this.showToast(
            this.locStatusToast,
            `Added preset location '${name}' (${geo.city}, ${geo.country})!`,
            "success"
          );
        } catch (err) {
          this.showToast(this.locStatusToast, err.message, "error");
        }
      });
    });

    if (this.customLocationsList) {
      this.customLocationsList.addEventListener("click", async (e) => {
        const btn = e.target.closest(".loc-del-btn");
        if (!btn || !this.currentUser) return;
        const idx = parseInt(btn.dataset.idx, 10);
        const updated = (this.currentUser.custom_locations || []).filter(
          (_, i) => i !== idx
        );
        await this.saveCustomLocations(updated);
        this.showToast(
          this.locStatusToast,
          "Location removed from Threat Map.",
          "success"
        );
      });
    }

    // ===================================================================
    // 3. CUSTOM FEED OPTIONS EVENTS (feeds.html)
    // ===================================================================
    const handleToggleFeedAtIndex = async (idx) => {
      if (!this.currentUser) return;
      const updated = (this.currentUser.custom_sources || []).map((s, i) =>
        i === idx ? { ...s, enabled: s.enabled === false } : s
      );
      const target = updated[idx];
      await this.saveCustomSources(updated);
      if (target) {
        this.showToast(
          this.feedStatusToast,
          `Feed '${target.name}' ${
            target.enabled ? "ENABLED" : "DISABLED"
          }.`,
          "success"
        );
      }
    };

    if (this.defaultSourcesList) {
      this.defaultSourcesList.addEventListener("click", async (e) => {
        const toggleBtn = e.target.closest(".feed-toggle-btn");
        if (!toggleBtn) return;
        const idx = parseInt(toggleBtn.dataset.idx, 10);
        await handleToggleFeedAtIndex(idx);
      });
    }

    if (this.btnEnableAllDefaults) {
      this.btnEnableAllDefaults.addEventListener("click", async () => {
        if (!this.currentUser) return;
        const updated = (this.currentUser.custom_sources || []).map((s) =>
          s.is_default ? { ...s, enabled: true } : s
        );
        await this.saveCustomSources(updated);
        this.showToast(
          this.feedStatusToast,
          "All 4 built-in Default OSINT Feeds ENABLED.",
          "success"
        );
      });
    }

    if (this.btnDisableAllDefaults) {
      this.btnDisableAllDefaults.addEventListener("click", async () => {
        if (!this.currentUser) return;
        const updated = (this.currentUser.custom_sources || []).map((s) =>
          s.is_default ? { ...s, enabled: false } : s
        );
        await this.saveCustomSources(updated);
        this.showToast(
          this.feedStatusToast,
          "All built-in Default OSINT Feeds DISABLED (streaming only enabled custom feeds).",
          "success"
        );
      });
    }

    if (this.feedForm) {
      this.feedForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const name = this.sourceNameInput.value.trim().toUpperCase();
        const url = this.sourceUrlInput.value.trim();
        if (!name || !url) return;

        const existing = this.currentUser.custom_sources || [];
        if (existing.some((s) => s.url === url)) {
          this.showToast(
            this.feedStatusToast,
            `Feed URL is already in your configured feeds.`,
            "error"
          );
          return;
        }

        const updated = [
          ...existing,
          {
            id: `custom_${Date.now()}`,
            name,
            url,
            is_default: false,
            enabled: true,
          },
        ];
        await this.saveCustomSources(updated);
        this.feedForm.reset();
        this.showToast(
          this.feedStatusToast,
          `Added & enabled custom threat feed '${name}'!`,
          "success"
        );
      });
    }

    document.querySelectorAll(".feed-preset-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const name = btn.dataset.name;
        const url = btn.dataset.url;
        const existing = this.currentUser.custom_sources || [];
        if (existing.some((s) => s.url === url)) {
          this.showToast(
            this.feedStatusToast,
            `Feed '${name}' is already in your list.`,
            "error"
          );
          return;
        }
        const updated = [
          ...existing,
          {
            id: `custom_${Date.now()}`,
            name,
            url,
            is_default: false,
            enabled: true,
          },
        ];
        await this.saveCustomSources(updated);
        this.showToast(
          this.feedStatusToast,
          `Added preset OSINT feed '${name}'!`,
          "success"
        );
      });
    });

    if (this.customSourcesList) {
      this.customSourcesList.addEventListener("click", async (e) => {
        const toggleBtn = e.target.closest(".feed-toggle-btn");
        if (toggleBtn) {
          const idx = parseInt(toggleBtn.dataset.idx, 10);
          await handleToggleFeedAtIndex(idx);
          return;
        }

        const delBtn = e.target.closest(".feed-del-btn");
        if (delBtn && this.currentUser) {
          const idx = parseInt(delBtn.dataset.idx, 10);
          const updated = (this.currentUser.custom_sources || []).filter(
            (_, i) => i !== idx
          );
          await this.saveCustomSources(updated);
          this.showToast(
            this.feedStatusToast,
            "Custom feed removed.",
            "success"
          );
        }
      });
    }
  }
}

document.addEventListener("DOMContentLoaded", () => {
  new SubpageController();
});
