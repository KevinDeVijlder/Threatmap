/**
 * Standalone Operator Configuration Page Controller (settings.html)
 * =================================================================
 * Manages operator profile avatar updates, Custom Threat Intelligence Feeds
 * CRUD, and Monitored Map Locations CRUD (with automatic IP geolocation).
 */

import { CONFIG } from "./config.js";
import { fileToDataUrl, getPinTypeMeta } from "./utils/helpers.js";

class SettingsPageController {
  constructor() {
    this.authToken = localStorage.getItem("soc_auth_token") || null;
    this.currentUser = null;

    // Header & Profile DOM
    this.btnSettingsLogout = document.getElementById("btn-settings-logout");
    this.profileAvatarPreview = document.getElementById("profile-avatar-preview");
    this.profileAvatarPlaceholder = document.getElementById("profile-avatar-placeholder");
    this.profileUsernameDisplay = document.getElementById("profile-username-display");
    this.profileAvatarInput = document.getElementById("profile-avatar-input");
    this.btnResetLocalStats = document.getElementById("btn-reset-local-stats");

    // Top Summary Counters
    this.statLocationsCount = document.getElementById("stat-locations-count");
    this.statFeedsCount = document.getElementById("stat-feeds-count");
    this.statLocalHits = document.getElementById("stat-local-hits");

    // Monitored Map Locations Form & List DOM
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

    // Custom Threat Feeds Form & List DOM
    this.feedForm = document.getElementById("feed-form");
    this.sourceNameInput = document.getElementById("source-name-input");
    this.sourceUrlInput = document.getElementById("source-url-input");
    this.feedStatusToast = document.getElementById("feed-status-toast");
    this.customSourcesList = document.getElementById("custom-sources-list");

    this.init();
  }

  async init() {
    if (!this.authToken) {
      window.location.href = "login.html?redirect=settings.html";
      return;
    }

    try {
      const res = await fetch(`${CONFIG.apiBase}/api/me`, {
        headers: { Authorization: `Bearer ${this.authToken}` },
      });
      if (!res.ok) {
        localStorage.removeItem("soc_auth_token");
        window.location.href = "login.html?redirect=settings.html";
        return;
      }
      const data = await res.json();
      this.currentUser = data.user;
    } catch {
      window.location.href = "login.html?redirect=settings.html";
      return;
    }

    this.bindEvents();
    this.renderAll();
  }

  showToast(el, message, type = "success") {
    if (!el) return;
    el.textContent = message;
    el.className = `status-toast ${type}`;
    clearTimeout(el._timer);
    el._timer = setTimeout(() => {
      el.className = "status-toast";
    }, 3500);
  }

  renderAll() {
    if (!this.currentUser) return;

    this.profileUsernameDisplay.textContent =
      this.currentUser.username.toUpperCase();

    if (this.currentUser.avatar) {
      this.profileAvatarPreview.src = this.currentUser.avatar;
      this.profileAvatarPreview.style.display = "block";
      this.profileAvatarPlaceholder.style.display = "none";
    } else {
      this.profileAvatarPreview.style.display = "none";
      this.profileAvatarPlaceholder.style.display = "block";
    }

    const locations = this.currentUser.custom_locations || [];
    const feeds = this.currentUser.custom_sources || [];
    const totalHits = parseInt(
      localStorage.getItem("soc_total_attacks") || "0",
      10
    );

    this.statLocationsCount.textContent = `${locations.length} NODES`;
    this.statFeedsCount.textContent = `${feeds.length} SOURCES`;
    this.statLocalHits.textContent = totalHits.toLocaleString();

    // Keep localStorage synced so the map renders pinned locations immediately
    localStorage.setItem("soc_custom_locations", JSON.stringify(locations));

    this.renderLocationsList();
    this.renderFeedsList();
  }

  renderLocationsList() {
    const locations = (this.currentUser && this.currentUser.custom_locations) || [];
    if (locations.length === 0) {
      this.customLocationsList.innerHTML = `<div class="ticker-empty">NO MONITORED LOCATIONS PINNED YET.<br/>ADD AN IP ADDRESS ABOVE TO DISPLAY A CITY ICON ON THE THREAT MAP.</div>`;
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
        const placeStr = [loc.city, loc.country].filter(Boolean).join(", ") || "Custom Coordinates";
        const targetBadge = loc.is_target !== false ? "TARGET ENABLED" : "DISPLAY ONLY";

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

  renderFeedsList() {
    const sources = (this.currentUser && this.currentUser.custom_sources) || [];
    if (sources.length === 0) {
      this.customSourcesList.innerHTML = `<div class="ticker-empty">NO CUSTOM FEEDS CONFIGURED YET.<br/>ADD A FEED URL OR IP:PORT ABOVE OR CLICK A PRESET.</div>`;
      return;
    }

    this.customSourcesList.innerHTML = sources
      .map(
        (s, idx) => `
        <div class="location-item-card">
          <div class="location-item-left">
            <div class="location-city-icon" style="color: var(--color-primary); border-color: var(--color-primary); background: rgba(0, 111, 255, 0.1);">
              <i class="fa-solid fa-satellite-dish"></i>
            </div>
            <div class="location-item-details">
              <div class="location-item-title-row">
                <span class="location-item-name" style="color: var(--color-primary);">${s.name}</span>
              </div>
              <div class="location-item-sub">
                <span class="source-item-url">${s.url}</span>
              </div>
            </div>
          </div>
          <button class="source-del-btn feed-del-btn" data-idx="${idx}" type="button" title="Remove Feed">✕</button>
        </div>
      `
      )
      .join("");
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
      throw new Error("Failed to save custom feeds.");
    }
    const data = await res.json();
    this.currentUser = data.user;
    this.renderAll();
  }

  bindEvents() {
    // Logout Button
    this.btnSettingsLogout.addEventListener("click", async () => {
      if (this.authToken) {
        await fetch(`${CONFIG.apiBase}/api/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${this.authToken}` },
        }).catch(() => {});
      }
      localStorage.removeItem("soc_auth_token");
      window.location.href = "index.html";
    });

    // Change Profile Avatar
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
      }
    });

    // Reset Local Browser Telemetry Counters
    this.btnResetLocalStats.addEventListener("click", () => {
      localStorage.removeItem("soc_total_attacks");
      localStorage.removeItem("soc_country_stats");
      localStorage.removeItem("soc_target_stats");
      this.renderAll();
      this.showToast(
        this.locStatusToast,
        "Local browser telemetry counters reset to zero.",
        "success"
      );
    });

    // Live Pin Category & Icon Preview Update
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

    // Auto-Locate IP Button
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

    // Add Monitored Location Form Submit
    this.locationForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      let name = this.locNameInput.value.trim();
      let ip = this.locIpInput.value.trim();
      let latStr = this.locLatInput.value.trim();
      let lonStr = this.locLonInput.value.trim();
      let city = this.locCityInput.value.trim();
      let country = this.locCountryInput.value.trim();
      let code = this.locCodeInput.value.trim();
      const color = this.locColorInput.value || "#00F0FF";
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
        // Automatically geolocate the IP if Latitude or Longitude was left blank
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
        this.locColorInput.dispatchEvent(new Event("change"));
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

    // Quick-Add Sample Locations
    document.querySelectorAll(".loc-preset-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const name = btn.dataset.name;
        const ip = btn.dataset.ip;
        const color = btn.dataset.color || "#00F0FF";
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

    // Delete Monitored Location
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

    // Add Custom Threat Feed Form Submit
    this.feedForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = this.sourceNameInput.value.trim().toUpperCase();
      const url = this.sourceUrlInput.value.trim();
      if (!name || !url) return;

      const updated = [
        ...(this.currentUser.custom_sources || []),
        { name, url },
      ];
      await this.saveCustomSources(updated);
      this.feedForm.reset();
      this.showToast(
        this.feedStatusToast,
        `Added custom threat feed '${name}'!`,
        "success"
      );
    });

    // Quick-Add OSINT Feed Presets
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
        const updated = [...existing, { name, url }];
        await this.saveCustomSources(updated);
        this.showToast(
          this.feedStatusToast,
          `Added preset OSINT feed '${name}'!`,
          "success"
        );
      });
    });

    // Delete Custom Threat Feed
    this.customSourcesList.addEventListener("click", async (e) => {
      const btn = e.target.closest(".feed-del-btn");
      if (!btn || !this.currentUser) return;
      const idx = parseInt(btn.dataset.idx, 10);
      const updated = (this.currentUser.custom_sources || []).filter(
        (_, i) => i !== idx
      );
      await this.saveCustomSources(updated);
      this.showToast(
        this.feedStatusToast,
        "Custom feed removed.",
        "success"
      );
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  new SettingsPageController();
});
