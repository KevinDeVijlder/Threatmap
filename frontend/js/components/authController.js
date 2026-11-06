/**
 * Authentication & Header Navigation Controller (Map Dashboard)
 * =============================================================
 * Verifies active operator session on the Threat Map, syncs custom monitored
 * locations, updates the top-right operator menu, and routes to the dedicated
 * `login.html` and `settings.html` pages.
 */

import { CONFIG } from "../config.js";

export class AuthController {
  constructor(app) {
    this.app = app;
  }

  switchFeedMode(mode) {
    if (mode === "custom" && !this.app.currentUser) {
      window.location.href = "login.html?redirect=settings.html";
      return;
    }

    this.app.activeFeedMode = mode;
    this.app.attacks = [];
    this.app.ripples = [];
    this.app.rawAttackBuffer = [];
    this.app.selectedAttack = null;
    this.app.updateAttackDossier();

    if (mode === "live") {
      this.app.btnModeLive.classList.add("active");
      this.app.btnModeLive.classList.remove("inactive");
      this.app.btnModeCustom.classList.remove("active");
      this.app.btnModeCustom.classList.add("inactive");
      this.app.feedModeLabel.textContent = this.app.isStreamPaused
        ? "STREAM PAUSED"
        : "LIVE OSINT STREAM";
      this.app.attackTicker.innerHTML = `<div class="ticker-empty">LISTENING FOR LIVE OSINT INTRUSIONS...</div>`;
    } else {
      this.app.btnModeCustom.classList.add("active");
      this.app.btnModeCustom.classList.remove("inactive");
      this.app.btnModeLive.classList.remove("active");
      this.app.btnModeLive.classList.add("inactive");
      this.app.feedModeLabel.textContent = `CUSTOM // ${this.app.currentUser.username.toUpperCase()}`;

      const hasSources = (this.app.currentUser.custom_sources || []).length > 0;
      this.app.attackTicker.innerHTML = hasSources
        ? `<div class="ticker-empty">STREAMING FROM YOUR CUSTOM FEEDS...</div>`
        : `<div class="ticker-empty">NO CUSTOM FEEDS ADDED YET.<br/><a href="settings.html#feeds" style="color: var(--color-accent);">OPEN CONFIGURATION PAGE TO ADD SOURCES →</a></div>`;
    }

    this.app.socketService.sendModeUpdate();
  }

  async checkExistingSession() {
    this.app.currentUser = null;
    this.app.customLocations = [];

    if (!this.app.authToken) {
      localStorage.removeItem("soc_custom_locations");
      this.updateUserHeaderUI();
      this.app.renderPinnedNodesLegend();
      return;
    }
    try {
      const res = await fetch(`${CONFIG.apiBase}/api/me`, {
        headers: { Authorization: `Bearer ${this.app.authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        this.app.currentUser = data.user;
        this.app.customLocations = data.user.custom_locations || [];
        localStorage.setItem(
          "soc_custom_locations",
          JSON.stringify(this.app.customLocations)
        );
      } else {
        this.app.authToken = null;
        this.app.currentUser = null;
        this.app.customLocations = [];
        localStorage.removeItem("soc_auth_token");
        localStorage.removeItem("soc_custom_locations");
      }
    } catch {
      this.app.currentUser = null;
      this.app.customLocations = [];
    }
    this.updateUserHeaderUI();
    this.app.renderPinnedNodesLegend();
  }

  updateUserHeaderUI() {
    if (this.app.currentUser) {
      this.app.customModeWrapper.classList.remove("locked");
      this.app.btnModeCustom.classList.remove("locked");
      this.app.btnModeCustom.disabled = false;

      this.app.btnUserProfile.classList.remove("logged-out");
      this.app.btnUserProfile.classList.add("logged-in");

      this.app.dropdownUserStatus.textContent = `OPERATOR // ${this.app.currentUser.username.toUpperCase()}`;
      this.app.menuIconAccount.className = "fa-solid fa-user-gear";
      this.app.menuTextAccount.textContent = "OPERATOR SETTINGS";
      this.app.menuBtnFeeds.classList.remove("disabled");
      this.app.menuBtnLogout.classList.remove("disabled");

      if (this.app.currentUser.avatar) {
        this.app.userAvatarImg.src = this.app.currentUser.avatar;
        this.app.userAvatarImg.style.display = "block";
        this.app.userDefaultIcon.style.display = "none";
      } else {
        this.app.userAvatarImg.style.display = "none";
        this.app.userDefaultIcon.style.display = "block";
      }
    } else {
      this.app.customModeWrapper.classList.add("locked");
      this.app.btnModeCustom.classList.add("locked");
      this.app.btnModeCustom.disabled = true;
      if (this.app.activeFeedMode === "custom") {
        this.switchFeedMode("live");
      }

      this.app.btnUserProfile.classList.add("logged-out");
      this.app.btnUserProfile.classList.remove("logged-in");
      this.app.userAvatarImg.style.display = "none";
      this.app.userDefaultIcon.style.display = "block";

      this.app.dropdownUserStatus.textContent = "UNAUTHENTICATED SESSION";
      this.app.menuIconAccount.className = "fa-solid fa-user-plus";
      this.app.menuTextAccount.textContent = "REGISTER / LOGIN";
      this.app.menuBtnFeeds.classList.add("disabled");
      this.app.menuBtnLogout.classList.add("disabled");
    }
  }

  bindAuthEvents() {
    this.app.btnModeLive.addEventListener("click", () => {
      this.switchFeedMode("live");
    });

    this.app.btnModeCustom.addEventListener("click", () => {
      if (this.app.currentUser) {
        this.switchFeedMode("custom");
      } else {
        window.location.href = "login.html";
      }
    });

    this.app.btnUserProfile.addEventListener("click", () => {
      window.location.href = this.app.currentUser
        ? "settings.html"
        : "login.html";
    });

    this.app.menuBtnAccount.addEventListener("click", () => {
      window.location.href = this.app.currentUser
        ? "settings.html"
        : "login.html";
    });

    this.app.menuBtnFeeds.addEventListener("click", () => {
      if (this.app.currentUser) {
        window.location.href = "settings.html#locations";
      } else {
        window.location.href = "login.html?redirect=settings.html";
      }
    });

    this.app.menuBtnLogout.addEventListener("click", async () => {
      if (!this.app.currentUser) return;
      if (this.app.authToken) {
        await fetch(`${CONFIG.apiBase}/api/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${this.app.authToken}` },
        }).catch(() => {});
      }
      this.app.authToken = null;
      this.app.currentUser = null;
      this.app.customLocations = [];
      localStorage.removeItem("soc_auth_token");
      localStorage.removeItem("soc_custom_locations");
      if (this.app.onlyPinnedFilter) {
        this.app.togglePinnedIpFilter();
      }
      this.updateUserHeaderUI();
      this.app.renderPinnedNodesLegend();
      this.app.socketService.sendModeUpdate();
    });
  }
}
