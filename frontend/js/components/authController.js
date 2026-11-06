/**
 * Authentication & Header Navigation Controller (Map Dashboard)
 * =============================================================
 * Verifies active operator session on the Threat Map, syncs custom monitored
 * locations & active feeds, updates the top-right hover-only operator menu
 * (Operator Settings, Map Locations, Custom Feed Options, GitHub Project, Logout),
 * and routes to the dedicated subpages (`operator.html`, `locations.html`, `feeds.html`).
 */

import { CONFIG } from "../config.js";

const GITHUB_REPO_URL = "https://github.com/KevinDeVijlder/Threatmap";

export class AuthController {
  constructor(app) {
    this.app = app;
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

  updateStreamLabels() {
    if (this.app.isStreamPaused) {
      if (this.app.feedModeLabel) this.app.feedModeLabel.textContent = "STREAM PAUSED";
      return;
    }

    if (this.app.currentUser) {
      const sources = this.app.currentUser.custom_sources || [];
      const enabledCount = sources.filter((s) => s.enabled !== false).length;
      const customEnabledCount = sources.filter(
        (s) => !s.is_default && s.enabled !== false
      ).length;

      if (this.app.feedStreamStatus) {
        this.app.feedStreamStatus.textContent =
          enabledCount > 0
            ? `ACTIVE STREAM (${enabledCount} FEEDS ON)`
            : "ALL FEEDS DISABLED";
      }
      if (this.app.feedModeLabel) {
        this.app.feedModeLabel.textContent =
          customEnabledCount > 0
            ? `UNIFIED + ${customEnabledCount} CUSTOM`
            : "DEFAULT OSINT STREAM";
      }

      if (enabledCount === 0 && this.app.attackTicker && this.app.rawAttackBuffer.length === 0) {
        this.app.attackTicker.innerHTML = `<div class="ticker-empty">ALL THREAT FEEDS ARE TURNED OFF.<br/><a href="feeds.html" style="color: var(--color-accent);">OPEN CUSTOM FEED OPTIONS TO ENABLE FEEDS →</a></div>`;
      }
    } else {
      if (this.app.feedStreamStatus) {
        this.app.feedStreamStatus.textContent = "ACTIVE THREAT STREAM (4 DEFAULT FEEDS)";
      }
      if (this.app.feedModeLabel) {
        this.app.feedModeLabel.textContent = "LIVE OSINT STREAM";
      }
    }
  }

  updateUserHeaderUI() {
    if (this.app.currentUser) {
      this.app.btnUserProfile.classList.remove("logged-out");
      this.app.btnUserProfile.classList.add("logged-in");

      this.app.dropdownUserStatus.textContent = `OPERATOR ${this.app.currentUser.username.toUpperCase()}`;
      if (this.app.dropdownLoginLink) {
        this.app.dropdownLoginLink.style.display = "none";
      }
      if (this.app.menuBtnLogout) {
        this.app.menuBtnLogout.classList.remove("disabled");
      }

      if (this.app.currentUser.avatar) {
        this.app.userAvatarImg.src = this.app.currentUser.avatar;
        this.app.userAvatarImg.style.display = "block";
        this.app.userDefaultIcon.style.display = "none";
      } else {
        this.app.userAvatarImg.style.display = "none";
        this.app.userDefaultIcon.style.display = "block";
      }
    } else {
      this.app.btnUserProfile.classList.add("logged-out");
      this.app.btnUserProfile.classList.remove("logged-in");
      this.app.userAvatarImg.style.display = "none";
      this.app.userDefaultIcon.style.display = "block";

      this.app.dropdownUserStatus.textContent = "GUEST SESSION";
      if (this.app.dropdownLoginLink) {
        this.app.dropdownLoginLink.style.display = "inline-block";
      }
      if (this.app.menuBtnLogout) {
        this.app.menuBtnLogout.classList.add("disabled");
      }
    }

    this.updateStreamLabels();
  }

  bindAuthEvents() {
    // Note: #btn-user-profile is intentionally hover-only and NOT clickable.

    // 1. Operator Settings
    if (this.app.menuBtnOperator) {
      this.app.menuBtnOperator.addEventListener("click", () => {
        window.location.href = this.app.currentUser
          ? "operator.html"
          : "login.html?redirect=operator.html";
      });
    }

    // 2. Map Locations
    if (this.app.menuBtnLocations) {
      this.app.menuBtnLocations.addEventListener("click", () => {
        window.location.href = this.app.currentUser
          ? "locations.html"
          : "login.html?redirect=locations.html";
      });
    }

    // 3. Custom Feed Options
    if (this.app.menuBtnFeeds) {
      this.app.menuBtnFeeds.addEventListener("click", () => {
        window.location.href = this.app.currentUser
          ? "feeds.html"
          : "login.html?redirect=feeds.html";
      });
    }

    // 4. Go to GitHub Project
    if (this.app.menuBtnGithub) {
      this.app.menuBtnGithub.addEventListener("click", () => {
        window.open(GITHUB_REPO_URL, "_blank", "noopener,noreferrer");
      });
    }

    // 5. Logout
    if (this.app.menuBtnLogout) {
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
        this.app.socketService.sendAuthUpdate();
      });
    }
  }
}
