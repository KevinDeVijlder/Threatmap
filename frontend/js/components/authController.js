/**
 * Authentication, Profile & Custom OSINT Feeds Controller
 * =======================================================
 * Handles operator login/registration, session persistence, profile avatar
 * updates, custom feed CRUD, and switching between 'live' and 'custom' modes.
 */

import { CONFIG } from "../config.js";
import { fileToDataUrl } from "../utils/helpers.js";

export class AuthController {
  constructor(app) {
    this.app = app;
  }

  switchFeedMode(mode) {
    if (mode === "custom" && !this.app.currentUser) return;

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
        : `<div class="ticker-empty">NO CUSTOM FEEDS ADDED YET.<br/>OPEN CUSTOM FEED SETTINGS TO ADD SOURCES.</div>`;
    }

    this.app.socketService.sendModeUpdate();
  }

  async checkExistingSession() {
    if (!this.app.authToken) {
      this.updateUserHeaderUI();
      return;
    }
    try {
      const res = await fetch(`${CONFIG.apiBase}/api/me`, {
        headers: { Authorization: `Bearer ${this.app.authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        this.app.currentUser = data.user;
      } else {
        this.app.authToken = null;
        localStorage.removeItem("soc_auth_token");
      }
    } catch {}
    this.updateUserHeaderUI();
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
      this.app.menuTextAccount.textContent = "ACCOUNT SETTINGS";
      this.app.menuBtnFeeds.classList.remove("disabled");
      this.app.menuBtnLogout.classList.remove("disabled");

      if (this.app.currentUser.avatar) {
        this.app.userAvatarImg.src = this.app.currentUser.avatar;
        this.app.userAvatarImg.style.display = "block";
        this.app.userDefaultIcon.style.display = "none";

        this.app.profileAvatarPreview.src = this.app.currentUser.avatar;
        this.app.profileAvatarPreview.style.display = "block";
        this.app.profileAvatarPlaceholder.style.display = "none";
      } else {
        this.app.userAvatarImg.style.display = "none";
        this.app.userDefaultIcon.style.display = "block";

        this.app.profileAvatarPreview.style.display = "none";
        this.app.profileAvatarPlaceholder.style.display = "block";
      }

      this.app.profileUsernameDisplay.textContent =
        this.app.currentUser.username.toUpperCase();
      this.renderCustomSourcesList();
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

  openModalSection(section) {
    this.app.authError.style.display = "none";
    this.app.modalAuthView.style.display = "none";
    this.app.modalAccountView.style.display = "none";
    this.app.modalFeedsView.style.display = "none";

    if (!this.app.currentUser || section === "auth") {
      this.app.modalTitle.textContent = "SOC OPERATOR AUTHENTICATION";
      this.app.modalAuthView.style.display = "flex";
    } else if (section === "account") {
      this.app.modalTitle.textContent = "ACCOUNT SETTINGS";
      this.app.modalAccountView.style.display = "flex";
    } else if (section === "feeds") {
      this.app.modalTitle.textContent = "CUSTOM FEED SETTINGS";
      this.app.modalFeedsView.style.display = "flex";
    }
    this.app.userModalBackdrop.style.display = "flex";
  }

  renderCustomSourcesList() {
    if (!this.app.currentUser) return;
    const sources = this.app.currentUser.custom_sources || [];
    if (sources.length === 0) {
      this.app.customSourcesList.innerHTML = `<div class="ticker-empty">NO CUSTOM FEEDS CONFIGURED YET</div>`;
      return;
    }
    this.app.customSourcesList.innerHTML = sources
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
    if (!this.app.authToken) return;
    const res = await fetch(`${CONFIG.apiBase}/api/profile/sources`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.app.authToken}`,
      },
      body: JSON.stringify({ custom_sources: sourcesArray }),
    });
    if (res.ok) {
      const data = await res.json();
      this.app.currentUser = data.user;
      this.renderCustomSourcesList();
      if (this.app.activeFeedMode === "custom") {
        this.switchFeedMode("custom");
      }
    }
  }

  bindAuthEvents() {
    this.app.btnModeLive.addEventListener("click", () => {
      this.switchFeedMode("live");
    });
    this.app.btnModeCustom.addEventListener("click", () => {
      if (this.app.currentUser) this.switchFeedMode("custom");
    });
    this.app.btnUserProfile.addEventListener("click", () => {
      this.openModalSection(this.app.currentUser ? "account" : "auth");
    });
    this.app.menuBtnAccount.addEventListener("click", () => {
      this.openModalSection(this.app.currentUser ? "account" : "auth");
    });
    this.app.menuBtnFeeds.addEventListener("click", () => {
      if (this.app.currentUser) this.openModalSection("feeds");
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
      localStorage.removeItem("soc_auth_token");
      this.updateUserHeaderUI();
      this.app.userModalBackdrop.style.display = "none";
    });

    this.app.btnCloseModal.addEventListener("click", () => {
      this.app.userModalBackdrop.style.display = "none";
    });
    this.app.userModalBackdrop.addEventListener("click", (e) => {
      if (e.target === this.app.userModalBackdrop)
        this.app.userModalBackdrop.style.display = "none";
    });

    this.app.tabLogin.addEventListener("click", () => {
      this.app.authMode = "login";
      this.app.tabLogin.classList.add("active");
      this.app.tabRegister.classList.remove("active");
      this.app.registerAvatarGroup.style.display = "none";
      this.app.btnAuthSubmit.textContent = "AUTHENTICATE";
      this.app.authError.style.display = "none";
    });

    this.app.tabRegister.addEventListener("click", () => {
      this.app.authMode = "register";
      this.app.tabRegister.classList.add("active");
      this.app.tabLogin.classList.remove("active");
      this.app.registerAvatarGroup.style.display = "flex";
      this.app.btnAuthSubmit.textContent = "REGISTER OPERATOR";
      this.app.authError.style.display = "none";
    });

    this.app.regAvatarInput.addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      this.app.pendingRegAvatar = await fileToDataUrl(file);
      this.app.regAvatarPreview.src = this.app.pendingRegAvatar;
      this.app.regAvatarPreview.style.display = "block";
      this.app.regAvatarPlaceholder.style.display = "none";
    });

    this.app.authForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      this.app.authError.style.display = "none";

      const endpoint =
        this.app.authMode === "register" ? "/api/register" : "/api/login";
      const payload = {
        username: this.app.authUsername.value.trim(),
        password: this.app.authPassword.value,
        avatar: this.app.authMode === "register" ? this.app.pendingRegAvatar : "",
      };

      try {
        const res = await fetch(`${CONFIG.apiBase}${endpoint}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) {
          this.app.authError.textContent =
            data.detail || "Authentication failed.";
          this.app.authError.style.display = "block";
          return;
        }

        this.app.authToken = data.token;
        this.app.currentUser = data.user;
        localStorage.setItem("soc_auth_token", this.app.authToken);
        this.app.authForm.reset();
        this.updateUserHeaderUI();
        this.app.userModalBackdrop.style.display = "none";
      } catch {
        this.app.authError.textContent =
          "Unable to reach authentication server.";
        this.app.authError.style.display = "block";
      }
    });

    this.app.profileAvatarInput.addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (!file || !this.app.authToken) return;
      const dataUrl = await fileToDataUrl(file);
      const res = await fetch(`${CONFIG.apiBase}/api/profile/avatar`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${this.app.authToken}`,
        },
        body: JSON.stringify({ avatar: dataUrl }),
      });
      if (res.ok) {
        const data = await res.json();
        this.app.currentUser = data.user;
        this.updateUserHeaderUI();
      }
    });

    this.app.btnAddSource.addEventListener("click", async () => {
      if (!this.app.currentUser) return;
      const name = this.app.sourceNameInput.value.trim();
      const url = this.app.sourceUrlInput.value.trim();
      if (!name || !url) return;

      const updated = [
        ...(this.app.currentUser.custom_sources || []),
        { name, url },
      ];
      await this.saveCustomSources(updated);
      this.app.sourceNameInput.value = "";
      this.app.sourceUrlInput.value = "";
    });

    this.app.customSourcesList.addEventListener("click", async (e) => {
      const btn = e.target.closest(".source-del-btn");
      if (!btn || !this.app.currentUser) return;
      const idx = parseInt(btn.dataset.idx, 10);
      const updated = (this.app.currentUser.custom_sources || []).filter(
        (_, i) => i !== idx
      );
      await this.saveCustomSources(updated);
    });
  }
}
