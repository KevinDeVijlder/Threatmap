/**
 * Standalone Login & Operator Registration Page Controller
 * ========================================================
 * Handles operator login, registration with optional avatar upload,
 * session detection, and automatic redirection back to the Threat Map
 * or Operator Settings page.
 */

import { CONFIG } from "./config.js";
import { fileToDataUrl } from "./utils/helpers.js";

class LoginPageController {
  constructor() {
    this.authToken = localStorage.getItem("soc_auth_token") || null;
    this.authMode = "login";
    this.pendingRegAvatar = "";

    this.authPageTitle = document.getElementById("auth-page-title");
    this.authFormSection = document.getElementById("auth-form-section");
    this.authLoggedInSection = document.getElementById("auth-logged-in-section");

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
    this.authSuccess = document.getElementById("auth-success");
    this.btnAuthSubmit = document.getElementById("btn-auth-submit");

    this.activeAvatarPreview = document.getElementById("active-avatar-preview");
    this.activeAvatarPlaceholder = document.getElementById("active-avatar-placeholder");
    this.activeUsernameDisplay = document.getElementById("active-username-display");
    this.btnPageLogout = document.getElementById("btn-page-logout");

    this.init();
  }

  async init() {
    const params = new URLSearchParams(window.location.search);
    if (params.get("mode") === "register") {
      this.setTab("register");
    }

    this.bindEvents();
    await this.checkExistingSession();
  }

  setTab(mode) {
    this.authMode = mode;
    this.authError.style.display = "none";
    this.authSuccess.style.display = "none";

    if (mode === "register") {
      this.tabRegister.classList.add("active");
      this.tabLogin.classList.remove("active");
      this.registerAvatarGroup.style.display = "flex";
      this.btnAuthSubmit.textContent = "REGISTER OPERATOR";
    } else {
      this.tabLogin.classList.add("active");
      this.tabRegister.classList.remove("active");
      this.registerAvatarGroup.style.display = "none";
      this.btnAuthSubmit.textContent = "AUTHENTICATE SESSION";
    }
  }

  async checkExistingSession() {
    if (!this.authToken) return;
    try {
      const res = await fetch(`${CONFIG.apiBase}/api/me`, {
        headers: { Authorization: `Bearer ${this.authToken}` },
      });
      if (res.ok) {
        const data = await res.json();
        this.showLoggedInState(data.user);
      } else {
        this.authToken = null;
        localStorage.removeItem("soc_auth_token");
        localStorage.removeItem("soc_custom_locations");
      }
    } catch {}
  }

  showLoggedInState(user) {
    this.authPageTitle.textContent = "ACTIVE OPERATOR SESSION";
    this.authFormSection.style.display = "none";
    this.authLoggedInSection.style.display = "flex";
    this.activeUsernameDisplay.textContent = user.username.toUpperCase();

    if (user.avatar) {
      this.activeAvatarPreview.src = user.avatar;
      this.activeAvatarPreview.style.display = "block";
      this.activeAvatarPlaceholder.style.display = "none";
    } else {
      this.activeAvatarPreview.style.display = "none";
      this.activeAvatarPlaceholder.style.display = "block";
    }
  }

  bindEvents() {
    this.tabLogin.addEventListener("click", () => this.setTab("login"));
    this.tabRegister.addEventListener("click", () => this.setTab("register"));

    this.regAvatarInput.addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      this.pendingRegAvatar = await fileToDataUrl(file);
      this.regAvatarPreview.src = this.pendingRegAvatar;
      this.regAvatarPreview.style.display = "block";
      this.regAvatarPlaceholder.style.display = "none";
    });

    this.authForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      this.authError.style.display = "none";
      this.authSuccess.style.display = "none";

      const endpoint =
        this.authMode === "register" ? "/api/register" : "/api/login";
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
          this.authError.textContent =
            data.detail || "Authentication failed.";
          this.authError.style.display = "block";
          return;
        }

        this.authToken = data.token;
        localStorage.setItem("soc_auth_token", this.authToken);
        if (data.user && data.user.custom_locations) {
          localStorage.setItem(
            "soc_custom_locations",
            JSON.stringify(data.user.custom_locations)
          );
        }

        const params = new URLSearchParams(window.location.search);
        const redirectTarget = params.get("redirect") || "index.html";
        window.location.href = redirectTarget;
      } catch {
        this.authError.textContent =
          "Unable to reach authentication server.";
        this.authError.style.display = "block";
      }
    });

    this.btnPageLogout.addEventListener("click", async () => {
      if (this.authToken) {
        await fetch(`${CONFIG.apiBase}/api/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${this.authToken}` },
        }).catch(() => {});
      }
      this.authToken = null;
      localStorage.removeItem("soc_auth_token");
      localStorage.removeItem("soc_custom_locations");
      this.authPageTitle.textContent = "SOC OPERATOR AUTHENTICATION";
      this.authLoggedInSection.style.display = "none";
      this.authFormSection.style.display = "flex";
    });
  }
}

document.addEventListener("DOMContentLoaded", () => {
  new LoginPageController();
});
