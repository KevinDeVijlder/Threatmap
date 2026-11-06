/**
 * WebSocket Telemetry Service
 * ===========================
 * Manages the WebSocket connection lifecycle, automatic reconnection,
 * status indicator updates, and session token synchronization.
 */

import { CONFIG } from "../config.js";

export class SocketService {
  constructor(app) {
    this.app = app;
  }

  connect() {
    try {
      this.app.ws = new WebSocket(CONFIG.wsUrl);

      this.app.ws.onopen = () => {
        this.app.isWsConnected = true;
        if (this.app.connStatus) {
          this.app.connStatus.style.backgroundColor = "#006FFF";
        }
        this.sendAuthUpdate();
      };

      this.app.ws.onmessage = (event) => {
        try {
          if (this.app.isStreamPaused) return;
          const payload = JSON.parse(event.data);
          this.app.triggerAttack(payload);
        } catch (err) {
          console.error("Failed to parse event:", err);
        }
      };

      this.app.ws.onclose = () => {
        this.app.isWsConnected = false;
        if (this.app.connStatus) {
          this.app.connStatus.style.backgroundColor = "#FFB800";
        }
        setTimeout(() => this.connect(), 4000);
      };

      this.app.ws.onerror = () => {
        if (this.app.ws) this.app.ws.close();
      };
    } catch {
      setTimeout(() => this.connect(), 4000);
    }
  }

  sendAuthUpdate() {
    if (this.app.ws && this.app.ws.readyState === WebSocket.OPEN) {
      this.app.ws.send(
        JSON.stringify({
          action: "auth",
          token: this.app.authToken,
        })
      );
    }
  }

  sendModeUpdate() {
    this.sendAuthUpdate();
  }
}
