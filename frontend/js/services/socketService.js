/**
 * WebSocket Telemetry Service
 * ===========================
 * Manages the WebSocket connection lifecycle, automatic reconnection,
 * status indicator updates, and live/custom feed mode synchronization.
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
        this.app.connStatus.style.backgroundColor = "#006FFF";
        this.sendModeUpdate();
      };

      this.app.ws.onmessage = (event) => {
        try {
          if (this.app.isStreamPaused) return;
          const payload = JSON.parse(event.data);
          if (payload.feedMode && payload.feedMode !== this.app.activeFeedMode) {
            return;
          }
          this.app.triggerAttack(payload);
        } catch (err) {
          console.error("Failed to parse event:", err);
        }
      };

      this.app.ws.onclose = () => {
        this.app.isWsConnected = false;
        this.app.connStatus.style.backgroundColor = "#FFB800";
        setTimeout(() => this.connect(), 4000);
      };

      this.app.ws.onerror = () => {
        if (this.app.ws) this.app.ws.close();
      };
    } catch {
      setTimeout(() => this.connect(), 4000);
    }
  }

  sendModeUpdate() {
    if (this.app.ws && this.app.ws.readyState === WebSocket.OPEN) {
      this.app.ws.send(
        JSON.stringify({
          action: "set_mode",
          mode: this.app.activeFeedMode,
          token: this.app.authToken,
        })
      );
    }
  }
}
