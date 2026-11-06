/**
 * Global Frontend Configuration
 * =============================
 * Centralizes canvas layout margins, map colors, severity palette,
 * trajectory speeds, and backend API / WebSocket URLs.
 */

export const CONFIG = {
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
