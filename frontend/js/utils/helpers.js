/**
 * Shared Utility, Pin Type Taxonomy & Math Functions
 * ==================================================
 * Pure helper functions for severity classification, color mapping,
 * 5-category map pin icons, Haversine geodesic distance, quadratic Bezier
 * interpolation, and image resizing.
 */

import { CONFIG } from "../config.js";

export const PIN_TYPES = {
  "#00F0FF": {
    key: "CITY",
    label: "DEFAULT CITY",
    faClass: "fa-city",
    unicode: "\uf64f",
    color: "#00F0FF",
  },
  "#006FFF": {
    key: "SOC_CORE",
    label: "SOC CORE",
    faClass: "fa-shield-halved",
    unicode: "\uf3ed",
    color: "#006FFF",
  },
  "#10B981": {
    key: "SENSOR",
    label: "SENSOR",
    faClass: "fa-satellite-dish",
    unicode: "\uf7c0",
    color: "#10B981",
  },
  "#FFB800": {
    key: "HIGH_VALUE",
    label: "HIGH VALUE",
    faClass: "fa-crown",
    unicode: "\uf521",
    color: "#FFB800",
  },
  "#FF5E36": {
    key: "HONEYPOT",
    label: "HONEYPOT",
    faClass: "fa-bug",
    unicode: "\uf188",
    color: "#FF5E36",
  },
};

export function getPinTypeMeta(color) {
  const norm = (color || "#00F0FF").toUpperCase();
  return PIN_TYPES[norm] || PIN_TYPES["#00F0FF"];
}

export function resolveSeverityBucket(data) {
  const rawSev = (data.severity || "").toUpperCase();
  const malware = (data.malware || "").toUpperCase();
  const category = (data.category || "").toUpperCase();

  if (rawSev === "LOW" || rawSev === "INFO") return "LOW";
  if (rawSev === "MEDIUM") return "MEDIUM";

  if (
    malware.includes("SCAN") ||
    malware.includes("BRUTE") ||
    category.includes("PROBE") ||
    category.includes("SCAN")
  ) {
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

export function getBucketColor(bucket) {
  if (bucket === "HIGH") return CONFIG.colorHigh;     // #FF5E36 (Cyber Flame Coral)
  if (bucket === "MEDIUM") return CONFIG.colorMed;    // #FFB800 (Solar Amber Gold)
  return CONFIG.colorLow;                             // #00A3FF (Electric Azure Blue)
}

export function calculateDistanceKm(lat1, lon1, lat2, lon2) {
  const toRad = (deg) => (deg * Math.PI) / 180;
  const R = 6371;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) *
      Math.cos(toRad(lat2)) *
      Math.sin(dLon / 2) *
      Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return Math.round(R * c);
}

export function getBezierPoint(t, p0, p1, p2) {
  const inv = 1 - t;
  return {
    x: inv * inv * p0.x + 2 * inv * t * p1.x + t * t * p2.x,
    y: inv * inv * p0.y + 2 * inv * t * p1.y + t * t * p2.y,
  };
}

export function getTopKey(mapObj, fallback) {
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

export function fileToDataUrl(file) {
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
