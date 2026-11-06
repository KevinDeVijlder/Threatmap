/**
 * Intrusion Feed, Search, Filter & Export Controller
 * ==================================================
 * Manages the left-sidebar live attack ticker, severity filter chips,
 * real-time search query filtering, stream pause/resume toggle, and
 * JSON/CSV session packet export.
 */

import { resolveSeverityBucket } from "../utils/helpers.js";

export class FeedController {
  constructor(app) {
    this.app = app;
  }

  matchesFilterBucket(bucket) {
    if (this.app.currentSeverityFilter === "ALL") return true;
    return bucket === this.app.currentSeverityFilter;
  }

  /**
   * Checks whether an attack telemetry event's destination IP (or source IP)
   * matches any of the user's pinned IP addresses.
   */
  matchesPinnedIp(data) {
    if (!data || !this.app.currentUser) return false;
    if (data._matchesPinnedIp) return true;
    const locations = this.app.customLocations || [];
    if (locations.length === 0) return false;

    const normalizeIp = (val) => String(val || "").trim().split(":")[0];
    const dstIp = normalizeIp(data.dstIp);
    const srcIp = normalizeIp(data.srcIp);

    return locations.some((loc) => {
      const locIp = normalizeIp(loc.ip);
      return locIp && locIp !== "N/A" && (locIp === dstIp || locIp === srcIp);
    });
  }

  matchesSearchQuery(data) {
    if (!this.app.searchQuery) return true;
    const q = this.app.searchQuery.toLowerCase();
    const haystack = [
      data.malware,
      data.category,
      data.srcIp,
      data.srcCity,
      data.srcCountry,
      data.srcCode,
      data.srcAsn,
      data.dstIp,
      data.dstCity,
      data.dstCountry,
      data.dstCode,
      data.cve,
      data.mitre,
      String(data.port || ""),
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();

    return haystack.includes(q);
  }

  matchesActiveFilters(data) {
    if (!data) return false;
    const bucket = data._bucket || resolveSeverityBucket(data);
    if (!this.matchesFilterBucket(bucket)) return false;
    if (this.app.onlyPinnedFilter && !this.matchesPinnedIp(data)) return false;
    return this.matchesSearchQuery(data);
  }

  togglePinnedIpFilter() {
    if (!this.app.currentUser && !this.app.onlyPinnedFilter) {
      window.location.href = "login.html";
      return;
    }
    this.app.onlyPinnedFilter = !this.app.onlyPinnedFilter;
    const isActive = this.app.onlyPinnedFilter;

    if (this.app.btnFilterPinned) {
      this.app.btnFilterPinned.classList.toggle("active", isActive);
    }
    if (this.app.pinnedFilterBadge) {
      this.app.pinnedFilterBadge.textContent = isActive ? "ON" : "OFF";
    }
    if (this.app.btnHudFilterPinned) {
      this.app.btnHudFilterPinned.classList.toggle("active", isActive);
    }

    if (
      this.app.selectedAttack &&
      !this.matchesActiveFilters(this.app.selectedAttack)
    ) {
      this.app.selectedAttack = null;
      this.app.updateAttackDossier();
    }

    this.rebuildTickerFromBuffer();
  }

  toggleStreamPause() {
    this.app.isStreamPaused = !this.app.isStreamPaused;
    this.app.btnPauseStream.classList.toggle("paused", this.app.isStreamPaused);
    if (this.app.isStreamPaused) {
      this.app.pauseIcon.className = "fa-solid fa-play";
      this.app.pauseLabel.textContent = "RESUME";
      this.app.feedModeLabel.textContent = "STREAM PAUSED";
    } else {
      this.app.pauseIcon.className = "fa-solid fa-pause";
      this.app.pauseLabel.textContent = "PAUSE";
      this.app.authController.updateStreamLabels();
    }
  }

  appendTickerRowDOM(data) {
    const row = document.createElement("div");
    const bucket = data._bucket || resolveSeverityBucket(data);

    let sevClass = "sev-low";
    if (bucket === "HIGH") sevClass = "sev-high";
    else if (bucket === "MEDIUM") sevClass = "sev-med";

    const isSelected =
      this.app.selectedAttack && this.app.selectedAttack._id === data._id;
    row.className = `ticker-row ${sevClass}${isSelected ? " selected" : ""}`;
    row.dataset.attackId = data._id;

    const originCity =
      data.srcCity && data.srcCity !== "Unknown"
        ? data.srcCity
        : data.srcCountry;
    const destCity = data.dstCity ? data.dstCity : data.dstCountry;
    const attackTitle = data.malware || "UNKNOWN_THREAT";
    const cveDisplay = (data.cve || "CVE-N/A").replace(/^CVE:\s*/i, "");

    row.innerHTML = `
      <div class="ticker-title-row">
        <div class="ticker-title">${attackTitle}</div>
        <span class="ticker-lock-hint">${
          isSelected ? "LOCKED ON MAP" : "CLICK TO TRACE"
        }</span>
      </div>
      <div class="ticker-meta">
        <span>${cveDisplay}</span>
        <span class="meta-dot">•</span>
        <span>MITRE: ${data.mitre || "T1071"}</span>
        <span class="meta-dot">•</span>
        <span>PORT: ${data.port}/${data.proto}</span>
      </div>
      <div class="ticker-vector-row">
        <span>${originCity} (${data.srcCode.toUpperCase()})</span>
        <span class="vector-arrow">→</span>
        <span>${destCity} (${data.dstCode.toUpperCase()})</span>
      </div>
    `;

    const empty = this.app.attackTicker.querySelector(".ticker-empty");
    if (empty) empty.remove();

    this.app.attackTicker.insertBefore(row, this.app.attackTicker.firstChild);
    while (this.app.attackTicker.children.length > 20) {
      this.app.attackTicker.removeChild(this.app.attackTicker.lastChild);
    }
  }

  syncSelectedCardDOM() {
    const rows = this.app.attackTicker.querySelectorAll(".ticker-row");
    rows.forEach((r) => {
      const isSel =
        this.app.selectedAttack &&
        r.dataset.attackId === this.app.selectedAttack._id;
      r.classList.toggle("selected", Boolean(isSel));
      const hint = r.querySelector(".ticker-lock-hint");
      if (hint) {
        hint.textContent = isSel ? "LOCKED ON MAP" : "CLICK TO TRACE";
      }
    });
  }

  rebuildTickerFromBuffer() {
    if (this.app.onlyPinnedFilter) {
      const hasPins =
        this.app.customLocations && this.app.customLocations.length > 0;
      this.app.attackTicker.innerHTML = hasPins
        ? `<div class="ticker-empty">WAITING FOR THREAT INTEL AGAINST PINNED IPs...</div>`
        : `<div class="ticker-empty">NO PINNED IPs CONFIGURED YET.<br/>ADD AN IP IN SETTINGS TO MONITOR.</div>`;
    } else {
      this.app.attackTicker.innerHTML = `<div class="ticker-empty">NO MATCHING INTRUSIONS IN BUFFER...</div>`;
    }

    const filtered = this.app.rawAttackBuffer.filter((data) =>
      this.matchesActiveFilters(data)
    );

    for (const data of filtered.slice(0, 20).reverse()) {
      this.appendTickerRowDOM(data);
    }
  }

  getFilteredBufferForExport() {
    return this.app.rawAttackBuffer.filter((d) => this.matchesActiveFilters(d));
  }

  exportSessionData(format = "json") {
    const records = this.getFilteredBufferForExport();
    if (records.length === 0) return;

    const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    let blob;
    let filename;

    if (format === "csv") {
      const headers = [
        "timestamp",
        "id",
        "severity",
        "malware",
        "category",
        "src_ip",
        "src_country",
        "src_code",
        "src_city",
        "src_asn",
        "src_lat",
        "src_lon",
        "dst_country",
        "dst_code",
        "dst_city",
        "dst_lat",
        "dst_lon",
        "port",
        "proto",
        "cve",
        "mitre",
        "feed_mode",
      ];
      const escapeCsv = (val) => `"${String(val ?? "").replace(/"/g, '""')}"`;
      const rows = records.map((d) =>
        [
          d._timestamp || "",
          d._id || "",
          d._bucket || d.severity || "",
          d.malware || "",
          d.category || "",
          d.srcIp || "",
          d.srcCountry || "",
          d.srcCode || "",
          d.srcCity || "",
          d.srcAsn || "",
          d.srcLat ?? "",
          d.srcLon ?? "",
          d.dstCountry || "",
          d.dstCode || "",
          d.dstCity || "",
          d.dstLat ?? "",
          d.dstLon ?? "",
          d.port ?? "",
          d.proto || "TCP",
          (d.cve || "").replace(/^CVE:\s*/i, ""),
          d.mitre || "",
          d.feedMode || "live",
        ]
          .map(escapeCsv)
          .join(",")
      );

      const csvContent = [headers.join(","), ...rows].join("\n");
      blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
      filename = `soc_threat_capture_${stamp}.csv`;
    } else {
      const cleanJson = records.map((d) => ({
        timestamp: d._timestamp,
        id: d._id,
        severity: d._bucket || d.severity,
        malware: d.malware,
        category: d.category,
        src_ip: d.srcIp,
        src_country: d.srcCountry,
        src_code: d.srcCode,
        src_city: d.srcCity,
        src_asn: d.srcAsn,
        src_lat: d.srcLat,
        src_lon: d.srcLon,
        dst_country: d.dstCountry,
        dst_code: d.dstCode,
        dst_city: d.dstCity,
        dst_lat: d.dstLat,
        dst_lon: d.dstLon,
        port: d.port,
        proto: d.proto,
        cve: (d.cve || "").replace(/^CVE:\s*/i, ""),
        mitre: d.mitre,
        feed_mode: d.feedMode || "live",
      }));
      blob = new Blob([JSON.stringify(cleanJson, null, 2)], {
        type: "application/json",
      });
      filename = `soc_threat_capture_${stamp}.json`;
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  bindFilterEvents() {
    const filterBar = document.querySelector(".feed-filter-bar");
    if (filterBar) {
      filterBar.addEventListener("click", (e) => {
        const chip = e.target.closest(".filter-chip");
        if (!chip) return;

        filterBar
          .querySelectorAll(".filter-chip")
          .forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        this.app.currentSeverityFilter = chip.dataset.severity;

        if (
          this.app.selectedAttack &&
          !this.matchesActiveFilters(this.app.selectedAttack)
        ) {
          this.app.selectedAttack = null;
          this.app.updateAttackDossier();
        }

        this.rebuildTickerFromBuffer();
      });
    }

    // Stream Pause / Resume Button
    if (this.app.btnPauseStream) {
      this.app.btnPauseStream.addEventListener("click", () => {
        this.toggleStreamPause();
      });
    }

    // Pinned IPs Only Filter Toggle Buttons (Sidebar + Map Legend HUD)
    if (this.app.btnFilterPinned) {
      this.app.btnFilterPinned.addEventListener("click", () => {
        this.togglePinnedIpFilter();
      });
    }
    if (this.app.btnHudFilterPinned) {
      this.app.btnHudFilterPinned.addEventListener("click", () => {
        this.togglePinnedIpFilter();
      });
    }

    // Export Session JSON & CSV Buttons
    if (this.app.btnExportJson) {
      this.app.btnExportJson.addEventListener("click", () =>
        this.exportSessionData("json")
      );
    }
    if (this.app.btnExportCsv) {
      this.app.btnExportCsv.addEventListener("click", () =>
        this.exportSessionData("csv")
      );
    }

    // Live Search Input & Clear Button
    if (this.app.feedSearchInput) {
      this.app.feedSearchInput.addEventListener("input", (e) => {
        this.app.searchQuery = e.target.value.trim();
        if (this.app.btnClearSearch) {
          this.app.btnClearSearch.style.display = this.app.searchQuery
            ? "block"
            : "none";
        }
        if (
          this.app.selectedAttack &&
          !this.matchesActiveFilters(this.app.selectedAttack)
        ) {
          this.app.selectedAttack = null;
          this.app.updateAttackDossier();
        }
        this.rebuildTickerFromBuffer();
      });
    }

    if (this.app.btnClearSearch) {
      this.app.btnClearSearch.addEventListener("click", () => {
        this.app.searchQuery = "";
        this.app.feedSearchInput.value = "";
        this.app.btnClearSearch.style.display = "none";
        this.rebuildTickerFromBuffer();
      });
    }

    // Click on a feed card to lock/unlock its trajectory & open/close the Attack Dossier Card
    this.app.attackTicker.addEventListener("click", (e) => {
      const row = e.target.closest(".ticker-row");
      if (!row) return;
      const attackId = row.dataset.attackId;
      const found = this.app.rawAttackBuffer.find(
        (item) => item._id === attackId
      );
      if (!found) return;

      if (this.app.selectedAttack && this.app.selectedAttack._id === attackId) {
        this.app.selectedAttack = null;
      } else {
        this.app.selectedAttack = found;
      }
      this.syncSelectedCardDOM();
      this.app.updateAttackDossier();
    });
  }
}
