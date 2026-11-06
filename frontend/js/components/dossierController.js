/**
 * Country & Attack Intelligence Dossiers + Hover HUD Controller
 * =============================================================
 * Manages the Gold Country Intelligence Dossier card, Detailed Attack
 * Telemetry Dossier card, external OSINT pivot links (VirusTotal, AbuseIPDB,
 * Shodan, NIST NVD, MITRE ATT&CK), one-click IOC copy, and hover cursor tooltip.
 */

import { getCountryMeta } from "../data/countries.js";
import {
  calculateDistanceKm,
  getTopKey,
  resolveSeverityBucket,
} from "../utils/helpers.js";

export class DossierController {
  constructor(app) {
    this.app = app;
  }

  updateHoverIntel(countryIndex, clientX, clientY) {
    if (
      !countryIndex ||
      countryIndex <= 0 ||
      countryIndex > this.app.countryFeatures.length
    ) {
      this.app.cursorTooltip.style.display = "none";
      this.app.countryIntelBar.classList.remove("active");
      this.app.countryIntelBar.classList.add("idle");
      this.app.countryNameEl.textContent = "STANDBY";
      this.app.countryCodeEl.textContent = "ISO";
      this.app.countryFlagEl.style.display = "none";
      this.app.flagPlaceholderEl.style.display = "block";
      return;
    }

    const feature = this.app.countryFeatures[countryIndex - 1];
    const meta = getCountryMeta(feature);

    this.app.countryIntelBar.classList.add("active");
    this.app.countryIntelBar.classList.remove("idle");

    if (meta && meta.code) {
      const flagUrl = `https://flagcdn.com/w80/${meta.code.toLowerCase()}.png`;

      this.app.cursorTooltipFlag.style.display = "block";
      this.app.cursorTooltipFlag.src = flagUrl;
      this.app.cursorTooltipName.textContent = meta.name.toUpperCase();
      this.app.cursorTooltip.style.left = `${clientX}px`;
      this.app.cursorTooltip.style.top = `${clientY}px`;
      this.app.cursorTooltip.style.display = "flex";

      this.app.countryNameEl.textContent = meta.name.toUpperCase();
      this.app.countryCodeEl.textContent = `ISO: ${meta.code.toUpperCase()} // ID: ${meta.idLabel}`;
      this.app.countryFlagEl.src = flagUrl;
      this.app.countryFlagEl.onload = () => {
        this.app.countryFlagEl.style.display = "block";
        this.app.flagPlaceholderEl.style.display = "none";
      };
    } else if (meta) {
      this.app.cursorTooltipFlag.style.display = "none";
      this.app.cursorTooltipName.textContent = meta.name.toUpperCase();
      this.app.cursorTooltip.style.left = `${clientX}px`;
      this.app.cursorTooltip.style.top = `${clientY}px`;
      this.app.cursorTooltip.style.display = "flex";

      this.app.countryNameEl.textContent = meta.name.toUpperCase();
      this.app.countryCodeEl.textContent = `ID: ${meta.idLabel}`;
      this.app.countryFlagEl.style.display = "none";
      this.app.flagPlaceholderEl.style.display = "block";
    }
  }

  updateCountryDossier() {
    if (
      !this.app.selectedCountryIndex ||
      this.app.selectedCountryIndex <= 0 ||
      this.app.selectedCountryIndex > this.app.countryFeatures.length
    ) {
      this.app.countryDossierCard.style.display = "none";
      return;
    }

    const feature =
      this.app.countryFeatures[this.app.selectedCountryIndex - 1];
    const meta = getCountryMeta(feature) || {
      name: "Unknown Sector",
      code: "un",
      idLabel: "--",
    };
    const code = (meta.code || "un").toLowerCase();

    const sortedOut = Array.from(this.app.countryStats.values()).sort(
      (a, b) => b.count - a.count
    );
    const outIdx = sortedOut.findIndex(
      (item) => item.code.toLowerCase() === code
    );
    const outHits = outIdx !== -1 ? sortedOut[outIdx].count : 0;
    const outRankStr =
      outIdx !== -1 ? `RANK: #${outIdx + 1} GLOBAL` : "RANK: UNRANKED";

    const sortedIn = Array.from(this.app.targetStats.values()).sort(
      (a, b) => b.count - a.count
    );
    const inIdx = sortedIn.findIndex(
      (item) => item.code.toLowerCase() === code
    );
    const inHits = inIdx !== -1 ? sortedIn[inIdx].count : 0;
    const inRankStr =
      inIdx !== -1 ? `RANK: #${inIdx + 1} TARGET` : "RANK: UNRANKED";

    const totalCountryHits = outHits + inHits;
    const globalShare =
      this.app.totalAttacksCount > 0
        ? (
            (totalCountryHits / (this.app.totalAttacksCount * 2)) *
            100
          ).toFixed(1)
        : "0.0";

    let threatLevel = "LOW ACTIVITY";
    if (outIdx >= 0 && outIdx < 3) threatLevel = "CRITICAL ORIGIN";
    else if (inIdx >= 0 && inIdx < 3) threatLevel = "PRIMARY TARGET";
    else if (totalCountryHits > 25) threatLevel = "ELEVATED";
    else if (totalCountryHits > 0) threatLevel = "ACTIVE NODE";

    const details = this.app.countryDetails.get(code);
    const topMalware = details
      ? getTopKey(details.malwareCounts, "SSL_C2_BEACON")
      : totalCountryHits > 0
      ? "SSL_C2_BEACON"
      : "NO SIGNATURES";
    const topPort = details
      ? getTopKey(details.portCounts, "443/TCP")
      : totalCountryHits > 0
      ? "443/TCP"
      : "--/TCP";
    const topMitre = details
      ? details.lastMitre
      : totalCountryHits > 0
      ? "T1071.001"
      : "N/A";
    const topAsn = details
      ? details.lastAsn
      : totalCountryHits > 0
      ? "AS_TRANSIT"
      : "N/A";

    this.app.dossierHeaderTag.textContent = `SECTOR INTELLIGENCE // ${code.toUpperCase()}`;
    if (meta.code) {
      this.app.dossierFlag.src = `https://flagcdn.com/w80/${code}.png`;
      this.app.dossierFlag.style.display = "block";
    } else {
      this.app.dossierFlag.style.display = "none";
    }
    this.app.dossierCountryName.textContent = meta.name.toUpperCase();
    this.app.dossierIsoSub.textContent = `ISO: ${code.toUpperCase()} // TRAFFIC SHARE: ${globalShare}%`;
    this.app.dossierThreatBadge.textContent = threatLevel;

    this.app.dossierOutboundVal.textContent = outHits.toLocaleString();
    this.app.dossierOutboundRank.textContent = outRankStr;
    this.app.dossierInboundVal.textContent = inHits.toLocaleString();
    this.app.dossierInboundRank.textContent = inRankStr;

    this.app.dossierTopMalware.textContent = topMalware;
    this.app.dossierTopMitre.textContent = `MITRE: ${topMitre}`;
    this.app.dossierTopPort.textContent = topPort;
    this.app.dossierTopAsn.textContent = `ASN: ${topAsn}`;

    const outPct =
      totalCountryHits > 0
        ? Math.round((outHits / totalCountryHits) * 100)
        : 50;
    const inPct = totalCountryHits > 0 ? 100 - outPct : 50;
    this.app.dossierRatioOutLbl.textContent = `OUTBOUND: ${outPct}%`;
    this.app.dossierRatioInLbl.textContent = `INBOUND: ${inPct}%`;
    this.app.dossierRatioFill.style.width = `${outPct}%`;

    this.app.countryDossierCard.style.display = "flex";
  }

  updateAttackDossier() {
    if (!this.app.attackDossierCard) return;

    if (!this.app.selectedAttack) {
      this.app.attackDossierCard.style.display = "none";
      return;
    }

    const d = this.app.selectedAttack;
    const bucket = d._bucket || resolveSeverityBucket(d);

    this.app.attackDossierCard.classList.remove(
      "sev-high",
      "sev-med",
      "sev-low"
    );
    if (bucket === "HIGH") this.app.attackDossierCard.classList.add("sev-high");
    else if (bucket === "MEDIUM")
      this.app.attackDossierCard.classList.add("sev-med");
    else this.app.attackDossierCard.classList.add("sev-low");

    const srcCode = (d.srcCode || "un").toLowerCase();
    const dstCode = (d.dstCode || "un").toLowerCase();
    const srcCity =
      d.srcCity && d.srcCity !== "Unknown" ? d.srcCity : d.srcCountry;
    const dstCity = d.dstCity || d.dstCountry;
    const distKm = calculateDistanceKm(
      d.srcLat,
      d.srcLon,
      d.dstLat,
      d.dstLon
    );
    const cveClean = (d.cve || "CVE-N/A").replace(/^CVE:\s*/i, "").trim();
    const mitreClean = (d.mitre || "T1071").trim();
    const ipClean = d.srcIp && d.srcIp !== "N/A" ? d.srcIp.trim() : "";

    this.app.atkDossierHeaderTag.textContent = `INTRUSION TELEMETRY // ID #${d._id.toUpperCase()}`;
    this.app.atkDossierMalware.textContent = d.malware || "UNKNOWN_THREAT";
    this.app.atkDossierCategory.textContent = `${
      d.category || "C2_EVENT"
    } // ${(d.feedMode || "LIVE").toUpperCase()} FEED`;
    this.app.atkDossierSevBadge.textContent = `${bucket} (${(
      d.severity || bucket
    ).toUpperCase()})`;

    this.app.atkDossierSrcIp.textContent = ipClean
      ? `IP: ${ipClean}`
      : `ASN: ${d.srcAsn || "AS_EDGE"}`;
    this.app.atkDossierSrcFlag.src = `https://flagcdn.com/w40/${srcCode}.png`;
    this.app.atkDossierSrcLoc.textContent = `${srcCity}, ${
      d.srcCountry
    } (${srcCode.toUpperCase()})`;
    this.app.atkDossierSrcCoords.textContent = `LAT: ${Number(d.srcLat).toFixed(
      4
    )}° | LON: ${Number(d.srcLon).toFixed(4)}°`;

    this.app.atkDossierDistance.textContent = `VECTOR DISTANCE: ${distKm.toLocaleString()} KM`;

    const dstIpClean = d.dstIp && d.dstIp !== "N/A" ? d.dstIp.trim() : "";
    this.app.atkDossierDstPort.textContent = dstIpClean
      ? `IP: ${dstIpClean} // PORT: ${d.port || 443}/${d.proto || "TCP"}`
      : `PORT: ${d.port || 443} / ${d.proto || "TCP"}`;
    this.app.atkDossierDstFlag.src = `https://flagcdn.com/w40/${dstCode}.png`;
    this.app.atkDossierDstLoc.textContent = `${dstCity}, ${
      d.dstCountry
    } (${dstCode.toUpperCase()})`;
    this.app.atkDossierDstCoords.textContent = `LAT: ${Number(d.dstLat).toFixed(
      4
    )}° | LON: ${Number(d.dstLon).toFixed(4)}°`;

    // Clickable NIST NVD Link for CVE
    const cveSpan = this.app.atkDossierCve.querySelector("span");
    if (cveSpan) cveSpan.textContent = cveClean;
    this.app.atkDossierCve.href = /^CVE-\d{4}-\d+/i.test(cveClean)
      ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveClean)}`
      : `https://nvd.nist.gov/vuln/search/results?query=${encodeURIComponent(
          d.malware || ""
        )}`;

    // Clickable MITRE ATT&CK Link (converts T1071.001 -> T1071/001)
    const mitreSpan = this.app.atkDossierMitre.querySelector("span");
    if (mitreSpan) mitreSpan.textContent = mitreClean;
    const mitrePath = mitreClean.replace(".", "/");
    this.app.atkDossierMitre.href = `https://attack.mitre.org/techniques/${mitrePath}/`;

    this.app.atkDossierAsn.textContent = d.srcAsn || "AS_EDGE";
    this.app.atkDossierTime.textContent = d._timestamp || "LIVE";

    // External Threat Intel Pivot Links (VirusTotal, AbuseIPDB, Shodan)
    const queryTarget = ipClean || d.srcCountry || "";
    this.app.atkPivotVt.href = ipClean
      ? `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(
          ipClean
        )}`
      : `https://www.virustotal.com/gui/search/${encodeURIComponent(
          queryTarget
        )}`;
    this.app.atkPivotAbuse.href = ipClean
      ? `https://www.abuseipdb.com/check/${encodeURIComponent(ipClean)}`
      : `https://www.abuseipdb.com/`;
    this.app.atkPivotShodan.href = ipClean
      ? `https://www.shodan.io/host/${encodeURIComponent(ipClean)}`
      : `https://www.shodan.io/search?query=${encodeURIComponent(queryTarget)}`;

    this.app.attackDossierCard.style.display = "flex";
  }

  async copySelectedIoc() {
    if (!this.app.selectedAttack) return;
    const d = this.app.selectedAttack;
    const srcCity =
      d.srcCity && d.srcCity !== "Unknown" ? d.srcCity : d.srcCountry;
    const dstCity = d.dstCity || d.dstCountry;
    const cveClean = (d.cve || "CVE-N/A").replace(/^CVE:\s*/i, "");

    const iocString = [
      `[SOC_THREAT_MATRIX_IOC]`,
      `Timestamp: ${d._timestamp || "LIVE"}`,
      `Threat: ${d.malware || "UNKNOWN"} (${d.category || "EVENT"})`,
      `Severity: ${d._bucket || d.severity}`,
      `Source_IP: ${d.srcIp || "N/A"}`,
      `ASN: ${d.srcAsn || "N/A"}`,
      `Origin: ${srcCity}, ${d.srcCountry} (${(d.srcCode || "").toUpperCase()})`,
      `Target: ${dstCity}, ${d.dstCountry} (${(d.dstCode || "").toUpperCase()})`,
      `Vector: ${d.port || 443}/${d.proto || "TCP"}`,
      `CVE: ${cveClean}`,
      `MITRE: ${d.mitre || "N/A"}`,
    ].join(" | ");

    try {
      await navigator.clipboard.writeText(iocString);
      this.app.btnCopyIoc.classList.add("copied");
      this.app.copyIocLabel.textContent = "COPIED!";
      setTimeout(() => {
        this.app.btnCopyIoc.classList.remove("copied");
        this.app.copyIocLabel.textContent = "COPY IOC";
      }, 1600);
    } catch (err) {
      console.error("Clipboard copy failed:", err);
    }
  }

  bindDossierEvents() {
    // Close Gold Country Dossier Button
    if (this.app.btnCloseDossier) {
      this.app.btnCloseDossier.addEventListener("click", () => {
        this.app.selectedCountryIndex = null;
        this.updateCountryDossier();
      });
    }

    // Close button on the Attack Dossier Card
    if (this.app.btnCloseAttackDossier) {
      this.app.btnCloseAttackDossier.addEventListener("click", () => {
        this.app.selectedAttack = null;
        this.app.syncSelectedCardDOM();
        this.updateAttackDossier();
      });
    }

    // Copy IOC Button inside Attack Dossier Card
    if (this.app.btnCopyIoc) {
      this.app.btnCopyIoc.addEventListener("click", () => {
        this.copySelectedIoc();
      });
    }
  }
}
