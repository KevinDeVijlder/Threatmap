/**
 * Dual Top 10 Leaderboards & Telemetry Persistence Controller
 * ===========================================================
 * Tracks outbound attacker country rankings, inbound targeted country rankings,
 * and dominant per-country threat signatures, persisting totals in localStorage.
 */

export class LeaderboardController {
  constructor(app) {
    this.app = app;
  }

  recordCountryDetail(code, data) {
    if (!code) return;
    const key = code.toLowerCase();
    if (!this.app.countryDetails.has(key)) {
      this.app.countryDetails.set(key, {
        malwareCounts: new Map(),
        portCounts: new Map(),
        lastMitre: data.mitre || "T1071.001",
        lastAsn: data.srcAsn || "AS_EDGE",
      });
    }
    const entry = this.app.countryDetails.get(key);
    const mw = data.malware || "C2_BEACON";
    const pt = `${data.port || 443}/${data.proto || "TCP"}`;
    entry.malwareCounts.set(mw, (entry.malwareCounts.get(mw) || 0) + 1);
    entry.portCounts.set(pt, (entry.portCounts.get(pt) || 0) + 1);
    if (data.mitre) entry.lastMitre = data.mitre;
    if (data.srcAsn && data.srcAsn !== "AS_EDGE") entry.lastAsn = data.srcAsn;
  }

  recordStats(srcCode, srcName, dstCode, dstName) {
    if (srcCode) {
      if (!this.app.countryStats.has(srcCode)) {
        this.app.countryStats.set(srcCode, {
          code: srcCode,
          name: srcName,
          count: 0,
        });
      }
      this.app.countryStats.get(srcCode).count++;
      localStorage.setItem(
        "soc_country_stats",
        JSON.stringify(Array.from(this.app.countryStats.entries()))
      );
    }

    if (dstCode) {
      if (!this.app.targetStats.has(dstCode)) {
        this.app.targetStats.set(dstCode, {
          code: dstCode,
          name: dstName,
          count: 0,
        });
      }
      this.app.targetStats.get(dstCode).count++;
      localStorage.setItem(
        "soc_target_stats",
        JSON.stringify(Array.from(this.app.targetStats.entries()))
      );
    }

    this.app.hudActiveOrigins.textContent = `${this.app.countryStats.size} REGIONS`;
    this.updateLeaderboards();
  }

  renderLeaderboardHTML(statsMap) {
    const sorted = Array.from(statsMap.values())
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const maxHits = sorted.length > 0 ? sorted[0].count : 1;

    return sorted
      .map((item, index) => {
        const pct = Math.round((item.count / maxHits) * 100);
        return `
        <div class="leaderboard-row">
          <div class="leaderboard-main">
            <div class="leaderboard-left">
              <span class="leaderboard-rank">#${index + 1}</span>
              <img class="leaderboard-flag" src="https://flagcdn.com/w40/${item.code.toLowerCase()}.png" alt="${item.name}" />
              <span class="leaderboard-name">${item.name}</span>
            </div>
            <span class="leaderboard-hits">${item.count}</span>
          </div>
          <div class="leaderboard-bar-track">
            <div class="leaderboard-bar-fill" style="width: ${pct}%"></div>
          </div>
        </div>
      `;
      })
      .join("");
  }

  updateLeaderboards() {
    const hitsLabel = `${this.app.totalAttacksCount.toLocaleString()} HITS`;
    this.app.leaderboardTotalHits.textContent = hitsLabel;
    this.app.targetTotalHits.textContent = hitsLabel;

    this.app.leaderboardList.innerHTML = this.renderLeaderboardHTML(
      this.app.countryStats
    );
    this.app.targetLeaderboardList.innerHTML = this.renderLeaderboardHTML(
      this.app.targetStats
    );
  }
}
