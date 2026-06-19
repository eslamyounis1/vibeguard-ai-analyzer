(function () {
  const vscode = acquireVsCodeApi();

  const loadingEl = document.getElementById("loading");
  const appEl = document.getElementById("app");

  const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

  function esc(str) {
    return String(str ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderReport(data) {
    loadingEl.hidden = true;
    appEl.hidden = false;

    const ts = new Date().toLocaleTimeString();
    const totalFindings = data.findings.length;

    // ── Header ──────────────────────────────────────────────────────────────
    let html = `
      <header>
        <div class="header-left">
          <h1>VibeGuard Report</h1>
          <span class="file-badge">${esc(data.file)}</span>
          <span class="ts">${esc(ts)}</span>
        </div>
        <button id="export-btn" ${totalFindings === 0 ? "disabled" : ""}>
          Export JSON
        </button>
      </header>`;

    // ── Severity summary bar ─────────────────────────────────────────────────
    html += `<section class="summary-bar">`;
    for (const sev of SEV_ORDER) {
      const count = data.bySeverity[sev] ?? 0;
      if (count > 0) {
        html += `<span class="pill pill-${sev.toLowerCase()}">${count} ${esc(sev)}</span>`;
      }
    }
    if (totalFindings === 0) {
      html += `<span class="pill pill-clean">&#10003; No issues found</span>`;
    }
    if (data.riskScore !== undefined) {
      const score = Math.round(data.riskScore);
      const cls = score >= 70 ? "risk-high" : score >= 40 ? "risk-medium" : "risk-low";
      html += `<span class="risk-badge ${cls}">Risk score: ${score}/100</span>`;
    }
    html += `</section>`;

    // ── Performance totals ───────────────────────────────────────────────────
    if (data.dynamic) {
      const d = data.dynamic;
      html += `<section class="perf-section">
        <h2>Sandbox Profile</h2>
        <div class="perf-grid">`;
      if (d.wallTimeSec !== undefined) {
        html += `<div class="perf-card"><span class="perf-val">${d.wallTimeSec.toFixed(3)}s</span><span class="perf-lbl">Wall time</span></div>`;
      }
      if (d.cpuTimeSec !== undefined) {
        html += `<div class="perf-card"><span class="perf-val">${d.cpuTimeSec.toFixed(3)}s</span><span class="perf-lbl">CPU time</span></div>`;
      }
      if (d.peakMemoryKb !== undefined) {
        html += `<div class="perf-card"><span class="perf-val">${d.peakMemoryKb.toFixed(1)} KB</span><span class="perf-lbl">Peak memory</span></div>`;
      }
      if (d.energyJoules !== undefined) {
        html += `<div class="perf-card"><span class="perf-val">${d.energyJoules.toFixed(4)} J</span><span class="perf-lbl">Est. energy</span></div>`;
      }
      html += `</div></section>`;
    }

    // ── Findings list ────────────────────────────────────────────────────────
    if (data.findings.length === 0) {
      html += `<section class="findings-section"><p class="no-findings">No security issues detected in this file.</p></section>`;
    } else {
      html += `<section class="findings-section"><h2>Findings (${totalFindings})</h2>`;
      for (const f of data.findings) {
        const sevClass = `sev-${(f.severity ?? "info").toLowerCase()}`;
        html += `
          <div class="finding-card ${sevClass}">
            <div class="finding-header">
              <span class="finding-rule">${esc(f.rule_id)}</span>
              <span class="finding-title">${esc(f.title)}</span>
              <span class="severity-tag ${sevClass}">${esc(f.severity)}</span>
              <button class="jump-btn" data-line="${esc(f.line)}">Line ${esc(f.line)} ↗</button>
            </div>
            <p class="finding-msg">${esc(f.message)}</p>
            <div class="finding-meta">`;
        if (f.cwe) {
          html += `<span class="badge badge-cwe">${esc(f.cwe)}</span>`;
        }
        if (f.owasp) {
          html += `<span class="badge badge-owasp">${esc(f.owasp)}</span>`;
        }
        if (f.confidence) {
          html += `<span class="badge badge-conf">Confidence: ${esc(f.confidence)}</span>`;
        }
        if (f.risk_score != null) {
          html += `<span class="badge badge-risk">Risk: ${esc(f.risk_score)}/100</span>`;
        }
        html += `</div>`;
        if (f.suggestion) {
          html += `<p class="finding-suggestion">&#128161; ${esc(f.suggestion)}</p>`;
        }
        if (f.snippet) {
          html += `<pre class="finding-snippet"><code>${esc(f.snippet.trim())}</code></pre>`;
        }
        html += `</div>`;
      }
      html += `</section>`;
    }

    appEl.innerHTML = html;

    // ── Wire buttons ─────────────────────────────────────────────────────────
    document.getElementById("export-btn")?.addEventListener("click", () => {
      vscode.postMessage({ type: "exportJson", findings: data.findings });
    });

    appEl.querySelectorAll(".jump-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const line = parseInt(btn.getAttribute("data-line") ?? "1", 10);
        vscode.postMessage({ type: "jumpToLine", line });
      });
    });
  }

  // ── Message handler ───────────────────────────────────────────────────────
  window.addEventListener("message", (event) => {
    const msg = event.data;
    if (msg.type === "render") {
      renderReport(msg.data);
    }
  });

  vscode.postMessage({ type: "ready" });
})();
