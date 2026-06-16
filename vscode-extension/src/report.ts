import type { AnalyzeResponse, CompareResponse, FixResponse, ProfileResponse } from "./types";

export function formatAnalyzeSummary(result: AnalyzeResponse): string {
  const lines: string[] = ["=== VibeGuard Security Analysis ===", ""];

  if (result.parse_errors.length > 0) {
    lines.push("Parse errors:");
    for (const err of result.parse_errors) {
      lines.push(`  • ${err.message}`);
    }
    lines.push("");
  }

  if (result.findings.length === 0) {
    lines.push("No security issues found.");
  } else {
    for (const f of result.findings) {
      lines.push(`[${f.severity}] ${f.rule_id} ${f.title}`);
      lines.push(`  Line ${f.line}: ${f.message}`);
      const metadata = [f.cwe, f.owasp, f.confidence ? `Confidence: ${f.confidence}` : undefined, f.risk_score ? `Risk: ${f.risk_score}/100` : undefined]
        .filter(Boolean)
        .join(" | ");
      if (metadata) {
        lines.push(`  ${metadata}`);
      }
      if (f.impact) {
        lines.push(`  Impact: ${f.impact}`);
      }
      if (f.snippet) {
        lines.push(`  Code: ${f.snippet.trim()}`);
      }
      if (f.suggestion) {
        lines.push(`  Fix: ${f.suggestion}`);
      }
      lines.push("");
    }
  }

  const summary = result.summary;
  if (summary && typeof summary === "object") {
    const bySeverity =
      "by_severity" in summary && typeof summary.by_severity === "object"
        ? (summary.by_severity as Record<string, number>)
        : (summary as Record<string, number>);
    const parts = Object.entries(bySeverity)
      .filter(([, count]) => count > 0)
      .map(([sev, count]) => `${count} ${sev.toLowerCase()}`);
    if (parts.length > 0) {
      lines.push(`Summary: ${parts.join(", ")}`);
    }
    if ("risk" in summary && typeof summary.risk === "object" && summary.risk !== null) {
      const risk = summary.risk as Record<string, number>;
      lines.push(
        `Security score: ${risk.security_score}/100 | ` +
          `max risk=${risk.max_risk_score}/100 | avg risk=${risk.average_risk_score}/100`,
      );
    }
  }

  return lines.join("\n");
}

export function formatProfileReport(result: ProfileResponse): string {
  const lines: string[] = ["=== VibeGuard Sandbox Profile ===", ""];

  if (!result.ok) {
    lines.push(`Error: ${result.error_message ?? result.error_type ?? "Unknown error"}`);
    if (result.stderr) {
      lines.push("", "stderr:", result.stderr);
    }
    return lines.join("\n");
  }

  if (result.text_report) {
    lines.push(result.text_report);
    lines.push("");
  }

  if (result.totals) {
    lines.push("Totals:");
    const t = result.totals;
    if (t.cpu_time_seconds !== undefined) {
      lines.push(`  CPU time: ${t.cpu_time_seconds}s`);
    }
    if (t.wall_time_seconds !== undefined) {
      lines.push(`  Wall time: ${t.wall_time_seconds}s`);
    }
    if (t.peak_memory_bytes !== undefined) {
      lines.push(`  Peak memory: ${(t.peak_memory_bytes / 1024).toFixed(1)} KB`);
    }
    if (t.energy_joules_estimate !== undefined) {
      lines.push(`  Est. energy: ${t.energy_joules_estimate} J`);
    }
    lines.push("");
  }

  if (result.stdout?.trim()) {
    lines.push("stdout:", result.stdout.trim(), "");
  }

  if (result.stderr?.trim()) {
    lines.push("stderr:", result.stderr.trim(), "");
  }

  if (result.profile.length > 0) {
    lines.push("Per-function metrics:");
    for (const entry of result.profile.slice(0, 25)) {
      lines.push(
        `  ${entry.function}: calls=${entry.calls}, cpu=${entry.cpu_time_seconds}s, ` +
          `memΔ=${entry.memory_delta_bytes}B, energy≈${entry.energy_joules_estimate}J`,
      );
    }
    if (result.profile.length > 25) {
      lines.push(`  … and ${result.profile.length - 25} more`);
    }
  }

  return lines.join("\n");
}

export function formatFixReport(result: FixResponse): string {
  const lines: string[] = ["=== VibeGuard Auto-Fix Report ===", ""];

  if (!result.ok) {
    lines.push("Fix failed.");
    return lines.join("\n");
  }

  if (!result.changed) {
    lines.push("No deterministic fixes could be applied.");
    if (result.note) {
      lines.push(`Note: ${result.note}`);
    }
    return lines.join("\n");
  }

  lines.push(`Applied ${result.applied.length} fix(es):`, "");
  for (const fix of result.applied) {
    const location = fix.line !== undefined ? ` (line ${fix.line})` : "";
    lines.push(`  • [${fix.rule_id}]${location}: ${fix.description}`);
  }
  lines.push("");

  const beforeCount = result.findings_before.length;
  const afterCount = result.findings_after.length;
  const delta = beforeCount - afterCount;
  lines.push(`Security findings: ${beforeCount} → ${afterCount} (${delta >= 0 ? "-" + String(delta) : "+" + String(Math.abs(delta))})`);
  lines.push(`Safe to apply: ${result.safe ? "yes" : "no — manual review required"}`);

  if (result.note) {
    lines.push(`Note: ${result.note}`);
  }

  return lines.join("\n");
}

export function formatCompareReport(result: CompareResponse): string {
  const lines: string[] = ["=== VibeGuard Compare Report ===", ""];

  if (!result.ok) {
    lines.push("Comparison failed.");
    return lines.join("\n");
  }

  const sec = result.security;
  const beforeCount = sec.findings_before.length;
  const afterCount = sec.findings_after.length;
  lines.push("Security:");
  lines.push(`  Findings before: ${beforeCount}`);
  lines.push(`  Findings after:  ${afterCount}`);
  lines.push(`  Delta:           ${sec.delta >= 0 ? "-" + String(sec.delta) : "+" + String(Math.abs(sec.delta))}`);
  lines.push("");

  const perf = result.performance;
  if (perf && (perf.cpu_before !== undefined || perf.energy_before !== undefined)) {
    lines.push("Performance:");
    if (perf.cpu_before !== undefined && perf.cpu_after !== undefined) {
      lines.push(`  CPU time: ${perf.cpu_before}s → ${perf.cpu_after}s`);
    }
    if (perf.energy_before !== undefined && perf.energy_after !== undefined) {
      lines.push(`  Energy: ${perf.energy_before}J → ${perf.energy_after}J`);
    }
    lines.push("");
  }

  if (result.delta_energy_joules !== undefined) {
    lines.push(`Energy saved: ${result.delta_energy_joules.toFixed(4)} J`);
  }

  lines.push(`Behavior preserved: ${result.behavior_preserved ? "yes" : "no — verify manually"}`);
  lines.push(`Fixes applied: ${result.fix.applied.length}`);

  return lines.join("\n");
}
