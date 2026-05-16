import type { AnalyzeResponse, ProfileResponse } from "./types";

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
      if (f.snippet) {
        lines.push(`  Code: ${f.snippet.trim()}`);
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
