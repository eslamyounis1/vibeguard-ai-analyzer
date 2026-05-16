export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface Finding {
  rule_id: string;
  title: string;
  message: string;
  severity: Severity;
  file: string;
  line: number;
  category?: string;
  snippet?: string | null;
  confidence?: "LOW" | "MEDIUM" | "HIGH" | null;
  risk_score?: number | null;
  cwe?: string | null;
  owasp?: string | null;
  impact?: string | null;
  suggestion?: string | null;
}

export interface ParseError {
  file: string;
  message: string;
}

export interface AnalyzeResponse {
  ok: boolean;
  error_type?: string | null;
  error_message?: string | null;
  scanned_files: number;
  findings: Finding[];
  parse_errors: ParseError[];
  summary: Record<string, number | Record<string, number>>;
}

export interface ProfileEntry {
  function: string;
  calls: number;
  cpu_time_seconds: number;
  wall_time_seconds: number;
  memory_delta_bytes: number;
  energy_joules_estimate: number;
}

export interface ProfileTotals {
  cpu_time_seconds?: number;
  wall_time_seconds?: number;
  peak_memory_bytes?: number;
  energy_joules_estimate?: number;
}

export interface ProfileResponse {
  ok: boolean;
  error_type?: string | null;
  error_message?: string | null;
  profile: ProfileEntry[];
  stdout?: string | null;
  stderr?: string | null;
  text_report?: string | null;
  totals?: ProfileTotals | null;
}

export interface VibeGuardConfig {
  securityApiUrl: string;
  sandboxApiUrl: string;
  minSeverity: Severity;
  runSandboxOnAnalyze: boolean;
  requestTimeoutMs: number;
}
