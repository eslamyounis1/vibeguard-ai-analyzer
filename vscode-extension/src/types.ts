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
  orchestratorApiUrl: string;
  minSeverity: Severity;
  runSandboxOnAnalyze: boolean;
  requestTimeoutMs: number;
  chatProvider: string;
  chatModel: string;
  chatRefine: boolean;
  chatMaxIterations: number;
}

export interface ChatMessage {
  role: string;
  content: string;
}

export interface ChatFinding {
  rule_id: string;
  line?: number | null;
  message: string;
  cwe?: string | null;
  owasp?: string | null;
  severity?: string;
}

export interface ChatResponse {
  ok: boolean;
  code: string;
  clean: boolean;
  findings: ChatFinding[];
  iterations: Array<{ attempt: number; findings_count: number; findings: ChatFinding[] }>;
  provider?: string;
  model?: string;
}

export interface FixResponse {
  ok: boolean;
  changed: boolean;
  safe: boolean;
  note?: string;
  findings_before: Finding[];
  findings_after: Finding[];
  applied: Array<{ rule_id: string; description: string; line?: number }>;
  fixed_code?: string;
}

export interface CompareResponse {
  ok: boolean;
  fix: { changed: boolean; safe: boolean; applied: unknown[] };
  security: { findings_before: Finding[]; findings_after: Finding[]; delta: number };
  performance: { cpu_before?: number; cpu_after?: number; energy_before?: number; energy_after?: number };
  behavior_preserved: boolean;
  delta_energy_joules?: number;
}

export interface AnalyzeProfileResponse {
  ok: boolean;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  static: AnalyzeResponse;
  dynamic: ProfileResponse;
  performance_corroboration: Array<{ rule_id: string; confirmed: boolean; measured_ms?: number }>;
}
