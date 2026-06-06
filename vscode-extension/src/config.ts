import * as vscode from "vscode";
import type { Severity, VibeGuardConfig } from "./types";

export function getConfig(): VibeGuardConfig {
  const cfg = vscode.workspace.getConfiguration("vibeguard");
  return {
    securityApiUrl: cfg.get<string>("securityApiUrl", "http://127.0.0.1:8000").replace(/\/$/, ""),
    sandboxApiUrl: cfg.get<string>("sandboxApiUrl", "http://127.0.0.1:8001").replace(/\/$/, ""),
    orchestratorApiUrl: cfg.get<string>("orchestratorApiUrl", "http://127.0.0.1:8002").replace(/\/$/, ""),
    minSeverity: cfg.get<Severity>("minSeverity", "LOW"),
    runSandboxOnAnalyze: cfg.get<boolean>("runSandboxOnAnalyze", true),
    requestTimeoutMs: cfg.get<number>("requestTimeoutMs", 120000),
    chatProvider: cfg.get<string>("chatProvider", "openai"),
    chatModel: cfg.get<string>("chatModel", "gpt-4o-mini"),
    chatRefine: cfg.get<boolean>("chatRefine", true),
    chatMaxIterations: cfg.get<number>("chatMaxIterations", 3),
  };
}
