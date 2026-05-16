import * as vscode from "vscode";
import type { AnalyzeResponse, Finding, Severity } from "./types";

const DIAGNOSTIC_SOURCE = "vibeguard";

const SEVERITY_MAP: Record<Severity, vscode.DiagnosticSeverity> = {
  INFO: vscode.DiagnosticSeverity.Information,
  LOW: vscode.DiagnosticSeverity.Hint,
  MEDIUM: vscode.DiagnosticSeverity.Warning,
  HIGH: vscode.DiagnosticSeverity.Error,
  CRITICAL: vscode.DiagnosticSeverity.Error,
};

export class VibeGuardDiagnostics {
  private readonly collection: vscode.DiagnosticCollection;

  constructor() {
    this.collection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);
  }

  dispose(): void {
    this.collection.dispose();
  }

  clear(uri: vscode.Uri): void {
    this.collection.delete(uri);
  }

  setFromAnalyze(uri: vscode.Uri, document: vscode.TextDocument, result: AnalyzeResponse): void {
    const diagnostics: vscode.Diagnostic[] = [];

    for (const err of result.parse_errors) {
      diagnostics.push(
        new vscode.Diagnostic(
          new vscode.Range(0, 0, 0, 0),
          err.message,
          vscode.DiagnosticSeverity.Error,
        ),
      );
    }

    for (const finding of result.findings) {
      diagnostics.push(findingToDiagnostic(finding, document));
    }

    this.collection.set(uri, diagnostics);
  }
}

function findingToDiagnostic(finding: Finding, document: vscode.TextDocument): vscode.Diagnostic {
  const line = Math.max(0, (finding.line ?? 1) - 1);
  const lineText = document.lineAt(Math.min(line, document.lineCount - 1)).text;
  const range = new vscode.Range(line, 0, line, Math.max(lineText.length, 1));

  const diagnostic = new vscode.Diagnostic(
    range,
    formatDiagnosticMessage(finding),
    SEVERITY_MAP[finding.severity] ?? vscode.DiagnosticSeverity.Warning,
  );
  diagnostic.source = DIAGNOSTIC_SOURCE;
  diagnostic.code = finding.rule_id;
  diagnostic.relatedInformation = [];

  if (finding.snippet) {
    diagnostic.relatedInformation.push(
      new vscode.DiagnosticRelatedInformation(
        new vscode.Location(document.uri, range),
        finding.snippet.trim(),
      ),
    );
  }

  return diagnostic;
}

function formatDiagnosticMessage(finding: Finding): string {
  const parts = [`[${finding.rule_id}] ${finding.message}`];
  if (finding.cwe) {
    parts.push(finding.cwe);
  }
  if (finding.confidence) {
    parts.push(`confidence=${finding.confidence.toLowerCase()}`);
  }
  if (finding.risk_score !== undefined && finding.risk_score !== null) {
    parts.push(`risk=${finding.risk_score}/100`);
  }
  return parts.join(" | ");
}
