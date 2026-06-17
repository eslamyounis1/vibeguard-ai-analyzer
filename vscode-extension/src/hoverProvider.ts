import * as vscode from "vscode";
import type { VibeGuardDiagnostics } from "./diagnostics";

export class VibeGuardHoverProvider implements vscode.HoverProvider {
  constructor(private readonly _diagnostics: VibeGuardDiagnostics) {}

  provideHover(
    document: vscode.TextDocument,
    position: vscode.Position,
  ): vscode.Hover | undefined {
    const findings = this._diagnostics.getFindingsAt(document.uri, position.line + 1);
    if (findings.length === 0) {
      return undefined;
    }

    const md = new vscode.MarkdownString("", true);
    md.isTrusted = false;
    md.supportHtml = false;

    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      md.appendMarkdown(`**[${f.rule_id}] ${f.title}** — \`${f.severity}\`\n\n`);
      md.appendMarkdown(`${f.message}\n\n`);
      if (f.cwe) {
        md.appendMarkdown(`**CWE:** ${f.cwe}  \n`);
      }
      if (f.owasp) {
        md.appendMarkdown(`**OWASP:** ${f.owasp}  \n`);
      }
      if (f.impact) {
        md.appendMarkdown(`**Impact:** ${f.impact}  \n`);
      }
      if (f.suggestion) {
        md.appendMarkdown(`**Suggestion:** ${f.suggestion}  \n`);
      }
      if (f.risk_score != null) {
        md.appendMarkdown(`**Risk score:** ${f.risk_score}/100  \n`);
      }
      if (i < findings.length - 1) {
        md.appendMarkdown(`\n---\n\n`);
      }
    }

    return new vscode.Hover(md);
  }
}
