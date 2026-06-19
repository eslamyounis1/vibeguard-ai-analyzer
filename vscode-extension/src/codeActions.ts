import * as vscode from "vscode";
import type { VibeGuardDiagnostics } from "./diagnostics";

const VIBEGUARD_SOURCE = "vibeguard";

export class VibeGuardCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix,
    vscode.CodeActionKind.Empty,
  ];

  constructor(private readonly _diagnostics: VibeGuardDiagnostics) {}

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const vibeGuardDiags = context.diagnostics.filter((d) => d.source === VIBEGUARD_SOURCE);
    if (vibeGuardDiags.length === 0) {
      return [];
    }

    const actions: vscode.CodeAction[] = [];

    const fixAction = new vscode.CodeAction(
      "Auto-Fix with VibeGuard",
      vscode.CodeActionKind.QuickFix,
    );
    fixAction.command = { command: "vibeguard.fix", title: "Auto-Fix with VibeGuard" };
    fixAction.diagnostics = vibeGuardDiags;
    fixAction.isPreferred = true;
    actions.push(fixAction);

    const findings = this._diagnostics.getFindingsAt(document.uri, range.start.line + 1);
    for (const finding of findings) {
      const explainAction = new vscode.CodeAction(
        `Explain "${finding.rule_id}" in VibeGuard Chat`,
        vscode.CodeActionKind.Empty,
      );
      explainAction.command = {
        command: "vibeguard.explainFinding",
        title: "Explain in Chat",
        arguments: [finding],
      };
      actions.push(explainAction);

      // Suppress this rule on this line via an inline comment
      const suppressAction = new vscode.CodeAction(
        `Suppress [${finding.rule_id}] on this line`,
        vscode.CodeActionKind.QuickFix,
      );
      const line = Math.max(0, (finding.line ?? 1) - 1);
      const lineText = document.lineAt(line).text;
      const lineEnd = new vscode.Position(line, lineText.length);
      suppressAction.edit = new vscode.WorkspaceEdit();
      suppressAction.edit.insert(
        document.uri,
        lineEnd,
        `  # vibeguard: ignore[${finding.rule_id}]`,
      );
      actions.push(suppressAction);
    }

    return actions;
  }
}
