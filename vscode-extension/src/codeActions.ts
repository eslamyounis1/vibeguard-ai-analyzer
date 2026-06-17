import * as vscode from "vscode";

const VIBEGUARD_SOURCE = "vibeguard";

export class VibeGuardCodeActionProvider implements vscode.CodeActionProvider {
  static readonly providedCodeActionKinds = [vscode.CodeActionKind.QuickFix];

  provideCodeActions(
    _document: vscode.TextDocument,
    _range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.CodeAction[] {
    const vibeGuardDiags = context.diagnostics.filter((d) => d.source === VIBEGUARD_SOURCE);
    if (vibeGuardDiags.length === 0) {
      return [];
    }
    const action = new vscode.CodeAction(
      "Auto-Fix with VibeGuard",
      vscode.CodeActionKind.QuickFix,
    );
    action.command = {
      command: "vibeguard.fix",
      title: "Auto-Fix with VibeGuard",
    };
    action.diagnostics = vibeGuardDiags;
    action.isPreferred = true;
    return [action];
  }
}
