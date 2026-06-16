import * as vscode from "vscode";
import { analyzeCode, analyzeProfile, ApiError, checkHealth, compareCode, fixCode, profileCode } from "./client";
import { VibeGuardCodeActionProvider } from "./codeActions";
import { ChatPanel } from "./chatPanel";
import { ChatViewProvider } from "./chatViewProvider";
import { getConfig } from "./config";
import { VibeGuardDiagnostics } from "./diagnostics";
import { VibeGuardHoverProvider } from "./hoverProvider";
import { formatAnalyzeSummary, formatCompareReport, formatFixReport, formatProfileReport } from "./report";
import type { Finding } from "./types";

const OUTPUT_CHANNEL = "VibeGuard";

function getActivePythonEditor(): vscode.TextEditor | undefined {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage("Open a Python file to analyze.");
    return undefined;
  }
  if (editor.document.languageId !== "python") {
    vscode.window.showWarningMessage("VibeGuard currently supports Python only.");
    return undefined;
  }
  return editor;
}

function getCodeFromEditor(editor: vscode.TextEditor, selectionOnly: boolean): string | undefined {
  const doc = editor.document;
  if (selectionOnly && !editor.selection.isEmpty) {
    return doc.getText(editor.selection);
  }
  const code = doc.getText();
  if (!code.trim()) {
    vscode.window.showWarningMessage("Nothing to analyze — the editor is empty.");
    return undefined;
  }
  return code;
}

export function activate(context: vscode.ExtensionContext): void {
  const output = vscode.window.createOutputChannel(OUTPUT_CHANNEL);
  const diagnostics = new VibeGuardDiagnostics();
  const chatViewProvider = new ChatViewProvider(context.extensionUri);

  // Status bar: chat shortcut (right side, priority 90)
  const chatStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 90);
  chatStatusBar.text = "$(comment-discussion) VibeGuard Chat";
  chatStatusBar.command = "vibeguard.openChat";
  chatStatusBar.tooltip = "Open VibeGuard Secure Code Chat (sidebar)";
  chatStatusBar.show();

  // Status bar: scan result counter (right side, priority 85 — appears left of chat button)
  const scanStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 85);
  scanStatusBar.command = "vibeguard.analyze";
  scanStatusBar.tooltip = "VibeGuard: click to re-analyze";

  function updateScanStatusBar(findings: Finding[]): void {
    const errors = findings.filter((f) => f.severity === "HIGH" || f.severity === "CRITICAL").length;
    const warnings = findings.filter((f) => f.severity === "MEDIUM").length;
    const hints = findings.filter((f) => f.severity === "LOW" || f.severity === "INFO").length;
    if (findings.length === 0) {
      scanStatusBar.text = "$(pass) VG";
      scanStatusBar.tooltip = "VibeGuard: no issues found — click to re-analyze";
      scanStatusBar.backgroundColor = undefined;
    } else {
      const parts: string[] = [];
      if (errors > 0) {
        parts.push(`$(error) ${errors}`);
      }
      if (warnings > 0) {
        parts.push(`$(warning) ${warnings}`);
      }
      if (hints > 0) {
        parts.push(`$(info) ${hints}`);
      }
      scanStatusBar.text = parts.join("  ");
      scanStatusBar.tooltip = `VibeGuard: ${findings.length} issue(s) — click to re-analyze`;
      scanStatusBar.backgroundColor =
        errors > 0
          ? new vscode.ThemeColor("statusBarItem.errorBackground")
          : new vscode.ThemeColor("statusBarItem.warningBackground");
    }
    scanStatusBar.show();
  }

  async function runAnalyze(options: { securityOnly: boolean; selectionOnly: boolean }) {
    const editor = getActivePythonEditor();
    if (!editor) {
      return;
    }

    const code = getCodeFromEditor(editor, options.selectionOnly);
    if (!code) {
      return;
    }

    const config = getConfig();
    const uri = editor.document.uri;

    await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: "VibeGuard",
        cancellable: false,
      },
      async (progress) => {
        try {
          if (!options.securityOnly && config.runSandboxOnAnalyze) {
            progress.report({ message: "Running security + sandbox analysis…" });
            const combined = await analyzeProfile(config, code);
            diagnostics.setFromAnalyze(uri, editor.document, combined.static);
            updateScanStatusBar(combined.static.findings);
            output.clear();
            output.appendLine(formatAnalyzeSummary(combined.static));
            output.appendLine("");
            output.appendLine(formatProfileReport(combined.dynamic));
            if (combined.performance_corroboration.length > 0) {
              output.appendLine("");
              output.appendLine("=== Performance Corroboration ===");
              for (const c of combined.performance_corroboration) {
                const status = c.confirmed ? "CONFIRMED" : "not observed";
                const timing = c.measured_ms !== undefined ? ` (${c.measured_ms}ms)` : "";
                output.appendLine(`  [${c.rule_id}] ${status}${timing}`);
              }
            }
            output.show(true);
            const issueCount = combined.static.findings.length;
            if (combined.static.parse_errors.length > 0) {
              vscode.window.showWarningMessage("VibeGuard: parse error — see Problems panel.");
            } else if (issueCount === 0) {
              vscode.window.showInformationMessage("VibeGuard: no security issues found.");
            } else {
              vscode.window.showWarningMessage(
                `VibeGuard: ${issueCount} issue(s) found — see Problems panel.`,
              );
            }
          } else {
            progress.report({ message: "Running security analysis…" });
            const analyzeResult = await analyzeCode(config, code);
            diagnostics.setFromAnalyze(uri, editor.document, analyzeResult);
            updateScanStatusBar(analyzeResult.findings);
            output.clear();
            output.appendLine(formatAnalyzeSummary(analyzeResult));
            output.show(true);

            const issueCount = analyzeResult.findings.length;
            if (analyzeResult.parse_errors.length > 0) {
              vscode.window.showWarningMessage(
                `VibeGuard: parse error — see Problems panel.`,
              );
            } else if (issueCount === 0) {
              vscode.window.showInformationMessage("VibeGuard: no security issues found.");
            } else {
              vscode.window.showWarningMessage(
                `VibeGuard: ${issueCount} issue(s) found — see Problems panel.`,
              );
            }
          }
        } catch (err) {
          handleError(err, options.securityOnly ? config.securityApiUrl : config.orchestratorApiUrl);
        }
      },
    );
  }

  async function runProfileInternal(
    config: ReturnType<typeof getConfig>,
    code: string,
    channel: vscode.OutputChannel,
    opts: { append: boolean },
  ): Promise<void> {
    try {
      const profileResult = await profileCode(config, code);
      if (!opts.append) {
        channel.clear();
      }
      channel.appendLine(formatProfileReport(profileResult));
      channel.show(true);

      if (!profileResult.ok) {
        vscode.window.showWarningMessage(
          `VibeGuard sandbox: ${profileResult.error_message ?? "profiling failed"}`,
        );
      }
    } catch (err) {
      handleError(err, config.sandboxApiUrl);
    }
  }

  function handleError(err: unknown, apiUrl: string): void {
    if (err instanceof ApiError) {
      const hint =
        err.status === undefined
          ? ` Is the API running at ${apiUrl}?`
          : "";
      vscode.window.showErrorMessage(`VibeGuard: ${err.message}${hint}`);
      return;
    }
    vscode.window.showErrorMessage(
      `VibeGuard: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  async function openChat(): Promise<void> {
    chatViewProvider.focus();
    await vscode.commands.executeCommand("workbench.view.extension.vibeguard");
  }

  context.subscriptions.push(
    output,
    diagnostics,
    chatStatusBar,
    scanStatusBar,
    vscode.window.registerWebviewViewProvider(ChatViewProvider.viewType, chatViewProvider),
    // Language providers
    vscode.languages.registerCodeActionsProvider(
      { language: "python" },
      new VibeGuardCodeActionProvider(),
      { providedCodeActionKinds: VibeGuardCodeActionProvider.providedCodeActionKinds },
    ),
    vscode.languages.registerHoverProvider(
      { language: "python" },
      new VibeGuardHoverProvider(diagnostics),
    ),
    // Commands
    vscode.commands.registerCommand("vibeguard.analyze", () =>
      runAnalyze({ securityOnly: false, selectionOnly: false }),
    ),
    vscode.commands.registerCommand("vibeguard.analyzeSecurity", () =>
      runAnalyze({ securityOnly: true, selectionOnly: false }),
    ),
    vscode.commands.registerCommand("vibeguard.analyzeSelection", () =>
      runAnalyze({ securityOnly: false, selectionOnly: true }),
    ),
    vscode.commands.registerCommand("vibeguard.profile", async () => {
      const editor = getActivePythonEditor();
      if (!editor) {
        return;
      }
      const code = getCodeFromEditor(editor, false);
      if (!code) {
        return;
      }
      const config = getConfig();
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "VibeGuard",
          cancellable: false,
        },
        async () => {
          await runProfileInternal(config, code, output, { append: false });
        },
      );
    }),
    vscode.commands.registerCommand("vibeguard.fix", async () => {
      const editor = getActivePythonEditor();
      if (!editor) {
        return;
      }
      const code = getCodeFromEditor(editor, false);
      if (!code) {
        return;
      }
      const config = getConfig();
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "VibeGuard",
          cancellable: false,
        },
        async () => {
          try {
            const result = await fixCode(config, code);
            output.clear();
            output.appendLine(formatFixReport(result));
            output.show(true);

            if (result.changed && result.safe && result.fixed_code) {
              const choice = await vscode.window.showInformationMessage(
                `VibeGuard: ${result.applied.length} fix(es) ready. Apply to file?`,
                "Apply",
              );
              if (choice === "Apply") {
                const edit = new vscode.WorkspaceEdit();
                const fullRange = new vscode.Range(0, 0, editor.document.lineCount, 0);
                edit.replace(editor.document.uri, fullRange, result.fixed_code);
                await vscode.workspace.applyEdit(edit);
              }
            } else if (!result.changed) {
              vscode.window.showInformationMessage("VibeGuard: no fixes available for this file.");
            } else if (!result.safe) {
              vscode.window.showWarningMessage(
                "VibeGuard: fixes generated but marked unsafe — review the output before applying.",
              );
            }
          } catch (err) {
            handleError(err, config.orchestratorApiUrl);
          }
        },
      );
    }),
    vscode.commands.registerCommand("vibeguard.compare", async () => {
      const editor = getActivePythonEditor();
      if (!editor) {
        return;
      }
      const code = getCodeFromEditor(editor, false);
      if (!code) {
        return;
      }
      const config = getConfig();
      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "VibeGuard",
          cancellable: false,
        },
        async () => {
          try {
            const result = await compareCode(config, code);
            output.clear();
            output.appendLine(formatCompareReport(result));
            output.show(true);
            const delta = result.security.delta;
            vscode.window.showInformationMessage(
              `VibeGuard: comparison complete — ${delta} finding(s) removed by fix.`,
            );
          } catch (err) {
            handleError(err, config.orchestratorApiUrl);
          }
        },
      );
    }),
    vscode.commands.registerCommand("vibeguard.checkHealth", async () => {
      const config = getConfig();
      const [securityOk, sandboxOk, orchestratorOk] = await Promise.all([
        checkHealth(config.securityApiUrl, config.requestTimeoutMs),
        checkHealth(config.sandboxApiUrl, config.requestTimeoutMs),
        checkHealth(config.orchestratorApiUrl, config.requestTimeoutMs),
      ]);

      const lines = [
        `Security API (${config.securityApiUrl}): ${securityOk ? "ok" : "unreachable"}`,
        `Sandbox API (${config.sandboxApiUrl}): ${sandboxOk ? "ok" : "unreachable"}`,
        `Orchestrator API (${config.orchestratorApiUrl}): ${orchestratorOk ? "ok" : "unreachable"}`,
      ];
      output.clear();
      output.appendLine(lines.join("\n"));
      output.show(true);

      if (securityOk && sandboxOk && orchestratorOk) {
        vscode.window.showInformationMessage("VibeGuard: all APIs are healthy.");
      } else {
        vscode.window.showWarningMessage("VibeGuard: one or more APIs are unreachable.");
      }
    }),
    vscode.commands.registerCommand("vibeguard.openChat", () => {
      void openChat();
    }),
    vscode.commands.registerCommand("vibeguard.openChatPanel", () => {
      ChatPanel.createOrShow(context);
    }),
  );
}

export function deactivate(): void {}
