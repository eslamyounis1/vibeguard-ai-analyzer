import * as vscode from "vscode";
import { analyzeCode, ApiError, checkHealth, profileCode } from "./client";
import { ChatPanel } from "./chatPanel";
import { ChatViewProvider } from "./chatViewProvider";
import { getConfig } from "./config";
import { VibeGuardDiagnostics } from "./diagnostics";
import { formatAnalyzeSummary, formatProfileReport } from "./report";

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

  const chatStatusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 90);
  chatStatusBar.text = "$(comment-discussion) VibeGuard Chat";
  chatStatusBar.command = "vibeguard.openChat";
  chatStatusBar.tooltip = "Open VibeGuard Secure Code Chat (sidebar)";
  chatStatusBar.show();

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
          progress.report({ message: "Running security analysis…" });
          const analyzeResult = await analyzeCode(config, code);
          diagnostics.setFromAnalyze(uri, editor.document, analyzeResult);
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

          if (!options.securityOnly && config.runSandboxOnAnalyze) {
            progress.report({ message: "Profiling in sandbox…" });
            await runProfileInternal(config, code, output, { append: true });
          }
        } catch (err) {
          handleError(err, config.securityApiUrl);
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
    vscode.window.registerWebviewViewProvider(ChatViewProvider.viewType, chatViewProvider),
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
