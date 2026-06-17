import * as vscode from "vscode";
import { ApiError, chatGenerate } from "./client";
import { getConfig } from "./config";
import type { ChatMessage, ChatResponse } from "./types";

export function getChatHtml(webview: vscode.Webview, extensionUri: vscode.Uri): string {
  const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, "media", "chat.js"));
  const styleUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, "media", "chat.css"));
  const nonce = String(Date.now());

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <link href="${styleUri}" rel="stylesheet" />
  <title>VibeGuard Chat</title>
</head>
<body>
  <header>
    <div class="header-text">
      <h1>VibeGuard Secure Code Chat</h1>
      <p id="config-line">Rule-aware generation via orchestrator</p>
    </div>
    <button id="clear-btn" aria-label="Start a new chat session" title="New chat">New chat</button>
  </header>
  <main id="messages" role="log" aria-live="polite" aria-label="Chat messages">
    <div id="empty-state">
      <p class="empty-title">Ask for secure Python code</p>
      <p class="empty-hint">Try: "hash a password with bcrypt" or "parameterised SQL user lookup"</p>
      <p class="empty-hint">Use <kbd>Ctrl+Enter</kbd> to send.</p>
    </div>
  </main>
  <footer>
    <label for="input" class="sr-only">Chat message</label>
    <textarea id="input" rows="3" placeholder="Ask for secure Python code…" aria-label="Chat message input"></textarea>
    <div class="actions">
      <button id="send" aria-label="Send message">Send</button>
      <button id="insert" disabled aria-label="Insert generated code into the active editor">Insert into editor</button>
      <button id="scan" disabled aria-label="Run VibeGuard security scan on the active editor">Scan editor</button>
    </div>
  </footer>
  <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
}

/** Shared chat logic for sidebar view and optional editor panel. */
export class ChatSession {
  private _history: ChatMessage[] = [];
  private _lastCode = "";

  constructor(private readonly _post: (message: unknown) => void) {}

  postConfig(): void {
    const cfg = getConfig();
    this._post({
      type: "config",
      provider: cfg.chatProvider,
      model: cfg.chatModel,
      orchestrator: cfg.orchestratorApiUrl,
    });
  }

  async handleMessage(message: { type?: string; text?: string; code?: string }): Promise<void> {
    switch (message.type) {
      case "ready":
        this.postConfig();
        break;
      case "send":
        await this.handleSend(String(message.text ?? ""));
        break;
      case "insert":
        await this.insertCode(String(message.code ?? this._lastCode));
        break;
      case "scan":
        await vscode.commands.executeCommand("vibeguard.analyze");
        break;
      case "clear":
        this._history = [];
        this._lastCode = "";
        break;
    }
  }

  private async handleSend(text: string): Promise<void> {
    const trimmed = text.trim();
    if (!trimmed) {
      return;
    }

    this._history.push({ role: "user", content: trimmed });
    this._post({ type: "user", content: trimmed });
    this._post({ type: "status", content: "Generating secure code…" });

    const editor = vscode.window.activeTextEditor;
    const codeContext =
      editor && editor.document.languageId === "python" ? editor.document.getText() : undefined;

    try {
      const cfg = getConfig();
      const result = await chatGenerate(cfg, this._history, codeContext);
      this._lastCode = result.code;
      this._history.push({ role: "assistant", content: result.code });
      this._post({ type: "assistant", response: result });
    } catch (err) {
      const msg =
        err instanceof ApiError
          ? `${err.message} (start orchestrator at ${getConfig().orchestratorApiUrl})`
          : err instanceof Error
            ? err.message
            : String(err);
      this._post({ type: "error", content: msg });
      vscode.window.showErrorMessage(`VibeGuard Chat: ${msg}`);
    }
  }

  private async insertCode(code: string): Promise<void> {
    if (!code.trim()) {
      vscode.window.showWarningMessage("VibeGuard Chat: no generated code to insert.");
      return;
    }

    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document.languageId !== "python") {
      vscode.window.showWarningMessage("Open a Python file to insert generated code.");
      return;
    }

    const edit = new vscode.WorkspaceEdit();
    const fullRange = new vscode.Range(
      editor.document.positionAt(0),
      editor.document.positionAt(editor.document.getText().length),
    );
    edit.replace(editor.document.uri, fullRange, code);
    await vscode.workspace.applyEdit(edit);
    vscode.window.showInformationMessage("VibeGuard: inserted generated code into the editor.");
  }
}

export function formatChatSummary(result: ChatResponse): string {
  const lines = ["=== VibeGuard Chat Result ===", ""];
  if (result.clean) {
    lines.push("Security scan: clean (no rule violations detected).");
  } else {
    lines.push(`Security scan: ${result.findings.length} issue(s) remaining.`);
    for (const f of result.findings) {
      lines.push(`  [${f.rule_id}] ${f.message}${f.owasp ? ` (${f.owasp})` : ""}`);
    }
  }
  if (result.iterations?.length) {
    lines.push("", `Refinement rounds: ${result.iterations.length}`);
  }
  return lines.join("\n");
}
