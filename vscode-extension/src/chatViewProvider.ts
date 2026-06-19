import * as vscode from "vscode";
import { ChatSession, getChatHtml } from "./chatWebview";
import type { Finding } from "./types";

export class ChatViewProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = "vibeguard.chatView";

  private _view?: vscode.WebviewView;
  private _session?: ChatSession;

  constructor(
    private readonly _extensionUri: vscode.Uri,
    private readonly _context: vscode.ExtensionContext,
  ) {}

  resolveWebviewView(
    webviewView: vscode.WebviewView,
    _context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken,
  ): void {
    this._view = webviewView;
    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [vscode.Uri.joinPath(this._extensionUri, "media")],
    };
    webviewView.webview.html = getChatHtml(webviewView.webview, this._extensionUri);

    this._session = new ChatSession((message) => {
      webviewView.webview.postMessage(message);
    });
    this._session.bindState(this._context.workspaceState);

    webviewView.webview.onDidReceiveMessage((message) => {
      if (message.type === "ready") {
        this._session?.postConfig();
        this._session?.loadHistory();
        return;
      }
      void this._session?.handleMessage(message);
    });
  }

  explainFinding(finding: Finding): void {
    void this._session?.explainFinding(finding);
  }

  focus(): void {
    if (this._view) {
      this._view.show?.(true);
    } else {
      void vscode.commands.executeCommand(`${ChatViewProvider.viewType}.focus`);
    }
  }
}
