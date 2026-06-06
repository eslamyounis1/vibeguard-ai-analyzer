import * as vscode from "vscode";
import { ChatSession, getChatHtml } from "./chatWebview";

export class ChatPanel {
  public static currentPanel: ChatPanel | undefined;
  public static readonly viewType = "vibeguardChat";

  private readonly _panel: vscode.WebviewPanel;
  private readonly _session: ChatSession;

  public static createOrShow(context: vscode.ExtensionContext): void {
    const column = vscode.window.activeTextEditor?.viewColumn;

    if (ChatPanel.currentPanel) {
      ChatPanel.currentPanel._panel.reveal(column);
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      ChatPanel.viewType,
      "VibeGuard Chat",
      column ?? vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, "media")],
      },
    );

    ChatPanel.currentPanel = new ChatPanel(panel, context.extensionUri);
  }

  private constructor(panel: vscode.WebviewPanel, extensionUri: vscode.Uri) {
    this._panel = panel;
    this._session = new ChatSession((message) => {
      this._panel.webview.postMessage(message);
    });

    this._panel.webview.html = getChatHtml(this._panel.webview, extensionUri);
    this._panel.onDidDispose(() => {
      ChatPanel.currentPanel = undefined;
    });

    this._panel.webview.onDidReceiveMessage((message) => {
      void this._session.handleMessage(message);
    });
  }
}
