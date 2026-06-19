import * as path from "path";
import * as vscode from "vscode";
import type { AnalyzeProfileResponse, AnalyzeResponse, Finding } from "./types";

export interface ReportData {
  file: string;
  findings: Finding[];
  bySeverity: Record<string, number>;
  riskScore?: number;
  dynamic?: {
    wallTimeSec?: number;
    cpuTimeSec?: number;
    peakMemoryKb?: number;
    energyJoules?: number;
  };
}

export function buildReportData(
  uri: vscode.Uri,
  analyzeResult: AnalyzeResponse,
  dynamicResult?: AnalyzeProfileResponse["dynamic"],
): ReportData {
  const summary = analyzeResult.summary ?? {};
  const bySeverity =
    "by_severity" in summary && typeof summary.by_severity === "object"
      ? (summary.by_severity as Record<string, number>)
      : {};
  const risk =
    "risk" in summary && typeof summary.risk === "object" && summary.risk !== null
      ? (summary.risk as Record<string, number>)
      : undefined;

  const totals = dynamicResult?.totals;
  const dynamic = totals
    ? {
        wallTimeSec: totals.wall_time_seconds,
        cpuTimeSec: totals.cpu_time_seconds,
        peakMemoryKb:
          totals.peak_memory_bytes !== undefined ? totals.peak_memory_bytes / 1024 : undefined,
        energyJoules: totals.energy_joules_estimate,
      }
    : undefined;

  return {
    file: path.basename(uri.fsPath),
    findings: analyzeResult.findings,
    bySeverity,
    riskScore: risk?.security_score,
    dynamic,
  };
}

export class ReportPanel {
  static currentPanel: ReportPanel | undefined;
  static readonly viewType = "vibeguardReport";

  private readonly _panel: vscode.WebviewPanel;
  private _currentUri: vscode.Uri;
  private _pendingData: ReportData;

  static createOrShow(
    context: vscode.ExtensionContext,
    data: ReportData,
    fileUri: vscode.Uri,
  ): void {
    const column = vscode.ViewColumn.Beside;

    if (ReportPanel.currentPanel) {
      ReportPanel.currentPanel._pendingData = data;
      ReportPanel.currentPanel._currentUri = fileUri;
      ReportPanel.currentPanel._panel.reveal(column);
      ReportPanel.currentPanel._panel.webview.postMessage({ type: "render", data });
      return;
    }

    const panel = vscode.window.createWebviewPanel(
      ReportPanel.viewType,
      "VibeGuard Report",
      column,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, "media")],
      },
    );

    ReportPanel.currentPanel = new ReportPanel(panel, context.extensionUri, fileUri, data);
  }

  private constructor(
    panel: vscode.WebviewPanel,
    extensionUri: vscode.Uri,
    fileUri: vscode.Uri,
    data: ReportData,
  ) {
    this._panel = panel;
    this._currentUri = fileUri;
    this._pendingData = data;

    this._panel.webview.html = getReportHtml(panel.webview, extensionUri);

    this._panel.onDidDispose(() => {
      ReportPanel.currentPanel = undefined;
    });

    this._panel.webview.onDidReceiveMessage(async (msg: { type: string; line?: number; findings?: Finding[] }) => {
      switch (msg.type) {
        case "ready":
          this._panel.webview.postMessage({ type: "render", data: this._pendingData });
          break;

        case "jumpToLine": {
          try {
            const doc = await vscode.workspace.openTextDocument(this._currentUri);
            const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
            const line = Math.max(0, (msg.line ?? 1) - 1);
            const pos = new vscode.Position(line, 0);
            editor.selection = new vscode.Selection(pos, pos);
            editor.revealRange(
              new vscode.Range(pos, pos),
              vscode.TextEditorRevealType.InCenter,
            );
          } catch {
            vscode.window.showErrorMessage("VibeGuard: could not navigate to that line.");
          }
          break;
        }

        case "exportJson": {
          const saveUri = await vscode.window.showSaveDialog({
            defaultUri: vscode.Uri.file("vibeguard-report.json"),
            filters: { JSON: ["json"] },
          });
          if (saveUri) {
            const json = JSON.stringify(msg.findings ?? this._pendingData.findings, null, 2);
            await vscode.workspace.fs.writeFile(saveUri, Buffer.from(json, "utf-8"));
            vscode.window.showInformationMessage(
              `VibeGuard: report saved to ${saveUri.fsPath}`,
            );
          }
          break;
        }
      }
    });
  }
}

function getReportHtml(webview: vscode.Webview, extensionUri: vscode.Uri): string {
  const scriptUri = webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, "media", "report.js"),
  );
  const styleUri = webview.asWebviewUri(
    vscode.Uri.joinPath(extensionUri, "media", "report.css"),
  );
  const nonce = String(Date.now());

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy"
    content="default-src 'none'; style-src ${webview.cspSource}; script-src 'nonce-${nonce}';" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <link href="${styleUri}" rel="stylesheet" />
  <title>VibeGuard Report</title>
</head>
<body>
  <div id="loading">Waiting for scan results…</div>
  <div id="app" hidden></div>
  <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
}
