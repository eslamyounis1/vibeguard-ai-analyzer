import * as path from "path";
import * as vscode from "vscode";
import type { Finding, Severity } from "./types";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function severityIcon(sev: Severity): string {
  return sev === "CRITICAL" || sev === "HIGH" ? "error" : sev === "MEDIUM" ? "warning" : "info";
}

export class FindingItem extends vscode.TreeItem {
  readonly finding: Finding;
  readonly fileUri: vscode.Uri;

  constructor(finding: Finding, fileUri: vscode.Uri) {
    super(`[${finding.rule_id}] ${finding.title}`, vscode.TreeItemCollapsibleState.None);
    this.finding = finding;
    this.fileUri = fileUri;
    this.description = `L${finding.line} · ${path.basename(fileUri.fsPath)}`;
    this.tooltip = new vscode.MarkdownString(
      `**${finding.title}** \`${finding.severity}\`\n\n${finding.message}` +
        (finding.cwe ? `\n\n**CWE:** ${finding.cwe}` : "") +
        (finding.suggestion ? `\n\n**Fix:** ${finding.suggestion}` : ""),
    );
    this.iconPath = new vscode.ThemeIcon(severityIcon(finding.severity));
    this.contextValue = "finding";
    this.command = {
      command: "vibeguard.navigateToFinding",
      title: "Go to Finding",
      arguments: [fileUri, finding],
    };
  }
}

export class SeverityGroupItem extends vscode.TreeItem {
  readonly severity: Severity;
  readonly children: FindingItem[];

  constructor(severity: Severity, children: FindingItem[]) {
    super(`${severity} (${children.length})`, vscode.TreeItemCollapsibleState.Expanded);
    this.severity = severity;
    this.children = children;
    this.iconPath = new vscode.ThemeIcon(severityIcon(severity));
    this.contextValue = "severityGroup";
  }
}

class PlaceholderItem extends vscode.TreeItem {
  constructor(label: string) {
    super(label, vscode.TreeItemCollapsibleState.None);
    this.contextValue = "placeholder";
  }
}

type TreeNode = SeverityGroupItem | FindingItem | PlaceholderItem;

export class FindingsTreeView implements vscode.TreeDataProvider<TreeNode> {
  private _findings: Finding[] = [];
  private _fileUri?: vscode.Uri;
  private _hasScanned = false;

  private readonly _onDidChangeTreeData = new vscode.EventEmitter<TreeNode | undefined | void>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  update(findings: Finding[], uri: vscode.Uri): void {
    this._findings = findings;
    this._fileUri = uri;
    this._hasScanned = true;
    this._onDidChangeTreeData.fire();
  }

  clear(): void {
    this._findings = [];
    this._fileUri = undefined;
    this._hasScanned = false;
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: TreeNode): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TreeNode): TreeNode[] {
    if (element instanceof SeverityGroupItem) {
      return element.children;
    }
    if (element) {
      return [];
    }

    if (!this._hasScanned) {
      return [new PlaceholderItem("Run VibeGuard: Analyze File to see findings")];
    }
    if (this._findings.length === 0) {
      return [new PlaceholderItem("No issues found")];
    }

    const uri = this._fileUri!;
    const groups: SeverityGroupItem[] = [];
    for (const sev of SEVERITY_ORDER) {
      const batch = this._findings.filter((f) => f.severity === sev);
      if (batch.length > 0) {
        groups.push(new SeverityGroupItem(sev, batch.map((f) => new FindingItem(f, uri))));
      }
    }
    return groups;
  }
}
