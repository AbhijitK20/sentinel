import * as vscode from "vscode";
import * as cp from "child_process";

export function activate(context: vscode.ExtensionContext) {
  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection("sentinel");

  // Scan current file
  const scanCmd = vscode.commands.registerCommand(
    "sentinel.scan",
    async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage("No active editor");
        return;
      }

      const document = editor.document;
      if (document.languageId !== "python") {
        vscode.window.showWarningMessage("Sentinel only supports Python files");
        return;
      }

      await scanDocument(document, diagnosticCollection);
    }
  );

  // Scan workspace
  const scanWorkspaceCmd = vscode.commands.registerCommand(
    "sentinel.scanWorkspace",
    async () => {
      const workspaceFolders = vscode.workspace.workspaceFolders;
      if (!workspaceFolders) {
        vscode.window.showWarningMessage("No workspace folder");
        return;
      }

      const folder = workspaceFolders[0].uri.fsPath;
      vscode.window.showInformationMessage(`Scanning ${folder}...`);

      cp.exec(
        `sentinel scan "${folder}" --format json`,
        async (error, stdout) => {
          if (error) {
            vscode.window.showErrorMessage(`Sentinel error: ${error.message}`);
            return;
          }
          try {
            const report = JSON.parse(stdout);
            const count = report.summary?.total_findings || 0;
            vscode.window.showInformationMessage(
              `Sentinel: ${count} finding(s) in ${report.summary?.total_files || 0} files`
            );
          } catch {
            vscode.window.showErrorMessage("Failed to parse sentinel output");
          }
        }
      );
    }
  );

  // Show rules
  const showRulesCmd = vscode.commands.registerCommand(
    "sentinel.showRules",
    () => {
      cp.exec("sentinel rules --format json", (error, stdout) => {
        if (!error) {
          const panel = vscode.window.createWebviewPanel(
            "sentinelRules",
            "Sentinel Rules",
            vscode.ViewColumn.One,
            {}
          );
          panel.webview.html = getRulesHtml(stdout);
        }
      });
    }
  );

  context.subscriptions.push(scanCmd, scanWorkspaceCmd, showRulesCmd, diagnosticCollection);

  // Auto-scan on save
  vscode.workspace.onDidSaveTextDocument((document) => {
    if (document.languageId === "python") {
      scanDocument(document, diagnosticCollection);
    }
  });
}

async function scanDocument(
  document: vscode.TextDocument,
  collection: vscode.DiagnosticCollection
) {
  const text = document.getText();
  const tmpFile = `/tmp/sentinel_vscode_${Date.now()}.py`;

  const fs = require("fs");
  fs.writeFileSync(tmpFile, text);

  cp.exec(`sentinel scan "${tmpFile}" --format json`, (error: any, stdout: string) => {
    fs.unlinkSync(tmpFile);

    if (error) return;

    try {
      const report = JSON.parse(stdout);
      const diagnostics: vscode.Diagnostic[] = [];

      for (const fr of report.file_reports || []) {
        for (const finding of fr.findings || []) {
          const line = Math.max(0, (finding.line || 1) - 1);
          const range = new vscode.Range(line, 0, line, 1000);

          const severity =
            finding.severity === "error"
              ? vscode.DiagnosticSeverity.Error
              : finding.severity === "warning"
              ? vscode.DiagnosticSeverity.Warning
              : vscode.DiagnosticSeverity.Information;

          const diag = new vscode.Diagnostic(range, finding.message, severity);
          diag.source = "sentinel";
          diag.code = finding.rule;
          diagnostics.push(diag);
        }
      }

      collection.set(document.uri, diagnostics);
    } catch {}
  });
}

function getRulesHtml(jsonData: string): string {
  return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Sentinel Rules</title>
<style>
body { font-family: monospace; padding: 1rem; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #333; padding: 0.5rem; text-align: left; }
.error { color: #f85149; } .warning { color: #d29922; } .info { color: #58a6ff; }
</style></head><body>
<h2>Sentinel Rules</h2>
<table><tr><th>Rule</th><th>Category</th><th>Severity</th><th>Description</th></tr>
<tr><td colspan="4"><pre>${jsonData}</pre></td></tr>
</table></body></html>`;
}

export function deactivate() {}
