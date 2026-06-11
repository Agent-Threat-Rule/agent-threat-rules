/**
 * ATR Scan extension entry point.
 *
 * Wires the scanner to VS Code: scan-on-save / scan-on-open for files
 * matching the configured glob patterns, two manual commands, a status
 * bar item, and a diagnostics collection for the Problems panel.
 */
import * as vscode from "vscode";
import { AtrScanner, resolveRulesDir } from "./scanner";
import { toDiagnostics, DIAGNOSTIC_SOURCE } from "./diagnostics";
import { getScanConfig, isRelevantDocument } from "./config";

const WORKSPACE_SCAN_EXCLUDE = "**/node_modules/**";

interface ExtensionState {
  readonly scanner: AtrScanner;
  readonly diagnostics: vscode.DiagnosticCollection;
  readonly statusBar: vscode.StatusBarItem;
}

export function activate(context: vscode.ExtensionContext): void {
  const state = createState(context);
  registerCommands(context, state);
  registerListeners(context, state);
  void scanVisibleDocuments(state);
}

export function deactivate(): void {
  // Disposables are released via context.subscriptions.
}

function createState(context: vscode.ExtensionContext): ExtensionState {
  const rulesDir = resolveRulesDir(__dirname);
  const scanner = new AtrScanner(rulesDir);
  const diagnostics =
    vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);
  const statusBar = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Right,
    100
  );
  statusBar.name = "ATR Scan";
  statusBar.command = "atrScan.scanCurrentFile";
  statusBar.text = "ATR: idle";
  statusBar.tooltip = "ATR Scan: click to scan the current file";
  statusBar.show();
  context.subscriptions.push(diagnostics, statusBar);
  return { scanner, diagnostics, statusBar };
}

function registerCommands(
  context: vscode.ExtensionContext,
  state: ExtensionState
): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("atrScan.scanCurrentFile", () =>
      scanCurrentFile(state)
    ),
    vscode.commands.registerCommand("atrScan.scanWorkspace", () =>
      scanWorkspace(state)
    )
  );
}

function registerListeners(
  context: vscode.ExtensionContext,
  state: ExtensionState
): void {
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((document) =>
      scanIfRelevant(state, document)
    ),
    vscode.workspace.onDidOpenTextDocument((document) =>
      scanIfRelevant(state, document)
    ),
    vscode.workspace.onDidCloseTextDocument((document) =>
      state.diagnostics.delete(document.uri)
    )
  );
}

function scanVisibleDocuments(state: ExtensionState): Promise<void[]> {
  const scans = vscode.window.visibleTextEditors.map((editor) =>
    scanIfRelevant(state, editor.document)
  );
  return Promise.all(scans);
}

async function scanIfRelevant(
  state: ExtensionState,
  document: vscode.TextDocument
): Promise<void> {
  const config = getScanConfig();
  if (!config.enabled) {
    return;
  }
  if (!isRelevantDocument(document, config.filePatterns)) {
    return;
  }
  await scanDocument(state, document);
}

async function scanCurrentFile(state: ExtensionState): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (editor === undefined) {
    void vscode.window.showInformationMessage("ATR Scan: no active file.");
    return;
  }
  const count = await scanDocument(state, editor.document);
  if (count === 0) {
    void vscode.window.showInformationMessage(
      "ATR Scan: no threats detected in the current file."
    );
  }
}

async function scanWorkspace(state: ExtensionState): Promise<void> {
  const config = getScanConfig();
  const fileLists = await Promise.all(
    config.filePatterns.map((pattern) =>
      vscode.workspace.findFiles(pattern, WORKSPACE_SCAN_EXCLUDE)
    )
  );
  const uris = dedupeUris(fileLists.flat());
  const counts = await Promise.all(
    uris.map((uri) => scanFileUri(state, uri))
  );
  const total = counts.reduce((sum, count) => sum + count, 0);
  updateStatusBar(state, total, `${uris.length} files`);
  void vscode.window.showInformationMessage(
    `ATR Scan: scanned ${uris.length} files, ${total} finding(s).`
  );
}

function dedupeUris(uris: readonly vscode.Uri[]): vscode.Uri[] {
  const seen = new Set<string>();
  return uris.filter((uri) => {
    if (seen.has(uri.toString())) {
      return false;
    }
    seen.add(uri.toString());
    return true;
  });
}

async function scanFileUri(
  state: ExtensionState,
  uri: vscode.Uri
): Promise<number> {
  try {
    const document = await vscode.workspace.openTextDocument(uri);
    return await scanDocument(state, document, { updateStatus: false });
  } catch {
    return 0;
  }
}

interface ScanOptions {
  readonly updateStatus: boolean;
}

async function scanDocument(
  state: ExtensionState,
  document: vscode.TextDocument,
  options: ScanOptions = { updateStatus: true }
): Promise<number> {
  const config = getScanConfig();
  try {
    const result = await state.scanner.scan(
      document.getText(),
      document.uri.fsPath
    );
    const diagnostics = toDiagnostics(
      result.matches,
      document,
      config.minSeverity
    );
    state.diagnostics.set(document.uri, diagnostics);
    if (options.updateStatus) {
      updateStatusBar(state, diagnostics.length, fileLabel(document));
    }
    return diagnostics.length;
  } catch (error) {
    reportScanError(error);
    return 0;
  }
}

function fileLabel(document: vscode.TextDocument): string {
  const segments = document.uri.path.split("/");
  return segments[segments.length - 1] ?? document.uri.path;
}

function updateStatusBar(
  state: ExtensionState,
  count: number,
  target: string
): void {
  state.statusBar.text =
    count > 0 ? `ATR: ${count} finding(s)` : "ATR: clean";
  state.statusBar.tooltip = `ATR Scan: last scan (${target}) found ${count} finding(s). Click to rescan the current file.`;
}

function reportScanError(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  void vscode.window.showErrorMessage(`ATR Scan failed: ${message}`);
}
