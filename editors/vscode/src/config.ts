/**
 * Configuration access for the ATR Scan extension.
 *
 * All reads go through getScanConfig() so the rest of the codebase
 * works with one immutable snapshot per operation.
 */
import * as vscode from "vscode";

export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

export interface ScanConfig {
  readonly enabled: boolean;
  readonly minSeverity: Severity;
  readonly filePatterns: readonly string[];
}

export const DEFAULT_FILE_PATTERNS: readonly string[] = [
  "**/SKILL.md",
  "**/.mcp.json",
  "**/mcp.json",
  "**/claude_desktop_config.json",
  "**/.cursorrules",
  "**/CLAUDE.md",
  "**/AGENTS.md",
  "**/agents.md",
];

const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
};

export function getScanConfig(): ScanConfig {
  const cfg = vscode.workspace.getConfiguration("atrScan");
  return {
    enabled: cfg.get<boolean>("enabled", true),
    minSeverity: normalizeSeverity(cfg.get<string>("minSeverity", "medium")),
    filePatterns: cfg.get<string[]>("filePatterns", [
      ...DEFAULT_FILE_PATTERNS,
    ]),
  };
}

export function normalizeSeverity(value: string): Severity {
  const lowered = value.toLowerCase();
  if (lowered in SEVERITY_RANK) {
    return lowered as Severity;
  }
  return "medium";
}

export function meetsMinSeverity(
  severity: string,
  minSeverity: Severity
): boolean {
  const rank = SEVERITY_RANK[normalizeSeverity(severity)];
  return rank >= SEVERITY_RANK[minSeverity];
}

/** True when the document matches one of the configured glob patterns. */
export function isRelevantDocument(
  document: vscode.TextDocument,
  patterns: readonly string[]
): boolean {
  return patterns.some(
    (pattern) =>
      vscode.languages.match({ pattern, scheme: "file" }, document) > 0
  );
}
