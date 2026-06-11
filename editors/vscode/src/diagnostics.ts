/**
 * Conversion of ATR scan results into VS Code diagnostics.
 *
 * The engine reports which patterns matched (strings, possibly regex
 * sources) but not document offsets, so we locate the first occurrence
 * of a matched pattern in the document to compute a Range and fall back
 * to line 0 when nothing can be located.
 */
import * as vscode from "vscode";
import type { ATRMatch } from "agent-threat-rules";
import { meetsMinSeverity, type Severity } from "./config";

export const DIAGNOSTIC_SOURCE = "atr-scan";

const SEVERITY_MAP: Readonly<Record<Severity, vscode.DiagnosticSeverity>> = {
  critical: vscode.DiagnosticSeverity.Error,
  high: vscode.DiagnosticSeverity.Error,
  medium: vscode.DiagnosticSeverity.Warning,
  low: vscode.DiagnosticSeverity.Information,
  informational: vscode.DiagnosticSeverity.Information,
};

export function toDiagnostics(
  matches: readonly ATRMatch[],
  document: vscode.TextDocument,
  minSeverity: Severity
): vscode.Diagnostic[] {
  return matches
    .filter((match) => meetsMinSeverity(match.rule.severity, minSeverity))
    .map((match) => toDiagnostic(match, document));
}

function toDiagnostic(
  match: ATRMatch,
  document: vscode.TextDocument
): vscode.Diagnostic {
  const range = locateRange(match, document);
  const diagnostic = new vscode.Diagnostic(
    range,
    buildMessage(match),
    mapSeverity(match.rule.severity)
  );
  diagnostic.source = DIAGNOSTIC_SOURCE;
  diagnostic.code = match.rule.id;
  return diagnostic;
}

function buildMessage(match: ATRMatch): string {
  const base = `[${match.rule.id}] ${match.rule.title}`;
  const remediation = match.rule.response?.message_template;
  if (typeof remediation === "string" && remediation.trim().length > 0) {
    return `${base} - ${remediation.trim()}`;
  }
  return base;
}

function mapSeverity(severity: string): vscode.DiagnosticSeverity {
  const key = severity.toLowerCase() as Severity;
  return SEVERITY_MAP[key] ?? vscode.DiagnosticSeverity.Warning;
}

/**
 * Locate the first matched pattern in the document. Patterns are tried
 * first as literal substrings (case-insensitive), then as regular
 * expressions. Falls back to the first line when nothing is found.
 */
function locateRange(
  match: ATRMatch,
  document: vscode.TextDocument
): vscode.Range {
  const text = document.getText();
  for (const pattern of match.matchedPatterns) {
    const located = locatePattern(pattern, text);
    if (located !== null) {
      return new vscode.Range(
        document.positionAt(located.start),
        document.positionAt(located.end)
      );
    }
  }
  return document.lineAt(0).range;
}

interface Located {
  readonly start: number;
  readonly end: number;
}

function locatePattern(pattern: string, text: string): Located | null {
  const literalIndex = text.toLowerCase().indexOf(pattern.toLowerCase());
  if (literalIndex >= 0) {
    return { start: literalIndex, end: literalIndex + pattern.length };
  }
  return locateRegex(pattern, text);
}

function locateRegex(pattern: string, text: string): Located | null {
  try {
    const result = new RegExp(pattern, "i").exec(text);
    if (result !== null && result[0].length > 0) {
      return { start: result.index, end: result.index + result[0].length };
    }
  } catch {
    // Pattern is not a valid JS regex; nothing to locate.
  }
  return null;
}
