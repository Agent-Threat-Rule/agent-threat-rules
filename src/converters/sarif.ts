/**
 * ATR-to-SARIF Converter
 *
 * Converts ATR scan results into SARIF v2.1.0 format for
 * GitHub Security tab integration via code scanning alerts.
 *
 * @module agent-threat-rules/converters/sarif
 */

import type { ATRRule, ATRMatch, ScanResult, ATRSeverity } from '../types.js';

/** SARIF severity levels */
type SARIFLevel = 'error' | 'warning' | 'note' | 'none';

/** Map ATR severity to SARIF level */
function severityToLevel(severity: ATRSeverity): SARIFLevel {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'informational':
      return 'note';
    default:
      return 'note';
  }
}

/** Map ATR severity to SARIF security-severity score (0-10) */
function severityToScore(severity: ATRSeverity): string {
  switch (severity) {
    case 'critical':
      return '9.5';
    case 'high':
      return '8.0';
    case 'medium':
      return '5.5';
    case 'low':
      return '3.0';
    case 'informational':
      return '1.0';
    default:
      return '1.0';
  }
}

/** Build a unique rule index across all results */
function collectRules(
  results: readonly ScanResult[],
): { readonly rules: readonly ATRRule[]; readonly ruleIndex: ReadonlyMap<string, number> } {
  const ruleIndex = new Map<string, number>();
  const rules: ATRRule[] = [];

  for (const result of results) {
    for (const match of result.matches) {
      if (!ruleIndex.has(match.rule.id)) {
        ruleIndex.set(match.rule.id, rules.length);
        rules.push(match.rule);
      }
    }
  }

  return { rules, ruleIndex };
}

/**
 * Normalize an input_file path to a SARIF artifact URI.
 *
 * Mirrors the location-URI logic used for result locations so an artifact
 * entry and the results referencing it agree on the same URI. Never exposes
 * absolute paths in SARIF output.
 */
function inputFileToUri(inputFile: string): string {
  const cwd = process.cwd() + '/';
  if (inputFile.startsWith(cwd)) {
    return inputFile.slice(cwd.length);
  }
  if (inputFile.startsWith('/') || /^[A-Z]:\\/.test(inputFile)) {
    // Absolute path outside CWD — strip to filename only
    return inputFile.split('/').pop() ?? inputFile.split('\\').pop() ?? 'unknown';
  }
  return inputFile;
}

/** One SARIF artifact entry per scanned file. */
interface SARIFArtifact {
  readonly location: { readonly uri: string; readonly uriBaseId: string };
  readonly hashes: { readonly 'sha-256': string };
}

/**
 * Build `run.artifacts[]` and an index from each scanned file to its artifact
 * position — the shared scan-report envelope's join key.
 *
 * The SHA-256 surfaced as `hashes["sha-256"]` is the engine's existing
 * `result.content_hash` (SHA-256 of the SKILL.md content) — placed where the
 * envelope expects the join key, not a new computation. One entry per unique
 * scanned file. Results with no `input_file` (e.g. MCP runtime events) produce
 * no artifact and reference none.
 *
 * The index is keyed on the raw `input_file`, not the display URI, so two
 * distinct files that normalize to the same URI (e.g. same basename from
 * different out-of-CWD directories) stay separate artifacts — each result then
 * always resolves to the artifact carrying its own file's content hash.
 */
function collectArtifacts(
  results: readonly ScanResult[],
): { readonly artifacts: readonly SARIFArtifact[]; readonly artifactIndex: ReadonlyMap<string, number> } {
  const artifactIndex = new Map<string, number>();
  const artifacts: SARIFArtifact[] = [];

  for (const result of results) {
    if (!result.input_file) {
      continue;
    }
    if (!artifactIndex.has(result.input_file)) {
      artifactIndex.set(result.input_file, artifacts.length);
      artifacts.push({
        location: { uri: inputFileToUri(result.input_file), uriBaseId: '%SRCROOT%' },
        hashes: { 'sha-256': result.content_hash },
      });
    }
  }

  return { artifacts, artifactIndex };
}

/**
 * Convert ATR scan results to SARIF v2.1.0 format.
 *
 * @param results - Array of ScanResult from evaluate/scanSkill
 * @param toolVersion - ATR version string (e.g. "1.0.0")
 * @returns SARIF JSON object ready for serialization
 */
export function scanResultToSARIF(
  results: readonly ScanResult[],
  toolVersion: string,
): object {
  const { rules, ruleIndex } = collectRules(results);
  const { artifacts, artifactIndex } = collectArtifacts(results);

  const sarifRules = rules.map((rule) => ({
    id: rule.id,
    name: rule.id,
    shortDescription: { text: rule.title },
    fullDescription: { text: rule.description.slice(0, 1000) },
    helpUri: `https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/${rule.tags.category}`,
    defaultConfiguration: {
      level: severityToLevel(rule.severity),
    },
    properties: {
      'security-severity': severityToScore(rule.severity),
      category: rule.tags.category,
      tags: ['security', 'ai-agent', rule.tags.category],
    },
  }));

  const sarifResults: object[] = [];

  for (const result of results) {
    for (const match of result.matches) {
      const idx = ruleIndex.get(match.rule.id) ?? 0;

      const location: Record<string, unknown> = {};
      if (result.input_file) {
        // Make path relative to CWD — never expose absolute paths in SARIF
        const artifactLocation: Record<string, unknown> = {
          uri: inputFileToUri(result.input_file),
          uriBaseId: '%SRCROOT%',
        };
        // Point back at the run.artifacts[] entry so a consumer can join this
        // finding to the file's content hash (the shared envelope join key).
        const artifactIdx = artifactIndex.get(result.input_file);
        if (artifactIdx !== undefined) {
          artifactLocation['index'] = artifactIdx;
        }
        location.physicalLocation = {
          artifactLocation,
          region: { startLine: 1 },
        };
      }

      sarifResults.push({
        ruleId: match.rule.id,
        ruleIndex: idx,
        level: severityToLevel(match.rule.severity),
        message: {
          text: `${match.rule.title} (confidence: ${(match.confidence * 100).toFixed(0)}%, conditions: ${match.matchedConditions.join(', ')})`,
        },
        ...(result.input_file ? { locations: [location] } : {}),
        properties: {
          // Shared scan-report envelope: marks every ATR finding as the
          // detection ("atr") layer so a consumer can partition findings by
          // producer when merging drift / content / atr reports on one digest.
          layer: 'atr',
          confidence: match.confidence,
          scan_type: result.scan_type,
          scan_context: match.scan_context,
          content_hash: result.content_hash,
        },
      });
    }
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'ATR (Agent Threat Rules)',
            version: toolVersion,
            semanticVersion: toolVersion,
            informationUri: 'https://github.com/Agent-Threat-Rule/agent-threat-rules',
            rules: sarifRules,
          },
        },
        // One entry per scanned SKILL.md; hashes["sha-256"] is the join key.
        artifacts,
        results: sarifResults,
      },
    ],
  };
}
