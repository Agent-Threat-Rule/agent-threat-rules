/**
 * ATR-to-SARIF Converter
 *
 * Converts ATR scan results into SARIF v2.1.0 format for
 * GitHub Security tab integration via code scanning alerts.
 *
 * @module agent-threat-rules/converters/sarif
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
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
 * Relative SARIF artifact URI for a scanned file.
 *
 * Absolute paths are never emitted — a SARIF report is routinely attached to
 * public CI runs, and the local filesystem layout is not the consumer's
 * business.
 */
function toArtifactUri(inputFile: string): string {
  const cwd = process.cwd() + '/';
  if (inputFile.startsWith(cwd)) return inputFile.slice(cwd.length);
  if (inputFile.startsWith('/') || /^[A-Z]:\\/.test(inputFile)) {
    // Absolute path outside CWD — strip to filename only.
    return inputFile.split('/').pop() ?? inputFile.split('\\').pop() ?? 'unknown';
  }
  return inputFile;
}

/**
 * Raw-octet SHA-256 of a file's bytes — the digest basis the shared envelope
 * profile joins layers on (claude-code-skill-security-check#24 §2): computed
 * over the raw octets, before any character decoding, so it equals `sha256sum`
 * of the file and matches the raw-byte basis used by skil-lock and skill-scanner.
 *
 * This deliberately does NOT reuse result.content_hash, which hashes the
 * UTF-8-*decoded* string (`update(content, 'utf8')`) and therefore diverges from
 * the raw-octet digest on artifacts containing invalid UTF-8 or lone surrogates —
 * exactly the case that would silently break the cross-layer join (two different
 * files can decode to one string, or one file can yield two digests across layers).
 *
 * Returns null when the file cannot be read as bytes; the caller then omits the
 * hash rather than emit a wrong-basis digest that only looks like a join key.
 */
function fileRawDigest(inputFile: string): string | null {
  try {
    return createHash('sha256').update(readFileSync(inputFile)).digest('hex');
  } catch {
    return null;
  }
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

  // SARIF run.artifacts — one entry per scanned file, carrying the SHA-256 that
  // the shared envelope profile (skil-lock#37 / SPEC 14.3) joins layers on.
  // Emitting it here rather than only in result.properties is what lets a
  // consumer match an ATR finding to the same artifact reported by another
  // layer without parsing tool-specific property bags.
  //
  // The digest is the file's RAW OCTETS (fileRawDigest), not result.content_hash:
  // the join is only sound if every layer hashes the same bytes, and the raw-octet
  // basis is normative per claude-code-skill-security-check#24 §2. content_hash
  // (UTF-8-decoded) is kept separately on each result for back-compat.
  const artifacts: object[] = [];
  const artifactIndex = new Map<string, number>();
  for (const result of results) {
    if (!result.input_file) continue;
    const uri = toArtifactUri(result.input_file);
    if (artifactIndex.has(uri)) continue;
    artifactIndex.set(uri, artifacts.length);
    const digest = fileRawDigest(result.input_file);
    artifacts.push({
      location: { uri, uriBaseId: '%SRCROOT%' },
      ...(digest ? { hashes: { 'sha-256': digest } } : {}),
    });
  }

  const sarifResults: object[] = [];

  for (const result of results) {
    for (const match of result.matches) {
      const idx = ruleIndex.get(match.rule.id) ?? 0;

      const location: Record<string, unknown> = {};
      if (result.input_file) {
        // Never expose absolute paths in SARIF — see toArtifactUri.
        const uri = toArtifactUri(result.input_file);
        const idxInArtifacts = artifactIndex.get(uri);
        location.physicalLocation = {
          artifactLocation: {
            uri,
            uriBaseId: '%SRCROOT%',
            // Points at the run.artifacts entry holding this file's SHA-256.
            ...(idxInArtifacts !== undefined ? { index: idxInArtifacts } : {}),
          },
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
          // Identifies which layer of the shared envelope profile produced this
          // result. Consumers that do not know the value treat it as opaque.
          layer: 'atr',
          confidence: match.confidence,
          scan_type: result.scan_type,
          scan_context: match.scan_context,
          // Retained alongside run.artifacts[].hashes for back-compat: anything
          // parsing today's output keeps working.
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
        ...(artifacts.length > 0 ? { artifacts } : {}),
        results: sarifResults,
      },
    ],
  };
}
