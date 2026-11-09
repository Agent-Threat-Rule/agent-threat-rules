import { readFileSync } from 'node:fs';

/**
 * Result of scripts/cisco-pack/benign-gate.py: every ATR rule that blocked or
 * flagged at least one benign skill when the exported pack ran inside Skill
 * Scanner itself.
 *
 * ATR's own benign checks run ATR's engine on ATR's event shape. The pack runs
 * somewhere else: Skill Scanner applies each pattern to every line of a
 * skill's files, compiled by Python `re`. A rule can be clean in one and fire
 * on most skills in the other, so the gate has to measure the exported pack
 * where it runs.
 */
export interface BenignGateResult {
  readonly scanner: { readonly repo: string; readonly commit: string };
  readonly corpus: { readonly path: string; readonly records: number; readonly sha256: string };
  /** ATR rule id -> number of benign records it fired on. Only rules that fired. */
  readonly hits: Readonly<Record<string, number>>;
}

export function parseBenignGate(text: string): BenignGateResult {
  const parsed = JSON.parse(text) as Partial<BenignGateResult>;
  const records = parsed.corpus?.records;
  if (typeof records !== 'number' || records <= 0) throw new Error('benign gate: no corpus.records');
  if (!parsed.hits || typeof parsed.hits !== 'object') throw new Error('benign gate: no hits');
  for (const [id, count] of Object.entries(parsed.hits)) {
    if (!/^ATR-\d{4}-\d{5}$/.test(id)) throw new Error(`benign gate: not an ATR rule id: ${id}`);
    if (!Number.isInteger(count) || count <= 0) throw new Error(`benign gate: bad count for ${id}`);
  }
  return parsed as BenignGateResult;
}

/** Rules to exclude, keyed by ATR id, with the reason the README lists. */
export function benignGateExclusions(gate: BenignGateResult): Map<string, string> {
  const total = gate.corpus.records;
  return new Map(
    Object.entries(gate.hits)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([id, count]) => [id, `benign gate: fires on ${count} of ${total} benign skills in Skill Scanner`]),
  );
}

export function readBenignGate(path: string): Map<string, string> {
  return benignGateExclusions(parseBenignGate(readFileSync(path, 'utf8')));
}
