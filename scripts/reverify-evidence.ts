#!/usr/bin/env node
/**
 * reverify-evidence.ts — compare a freshly regenerated benign-FP measurement
 * with the committed one (data/benign-fp-measurement.json), and fail only on a
 * difference that means the committed evidence is not true.
 *
 * WHY THIS REPLACED THE INLINE DIFF IN action-eligibility.yml
 *
 * The old step failed on any rule whose committed fp_count !== the fresh one.
 * That folded four different states into one red:
 *
 *   - a rule added after the evidence was generated (committed: undefined)
 *   - a rule whose detection changed since (its record describes old regexes)
 *   - a rule deleted since (the record outlives the rule)
 *   - the same detection on the same corpus producing a different number
 *
 * Only the last one is evidence that the file was edited by hand or that the
 * measurement is not deterministic. The first three are coverage: the action
 * gate (scripts/gate-action-eligibility.ts) already treats a missing record and a
 * fingerprint mismatch as UNMEASURED and caps the rule at the observe tier, on
 * every PR. Every completed run of the old step (2026-09-25, 10-01, 10-11, 10-13)
 * failed on new rules alone — 32 to 36 of them, all `committed=undefined
 * measured=0` — so the check red-flagged every day and said nothing.
 *
 * It also compared fp_count only, which is not all the action gate reads.
 * Eligibility uses the record's partial_measurement flag (a 0-FP partial
 * measurement counts as unmeasured) and the file's sample_count (the denominator
 * of every FP rate). Flipping the flag, or inflating the denominator to dilute a
 * rate below the 0.5% ceiling, raised a rule's permitted tier without touching a
 * single fp_count, and the old diff could not see either.
 *
 * WHAT FAILS
 *   - corpus_digest differs: the evidence does not describe this corpus
 *   - sample_count differs on the same corpus
 *   - same corpus, same detection fingerprint, different fp_count or
 *     partial_measurement
 *
 * WHAT IS REPORTED (and makes the job open a refresh PR, never fail)
 *   - not covered: rules the evidence has no record for
 *   - detection changed: the record's fingerprint is not the rule's
 *   - removed: records for rules no longer on disk
 *   - metadata: same detection and numbers, but a field nothing gates on
 *     (the record's maturity, skill_path_unmeasured) is stale
 *
 * A moved corpus fails AND asks for a refresh: regenerating is the fix, and the
 * refresh PR is reviewed like any other.
 *
 * Usage:
 *   reverify-evidence.ts --committed <path> --fresh <path> [--pr-body <path>]
 * Exit 0 when nothing fails (whether or not a refresh is needed), 1 when the
 * evidence does not reproduce, 2 on a usage or input error. With $GITHUB_OUTPUT
 * set it writes `fail` and `needs-refresh`; with $GITHUB_STEP_SUMMARY set it
 * appends the report there.
 */
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export interface RuleRecord {
  readonly fp_count: number;
  readonly maturity?: string | null;
  readonly detection_fingerprint?: string | null;
  readonly partial_measurement?: boolean;
  readonly skill_path_unmeasured?: boolean;
}

export interface Measurement {
  readonly corpus_digest?: string;
  readonly sample_count?: number;
  readonly rules: Readonly<Record<string, RuleRecord>>;
}

export interface CountChange {
  readonly id: string;
  readonly committed: RuleRecord;
  readonly fresh: RuleRecord;
}

export interface EvidenceDiff {
  readonly corpusMoved: boolean;
  readonly sampleCountChanged: boolean;
  /** Same corpus, same detection, different fp_count / partial_measurement. */
  readonly drift: readonly CountChange[];
  readonly notCovered: readonly { readonly id: string; readonly fresh: RuleRecord }[];
  readonly detectionChanged: readonly CountChange[];
  readonly removed: readonly { readonly id: string; readonly committed: RuleRecord }[];
  readonly metadata: readonly CountChange[];
}

/** Thrown when an input file is not a measurement this script can read. */
export class EvidenceInputError extends Error {}

/** The only shape a rule id on disk takes (`grep '^id:'` over rules/, 2026-10-15: 830/830). */
const RULE_ID = /^ATR-\d{4}-\d{5}$/;
const HEX = /^[0-9a-f]+$/;

/**
 * Parse and shape-check a measurement file's contents.
 *
 * Strict on purpose. Every string that reaches the report — rule ids, the corpus
 * digest — is printed to the job log, where GitHub Actions executes lines that
 * start with `::` as workflow commands, and is written into the refresh PR's
 * body. The committed file is the untrusted side: a key like
 * "ATR-2026-00001\n::warning::..." or a body line addressed to a reviewer would
 * otherwise travel through verbatim. Anything that is not a rule id, a hex
 * digest or a count is an input error, so the step fails before it prints.
 */
export function parseMeasurement(text: string, label: string): Measurement {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    throw new EvidenceInputError(`${label}: not JSON (${(e as Error).message})`);
  }
  const rules = (doc as { rules?: unknown } | null)?.rules;
  if (rules === null || typeof rules !== "object" || Array.isArray(rules)) {
    throw new EvidenceInputError(`${label}: no "rules" object`);
  }
  const top = doc as { corpus_digest?: unknown; sample_count?: unknown };
  if (top.corpus_digest !== undefined && (typeof top.corpus_digest !== "string" || !HEX.test(top.corpus_digest))) {
    throw new EvidenceInputError(`${label}: corpus_digest is not a hex digest`);
  }
  if (
    top.sample_count !== undefined &&
    (typeof top.sample_count !== "number" || !Number.isSafeInteger(top.sample_count) || top.sample_count < 0)
  ) {
    throw new EvidenceInputError(`${label}: sample_count is not a non-negative integer`);
  }
  // Object.keys, not for...in: an own "__proto__" key from JSON.parse is listed
  // here and fails the id check like any other junk key.
  for (const id of Object.keys(rules as Record<string, unknown>)) {
    if (!RULE_ID.test(id)) {
      throw new EvidenceInputError(`${label}: a key in "rules" is not a rule id (${JSON.stringify(id).slice(0, 40)}...)`);
    }
    const rec = (rules as Record<string, unknown>)[id] as Record<string, unknown> | null;
    const n = rec?.fp_count;
    if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 0) {
      throw new EvidenceInputError(`${label}: ${id} has no valid fp_count`);
    }
    const fp = rec?.detection_fingerprint;
    if (fp !== undefined && fp !== null && (typeof fp !== "string" || !HEX.test(fp))) {
      throw new EvidenceInputError(`${label}: ${id} has a detection_fingerprint that is not hex`);
    }
  }
  return doc as Measurement;
}

const sameNumbers = (a: RuleRecord, b: RuleRecord): boolean =>
  a.fp_count === b.fp_count &&
  (a.partial_measurement === true) === (b.partial_measurement === true);

const sameMetadata = (a: RuleRecord, b: RuleRecord): boolean =>
  (a.maturity ?? null) === (b.maturity ?? null) &&
  (a.skill_path_unmeasured === true) === (b.skill_path_unmeasured === true);

/** Sort every committed/fresh record into exactly one bucket (or none, if equal). */
export function classifyEvidence(committed: Measurement, fresh: Measurement): EvidenceDiff {
  const drift: CountChange[] = [];
  const notCovered: { id: string; fresh: RuleRecord }[] = [];
  const detectionChanged: CountChange[] = [];
  const removed: { id: string; committed: RuleRecord }[] = [];
  const metadata: CountChange[] = [];
  const ids = [...new Set([...Object.keys(committed.rules), ...Object.keys(fresh.rules)])].sort();
  for (const id of ids) {
    const c = committed.rules[id];
    const f = fresh.rules[id];
    if (c === undefined && f !== undefined) notCovered.push({ id, fresh: f });
    else if (f === undefined && c !== undefined) removed.push({ id, committed: c });
    else if (c !== undefined && f !== undefined) {
      if ((c.detection_fingerprint ?? null) !== (f.detection_fingerprint ?? null)) {
        detectionChanged.push({ id, committed: c, fresh: f });
      } else if (!sameNumbers(c, f)) {
        drift.push({ id, committed: c, fresh: f });
      } else if (!sameMetadata(c, f)) {
        metadata.push({ id, committed: c, fresh: f });
      }
    }
  }
  return {
    corpusMoved: committed.corpus_digest !== fresh.corpus_digest,
    sampleCountChanged: committed.sample_count !== fresh.sample_count,
    drift,
    notCovered,
    detectionChanged,
    removed,
    metadata,
  };
}

/** Fail when the committed evidence does not reproduce. */
export function evidenceFails(d: EvidenceDiff): boolean {
  if (d.corpusMoved) return true;
  return d.sampleCountChanged || d.drift.length > 0;
}

/**
 * Ask for a refresh PR when the evidence is stale but not contradicted. Never on
 * a reproduction failure on an unchanged corpus: that needs a person to find out
 * why before anything regenerates the numbers over it.
 */
export function needsRefresh(d: EvidenceDiff): boolean {
  if (d.corpusMoved) return true;
  if (evidenceFails(d)) return false;
  return (
    d.notCovered.length + d.detectionChanged.length + d.removed.length + d.metadata.length > 0
  );
}

const rec = (r: RuleRecord): string =>
  `fp_count=${r.fp_count}${r.partial_measurement === true ? " (partial)" : ""}`;

function section(title: string, lines: readonly string[], cap = 50): string[] {
  if (lines.length === 0) return [];
  const shown = lines.slice(0, cap).map((l) => `- ${l}`);
  if (lines.length > cap) shown.push(`- ... and ${lines.length - cap} more`);
  return [``, `${title} (${lines.length})`, ``, ...shown];
}

/** A plain-text report, used for the job summary and the refresh PR body. */
export function renderReport(d: EvidenceDiff, committed: Measurement, fresh: Measurement): string {
  const out: string[] = [];
  if (d.corpusMoved) {
    out.push(
      `FAIL: the committed evidence was measured on a different corpus ` +
        `(recorded ${String(committed.corpus_digest)}, on disk ${String(fresh.corpus_digest)}).`,
    );
  } else if (d.sampleCountChanged) {
    out.push(
      `FAIL: same corpus, different sample count (committed ${String(committed.sample_count)}, ` +
        `measured ${String(fresh.sample_count)}). Every FP rate uses this denominator.`,
    );
  }
  if (!d.corpusMoved && d.drift.length > 0) {
    out.push(
      `FAIL: ${d.drift.length} rule(s) whose committed numbers do not reproduce on the same ` +
        `corpus with the same detection. Either the file was edited or the measurement is not ` +
        `deterministic; find out which before regenerating it.`,
    );
  }
  if (!evidenceFails(d)) {
    out.push(
      `Evidence reproduces: every record with a current detection fingerprint matches ` +
        `the fresh measurement (${Object.keys(fresh.rules).length} rules, ` +
        `${String(fresh.sample_count)} samples).`,
    );
  }
  out.push(
    ...section(
      d.corpusMoved ? "Counts that moved with the corpus" : "Did not reproduce",
      d.drift.map((x) => `${x.id}: committed ${rec(x.committed)}, measured ${rec(x.fresh)}`),
    ),
    ...section(
      "Not covered — no record yet; the action gate caps these at observe",
      d.notCovered.map((x) => `${x.id}: measured ${rec(x.fresh)}`),
    ),
    ...section(
      "Detection changed since the record — the action gate treats these as unmeasured",
      d.detectionChanged.map(
        (x) => `${x.id}: recorded ${rec(x.committed)}, measured now ${rec(x.fresh)}`,
      ),
    ),
    ...section(
      "Records for rules no longer on disk",
      d.removed.map((x) => `${x.id}: recorded ${rec(x.committed)}`),
    ),
    ...section(
      "Stale record metadata (maturity / skill_path_unmeasured; not used for eligibility)",
      d.metadata.map((x) => x.id),
    ),
  );
  return `${out.join("\n")}\n`;
}

function argValue(argv: readonly string[], name: string): string | null {
  const i = argv.indexOf(name);
  if (i < 0) return null;
  const v = argv[i + 1];
  if (v === undefined || v.startsWith("--")) throw new EvidenceInputError(`${name} requires a value`);
  return v;
}

export function main(argv: readonly string[], env: NodeJS.ProcessEnv = process.env): number {
  let committed: Measurement;
  let fresh: Measurement;
  let prBody: string | null;
  try {
    const committedPath = argValue(argv, "--committed");
    const freshPath = argValue(argv, "--fresh");
    prBody = argValue(argv, "--pr-body");
    if (committedPath === null || freshPath === null) {
      throw new EvidenceInputError("usage: reverify-evidence.ts --committed <path> --fresh <path> [--pr-body <path>]");
    }
    committed = parseMeasurement(readFileSync(committedPath, "utf-8"), committedPath);
    fresh = parseMeasurement(readFileSync(freshPath, "utf-8"), freshPath);
  } catch (e) {
    console.error(`[reverify] ${(e as Error).message}`);
    return 2;
  }

  const diff = classifyEvidence(committed, fresh);
  const fails = evidenceFails(diff);
  const refresh = needsRefresh(diff);
  const report = renderReport(diff, committed, fresh);
  (fails ? console.error : console.log)(report);
  if (prBody !== null) writeFileSync(prBody, report, "utf-8");
  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, `${report}\n`);
  if (env.GITHUB_OUTPUT) {
    appendFileSync(env.GITHUB_OUTPUT, `fail=${fails}\nneeds-refresh=${refresh}\n`);
  }
  return fails ? 1 : 0;
}

const INVOKED_DIRECTLY =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) {
  process.exitCode = main(process.argv.slice(2));
}
