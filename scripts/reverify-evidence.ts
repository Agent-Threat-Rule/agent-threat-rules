#!/usr/bin/env node
/**
 * reverify-evidence.ts — compare a freshly regenerated benign-FP measurement
 * with the committed one (data/benign-fp-measurement.json), and fail on every
 * difference that means the committed evidence is not true.
 *
 * WHY THIS REPLACED THE INLINE DIFF IN action-eligibility.yml
 *
 * The old step failed on any rule whose committed fp_count !== the fresh one.
 * That folded four different states into one red: a rule added after the
 * evidence was generated, a rule whose detection changed since, a rule deleted
 * since, and the same detection on the same corpus producing a different
 * number. Every completed run (2026-09-25, 10-01, 10-11, 10-13) failed on new
 * rules alone, 32 to 36 of them, all `committed=undefined measured=0`.
 *
 * It also compared fp_count only, which is not all the action gate reads:
 * eligibility uses a record's partial_measurement flag (a 0-FP partial record is
 * unmeasured) and the file's sample_count (the denominator of every rate).
 *
 * THE RULE: A RECORD THE GATE TRUSTS MUST REPRODUCE
 *
 * scripts/gate-action-eligibility.ts trusts a record when its rule is live on
 * disk and the record's detection_fingerprint equals the rule's. Which rules are
 * on disk, and their fingerprints, come from that gate's own reader
 * (readRules), never from a looser listing: an earlier version took "the rule
 * is gone" from the record's absence in the fresh file, and a rule written so
 * a grep for `^id: ATR-` missed it (single quotes, two spaces, a symlink) was
 * both trusted by the gate and never re-measured — its forged record would
 * have been reported as a removed rule forever.
 *
 * FAILS (and never asks for a refresh: a person finds out why first)
 *   - the evidence names a corpus list other than MEASUREMENT_CORPORA
 *   - corpus_digest differs from the fresh one
 *   - sample_count differs
 *   - a trusted record has no fresh counterpart, or the fresh one has another
 *     fingerprint, another fp_count or another partial_measurement
 *
 * REPORTED (and turned into a refresh PR the job opens for review)
 *   - not covered: a fresh record for a rule the evidence has no record of
 *   - detection changed: the record's fingerprint is not the rule's on disk
 *   - removed: a record for a rule id no file on disk carries
 *   - inert: a record for a draft/deprecated rule, which no measurement writes
 *   (the action gate refuses evidence holding either of these two: exit 2)
 *   - metadata: same detection and numbers, stale maturity/skill_path_unmeasured
 *
 * Usage:
 *   reverify-evidence.ts --committed <path> --fresh <path> [--rules <dir>] [--pr-body <path>]
 *   reverify-evidence.ts --list-ids [--rules <dir>]
 * Exit 0 when nothing fails, 1 when the evidence does not reproduce, 2 on a
 * usage or input error. With $GITHUB_OUTPUT set it writes `fail` and
 * `needs-refresh`; with $GITHUB_STEP_SUMMARY set it appends the report.
 */
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { MEASUREMENT_CORPORA } from "../src/quality/action-eligibility.js";
import { isInert, readRules } from "./gate-action-eligibility.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export interface RuleRecord {
  readonly fp_count: number;
  readonly maturity?: string | null;
  readonly detection_fingerprint?: string | null;
  readonly partial_measurement?: boolean;
  readonly skill_path_unmeasured?: boolean;
}

export interface Measurement {
  readonly corpora?: readonly string[];
  readonly corpus_digest?: string;
  readonly sample_count?: number;
  readonly rules: Readonly<Record<string, RuleRecord>>;
}

/** What the classification needs to know about a rule file on disk. */
export interface DiskRule {
  readonly id: string;
  readonly status: string | null;
  readonly maturity: string | null;
  readonly fingerprint: string;
}

export interface RecordChange {
  readonly id: string;
  readonly committed?: RuleRecord;
  readonly fresh?: RuleRecord;
}

export interface EvidenceDiff {
  readonly corporaChanged: boolean;
  readonly corpusMoved: boolean;
  readonly sampleCountChanged: boolean;
  /** Trusted records that did not reproduce. Any entry fails the job. */
  readonly drift: readonly RecordChange[];
  readonly notCovered: readonly RecordChange[];
  readonly detectionChanged: readonly RecordChange[];
  readonly removed: readonly RecordChange[];
  readonly inert: readonly RecordChange[];
  readonly metadata: readonly RecordChange[];
}

/** Thrown when an input file is not a measurement this script can read. */
export class EvidenceInputError extends Error {}

/** The only shape a rule id on disk takes (2026-10-15: 830 of 830). */
const RULE_ID = /^ATR-\d{4}-\d{5}$/;
const HEX = /^[0-9a-f]+$/;

/**
 * Parse and shape-check a measurement file's contents.
 *
 * Strict on purpose. Every string that reaches the report is printed to the job
 * log, where GitHub Actions executes lines that start with `::` as workflow
 * commands, and is written into the refresh PR's body. The committed file is the
 * untrusted side: a key like "ATR-2026-00001\n::warning::..." or a line
 * addressed to a reviewer would otherwise travel through verbatim. Anything that
 * is not a rule id, a hex digest or a count is an input error, so the step fails
 * before it prints. The parse error itself is quoted with JSON.stringify for the
 * same reason: V8 echoes the characters around the error position.
 */
export function parseMeasurement(text: string, label: string): Measurement {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    throw new EvidenceInputError(`${label}: not JSON (${JSON.stringify((e as Error).message)})`);
  }
  const rules = (doc as { rules?: unknown } | null)?.rules;
  if (rules === null || typeof rules !== "object" || Array.isArray(rules)) {
    throw new EvidenceInputError(`${label}: no "rules" object`);
  }
  const top = doc as { corpora?: unknown; corpus_digest?: unknown; sample_count?: unknown };
  if (
    top.corpora !== undefined &&
    (!Array.isArray(top.corpora) || !top.corpora.every((c) => typeof c === "string"))
  ) {
    throw new EvidenceInputError(`${label}: corpora is not a list of paths`);
  }
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

/** The rule files on disk, as the action gate reads them. */
export function diskRules(rulesDir: string): readonly DiskRule[] {
  return readRules(rulesDir).map(({ id, status, maturity, fingerprint }) => ({
    id,
    status,
    maturity,
    fingerprint,
  }));
}

const sameNumbers = (a: RuleRecord, b: RuleRecord): boolean =>
  a.fp_count === b.fp_count &&
  (a.partial_measurement === true) === (b.partial_measurement === true);

const sameMetadata = (a: RuleRecord, b: RuleRecord): boolean =>
  (a.maturity ?? null) === (b.maturity ?? null) &&
  (a.skill_path_unmeasured === true) === (b.skill_path_unmeasured === true);

const sameRecord = (a: RuleRecord, b: RuleRecord): boolean =>
  sameNumbers(a, b) &&
  sameMetadata(a, b) &&
  (a.detection_fingerprint ?? null) === (b.detection_fingerprint ?? null);

/** Sort every committed and fresh record into at most one bucket. */
export function classifyEvidence(
  committed: Measurement,
  fresh: Measurement,
  disk: readonly DiskRule[],
  canonicalCorpora: readonly string[] = MEASUREMENT_CORPORA,
): EvidenceDiff {
  const onDisk = new Set(disk.map((r) => r.id));
  const live = new Map<string, DiskRule[]>();
  for (const r of disk) {
    if (isInert(r.status, r.maturity)) continue;
    live.set(r.id, [...(live.get(r.id) ?? []), r]);
  }

  const drift: RecordChange[] = [];
  const notCovered: RecordChange[] = [];
  const detectionChanged: RecordChange[] = [];
  const removed: RecordChange[] = [];
  const inert: RecordChange[] = [];
  const metadata: RecordChange[] = [];

  const ids = [...new Set([...Object.keys(committed.rules), ...Object.keys(fresh.rules)])].sort();
  for (const id of ids) {
    const c = Object.hasOwn(committed.rules, id) ? committed.rules[id] : undefined;
    const f = Object.hasOwn(fresh.rules, id) ? fresh.rules[id] : undefined;
    if (c === undefined) {
      if (f !== undefined) notCovered.push({ id, fresh: f });
      continue;
    }
    if (!onDisk.has(id)) {
      removed.push({ id, committed: c, fresh: f });
      continue;
    }
    const liveRules = live.get(id);
    if (liveRules === undefined) {
      // Only inert rules carry this id. No measurement records one, and the action
      // gate refuses evidence that holds such a record; the refresh drops it.
      if (f === undefined || !sameRecord(c, f)) inert.push({ id, committed: c, fresh: f });
      continue;
    }
    const trusted = liveRules.some((r) => r.fingerprint === (c.detection_fingerprint ?? null));
    if (!trusted) {
      detectionChanged.push({ id, committed: c, fresh: f });
      continue;
    }
    if (
      f === undefined ||
      (f.detection_fingerprint ?? null) !== (c.detection_fingerprint ?? null) ||
      !sameNumbers(c, f)
    ) {
      drift.push({ id, committed: c, fresh: f });
    } else if (!sameMetadata(c, f)) {
      metadata.push({ id, committed: c, fresh: f });
    }
  }

  return {
    corporaChanged: JSON.stringify(committed.corpora ?? null) !== JSON.stringify(canonicalCorpora),
    corpusMoved: committed.corpus_digest !== fresh.corpus_digest,
    sampleCountChanged: committed.sample_count !== fresh.sample_count,
    drift,
    notCovered,
    detectionChanged,
    removed,
    inert,
    metadata,
  };
}

/** Fail when the committed evidence does not reproduce. */
export function evidenceFails(d: EvidenceDiff): boolean {
  return d.corporaChanged || d.corpusMoved || d.sampleCountChanged || d.drift.length > 0;
}

/**
 * Ask for a refresh PR only when the evidence reproduces but is stale. Never
 * after a failure: regenerating over numbers that did not reproduce, or over a
 * corpus claim that does not hold, would erase the evidence of what happened.
 */
export function needsRefresh(d: EvidenceDiff): boolean {
  if (evidenceFails(d)) return false;
  return (
    d.notCovered.length +
      d.detectionChanged.length +
      d.removed.length +
      d.inert.length +
      d.metadata.length >
    0
  );
}

const rec = (r: RuleRecord | undefined): string =>
  r === undefined ? "no record" : `fp_count=${r.fp_count}${r.partial_measurement === true ? " (partial)" : ""}`;

function section(title: string, lines: readonly string[], cap = 50): string[] {
  if (lines.length === 0) return [];
  const shown = lines.slice(0, cap).map((l) => `- ${l}`);
  if (lines.length > cap) shown.push(`- ... and ${lines.length - cap} more`);
  return [``, `${title} (${lines.length})`, ``, ...shown];
}

/** A plain-text report, used for the job summary and the refresh PR body. */
export function renderReport(d: EvidenceDiff, committed: Measurement, fresh: Measurement): string {
  const out: string[] = [];
  if (d.corporaChanged) {
    out.push(
      `FAIL: the committed evidence names a corpus list other than the canonical one. ` +
        `The gate recomputes the digest over the list the file names, so an edited list ` +
        `can make an edited digest look valid. Treat it as tampering until shown otherwise.`,
    );
  }
  if (d.corpusMoved) {
    out.push(
      `FAIL: the committed evidence was measured on a different corpus ` +
        `(recorded ${String(committed.corpus_digest)}, on disk ${String(fresh.corpus_digest)}). ` +
        `Find out how a corpus change reached main without its re-measurement before regenerating.`,
    );
  }
  if (d.sampleCountChanged) {
    out.push(
      `FAIL: different sample count (committed ${String(committed.sample_count)}, ` +
        `measured ${String(fresh.sample_count)}). Every FP rate uses this denominator.`,
    );
  }
  if (d.drift.length > 0) {
    out.push(
      `FAIL: ${d.drift.length} record(s) the action gate trusts did not reproduce. Either the ` +
        `file was edited or the measurement is not deterministic; find out which before ` +
        `regenerating it.`,
    );
  }
  if (!evidenceFails(d)) {
    out.push(
      `Evidence reproduces: every record the action gate trusts matches the fresh measurement ` +
        `(${Object.keys(fresh.rules).length} rules measured, ${String(fresh.sample_count)} samples).`,
    );
  }
  out.push(
    ...section(
      "Trusted records that did not reproduce",
      d.drift.map((x) => {
        const fp = x.fresh !== undefined && (x.fresh.detection_fingerprint ?? null) !== (x.committed?.detection_fingerprint ?? null)
          ? " (measured a different detection)"
          : "";
        return `${x.id}: committed ${rec(x.committed)}, measured ${rec(x.fresh)}${fp}`;
      }),
    ),
    ...section(
      "Not covered — no record yet; the action gate caps these at observe",
      d.notCovered.map((x) => `${x.id}: measured ${rec(x.fresh)}`),
    ),
    ...section(
      "Detection changed since the record — the action gate treats these as unmeasured",
      d.detectionChanged.map((x) => `${x.id}: recorded ${rec(x.committed)}, measured now ${rec(x.fresh)}`),
    ),
    ...section(
      "Records for rule ids no file on disk carries — the action gate refuses evidence that holds one; this refresh drops them",
      d.removed.map((x) => `${x.id}: recorded ${rec(x.committed)}`),
    ),
    ...section(
      "Records for draft or deprecated rules — no measurement writes these, and the action gate refuses evidence that holds one; this refresh drops them",
      d.inert.map((x) => `${x.id}: recorded ${rec(x.committed)}, measured now ${rec(x.fresh)}`),
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
  let rulesDir: string;
  try {
    rulesDir = argValue(argv, "--rules") ?? join(REPO_ROOT, "rules");
  } catch (e) {
    console.error(`[reverify] ${(e as Error).message}`);
    return 2;
  }

  if (argv.includes("--list-ids")) {
    // The ids the action gate reads, for the measurement step to measure. An id
    // the evidence parser would refuse is named here, with its file, rather than
    // surfacing later as an unreadable measurement.
    const rules = readRules(rulesDir);
    const bad = rules.filter((r) => !RULE_ID.test(r.id));
    if (bad.length > 0) {
      for (const r of bad) console.error(`[reverify] ${r.file}: id ${JSON.stringify(r.id).slice(0, 40)} is not ATR-YYYY-NNNNN`);
      return 2;
    }
    const ids = [...new Set(rules.map((r) => r.id))].sort();
    if (ids.length === 0) {
      console.error(`[reverify] no rule files under ${rulesDir}`);
      return 2;
    }
    process.stdout.write(`${ids.join("\n")}\n`);
    return 0;
  }

  let committed: Measurement;
  let fresh: Measurement;
  let prBody: string | null;
  try {
    const committedPath = argValue(argv, "--committed");
    const freshPath = argValue(argv, "--fresh");
    prBody = argValue(argv, "--pr-body");
    if (committedPath === null || freshPath === null) {
      throw new EvidenceInputError(
        "usage: reverify-evidence.ts --committed <path> --fresh <path> [--rules <dir>] [--pr-body <path>]",
      );
    }
    committed = parseMeasurement(readFileSync(committedPath, "utf-8"), committedPath);
    fresh = parseMeasurement(readFileSync(freshPath, "utf-8"), freshPath);
  } catch (e) {
    console.error(`[reverify] ${(e as Error).message}`);
    return 2;
  }

  const diff = classifyEvidence(committed, fresh, diskRules(rulesDir));
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
