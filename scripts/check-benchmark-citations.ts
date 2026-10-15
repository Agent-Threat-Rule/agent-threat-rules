#!/usr/bin/env npx tsx
/**
 * scripts/check-benchmark-citations.ts
 *
 * Assert that the two HAND-EDITED surfaces which quote benchmark numbers —
 * README.md's benchmark table and the root `stats.json` `benchmarks` block —
 * agree with the version-pinned measurement files under `data/measurements/`.
 *
 * WHY THIS EXISTS
 *
 * The repo already had a gate for this: `sync-stats-from-measurements.ts
 * --check`, run by eval.yml. But it only compares `data/stats.json`'s
 * `benchmarks[]` against `data/measurements/<source>/latest.json`. Nothing
 * compared the two surfaces a human actually edits, and root `stats.json` is
 * the file `sync-stats.ts` propagates into README badges, CITATION.cff, the
 * docs site and the schema.org JSON-LD.
 *
 * On 2026-08-04, PR #370 ("correct garak recall 95.7%->91.5%") changed root
 * stats.json, README.md, and two report JSONs — and produced no measurement
 * file. `--check` stayed green because it never looked at either file it
 * changed. The result shipped to main: README and root stats.json cited
 * 91.5% at ATR 3.5.11, while `data/measurements/garak/latest.json` and
 * `data/stats.json` both said 95.69% at 3.5.8, and no file on disk contained
 * a 91.5% garak run at all. The repo's own invariant — every external number
 * is a version-pinned, reproducible measurement — was violated by the surface
 * the outside world reads.
 *
 * Usage:
 *   npx tsx scripts/check-benchmark-citations.ts          # exit 1 on mismatch
 *
 * Exit codes: 0 = every citation is backed by a measurement file. 1 = at
 * least one cited number, ATR version, or measurement date has no file behind
 * it (or the table could not be parsed at all, which is also a failure — a
 * checker that silently checks nothing is the bug it is here to prevent).
 */

import { existsSync, readFileSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { ENFORCE_LANE_BREAKDOWN_KEY, parseEnforceLaneRecall } from "../src/measurement/schema.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const README_PATH = resolve(REPO_ROOT, "README.md");
const ROOT_STATS_PATH = resolve(REPO_ROOT, "stats.json");
const DATA_STATS_PATH = resolve(REPO_ROOT, "data", "stats.json");

/**
 * README's first column is a human label; the measurement's identity is its
 * `source`. The mapping is explicit on purpose — a row whose label is not
 * listed here fails the check rather than being skipped, because "I did not
 * recognise this row" and "this row is fine" must never produce the same
 * output.
 */
export const LABEL_TO_SOURCE: ReadonlyMap<string, string> = new Map([
  ["AdvBench (LLM-attacks behaviors)", "advbench"],
  ["atr-self-test", "atr-self-test"],
  ["autoresearch", "autoresearch"],
  ["garak (in-the-wild jailbreaks)", "garak"],
  ["garak-full (all probe families)", "garak-full"],
  ["hackaprompt", "hackaprompt"],
  ["HarmBench (CAIS behaviors)", "harmbench"],
  ["hh-rlhf (Anthropic red-team-attempts)", "hh-rlhf"],
  ["JailbreakBench (JBB-Behaviors)", "jailbreakbench"],
  ["llm-guard (Protect AI test fixtures)", "llm-guard"],
  ["MITRE ATLAS", "mitre-atlas"],
  ["NeMo Guardrails (NVIDIA test fixtures)", "nemo-guardrails"],
  ["OWASP LLM Top 10", "owasp-llm-top10"],
  ["PINT-format (deepset + Lakera Gandalf)", "pint"],
  ["PromptBench (academic adversarial)", "promptbench"],
  ["promptfoo (red-team plugin fixtures)", "promptfoo"],
  ["PromptInject (academic adversarial)", "promptinject"],
  ["SKILL.md benchmark (internal)", "skill-benchmark"],
  ["Wild scan (OpenClaw + Skills.sh + Hermes + ClawHub)", "wild-scan"],
]);

/**
 * Rows whose cells are deliberately not a plain recall/precision projection.
 * `wild-scan` reports a precision FLOOR and a flag rate over a 96k unlabelled
 * corpus; there is no recall to compare because nothing labelled the negatives.
 * Listed by source so the exemption is visible instead of implicit.
 */
export const EXEMPT_SOURCES: ReadonlySet<string> = new Set(["wild-scan"]);

export interface BenchmarkEntry {
  source: string;
  source_version: string;
  atr_version: string;
  measured_at: string;
  samples: number;
  recall: number | null;
  precision: number | null;
  fp_rate: number | null;
}

export interface TableRow {
  label: string;
  sourceVersion: string;
  samples: string;
  recall: string;
  atrVersion: string;
  measured: string;
  lineNo: number;
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf-8"));
}

/**
 * Compare a README recall cell against the measurement.
 *
 * Recall is lane-dependent, and quoting one number without the lane can be
 * catastrophically misleading: the headline garak corpus scores 600/650 in
 * `hunt` and 6/650 in `enforce` (ATR 4.1.5), and someone reading only the
 * first would deploy auto-block expecting detection that is structurally
 * absent. So a measurement records both — `metrics.recall` (hunt) and
 * `breakdown.enforce_lane` — and the cell cites both:
 *
 *     92.3% (hunt) / 0.9% (enforce)
 *     100.0%                          (only while no measurement records an enforce figure)
 *
 * The rules, each closing a way to publish a number nothing backs:
 *
 *   1. The first figure equals the measured hunt recall. Not "any figure":
 *      `42.0% (hunt) / 92.3% (enforce)` contains the number but attaches it to
 *      the wrong lane.
 *   2. With more than one figure, every figure is lane-annotated, so "add a
 *      second number until one matches" cannot launder a wrong one.
 *   3. The first figure is the hunt lane, and the only other lane cited is
 *      `enforce`: no run measures `alert`.
 *   4. When the measurement records an enforce figure the cell cites it, at
 *      the recorded value (pctLane), and the hunt figure never stands alone.
 *      When it records none, the cell cites none.
 */
export function checkRecallCell(cell: string, measured: number, enforce: number | null = null): string | null {
  const want = pct1(measured);
  const values = [...cell.matchAll(/(\d+(?:\.\d+)?%)(\s*\(([a-z-]+)\))?/g)];
  if (values.length === 0) return `recall ${cell} is not a percentage`;
  if (values.length > 1 && values.some((m) => m[3] === undefined)) {
    return (
      `recall ${cell} lists ${values.length} values but not all are lane-annotated — ` +
      `write each as "N% (lane)" so a reader knows which lane each number belongs to`
    );
  }
  if (values[0][1] !== want) {
    return `recall ${cell} leads with ${values[0][1]}, but the measurement is ${want}`;
  }
  const leadLane = values[0][3];
  if (leadLane !== undefined && leadLane !== "hunt") {
    return `recall ${cell} labels its leading figure ${leadLane}, but the measured headline is the hunt lane`;
  }
  const others = values.slice(1);
  const unmeasured = others.find((m) => m[3] !== "enforce");
  if (unmeasured !== undefined) {
    return `recall ${cell} cites a ${unmeasured[3]}-lane figure; no measurement records that lane beside the headline`;
  }
  if (enforce === null) {
    return others.length === 0
      ? null
      : `recall ${cell} cites an enforce-lane figure, but the measurement records none (breakdown.enforce_lane)`;
  }
  const recorded = pctLane(enforce);
  if (others.length === 0) {
    return (
      `recall ${cell} omits the enforce-lane figure the measurement records (${recorded}); ` +
      `write "${want} (hunt) / ${recorded} (enforce)"`
    );
  }
  if (others.length > 1 || others[0][1] !== recorded) {
    return `recall ${cell} cites ${others.map((m) => m[1]).join(", ")} for the enforce lane, but the measurement records ${recorded}`;
  }
  return null;
}

const MAX_DECIMALS = 8;

/**
 * Decimals needed so a non-zero rate never reads 0% and a rate below one never
 * reads 100%: a 0.04% figure written as "0.0%" is a claim of none.
 */
export function decimalsFor(value: number, min: number): number {
  const shown = (d: number) => Number((value * 100).toFixed(d));
  let d = min;
  while (d < MAX_DECIMALS && ((value !== 0 && shown(d) === 0) || (value !== 1 && shown(d) === 100))) d += 1;
  return d;
}

/**
 * An enforce-lane recall as README cites it: one decimal, more when one would
 * read a non-zero figure as 0% (1 of 3,475 is `0.03%`, not `0.0%`). Enforce
 * figures sit near zero, where pct1 would erase exactly what they disclose.
 */
export function pctLane(n: number): string {
  return `${(n * 100).toFixed(decimalsFor(n, 1))}%`;
}

/** The same figure as stats.json's `enforceLaneRecall` carries it, in percent. */
export function pctLaneNumber(n: number): number {
  return Number((n * 100).toFixed(decimalsFor(n, 1)));
}

/** `0.915` -> `"91.5%"`, matching how the README table renders a recall. */
export function pct1(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

/**
 * Pull the benchmark table out of README. Returns [] if the header row is not
 * found — callers treat that as a hard failure, not an empty pass.
 */
/**
 * Drop `[^name]` footnote references from a table cell.
 *
 * Not a cosmetic trim: the footnote is how a row carries its caveat (scope,
 * lane, corpus provenance), so rows acquire and lose them as the honesty of a
 * number is worked out. Keying the source map on a label that includes the
 * marker would mean every new caveat silently un-maps its own row -- and an
 * un-mapped row is a number nothing checks, which is the failure this script
 * exists to prevent.
 */
export function stripFootnoteRefs(cell: string): string {
  return cell.replace(/\s*\[\^[^\]]+\]/g, "").trim();
}

export function parseBenchmarkTable(readme: string): TableRow[] {
  const lines = readme.split("\n");
  const headerIdx = lines.findIndex((l) =>
    /^\|\s*Source\s*\|\s*Source version\s*\|\s*Samples\s*\|\s*Recall\s*\|/.test(l),
  );
  if (headerIdx === -1) return [];

  const rows: TableRow[] = [];
  // headerIdx + 1 is the |---|---| separator.
  for (let i = headerIdx + 2; i < lines.length; i++) {
    const line = lines[i];
    if (!line.startsWith("|")) break;
    const cells = line
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    if (cells.length < 8) continue;
    rows.push({
      // Footnote references are stripped so LABEL_TO_SOURCE stays keyed on the
      // stable human name. A row gains a `[^pint]`-style marker whenever a
      // caveat is documented -- which is exactly when this check matters most,
      // and it must not be the thing that breaks the mapping and forces the
      // label into the map twice.
      label: stripFootnoteRefs(cells[0]),
      sourceVersion: cells[1],
      samples: cells[2],
      recall: cells[3],
      atrVersion: cells[6],
      measured: cells[7],
      lineNo: i + 1,
    });
  }
  return rows;
}

/** The slice of root `stats.json` this check reads. */
export interface RootStats {
  benchmarks?: Record<
    string,
    { recall?: number; samples?: number; atr_version?: string; measured?: string; enforceLaneRecall?: number }
  >;
}

/** Root stats.json blocks and the measurement source each one cites. */
export const ROOT_BLOCK_SOURCES: ReadonlyMap<string, string> = new Map([
  ["garak", "garak"],
  ["pint", "pint"],
  ["skill", "skill-benchmark"],
]);

/**
 * Each source's enforce-lane recall, read from `breakdown.enforce_lane` of the
 * measurement file its benchmarks[] entry names. A source whose measurement
 * records none is absent. A malformed record throws: verify.ts rejects it too.
 */
export function enforceRecallBySource(
  root: string,
  entries: readonly { source: string; measurement_file?: string }[],
): Map<string, number> {
  const out = new Map<string, number>();
  for (const e of entries) {
    if (e.measurement_file === undefined) continue;
    const path = resolve(root, e.measurement_file);
    if (!existsSync(path)) throw new Error(`${e.source}: measurement file ${e.measurement_file} does not exist`);
    const m = JSON.parse(readFileSync(path, "utf-8")) as { breakdown?: Record<string, unknown> };
    const raw = m.breakdown?.[ENFORCE_LANE_BREAKDOWN_KEY];
    if (raw !== undefined) out.set(e.source, parseEnforceLaneRecall(raw).recall);
  }
  return out;
}

export interface CitationCheck {
  /** Set when the check could not run at all; a failure, never a pass. */
  fatal: string | null;
  /** README benchmark rows parsed. */
  rowCount: number;
  problems: string[];
}

/**
 * The whole check over in-memory documents, so a caller that renders the table
 * (scripts/render-benchmark-table.ts) can prove its output against the exact
 * rules this script enforces instead of a copy of them.
 */
export function findCitationProblems(
  readme: string,
  dataStats: { benchmarks?: BenchmarkEntry[] },
  rootStats: RootStats,
  /** Enforce-lane recall per source (enforceRecallBySource); a source not in it records none. */
  enforce: ReadonlyMap<string, number> = new Map(),
): CitationCheck {
  const problems: string[] = [];

  const entries = dataStats.benchmarks ?? [];
  if (entries.length === 0) {
    return { fatal: "FAIL: data/stats.json has no benchmarks[] — nothing to check against.", rowCount: 0, problems };
  }
  const bySource = new Map(entries.map((e) => [e.source, e]));

  // ── README benchmark table ────────────────────────────────────────────────
  const rows = parseBenchmarkTable(readme);
  if (rows.length === 0) {
    return {
      fatal:
        "FAIL: could not find the benchmark table in README.md. Either the table " +
        "was removed or its header changed — fix this parser rather than " +
        "letting the check pass on zero rows.",
      rowCount: 0,
      problems,
    };
  }

  for (const row of rows) {
    const source = LABEL_TO_SOURCE.get(row.label);
    if (source === undefined) {
      problems.push(
        `README.md:${row.lineNo}: benchmark row "${row.label}" is not mapped to a ` +
          `measurement source. Add it to LABEL_TO_SOURCE in ` +
          `scripts/check-benchmark-citations.ts (or to EXEMPT_SOURCES with a reason).`,
      );
      continue;
    }
    if (EXEMPT_SOURCES.has(source)) continue;

    const entry = bySource.get(source);
    if (entry === undefined) {
      problems.push(
        `README.md:${row.lineNo}: cites source "${source}" but data/stats.json ` +
          `benchmarks[] has no such entry — so no measurement file backs it.`,
      );
      continue;
    }

    if (row.sourceVersion !== entry.source_version) {
      problems.push(
        `README.md:${row.lineNo} (${source}): source version "${row.sourceVersion}" ` +
          `!= measured "${entry.source_version}"`,
      );
    }
    const samplesNum = Number(row.samples.replace(/,/g, ""));
    if (samplesNum !== entry.samples) {
      problems.push(
        `README.md:${row.lineNo} (${source}): samples ${row.samples} != measured ${entry.samples}`,
      );
    }
    if (entry.recall !== null && row.recall !== "—") {
      const recallProblem = checkRecallCell(row.recall, entry.recall, enforce.get(source) ?? null);
      if (recallProblem !== null) {
        problems.push(
          `README.md:${row.lineNo} (${source}): ${recallProblem} ` +
            `(data/measurements/${source}/latest.json)`,
        );
      }
    }
    if (row.atrVersion !== entry.atr_version) {
      problems.push(
        `README.md:${row.lineNo} (${source}): ATR version ${row.atrVersion} != measured ` +
          `${entry.atr_version}`,
      );
    }
    if (row.measured !== entry.measured_at.slice(0, 10)) {
      problems.push(
        `README.md:${row.lineNo} (${source}): measured ${row.measured} != measurement file ` +
          `date ${entry.measured_at.slice(0, 10)}`,
      );
    }
  }

  const seen = new Set(rows.map((r) => LABEL_TO_SOURCE.get(r.label)).filter(Boolean));
  for (const source of LABEL_TO_SOURCE.values()) {
    if (!seen.has(source)) {
      problems.push(
        `README.md: benchmark table has no row for "${source}", which ` +
          `LABEL_TO_SOURCE says it should. A dropped row is how a number stops ` +
          `being checked.`,
      );
    }
  }

  // ── root stats.json (the file sync-stats.ts propagates everywhere) ─────────
  const garakCite = rootStats.benchmarks?.garak;
  const garakMeasured = bySource.get("garak");
  if (garakCite === undefined) {
    problems.push("stats.json: benchmarks.garak is missing — README badges read this.");
  } else if (garakMeasured === undefined || garakMeasured.recall === null) {
    problems.push("data/stats.json: no garak entry with a recall to check stats.json against.");
  } else {
    const expected = Number((garakMeasured.recall * 100).toFixed(1));
    if (garakCite.recall !== expected) {
      problems.push(
        `stats.json: benchmarks.garak.recall = ${garakCite.recall} but ` +
          `data/measurements/garak/latest.json measured ${expected}`,
      );
    }
    if (garakCite.samples !== garakMeasured.samples) {
      problems.push(
        `stats.json: benchmarks.garak.samples = ${garakCite.samples} but measured ` +
          `${garakMeasured.samples}`,
      );
    }
    if (garakCite.atr_version !== undefined && garakCite.atr_version !== garakMeasured.atr_version) {
      problems.push(
        `stats.json: benchmarks.garak.atr_version = ${garakCite.atr_version} but the ` +
          `measurement was taken on ${garakMeasured.atr_version}`,
      );
    }
    if (
      garakCite.measured !== undefined &&
      garakCite.measured !== garakMeasured.measured_at.slice(0, 10)
    ) {
      problems.push(
        `stats.json: benchmarks.garak.measured = ${garakCite.measured} but the ` +
          `measurement file is dated ${garakMeasured.measured_at.slice(0, 10)}`,
      );
    }
  }

  const pintCite = rootStats.benchmarks?.pint;
  const pintMeasured = bySource.get("pint");
  if (pintCite !== undefined && pintMeasured !== undefined && pintMeasured.recall !== null) {
    const expected = Number((pintMeasured.recall * 100).toFixed(1));
    if (pintCite.recall !== expected) {
      problems.push(
        `stats.json: benchmarks.pint.recall = ${pintCite.recall} but ` +
          `data/measurements/pint/latest.json measured ${expected}`,
      );
    }
    if (pintCite.atr_version !== undefined && pintCite.atr_version !== pintMeasured.atr_version) {
      problems.push(
        `stats.json: benchmarks.pint.atr_version = ${pintCite.atr_version} but the ` +
          `measurement was taken on ${pintMeasured.atr_version}`,
      );
    }
  }

  // An enforce-lane figure next to a headline is only as good as the
  // measurement behind it: skill.enforceLaneRecall was hand-written as 0 for
  // weeks with no run recording it.
  for (const [block, source] of ROOT_BLOCK_SOURCES) {
    const cited = rootStats.benchmarks?.[block]?.enforceLaneRecall;
    if (cited === undefined) continue;
    const recorded = enforce.get(source);
    if (recorded === undefined) {
      problems.push(
        `stats.json: benchmarks.${block}.enforceLaneRecall = ${cited} but data/measurements/${source}/ ` +
          `records no enforce lane (breakdown.enforce_lane)`,
      );
    } else if (cited !== pctLaneNumber(recorded)) {
      problems.push(
        `stats.json: benchmarks.${block}.enforceLaneRecall = ${cited} but the measurement records ` +
          `${pctLaneNumber(recorded)} (data/measurements/${source}/latest.json, breakdown.enforce_lane)`,
      );
    }
  }

  return { fatal: null, rowCount: rows.length, problems };
}

function main(): number {
  const dataStats = readJson(DATA_STATS_PATH) as { benchmarks?: (BenchmarkEntry & { measurement_file?: string })[] };
  const { fatal, rowCount, problems } = findCitationProblems(
    readFileSync(README_PATH, "utf-8"),
    dataStats,
    readJson(ROOT_STATS_PATH) as RootStats,
    enforceRecallBySource(REPO_ROOT, dataStats.benchmarks ?? []),
  );
  if (fatal !== null) {
    console.error(fatal);
    return 1;
  }

  if (problems.length > 0) {
    console.error(`FAIL: ${problems.length} benchmark citation(s) not backed by a measurement file:\n`);
    for (const p of problems) console.error(`  - ${p}`);
    console.error(
      "\nFix by RE-MEASURING (the eval script writes data/measurements/<source>/ and\n" +
        "updates latest.json), then `npx tsx scripts/sync-stats-from-measurements.ts`.\n" +
        "Do NOT hand-edit the cited number to make this pass — that is exactly the\n" +
        "failure this check exists to catch.",
    );
    return 1;
  }

  console.log(
    `benchmark citations OK: ${rowCount} README rows + stats.json all match ` +
      `data/measurements/`,
  );
  return 0;
}

// Imported by scripts/render-benchmark-table.ts and its tests; only a direct
// run checks the repo.
// Real paths on both sides: a script run through a symlink (or macOS's /tmp)
// sees its own URL resolved while argv keeps the path it was called by.
const INVOKED_DIRECTLY =
  process.argv[1] !== undefined &&
  realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) {
  process.exitCode = main();
}
