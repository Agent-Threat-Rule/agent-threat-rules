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

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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
const LABEL_TO_SOURCE: ReadonlyMap<string, string> = new Map([
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
const EXEMPT_SOURCES: ReadonlySet<string> = new Set(["wild-scan"]);

interface BenchmarkEntry {
  source: string;
  source_version: string;
  atr_version: string;
  measured_at: string;
  samples: number;
  recall: number | null;
  precision: number | null;
  fp_rate: number | null;
}

interface TableRow {
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
 * Compare a README recall cell against the measured value.
 *
 * A cell is normally one percentage. It may also be lane-annotated, because
 * recall is lane-dependent and quoting one number without the lane can be
 * catastrophically misleading: the SKILL.md corpus scores 100% in `hunt` and
 * 0% in `enforce`, and someone reading only the first would deploy auto-block
 * expecting detection that is structurally absent.
 *
 *     100.0%
 *     100.0% (hunt) / 0.0% (enforce)
 *
 * Two rules, and the second is the one that keeps this honest:
 *
 *   1. One of the percentages must equal the measurement. Otherwise the cell
 *      is not backed by anything.
 *   2. If the cell carries more than one percentage, EVERY percentage must be
 *      lane-annotated. Without that, "add a second number until one matches"
 *      becomes a way to launder a wrong figure past this check — which is the
 *      exact failure mode the script exists to prevent.
 */
function checkRecallCell(cell: string, measured: number): string | null {
  const want = pct1(measured);
  const values = [...cell.matchAll(/(\d+(?:\.\d+)?%)(\s*\(([a-z-]+)\))?/g)];
  if (values.length === 0) return `recall ${cell} is not a percentage`;
  if (values.length > 1 && values.some((m) => m[3] === undefined)) {
    return (
      `recall ${cell} lists ${values.length} values but not all are lane-annotated — ` +
      `write each as "N% (lane)" so a reader knows which lane each number belongs to`
    );
  }
  // The FIRST value, not any value. `42.0% (hunt) / 100.0% (enforce)` contains
  // the measured number while attaching it to the wrong lane — checking only for
  // presence would wave that through. The measurement is a hunt-lane run (the
  // engine default), and the first value is the one a reader takes as headline,
  // so those two have to be the same number.
  if (values[0][1] !== want) {
    return `recall ${cell} leads with ${values[0][1]}, but the measurement is ${want}`;
  }
  return null;
}

/** `0.915` -> `"91.5%"`, matching how the README table renders a recall. */
function pct1(n: number): string {
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
function stripFootnoteRefs(cell: string): string {
  return cell.replace(/\s*\[\^[^\]]+\]/g, "").trim();
}

function parseBenchmarkTable(readme: string): TableRow[] {
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

function main(): number {
  const problems: string[] = [];

  const dataStats = readJson(DATA_STATS_PATH) as { benchmarks?: BenchmarkEntry[] };
  const entries = dataStats.benchmarks ?? [];
  if (entries.length === 0) {
    console.error("FAIL: data/stats.json has no benchmarks[] — nothing to check against.");
    return 1;
  }
  const bySource = new Map(entries.map((e) => [e.source, e]));

  // ── README benchmark table ────────────────────────────────────────────────
  const readme = readFileSync(README_PATH, "utf-8");
  const rows = parseBenchmarkTable(readme);
  if (rows.length === 0) {
    console.error(
      "FAIL: could not find the benchmark table in README.md. Either the table " +
        "was removed or its header changed — fix this parser rather than " +
        "letting the check pass on zero rows.",
    );
    return 1;
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
      const recallProblem = checkRecallCell(row.recall, entry.recall);
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
  const rootStats = readJson(ROOT_STATS_PATH) as {
    benchmarks?: Record<string, { recall?: number; samples?: number; atr_version?: string; measured?: string }>;
  };
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
    `benchmark citations OK: ${rows.length} README rows + stats.json all match ` +
      `data/measurements/`,
  );
  return 0;
}

process.exitCode = main();
