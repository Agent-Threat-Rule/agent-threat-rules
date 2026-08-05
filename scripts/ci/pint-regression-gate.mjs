#!/usr/bin/env node
/**
 * scripts/ci/pint-regression-gate.mjs
 *
 * Decide whether a freshly-run PINT benchmark regressed against the committed
 * baseline. Called by .github/workflows/rule-quality.yml AFTER
 * `npm run eval:pint` has written a new report.
 *
 * WHY THIS FILE EXISTS
 *
 * The workflow step named "Run PINT eval regression check" did none of the
 * three things its name claims:
 *
 *   1. It ran `npm run eval` — src/eval/run-eval.ts, the internal self-test
 *      harness — not `npm run eval:pint`. PINT never ran.
 *   2. It then read `data/pint-benchmark/pint-eval-report.json`, a file that
 *      is committed to git and that step 1 does not write. So it printed a
 *      report produced by a human, on some earlier commit, on some earlier
 *      rule set.
 *   3. It read `.recall` off that report. The report has no top-level
 *      `recall` — it lives at `.report.overall.recall` — so the step printed
 *      the literal string "PINT recall: undefined" on every run, and wrote
 *      that string into an output nothing downstream ever read.
 *
 * A PINT regression therefore could not fail a PR. This script is the gate
 * that step pretended to be.
 *
 * WHAT IT CHECKS
 *
 *   - The report is FRESH. The caller snapshots the committed report first;
 *     if the fresh report carries the same timestamp, `eval:pint` did not run
 *     and we are reading git again — that is a hard failure, not a pass.
 *   - Recall did not fall more than `--tolerance` below the committed
 *     baseline in data/measurements/pint/latest.json.
 *   - False-positive rate did not rise more than `--tolerance` above it.
 *
 * Deliberately NOT gated here: the p50/p95/p99 latency thresholds the PINT
 * runner applies internally. Those depend on the shared GitHub runner, not on
 * the rules in the PR, and would flake a correctness gate. They are still
 * printed by the runner itself.
 *
 * Usage:
 *   node scripts/ci/pint-regression-gate.mjs \
 *     --report data/pint-benchmark/pint-eval-report.json \
 *     --before /tmp/pint-report-before.json \
 *     --baseline /tmp/pint-baseline.json \
 *     --tolerance 0.02
 *
 * Exit codes: 0 = no regression. 1 = regression, or the report is missing,
 * malformed, or stale (i.e. no measurement actually happened).
 */

import { readFileSync, existsSync } from "node:fs";

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] !== undefined ? process.argv[i + 1] : fallback;
}

function readJson(path, label) {
  if (!existsSync(path)) {
    console.error(`FAIL: ${label} not found at ${path}`);
    process.exit(1);
  }
  try {
    return JSON.parse(readFileSync(path, "utf-8"));
  } catch (err) {
    console.error(`FAIL: ${label} at ${path} is not valid JSON — ${err.message}`);
    process.exit(1);
  }
}

const reportPath = arg("report", "data/pint-benchmark/pint-eval-report.json");
const beforePath = arg("before", "");
const baselinePath = arg("baseline", "data/measurements/pint/latest.json");
const tolerance = Number(arg("tolerance", "0.02"));

if (!Number.isFinite(tolerance) || tolerance < 0) {
  console.error(`FAIL: --tolerance must be a non-negative number, got "${arg("tolerance", "")}"`);
  process.exit(1);
}

const report = readJson(reportPath, "PINT report");
const overall = report?.report?.overall;

if (!overall || typeof overall.recall !== "number" || typeof overall.fpRate !== "number") {
  console.error(
    `FAIL: ${reportPath} has no .report.overall.{recall,fpRate}. ` +
      `The PINT run did not produce a usable report — treat this as a failed ` +
      `measurement, not as a pass.`,
  );
  process.exit(1);
}

// Freshness: the whole point of the old bug was reading a git-committed report.
if (beforePath) {
  const before = readJson(beforePath, "pre-run PINT report snapshot");
  const beforeTs = before?.report?.timestamp;
  const afterTs = report?.report?.timestamp;
  if (beforeTs !== undefined && beforeTs === afterTs) {
    console.error(
      `FAIL: ${reportPath} still carries the pre-run timestamp (${afterTs}). ` +
        `\`npm run eval:pint\` did not rewrite it, so these numbers came out of ` +
        `git, not out of this PR's rules.`,
    );
    process.exit(1);
  }
  console.log(`report freshness OK: ${beforeTs ?? "(none)"} -> ${afterTs}`);
}

const baseline = readJson(baselinePath, "PINT baseline measurement");
const baseRecall = baseline?.metrics?.recall;
const baseFp = baseline?.metrics?.fp_rate;

if (typeof baseRecall !== "number" || typeof baseFp !== "number") {
  console.error(`FAIL: ${baselinePath} has no .metrics.{recall,fp_rate}`);
  process.exit(1);
}

const pct = (n) => `${(n * 100).toFixed(2)}%`;
const recallDrop = baseRecall - overall.recall;
const fpRise = overall.fpRate - baseFp;

console.log(`PINT samples : ${report.report.corpusSize ?? "?"}`);
console.log(`PINT recall  : ${pct(overall.recall)}  (baseline ${pct(baseRecall)}, delta ${recallDrop <= 0 ? "+" : "-"}${pct(Math.abs(recallDrop))})`);
console.log(`PINT fp_rate : ${pct(overall.fpRate)}  (baseline ${pct(baseFp)}, delta ${fpRise >= 0 ? "+" : "-"}${pct(Math.abs(fpRise))})`);
console.log(`tolerance    : ${pct(tolerance)}`);

const violations = [];
if (recallDrop > tolerance) {
  violations.push(
    `recall fell ${pct(recallDrop)} below baseline (${pct(overall.recall)} vs ${pct(baseRecall)}), ` +
      `more than the ${pct(tolerance)} tolerance`,
  );
}
if (fpRise > tolerance) {
  violations.push(
    `false-positive rate rose ${pct(fpRise)} above baseline (${pct(overall.fpRate)} vs ${pct(baseFp)}), ` +
      `more than the ${pct(tolerance)} tolerance`,
  );
}

if (violations.length > 0) {
  console.error("\nPINT REGRESSION:");
  for (const v of violations) console.error(`  - ${v}`);
  console.error(
    "\nIf the change is a deliberate, honest trade (a rule was tightened to kill a\n" +
      "false positive and lost recall with it), re-measure and commit the new\n" +
      "data/measurements/pint/ file in this PR so the baseline moves WITH the\n" +
      "evidence, then re-run.",
  );
  process.exit(1);
}

console.log("\nPINT regression gate: PASS");
