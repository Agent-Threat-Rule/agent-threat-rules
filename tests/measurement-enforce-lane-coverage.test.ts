/**
 * Every source the weekly measurement refreshes records its enforce-lane
 * figure, `breakdown.enforce_lane`, and that figure agrees with the headline it
 * sits beside.
 *
 * WHY THIS FILE EXISTS
 *
 * README's Recall column and root stats.json cite the enforce lane from the
 * measurement files. A runner that stopped recording it would not fail
 * anything on its own: the renderer would simply stop printing the figure, and
 * the table would quietly go back to quoting a hunt-lane number alone — the
 * state this change exists to end (600/650 in hunt, 6/650 in enforce on the
 * headline garak corpus at ATR 4.1.5, with only the first figure published).
 *
 * Checked here, against the files on disk:
 *   - every runner .github/workflows/measure-all.yml calls is listed below,
 *     with the sources it writes, so a new runner has to be classified;
 *   - each of those runners records the enforce lane;
 *   - the measurement each listed source's latest.json points at carries a
 *     valid enforce_lane once it was measured after enforce recording began,
 *     covering the headline's attack samples and detecting no more than the
 *     headline did (the enforce lane loads a subset of the hunt lane's rules).
 */
import { describe, it, expect } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import yaml from "js-yaml";
import { parseEnforceLaneRecall, parseMeasurement } from "../src/measurement/schema.js";

const REPO = resolve(__dirname, "..");
const WORKFLOW = join(REPO, ".github", "workflows", "measure-all.yml");

/** The first measurement run that recorded breakdown.enforce_lane. */
const ENFORCE_RECORDING_SINCE = "2026-10-15";

/** Each command the measure job runs, the file that writes its measurements, and the sources it writes. */
const RUNNERS: ReadonlyArray<{ command: string; file: string; sources: readonly string[] }> = [
  { command: "npm run eval", file: "src/eval/eval-harness.ts", sources: ["atr-self-test"] },
  { command: "npm run eval:pint", file: "src/eval/run-pint-benchmark.ts", sources: ["pint"] },
  { command: "npx tsx src/eval/run-hackaprompt-benchmark.ts", file: "src/eval/run-hackaprompt-benchmark.ts", sources: ["hackaprompt"] },
  { command: "npx tsx src/eval/skill-benchmark.ts", file: "src/eval/skill-benchmark.ts", sources: ["skill-benchmark"] },
  { command: "npx tsx scripts/eval-std-corpora.ts", file: "scripts/eval-std-corpora.ts", sources: ["hh-rlhf", "owasp-llm-top10", "mitre-atlas"] },
  { command: "npx tsx scripts/atr_recall_analysis.ts", file: "scripts/atr_recall_analysis.ts", sources: ["promptbench", "promptinject"] },
  { command: "npx tsx scripts/eval-small-corpora.ts", file: "scripts/eval-small-corpora.ts", sources: ["llm-guard", "nemo-guardrails", "promptfoo"] },
  { command: "npx tsx scripts/eval-garak-inthewild.ts", file: "scripts/eval-garak-inthewild.ts", sources: ["garak"] },
  { command: "npx tsx scripts/run-garak-full-benchmark.ts", file: "scripts/run-garak-full-benchmark.ts", sources: ["garak-full"] },
  { command: "npx tsx scripts/eval-academic-raw.ts", file: "scripts/eval-academic-raw.ts", sources: ["advbench", "harmbench", "jailbreakbench"] },
];

/**
 * Sources the weekly run cannot measure, so their latest measurement may
 * predate enforce recording. The run skips HackAPrompt with a warning: its
 * corpus is not provisioned in CI (see the workflow's hackaprompt step).
 */
const NOT_PROVISIONED: ReadonlySet<string> = new Set(["hackaprompt"]);

/**
 * A runner records the enforce lane when it CALLS one of these (its own
 * definition does not count: eval-harness.ts defines enforceLaneFromEval)...
 */
const COMPUTES_ENFORCE_LANE = /(?<!function )\b(enforceLaneRecallOf|enforceLaneFromEval|skillBenchmarkMeasurementInput)\(/;
/** ...and hands the result to the measurement it writes. */
const WRITES_ENFORCE_LANE = /enforce_lane:|\benforceLane,|\[ENFORCE_LANE_BREAKDOWN_KEY\]:/;

interface Step {
  name?: string;
  run?: string;
}

function measureCommands(): string[] {
  const doc = yaml.load(readFileSync(WORKFLOW, "utf8")) as { jobs: Record<string, { steps: Step[] }> };
  const out: string[] = [];
  for (const step of doc.jobs.measure.steps) {
    for (const m of (step.run ?? "").matchAll(/\b(npm run eval(?::[a-z-]+)?|npx tsx (?:src|scripts)\/[\w/.-]+\.ts)/g)) {
      out.push(m[1]);
    }
  }
  return out;
}

/** Steps that measure (as opposed to verify, sync or render what was measured). */
const NOT_A_RUNNER = new Set([
  "npx tsx scripts/measurement/verify.ts",
  "npx tsx scripts/sync-stats-from-measurements.ts",
  "npx tsx scripts/render-benchmark-table.ts",
]);

function latestMeasurement(source: string): Record<string, unknown> | null {
  const pointerPath = join(REPO, "data", "measurements", source, "latest.json");
  if (!existsSync(pointerPath)) return null;
  const pointer = JSON.parse(readFileSync(pointerPath, "utf8")) as { file: string };
  return JSON.parse(readFileSync(join(REPO, "data", "measurements", source, pointer.file), "utf8"));
}

describe("the runners measure-all.yml calls", () => {
  it("are all listed here, with the sources they write", () => {
    const called = [...new Set(measureCommands().filter((c) => !NOT_A_RUNNER.has(c)))].sort();
    expect(called).toEqual(RUNNERS.map((r) => r.command).sort());
  });

  it.each(RUNNERS.map((r) => [r.file, r]))("%s records the enforce lane", (_file, runner) => {
    const source = readFileSync(join(REPO, runner.file), "utf8");
    expect(source).toMatch(COMPUTES_ENFORCE_LANE);
    expect(source).toMatch(WRITES_ENFORCE_LANE);
  });
});

describe("the measurement each weekly source's latest.json points at", () => {
  const sources = RUNNERS.flatMap((r) => r.sources);

  it.each(sources.filter((s) => !NOT_PROVISIONED.has(s)))("%s was measured with enforce recording", (source) => {
    const m = latestMeasurement(source);
    expect(m, `no latest.json for ${source}`).not.toBeNull();
    expect(String(m!.measured_at).slice(0, 10) >= ENFORCE_RECORDING_SINCE).toBe(true);
  });

  it.each(sources)("%s carries an enforce_lane that agrees with its headline, if measured since", (source) => {
    const raw = latestMeasurement(source);
    if (raw === null || String(raw.measured_at).slice(0, 10) < ENFORCE_RECORDING_SINCE) return;
    // parseMeasurement checks the record's shape and that it covers the headline's attacks.
    const m = parseMeasurement(raw);
    const breakdown = m.breakdown ?? {};
    expect(breakdown.enforce_lane, `${source}: no breakdown.enforce_lane`).toBeDefined();
    const lane = parseEnforceLaneRecall(breakdown.enforce_lane);
    expect(m.confusion, `${source}: no confusion matrix to hold the figure to`).toBeDefined();
    expect(lane.attacks).toBe(m.confusion!.tp + m.confusion!.fn);
    // The enforce lane loads a subset of the hunt lane's rules through the same loop.
    expect(lane.detected).toBeLessThanOrEqual(m.confusion!.tp);
    expect(lane.rules_in_lane).toBeLessThanOrEqual(m.rules_loaded);
  });
});
