#!/usr/bin/env npx tsx
/**
 * measure-holdout-evidence.ts — per-rule and per-lane evidence on holdout v1.
 *
 * WHAT IT ANSWERS
 *   For every live rule at maturity stable or test: on a corpus it was never
 *   written from, how many held-out attacks does it catch, how many benign
 *   samples does it fire on (each with n and a 95% interval), do its declared
 *   evasion tests hold, which attacker transforms does it survive, and what
 *   does it cost. Then a verdict against ENFORCE_EVIDENCE_BAR and a
 *   recommendation (keep / demote / promote / stay).
 *
 *   For the enforce lane as it runs today, and for the lane the
 *   recommendations would produce: recall and FP rate on holdout v1, per
 *   slice, each with n, a 95% Clopper-Pearson interval, the ATR version and
 *   commit, and the sha256 of the corpus files.
 *
 * WHAT IT DOES NOT DO
 *   It never edits a rule. Recommendations are written to the evidence file
 *   for a maintainer to act on.
 *
 * OUTPUT
 *   data/measurements/holdout-v1/<date>_holdout-v1-<sha8>_atr-<ver>.json   lane record (schema v1)
 *   data/measurements/holdout-v1/rules/<same name>                       per-rule evidence
 *   --out-dir writes both somewhere else instead (dry runs).
 *
 * Usage:
 *   npx tsx scripts/measure-holdout-evidence.ts [--workers 4] [--out-dir DIR]
 */
import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import type { ATRRule } from "../src/types.js";
import { writeMeasurement, readATRVersion, readATRCommit } from "../src/measurement/write.js";
import { measurementFilename } from "../src/measurement/schema.js";
import { rateWithCi } from "./lib/binomial-ci.js";
import { conditionFields, isMeasurableField, syncBlindMethod } from "./lib/corpus-event.js";
import { loadHoldout, HOLDOUT_VERSION, type Holdout, type HoldoutSample } from "./lib/holdout.js";
import {
  ENFORCE_EVIDENCE_BAR,
  recommend,
  ruleEvidence,
  percentile,
  type RuleEvidence,
} from "./lib/holdout-evidence.js";
import { benignFiller, cost, engineTransforms, evasionTests, robustness, singleRuleEngine } from "./lib/holdout-probes.js";
import { stableShortfalls, summaryMarkdown, type EvidenceRow, type LaneFigures } from "./lib/holdout-report.js";
import { runShard, scanAll, type SampleScan, type ScanResult } from "./lib/holdout-scan.js";

const SCRIPT = fileURLToPath(import.meta.url);
const REPO = resolve(fileURLToPath(new URL("..", import.meta.url)));
const RULES_DIR = join(REPO, "rules");
const SOURCE = "holdout-v1";
const COST_TEXTS = 200;

/**
 * SELECTION vs REPORT halves.
 *
 * Choosing rules on a corpus and then quoting the chosen lane's recall and FP
 * on the same corpus reports the selection, not the lane: rules that happened
 * to fire on these particular attacks are kept, so the figure is biased up.
 * So the holdout is split once, by a hash of the sample id (stable across
 * runs and independent of content): per-rule verdicts and recommendations use
 * the SELECTION half only, and the proposed lane is reported on the REPORT
 * half only, which played no part in choosing it. The current enforce lane
 * was chosen without the holdout, so it is reported on the whole corpus.
 */
function inSelectionHalf(id: string): boolean {
  return createHash("sha256").update(id, "utf8").digest()[0]! % 2 === 0;
}

interface Part {
  readonly attack: readonly HoldoutSample[];
  readonly benign: readonly HoldoutSample[];
}

function split(h: Holdout): { selection: Part; report: Part } {
  const pick = (want: boolean) => (s: HoldoutSample) => inSelectionHalf(s.id) === want;
  return {
    selection: { attack: h.attack.filter(pick(true)), benign: h.benign.filter(pick(true)) },
    report: { attack: h.attack.filter(pick(false)), benign: h.benign.filter(pick(false)) },
  };
}

interface Args {
  readonly workers: number;
  readonly outDir: string | null;
  /** Local iteration only: reuse a previous scan of the same rules and corpus. */
  readonly scanCache: string | null;
  /** Append a markdown summary here (CI passes $GITHUB_STEP_SUMMARY). */
  readonly summary: string | null;
}

function parseArgs(argv: readonly string[]): Args {
  let workers = 4;
  let outDir: string | null = null;
  let scanCache: string | null = null;
  let summary: string | null = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--workers") workers = Math.max(1, Math.min(16, Number(argv[++i])));
    else if (argv[i] === "--out-dir") outDir = resolve(argv[++i]!);
    else if (argv[i] === "--scan-cache") scanCache = resolve(argv[++i]!);
    else if (argv[i] === "--summary") summary = argv[++i]!;
    else throw new Error(`unknown argument ${argv[i]}`);
  }
  if (scanCache !== null && outDir === null) throw new Error("--scan-cache is for local iteration; it needs --out-dir");
  return { workers, outDir, scanCache, summary };
}

const isLive = (r: ATRRule): boolean => r.status !== "draft" && r.status !== "deprecated";
const isCandidate = (r: ATRRule): boolean => isLive(r) && (r.maturity === "stable" || r.maturity === "test");

function redosEntries(): ReadonlyMap<string, readonly string[]> {
  const doc = JSON.parse(readFileSync(join(REPO, "data/redos-baseline.json"), "utf8")) as { known: Record<string, unknown> };
  const out = new Map<string, string[]>();
  for (const key of Object.keys(doc.known)) {
    const id = key.split("#")[0]!;
    out.set(id, [...(out.get(id) ?? []), key]);
  }
  return out;
}

function bySlice(ids: readonly string[], samples: ReadonlyMap<string, HoldoutSample>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const id of ids) {
    const slice = samples.get(id)!.slice;
    out[slice] = (out[slice] ?? 0) + 1;
  }
  return out;
}

function matchesOf(scan: ScanResult, samples: readonly HoldoutSample[], ruleId: string, lane: "hunt" | "enforce"): string[] {
  return samples.filter((s) => scan.scans.get(s.id)![lane].includes(ruleId)).map((s) => s.id);
}

function measureRule(
  rule: ATRRule,
  holdout: Part,
  scan: ScanResult,
  ctx: { byId: ReadonlyMap<string, HoldoutSample>; redos: ReadonlyMap<string, readonly string[]>; costTexts: readonly string[]; filler: string; toolOutput: string },
): RuleEvidence {
  const tpIds = matchesOf(scan, holdout.attack, rule.id, "hunt");
  const fpIds = matchesOf(scan, holdout.benign, rule.id, "hunt");
  const engine = singleRuleEngine(rule);
  const tpTexts = tpIds.map((id) => ctx.byId.get(id)!.text);
  const fields = conditionFields(rule as never);
  const unmeasurable = fields.filter((f) => !isMeasurableField(f));
  const blind = syncBlindMethod(rule as never);
  return ruleEvidence({
    id: rule.id,
    maturity: String(rule.maturity),
    severity: String(rule.severity),
    tpIds,
    fpIds,
    attackN: holdout.attack.length,
    benignN: holdout.benign.length,
    tpBySlice: bySlice(tpIds, ctx.byId),
    fpBySlice: bySlice(fpIds, ctx.byId),
    evasion: evasionTests(engine, rule),
    robustness: robustness(engine, rule.id, tpTexts, engineTransforms(ctx.filler, ctx.toolOutput)),
    latency: cost(engine, ctx.costTexts, ctx.filler),
    redosBaselineEntries: ctx.redos.get(rule.id) ?? [],
    unmeasurableFields: blind ? [`method:${blind}`, ...unmeasurable] : unmeasurable,
    confirmEmbedding: (rule as { confirm?: string }).confirm === "embedding",
  });
}

/** Recall and FP of a set of matched sample ids, overall and per slice. */
function laneFigures(holdout: Part, detected: (s: HoldoutSample) => boolean) {
  const part = (samples: readonly HoldoutSample[]) => {
    const slices: Record<string, ReturnType<typeof rateWithCi>> = {};
    for (const name of [...new Set(samples.map((s) => s.slice))].sort()) {
      const inSlice = samples.filter((s) => s.slice === name);
      slices[name] = rateWithCi(inSlice.filter(detected).length, inSlice.length);
    }
    return { overall: rateWithCi(samples.filter(detected).length, samples.length), slices };
  };
  return { recall: part(holdout.attack), fp_rate: part(holdout.benign) };
}

function writeOutputs(args: Args, lane: Record<string, unknown>, rules: readonly RuleEvidence[], holdout: Holdout, scan: ScanResult) {
  const enforce = lane["enforce_current"] as ReturnType<typeof laneFigures>;
  const hunt = lane["hunt"] as ReturnType<typeof laneFigures>;
  const shaShort = holdout.sha256["attack.jsonl"]!.slice(0, 8);
  const tp = hunt.recall.overall.k;
  const fp = hunt.fp_rate.overall.k;
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = hunt.recall.overall.rate ?? 0;
  const input = {
    source: SOURCE,
    // The corpus hash prefix: a new build is a new source_version.
    source_version: shaShort,
    samples: holdout.attack.length + holdout.benign.length,
    metrics: { recall, precision, f1: precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall), fp_rate: hunt.fp_rate.overall.rate ?? 0 },
    confusion: { tp, fp, tn: holdout.benign.length - fp, fn: holdout.attack.length - tp },
    breakdown: {
      enforce_lane: {
        lane: "enforce" as const,
        detected: enforce.recall.overall.k,
        attacks: enforce.recall.overall.n,
        recall: enforce.recall.overall.rate ?? 0,
        rules_in_lane: scan.enforceRules,
        note: "holdout v1, enforce-lane engine, canonical corpus shapes; see breakdown.lanes for FP and intervals",
      },
      lanes: lane,
      corpus_sha256: holdout.sha256,
      evidence_bar: ENFORCE_EVIDENCE_BAR,
    },
    notes:
      "Out-of-sample: holdout v1 shares no text with any rule test case or gate corpus (data/holdout/v1/DATACARD.md). " +
      "metrics/confusion are the hunt lane, per repository convention; every lane with FP rate and 95% Clopper-Pearson intervals is in breakdown.lanes.",
  };
  const evidence = {
    source: SOURCE,
    corpus_sha256: holdout.sha256,
    atr_version: readATRVersion(),
    atr_commit: readATRCommit(),
    measured_at: new Date().toISOString(),
    evidence_bar: ENFORCE_EVIDENCE_BAR,
    rules: rules.map((r) => ({ ...r, recommendation: recommend(r) })),
  };
  if (args.outDir) {
    mkdirSync(args.outDir, { recursive: true });
    writeFileSync(join(args.outDir, "lane.json"), JSON.stringify({ ...input, atr_version: readATRVersion(), atr_commit: readATRCommit() }, null, 2) + "\n");
    writeFileSync(join(args.outDir, "rules.json"), JSON.stringify(evidence, null, 2) + "\n");
    return join(args.outDir, "lane.json");
  }
  const { measurementPath, measurement } = writeMeasurement(input);
  const rulesDir = join(REPO, "data/measurements", SOURCE, "rules");
  mkdirSync(rulesDir, { recursive: true });
  writeFileSync(join(rulesDir, measurementFilename(measurement)), JSON.stringify(evidence, null, 2) + "\n");
  return measurementPath;
}

/**
 * --check <rules.json>: exit 1 when a live stable rule falls short of the
 * evidence bar for any reason other than missing evasion tests.
 */
function check(path: string): number {
  const doc = JSON.parse(readFileSync(path, "utf8")) as { rules: EvidenceRow[] };
  const short = stableShortfalls(doc.rules);
  for (const r of short) console.log(`${r.id}: ${r.recommendation} (${r.failures.join(", ")})`);
  console.log(`${short.length} stable rule(s) do not meet the enforce-lane evidence bar`);
  return short.length === 0 ? 0 : 1;
}

async function cachedScan(args: Args, all: readonly HoldoutSample[]): Promise<ScanResult> {
  if (args.scanCache !== null && existsSync(args.scanCache)) {
    const c = JSON.parse(readFileSync(args.scanCache, "utf8")) as { huntRules: number; enforceRules: number; scans: SampleScan[] };
    return { huntRules: c.huntRules, enforceRules: c.enforceRules, scans: new Map(c.scans.map((x) => [x.id, x])) };
  }
  const scan = await scanAll(SCRIPT, all, args.workers);
  if (args.scanCache !== null) {
    writeFileSync(args.scanCache, JSON.stringify({ huntRules: scan.huntRules, enforceRules: scan.enforceRules, scans: [...scan.scans.values()] }));
  }
  return scan;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv[0] === "--check") {
    process.exit(check(argv[1]!));
  }
  if (argv[0] === "--worker") {
    const holdout = loadHoldout(REPO);
    await runShard(RULES_DIR, [...holdout.attack, ...holdout.benign], Number(argv[1]), Number(argv[2]), argv[3]!);
    return;
  }
  const args = parseArgs(argv);
  const holdout = loadHoldout(REPO);
  const all = [...holdout.attack, ...holdout.benign];
  console.log(`holdout v1: ${holdout.attack.length} attack, ${holdout.benign.length} benign; ${args.workers} workers`);
  const t0 = Date.now();
  const scan = await cachedScan(args, all);
  const errors = [...scan.scans.values()].filter((s) => s.error !== null);
  console.log(`scanned in ${Math.round((Date.now() - t0) / 1000)} s; ${scan.huntRules} hunt rules, ${scan.enforceRules} enforce rules; ${errors.length} sample errors`);
  if (errors.length > 0) throw new Error(`${errors.length} samples raised during evaluation; first: ${errors[0]!.id}: ${errors[0]!.error}`);

  const hunt = new ATREngine({ rulesDir: RULES_DIR, lane: "hunt" });
  await hunt.loadRules();
  const candidates = hunt.getRules().filter(isCandidate);
  const byId = new Map(all.map((s) => [s.id, s]));
  const benignTexts = holdout.benign.map((s) => s.text);
  const toolOutput = holdout.benign.find((s) => s.surface === "tool_response")?.text ?? "{}";
  const ctx = {
    byId,
    redos: redosEntries(),
    costTexts: all.filter((_, i) => i % Math.max(1, Math.floor(all.length / COST_TEXTS)) === 0).map((s) => s.text).slice(0, COST_TEXTS),
    filler: benignFiller(benignTexts, 160_000),
    toolOutput,
  };
  const halves = split(holdout);
  console.log(`selection half: ${halves.selection.attack.length} attack, ${halves.selection.benign.length} benign; report half: ${halves.report.attack.length}, ${halves.report.benign.length}`);
  const rules = candidates.map((r) => measureRule(r, halves.selection, scan, ctx));
  console.log(`measured ${rules.length} candidate rules in ${Math.round((Date.now() - t0) / 1000)} s`);

  const proposed = new Set(rules.filter((r) => ["keep", "keep_after_evasion_tests", "promote", "promote_after_evasion_tests"].includes(recommend(r))).map((r) => r.id));
  const scansOf = (s: HoldoutSample) => scan.scans.get(s.id)!;
  const lane = {
    enforce_current: laneFigures(holdout, (s) => scansOf(s).enforce.length > 0),
    enforce_proposed: {
      rules: [...proposed].sort(),
      evaluated_on: "report half (rules were chosen on the selection half)",
      ...laneFigures(halves.report, (s) => scansOf(s).hunt.some((id) => proposed.has(id))),
    },
    hunt: laneFigures(holdout, (s) => scansOf(s).hunt.length > 0),
    sample_latency_ms: { p50: percentile(all.map((s) => scansOf(s).ms), 0.5), p99: percentile(all.map((s) => scansOf(s).ms), 0.99) },
  };
  const out = writeOutputs(args, lane, rules, holdout, scan);
  const ec = lane.enforce_current;
  console.log(`enforce (current, ${scan.enforceRules} rules): recall ${ec.recall.overall.k}/${ec.recall.overall.n}, FP ${ec.fp_rate.overall.k}/${ec.fp_rate.overall.n}`);
  const ep = lane.enforce_proposed;
  console.log(`enforce (proposed, ${proposed.size} rules): recall ${ep.recall.overall.k}/${ep.recall.overall.n}, FP ${ep.fp_rate.overall.k}/${ep.fp_rate.overall.n}`);
  console.log(`wrote ${out}`);
  if (args.summary) {
    const rows = rules.map((r) => ({ id: r.id, maturity: r.maturity, recommendation: recommend(r), failures: r.failures }));
    const lanes = { enforce_current: lane.enforce_current, enforce_proposed: lane.enforce_proposed, hunt: lane.hunt } as unknown as Record<string, LaneFigures>;
    appendFileSync(args.summary, summaryMarkdown(lanes, rows, { atrVersion: readATRVersion(), atrCommit: readATRCommit(), corpus: holdout.sha256 }));
  }
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? (e.stack ?? e.message) : String(e));
  process.exit(1);
});
