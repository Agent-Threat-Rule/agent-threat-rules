/**
 * Hand-written benign probes for the maturity:stable + severity:critical rules
 * whose benign-gate zero is vacuous (corpus visibility blind or thin).
 *
 * WHY THIS EXISTS
 *   gate-corpus-visibility.ts proves a rule's 0 FP carries no information when
 *   no benign sample could have matched it. It cannot say whether that blindness
 *   is fine (the rule keys on a string with no legitimate use) or dangerous (the
 *   rule keys on a neutral primitive the corpus simply lacks). Only writing the
 *   missing legitimate samples answers that, so this harness runs them.
 *
 *   The population matters because of src/verdict.ts determineOutcome: severity
 *   critical is denied outright, without consulting confidence, maturity or
 *   lane. A false positive on one of these rules is a blocked legitimate action,
 *   not an advisory line in a log.
 *
 * CONTROL
 *   Every probed rule is first fired with its own declared true positive. A rule
 *   whose control does not fire is reported and excluded from the conclusions —
 *   a silent 0 across the benign probes would otherwise be indistinguishable
 *   from "the engine never loaded this rule".
 *
 * EVENT SHAPE
 *   src/corpus-event.ts matchedRuleIds — the same shape set gate-promotion-fp.ts
 *   charges rules against, so a hit here is a hit the benign gate would have
 *   counted had the sample been in the corpus.
 *
 * Usage:
 *   npx tsx scripts/detection-boundary/stable-critical-probe.ts
 *   npx tsx scripts/detection-boundary/stable-critical-probe.ts --json
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { load as loadYaml } from "js-yaml";

import { corpusShapes, matchedRuleIds } from "../../src/corpus-event.js";
import { ATREngine } from "../../src/engine.js";
import type { ATRMatch } from "../../src/types.js";
import { computeVerdict } from "../../src/verdict.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");
const RULES_DIR = join(REPO_ROOT, "rules");
const PROBE_FILE = join(REPO_ROOT, "data", "measurements", "stable-critical-triage", "benign-probes.jsonl");

const JSON_OUT = process.argv.includes("--json");

interface Probe {
  readonly id: string;
  readonly targets: readonly string[];
  readonly kind: string;
  readonly why: string;
  readonly text: string;
}

interface RuleMeta {
  readonly id: string;
  readonly file: string;
  readonly title: string;
  readonly severity: string;
  readonly maturity: string;
  readonly status: string;
  readonly firstTruePositive: string | null;
  readonly conditionDescriptions: readonly string[];
}

function yamlFiles(dir: string): readonly string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...yamlFiles(path));
    else if (entry.endsWith(".yaml")) out.push(path);
  }
  return out;
}

function readRuleMeta(): ReadonlyMap<string, RuleMeta> {
  const map = new Map<string, RuleMeta>();
  for (const file of yamlFiles(RULES_DIR)) {
    const doc = loadYaml(readFileSync(file, "utf-8")) as Record<string, unknown> | null;
    if (doc == null || typeof doc !== "object") continue;
    const id = typeof doc.id === "string" ? doc.id : null;
    if (id == null) continue;
    const cases = (doc.test_cases ?? {}) as Record<string, unknown>;
    const tps = Array.isArray(cases.true_positives) ? cases.true_positives : [];
    const first = tps.length > 0 ? (tps[0] as Record<string, unknown>) : null;
    const detection = (doc.detection ?? {}) as Record<string, unknown>;
    const conds = Array.isArray(detection.conditions) ? detection.conditions : [];
    const condDescs = conds.map((c) => {
      const rec = c as Record<string, unknown>;
      const desc = typeof rec.description === "string" ? rec.description : "";
      const value = typeof rec.value === "string" ? rec.value : "";
      const field = typeof rec.field === "string" ? rec.field : "";
      return `${field}: ${desc} :: ${value}`;
    });
    map.set(id, {
      id,
      file: relative(REPO_ROOT, file),
      title: typeof doc.title === "string" ? doc.title : "",
      severity: typeof doc.severity === "string" ? doc.severity : "",
      maturity: typeof doc.maturity === "string" ? doc.maturity : "",
      status: typeof doc.status === "string" ? doc.status : "",
      firstTruePositive: first != null && typeof first.input === "string" ? first.input : null,
      conditionDescriptions: condDescs,
    });
  }
  return map;
}

function readProbes(): readonly Probe[] {
  return readFileSync(PROBE_FILE, "utf-8")
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as Probe);
}

/**
 * Decide the same match again at each severity, through the real
 * src/verdict.ts. Answers "would downgrading this rule stop the block?"
 * without anyone having to re-derive the outcome table by hand.
 */
function whatIf(id: string, confidence: number): Readonly<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const severity of ["critical", "high", "medium", "low"]) {
    const fake = [
      {
        rule: { id, severity, title: id, response: { actions: [] } },
        matchedConditions: [],
        matchedPatterns: [],
        confidence,
        timestamp: new Date().toISOString(),
        scan_context: "native",
      },
    ] as unknown as readonly ATRMatch[];
    out[severity] = computeVerdict(fake).outcome;
  }
  return out;
}

async function main(): Promise<number> {
  const meta = readRuleMeta();
  const probes = readProbes();

  const engine = new ATREngine({ rulesDir: RULES_DIR, lane: "hunt" });
  const loaded = await engine.loadRules();

  const enforceEngine = new ATREngine({ rulesDir: RULES_DIR, lane: "enforce" });
  await enforceEngine.loadRules();

  const probedRules = [...new Set(probes.flatMap((p) => p.targets))].sort();

  // CONTROL — every probed rule must fire on its own declared true positive.
  const controlPass: string[] = [];
  const controlFail: string[] = [];
  for (const id of probedRules) {
    const tp = meta.get(id)?.firstTruePositive ?? null;
    if (tp == null) {
      controlFail.push(id);
      continue;
    }
    if (matchedRuleIds(engine, tp).has(id)) controlPass.push(id);
    else controlFail.push(id);
  }
  if (controlPass.length === 0) {
    console.error("CONTROL TOTAL FAILURE: no probed rule fired on its own true positive — aborting.");
    return 1;
  }

  interface Hit {
    readonly probe: string;
    readonly kind: string;
    readonly why: string;
    readonly rules: readonly string[];
    readonly enforceRules: readonly string[];
    readonly verdict: string;
    readonly conditions: Readonly<Record<string, readonly string[]>>;
  }
  const hits: Hit[] = [];

  const firedBy = new Map<string, string[]>();
  const conditionsFired = new Map<string, Set<string>>();
  const confidences = new Map<string, number[]>();

  const RANK: Readonly<Record<string, number>> = { allow: 0, ask: 1, deny: 2 };

  for (const p of probes) {
    const matched = [...matchedRuleIds(engine, p.text)]
      .filter((id) => meta.get(id)?.severity === "critical")
      .sort();
    const enforceMatched = [...matchedRuleIds(enforceEngine, p.text)]
      .filter((id) => meta.get(id)?.severity === "critical")
      .sort();

    // Worst verdict the production path (hook-handler -> evaluateWithVerdict)
    // would return for this text, over the canonical shape set.
    let verdict = "allow";
    const perRuleConditions: Record<string, string[]> = {};
    for (const shape of corpusShapes(p.text)) {
      const { verdict: v } = await engine.evaluateWithVerdict(shape.event);
      if ((RANK[v.outcome] ?? 0) > (RANK[verdict] ?? 0)) verdict = v.outcome;
      for (const m of v.matches) {
        if (m.rule.severity !== "critical") continue;
        const seen = new Set(perRuleConditions[m.rule.id] ?? []);
        for (const c of m.matchedConditions) seen.add(c);
        perRuleConditions[m.rule.id] = [...seen];
        const global = conditionsFired.get(m.rule.id) ?? new Set<string>();
        for (const c of m.matchedConditions) global.add(c);
        conditionsFired.set(m.rule.id, global);
        const confs = confidences.get(m.rule.id) ?? [];
        confs.push(m.confidence);
        confidences.set(m.rule.id, confs);
      }
    }

    if (matched.length > 0) {
      hits.push({
        probe: p.id,
        kind: p.kind,
        why: p.why,
        rules: matched,
        enforceRules: enforceMatched,
        verdict,
        conditions: perRuleConditions,
      });
      for (const id of matched) {
        const list = firedBy.get(id) ?? [];
        list.push(p.id);
        firedBy.set(id, list);
      }
    }
  }

  // Corpus impact: what adding these probes to the benign gate would do to the
  // WHOLE ruleset, not just the critical slice. Answers "why is this file not
  // simply committed into data/benign-corpus-extended/".
  const measurementPath = join(REPO_ROOT, "data", "benign-fp-measurement.json");
  const measurement = JSON.parse(readFileSync(measurementPath, "utf-8")) as {
    rules: Record<string, { fp_count: number }>;
  };
  const allHits = new Map<string, number>();
  for (const p of probes) {
    for (const id of matchedRuleIds(engine, p.text)) allHits.set(id, (allHits.get(id) ?? 0) + 1);
  }
  let currentlyClean = 0;
  let currentlyDirty = 0;
  let noRecord = 0;
  for (const id of allHits.keys()) {
    const rec = measurement.rules[id];
    if (rec == null) noRecord++;
    else if (rec.fp_count === 0) currentlyClean++;
    else currentlyDirty++;
  }
  const corpusImpact = {
    distinct_rules_fired: allHits.size,
    currently_zero_fp: currentlyClean,
    already_dirty: currentlyDirty,
    no_measurement_record: noRecord,
    total_rule_probe_firings: [...allHits.values()].reduce((a, b) => a + b, 0),
  };

  const report = {
    rules_loaded_hunt: loaded,
    corpus_impact_if_added_to_benign_gate: corpusImpact,
    probes: probes.length,
    probed_rules: probedRules.length,
    control_pass: controlPass,
    control_fail: controlFail,
    probes_firing_a_critical_rule: hits.length,
    hits,
    probes_denied: hits.filter((h) => h.verdict === "deny").length,
    fired_rules: [...firedBy.entries()]
      .map(([id, ps]) => ({
        id,
        title: meta.get(id)?.title ?? "",
        severity: meta.get(id)?.severity ?? "",
        maturity: meta.get(id)?.maturity ?? "",
        probes: ps,
        count: ps.length,
        conditions: [...(conditionsFired.get(id) ?? [])].map((idx) => ({
          index: idx,
          description: meta.get(id)?.conditionDescriptions[Number(idx)] ?? "(index out of range)",
        })),
        observed_confidence: {
          min: Math.min(...(confidences.get(id) ?? [0])),
          max: Math.max(...(confidences.get(id) ?? [0])),
        },
        // What the SAME match would be decided as if severity were downgraded.
        // Run through src/verdict.ts computeVerdict, not reasoned about.
        what_if_severity: whatIf(id, Math.max(...(confidences.get(id) ?? [0]))),
      }))
      .sort((a, b) => b.count - a.count),
  };

  if (JSON_OUT) {
    console.log(JSON.stringify(report, null, 2));
    return 0;
  }

  console.log(`rules loaded (hunt): ${loaded}`);
  console.log(`probes: ${probes.length}   probed rules: ${probedRules.length}`);
  console.log(`CONTROL: ${controlPass.length} fired on own TP, ${controlFail.length} did not`);
  if (controlFail.length > 0) console.log(`  control failures: ${controlFail.join(", ")}`);
  console.log(`probes firing at least one severity:critical rule: ${hits.length}/${probes.length}`);
  console.log(`probes whose production verdict is deny: ${report.probes_denied}/${probes.length}`);
  console.log("");
  for (const h of hits) {
    console.log(`${h.probe} [${h.kind}] verdict=${h.verdict} -> ${h.rules.join(", ")}`);
    if (h.enforceRules.length > 0) console.log(`      enforce lane: ${h.enforceRules.join(", ")}`);
  }
  console.log("");
  console.log("if these probes entered the benign gate corpus:");
  console.log(`  distinct rules they fire: ${corpusImpact.distinct_rules_fired}`);
  console.log(`  of which currently 0 FP on record: ${corpusImpact.currently_zero_fp}`);
  console.log(`  of which already dirty: ${corpusImpact.already_dirty}`);
  console.log(`  total (rule, probe) firings: ${corpusImpact.total_rule_probe_firings}`);
  console.log("");
  console.log("per rule:");
  for (const r of report.fired_rules) {
    console.log(`  ${r.id}  ${r.count} probe(s)  [${r.maturity}]  ${r.title}`);
    console.log(`      ${r.probes.join(" ")}`);
  }
  return 0;
}

main().then((code) => process.exit(code));
