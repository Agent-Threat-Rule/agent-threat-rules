#!/usr/bin/env npx tsx
/**
 * ATR recall analysis against PromptBench and PromptInject corpora.
 * Runs extracted prompts against all ATR rules, identifies misses,
 * and clusters them by phrase/template family.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent } from "../src/types.js";
import { writeMeasurement } from "../src/measurement/write.js";
import { matchedRuleIds, shapeNames } from "./lib/corpus-event.js";

/**
 * Repo root, located RELATIVE TO THIS FILE.
 *
 * This used to be a hardcoded absolute path to one particular clone. Every
 * worktree, CI checkout and contributor machine therefore loaded THAT clone's
 * rules and corpora while writing measurement files (via src/measurement/write.ts,
 * which resolves relative to itself) into the checkout actually being tested.
 * A measurement could describe rules the branch under test never contained.
 */
const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PB_FILE = join(REPO, "data/test-corpora/promptbench/all.json");
const PI_FILE = join(REPO, "data/test-corpora/promptinject/all.json");

interface PromptRecord {
  source?: string;
  attack_type?: string;
  attack_class?: string;
  attack_key?: string;
  attacked?: string;
  full_prompt?: string;
  original?: string;
  rogue_string?: string;
  attack_instruction?: string;
  template?: boolean;
}

function getPromptText(r: PromptRecord): string {
  return r.attacked ?? r.full_prompt ?? r.attack_instruction ?? "";
}

/**
 * The event this harness has always used for its headline recall number, kept
 * bit-for-bit so published figures stay comparable across versions.
 *
 * IT IS NOT WHAT ITS NAME SAYS, and the correction matters. `llm_io` is not a
 * member of `AgentEvent["type"]` — the valid set is in `EVENT_TYPE_TO_SOURCE`
 * (`llm_input`, `llm_output`, `tool_call`, `tool_response`, `agent_behavior`,
 * `multi_agent_message`). So `EVENT_TYPE_TO_SOURCE["llm_io"]` is `undefined`,
 * and `src/engine.ts:388` guards the source filter with `eventSourceType &&`.
 * An unroutable type does not narrow rule admission — it switches the source
 * filter OFF, and every rule runs.
 *
 * A previous version of this comment asserted the opposite ("an `llm_io` event
 * admits only llm_io rules"). That was wrong in the direction that flatters:
 * the baseline is WIDER than the canonical set on rule admission, while still
 * being narrower on fields — nothing resolves `tool_args`, `agent_output` or
 * `tool_description` here. It is a strange hybrid, not a narrow shape, and the
 * only reason to keep it is continuity with numbers already published.
 *
 * The cast is deliberate. This shape is wrong by construction; `tsconfig.scripts.json`
 * is right to reject it, and it is preserved only so the `legacy_*` field in the
 * measurement stays comparable. Do not copy this pattern into a new harness —
 * use `matchedRuleIds` from scripts/lib/corpus-event.ts, which every run also
 * reports and which is the shape set the benign FP gate charges rules on.
 */
function legacyLlmIoEvent(text: string): AgentEvent {
  return {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- see above
    type: "llm_io" as unknown as AgentEvent["type"],
    timestamp: new Date().toISOString(),
    content: text,
    fields: { user_input: text },
    source: "user_input",
  } as AgentEvent;
}

interface RecallResult {
  total: number;
  matched: number;
  missed: number;
  missedRecords: Array<{ text: string; record: PromptRecord }>;
  /** Samples attributed to each rule under the legacy narrow llm_io event. */
  matchedByRule: Record<string, number>;
  /** Samples attributed to each rule under the canonical corpus shape set. */
  canonicalMatchedByRule: Record<string, number>;
  /** Samples matched by >= 1 rule under the canonical shape set. */
  canonicalMatched: number;
  /** Samples where a rule was the ONLY rule to fire — what dies with the rule. */
  soleByRule: Record<string, number>;
  canonicalSoleByRule: Record<string, number>;
}

async function runRecallAnalysis(
  _label: string,
  records: PromptRecord[],
  engine: ATREngine
): Promise<RecallResult> {
  let matched = 0;
  let missed = 0;
  let canonicalMatched = 0;
  const missedRecords: Array<{ text: string; record: PromptRecord }> = [];
  const matchedByRule: Record<string, number> = {};
  const canonicalMatchedByRule: Record<string, number> = {};
  const soleByRule: Record<string, number> = {};
  const canonicalSoleByRule: Record<string, number> = {};

  for (const record of records) {
    const text = getPromptText(record);
    if (!text || text.length < 5) continue;

    // Canonical attribution: the shape set the benign gate uses. Counted per
    // SAMPLE (matchedRuleIds returns a Set), so a rule firing on three shapes
    // is one true positive, not three — symmetric with how an FP is counted.
    try {
      const canonicalIds = matchedRuleIds(engine, text);
      if (canonicalIds.size > 0) canonicalMatched++;
      for (const id of canonicalIds) {
        canonicalMatchedByRule[id] = (canonicalMatchedByRule[id] ?? 0) + 1;
        if (canonicalIds.size === 1) canonicalSoleByRule[id] = (canonicalSoleByRule[id] ?? 0) + 1;
      }
    } catch (_) {
      // a canonical-shape engine error is not a headline miss; leave it uncounted
    }

    try {
      const matches = engine.evaluate(legacyLlmIoEvent(text));
      if (matches && matches.length > 0) {
        matched++;
        // ATRMatch carries the rule OBJECT (`rule.id`); reading `rule_id`/
        // `ruleId` off it always yielded undefined, so every hit was bucketed
        // under the literal string "unknown". The COUNT was right — the 3,624
        // the 3.5.2 promptinject measurement published is exactly the sum over
        // the nine rules that fired — but it was printed as one rule's tally,
        // which reads as a single regex matching 3,624 times across 1,080
        // samples. Nothing in the record could say how many rules produced the
        // recall, or whether removing one would collapse it.
        //
        // The Set is a safety net, not the fix: src/engine.ts emits at most one
        // ATRMatch per rule per event. It keeps the per-rule tallies per SAMPLE
        // even if that ever changes, so a rule can never earn a larger apparent
        // share of the true positives than the run had true positives.
        const seen = new Set<string>();
        for (const m of matches) seen.add(m.rule.id);
        for (const id of seen) {
          matchedByRule[id] = (matchedByRule[id] ?? 0) + 1;
          if (seen.size === 1) soleByRule[id] = (soleByRule[id] ?? 0) + 1;
        }
      } else {
        missed++;
        missedRecords.push({ text, record });
      }
    } catch (_) {
      // engine errors count as missed
      missed++;
      missedRecords.push({ text, record });
    }
  }

  return {
    total: matched + missed,
    matched,
    missed,
    missedRecords,
    matchedByRule,
    canonicalMatchedByRule,
    canonicalMatched,
    soleByRule,
    canonicalSoleByRule,
  };
}

/** Concentration of a corpus's true positives in its single most-firing rule. */
interface Concentration {
  rules_fired: number;
  rules_loaded: number;
  top_rule_id: string | null;
  top_rule_tp: number;
  /** Share of MATCHED SAMPLES the single top rule alone accounts for. */
  top_rule_share_of_tp: number;
  /** Recall that survives if the single top rule is deleted. */
  recall_without_top_rule: number;
}

function concentration(
  byRule: Record<string, number>,
  matchedSamples: number,
  totalSamples: number,
  rulesLoaded: number,
  soleAttributions: number,
): Concentration {
  const ranked = Object.entries(byRule).sort((a, b) => b[1] - a[1]);
  const top = ranked[0];
  return {
    rules_fired: ranked.length,
    rules_loaded: rulesLoaded,
    top_rule_id: top ? top[0] : null,
    top_rule_tp: top ? top[1] : 0,
    top_rule_share_of_tp:
      matchedSamples === 0 || !top ? 0 : +(top[1] / matchedSamples).toFixed(4),
    recall_without_top_rule:
      totalSamples === 0 ? 0 : +((matchedSamples - soleAttributions) / totalSamples).toFixed(4),
  };
}

// N-gram phrase extractor (3-7 words, used by auto-regex)
function extractNgrams(text: string, minN = 3, maxN = 7): string[] {
  const words = text.toLowerCase()
    .replace(/[^a-z0-9\s'"-]/g, " ")
    .split(/\s+/)
    .filter(w => w.length > 0);
  const ngrams: string[] = [];
  for (let n = minN; n <= maxN; n++) {
    for (let i = 0; i <= words.length - n; i++) {
      const phrase = words.slice(i, i + n).join(" ");
      if (phrase.length >= 12 && phrase.length <= 80) {
        ngrams.push(phrase);
      }
    }
  }
  return ngrams;
}

// Cluster missed prompts by dominant n-gram phrase
function clusterMisses(
  missedRecords: Array<{ text: string; record: PromptRecord }>,
  minClusterSize = 5
): Array<{
  phrase: string;
  count: number;
  examples: string[];
  attack_types: string[];
}> {
  // Count phrase occurrences across all missed prompts
  const phraseCount: Record<string, number> = {};
  const phraseExamples: Record<string, string[]> = {};
  const phraseTypes: Record<string, Set<string>> = {};

  for (const { text, record } of missedRecords) {
    const ngrams = extractNgrams(text);
    const seenForThisDoc = new Set<string>();
    for (const phrase of ngrams) {
      if (!seenForThisDoc.has(phrase)) {
        seenForThisDoc.add(phrase);
        phraseCount[phrase] = (phraseCount[phrase] ?? 0) + 1;
        phraseExamples[phrase] = phraseExamples[phrase] ?? [];
        if (phraseExamples[phrase].length < 15) {
          phraseExamples[phrase].push(text);
        }
        phraseTypes[phrase] = phraseTypes[phrase] ?? new Set();
        const t = record.attack_type ?? record.attack_class ?? record.attack_key ?? "unknown";
        phraseTypes[phrase].add(t);
      }
    }
  }

  // Sort by count desc, filter by minClusterSize
  const entries = Object.entries(phraseCount)
    .filter(([, c]) => c >= minClusterSize)
    .sort((a, b) => b[1] - a[1]);

  // Greedy de-overlap: skip phrases that are substrings of a higher-scoring selected phrase
  const selected: Array<{
    phrase: string;
    count: number;
    examples: string[];
    attack_types: string[];
  }> = [];

  for (const [phrase, count] of entries) {
    const dominated = selected.some(
      s => s.phrase.includes(phrase) || phrase.includes(s.phrase)
    );
    if (!dominated) {
      selected.push({
        phrase,
        count,
        examples: [...new Set(phraseExamples[phrase])].slice(0, 12),
        attack_types: Array.from(phraseTypes[phrase]),
      });
    }
    if (selected.length >= 20) break;
  }

  return selected;
}

/** Both attribution views of one corpus, ready for JSON or a console banner. */
function attribution(res: RecallResult, rulesLoaded: number) {
  return {
    /**
     * The shape the headline recall is measured on. Narrow by construction —
     * see legacyLlmIoEvent.
     */
    legacy_llm_io: {
      shape: "llm_io { content, fields.user_input }",
      matched_samples: res.matched,
      ...concentration(
        res.matchedByRule,
        res.matched,
        res.total,
        rulesLoaded,
        res.soleByRule[
          Object.entries(res.matchedByRule).sort((a, b) => b[1] - a[1])[0]?.[0] ?? ""
        ] ?? 0,
      ),
      rules: Object.entries(res.matchedByRule)
        .sort((a, b) => b[1] - a[1])
        .map(([id, n]) => ({ rule_id: id, samples: n, sole_detector_on: res.soleByRule[id] ?? 0 })),
    },
    /**
     * The canonical shape set from scripts/lib/corpus-event.ts — identical to
     * what the benign FP gate charges rules on, so recall and FP here are
     * measured on the same presentation of the same text.
     */
    canonical_shapes: {
      shapes: [...shapeNames(), "scanSkill"],
      matched_samples: res.canonicalMatched,
      ...concentration(
        res.canonicalMatchedByRule,
        res.canonicalMatched,
        res.total,
        rulesLoaded,
        res.canonicalSoleByRule[
          Object.entries(res.canonicalMatchedByRule).sort((a, b) => b[1] - a[1])[0]?.[0] ?? ""
        ] ?? 0,
      ),
      rules: Object.entries(res.canonicalMatchedByRule)
        .sort((a, b) => b[1] - a[1])
        .map(([id, n]) => ({
          rule_id: id,
          samples: n,
          sole_detector_on: res.canonicalSoleByRule[id] ?? 0,
        })),
    },
  };
}

function reportConcentration(label: string, res: RecallResult, rulesLoaded: number): void {
  const a = attribution(res, rulesLoaded);
  for (const [view, v] of Object.entries(a)) {
    console.log(
      `  [${label}/${view}] rulesFired ${v.rules_fired}/${v.rules_loaded}` +
        ` · top ${v.top_rule_id ?? "-"} = ${v.top_rule_tp} TP` +
        ` (${(v.top_rule_share_of_tp * 100).toFixed(1)}% of matched samples)` +
        ` · recall without it ${(v.recall_without_top_rule * 100).toFixed(1)}%`,
    );
  }
}

async function main() {
  console.log("Loading ATR engine...");
  const engine = new ATREngine({ rulesDir: join(REPO, "rules") });
  const ruleCount = await engine.loadRules();
  console.log(`Engine initialized with ${ruleCount} rules.\n`);

  // ---- PromptBench ----
  console.log("=== PromptBench Analysis ===");
  const pbRecords: PromptRecord[] = JSON.parse(readFileSync(PB_FILE, "utf-8"));
  console.log(`Loaded ${pbRecords.length} promptbench records`);

  const pbResult = await runRecallAnalysis("promptbench", pbRecords, engine);
  console.log(`  Matched: ${pbResult.matched}/${pbResult.total} (${(pbResult.matched/pbResult.total*100).toFixed(1)}%)`);
  console.log(`  Missed: ${pbResult.missed}`);
  reportConcentration("promptbench", pbResult, ruleCount);

  const pbClusters = clusterMisses(pbResult.missedRecords, 8);
  console.log(`  Clusters (>= 8 examples): ${pbClusters.length}`);
  for (const c of pbClusters.slice(0, 15)) {
    console.log(`    [${c.count}] "${c.phrase}" (${c.attack_types.join(",")})`);
  }

  // ---- PromptInject ----
  console.log("\n=== PromptInject Analysis ===");
  const piRecords: PromptRecord[] = JSON.parse(readFileSync(PI_FILE, "utf-8"));
  console.log(`Loaded ${piRecords.length} promptinject records`);

  const piResult = await runRecallAnalysis("promptinject", piRecords, engine);
  console.log(`  Matched: ${piResult.matched}/${piResult.total} (${(piResult.matched/piResult.total*100).toFixed(1)}%)`);
  console.log(`  Missed: ${piResult.missed}`);
  reportConcentration("promptinject", piResult, ruleCount);

  const piClusters = clusterMisses(piResult.missedRecords, 5);
  console.log(`  Clusters (>= 5 examples): ${piClusters.length}`);
  for (const c of piClusters.slice(0, 15)) {
    console.log(`    [${c.count}] "${c.phrase}" (${c.attack_types.join(",")})`);
  }

  // Write analysis output
  const analysisOut = {
    promptbench: {
      total: pbResult.total,
      matched: pbResult.matched,
      missed: pbResult.missed,
      recall_pct: +(pbResult.matched/pbResult.total*100).toFixed(1),
      attribution: attribution(pbResult, ruleCount),
      top_matching_rules: Object.entries(pbResult.matchedByRule)
        .sort((a,b) => b[1]-a[1]).slice(0, 10)
        .map(([id, n]) => ({ id, n })),
      clusters: pbClusters,
      missed_sample: pbResult.missedRecords.slice(0, 30).map(x => ({
        text: x.text.slice(0, 200),
        attack_type: x.record.attack_type ?? x.record.attack_class,
      })),
    },
    promptinject: {
      total: piResult.total,
      matched: piResult.matched,
      missed: piResult.missed,
      recall_pct: +(piResult.matched/piResult.total*100).toFixed(1),
      attribution: attribution(piResult, ruleCount),
      top_matching_rules: Object.entries(piResult.matchedByRule)
        .sort((a,b) => b[1]-a[1]).slice(0, 10)
        .map(([id, n]) => ({ id, n })),
      clusters: piClusters,
      missed_sample: piResult.missedRecords.slice(0, 30).map(x => ({
        text: x.text.slice(0, 200),
        attack_class: x.record.attack_class,
        attack_key: x.record.attack_key,
      })),
    },
  };

  writeFileSync(
    join(REPO, "data/test-corpora/recall-analysis.json"),
    JSON.stringify(analysisOut, null, 2)
  );
  console.log("\nWrote data/test-corpora/recall-analysis.json");

  // Standardized Measurement files (version-pinned, immutable). Both corpora
  // are 100% adversarial → precision = 1 by construction, fp_rate undefined (0).
  const writePure = (
    source: "promptbench" | "promptinject",
    res: RecallResult,
  ) => {
    const recall = res.matched / res.total;
    const f1 = recall === 0 ? 0 : (2 * recall) / (recall + 1);
    const attr = attribution(res, ruleCount);
    const topRules = attr.legacy_llm_io.rules
      .slice(0, 10)
      .map((r) => ({ rule_id: r.rule_id, matches: r.samples }));
    const { measurementPath } = writeMeasurement(
      {
        source,
        source_version: "snapshot-2026-04",
        samples: res.total,
        metrics: {
          recall,
          precision: 1,
          f1,
          fp_rate: 0,
        },
        confusion: {
          tp: res.matched,
          fp: 0,
          tn: 0,
          fn: res.missed,
        },
        breakdown: { top_matching_rules: topRules, attribution: attr },
        notes:
          `${source} academic adversarial corpus — 100% attack samples; fp_rate undefined and recorded as 0 by convention. ` +
          `precision=1 is a property of the corpus (no benign samples), NOT a measured result — read it with the benign-gate FP rate, never alone. ` +
          `Recall is measured on the narrow llm_io event (breakdown.attribution.legacy_llm_io); ` +
          `breakdown.attribution.canonical_shapes gives the same corpus on the shape set the benign FP gate uses. ` +
          `Concentration (top_rule_share_of_tp / recall_without_top_rule) states how much of the number rests on a single rule.`,
      },
      { force: true },
    );
    console.log(`  Measurement: ${measurementPath}`);
  };
  writePure("promptbench", pbResult);
  writePure("promptinject", piResult);
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
