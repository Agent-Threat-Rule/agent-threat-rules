#!/usr/bin/env npx tsx
/**
 * ATR recall analysis against PromptBench and PromptInject corpora.
 * Runs extracted prompts against all ATR rules, identifies misses,
 * and clusters them by phrase/template family.
 */

import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve, join } from "node:path";
import { ATREngine } from "../src/engine.js";
import { writeMeasurement } from "../src/measurement/write.js";

const REPO = resolve("/Users/user/Downloads/agent-threat-rules");
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

async function runRecallAnalysis(
  label: string,
  records: PromptRecord[],
  engine: ATREngine
): Promise<{
  total: number;
  matched: number;
  missed: number;
  missedRecords: Array<{ text: string; record: PromptRecord }>;
  matchedByRule: Record<string, number>;
}> {
  let matched = 0;
  let missed = 0;
  const missedRecords: Array<{ text: string; record: PromptRecord }> = [];
  const matchedByRule: Record<string, number> = {};

  for (const record of records) {
    const text = getPromptText(record);
    if (!text || text.length < 5) continue;

    const event = {
      type: "llm_io" as const,
      timestamp: new Date().toISOString(),
      user_input: text,
      source: "user_input",
    };

    try {
      const matches = engine.evaluate(event);
      if (matches && matches.length > 0) {
        matched++;
        for (const m of matches) {
          const ruleId = (m as any).rule_id ?? (m as any).ruleId ?? "unknown";
          matchedByRule[ruleId] = (matchedByRule[ruleId] ?? 0) + 1;
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

  return { total: matched + missed, matched, missed, missedRecords, matchedByRule };
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
    res: typeof pbResult,
  ) => {
    const recall = res.matched / res.total;
    const f1 = recall === 0 ? 0 : (2 * recall) / (recall + 1);
    const topRules = Object.entries(res.matchedByRule)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([id, n]) => ({ rule_id: id, matches: n }));
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
        breakdown: { top_matching_rules: topRules },
        notes: `${source} academic adversarial corpus — 100% attack samples; fp_rate undefined and recorded as 0 by convention.`,
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
