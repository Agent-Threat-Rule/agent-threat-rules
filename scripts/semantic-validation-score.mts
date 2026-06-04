#!/usr/bin/env tsx
/**
 * Reproducible scorer for the semantic-validation corpus (data/semantic-validation/).
 *
 * Stage 1: the deterministic ATR regex engine (all rules) screens every item.
 * Stage 2: a semantic judge adjudicates the items Stage 1 missed. Judge verdicts
 *          come from scan-with-judge.mts (OpenAI-compatible backend, or the no-key
 *          worklist mode where a Claude Code session is the judge), passed via
 *          --verdicts. Without --verdicts, only the Stage-1 regex layer is scored.
 *
 * This measures the TWO narrow threats the v3.1.0 semantic rules target:
 * paraphrased instruction-override (00573) and indirect system-prompt extraction
 * (00574). It is a focused validation harness, NOT an independent benchmark.
 *
 * Usage: tsx scripts/semantic-validation-score.mts [--verdicts verdicts.json]
 */
import { ATREngine } from "../src/index.js";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const THRESHOLD = Number(process.env.JUDGE_THRESHOLD ?? "0.7");
const RULES = resolve(import.meta.dirname, "../rules");
const DIR = resolve(import.meta.dirname, "../data/semantic-validation");

function fieldToEventType(field: string): string {
  const m: Record<string, string> = { user_input: "llm_input", tool_response: "tool_response", tool_description: "tool_call", tool_name: "tool_call", tool_args: "tool_call", content: "llm_input" };
  return m[field] || "llm_input";
}
const payloadOf = (it: any): string => it.payload ?? it.content ?? it.text ?? "";

const engine = new ATREngine({ rulesDir: RULES });
await engine.loadRules();

function regexHits(it: any): string[] {
  const field = it.detection_field ?? "user_input";
  const payload = payloadOf(it);
  const ev: any = { type: fieldToEventType(field), content: payload, timestamp: new Date().toISOString(), fields: { [field]: payload } };
  let m: any[] = [];
  try { m = engine.evaluate(ev); } catch { /* ignore */ }
  return m.map((x) => x.rule?.id ?? "?");
}

const verdictsArg = process.argv.indexOf("--verdicts");
const verdicts: Record<string, any> = {};
if (verdictsArg >= 0) {
  const arr: any[] = JSON.parse(readFileSync(process.argv[verdictsArg + 1], "utf8"));
  for (const v of arr) verdicts[String(v.id)] = v;
}
const judgeFlags = (id: string): boolean => {
  const v = verdicts[String(id)];
  return !!(v && v.category && v.category !== "benign" && v.category !== "unknown" && Number(v.confidence) >= THRESHOLD);
};

const attacks: any[] = JSON.parse(readFileSync(resolve(DIR, "attacks.json"), "utf8"));
const benign: any[] = JSON.parse(readFileSync(resolve(DIR, "benign.json"), "utf8"));

let aRegex = 0, aJudge = 0;
console.log(`=== ATTACKS (n=${attacks.length}) ===`);
for (const it of attacks) {
  const hits = regexHits(it);
  const r = hits.length > 0;
  if (r) aRegex++;
  const j = !r && judgeFlags(it.id);
  if (j) aJudge++;
  const stat = r ? "regex " : j ? "judge " : verdictsArg >= 0 ? "MISS  " : "→judge";
  console.log(`  [${stat}] ${it.id}${r ? "  " + hits.join(",") : ""}`);
}

let bRegexFP = 0, bJudgeFP = 0, bCombinedFP = 0;
console.log(`=== BENIGN (n=${benign.length}) — only FPs shown ===`);
for (const it of benign) {
  const hits = regexHits(it);
  const r = hits.length > 0;
  const j = judgeFlags(it.id);
  if (r) bRegexFP++;
  if (j) bJudgeFP++;
  if (r || j) { bCombinedFP++; console.log(`  [${r ? "regex-FP" : "judge-FP"}] ${it.id}  ${hits.join(",")}`); }
}

const A = attacks.length, B = benign.length;
const aCombined = aRegex + aJudge;
const tp = aCombined, fp = bCombinedFP;
const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
console.log("\n=== SUMMARY (threshold " + THRESHOLD + ") ===");
console.log(`Attack recall:   regex ${aRegex}/${A} (${(aRegex / A * 100).toFixed(0)}%)  →  +semantic ${aJudge}  →  combined ${aCombined}/${A} (${(aCombined / A * 100).toFixed(0)}%)`);
console.log(`Benign FP:       regex ${bRegexFP}/${B}  |  judge ${bJudgeFP}/${B}  |  combined ${bCombinedFP}/${B} (${(bCombinedFP / B * 100).toFixed(0)}%)`);
console.log(`Precision proxy: ${(precision * 100).toFixed(1)}%  (TP ${tp} / (TP ${tp} + FP ${fp}))`);
if (verdictsArg < 0) console.log("(regex-only — pass --verdicts to score the semantic judge stage)");
