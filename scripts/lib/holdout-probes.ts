/**
 * holdout-probes.ts — the per-rule measurements that need the rule alone:
 * declared evasion tests, robustness of its held-out detections, and cost.
 *
 * Each probe runs on an engine that holds exactly one rule, so a time or a
 * verdict is that rule's and no other's.
 *
 * ROBUSTNESS
 *   For a sample of the rule's held-out true positives, apply a transform an
 *   attacker controls and count how many the rule still catches. These are the
 *   evasions the rule's own `evasion_tests` should document. Two transforms
 *   are about the engine rather than the rule:
 *     embed-in-tool-output  the payload inside an ordinary JSON tool result,
 *                           the way an indirect injection actually arrives;
 *     pad-past-scan-limit   the payload after 150,000 characters of benign
 *                           text. On an engine that skips fields longer than
 *                           its scan limit this drops to 0 for every rule:
 *                           that is the fail-open, measured.
 *
 * COST
 *   p50/p99/max over a fixed set of held-out texts, plus one 100,000-character
 *   field (the longest field the engine scans whole) built from benign text.
 *   The 0.3 s budget is data/redos-baseline.json's; the adversarial ReDoS
 *   inputs themselves are scripts/gate-redos.py's job, whose known entries are
 *   read from that baseline rather than re-derived here.
 */
import { ATREngine } from "../../src/engine.js";
import type { ATRRule } from "../../src/types.js";
import { matchedRuleIds } from "./corpus-event.js";
import { transformById } from "./garak-transforms.js";
import { percentile, type EvasionTestResult, type RobustnessResult } from "./holdout-evidence.js";

export const ROBUSTNESS_SAMPLE = 20;
export const PAD_CHARS = 150_000;
export const LONG_FIELD_CHARS = 100_000;

export function singleRuleEngine(rule: ATRRule): ATREngine {
  const engine = new ATREngine();
  engine.addRule(rule);
  return engine;
}

function hits(engine: ATREngine, id: string, text: string): boolean {
  return matchedRuleIds(engine, text).has(id);
}

/** Run a rule's declared evasion_tests through the canonical shapes. */
export function evasionTests(engine: ATREngine, rule: ATRRule): EvasionTestResult {
  const cases = Array.isArray(rule.evasion_tests) ? rule.evasion_tests : [];
  let notTriggeredButTriggered = 0;
  let triggeredButNotTriggered = 0;
  for (const c of cases) {
    if (typeof c?.input !== "string") continue;
    const hit = hits(engine, rule.id, c.input);
    if (c.expected === "not_triggered" && hit) notTriggeredButTriggered++;
    if (c.expected === "triggered" && !hit) triggeredButNotTriggered++;
  }
  return { declared: cases.length, notTriggeredButTriggered, triggeredButNotTriggered };
}

export interface Transform {
  readonly id: string;
  readonly apply: (text: string) => string;
}

function garak(id: string): Transform {
  const t = transformById(id);
  return { id, apply: (s) => t.expand(s)[0] ?? s };
}

export function engineTransforms(benignPad: string, toolOutput: string): readonly Transform[] {
  return Object.freeze([
    {
      id: "embed-in-tool-output",
      apply: (s: string) => JSON.stringify({ status: "ok", result: toolOutput, note: s }),
    },
    { id: "pad-past-scan-limit", apply: (s: string) => `${benignPad.slice(0, PAD_CHARS)}\n${s}` },
    garak("badchars-homoglyph"),
    garak("badchars-invisible"),
    garak("encoding-leetspeak"),
    garak("encoding-base64"),
  ]);
}

export function robustness(
  engine: ATREngine,
  id: string,
  tpTexts: readonly string[],
  transforms: readonly Transform[],
): readonly RobustnessResult[] {
  const sample = tpTexts.slice(0, ROBUSTNESS_SAMPLE);
  return transforms.map((t) => ({
    transform: t.id,
    applied: sample.length,
    retained: sample.filter((s) => hits(engine, id, t.apply(s))).length,
  }));
}

export function cost(
  engine: ATREngine,
  texts: readonly string[],
  longField: string,
): { p50: number; p99: number; max: number; longInputMs: number } {
  const times: number[] = [];
  for (const t of texts) {
    const start = performance.now();
    matchedRuleIds(engine, t);
    times.push(performance.now() - start);
  }
  const start = performance.now();
  matchedRuleIds(engine, longField.slice(0, LONG_FIELD_CHARS));
  const longInputMs = performance.now() - start;
  const round = (n: number): number => Math.round(n * 1000) / 1000;
  return {
    p50: round(percentile(times, 0.5)),
    p99: round(percentile(times, 0.99)),
    max: round(Math.max(0, ...times)),
    longInputMs: round(longInputMs),
  };
}

/** Build a benign filler of at least `chars` characters from benign texts, in order. */
export function benignFiller(texts: readonly string[], chars: number): string {
  const parts: string[] = [];
  let n = 0;
  for (let i = 0; n < chars && texts.length > 0; i++) {
    const t = texts[i % texts.length]!;
    parts.push(t);
    n += t.length + 1;
  }
  return parts.join("\n");
}
