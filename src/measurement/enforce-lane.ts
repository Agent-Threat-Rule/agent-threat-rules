/**
 * src/measurement/enforce-lane.ts
 *
 * The enforce-lane figure every benchmark runner records beside its headline,
 * as `breakdown.enforce_lane` (shape and validation: ./schema.ts).
 *
 * WHY THIS EXISTS
 *
 * A runner's headline recall comes from `new ATREngine({ rulesDir })`, and an
 * engine given no lane is pinned to `hunt`, which loads every maturity. The
 * enforce lane — the one to run with blocking on, where a detection stops the
 * agent with no human in the loop — loads only `maturity: stable`. On ATR 4.1.5
 * the headline garak corpus scored 600 of 650 in hunt and 6 of 650 in enforce,
 * and the SKILL.md corpus 32 of 32 against 0 of 32. Those enforce figures were
 * one-off replays: no measurement recorded them, so README could cite them only
 * as figures nothing refreshed, and stats.json dropped the one it had.
 *
 * THE RULE: SAME SAMPLES, SAME LOOP, OTHER LANE
 *
 * A runner passes the predicate that decides its own headline — the same
 * function, not a re-implementation — to `enforceLaneRecallOf`, which runs it
 * on an engine constructed with `lane: 'enforce'` over the same attack samples.
 * Anything else (a wider event shape, a different sample filter) would make the
 * enforce figure a measurement of something the headline is not.
 */

import { ATREngine, type ATREngineConfig } from "../engine.js";
import { laneAllows, type Lane } from "../quality/rule-contract.js";
import { parseEnforceLaneRecall, type EnforceLaneRecall } from "./schema.js";

export type { EnforceLaneRecall } from "./schema.js";

/** Stored in every record, so the figure explains itself wherever it is read. */
export const ENFORCE_LANE_NOTE =
  "Recall of the same attack samples, through the same detection loop as metrics.recall, " +
  "on an engine constructed with lane: 'enforce', which loads only maturity: stable rules: " +
  "the lane README recommends when blocking is on. A match is not necessarily a block (src/verdict.ts " +
  "decides that from severity and confidence), so this is an upper bound on what blocking stops. " +
  "metrics.recall is the hunt lane (the engine default, every maturity). Not a headline.";

/**
 * Rules an engine in `lane` loads: the engine's own two gates, in its order —
 * status `draft` / `deprecated` is skipped outright (src/engine.ts), then the
 * maturity -> lane mapping every pipeline imports (laneAllows). A loaded rule
 * marked `confirm: embedding` still fires only once embedding similarity
 * confirms it, outside the hunt lane; the synchronous evaluate() most runners
 * use cannot confirm, so on that path such a rule is counted here but never
 * fires.
 */
export function rulesInLane(rules: readonly { status?: unknown; maturity?: unknown }[], lane: Lane): number {
  return rules.filter((r) => r.status !== "draft" && r.status !== "deprecated" && laneAllows(r.maturity, lane))
    .length;
}

/** An engine in the enforce lane, and how many rules that lane loads. */
export interface EnforceLaneEngine {
  readonly engine: ATREngine;
  readonly rulesInLane: number;
}

/**
 * Construct and load an enforce-lane engine. Throws when no rule loads: an
 * engine with no rules reports 0 recall, which reads as a measured result.
 */
export async function loadEnforceLaneEngine(config: Omit<ATREngineConfig, "lane">): Promise<EnforceLaneEngine> {
  const engine = new ATREngine({ ...config, lane: "enforce" });
  const loaded = await engine.loadRules();
  if (loaded === 0) {
    throw new Error(`enforce lane: no rules loaded from ${config.rulesDir ?? "the bundled rules directory"}`);
  }
  return { engine, rulesInLane: rulesInLane(engine.getRules(), "enforce") };
}

/** The record, validated by the same parser verify.ts runs over every file. */
export function enforceLaneRecall(input: { detected: number; attacks: number; rulesInLane: number }): EnforceLaneRecall {
  const { detected, attacks, rulesInLane: inLane } = input;
  if (!Number.isInteger(attacks) || attacks < 1) {
    throw new Error(`enforce lane: attacks must be a positive integer, got ${attacks}`);
  }
  if (!Number.isInteger(detected) || detected < 0 || detected > attacks) {
    throw new Error(`enforce lane: detected must be an integer in [0, ${attacks}], got ${detected}`);
  }
  return parseEnforceLaneRecall({
    lane: "enforce",
    detected,
    attacks,
    recall: detected / attacks,
    rules_in_lane: inLane,
    note: ENFORCE_LANE_NOTE,
  });
}

/**
 * Run `detect` — the runner's own headline predicate — once per attack sample
 * on the enforce-lane engine, and record how many it detected.
 */
export function enforceLaneRecallOf<T>(
  samples: readonly T[],
  detect: (engine: ATREngine, sample: T) => boolean,
  lane: EnforceLaneEngine,
): EnforceLaneRecall {
  if (lane.engine.getLane() !== "enforce") {
    throw new Error(`enforce lane: the engine is in the ${lane.engine.getLane()} lane, not enforce`);
  }
  const detected = samples.filter((s) => detect(lane.engine, s)).length;
  return enforceLaneRecall({ detected, attacks: samples.length, rulesInLane: lane.rulesInLane });
}
