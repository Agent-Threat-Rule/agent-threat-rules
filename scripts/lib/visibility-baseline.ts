/**
 * Baseline and ratchet logic for gate-corpus-visibility.ts.
 *
 * The baseline records a TIER per rule ("blind" or "thin"), never a visibility
 * number. Numbers move whenever the corpus grows, and a committed number that
 * nobody re-derives is exactly the stale artefact this repo keeps getting
 * burned by. The live numbers are in `--json`, regenerated on every run.
 *
 * The ratchet may only ever record an IMPROVEMENT:
 *   blind -> thin      recorded (debt shrank)
 *   thin  -> measured  entry dropped
 *   thin  -> blind     entry stays "thin", so the gate fails on the regression
 * Widening is the one move that would let this gate lie, so it is not
 * automatable: a genuine new exception has to be hand-written into the file
 * where review can see it.
 */
import { readFileSync } from "node:fs";
import { ENFORCE_LANE_MATURITIES } from "./corpus-event.js";
import type { RuleVisibility, VisibilityTier } from "./visibility-scan.js";

export const BASELINE_PATH = "data/corpus-visibility-baseline.json";

export const BASELINE_NOTE =
  "Rules the benign corpus (MEASUREMENT_CORPORA) cannot meaningfully test: it " +
  "contains too few samples that could match them, so a 0-false-positive result " +
  "for these rules is not evidence of precision. Tier only -- 'blind' means the " +
  "corpus can produce no candidate at all. Ratchet: entries may improve or be " +
  "removed, never added, to silence a new rule. See scripts/gate-corpus-visibility.ts.";

export class VisibilityBaselineError extends Error {}

export interface VisibilityBaseline {
  readonly generatedAt: string;
  readonly note: string;
  readonly visibilityFloor: number;
  readonly corpus: { readonly samples: number; readonly rules: number };
  /** ruleId -> recorded tier. Only "blind" and "thin" are ever stored. */
  readonly knownUnmeasured: Readonly<Record<string, VisibilityTier>>;
}

export const EMPTY_BASELINE: VisibilityBaseline = {
  generatedAt: "",
  note: BASELINE_NOTE,
  visibilityFloor: 0,
  corpus: { samples: 0, rules: 0 },
  knownUnmeasured: {},
};

const TIER_RANK: Readonly<Record<VisibilityTier, number>> = {
  blind: 0,
  thin: 1,
  measured: 2,
};

const STORED_TIERS = new Set<string>(["blind", "thin"]);

/**
 * Parse and validate. Never trusts the shape on disk: a corrupt file read as an
 * empty baseline turns the whole backlog into new failures, and one read as
 * "everything allowed" turns the gate into a no-op. Both are worse than
 * refusing to run.
 */
export function parseBaseline(raw: string, source: string): VisibilityBaseline {
  let doc: Partial<VisibilityBaseline>;
  try {
    doc = JSON.parse(raw) as Partial<VisibilityBaseline>;
  } catch (err) {
    throw new VisibilityBaselineError(`${source}: not valid JSON -- ${(err as Error).message}`);
  }
  const known = doc.knownUnmeasured;
  if (known === undefined || known === null || typeof known !== "object" || Array.isArray(known)) {
    throw new VisibilityBaselineError(
      `${source}: "knownUnmeasured" must be an object of ruleId -> tier`,
    );
  }
  for (const [id, tier] of Object.entries(known)) {
    if (typeof tier !== "string" || !STORED_TIERS.has(tier)) {
      throw new VisibilityBaselineError(
        `${source}: ${id} has tier ${JSON.stringify(tier)}; only "blind" or "thin" may be recorded`,
      );
    }
  }
  return { ...EMPTY_BASELINE, ...doc, knownUnmeasured: { ...known } };
}

export function loadBaseline(path: string): VisibilityBaseline {
  return parseBaseline(readFileSync(path, "utf-8"), path);
}

// ---------------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------------

export interface VisibilityComparison {
  /** Below the floor with no baseline entry. These fail the build. */
  readonly newlyUnmeasured: readonly RuleVisibility[];
  /** Baselined rules now worse than recorded. These fail the build. */
  readonly regressed: readonly RuleVisibility[];
  /** Baselined rules still at their recorded tier. Accepted debt. */
  readonly grandfathered: readonly RuleVisibility[];
  /** Below-floor rules in the auto-blocking enforce lane. Loud by default. */
  readonly enforceLaneDebt: readonly RuleVisibility[];
  /** Baseline ids that improved past their record (or vanished). Tighten these. */
  readonly resolved: readonly string[];
  readonly baselineSize: number;
}

export function compareToBaseline(
  results: readonly RuleVisibility[],
  baseline: VisibilityBaseline,
): VisibilityComparison {
  const recorded = baseline.knownUnmeasured;
  const newlyUnmeasured: RuleVisibility[] = [];
  const regressed: RuleVisibility[] = [];
  const grandfathered: RuleVisibility[] = [];
  const seen = new Set<string>();

  for (const rule of results) {
    const record = recorded[rule.id];
    if (record !== undefined) seen.add(rule.id);
    if (rule.tier === "measured") continue;
    if (record === undefined) {
      newlyUnmeasured.push(rule);
      continue;
    }
    if (TIER_RANK[rule.tier] < TIER_RANK[record]) regressed.push(rule);
    else grandfathered.push(rule);
  }

  const resolved = Object.keys(recorded)
    .filter((id) => {
      const rule = results.find((r) => r.id === id);
      return rule === undefined || TIER_RANK[rule.tier] > TIER_RANK[recorded[id] as VisibilityTier];
    })
    .sort();

  const enforceLaneDebt = [...newlyUnmeasured, ...regressed, ...grandfathered]
    .filter((r) => ENFORCE_LANE_MATURITIES.has(r.maturity))
    .sort((a, b) => a.visibility - b.visibility || a.id.localeCompare(b.id));

  return {
    newlyUnmeasured,
    regressed,
    grandfathered,
    enforceLaneDebt,
    resolved,
    baselineSize: Object.keys(recorded).length,
  };
}

/**
 * Tighten-only rebuild. Entries are kept at the BETTER of their recorded tier
 * and the tier observed now, so a regression cannot be laundered into the
 * baseline by re-running --write-baseline. Nothing is ever added.
 */
export function tightenBaseline(
  baseline: VisibilityBaseline,
  results: readonly RuleVisibility[],
  now: string,
  sampleCount = 0,
  visibilityFloor = 0,
): VisibilityBaseline {
  const current = new Map(results.map((r) => [r.id, r.tier] as const));
  const next: Record<string, VisibilityTier> = {};
  for (const [id, recordedTier] of Object.entries(baseline.knownUnmeasured)) {
    const observed = current.get(id);
    if (observed === undefined) continue; // rule is gone
    const best = TIER_RANK[observed] > TIER_RANK[recordedTier] ? observed : recordedTier;
    if (best === "measured") continue; // debt cleared
    next[id] = best;
  }
  return {
    generatedAt: now,
    note: BASELINE_NOTE,
    visibilityFloor: visibilityFloor || baseline.visibilityFloor,
    corpus: {
      samples: sampleCount || baseline.corpus.samples,
      rules: results.length,
    },
    knownUnmeasured: Object.fromEntries(
      Object.entries(next).sort(([a], [b]) => a.localeCompare(b)),
    ),
  };
}
