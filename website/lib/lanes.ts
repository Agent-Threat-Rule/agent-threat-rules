/**
 * Which detection lanes evaluate a rule, mirroring the reference engine:
 *
 *   src/engine.ts evaluates()          status draft or deprecated -> no lane at all
 *   src/quality/rule-contract.ts       enforce = maturity stable
 *     laneAllows()                     alert   = maturity stable or test
 *                                      hunt    = every maturity except deprecated
 *
 * A rule in no lane is "inert": its file is on main but no engine loads it.
 * This file has no imports so the client-side rule explorer can use it too.
 */

export const LANES = ["enforce", "alert", "hunt"] as const;
export type Lane = (typeof LANES)[number];

const MATURITIES: ReadonlySet<string> = new Set(["draft", "experimental", "test", "stable", "deprecated"]);

/** As normalizeMaturity() in src/quality/rule-contract.ts: missing or unknown reads as experimental. */
export function normalizeMaturity(maturity: unknown): string {
  const s = String(maturity ?? "").trim();
  return MATURITIES.has(s) ? s : "experimental";
}

export function rulesLanes(rule: { status?: string; maturity?: string }): Lane[] {
  if (rule.status === "draft" || rule.status === "deprecated") return [];
  const m = normalizeMaturity(rule.maturity);
  if (m === "deprecated") return [];
  return LANES.filter((lane) => lane === "hunt" || m === "stable" || (lane === "alert" && m === "test"));
}

export interface LaneCounts {
  /** Rule files on main. */
  files: number;
  /** Files the engine loads in at least one lane. */
  effective: number;
  /** Files in no lane (status draft or deprecated). */
  inert: number;
  byLane: Record<Lane, number>;
}

export function countLanes(rules: ReadonlyArray<{ status?: string; maturity?: string }>): LaneCounts {
  const lanes = rules.map(rulesLanes);
  const byLane = Object.fromEntries(
    LANES.map((lane) => [lane, lanes.filter((l) => l.includes(lane)).length]),
  ) as Record<Lane, number>;
  const effective = lanes.filter((l) => l.length > 0).length;
  return { files: rules.length, effective, inert: rules.length - effective, byLane };
}
