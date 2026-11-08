import { rulesLanes } from "./lanes";

/**
 * How the effective rules record `metadata_provenance`, counted from rules/ at
 * build time so the quality-standard page never carries a hand-typed share.
 *
 * The field records who or what set each mapping field of a rule (OWASP, MITRE,
 * CWE and so on), or which corpus a payload came from. It does not say who
 * wrote the detection logic, so the buckets describe the mappings only.
 */

const HUMAN_VALUES: ReadonlySet<string> = new Set(["human-reviewed", "human-authored"]);

export interface ProvenanceBreakdown {
  /** Rules the engine loads in at least one lane. */
  total: number;
  /** At least one field marked human-reviewed or human-authored. */
  human: number;
  /** Provenance recorded, but no field marked by a human (auto-generated mappings, sync feeds, corpus sources). */
  other: number;
  /** No metadata_provenance block at all. */
  none: number;
  /** Effective rules at maturity stable (the enforce lane). */
  stable: number;
  /** Stable rules with at least one field marked by a human. */
  stableHuman: number;
}

export function provenanceBreakdown(
  rules: ReadonlyArray<{ status?: string; maturity?: string; provenance?: readonly string[] }>,
): ProvenanceBreakdown {
  const effective = rules.filter((r) => rulesLanes(r).length > 0);
  const none = effective.filter((r) => r.provenance === undefined || r.provenance.length === 0).length;
  const byHuman = (r: { provenance?: readonly string[] }) => (r.provenance ?? []).some((v) => HUMAN_VALUES.has(v));
  const human = effective.filter(byHuman).length;
  const stable = effective.filter((r) => rulesLanes(r).includes("enforce"));
  return {
    total: effective.length,
    human,
    other: effective.length - none - human,
    none,
    stable: stable.length,
    stableHuman: stable.filter(byHuman).length,
  };
}

/** Whole-number percentage; "<1%" rather than a misleading 0% for a non-empty bucket. */
export function shareOf(part: number, total: number): string {
  if (total === 0) return "0%";
  const pct = Math.round((part / total) * 100);
  return pct === 0 && part > 0 ? "<1%" : `${pct}%`;
}
