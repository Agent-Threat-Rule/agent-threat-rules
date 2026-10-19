/**
 * `breakdown.in_sample_ablation` of a measurement: the same samples re-measured
 * with the rules written from that corpus removed. `reference` names the
 * ablation to cite beside the headline. It approximates an out-of-sample
 * figure; it is not one, so every surface that quotes it calls it the ablation
 * reference.
 *
 * @module agent-threat-rules/measurement/in-sample-ablation
 */

export const IN_SAMPLE_ABLATION_BREAKDOWN_KEY = 'in_sample_ablation' as const;

export interface AblationLaneFigure {
  readonly detected: number;
  readonly attacks: number;
  readonly recall: number;
}

export interface AblationReference {
  /** Key of the cited ablation inside breakdown.in_sample_ablation. */
  readonly key: string;
  readonly removed_rule_ids: readonly string[];
  readonly hunt: AblationLaneFigure;
  readonly enforce: AblationLaneFigure;
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0;

function laneFigure(raw: unknown, where: string): AblationLaneFigure {
  if (!isRecord(raw) || !isCount(raw.detected) || !isCount(raw.attacks) || raw.attacks === 0
    || typeof raw.recall !== 'number' || Math.abs(raw.recall - raw.detected / raw.attacks) > 1e-9) {
    throw new Error(`${where} is malformed (detected / attacks / recall)`);
  }
  return { detected: raw.detected, attacks: raw.attacks, recall: raw.recall };
}

/**
 * The cited ablation, or null when the measurement records none. A record
 * that is present but malformed throws: quoting a headline without the
 * reference it is meant to travel with is the failure this record prevents.
 */
export function parseAblationReference(breakdown: unknown): AblationReference | null {
  if (!isRecord(breakdown)) return null;
  const raw = breakdown[IN_SAMPLE_ABLATION_BREAKDOWN_KEY];
  if (raw === undefined) return null;
  const where = `breakdown.${IN_SAMPLE_ABLATION_BREAKDOWN_KEY}`;
  if (!isRecord(raw) || typeof raw.reference !== 'string') throw new Error(`${where}.reference is missing`);
  const rec = raw[raw.reference];
  if (!isRecord(rec) || !Array.isArray(rec.removed_rule_ids) || !isRecord(rec.lanes)) {
    throw new Error(`${where}.${raw.reference} is malformed`);
  }
  return {
    key: raw.reference,
    removed_rule_ids: rec.removed_rule_ids.filter((x): x is string => typeof x === 'string'),
    hunt: laneFigure(rec.lanes.hunt, `${where}.${raw.reference}.lanes.hunt`),
    enforce: laneFigure(rec.lanes.enforce, `${where}.${raw.reference}.lanes.enforce`),
  };
}
