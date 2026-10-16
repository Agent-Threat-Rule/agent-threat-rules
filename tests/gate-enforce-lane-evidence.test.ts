/**
 * Tests for scripts/gate-enforce-lane-evidence.ts, the ratchet over every
 * `maturity: stable` (enforce-lane) rule that lacks the evidence
 * docs/QUALITY-STANDARD.md requires.
 *
 * - shortfalls() names each missing or failing piece of evidence.
 * - classifyBaseline() splits the comparison with the committed baseline. A
 *   baselined rule that no longer shows a shortfall either still runs in the
 *   enforce lane and now meets the bar, or has left the lane (demoted, made
 *   inert or deleted). Before this split both were reported as "now meet the
 *   bar": #625 demoted ATR-2026-00080, -00436 and -01606 for false positives,
 *   and the gate then claimed those three now met the stable bar.
 */
import { describe, it, expect } from "vitest";
import {
  STABLE_MAX_WILD_FP_PCT,
  STABLE_MIN_CONFIDENCE,
  classifyBaseline,
  shortfalls,
  type Shortfall,
} from "../scripts/gate-enforce-lane-evidence.js";

const short = (id: string): Shortfall => ({ id, file: `rules/x/${id}.yaml`, reasons: ["no wild_fp_rate (never measured)"] });

describe("shortfalls", () => {
  it("passes a rule that meets both bars", () => {
    expect(shortfalls({ confidence: STABLE_MIN_CONFIDENCE, wild_fp_rate: STABLE_MAX_WILD_FP_PCT })).toEqual([]);
  });

  it("names absent evidence as absent, not as passing", () => {
    expect(shortfalls({})).toEqual(["no confidence field", "no wild_fp_rate (never measured)"]);
  });

  it("names each bar a rule misses", () => {
    expect(shortfalls({ confidence: STABLE_MIN_CONFIDENCE - 1, wild_fp_rate: STABLE_MAX_WILD_FP_PCT + 0.1 })).toEqual([
      `confidence ${STABLE_MIN_CONFIDENCE - 1} < ${STABLE_MIN_CONFIDENCE}`,
      `wild_fp_rate ${STABLE_MAX_WILD_FP_PCT + 0.1} > ${STABLE_MAX_WILD_FP_PCT}`,
    ]);
  });
});

describe("classifyBaseline", () => {
  it("fails only on a shortfall the baseline does not record", () => {
    const r = classifyBaseline(new Set(["A"]), [short("A"), short("B")], new Set(["A", "B"]));
    expect(r.novel.map((s) => s.id)).toEqual(["B"]);
    expect(r.nowMeetBar).toEqual([]);
    expect(r.leftEnforceLane).toEqual([]);
  });

  it("reports a baselined rule that is still stable and now passes as meeting the bar", () => {
    const r = classifyBaseline(new Set(["A"]), [], new Set(["A"]));
    expect(r.nowMeetBar).toEqual(["A"]);
    expect(r.leftEnforceLane).toEqual([]);
  });

  it("reports a baselined rule that is no longer stable as having left the lane, not as meeting the bar", () => {
    const r = classifyBaseline(new Set(["ATR-2026-00080", "ATR-2026-00436"]), [], new Set(["OTHER"]));
    expect(r.leftEnforceLane).toEqual(["ATR-2026-00080", "ATR-2026-00436"]);
    expect(r.nowMeetBar).toEqual([]);
    expect(r.novel).toEqual([]);
  });

  it("sorts each list so the report is stable from run to run", () => {
    const r = classifyBaseline(new Set(["C", "A", "B"]), [], new Set(["C", "A"]));
    expect(r.nowMeetBar).toEqual(["A", "C"]);
    expect(r.leftEnforceLane).toEqual(["B"]);
  });
});
