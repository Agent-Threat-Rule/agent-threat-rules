/**
 * Unit tests for scripts/lib/enforce-lane-entry.ts: what counts as firing in the
 * enforce lane, and which changed rule files enter it.
 *
 * The decision has to match the engine, not a tidier idea of it. src/engine.ts
 * skips a rule only when `rule.status === 'draft' || rule.status ===
 * 'deprecated'`, so `Draft`, `[draft]` and a missing status are all live, and a
 * gate that read them as inert would leave a live rule unmeasured. The end-to-end
 * cases, through a real git repository, are in
 * tests/gate-promotion-fp-status-revival.test.ts.
 */

import { describe, it, expect } from "vitest";
import {
  ENFORCE_MATURITIES,
  enteringEnforceLane,
  firesInEnforceLane,
  type RuleFileChange,
  type RuleLaneState,
} from "../scripts/lib/enforce-lane-entry.js";

const ID = "ATR-2026-90021";

function state(status: unknown, maturity: unknown, id: unknown = ID): RuleLaneState {
  return { id, status, maturity };
}

describe("firesInEnforceLane", () => {
  it("is live unless the status is exactly draft or deprecated, as in the engine", () => {
    for (const status of ["experimental", "stable", undefined, "Draft", "draft ", ["draft"]]) {
      expect(firesInEnforceLane(state(status, "stable")), JSON.stringify(status)).toBe(true);
    }
    for (const status of ["draft", "deprecated"]) {
      expect(firesInEnforceLane(state(status, "stable")), status).toBe(false);
    }
  });

  it("counts the gate's enforce maturities, trimmed, and nothing else", () => {
    expect([...ENFORCE_MATURITIES].sort()).toEqual(["production", "stable"]);
    for (const maturity of ["stable", " stable ", "production"]) {
      expect(firesInEnforceLane(state("experimental", maturity)), maturity).toBe(true);
    }
    for (const maturity of ["test", "experimental", "draft", "deprecated", "Stable", "", undefined, null]) {
      expect(firesInEnforceLane(state("experimental", maturity)), String(maturity)).toBe(false);
    }
  });

  it("is false for a file that does not load", () => {
    expect(firesInEnforceLane(null)).toBe(false);
  });
});

describe("enteringEnforceLane", () => {
  const LIVE_STABLE = state("experimental", "stable");

  function change(base: RuleLaneState | null, head: RuleLaneState | null): RuleFileChange {
    return { file: "rules/a/x.yaml", base, head };
  }

  it("names a rule that fires in the enforce lane now and did not at the merge base", () => {
    for (const base of [
      null, // new path, rename, or not loadable at the base
      state("draft", "stable"), // revived by its status
      state("deprecated", "stable"),
      state("experimental", "test"), // promoted by its maturity
      state("experimental", "stable", "ATR-2026-90022"), // another rule had this path
    ]) {
      expect(enteringEnforceLane([change(base, LIVE_STABLE)]), JSON.stringify(base)).toEqual(["rules/a/x.yaml"]);
    }
  });

  it("reads the merge base as the engine does, so production -> stable is a move in", () => {
    // The gate counts `production` as enforce on the way in (an over-approximation);
    // the engine never admitted it, so it cannot count as already being there.
    expect(enteringEnforceLane([change(state("experimental", "production"), LIVE_STABLE)])).toEqual(["rules/a/x.yaml"]);
    expect(enteringEnforceLane([change(state("experimental", " stable "), LIVE_STABLE)])).toEqual([]);
  });

  it("names a maturity raised into the enforce lane even while the rule stays inert", () => {
    // The scan cannot measure it, and the gate must say so; otherwise a later
    // status-only change, judged on its own, would carry it in unmeasured.
    expect(enteringEnforceLane([change(state("draft", "test"), state("draft", "stable"))])).toEqual(["rules/a/x.yaml"]);
    expect(enteringEnforceLane([change(null, state("deprecated", "production"))])).toEqual(["rules/a/x.yaml"]);
  });

  it("leaves alone the same rule already holding an enforce maturity, unless it was revived", () => {
    expect(enteringEnforceLane([change(LIVE_STABLE, state("stable", " stable "))])).toEqual([]);
    expect(enteringEnforceLane([change(state("draft", "stable"), state("draft", "stable"))])).toEqual([]);
    expect(enteringEnforceLane([change(state("draft", "stable"), state("experimental", "test"))])).toEqual([]);
    expect(enteringEnforceLane([change(LIVE_STABLE, state("deprecated", "stable"))])).toEqual([]);
    expect(enteringEnforceLane([change(LIVE_STABLE, state("experimental", "test"))])).toEqual([]);
    expect(enteringEnforceLane([change(state("draft", "stable"), null)])).toEqual([]);
  });

  it("keeps the order of the changes it was given", () => {
    const changes: RuleFileChange[] = [
      { file: "rules/b.yaml", base: null, head: LIVE_STABLE },
      { file: "rules/a.yaml", base: LIVE_STABLE, head: LIVE_STABLE },
      { file: "rules/c.yaml", base: state("draft", "stable"), head: LIVE_STABLE },
    ];
    expect(enteringEnforceLane(changes)).toEqual(["rules/b.yaml", "rules/c.yaml"]);
  });
});
