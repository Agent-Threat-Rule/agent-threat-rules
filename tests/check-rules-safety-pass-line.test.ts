/**
 * Tests for the line scripts/check-rules-safety.ts prints when every check
 * passes.
 *
 * It used to read "N rule(s) safe to auto-merge". Auto-merge was retired in
 * 521b4b0e (2026-06-03) and the repository has auto-merge turned off, so the
 * line told contributors something that does not happen: a maintainer reviews
 * and merges every rule PR. scripts/fn-mine-llm.ts decides pass or fail by
 * matching /PASS —/ in this output, so the prefix must not move.
 */
import { describe, it, expect } from "vitest";
import { passLine } from "../scripts/check-rules-safety.js";

describe("passLine", () => {
  it("keeps the prefix fn-mine-llm.ts matches on", () => {
    expect(passLine(3, false)).toMatch(/^\[safety-gate\] PASS — /);
    expect(passLine(2, true)).toMatch(/^\[safety-gate\] PASS — /);
    expect(/PASS —/.test(passLine(3, false))).toBe(true);
  });

  it("does not promise a merge that no longer happens automatically", () => {
    const line = passLine(3, false);
    expect(line).not.toMatch(/auto-?merge/i);
    expect(line).toMatch(/3 rule\(s\) cleared every check/);
    expect(line).toMatch(/maintainer/);
  });

  it("reports named rules the way it always has", () => {
    expect(passLine(2, true)).toBe("[safety-gate] PASS — 2 named rule(s) cleared every check");
  });
});
