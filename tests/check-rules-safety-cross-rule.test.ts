import { describe, expect, it } from "vitest";
import {
  findCrossRuleConflicts,
  type RuleTNSample,
} from "../scripts/check-rules-safety.js";

const tn = (ownerRuleId: string, text: string): RuleTNSample => ({
  ownerRuleId,
  ownerFile: `rules/${ownerRuleId}.yaml`,
  text,
});

describe("findCrossRuleConflicts", () => {
  it("checks peer true negatives in both directions", () => {
    const samples = [tn("RULE-A", "safe for A"), tn("RULE-B", "safe for B")];
    const matches = (text: string) =>
      new Set(text === "safe for A" ? ["RULE-B"] : ["RULE-A"]);

    expect([...findCrossRuleConflicts(new Set(["RULE-A", "RULE-B"]), samples, matches).keys()]).toEqual([
      "RULE-B",
      "RULE-A",
    ]);
  });

  it("does not report a rule matching its own true negative as cross-rule", () => {
    const conflicts = findCrossRuleConflicts(
      new Set(["RULE-A"]),
      [tn("RULE-A", "own sample")],
      () => new Set(["RULE-A"]),
    );
    expect(conflicts.size).toBe(0);
  });

  it("passes when peer true negatives are silent", () => {
    const conflicts = findCrossRuleConflicts(
      new Set(["RULE-A", "RULE-B"]),
      [tn("RULE-A", "safe for A"), tn("RULE-B", "safe for B")],
      () => new Set(),
    );
    expect(conflicts.size).toBe(0);
  });
});
