import { describe, it, expect } from "vitest";
import { collisions, type BranchRules } from "../scripts/lib/id-collision.js";

/**
 * Guards the failure that actually happened on 2026-09-04.
 *
 * ATR-2026-02816 and ATR-2026-02818 existed on TWO branches at once —
 * feat/resweep-rules-b1 (authored 08-24) and feat/paper-mine-rules (08-27) —
 * with different detection logic, both marked rule_version 1, and both
 * passing every gate. They passed because every existing check runs against
 * one tree: tests/validate-rules.ts catches two files sharing an ID inside a
 * branch, and sees nothing when the two files live on different branches.
 *
 * Whichever PR merged second would have conflicted, and a careless resolution
 * would have silently dropped one version's conditions. Nothing in CI could
 * have said so, because CI never looks sideways.
 */

const base: BranchRules = {
  "ATR-2026-00001": "hash-a",
  "ATR-2026-00002": "hash-b",
};

describe("cross-branch rule ID collisions", () => {
  it("flags an id claimed by a sibling branch with different content", () => {
    const found = collisions(
      { "ATR-2026-02816": "mine-v2" },
      base,
      { "feat/resweep-rules-b1": { "ATR-2026-02816": "theirs-v1" } },
    );
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ id: "ATR-2026-02816", branch: "feat/resweep-rules-b1" });
  });

  it("stays silent when the sibling carries byte-identical content", () => {
    // A shared ancestor, or the same rule cherry-picked. Not a collision.
    expect(
      collisions(
        { "ATR-2026-02816": "same" },
        base,
        { "feat/other": { "ATR-2026-02816": "same" } },
      ),
    ).toHaveLength(0);
  });

  it("ignores ids the branch did not introduce", () => {
    // Already on the base. Every branch carries it; that is not a claim.
    expect(
      collisions(
        { "ATR-2026-00001": "hash-a" },
        base,
        { "feat/other": { "ATR-2026-00001": "hash-a-modified" } },
      ),
    ).toHaveLength(0);
  });

  it("reports every branch that claims the same id", () => {
    const found = collisions(
      { "ATR-2026-02818": "mine" },
      base,
      {
        "feat/one": { "ATR-2026-02818": "a" },
        "feat/two": { "ATR-2026-02818": "b" },
        "feat/unrelated": { "ATR-2026-09999": "c" },
      },
    );
    expect(found.map((c) => c.branch).sort()).toEqual(["feat/one", "feat/two"]);
  });

  it("reports every colliding id, not just the first", () => {
    const found = collisions(
      { "ATR-2026-02816": "m1", "ATR-2026-02818": "m2" },
      base,
      { "feat/b1": { "ATR-2026-02816": "t1", "ATR-2026-02818": "t2" } },
    );
    expect(found.map((c) => c.id).sort()).toEqual(["ATR-2026-02816", "ATR-2026-02818"]);
  });

  it("is silent on an empty branch", () => {
    expect(collisions({}, base, { "feat/other": { "ATR-2026-02816": "x" } })).toHaveLength(0);
  });

  it("is silent when there are no sibling branches at all", () => {
    expect(collisions({ "ATR-2026-02816": "m" }, base, {})).toHaveLength(0);
  });
});
