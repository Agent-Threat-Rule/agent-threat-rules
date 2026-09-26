/**
 * Cross-branch rule-ID collision detection.
 *
 * Every existing check runs against one tree. tests/validate-rules.ts catches
 * two files sharing an ID inside a branch; it sees nothing when the two files
 * live on different branches. On 2026-09-04 that gap let ATR-2026-02816 and
 * ATR-2026-02818 exist on two branches at once with different detection logic,
 * both marked rule_version 1, both green. Whichever merged second would have
 * conflicted, and a careless resolution would have dropped one version's
 * conditions with nothing in CI able to say so.
 *
 * The rule is narrow on purpose: an ID is only a collision when THIS branch
 * introduces it (it is not on the base) AND a sibling branch carries the same
 * ID with DIFFERENT content. Same content is a cherry-pick or a shared
 * ancestor, not a clash; an ID already on the base belongs to everyone.
 */

/** rule id -> a content hash for the file carrying it. */
export type BranchRules = Readonly<Record<string, string>>;

export interface Collision {
  readonly id: string;
  readonly branch: string;
}

export function collisions(
  branch: BranchRules,
  base: BranchRules,
  siblings: Readonly<Record<string, BranchRules>>,
): readonly Collision[] {
  const introduced = Object.keys(branch).filter((id) => !(id in base));
  const out: Collision[] = [];
  for (const id of introduced) {
    for (const [name, rules] of Object.entries(siblings)) {
      const theirs = rules[id];
      if (theirs !== undefined && theirs !== branch[id]) {
        out.push({ id, branch: name });
      }
    }
  }
  return out;
}
