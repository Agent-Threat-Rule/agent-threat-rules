/**
 * Tests for new-rule discovery in scripts/check-rules-safety.ts.
 *
 * THE BUG THESE PIN
 *   Discovery was `git diff --diff-filter=A base...HEAD -- rules/`, which only
 *   sees committed files. scripts/fn-mine-llm.ts writes each authored rule
 *   straight into rules/ and then runs this gate — so every one of those rules
 *   was invisible, the gate printed "0 new rule file(s) detected — nothing to
 *   check, treating as safe", exited 0, and the caller recorded a PASS. Six
 *   substantive checks (benign-corpus FP, benign-code FP, research-mention FP,
 *   cross-rule conflict, own-TP coverage, loose-regex lint) were skipped while
 *   reporting success.
 *
 *   Discovery now unions the diff with untracked-but-not-ignored files, so a
 *   rule that exists on disk is measured whether or not git has heard of it.
 *
 * Git is injected rather than spawned: the contract worth pinning is which
 * commands are issued and how their outputs combine, not git's own behaviour.
 * A test that shelled out to a real repo would also be a git-writing test,
 * which is exactly what a rule repo does not need in its unit suite.
 */

import { describe, it, expect } from "vitest";
import {
  getNewRuleFiles,
  getUntrackedRuleFiles,
  getModifiedRuleFiles,
  getRenamedRuleFiles,
  routeChangedRuleFiles,
  type GitRunner,
} from "../scripts/check-rules-safety.js";

const REPO = "/fake/repo";

interface FakeGit {
  readonly run: GitRunner;
  readonly calls: string[][];
}

/** Answers `git diff` and `git ls-files --others` separately, recording argv. */
function fakeGit(
  responses: { diffAdded?: string; diffModified?: string; diffRenamed?: string; untracked?: string },
  failOn: (args: readonly string[]) => boolean = () => false,
): FakeGit {
  const calls: string[][] = [];
  const run: GitRunner = (args) => {
    calls.push([...args]);
    if (failOn(args)) throw new Error("simulated git failure");
    if (args.includes("--others")) return responses.untracked ?? "";
    if (args.includes("--diff-filter=MT")) return responses.diffModified ?? "";
    if (args.includes("--diff-filter=R")) return responses.diffRenamed ?? "";
    return responses.diffAdded ?? "";
  };
  return { run, calls };
}

describe("getNewRuleFiles", () => {
  it("finds an uncommitted rule file — the case that reported 'treating as safe'", () => {
    const { run } = fakeGit({
      diffAdded: "",
      untracked: "rules/tool-poisoning/ATR-2026-02400-new.yaml\n",
    });
    expect(getNewRuleFiles("origin/main", REPO, run)).toEqual([
      "rules/tool-poisoning/ATR-2026-02400-new.yaml",
    ]);
  });

  it("asks git for untracked files with --exclude-standard, scoped to rules/", () => {
    const { run, calls } = fakeGit({});
    getNewRuleFiles("origin/main", REPO, run);
    const others = calls.find((c) => c.includes("--others"));
    expect(others).toBeDefined();
    expect(others).toContain("--exclude-standard");
    expect(others).toContain("rules/");
  });

  it("still asks the diff question, against the base it was given", () => {
    const { run, calls } = fakeGit({});
    getNewRuleFiles("origin/release", REPO, run);
    const diff = calls.find((c) => c.includes("--diff-filter=A"));
    expect(diff).toBeDefined();
    expect(diff).toContain("origin/release...HEAD");
  });

  it("unions both sources, de-duplicates, and sorts", () => {
    const { run } = fakeGit({
      diffAdded: "rules/b/ATR-2026-00002-b.yaml\nrules/a/ATR-2026-00001-a.yaml\n",
      untracked: "rules/c/ATR-2026-00003-c.yaml\nrules/a/ATR-2026-00001-a.yaml\n",
    });
    expect(getNewRuleFiles("origin/main", REPO, run)).toEqual([
      "rules/a/ATR-2026-00001-a.yaml",
      "rules/b/ATR-2026-00002-b.yaml",
      "rules/c/ATR-2026-00003-c.yaml",
    ]);
  });

  it("is unchanged from the old behaviour when nothing is uncommitted", () => {
    const { run } = fakeGit({
      diffAdded: "rules/a/ATR-2026-00001-a.yaml\n",
      untracked: "",
    });
    expect(getNewRuleFiles("origin/main", REPO, run)).toEqual([
      "rules/a/ATR-2026-00001-a.yaml",
    ]);
  });

  it("returns nothing when both sources are empty (a real 'nothing to check')", () => {
    const { run } = fakeGit({});
    expect(getNewRuleFiles("origin/main", REPO, run)).toEqual([]);
  });

  it("ignores non-rule paths from either source", () => {
    const { run } = fakeGit({
      diffAdded: "rules/a/README.md\nrules/a/ATR-2026-00001-a.yaml\n",
      untracked: "rules/b/notes.txt\nrules/b/ATR-2026-00002-b.yml\n",
    });
    expect(getNewRuleFiles("origin/main", REPO, run)).toEqual([
      "rules/a/ATR-2026-00001-a.yaml",
      "rules/b/ATR-2026-00002-b.yml",
    ]);
  });

  it("keeps the untracked source when the diff fails (shallow clone, bad base ref)", () => {
    const { run } = fakeGit(
      { untracked: "rules/a/ATR-2026-00001-a.yaml\n" },
      (args) => args.includes("--diff-filter=A"),
    );
    expect(getNewRuleFiles("origin/main", REPO, run)).toEqual([
      "rules/a/ATR-2026-00001-a.yaml",
    ]);
  });

  it("keeps the diff source when the untracked query fails", () => {
    const { run } = fakeGit(
      { diffAdded: "rules/a/ATR-2026-00001-a.yaml\n" },
      (args) => args.includes("--others"),
    );
    expect(getNewRuleFiles("origin/main", REPO, run)).toEqual([
      "rules/a/ATR-2026-00001-a.yaml",
    ]);
  });
});

describe("getUntrackedRuleFiles", () => {
  it("reports only rule files git does not track", () => {
    const { run } = fakeGit({
      untracked: "rules/a/ATR-2026-00001-a.yaml\nrules/a/scratch.md\n",
    });
    expect(getUntrackedRuleFiles(REPO, run)).toEqual([
      "rules/a/ATR-2026-00001-a.yaml",
    ]);
  });
});

describe("getModifiedRuleFiles", () => {
  it("stays diff-only — an untracked file has no base version to differ from", () => {
    const { run } = fakeGit({
      diffModified: "rules/a/ATR-2026-00001-a.yaml\n",
      untracked: "rules/b/ATR-2026-00002-b.yaml\n",
    });
    expect(getModifiedRuleFiles("origin/main", REPO, run)).toEqual([
      "rules/a/ATR-2026-00001-a.yaml",
    ]);
  });

  it("asks for modified files against the given base", () => {
    const { run, calls } = fakeGit({});
    getModifiedRuleFiles("origin/main", REPO, run);
    // T as well: a rule file replaced by a symlink is listed under neither A, M nor R.
    const diff = calls.find((c) => c.includes("--diff-filter=MT"));
    expect(diff).toBeDefined();
    expect(diff).toContain("origin/main...HEAD");
    expect(diff).toContain("rules/");
  });
});

/**
 * `git diff` pairs a moved file with its old path, and then lists it under
 * neither --diff-filter=A nor M. Moving a rule to another directory and breaking
 * it in the same commit used to clear this gate with "No new or modified rule
 * files ... treating as safe" (checked on a scratch checkout of main, where git
 * reported the move as R099).
 */
describe("getRenamedRuleFiles", () => {
  const z = (...fields: string[]): string => `${fields.join("\0")}\0`;

  it("pairs each renamed rule file with the path it had at base", () => {
    const { run } = fakeGit({
      diffRenamed: z(
        "R099",
        "rules/prompt-injection/ATR-2026-00001-a.yaml",
        "rules/agent-manipulation/ATR-2026-00001-a.yaml",
        "R100",
        "rules/x/README.md",
        "rules/y/README.md",
        "R087",
        "rules/x/notes.txt",
        "rules/x/ATR-2026-00002-b.yaml",
      ),
    });
    expect(getRenamedRuleFiles("origin/main", REPO, run)).toEqual([
      {
        basePath: "rules/prompt-injection/ATR-2026-00001-a.yaml",
        headPath: "rules/agent-manipulation/ATR-2026-00001-a.yaml",
      },
      // Not a rule at base: main() treats it as a new rule, not a modified one.
      { basePath: "rules/x/notes.txt", headPath: "rules/x/ATR-2026-00002-b.yaml" },
    ]);
  });

  it("asks git for renames explicitly, NUL-separated, against the given base", () => {
    const { run, calls } = fakeGit({});
    getRenamedRuleFiles("origin/main", REPO, run);
    const diff = calls.find((c) => c.includes("--diff-filter=R"));
    expect(diff).toEqual(
      expect.arrayContaining(["--name-status", "-z", "--find-renames", "origin/main...HEAD", "rules/"]),
    );
  });

  it("reports a git failure instead of answering with a clean empty list", () => {
    const errors: string[] = [];
    const { run } = fakeGit({}, (args) => args.includes("--diff-filter=R"));
    expect(getRenamedRuleFiles("origin/main", REPO, run, (m) => errors.push(m))).toEqual([]);
    expect(errors).toEqual([expect.stringMatching(/renamed/)]);
  });

  it("reports output it cannot read rather than dropping it", () => {
    const errors: string[] = [];
    const { run } = fakeGit({ diffRenamed: z("R099", "rules/a/ATR-2026-00001-a.yaml") });
    getRenamedRuleFiles("origin/main", REPO, run, (m) => errors.push(m));
    expect(errors).toHaveLength(1);
  });
});

/**
 * ATR ids are permanent. git pairs a deleted rule with a similar added one as a
 * rename, and an id edited in place swaps one rule for another; both are rules
 * the rulebase has not had, and must get the new-rule checks rather than a
 * comparison with the rule they replaced.
 */
describe("routeChangedRuleFiles", () => {
  const ids = (map: Record<string, string | null>) => (path: string) => map[path] ?? null;
  const A = "rules/a/ATR-2026-00001-a.yaml";
  const B = "rules/b/ATR-2026-00001-a.yaml";

  it("keeps a modified or renamed rule with the same id as a modified one", () => {
    const pairs = [
      { basePath: A, headPath: A },
      { basePath: A, headPath: B },
    ];
    const routed = routeChangedRuleFiles(pairs, ids({ [A]: "ATR-2026-00001" }), ids({ [A]: "ATR-2026-00001", [B]: "ATR-2026-00001" }));
    expect(routed).toEqual({ modified: pairs, added: [] });
  });

  it("checks a pair whose rule id changed as a new rule", () => {
    const routed = routeChangedRuleFiles(
      [{ basePath: A, headPath: B }, { basePath: A, headPath: A }],
      ids({ [A]: "ATR-2026-00001" }),
      ids({ [A]: "ATR-2026-99999", [B]: "ATR-2026-99998" }),
    );
    expect(routed).toEqual({ modified: [], added: [B, A] });
  });

  it("checks a rule file renamed from a file that was not a rule as a new rule", () => {
    const routed = routeChangedRuleFiles([{ basePath: "rules/x/notes.txt", headPath: B }], ids({}), ids({ [B]: "ATR-2026-00002" }));
    expect(routed).toEqual({ modified: [], added: [B] });
  });

  it("leaves a pair whose id cannot be read as modified, for the modified-rule checks to report", () => {
    const pairs = [{ basePath: A, headPath: B }];
    expect(routeChangedRuleFiles(pairs, ids({}), ids({ [B]: "ATR-2026-00001" }))).toEqual({ modified: pairs, added: [] });
  });
});
