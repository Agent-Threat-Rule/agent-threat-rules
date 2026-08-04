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
  type GitRunner,
} from "../scripts/check-rules-safety.js";

const REPO = "/fake/repo";

interface FakeGit {
  readonly run: GitRunner;
  readonly calls: string[][];
}

/** Answers `git diff` and `git ls-files --others` separately, recording argv. */
function fakeGit(
  responses: { diffAdded?: string; diffModified?: string; untracked?: string },
  failOn: (args: readonly string[]) => boolean = () => false,
): FakeGit {
  const calls: string[][] = [];
  const run: GitRunner = (args) => {
    calls.push([...args]);
    if (failOn(args)) throw new Error("simulated git failure");
    if (args.includes("--others")) return responses.untracked ?? "";
    if (args.includes("--diff-filter=M")) return responses.diffModified ?? "";
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
    const diff = calls.find((c) => c.includes("--diff-filter=M"));
    expect(diff).toBeDefined();
    expect(diff).toContain("origin/main...HEAD");
    expect(diff).toContain("rules/");
  });
});
