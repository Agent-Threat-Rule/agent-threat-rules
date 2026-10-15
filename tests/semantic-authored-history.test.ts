/**
 * Tests for scripts/lib/semantic-exclusions.ts — the record of every cluster the
 * semantic lane has ever authored, read back out of git history.
 *
 * WHY HISTORY, NOT THE TREE
 *   The author script dedupes against `_semantic_authored.source_cluster` in the
 *   rules tree it runs on. A rolling PR closed without merging, or a rule a
 *   reviewer deleted from one, leaves nothing in that tree, so the next run picks
 *   the same clusters again and opens a new PR with a regenerated copy of the
 *   rejected rules. The commits that added those rules survive in the PR's head
 *   ref, so the history is where a rejection can be read back.
 *
 * The git tests build a throwaway repository; nothing touches this checkout.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  sourceClusterOf,
  parseExcludeList,
  formatExcludeList,
  clustersAuthoredInHistory,
} from "../scripts/lib/semantic-exclusions.js";
import { parseArgs } from "../scripts/semantic-authored-history.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function laneRule(id: string, cluster: string): string {
  return [
    `id: ${id}`,
    "title: fixture",
    "detection:",
    "  method: semantic",
    "_semantic_authored:",
    "  model: fixture-model",
    `  source_cluster: ${cluster}`,
    "  family: null",
    "",
  ].join("\n");
}

describe("sourceClusterOf", () => {
  it("reads the proposal path a lane-authored rule came from", () => {
    expect(sourceClusterOf(laneRule("ATR-2026-09001", "proposals/garak-clusters/a.yaml"))).toBe(
      "proposals/garak-clusters/a.yaml",
    );
  });

  it("ignores rules the lane did not author, and text that is not YAML", () => {
    expect(sourceClusterOf("id: ATR-2026-00001\ntitle: hand-written\n")).toBeUndefined();
    expect(sourceClusterOf("source_cluster: proposals/x.yaml\n")).toBeUndefined();
    expect(sourceClusterOf(":\n  - [unclosed")).toBeUndefined();
    expect(sourceClusterOf("_semantic_authored:\n  source_cluster: 42\n")).toBeUndefined();
  });
});

describe("parseExcludeList / formatExcludeList", () => {
  it("reads one proposal path per line, skipping blanks and comments", () => {
    const text = "# rejected\nproposals/a.yaml\n\n  proposals/b.yaml  \nproposals/a.yaml\n";
    expect([...parseExcludeList(text)]).toEqual(["proposals/a.yaml", "proposals/b.yaml"]);
  });

  it("round-trips, sorted, so the file is stable between runs", () => {
    const text = formatExcludeList(new Set(["proposals/b.yaml", "proposals/a.yaml"]));
    expect(text).toBe("proposals/a.yaml\nproposals/b.yaml\n");
    expect([...parseExcludeList(text)]).toEqual(["proposals/a.yaml", "proposals/b.yaml"]);
  });

  it("writes an empty file when nothing has been authored", () => {
    expect(formatExcludeList(new Set())).toBe("");
  });
});

describe("clustersAuthoredInHistory", () => {
  let repo: string;
  const git = (...args: string[]) =>
    execFileSync("git", args, {
      cwd: repo,
      encoding: "utf-8",
      env: { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" },
    }).trim();
  const write = (rel: string, text: string) => {
    mkdirSync(dirname(join(repo, rel)), { recursive: true });
    writeFileSync(join(repo, rel), text);
  };
  const commit = (msg: string) => {
    git("add", "-A");
    git("commit", "-q", "-m", msg);
  };

  beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), "semantic-history-"));
    git("init", "-q", "-b", "main");
    git("config", "user.name", "fixture");
    git("config", "user.email", "fixture@example.invalid");
    write("rules/prompt-injection/ATR-2026-00001-hand.yaml", "id: ATR-2026-00001\ntitle: hand\n");
    commit("main: a hand-written rule");

    // Rolling PR #1: the lane adds A and B; a reviewer deletes B; the PR is
    // closed without merging. GitHub keeps its head as refs/pull/1/head.
    git("checkout", "-q", "-b", "auto-semantic/rolling");
    write("rules/prompt-injection/ATR-2026-09001-a.yaml", laneRule("ATR-2026-09001", "proposals/garak-clusters/A.yaml"));
    write("rules/prompt-injection/ATR-2026-09002-b.yaml", laneRule("ATR-2026-09002", "proposals/garak-clusters/B.yaml"));
    commit("lane: author A and B");
    git("rm", "-q", "rules/prompt-injection/ATR-2026-09002-b.yaml");
    commit("review: drop B");
    git("update-ref", "refs/pull/1/head", "HEAD");

    // Rolling PR #2 starts fresh from main and overwrites the branch, so the
    // branch no longer holds A or B. It authors C and is closed as well.
    git("checkout", "-q", "-B", "auto-semantic/rolling", "main");
    write("rules/prompt-injection/ATR-2026-09003-c.yaml", laneRule("ATR-2026-09003", "proposals/hackaprompt-clusters/C.yaml"));
    commit("lane: author C");
    git("update-ref", "refs/pull/2/head", "HEAD");

    // The branch is overwritten again with D, and no PR was ever opened for it
    // (for instance `gh pr create` failed). Nobody reviewed D.
    git("checkout", "-q", "-B", "auto-semantic/rolling", "main");
    write("rules/prompt-injection/ATR-2026-09004-d.yaml", laneRule("ATR-2026-09004", "proposals/garak-clusters/D.yaml"));
    commit("lane: author D");

    // Main merged one lane rule (E) and later deleted it.
    git("checkout", "-q", "main");
    write("rules/prompt-injection/ATR-2026-09005-e.yaml", laneRule("ATR-2026-09005", "proposals/garak-clusters/E.yaml"));
    commit("main: merge E");
    git("rm", "-q", "rules/prompt-injection/ATR-2026-09005-e.yaml");
    commit("main: remove E");
  });

  afterAll(() => {
    rmSync(repo, { recursive: true, force: true });
  });

  it("keeps the clusters of a closed PR even after its branch was overwritten", () => {
    const seen = clustersAuthoredInHistory(["main", "refs/pull/1/head", "refs/pull/2/head"], repo);
    expect(seen.has("proposals/garak-clusters/A.yaml")).toBe(true);
    expect(seen.has("proposals/hackaprompt-clusters/C.yaml")).toBe(true);
  });

  it("keeps a cluster whose rule a reviewer deleted from the PR", () => {
    const seen = clustersAuthoredInHistory(["refs/pull/1/head"], repo);
    expect(seen.has("proposals/garak-clusters/B.yaml")).toBe(true);
  });

  it("keeps a cluster whose rule main merged and later removed", () => {
    expect(clustersAuthoredInHistory(["main"], repo).has("proposals/garak-clusters/E.yaml")).toBe(true);
  });

  it("does not count a rule only a branch without a PR ever held", () => {
    const seen = clustersAuthoredInHistory(["main", "refs/pull/1/head", "refs/pull/2/head"], repo);
    expect(seen.has("proposals/garak-clusters/D.yaml")).toBe(false);
    expect([...seen].sort()).toEqual([
      "proposals/garak-clusters/A.yaml",
      "proposals/garak-clusters/B.yaml",
      "proposals/garak-clusters/E.yaml",
      "proposals/hackaprompt-clusters/C.yaml",
    ]);
  });

  it("reads refs matched by a glob, and a glob matching nothing adds nothing", () => {
    const seen = clustersAuthoredInHistory(["--glob=refs/pull/*/head"], repo);
    expect([...seen].sort()).toEqual([
      "proposals/garak-clusters/A.yaml",
      "proposals/garak-clusters/B.yaml",
      "proposals/hackaprompt-clusters/C.yaml",
    ]);
    expect(clustersAuthoredInHistory(["--glob=refs/no-such/*"], repo).size).toBe(0);
  });

  it("fails loudly on a ref that does not exist instead of returning an empty record", () => {
    expect(() => clustersAuthoredInHistory(["refs/pull/999/head"], repo)).toThrow();
  });

  it("refuses an argument that git would read as some other option", () => {
    expect(() => clustersAuthoredInHistory(["--output=/tmp/x"], repo)).toThrow(/not a revision/);
  });

  // The workflow step runs exactly this command line.
  it("CLI writes the record the author script reads, and fails on a missing ref", () => {
    const out = join(repo, "authored.txt");
    const cli = (...args: string[]) =>
      spawnSync(join(REPO_ROOT, "node_modules/.bin/tsx"), [join(REPO_ROOT, "scripts/semantic-authored-history.ts"), ...args], {
        cwd: repo,
        encoding: "utf-8",
      });
    const ok = cli("--out", out, "main", "--glob", "refs/pull/*/head");
    expect(ok.status, ok.stderr).toBe(0);
    expect(readFileSync(out, "utf-8")).toBe(
      [
        "proposals/garak-clusters/A.yaml",
        "proposals/garak-clusters/B.yaml",
        "proposals/garak-clusters/E.yaml",
        "proposals/hackaprompt-clusters/C.yaml",
        "",
      ].join("\n"),
    );
    const bad = cli("--out", join(repo, "never.txt"), "main", "refs/pull/999/head");
    expect(bad.status).toBe(1);
    expect(() => readFileSync(join(repo, "never.txt"))).toThrow();
  });
});

describe("semantic-authored-history parseArgs", () => {
  it("takes refs and globs in order", () => {
    expect(parseArgs(["--out", "/tmp/a.txt", "origin/main", "--glob", "refs/semantic-history/*"])).toEqual({
      out: "/tmp/a.txt",
      revs: ["origin/main", "--glob=refs/semantic-history/*"],
    });
  });

  it("refuses to run without somewhere to write or something to read", () => {
    expect(() => parseArgs(["origin/main"])).toThrow(/--out/);
    expect(() => parseArgs(["--out", "/tmp/a.txt"])).toThrow(/REF/);
    expect(() => parseArgs(["--out"])).toThrow(/needs a value/);
    expect(() => parseArgs(["--out", "/tmp/a.txt", "--glob"])).toThrow(/needs a value/);
  });

  it("refuses an unknown option rather than passing it on to git", () => {
    expect(() => parseArgs(["--out", "/tmp/a.txt", "--output=/etc/x", "origin/main"])).toThrow(/unknown option/);
  });
});
