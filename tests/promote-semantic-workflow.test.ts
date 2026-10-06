/**
 * Behaviour tests for the shell steps of .github/workflows/promote-semantic.yml.
 *
 * The rolling-PR logic lives in the workflow's `run:` blocks, so these tests
 * lift those blocks out of the YAML verbatim and run them against a throwaway
 * bare "origin" with a fake `gh` on PATH. What they pin:
 *
 *  - A fork can open a PR from a branch that is also named auto-semantic/rolling.
 *    `gh pr list --head` matches the branch name only, so without a same-repo
 *    filter that fork PR is taken for the rolling PR: a rejected branch is
 *    resumed, and new rules are pushed to a branch no PR in this repo tracks.
 *  - A resumed branch that gains no rule this run still moved (main merged in,
 *    derived files regenerated). That has to be pushed, or the open PR stays
 *    conflicting with main behind a green run. The fresh-from-main path must not
 *    push anything when there is no rule.
 *  - Every same-repo rolling PR's head is fetched, so the history of a closed PR
 *    is still readable after its branch has been overwritten.
 *
 * Nothing here touches the network or this checkout. `jq` stands in for gh's
 * built-in --jq; it ships on GitHub's ubuntu runners and on macOS.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const WORKFLOW = resolve(REPO_ROOT, ".github/workflows/promote-semantic.yml");
const BRANCH = "auto-semantic/rolling";
const HAS_JQ = spawnSync("jq", ["--version"]).status === 0;

interface Step {
  name?: string;
  run?: string;
  env?: Record<string, string>;
  if?: string;
}

function workflowSteps(): Step[] {
  const doc = yaml.load(readFileSync(WORKFLOW, "utf-8")) as {
    jobs: Record<string, { steps: Step[] }>;
  };
  return doc.jobs["author-semantic"].steps;
}

function runBlock(name: string): string {
  const step = workflowSteps().find((s) => s.name === name);
  if (!step?.run) throw new Error(`workflow has no run step named "${name}"`);
  return step.run;
}

// A stand-in for gh: answers `pr list` from a canned JSON array through jq, and
// records `pr create` (with the body it was given) instead of opening anything.
const FAKE_GH = `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FAKE_GH_LOG"
if [ -n "\${FAKE_GH_FAIL:-}" ]; then echo "fake gh: API unavailable" >&2; exit 1; fi
if [ "\${1:-} \${2:-}" = "pr list" ]; then
  state=open; expr=.
  while [ $# -gt 0 ]; do
    case "$1" in
      --state) state=$2; shift ;;
      --jq) expr=$2; shift ;;
    esac
    shift
  done
  jq -r --arg s "$state" "map(select(\\$s == \\"all\\" or (.state | ascii_downcase) == \\$s or (\\$s == \\"closed\\" and .state == \\"MERGED\\"))) | $expr" "$FAKE_GH_PRS"
  exit 0
fi
if [ "\${1:-} \${2:-}" = "pr create" ]; then
  cat > "$FAKE_GH_LOG.body"
  echo "https://example.invalid/pull/999"
  exit 0
fi
echo "fake gh: unexpected call: $*" >&2
exit 1
`;

interface Pr {
  number: number;
  state: "OPEN" | "CLOSED" | "MERGED";
  isCrossRepository: boolean;
  labels?: Array<{ name: string }>;
}

interface Fixture {
  root: string;
  origin: string;
  work: string;
  rollingSha: string;
  mainSha: string;
  ghLog: string;
  env: Record<string, string>;
}

// An explicit identity: CI runners have no git identity and a hostname git cannot
// derive an email from, and `commit-tree` in the bare origin needs one.
const FIXTURE_IDENTITY = {
  GIT_AUTHOR_NAME: "fixture",
  GIT_AUTHOR_EMAIL: "fixture@example.invalid",
  GIT_COMMITTER_NAME: "fixture",
  GIT_COMMITTER_EMAIL: "fixture@example.invalid",
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf-8",
    env: {
      PATH: process.env.PATH ?? "",
      HOME: cwd,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_NOSYSTEM: "1",
      ...FIXTURE_IDENTITY,
    },
  }).trim();
}

function put(dir: string, rel: string, text: string): void {
  mkdirSync(dirname(join(dir, rel)), { recursive: true });
  writeFileSync(join(dir, rel), text);
}

// A lane rule as the current builder writes it: a non-quarantined source and
// a mappings note under _semantic_authored. The resume step refuses a rolling
// PR holding anything else (see staleLaneRule and its test).
function laneRule(n: number): string {
  return `id: ATR-2026-0${9000 + n}\n_semantic_authored:\n  source_cluster: proposals/promptinject-clusters/C${n}.proposal.yaml\n  mappings: auto-generated template\n`;
}

/** A lane rule from before the current gate: no mappings note. */
function staleLaneRule(n: number, source = "promptinject"): string {
  return `id: ATR-2026-0${9000 + n}\n_semantic_authored:\n  source_cluster: proposals/${source}-clusters/C${n}.proposal.yaml\n`;
}

/** Rewrite the four derived files from the rule count, like reconcile + the crosswalk generators. */
function regenerate(dir: string): void {
  const count = git(dir, "ls-files", "--others", "--cached", "--exclude-standard", "rules/").split("\n").filter(Boolean).length;
  put(dir, "stats.json", `{"rules":{"total":${count}}}\n`);
  put(dir, "data/stats.json", `{"rules":{"total":${count}}}\n`);
  put(dir, "docs/crosswalks/atr-attack-crosswalk.md", `rules: ${count}\n`);
  put(dir, "docs/crosswalks/atr-ast-crosswalk.md", `rules: ${count}\n`);
}

/**
 * origin: main with one hand-written rule; auto-semantic/rolling adds one lane
 * rule and its count cache (the open PR, #632); main then moves on with another
 * rule and a different count cache, so merging main into the branch conflicts
 * on stats.json exactly the way the real branch does.
 */
function buildFixture(): Fixture {
  const root = mkdtempSync(join(tmpdir(), "promote-semantic-wf-"));
  const origin = join(root, "origin.git");
  const seed = join(root, "seed");
  const work = join(root, "work");
  git(root, "init", "-q", "--bare", "-b", "main", origin);
  git(root, "init", "-q", "-b", "main", seed);
  git(seed, "config", "user.name", "fixture");
  git(seed, "config", "user.email", "fixture@example.invalid");
  git(seed, "remote", "add", "origin", origin);

  put(seed, "rules/prompt-injection/ATR-2026-00001-hand.yaml", "id: ATR-2026-00001\n");
  regenerate(seed);
  git(seed, "add", "-A");
  git(seed, "commit", "-q", "-m", "main: seed");
  git(seed, "push", "-q", "origin", "main");

  git(seed, "checkout", "-q", "-b", BRANCH);
  put(seed, "rules/prompt-injection/ATR-2026-09001-lane.yaml", laneRule(1));
  put(seed, "stats.json", `{"rules":{"total":2},"from":"rolling"}\n`);
  git(seed, "add", "-A");
  git(seed, "commit", "-q", "-m", "lane: author 1 rule");
  git(seed, "push", "-q", "origin", BRANCH);
  const rollingSha = git(seed, "rev-parse", "HEAD");
  git(origin, "update-ref", "refs/pull/632/head", rollingSha);

  git(seed, "checkout", "-q", "main");
  put(seed, "rules/prompt-injection/ATR-2026-00002-hand.yaml", "id: ATR-2026-00002\n");
  put(seed, "stats.json", `{"rules":{"total":2},"from":"main"}\n`);
  git(seed, "add", "-A");
  git(seed, "commit", "-q", "-m", "main: another rule");
  git(seed, "push", "-q", "origin", "main");
  const mainSha = git(seed, "rev-parse", "HEAD");

  git(root, "clone", "-q", origin, work);

  const bin = join(root, "bin");
  mkdirSync(bin);
  writeFileSync(join(bin, "gh"), FAKE_GH);
  chmodSync(join(bin, "gh"), 0o755);
  const ghLog = join(root, "gh.log");
  writeFileSync(ghLog, "");
  const env = {
    PATH: `${bin}:${process.env.PATH ?? ""}`,
    HOME: root,
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GITHUB_ENV: join(root, "github.env"),
    FAKE_GH_LOG: ghLog,
    FAKE_GH_PRS: join(root, "prs.json"),
    GH_TOKEN: "fixture-not-a-token",
    PUSH_TOKEN: "fixture-not-a-token",
  };
  writeFileSync(env.GITHUB_ENV, "");
  return { root, origin, work, rollingSha, mainSha, ghLog, env };
}

function setPrs(fx: Fixture, prs: Pr[]): void {
  writeFileSync(fx.env.FAKE_GH_PRS, JSON.stringify(prs));
}

/** What earlier steps exported through $GITHUB_ENV, as later steps would see it. */
function exported(fx: Fixture): Record<string, string> {
  const lines = readFileSync(fx.env.GITHUB_ENV, "utf-8").split("\n").filter(Boolean);
  return Object.fromEntries(lines.map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));
}

function runStep(fx: Fixture, name: string, counts?: { before: number; after: number }) {
  const script = runBlock(name)
    .replace(/\$\{\{\s*steps\.before\.outputs\.count\s*\}\}/g, String(counts?.before ?? 0))
    .replace(/\$\{\{\s*steps\.after\.outputs\.count\s*\}\}/g, String(counts?.after ?? 0));
  if (script.includes("${{")) throw new Error(`unsubstituted expression in "${name}"`);
  const file = join(fx.root, "step.sh");
  writeFileSync(file, script);
  const r = spawnSync("bash", ["--noprofile", "--norc", "-eo", "pipefail", file], {
    cwd: fx.work,
    encoding: "utf-8",
    env: { ...fx.env, ...exported(fx) },
  });
  return { status: r.status, out: `${r.stdout}${r.stderr}` };
}

function originSha(fx: Fixture): string {
  return git(fx.origin, "rev-parse", `refs/heads/${BRANCH}`);
}

function ghCalls(fx: Fixture): string {
  return readFileSync(fx.ghLog, "utf-8");
}

function isAncestor(fx: Fixture, a: string, b: string): boolean {
  return spawnSync("git", ["merge-base", "--is-ancestor", a, b], { cwd: fx.work }).status === 0;
}

describe.skipIf(!HAS_JQ)("promote-semantic.yml rolling-branch steps", () => {
  let fx: Fixture;
  beforeEach(() => {
    fx = buildFixture();
  });
  afterEach(() => {
    rmSync(fx.root, { recursive: true, force: true });
  });

  describe("Resume the rolling branch", () => {
    it("resumes the open same-repo rolling PR and tells the push step it did", () => {
      setPrs(fx, [{ number: 632, state: "OPEN", isCrossRepository: false }]);
      const r = runStep(fx, "Resume the rolling branch");
      expect(r.status, r.out).toBe(0);
      expect(r.out).toContain("Resuming auto-semantic/rolling for open PR #632");
      const head = git(fx.work, "rev-parse", "HEAD");
      expect(isAncestor(fx, fx.rollingSha, head)).toBe(true);
      expect(isAncestor(fx, fx.mainSha, head)).toBe(true);
      expect(exported(fx)).toMatchObject({ ROLLING_OLD_SHA: fx.rollingSha, ROLLING_RESUMED: "1" });
    });

    // PR #632 is this case: rules from the builder before the current gate (no
    // mappings note) and from garak. Resuming would mark their clusters
    // authored, the backstop would fail on them every run, and nothing new
    // would ever be pushed. The step stops and says to close the PR instead.
    function addToRolling(fx: Fixture, rel: string, text: string): void {
      const tmp = join(fx.root, "stale-clone");
      git(fx.root, "clone", "-q", "-b", BRANCH, fx.origin, tmp);
      git(tmp, "config", "user.name", "fixture");
      git(tmp, "config", "user.email", "fixture@example.invalid");
      put(tmp, rel, text);
      git(tmp, "add", "-A");
      git(tmp, "commit", "-q", "-m", "lane: stale rule");
      git(tmp, "push", "-q", "origin", BRANCH);
    }

    it("refuses to resume a rolling PR holding a rule from before the current gate", () => {
      const rel = "rules/prompt-injection/ATR-2026-09003-lane.yaml";
      addToRolling(fx, rel, staleLaneRule(3));
      setPrs(fx, [{ number: 632, state: "OPEN", isCrossRepository: false }]);
      const r = runStep(fx, "Resume the rolling branch");
      expect(r.status, r.out).toBe(1);
      expect(r.out).toContain(rel);
      expect(r.out).toContain("Close PR #632 without merging");
      expect(exported(fx).ROLLING_RESUMED).toBeUndefined();
    });

    it("refuses to resume a rolling PR holding a rule from a quarantined source", () => {
      const rel = "rules/prompt-injection/ATR-2026-09004-lane.yaml";
      addToRolling(fx, rel, laneRule(4).replace("promptinject-clusters", "garak-clusters"));
      setPrs(fx, [{ number: 632, state: "OPEN", isCrossRepository: false }]);
      const r = runStep(fx, "Resume the rolling branch");
      expect(r.status, r.out).toBe(1);
      expect(r.out).toContain(rel);
    });

    it("does not take a fork's PR from a same-named branch for the rolling PR", () => {
      // #632 was closed without merging; a fork then opened #603 from its own
      // auto-semantic/rolling. The rejected branch must not be resumed.
      setPrs(fx, [
        { number: 632, state: "CLOSED", isCrossRepository: false },
        { number: 603, state: "OPEN", isCrossRepository: true },
      ]);
      const r = runStep(fx, "Resume the rolling branch");
      expect(r.status, r.out).toBe(0);
      expect(r.out).not.toContain("Resuming");
      expect(git(fx.work, "rev-parse", "HEAD")).toBe(fx.mainSha);
      expect(exported(fx).ROLLING_RESUMED).toBeUndefined();
    });

    it("starts fresh from main when the rolling PR was closed", () => {
      setPrs(fx, [{ number: 632, state: "CLOSED", isCrossRepository: false }]);
      const r = runStep(fx, "Resume the rolling branch");
      expect(r.status, r.out).toBe(0);
      expect(git(fx.work, "rev-parse", "HEAD")).toBe(fx.mainSha);
      expect(exported(fx)).toMatchObject({ ROLLING_OLD_SHA: fx.rollingSha });
      expect(exported(fx).ROLLING_RESUMED).toBeUndefined();
    });
  });

  describe("Fetch the history of every rolling PR", () => {
    it("fetches every same-repo rolling PR head, whatever its state, and no fork's", () => {
      // #500 is an earlier rolling PR, closed; its branch was overwritten since,
      // so refs/pull/500/head is the only place its rules still exist.
      const earlier = git(fx.origin, "commit-tree", "-m", "earlier rolling PR", `${fx.mainSha}^{tree}`);
      git(fx.origin, "update-ref", "refs/pull/500/head", earlier);
      git(fx.origin, "update-ref", "refs/pull/603/head", fx.mainSha);
      setPrs(fx, [
        { number: 632, state: "OPEN", isCrossRepository: false },
        { number: 603, state: "OPEN", isCrossRepository: true },
        { number: 500, state: "CLOSED", isCrossRepository: false },
        { number: 410, state: "MERGED", isCrossRepository: false },
      ]);
      git(fx.origin, "update-ref", "refs/pull/410/head", fx.mainSha);
      const r = runStep(fx, "Fetch the history of every rolling PR");
      expect(r.status, r.out).toBe(0);
      const refs = git(fx.work, "for-each-ref", "--format=%(refname)", "refs/semantic-history/").split("\n");
      expect(refs.sort()).toEqual([
        "refs/semantic-history/410",
        "refs/semantic-history/500",
        "refs/semantic-history/632",
      ]);
      expect(git(fx.work, "rev-parse", "refs/semantic-history/500")).toBe(earlier);
    });

    // #632 was closed for how it was built (before the current gate), not for what
    // it detects. Without a way out its clusters were rejected for good, the four
    // that pass the current gate included.
    it("leaves out a PR closed unmerged with the semantic-reauthor label, and only that", () => {
      const REAUTHOR = [{ name: "semantic-reauthor" }];
      for (const n of [632, 500, 410, 700]) git(fx.origin, "update-ref", `refs/pull/${n}/head`, fx.mainSha);
      setPrs(fx, [
        { number: 632, state: "CLOSED", isCrossRepository: false, labels: REAUTHOR },
        { number: 500, state: "CLOSED", isCrossRepository: false, labels: [{ name: "needs-human-review" }] },
        { number: 410, state: "MERGED", isCrossRepository: false, labels: REAUTHOR },
        { number: 700, state: "OPEN", isCrossRepository: false, labels: REAUTHOR },
      ]);
      const r = runStep(fx, "Fetch the history of every rolling PR");
      expect(r.status, r.out).toBe(0);
      const refs = git(fx.work, "for-each-ref", "--format=%(refname)", "refs/semantic-history/").split("\n");
      expect(refs.sort()).toEqual([
        "refs/semantic-history/410",
        "refs/semantic-history/500",
        "refs/semantic-history/700",
      ]);
    });

    it("fails when the PR list cannot be read, rather than proceeding with no history", () => {
      // An empty record would let every rejected cluster back in, behind a green run.
      setPrs(fx, [{ number: 632, state: "CLOSED", isCrossRepository: false }]);
      fx = { ...fx, env: { ...fx.env, FAKE_GH_FAIL: "1" } };
      const r = runStep(fx, "Fetch the history of every rolling PR");
      expect(r.status, r.out).not.toBe(0);
      expect(git(fx.work, "for-each-ref", "refs/semantic-history/")).toBe("");
    });
  });

  describe("Push to the rolling branch and open or update its PR", () => {
    const PUSH = "Push to the rolling branch and open or update its PR";

    it("pushes a resumed branch that gained no rule, so the open PR stops conflicting", () => {
      setPrs(fx, [{ number: 632, state: "OPEN", isCrossRepository: false }]);
      expect(runStep(fx, "Resume the rolling branch").status).toBe(0);
      regenerate(fx.work);
      const r = runStep(fx, PUSH, { before: 3, after: 3 });
      expect(r.status, r.out).toBe(0);
      const pushed = originSha(fx);
      expect(pushed).toBe(git(fx.work, "rev-parse", "HEAD"));
      expect(isAncestor(fx, fx.rollingSha, pushed)).toBe(true);
      expect(isAncestor(fx, fx.mainSha, pushed)).toBe(true);
      expect(git(fx.origin, "show", `${pushed}:stats.json`)).toBe('{"rules":{"total":3}}');
      expect(ghCalls(fx)).not.toContain("pr create");
    });

    it("pushes nothing when it started fresh from main and authored no rule", () => {
      setPrs(fx, [{ number: 632, state: "CLOSED", isCrossRepository: false }]);
      expect(runStep(fx, "Resume the rolling branch").status).toBe(0);
      regenerate(fx.work); // derived files differ from main's, but there is no rule to ship
      const r = runStep(fx, PUSH, { before: 2, after: 2 });
      expect(r.status, r.out).toBe(0);
      expect(originSha(fx)).toBe(fx.rollingSha);
      expect(ghCalls(fx)).not.toContain("pr create");
    });

    it("opens the rolling PR here when the only open PR on that branch name is a fork's", () => {
      setPrs(fx, [
        { number: 632, state: "CLOSED", isCrossRepository: false },
        { number: 603, state: "OPEN", isCrossRepository: true },
      ]);
      expect(runStep(fx, "Resume the rolling branch").status).toBe(0);
      put(fx.work, "rules/prompt-injection/ATR-2026-09002-lane.yaml", laneRule(2));
      regenerate(fx.work);
      const r = runStep(fx, PUSH, { before: 2, after: 3 });
      expect(r.status, r.out).toBe(0);
      expect(r.out).not.toContain("#603");
      expect(ghCalls(fx)).toContain(`pr create --head ${BRANCH}`);
      expect(originSha(fx)).toBe(git(fx.work, "rev-parse", "HEAD"));
      // A reviewer has to know that closing the PR is final for its clusters.
      expect(readFileSync(`${fx.ghLog}.body`, "utf-8")).toMatch(/[Cc]losing this PR without merging/);
    });

    it("adds new rules to the open rolling PR instead of opening another", () => {
      setPrs(fx, [{ number: 632, state: "OPEN", isCrossRepository: false }]);
      expect(runStep(fx, "Resume the rolling branch").status).toBe(0);
      put(fx.work, "rules/prompt-injection/ATR-2026-09002-lane.yaml", laneRule(2));
      regenerate(fx.work);
      const r = runStep(fx, PUSH, { before: 3, after: 4 });
      expect(r.status, r.out).toBe(0);
      expect(r.out).toContain("open rolling PR #632");
      expect(ghCalls(fx)).not.toContain("pr create");
      expect(isAncestor(fx, fx.rollingSha, originSha(fx))).toBe(true);
    });
  });
});

describe("promote-semantic.yml wiring of the authored-cluster record", () => {
  const names = workflowSteps().map((s) => s.name ?? "");
  const at = (name: string) => {
    const i = names.indexOf(name);
    if (i < 0) throw new Error(`no step named "${name}"`);
    return i;
  };

  it("fetches PR heads before any dependency code runs, so the token never meets it", () => {
    expect(at("Fetch the history of every rolling PR")).toBeLessThan(at("Install dependencies"));
  });

  it("builds the record from main and every fetched PR head, before authoring", () => {
    const listing = workflowSteps().find((s) => s.run?.includes("scripts/semantic-authored-history.ts"));
    expect(listing, "a step runs scripts/semantic-authored-history.ts").toBeDefined();
    expect(listing!.run).toContain("origin/main");
    expect(listing!.run).toContain("refs/semantic-history/");
    expect(listing!.run).toContain("/tmp/semantic-authored.txt");
    expect(listing!.env ?? {}).not.toHaveProperty("GH_TOKEN");
    expect(names.indexOf(listing!.name ?? "")).toBeLessThan(at("Author semantic rules (deterministic 0-FP gate)"));
    expect(names.indexOf(listing!.name ?? "")).toBeGreaterThan(at("Fetch the history of every rolling PR"));
  });

  it("hands the record to the author script", () => {
    expect(runBlock("Author semantic rules (deterministic 0-FP gate)")).toContain(
      "--exclude-from /tmp/semantic-authored.txt",
    );
  });

  it("runs a script that exists", () => {
    expect(existsSync(resolve(REPO_ROOT, "scripts/semantic-authored-history.ts"))).toBe(true);
  });

  // check-rules-safety counts a resumed branch's earlier rules against the per-PR
  // cap and as check-5 peers; the author script only sees them through --base.
  it("tells the author script the PR's base, so it counts the rules the PR already adds", () => {
    expect(runBlock("Author semantic rules (deterministic 0-FP gate)")).toContain("--base origin/main");
  });

  it("runs the tests before pushing a resumed branch that authored nothing", () => {
    const tests = workflowSteps().find((st) => st.name === "Run tests");
    expect(tests?.if).toContain("env.ROLLING_RESUMED == '1'");
    expect(tests?.if).toContain("steps.authored.outputs.any == 'true'");
  });
});
