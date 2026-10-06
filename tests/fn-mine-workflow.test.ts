/**
 * Tests for .github/workflows/fn-mine-scheduled.yml — the shell the scheduled
 * FN-mine lane runs around scripts/fn-mine-llm.ts.
 *
 * The steps are pulled out of the workflow file and run with bash against a
 * throwaway git repository, a stub `gh` and a stub `npx`, so what is tested is
 * the text GitHub Actions would execute, not a copy of it.
 *
 * - A dispatch on a branch other than main used to have the resume step swap
 *   the working tree to main (or fn-mine/rolling): the run then mined with
 *   main's miner, not the dispatched one, and could push to the rolling PR.
 * - Rule ids are allocated past what open PRs hold. The list is collected by
 *   its own step so that the mining step, which feeds attack payloads to a
 *   model CLI, never holds a GitHub token.
 */
import { describe, it, expect, afterEach } from "vitest";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { load } from "js-yaml";

const WORKFLOW = resolve(__dirname, "..", ".github", "workflows", "fn-mine-scheduled.yml");
const RESUME = "Resume the rolling branch";
const COLLECT = "Collect the rule files open PRs hold";
const MINE = "Run FN mining";
const PUSH = "Push to the rolling branch and open or update its PR";

interface Step {
  readonly name?: string;
  readonly id?: string;
  readonly if?: string;
  readonly run?: string;
  readonly env?: Readonly<Record<string, string>>;
}

function steps(): readonly Step[] {
  const wf = load(readFileSync(WORKFLOW, "utf8")) as { jobs: { mine: { steps: Step[] } } };
  return wf.jobs.mine.steps;
}

function step(name: string): Step {
  const found = steps().find((s) => s.name === name);
  if (!found) throw new Error(`workflow has no step named "${name}"`);
  return found;
}

const tmpDirs: string[] = [];
afterEach(() => {
  for (const d of tmpDirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

interface Sandbox {
  readonly root: string;
  readonly work: string;
  readonly env: Readonly<Record<string, string>>;
}

const STUB_GH = `#!/usr/bin/env bash
if [ "\${FAKE_GH_STATUS:-0}" != 0 ]; then echo "gh: HTTP 401: Bad credentials" >&2; exit "$FAKE_GH_STATUS"; fi
cat "\${FAKE_GH_OUT:-/dev/null}"
`;
const STUB_NPX = `#!/usr/bin/env bash
echo "npx-args: $*"
echo "::authored-files::"
`;

function writeStub(dir: string, name: string, body: string): void {
  writeFileSync(join(dir, name), body);
  chmodSync(join(dir, name), 0o755);
}

/** origin (bare) with main and feature, each carrying its own miner; a clone on `checkedOut`. */
function sandbox(checkedOut: "main" | "feature"): Sandbox {
  const root = mkdtempSync(join(tmpdir(), "fn-mine-wf-"));
  tmpDirs.push(root);
  const bin = join(root, "bin");
  mkdirSync(bin);
  writeStub(bin, "gh", STUB_GH);
  writeStub(bin, "npx", STUB_NPX);
  writeFileSync(join(root, "github_env"), "");
  writeFileSync(join(root, "github_output"), "");
  const env = {
    PATH: `${bin}:${process.env.PATH ?? ""}`,
    HOME: root,
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_AUTHOR_NAME: "t",
    GIT_AUTHOR_EMAIL: "t@example.invalid",
    GIT_COMMITTER_NAME: "t",
    GIT_COMMITTER_EMAIL: "t@example.invalid",
    GITHUB_ENV: join(root, "github_env"),
    GITHUB_OUTPUT: join(root, "github_output"),
    RUNNER_TEMP: root,
  };
  const git = (cwd: string, ...args: string[]) => execFileSync("git", args, { cwd, env, encoding: "utf8" });
  git(root, "init", "--quiet", "--bare", "-b", "main", "origin.git");
  git(root, "clone", "--quiet", "origin.git", "work");
  const work = join(root, "work");
  mkdirSync(join(work, "scripts"));
  writeFileSync(join(work, "scripts", "fn-mine-llm.ts"), "main miner\n");
  git(work, "add", ".");
  git(work, "commit", "--quiet", "-m", "main");
  git(work, "push", "--quiet", "origin", "main");
  git(work, "checkout", "--quiet", "-b", "feature");
  writeFileSync(join(work, "scripts", "fn-mine-llm.ts"), "feature miner\n");
  git(work, "commit", "--quiet", "-am", "feature");
  git(work, "push", "--quiet", "origin", "feature");
  git(work, "checkout", "--quiet", checkedOut);
  return { root, work, env };
}

function runStep(sb: Sandbox, run: string, extraEnv: Record<string, string> = {}) {
  const script = join(sb.root, "step.sh");
  writeFileSync(script, run);
  return spawnSync("bash", ["--noprofile", "--norc", "-eo", "pipefail", script], {
    cwd: sb.work,
    env: { ...sb.env, ...extraEnv },
    encoding: "utf8",
  });
}

function head(sb: Sandbox): { branch: string; miner: string } {
  const branch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], { cwd: sb.work, env: sb.env, encoding: "utf8" }).trim();
  return { branch, miner: readFileSync(join(sb.work, "scripts", "fn-mine-llm.ts"), "utf8").trim() };
}

const githubEnv = (sb: Sandbox) => readFileSync(sb.env.GITHUB_ENV, "utf8");

describe("resume step", () => {
  it("leaves a non-main dispatch on its own ref and forces a dry run", () => {
    const sb = sandbox("feature");
    const res = runStep(sb, step(RESUME).run ?? "", { GITHUB_REF: "refs/heads/feature" });
    expect(res.status, res.stderr).toBe(0);
    expect(head(sb)).toEqual({ branch: "feature", miner: "feature miner" });
    expect(githubEnv(sb)).toMatch(/^FORCE_DRY_RUN=true$/m);
  });

  it("still resumes fn-mine/rolling from main on the scheduled ref", () => {
    const sb = sandbox("main");
    const res = runStep(sb, step(RESUME).run ?? "", { GITHUB_REF: "refs/heads/main" });
    expect(res.status, res.stderr).toBe(0);
    expect(head(sb)).toEqual({ branch: "fn-mine/rolling", miner: "main miner" });
    expect(githubEnv(sb)).not.toMatch(/FORCE_DRY_RUN/);
  });
});

/** The mining step as a scheduled run sees it: no inputs. */
function scheduledMineRun(sb: Sandbox): string {
  return (step(MINE).run ?? "")
    .replaceAll("${{ inputs.dry_run }}", "")
    .replaceAll("${{ inputs.cap || '5' }}", "5")
    .replaceAll("/tmp/fn-mine.out", join(sb.root, "fn-mine.out"));
}

describe("mining step", () => {
  it("passes --dry-run when the resume step forced one", () => {
    const sb = sandbox("feature");
    const res = runStep(sb, scheduledMineRun(sb), { FORCE_DRY_RUN: "true" });
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toMatch(/npx-args: .*--dry-run/);
  });

  it("does not pass --dry-run on a normal scheduled run", () => {
    const sb = sandbox("main");
    const res = runStep(sb, scheduledMineRun(sb));
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).not.toMatch(/--dry-run/);
  });

  it("holds no GitHub token — it feeds attack payloads to a model CLI", () => {
    const env = JSON.stringify(step(MINE).env ?? {});
    expect(env).not.toMatch(/GH_TOKEN|GITHUB_TOKEN|ATR_REPO_TOKEN/);
  });
});

describe("push step", () => {
  it("never runs on a forced dry run, whatever the miner prints", () => {
    expect(step(PUSH).if).toContain("env.FORCE_DRY_RUN != 'true'");
  });
});

describe("open-PR rule files step", () => {
  it("runs after the resume and before the mining", () => {
    const names = steps().map((s) => s.name);
    expect(names.indexOf(RESUME)).toBeLessThan(names.indexOf(COLLECT));
    expect(names.indexOf(COLLECT)).toBeLessThan(names.indexOf(MINE));
  });

  // The step runs scripts/list-open-pr-files.sh from the checkout; here, this repository's.
  const WORKSPACE = { GITHUB_WORKSPACE: resolve(__dirname, "..") };

  it("writes the paths open PRs touch to a file the miner is pointed at", () => {
    const sb = sandbox("main");
    const prs = [
      { number: 638, changedFiles: 2, files: [{ path: "rules/prompt-injection/ATR-2026-02846-semantic.yaml" }, { path: "docs/x.md" }] },
    ];
    writeFileSync(join(sb.root, "gh.out"), JSON.stringify(prs));
    const res = runStep(sb, step(COLLECT).run ?? "", { ...WORKSPACE, FAKE_GH_OUT: join(sb.root, "gh.out") });
    expect(res.status, res.stderr).toBe(0);
    const pointer = /^FN_MINE_OPEN_PR_FILES=(.+)$/m.exec(githubEnv(sb))?.[1];
    expect(pointer).toBeTruthy();
    expect(readFileSync(pointer ?? "", "utf8")).toBe("rules/prompt-injection/ATR-2026-02846-semantic.yaml\ndocs/x.md\n");
  });

  it("fails the job when gh cannot list the open PRs", () => {
    const sb = sandbox("main");
    const res = runStep(sb, step(COLLECT).run ?? "", { ...WORKSPACE, FAKE_GH_STATUS: "1" });
    expect(res.status).not.toBe(0);
    expect(githubEnv(sb)).not.toMatch(/FN_MINE_OPEN_PR_FILES/);
  });
});

// #639 failed three PR checks the lane never ran. The backstop runs the PR's
// rule checks on the tree about to be pushed, and only when rules were authored.
describe("pre-push backstop", () => {
  const BACKSTOP = [
    "npm run validate",
    "npm run validate:compliance",
    "npm run audit:mappings",
    "scripts/generate-attack-crosswalk.py --check",
    "scripts/generate-ast-crosswalk.py --check",
    "scripts/gate-re2-portability.ts",
    "scripts/gate-corpus-visibility.ts",
    "scripts/check-rules-safety.ts --base origin/main",
    "scripts/gate-redos.py",
    "npm run gate:generalization",
    "scripts/gate-rule-status.ts",
    "scripts/gate-action-eligibility.ts",
    "npm test",
  ];

  it.each(BACKSTOP)("runs %s after the mining and before the push, only when rules were authored", (cmd) => {
    const all = steps();
    const i = all.findIndex((s) => (s.run ?? "").includes(cmd) && all.indexOf(s) > all.findIndex((t) => t.name === MINE));
    expect(i, `no step after mining runs ${cmd}`).toBeGreaterThan(-1);
    expect(i).toBeLessThan(all.findIndex((s) => s.name === PUSH));
    expect(all[i].if).toBe("steps.mine.outputs.files != ''");
  });
});
