/**
 * Shared harness for the bot-lane workflow tests (measure-all, garak bridge).
 *
 * A step's `run:` block is lifted out of the workflow file verbatim and run
 * with bash in a throwaway clone of a bare "origin", with a stand-in `gh` on
 * PATH. What is tested is the text GitHub Actions would execute, not a copy.
 * `jq` stands in for gh's built-in --jq; it ships on GitHub's ubuntu runners
 * and on macOS.
 */
import { execFileSync, spawnSync, type SpawnSyncReturns } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import yaml from "js-yaml";

export const HAS_JQ = spawnSync("jq", ["--version"]).status === 0;

export interface Step {
  readonly name?: string;
  readonly if?: string;
  readonly run?: string;
  readonly env?: Readonly<Record<string, string>>;
}

export function workflowDoc(path: string): Record<string, unknown> {
  return yaml.load(readFileSync(path, "utf8")) as Record<string, unknown>;
}

export function jobSteps(path: string, job: string): readonly Step[] {
  const doc = workflowDoc(path) as { jobs: Record<string, { steps: Step[] }> };
  return doc.jobs[job].steps;
}

export function runBlock(path: string, job: string, name: string): string {
  const found = jobSteps(path, job).find((s) => s.name === name);
  if (!found?.run) throw new Error(`workflow has no run step named "${name}"`);
  return found.run;
}

// Answers `pr list` from a canned JSON array through jq and records `pr create`
// instead of opening anything. FAKE_GH_CREATE_FAIL makes `pr create` fail the
// way a token without PR rights does.
const FAKE_GH = `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FAKE_GH_LOG"
if [ "\${1:-} \${2:-}" = "pr list" ]; then
  state=open; expr=.
  while [ $# -gt 0 ]; do
    case "$1" in
      --state) state=$2; shift ;;
      --jq) expr=$2; shift ;;
    esac
    shift
  done
  jq -r --arg s "$state" "map(select(\\$s == \\"all\\" or (.state | ascii_downcase) == \\$s)) | $expr" "$FAKE_GH_PRS"
  exit 0
fi
if [ "\${1:-} \${2:-}" = "pr create" ]; then
  if [ -n "\${FAKE_GH_CREATE_FAIL:-}" ]; then echo "pull request create failed: HTTP 403" >&2; exit 1; fi
  cat > "$FAKE_GH_LOG.body" || true
  echo "https://example.invalid/pull/999"
  exit 0
fi
echo "fake gh: unexpected call: $*" >&2
exit 1
`;

export interface Pr {
  readonly number: number;
  readonly state: "OPEN" | "CLOSED" | "MERGED";
  readonly isCrossRepository: boolean;
}

export interface Sandbox {
  readonly root: string;
  readonly origin: string;
  readonly work: string;
  readonly env: Readonly<Record<string, string>>;
}

const sandboxes: string[] = [];

/** Remove every sandbox made so far; call from afterEach. */
export function cleanSandboxes(): void {
  for (const d of sandboxes.splice(0)) rmSync(d, { recursive: true, force: true });
}

export function put(dir: string, rel: string, text: string): void {
  mkdirSync(dirname(join(dir, rel)), { recursive: true });
  writeFileSync(join(dir, rel), text);
}

export function git(sb: Sandbox, cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, env: sb.env, encoding: "utf8" }).trim();
}

/** A bare origin whose main holds `files`, cloned to `work` and checked out on main. */
export function sandbox(prefix: string, files: Readonly<Record<string, string>>): Sandbox {
  const root = mkdtempSync(join(tmpdir(), prefix));
  sandboxes.push(root);
  const bin = join(root, "bin");
  mkdirSync(bin);
  writeFileSync(join(bin, "gh"), FAKE_GH);
  chmodSync(join(bin, "gh"), 0o755);
  for (const f of ["github_env", "github_output", "step_summary", "gh.log"]) writeFileSync(join(root, f), "");
  writeFileSync(join(root, "prs.json"), "[]");
  const env = {
    PATH: `${bin}:${process.env.PATH ?? ""}`,
    HOME: root,
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_AUTHOR_NAME: "fixture",
    GIT_AUTHOR_EMAIL: "fixture@example.invalid",
    GIT_COMMITTER_NAME: "fixture",
    GIT_COMMITTER_EMAIL: "fixture@example.invalid",
    GITHUB_ENV: join(root, "github_env"),
    GITHUB_OUTPUT: join(root, "github_output"),
    GITHUB_STEP_SUMMARY: join(root, "step_summary"),
    RUNNER_TEMP: root,
    FAKE_GH_LOG: join(root, "gh.log"),
    FAKE_GH_PRS: join(root, "prs.json"),
  };
  const sb = { root, origin: join(root, "origin.git"), work: join(root, "work"), env };
  git(sb, root, "init", "--quiet", "--bare", "-b", "main", "origin.git");
  git(sb, root, "clone", "--quiet", "origin.git", "work");
  for (const [rel, text] of Object.entries(files)) put(sb.work, rel, text);
  git(sb, sb.work, "add", "-A");
  git(sb, sb.work, "commit", "--quiet", "-m", "main");
  git(sb, sb.work, "push", "--quiet", "origin", "main");
  return sb;
}

/**
 * Put `branch` on origin: main plus `files`, committed in a scratch clone so
 * the work tree under test never sees it until a step fetches it.
 */
export function pushBranch(sb: Sandbox, branch: string, files: Readonly<Record<string, string>>): string {
  const scratch = join(mkdtempSync(join(sb.root, "scratch-")), "clone");
  git(sb, sb.root, "clone", "--quiet", sb.origin, scratch);
  git(sb, scratch, "checkout", "--quiet", "-b", branch);
  for (const [rel, text] of Object.entries(files)) put(scratch, rel, text);
  git(sb, scratch, "add", "-A");
  git(sb, scratch, "commit", "--quiet", "-m", branch);
  git(sb, scratch, "push", "--quiet", "--force", "origin", branch);
  return git(sb, scratch, "rev-parse", "HEAD");
}

export function setPrs(sb: Sandbox, prs: readonly Pr[]): void {
  writeFileSync(sb.env.FAKE_GH_PRS, JSON.stringify(prs));
}

export function ghCalls(sb: Sandbox): string {
  return readFileSync(sb.env.FAKE_GH_LOG, "utf8");
}

export function runStep(sb: Sandbox, script: string, extraEnv: Record<string, string> = {}): SpawnSyncReturns<string> {
  const file = join(sb.root, "step.sh");
  writeFileSync(file, script);
  return spawnSync("bash", ["--noprofile", "--norc", "-eo", "pipefail", file], {
    cwd: sb.work,
    env: { ...sb.env, ...extraEnv },
    encoding: "utf8",
  });
}

/** The sha `branch` points at on origin, or "" when it does not exist. */
export function originSha(sb: Sandbox, branch: string): string {
  const res = spawnSync("git", ["rev-parse", "--verify", "--quiet", `refs/heads/${branch}`], {
    cwd: sb.origin,
    env: sb.env,
    encoding: "utf8",
  });
  return res.status === 0 ? res.stdout.trim() : "";
}
