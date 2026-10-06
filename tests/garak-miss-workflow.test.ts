/**
 * Tests for .github/workflows/garak-miss-proposals.yml — the shell around
 * scripts/garak-miss-to-proposals.ts. Steps run verbatim against a throwaway
 * origin and a stand-in gh (see tests/workflow-step-harness.ts).
 *
 * - The garak corpus is a frozen snapshot, so most weekly runs found the same
 *   misses and differed from main only in the run date. The rolling PR (#624)
 *   was force-pushed every week with a diff of nothing but dates. A run whose
 *   proposals match main now pushes nothing.
 * - Two failures used to end green with nothing produced: a benchmark that
 *   exited non-zero fell back to the committed report, and a PR that failed to
 *   open was swallowed by `|| echo`. Both fail the job now.
 * - The push used to fall back from --force-with-lease to a plain --force.
 */
import { describe, it, expect, afterEach } from "vitest";
import { chmodSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  HAS_JQ,
  cleanSandboxes,
  ghCalls,
  git,
  originSha,
  pushBranch,
  put,
  runBlock,
  runStep,
  sandbox,
  setPrs,
  workflowDoc,
  type Sandbox,
} from "./workflow-step-harness.js";

const WORKFLOW = resolve(__dirname, "..", ".github", "workflows", "garak-miss-proposals.yml");
const JOB = "bridge";
const REFRESH = "Refresh garak full report (local corpus, no python needed)";
const OPEN_PR = "Open PR for refreshed proposals (human review required)";
const BRANCH = "garak-miss-bridge/rolling";
const PROPOSAL = "proposals/garak-clusters/ATR-GARAK-0c4383a1.proposal.yaml";
const REPORT = "data/garak-benchmark/garak-full-report.json";

afterEach(cleanSandboxes);

function bridgeSandbox(): Sandbox {
  return sandbox("garak-wf-", {
    [PROPOSAL]: 'date: "2026-09-21"\ntrue_positives: [a, b]\n',
    [REPORT]: '{ "date": "2026-09-21" }\n',
  });
}

/** What the generate step leaves when the misses did not change: only the report moved. */
function regenerateUnchanged(sb: Sandbox): void {
  put(sb.work, REPORT, '{ "date": "2026-10-05" }\n');
}

function regenerateChanged(sb: Sandbox): void {
  regenerateUnchanged(sb);
  put(sb.work, PROPOSAL, 'date: "2026-10-05"\ntrue_positives: [a, b, c]\n');
}

const openPr = () => runBlock(WORKFLOW, JOB, OPEN_PR);

describe("triggers", () => {
  it("chains after measure-all and has no idle cron of its own", () => {
    const on = workflowDoc(WORKFLOW).on as Record<string, unknown>;
    expect(on.schedule).toBeUndefined();
    expect(on.workflow_run).toEqual({ workflows: ["Measure All Benchmarks"], types: ["completed"] });
    expect(on.workflow_dispatch).toBeDefined();
  });
});

describe("refresh step", () => {
  it("fails the job when the benchmark fails, instead of reusing the committed report", () => {
    const sb = bridgeSandbox();
    put(sb.work, "data/test-corpora/garak-full/dan.json", "{}");
    const npx = join(sb.root, "bin", "npx");
    writeFileSync(npx, "#!/usr/bin/env bash\necho 'engine failed to load' >&2\nexit 1\n");
    chmodSync(npx, 0o755);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, REFRESH));
    expect(res.status).not.toBe(0);
  });
});

describe.skipIf(!HAS_JQ)("open-PR step", () => {
  it("pushes nothing and opens nothing when only the report's date moved", () => {
    const sb = bridgeSandbox();
    regenerateUnchanged(sb);
    const res = runStep(sb, openPr());
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toMatch(/Proposals unchanged from main/);
    expect(originSha(sb, BRANCH)).toBe("");
    expect(ghCalls(sb)).toBe("");
  });

  it("leaves an open rolling PR untouched when the proposals did not change", () => {
    const sb = bridgeSandbox();
    const before = pushBranch(sb, BRANCH, { [REPORT]: '{ "date": "2026-09-28" }\n' });
    setPrs(sb, [{ number: 624, state: "OPEN", isCrossRepository: false }]);
    regenerateUnchanged(sb);
    const res = runStep(sb, openPr());
    expect(res.status, res.stderr).toBe(0);
    expect(originSha(sb, BRANCH)).toBe(before);
  });

  it("pushes the proposals with the report they came from and opens the PR", () => {
    const sb = bridgeSandbox();
    regenerateChanged(sb);
    const res = runStep(sb, openPr());
    expect(res.status, res.stderr).toBe(0);
    const pushed = originSha(sb, BRANCH);
    expect(pushed).not.toBe("");
    const files = git(sb, sb.origin, "diff", "--name-only", "main", pushed);
    expect(files.split("\n").sort()).toEqual([REPORT, PROPOSAL].sort());
    expect(ghCalls(sb)).toMatch(/^pr create /m);
  });

  it("force-pushes an open rolling PR's branch without opening a second", () => {
    const sb = bridgeSandbox();
    const before = pushBranch(sb, BRANCH, { [REPORT]: '{ "date": "2026-09-28" }\n' });
    setPrs(sb, [{ number: 624, state: "OPEN", isCrossRepository: false }]);
    regenerateChanged(sb);
    const res = runStep(sb, openPr());
    expect(res.status, res.stderr).toBe(0);
    expect(originSha(sb, BRANCH)).not.toBe(before);
    expect(res.stdout).toMatch(/open rolling PR #624/);
    expect(ghCalls(sb)).not.toMatch(/^pr create /m);
  });

  it("opens its own PR when the only open one is a fork's same-named branch", () => {
    const sb = bridgeSandbox();
    setPrs(sb, [{ number: 700, state: "OPEN", isCrossRepository: true }]);
    regenerateChanged(sb);
    const res = runStep(sb, openPr());
    expect(res.status, res.stderr).toBe(0);
    expect(ghCalls(sb)).toMatch(/^pr create /m);
  });

  it("fails the job when the PR cannot be opened", () => {
    const sb = bridgeSandbox();
    regenerateChanged(sb);
    const res = runStep(sb, openPr(), { FAKE_GH_CREATE_FAIL: "1" });
    expect(res.status).not.toBe(0);
    expect(res.stdout).not.toMatch(/Opened PR/);
  });

  it("does not overwrite a branch that moved after it was fetched", () => {
    const sb = bridgeSandbox();
    pushBranch(sb, BRANCH, { [REPORT]: '{ "date": "2026-09-28" }\n' });
    regenerateChanged(sb);
    // Someone pushes to the branch between this step's fetch and its push: the
    // fetch is made to see the old sha by pointing it at a stale mirror.
    const stale = join(sb.root, "stale.git");
    git(sb, sb.root, "clone", "--quiet", "--mirror", sb.origin, stale);
    const moved = pushBranch(sb, BRANCH, { "other.txt": "someone else\n" });
    const script = openPr().replace(
      'git fetch --quiet origin "$BRANCH"',
      `git fetch --quiet ${stale} "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH"`,
    );
    const res = runStep(sb, script);
    expect(res.status).not.toBe(0);
    expect(originSha(sb, BRANCH)).toBe(moved);
  });
});
