/**
 * Tests for .github/workflows/measure-all.yml — how a measurement run reaches
 * main. Steps run verbatim against a throwaway origin and a stand-in gh (see
 * tests/workflow-step-harness.ts).
 *
 * - The workflow had never run: its only triggers were a manual dispatch and a
 *   published release, and releases are published by a bot whose token
 *   triggers no workflow. It now also runs weekly.
 * - Its output goes to one rolling branch, pushed against a lease, and one PR,
 *   as the other bot lanes do. While that PR is open, the measurement files it
 *   adds are carried into the next run, so an unmerged week stays in the trend.
 *   So is each latest.json the PR moved past main's: a source the next run
 *   does not measure again keeps its newer pointer, and the stats built from
 *   the pointers with it.
 * - A PR that fails to open fails the job.
 */
import { describe, it, expect, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
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

const WORKFLOW = resolve(__dirname, "..", ".github", "workflows", "measure-all.yml");
const JOB = "measure";
const CARRY = "Carry the rolling PR's measurements";
const DETECT = "Detect changes";
const PUSH = "Push to the rolling branch and open or update its PR";
const BRANCH = "measure-all/rolling";

const LATEST = "data/measurements/pint/latest.json";
const MERGED = "data/measurements/pint/2026-08-15_pint_atr-3-5-12.json";
const UNMERGED = "data/measurements/pint/2026-09-28_pint_atr-4-0-0.json";
const TODAY = "data/measurements/pint/2026-10-05_pint_atr-4-0-0.json";
const GARAK_LATEST = "data/measurements/garak-full/latest.json";
const GARAK_MERGED = "data/measurements/garak-full/2026-08-15_garak-full_atr-3-5-12.json";
const GARAK_UNMERGED = "data/measurements/garak-full/2026-09-28_garak-full_atr-4-0-0.json";

/** A latest.json pointer; writeMeasurement moves it only to a strictly newer measured_at. */
const pointer = (file: string, measuredAt: string) =>
  JSON.stringify({ file, measured_at: measuredAt }, null, 2) + "\n";

afterEach(cleanSandboxes);

function measureSandbox(): Sandbox {
  return sandbox("measure-wf-", {
    [MERGED]: "{}\n",
    [LATEST]: pointer(MERGED, "2026-08-15T05:00:00.000Z"),
    [GARAK_MERGED]: "{}\n",
    [GARAK_LATEST]: pointer(GARAK_MERGED, "2026-08-15T05:10:00.000Z"),
    "data/stats.json": '{ "benchmarks": [] }\n',
  });
}

/** The rolling branch as last week's run left it: one more measurement per source, latest.json moved. */
function lastWeeksBranch(sb: Sandbox): string {
  return pushBranch(sb, BRANCH, {
    [UNMERGED]: "{}\n",
    [LATEST]: pointer(UNMERGED, "2026-09-28T05:00:00.000Z"),
    [GARAK_UNMERGED]: "{}\n",
    [GARAK_LATEST]: pointer(GARAK_UNMERGED, "2026-09-28T05:10:00.000Z"),
  });
}

const readPointer = (sb: Sandbox, rel: string) => JSON.parse(readFileSync(resolve(sb.work, rel), "utf8")).file;

const githubEnv = (sb: Sandbox) => readFileSync(sb.env.GITHUB_ENV, "utf8");
const leaseEnv = (sb: Sandbox) => ({ ROLLING_OLD_SHA: /^ROLLING_OLD_SHA=(.*)$/m.exec(githubEnv(sb))?.[1] ?? "" });
const staged = (sb: Sandbox) => git(sb, sb.work, "diff", "--cached", "--name-only");

/** Carry, then this run's measurement, then the detect step: the tree the push step sees. */
function measuredRun(sb: Sandbox): Record<string, string> {
  const carry = runStep(sb, runBlock(WORKFLOW, JOB, CARRY));
  if (carry.status !== 0) throw new Error(carry.stderr);
  put(sb.work, TODAY, "{}\n");
  put(sb.work, LATEST, pointer(TODAY, "2026-10-05T05:00:00.000Z"));
  const detect = runStep(sb, runBlock(WORKFLOW, JOB, DETECT));
  if (detect.status !== 0) throw new Error(detect.stderr);
  return leaseEnv(sb);
}

describe("triggers", () => {
  it("runs weekly and keeps the dispatch and release triggers", () => {
    const doc = workflowDoc(WORKFLOW) as { on: Record<string, unknown>; concurrency?: unknown };
    expect(doc.on.schedule).toEqual([{ cron: "0 5 * * 1" }]);
    expect(doc.on.workflow_dispatch).toBeDefined();
    expect(doc.on.release).toEqual({ types: ["published"] });
    expect(doc.concurrency).toBeDefined();
  });
});

describe.skipIf(!HAS_JQ)("carry step", () => {
  it("carries the measurement files an open rolling PR adds and the newer pointers it moved", () => {
    const sb = measureSandbox();
    const sha = lastWeeksBranch(sb);
    setPrs(sb, [{ number: 700, state: "OPEN", isCrossRepository: false }]);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, CARRY));
    expect(res.status, res.stderr).toBe(0);
    expect(staged(sb).split("\n").sort()).toEqual([GARAK_LATEST, GARAK_UNMERGED, LATEST, UNMERGED].sort());
    expect(githubEnv(sb)).toContain(`ROLLING_OLD_SHA=${sha}`);
  });

  it("keeps last week's pointer for a source this run does not measure again", () => {
    const sb = measureSandbox();
    lastWeeksBranch(sb);
    setPrs(sb, [{ number: 700, state: "OPEN", isCrossRepository: false }]);
    measuredRun(sb);
    expect(readPointer(sb, LATEST)).toBe(TODAY);
    expect(readPointer(sb, GARAK_LATEST)).toBe(GARAK_UNMERGED);
  });

  it("keeps main's pointer when main moved past the rolling PR's", () => {
    const sb = measureSandbox();
    lastWeeksBranch(sb);
    const newer = "data/measurements/garak-full/2026-10-01_garak-full_atr-4-0-1.json";
    put(sb.work, newer, "{}\n");
    put(sb.work, GARAK_LATEST, pointer(newer, "2026-10-01T09:00:00.000Z"));
    git(sb, sb.work, "add", "-A");
    git(sb, sb.work, "commit", "--quiet", "-m", "manual garak-full measurement");
    git(sb, sb.work, "push", "--quiet", "origin", "main");
    setPrs(sb, [{ number: 700, state: "OPEN", isCrossRepository: false }]);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, CARRY));
    expect(res.status, res.stderr).toBe(0);
    expect(staged(sb).split("\n")).not.toContain(GARAK_LATEST);
    expect(readPointer(sb, GARAK_LATEST)).toBe(newer);
  });

  it("carries nothing from a PR closed without merging, but still records the lease", () => {
    const sb = measureSandbox();
    const sha = lastWeeksBranch(sb);
    setPrs(sb, [{ number: 700, state: "CLOSED", isCrossRepository: false }]);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, CARRY));
    expect(res.status, res.stderr).toBe(0);
    expect(staged(sb)).toBe("");
    expect(githubEnv(sb)).toContain(`ROLLING_OLD_SHA=${sha}`);
  });

  it("carries nothing from a fork's PR with a same-named branch", () => {
    const sb = measureSandbox();
    lastWeeksBranch(sb);
    setPrs(sb, [{ number: 701, state: "OPEN", isCrossRepository: true }]);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, CARRY));
    expect(res.status, res.stderr).toBe(0);
    expect(staged(sb)).toBe("");
  });

  it("records an empty lease when the rolling branch does not exist", () => {
    const sb = measureSandbox();
    const res = runStep(sb, runBlock(WORKFLOW, JOB, CARRY));
    expect(res.status, res.stderr).toBe(0);
    expect(githubEnv(sb)).toMatch(/^ROLLING_OLD_SHA=$/m);
  });
});

describe.skipIf(!HAS_JQ)("push step", () => {
  it("pushes this week and the carried week to the rolling branch and opens the PR", () => {
    const sb = measureSandbox();
    lastWeeksBranch(sb);
    setPrs(sb, [{ number: 700, state: "OPEN", isCrossRepository: false }]);
    const lease = measuredRun(sb);
    setPrs(sb, []);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, PUSH), lease);
    expect(res.status, res.stderr).toBe(0);
    const files = git(sb, sb.origin, "diff", "--name-only", "main", originSha(sb, BRANCH));
    expect(files.split("\n").sort()).toEqual([GARAK_LATEST, GARAK_UNMERGED, LATEST, UNMERGED, TODAY].sort());
    expect(ghCalls(sb)).toMatch(/^pr create --base main --head measure-all\/rolling /m);
    expect(originSha(sb, "main")).toBe(git(sb, sb.work, "rev-parse", "origin/main"));
  });

  it("updates an open rolling PR without opening a second", () => {
    const sb = measureSandbox();
    const before = lastWeeksBranch(sb);
    setPrs(sb, [{ number: 700, state: "OPEN", isCrossRepository: false }]);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, PUSH), measuredRun(sb));
    expect(res.status, res.stderr).toBe(0);
    expect(originSha(sb, BRANCH)).not.toBe(before);
    expect(ghCalls(sb)).not.toMatch(/^pr create /m);
  });

  it("measures but does not push a dispatch on a ref that is not on main", () => {
    const sb = measureSandbox();
    git(sb, sb.work, "checkout", "--quiet", "-b", "feature");
    put(sb.work, "rules/new.yaml", "id: x\n");
    git(sb, sb.work, "add", "-A");
    git(sb, sb.work, "commit", "--quiet", "-m", "feature");
    const res = runStep(sb, runBlock(WORKFLOW, JOB, PUSH), measuredRun(sb));
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toMatch(/not on main: measured, not pushed/);
    expect(originSha(sb, BRANCH)).toBe("");
  });

  it("fails the job when the PR cannot be opened", () => {
    const sb = measureSandbox();
    const res = runStep(sb, runBlock(WORKFLOW, JOB, PUSH), { ...measuredRun(sb), FAKE_GH_CREATE_FAIL: "1" });
    expect(res.status).not.toBe(0);
  });

  it("does not overwrite a rolling branch that moved after the carry step fetched it", () => {
    const sb = measureSandbox();
    lastWeeksBranch(sb);
    const lease = measuredRun(sb);
    const moved = pushBranch(sb, BRANCH, { "other.txt": "someone else\n" });
    const res = runStep(sb, runBlock(WORKFLOW, JOB, PUSH), lease);
    expect(res.status).not.toBe(0);
    expect(originSha(sb, BRANCH)).toBe(moved);
  });
});
