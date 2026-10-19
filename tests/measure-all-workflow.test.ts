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
 * - README's benchmark table and root stats.json are re-rendered from the
 *   pointers after Sync stats and committed with the measurements; otherwise
 *   check-benchmark-citations.ts rejects the PR (#656: 45 mismatches). What
 *   the renderer leaves to a human — prose near the table citing a version or
 *   a percentage, stats.json fields it dropped — is listed in the PR body,
 *   which every push rewrites.
 * - LIMITATIONS.md, the docs that quote the same corpora, and CITATION.cff's
 *   garak sentence are re-rendered after the table and staged with it, so the
 *   PR passes eval.yml's checks of them too.
 */
import { describe, it, expect, afterEach } from "vitest";
import { readFileSync, symlinkSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  HAS_JQ,
  cleanSandboxes,
  ghCalls,
  git,
  jobSteps,
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
import { DOCUMENTS } from "../scripts/render-recall-citations.js";

const WORKFLOW = resolve(__dirname, "..", ".github", "workflows", "measure-all.yml");
const JOB = "measure";
const CARRY = "Carry the rolling PR's measurements";
const SYNC = "Sync stats.json benchmarks";
const RENDER = "Render README benchmark table";
const RECALL = "Render recall citations in Markdown docs";
const CITATION = "Sync CITATION.cff garak sentence";
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

/** The other files the measure job re-renders and stages; on main they always exist. */
const RENDERED_ELSEWHERE: Readonly<Record<string, string>> = Object.fromEntries(
  ["CITATION.cff", ...DOCUMENTS].map((doc) => [doc, `# ${doc}\n`]),
);

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
    "README.md": "# ATR\n",
    "stats.json": '{ "benchmarks": {} }\n',
    ...RENDERED_ELSEWHERE,
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
const prBody = (sb: Sandbox) => readFileSync(`${sb.env.FAKE_GH_LOG}.body`, "utf8");

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
    expect(prBody(sb)).toMatch(/^Auto-generated measurement refresh/);
    expect(prBody(sb)).not.toMatch(/README prose to check/);
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
    expect(ghCalls(sb)).toMatch(/^api -X PATCH repos\/fixture-owner\/fixture-repo\/pulls\/700 -F body=@/m);
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

const REPO = resolve(__dirname, "..");
const PINT_FILE = "2026-10-05_pint-v1_atr-4-1-5.json";
const PINT_ROW = (cells: string) => `| PINT-format (deepset + Lakera Gandalf) [^pint] | ${cells} |`;
const README_TABLE = (pintCells: string) =>
  [
    "# ATR",
    "",
    "| Source | Source version | Samples | Recall | Precision | FP rate | ATR version | Measured |",
    "|---|---|---:|---:|---:|---:|---|---|",
    PINT_ROW(pintCells),
    "",
    "Prose after the table, citing ATR 3.5.12.",
    "",
  ].join("\n");

/**
 * main as Sync stats leaves it after a pint run: a schema-valid pointer and
 * data/stats.json projected from it, while README and stats.json still cite
 * the last run. The renderer and its imports are linked in from this checkout;
 * --root keeps every read and write inside the sandbox.
 */
function renderSandbox(): Sandbox {
  const base = { source: "pint", source_version: "v1", atr_version: "4.1.5", measured_at: "2026-10-05T05:00:00.000Z", samples: 850 };
  const metrics = { recall: 0.6, precision: 1, f1: 0.75, fp_rate: 0 };
  const sb = sandbox("measure-render-", {
    [`data/measurements/pint/${PINT_FILE}`]: JSON.stringify({ ...base, metrics, confusion: { tp: 271, fp: 0, tn: 399, fn: 180 } }),
    [LATEST]: JSON.stringify({ ...base, file: PINT_FILE, metrics }, null, 2) + "\n",
    "data/stats.json":
      JSON.stringify(
        {
          benchmarks: [
            {
              source: "pint",
              source_version: "v1",
              atr_version: "4.1.5",
              measured_at: "2026-10-05",
              samples: 850,
              recall: 0.6,
              precision: 1,
              f1: 0.75,
              fp_rate: 0,
              measurement_file: `data/measurements/pint/${PINT_FILE}`,
            },
          ],
        },
        null,
        2,
      ) + "\n",
    "README.md": README_TABLE("v1 | 850 | 65.4% | 100.0% | 0.0% | 3.5.12 | 2026-08-15"),
    "stats.json":
      JSON.stringify(
        { benchmarks: { pint: { recall: 65.4, atr_version: "3.5.12", measured: "2026-08-15", comment: "62 of 784 rules fire." } } },
        null,
        2,
      ) + "\n",
    ...RENDERED_ELSEWHERE,
  });
  for (const dir of ["scripts", "node_modules"]) symlinkSync(join(REPO, dir), join(sb.work, dir));
  return sb;
}

describe("README benchmark table", () => {
  it("is rendered after Sync stats and before changes are detected", () => {
    const names = jobSteps(WORKFLOW, JOB).map((s) => s.name);
    const at = (n: string) => names.indexOf(n);
    expect(at(RENDER)).toBeGreaterThan(at(SYNC));
    expect(at(DETECT)).toBeGreaterThan(at(RENDER));
    expect(runBlock(WORKFLOW, JOB, RENDER)).toMatch(
      /scripts\/render-benchmark-table\.ts --root \. --review-notes "\$RUNNER_TEMP\/benchmark-review\.md"$/m,
    );
  });

  it.skipIf(!HAS_JQ)("is rendered from the measurements and pushed with them to the rolling branch", () => {
    const sb = renderSandbox();
    const render = runStep(sb, runBlock(WORKFLOW, JOB, RENDER));
    expect(render.status, render.stderr).toBe(0);
    expect(readFileSync(resolve(sb.work, "README.md"), "utf8")).toBe(
      README_TABLE("v1 | 850 | 60.0% | 100.0% | 0.0% | 4.1.5 | 2026-10-05"),
    );

    const detect = runStep(sb, runBlock(WORKFLOW, JOB, DETECT));
    expect(detect.status, detect.stderr).toBe(0);
    expect(staged(sb).split("\n").sort()).toEqual(["README.md", "stats.json"]);

    const res = runStep(sb, runBlock(WORKFLOW, JOB, PUSH), { ROLLING_OLD_SHA: "" });
    expect(res.status, res.stderr).toBe(0);
    const pushed = git(sb, sb.origin, "diff", "--name-only", "main", originSha(sb, BRANCH));
    expect(pushed.split("\n").sort()).toEqual(["README.md", "stats.json"]);
    const rootStats = JSON.parse(git(sb, sb.origin, "show", `${BRANCH}:stats.json`));
    expect(rootStats.benchmarks.pint).toEqual({ recall: 60, atr_version: "4.1.5", measured: "2026-10-05" });
  });

  it.skipIf(!HAS_JQ)("lists what it could not re-render in the body of the PR it opens", () => {
    const sb = renderSandbox();
    expect(runStep(sb, runBlock(WORKFLOW, JOB, RENDER)).status).toBe(0);
    expect(runStep(sb, runBlock(WORKFLOW, JOB, DETECT)).status).toBe(0);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, PUSH), { ROLLING_OLD_SHA: "" });
    expect(res.status, res.stderr).toBe(0);
    expect(ghCalls(sb)).toMatch(/^pr create .*--body-file /m);
    const body = prBody(sb);
    expect(body).toMatch(/^Auto-generated measurement refresh/);
    expect(body).toMatch(/^- README\.md:7 — Prose after the table, citing ATR 3\.5\.12\.$/m);
    expect(body).toMatch(/^- `benchmarks\.pint\.comment`$/m);
  });

  it.skipIf(!HAS_JQ)("rewrites the body of the open rolling PR with this run's notes", () => {
    const sb = renderSandbox();
    setPrs(sb, [{ number: 700, state: "OPEN", isCrossRepository: false }]);
    expect(runStep(sb, runBlock(WORKFLOW, JOB, RENDER)).status).toBe(0);
    expect(runStep(sb, runBlock(WORKFLOW, JOB, DETECT)).status).toBe(0);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, PUSH), { ROLLING_OLD_SHA: "" });
    expect(res.status, res.stderr).toBe(0);
    expect(ghCalls(sb)).toMatch(/^api -X PATCH repos\/fixture-owner\/fixture-repo\/pulls\/700 -F body=@/m);
    expect(ghCalls(sb)).not.toMatch(/^pr create /m);
    expect(prBody(sb)).toMatch(/README\.md:7 — Prose after the table/);
  });

  it("leaves README and stats.json alone when they already match", () => {
    const sb = renderSandbox();
    expect(runStep(sb, runBlock(WORKFLOW, JOB, RENDER)).status).toBe(0);
    git(sb, sb.work, "add", "README.md", "stats.json");
    git(sb, sb.work, "commit", "--quiet", "-m", "rendered");
    const again = runStep(sb, runBlock(WORKFLOW, JOB, RENDER));
    expect(again.status, again.stderr).toBe(0);
    expect(git(sb, sb.work, "status", "--porcelain", "--", "README.md", "stats.json")).toBe("");
  });
});

describe("recall citations outside README", () => {
  it("are rendered after the README table, which writes the stats.json they read, and before changes are detected", () => {
    const names = jobSteps(WORKFLOW, JOB).map((s) => s.name);
    const at = (n: string) => names.indexOf(n);
    expect(at(RECALL)).toBeGreaterThan(at(RENDER));
    expect(at(CITATION)).toBeGreaterThan(at(RENDER));
    expect(at(DETECT)).toBeGreaterThan(Math.max(at(RECALL), at(CITATION)));
    expect(runBlock(WORKFLOW, JOB, RECALL)).toMatch(
      /scripts\/render-recall-citations\.ts --root \. --review-notes "\$RUNNER_TEMP\/benchmark-review\.md"$/m,
    );
    expect(runBlock(WORKFLOW, JOB, CITATION)).toMatch(
      /scripts\/sync-citation-garak\.ts --root \. --review-notes "\$RUNNER_TEMP\/benchmark-review\.md"$/m,
    );
  });

  it("stages CITATION.cff and every document render-recall-citations.ts renders", () => {
    const sb = measureSandbox();
    for (const doc of Object.keys(RENDERED_ELSEWHERE)) put(sb.work, doc, `# ${doc}\nre-rendered\n`);
    const detect = runStep(sb, runBlock(WORKFLOW, JOB, DETECT));
    expect(detect.status, detect.stderr).toBe(0);
    expect(staged(sb).split("\n").sort()).toEqual(Object.keys(RENDERED_ELSEWHERE).sort());
  });
});
