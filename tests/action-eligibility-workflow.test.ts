/**
 * Tests for the reverify job in .github/workflows/action-eligibility.yml.
 *
 * The steps are run verbatim with bash (tests/workflow-step-harness.ts) against
 * a throwaway origin, with stand-ins for `gh` and `npx`. What is pinned:
 *
 * - The measurement step can no longer fail quietly: no `|| true`, and an empty
 *   rule-id list stops the job instead of producing no file.
 * - The diff is scripts/reverify-evidence.ts, whose verdicts are tested in
 *   tests/reverify-evidence.test.ts.
 * - Stale-but-true evidence becomes a rolling PR, evidence-refresh/rolling,
 *   built from main plus the regenerated file and nothing else. Nothing is
 *   pushed to main, and a dispatch on another branch pushes nothing.
 */
import { describe, it, expect, afterEach } from "vitest";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  HAS_JQ,
  cleanSandboxes,
  ghCalls,
  git,
  jobSteps,
  originSha,
  put,
  runBlock,
  runStep,
  sandbox,
  setPrs,
  workflowDoc,
  type Sandbox,
} from "./workflow-step-harness.js";

const WORKFLOW = resolve(__dirname, "..", ".github", "workflows", "action-eligibility.yml");
const JOB = "reverify";
const REGENERATE = "Regenerate the measurement from the corpus";
const DIFF = "Diff against the committed evidence";
const REFRESH = "Open or update the evidence refresh PR";
const BRANCH = "evidence-refresh/rolling";
const EVIDENCE = "data/benign-fp-measurement.json";

const OLD = JSON.stringify({ corpus_digest: "d", sample_count: 3, rules: { "ATR-2026-00001": { fp_count: 0 } } }, null, 2);
const NEW = JSON.stringify(
  { corpus_digest: "d", sample_count: 3, rules: { "ATR-2026-00001": { fp_count: 0 }, "ATR-2026-00900": { fp_count: 1 } } },
  null,
  2,
);

afterEach(cleanSandboxes);

function reverifySandbox(): Sandbox {
  const sb = sandbox("reverify-wf-", {
    [EVIDENCE]: `${OLD}\n`,
    "rules/a/ATR-2026-00001-x.yaml": 'id: "ATR-2026-00001"\n',
  });
  // What the regenerate and diff steps leave in RUNNER_TEMP for the refresh step.
  writeFileSync(join(sb.root, "fresh-measurement.json"), `${NEW}\n`);
  writeFileSync(join(sb.root, "evidence-report.md"), "Not covered (1)\n\n- ATR-2026-00900: measured fp_count=1\n");
  return sb;
}

function stubNpx(sb: Sandbox): void {
  const npx = join(sb.root, "bin", "npx");
  writeFileSync(npx, `#!/usr/bin/env bash\nprintf '%s\\n' "$*" >> "${sb.root}/npx.log"\n`);
  chmodSync(npx, 0o755);
}

const prBody = (sb: Sandbox) => readFileSync(`${sb.env.FAKE_GH_LOG}.body`, "utf8");

describe("job shape", () => {
  it("runs on the schedule and on dispatch only, can write, and never overlaps itself", () => {
    const job = (workflowDoc(WORKFLOW).jobs as Record<string, Record<string, unknown>>)[JOB];
    expect(job.if).toBe("github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'");
    expect(job.permissions).toEqual({ contents: "write", "pull-requests": "write" });
    expect(job.concurrency).toEqual({ group: "evidence-refresh", "cancel-in-progress": false });
  });

  it("diffs with reverify-evidence.ts and opens the refresh PR only when it asks for one", () => {
    const steps = jobSteps(WORKFLOW, JOB) as readonly { name?: string; id?: string; if?: string; run?: string }[];
    const diff = steps.find((s) => s.name === DIFF);
    expect(diff?.id).toBe("diff");
    expect(diff?.run).toMatch(/npx tsx scripts\/reverify-evidence\.ts\s+\\\s+--committed data\/benign-fp-measurement\.json/);
    const refresh = steps.find((s) => s.name === REFRESH);
    expect(refresh?.if).toContain("!cancelled()");
    expect(refresh?.if).toContain("steps.diff.outputs.needs-refresh == 'true'");
  });
});

describe("regenerate step", () => {
  it("has no `|| true`", () => {
    const code = runBlock(WORKFLOW, JOB, REGENERATE)
      .split("\n")
      .filter((l) => !/^\s*#/.test(l))
      .join("\n");
    expect(code).not.toMatch(/\|\|\s*true/);
  });

  it("measures every rule id on disk through a file", () => {
    const sb = reverifySandbox();
    stubNpx(sb);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, REGENERATE));
    expect(res.status, res.stderr).toBe(0);
    const call = readFileSync(join(sb.root, "npx.log"), "utf8");
    expect(call).toMatch(/^tsx scripts\/gate-promotion-fp\.ts --ids \S+rule-ids\.txt --filter-mode --emit-measurement \S+fresh-measurement\.json/);
    expect(readFileSync(join(sb.root, "rule-ids.txt"), "utf8")).toBe("ATR-2026-00001\n");
  });

  it("stops when no rule id is found instead of measuring nothing", () => {
    const sb = sandbox("reverify-wf-empty-", { [EVIDENCE]: `${OLD}\n`, "rules/README.md": "no rules\n" });
    stubNpx(sb);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, REGENERATE));
    expect(res.status).not.toBe(0);
    expect(() => readFileSync(join(sb.root, "npx.log"), "utf8")).toThrow();
  });
});

describe.skipIf(!HAS_JQ)("refresh step", () => {
  it("pushes main plus the regenerated file to the rolling branch and opens the PR", () => {
    const sb = reverifySandbox();
    const mainBefore = originSha(sb, "main");
    const res = runStep(sb, runBlock(WORKFLOW, JOB, REFRESH));
    expect(res.status, res.stderr).toBe(0);
    expect(git(sb, sb.origin, "diff", "--name-only", "main", originSha(sb, BRANCH))).toBe(EVIDENCE);
    expect(git(sb, sb.origin, "show", `${BRANCH}:${EVIDENCE}`)).toBe(NEW);
    expect(git(sb, sb.origin, "log", "-1", "--format=%an <%ae>", BRANCH)).toBe(
      "ATR Measurement Bot <measurement-bot@agentthreatrule.org>",
    );
    expect(ghCalls(sb)).toMatch(/^pr create --base main --head evidence-refresh\/rolling /m);
    expect(prBody(sb)).toMatch(/^Auto-generated from the scheduled reverify job/);
    expect(prBody(sb)).toMatch(/- ATR-2026-00900: measured fp_count=1/);
    expect(originSha(sb, "main")).toBe(mainBefore);
  });

  it("updates an open refresh PR without opening a second", () => {
    const sb = reverifySandbox();
    setPrs(sb, [{ number: 812, state: "OPEN", isCrossRepository: false }]);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, REFRESH));
    expect(res.status, res.stderr).toBe(0);
    expect(ghCalls(sb)).not.toMatch(/^pr create /m);
    expect(ghCalls(sb)).toMatch(/^api -X PATCH repos\/fixture-owner\/fixture-repo\/pulls\/812 -F body=@/m);
  });

  it("rebuilds the branch from main on the next run", () => {
    const sb = reverifySandbox();
    expect(runStep(sb, runBlock(WORKFLOW, JOB, REFRESH)).status).toBe(0);
    const first = originSha(sb, BRANCH);
    // The next scheduled run starts from a fresh checkout of main.
    git(sb, sb.work, "fetch", "--quiet", "origin");
    git(sb, sb.work, "reset", "--quiet", "--hard", "origin/main");
    put(sb.work, "rules/a/ATR-2026-00002-y.yaml", 'id: "ATR-2026-00002"\n');
    git(sb, sb.work, "add", "-A");
    git(sb, sb.work, "commit", "--quiet", "-m", "a new rule on main");
    git(sb, sb.work, "push", "--quiet", "origin", "main");
    const res = runStep(sb, runBlock(WORKFLOW, JOB, REFRESH));
    expect(res.status, res.stderr).toBe(0);
    const second = originSha(sb, BRANCH);
    expect(second).not.toBe(first);
    expect(git(sb, sb.origin, "rev-parse", `${second}^`)).toBe(originSha(sb, "main"));
  });

  it("pushes nothing when the regenerated file is identical", () => {
    const sb = reverifySandbox();
    writeFileSync(join(sb.root, "fresh-measurement.json"), `${OLD}\n`);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, REFRESH));
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toMatch(/identical to the committed one/);
    expect(originSha(sb, BRANCH)).toBe("");
  });

  it("does not push a dispatch on a ref that is not on main", () => {
    const sb = reverifySandbox();
    git(sb, sb.work, "checkout", "--quiet", "-b", "feature");
    put(sb.work, "rules/b/new.yaml", 'id: "ATR-2026-00003"\n');
    git(sb, sb.work, "add", "-A");
    git(sb, sb.work, "commit", "--quiet", "-m", "feature");
    const res = runStep(sb, runBlock(WORKFLOW, JOB, REFRESH));
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toMatch(/not on main: measured, not pushed/);
    expect(originSha(sb, BRANCH)).toBe("");
  });

  it("fails the job when the PR cannot be opened", () => {
    const sb = reverifySandbox();
    const res = runStep(sb, runBlock(WORKFLOW, JOB, REFRESH), { FAKE_GH_CREATE_FAIL: "1" });
    expect(res.status).not.toBe(0);
  });
});
