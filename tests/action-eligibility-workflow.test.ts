/**
 * Tests for the reverify and refresh jobs in .github/workflows/action-eligibility.yml.
 *
 * The steps are run verbatim with bash (tests/workflow-step-harness.ts) against
 * a throwaway origin, with stand-ins for `gh` and `npx`. What is pinned:
 *
 * - The measuring job holds no write token: it runs npm ci and the repository's
 *   scripts for as long as the scan takes. Only the refresh job can push, and it
 *   runs git and gh, nothing else.
 * - The measurement measures the rules the action gate reads (listed by
 *   reverify-evidence.ts --list-ids, not a grep), cannot fail quietly (no
 *   `|| true`), and stops on an empty id list instead of producing no file.
 * - Stale-but-true evidence becomes a rolling PR, evidence-refresh/rolling, built
 *   from the measured commit plus the regenerated file and nothing else. Nothing
 *   is pushed to main, and a dispatch on another branch pushes nothing.
 */
import { describe, it, expect, afterEach } from "vitest";
import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
const REGENERATE = "Regenerate the measurement from the corpus";
const DIFF = "Diff against the committed evidence";
const HAND_OVER = "Hand the regenerated evidence to the refresh job";
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

type Job = Record<string, unknown> & { steps: { name?: string; id?: string; if?: string; run?: string; uses?: string; with?: Record<string, unknown> }[] };
const jobs = () => (workflowDoc(WORKFLOW).jobs as Record<string, Job>);

function reverifySandbox(): Sandbox {
  const sb = sandbox("reverify-wf-", {
    [EVIDENCE]: `${OLD}\n`,
    "rules/a/ATR-2026-00001-x.yaml": 'id: "ATR-2026-00001"\n',
  });
  // What the download-artifact step leaves for the refresh step.
  mkdirSync(join(sb.root, "evidence"));
  writeFileSync(join(sb.root, "evidence", "fresh-measurement.json"), `${NEW}\n`);
  writeFileSync(join(sb.root, "evidence", "evidence-report.md"), "Not covered (1)\n\n- ATR-2026-00900: measured fp_count=1\n");
  return sb;
}

/** A stand-in npx: logs each call; `--list-ids` prints whatever $STUB_IDS holds. */
function stubNpx(sb: Sandbox, ids: string): void {
  writeFileSync(join(sb.root, "stub-ids.txt"), ids);
  const npx = join(sb.root, "bin", "npx");
  writeFileSync(
    npx,
    `#!/usr/bin/env bash\nprintf '%s\\n' "$*" >> "${sb.root}/npx.log"\n` +
      `case " $* " in *" --list-ids "*) cat "${sb.root}/stub-ids.txt" ;; esac\n`,
  );
  chmodSync(npx, 0o755);
}

const prBody = (sb: Sandbox) => readFileSync(`${sb.env.FAKE_GH_LOG}.body`, "utf8");

describe("job shape", () => {
  it("measures on the schedule and on dispatch only, without a write token", () => {
    const job = jobs().reverify;
    expect(job.if).toBe("github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'");
    expect(job.permissions).toEqual({ contents: "read" });
    expect(job.outputs).toEqual({ "needs-refresh": "${{ steps.diff.outputs.needs-refresh }}" });
    expect(JSON.stringify(job)).not.toMatch(/ATR_REPO_TOKEN|PUSH_TOKEN|GH_TOKEN/);
  });

  it("writes only from the refresh job, which runs only when the diff asked for it", () => {
    const job = jobs().refresh;
    expect(job.needs).toBe("reverify");
    expect(job.if).toBe("needs.reverify.outputs.needs-refresh == 'true'");
    expect(job.permissions).toEqual({ contents: "write", "pull-requests": "write" });
    expect(job.concurrency).toEqual({ group: "evidence-refresh", "cancel-in-progress": false });
    // git and gh only: no install step, no repository script.
    const runs = job.steps.map((s) => s.run ?? "").join("\n");
    expect(runs).not.toMatch(/npm|npx|node |tsx/);
  });

  it("diffs with reverify-evidence.ts and hands over the evidence only when asked", () => {
    const steps = jobSteps(WORKFLOW, "reverify") as Job["steps"];
    const diff = steps.find((s) => s.name === DIFF);
    expect(diff?.id).toBe("diff");
    expect(diff?.run).toMatch(/npx tsx scripts\/reverify-evidence\.ts\s+\\\s+--committed data\/benign-fp-measurement\.json/);
    const handOver = steps.find((s) => s.name === HAND_OVER);
    expect(handOver?.if).toBe("steps.diff.outputs.needs-refresh == 'true'");
    expect(handOver?.uses).toMatch(/^actions\/upload-artifact@/);
  });
});

describe("regenerate step", () => {
  it("has no `|| true`", () => {
    const code = runBlock(WORKFLOW, "reverify", REGENERATE)
      .split("\n")
      .filter((l) => !/^\s*#/.test(l))
      .join("\n");
    expect(code).not.toMatch(/\|\|\s*true/);
  });

  it("measures the rule ids the gate's reader lists, through a file", () => {
    const sb = reverifySandbox();
    stubNpx(sb, "ATR-2026-00001\n");
    const res = runStep(sb, runBlock(WORKFLOW, "reverify", REGENERATE));
    expect(res.status, res.stderr).toBe(0);
    const calls = readFileSync(join(sb.root, "npx.log"), "utf8").trim().split("\n");
    expect(calls[0]).toBe("tsx scripts/reverify-evidence.ts --list-ids");
    expect(calls[1]).toMatch(
      /^tsx scripts\/gate-promotion-fp\.ts --ids \S+rule-ids\.txt --filter-mode --emit-measurement \S+\/evidence\/fresh-measurement\.json/,
    );
    expect(readFileSync(join(sb.root, "rule-ids.txt"), "utf8")).toBe("ATR-2026-00001\n");
  });

  it("stops when no rule id is listed instead of measuring nothing", () => {
    const sb = reverifySandbox();
    stubNpx(sb, "");
    const res = runStep(sb, runBlock(WORKFLOW, "reverify", REGENERATE));
    expect(res.status).not.toBe(0);
    expect(readFileSync(join(sb.root, "npx.log"), "utf8").trim().split("\n")).toHaveLength(1);
  });
});

describe.skipIf(!HAS_JQ)("refresh step", () => {
  it("pushes the measured commit plus the regenerated file to the rolling branch and opens the PR", () => {
    const sb = reverifySandbox();
    const mainBefore = originSha(sb, "main");
    const res = runStep(sb, runBlock(WORKFLOW, "refresh", REFRESH));
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
    const res = runStep(sb, runBlock(WORKFLOW, "refresh", REFRESH));
    expect(res.status, res.stderr).toBe(0);
    expect(ghCalls(sb)).not.toMatch(/^pr create /m);
    expect(ghCalls(sb)).toMatch(/^api -X PATCH repos\/fixture-owner\/fixture-repo\/pulls\/812 -F body=@/m);
  });

  it("rebuilds the branch from main on the next run", () => {
    const sb = reverifySandbox();
    expect(runStep(sb, runBlock(WORKFLOW, "refresh", REFRESH)).status).toBe(0);
    const first = originSha(sb, BRANCH);
    // The next scheduled run starts from a fresh checkout of main.
    git(sb, sb.work, "fetch", "--quiet", "origin");
    git(sb, sb.work, "reset", "--quiet", "--hard", "origin/main");
    put(sb.work, "rules/a/ATR-2026-00002-y.yaml", 'id: "ATR-2026-00002"\n');
    git(sb, sb.work, "add", "-A");
    git(sb, sb.work, "commit", "--quiet", "-m", "a new rule on main");
    git(sb, sb.work, "push", "--quiet", "origin", "main");
    const res = runStep(sb, runBlock(WORKFLOW, "refresh", REFRESH));
    expect(res.status, res.stderr).toBe(0);
    const second = originSha(sb, BRANCH);
    expect(second).not.toBe(first);
    expect(git(sb, sb.origin, "rev-parse", `${second}^`)).toBe(originSha(sb, "main"));
  });

  it("pushes nothing when the regenerated file is identical", () => {
    const sb = reverifySandbox();
    writeFileSync(join(sb.root, "evidence", "fresh-measurement.json"), `${OLD}\n`);
    const res = runStep(sb, runBlock(WORKFLOW, "refresh", REFRESH));
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
    const res = runStep(sb, runBlock(WORKFLOW, "refresh", REFRESH));
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toMatch(/not on main: measured, not pushed/);
    expect(originSha(sb, BRANCH)).toBe("");
  });

  it("fails the job when the PR cannot be opened", () => {
    const sb = reverifySandbox();
    const res = runStep(sb, runBlock(WORKFLOW, "refresh", REFRESH), { FAKE_GH_CREATE_FAIL: "1" });
    expect(res.status).not.toBe(0);
  });
});
