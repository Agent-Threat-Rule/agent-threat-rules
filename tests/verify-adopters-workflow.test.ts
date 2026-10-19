/**
 * Tests for .github/workflows/verify-adopters.yml — the shell around
 * scripts/verify-adopters.mjs. Steps run verbatim against a throwaway origin and
 * a stand-in gh (see tests/workflow-step-harness.ts).
 *
 * - The job commits the refreshed data/adopters-verification.json straight to
 *   main. It pushed with a plain `git push`, so a run that started before some
 *   other commit landed on main was rejected ("fetch first") and failed red
 *   with nothing wrong in ADOPTERS.md: 2026-10-07 and 2026-10-15. It now
 *   rebases its one-file commit onto the moved main and retries, runs one at a
 *   time, and checks out the branch tip, so a run that waited behind another
 *   starts from the data commit the other pushed instead of conflicting with it.
 * - Four red runs in a row (2026-10-12 to 10-15) went unnoticed for days. A
 *   failure on main now opens one tracking issue, or rewrites the open one, and
 *   the next green run closes it, as rule-latency.yml does.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  HAS_JQ,
  cleanSandboxes,
  ghCalls,
  git,
  put,
  runBlock,
  runStep,
  sandbox,
  workflowDoc,
  type Sandbox,
} from "./workflow-step-harness.js";

const WORKFLOW = resolve(__dirname, "..", ".github", "workflows", "verify-adopters.yml");
const JOB = "verify";
const COMMIT = "Commit refreshed verification data";
const OPEN_ISSUE = "Open or update the tracking issue";
const CLOSE_ISSUE = "Close the tracking issue once evidence matches again";
const TITLE = "ADOPTERS.md evidence no longer matches GitHub";
const DATA = "data/adopters-verification.json";
const BOT_SUBJECT = "chore(adopters): auto re-verify evidence links";

afterEach(cleanSandboxes);

function verification(date: string, drift: { name: string; declared: string; observed: string }[] = []): string {
  return `${JSON.stringify({ verified_at: date, total: 3, ok: 3 - drift.length, drift, results: [] }, null, 2)}\n`;
}

/** Someone else's commit lands on origin/main after the job checked out. */
function advanceMain(sb: Sandbox, rel: string, text: string): void {
  const dir = join(mkdtempSync(join(sb.root, "other-")), "clone");
  git(sb, sb.root, "clone", "--quiet", sb.origin, dir);
  put(dir, rel, text);
  git(sb, dir, "add", "-A");
  git(sb, dir, "commit", "--quiet", "-m", "someone else");
  git(sb, dir, "push", "--quiet", "origin", "main");
}

function originSubjects(sb: Sandbox): string[] {
  return git(sb, sb.origin, "log", "--format=%s", "main").split("\n");
}

function output(sb: Sandbox): string {
  return readFileSync(join(sb.root, "github_output"), "utf8");
}

/** Open issues the stand-in gh can find, as gh issue list --json would list them. */
function issues(sb: Sandbox, list: { number: number; title: string; labels: string[] }[]): string {
  const file = join(sb.root, "issues.json");
  writeFileSync(file, JSON.stringify(list.map((i) => ({ ...i, state: "OPEN" }))));
  return file;
}

const OURS = { number: 42, title: TITLE, labels: ["auto-generated"] };
// A real open issue on the repository, also labelled auto-generated.
const UNRELATED = { number: 82, title: "ATR: proposals awaiting human PoC", labels: ["auto-generated"] };

describe("verify-adopters.yml: committing the refreshed data", () => {
  const block = runBlock(WORKFLOW, JOB, COMMIT);

  it("pushes the refreshed data", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: verification("2026-10-12"), "README.md": "a\n" });
    put(sb.work, DATA, verification("2026-10-19"));
    const res = runStep(sb, block);
    expect(res.status, res.stderr).toBe(0);
    expect(originSubjects(sb)[0]).toBe(BOT_SUBJECT);
    expect(output(sb)).toMatch(/committed=true/);
  });

  it("rebases and pushes when main moved after checkout (the 2026-10-15 failure)", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: verification("2026-10-12"), "README.md": "a\n" });
    advanceMain(sb, "README.md", "b\n");
    put(sb.work, DATA, verification("2026-10-19"));
    const res = runStep(sb, block);
    expect(res.status, res.stderr).toBe(0);
    expect(originSubjects(sb).slice(0, 2)).toEqual([BOT_SUBJECT, "someone else"]);
    expect(output(sb)).toMatch(/committed=true/);
  });

  it("pushes nothing and reports no commit when main already holds the same data", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: verification("2026-10-12"), "README.md": "a\n" });
    advanceMain(sb, DATA, verification("2026-10-19"));
    put(sb.work, DATA, verification("2026-10-19"));
    const res = runStep(sb, block);
    expect(res.status, res.stderr).toBe(0);
    expect(originSubjects(sb)[0]).toBe("someone else");
    expect(output(sb)).toMatch(/committed=false/);
    expect(output(sb)).not.toMatch(/committed=true/);
  });

  it("fails, pushing nothing, when the generated file changed on main after checkout", () => {
    // Checking out the branch tip (below) keeps a queued run from getting here;
    // a hand edit of the generated file still can, and must not be overwritten.
    const sb = sandbox("adopters-wf-", { [DATA]: verification("2026-10-12"), "README.md": "a\n" });
    advanceMain(sb, DATA, verification("2026-10-18", [{ name: "x", declared: "shipped", observed: "closed" }]));
    put(sb.work, DATA, verification("2026-10-19"));
    const res = runStep(sb, block);
    expect(res.status).not.toBe(0);
    expect(originSubjects(sb)[0]).toBe("someone else");
    expect(output(sb)).not.toMatch(/committed=/);
  });

  it("gives up after three rejected pushes rather than looping", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: verification("2026-10-12"), "README.md": "a\n" });
    put(sb.work, DATA, verification("2026-10-19"));
    // Make every push fail the way a rejected push does.
    writeFileSync(join(sb.origin, "hooks", "pre-receive"), "#!/bin/sh\necho rejected >&2\nexit 1\n", { mode: 0o755 });
    const res = runStep(sb, block);
    expect(res.status).not.toBe(0);
    expect(res.stdout.match(/push rejected \(attempt \d\)/g)).toHaveLength(3);
    expect(output(sb)).not.toMatch(/committed=true/);
  });

  it("commits nothing when the data did not change", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: verification("2026-10-12") });
    const res = runStep(sb, block);
    expect(res.status, res.stderr).toBe(0);
    expect(originSubjects(sb)).toEqual(["main"]);
    expect(output(sb)).toMatch(/committed=false/);
  });
});

describe("verify-adopters.yml: runs and checkouts", () => {
  const doc = workflowDoc(WORKFLOW) as {
    concurrency?: { group?: string; "cancel-in-progress"?: boolean };
    permissions?: Record<string, string>;
    jobs: Record<string, { steps: { name?: string; id?: string; if?: string; run?: string; uses?: string; with?: Record<string, unknown> }[] }>;
  };
  const steps = doc.jobs[JOB].steps;

  it("runs one verification at a time per branch, so its own pushes cannot race", () => {
    expect(doc.concurrency?.group).toBe("verify-adopters-${{ github.ref }}");
    expect(doc.concurrency?.["cancel-in-progress"]).toBe(false);
  });

  it("checks out the branch tip, so a run that waited starts from the data its predecessor pushed (the 2026-10-07 pair)", () => {
    const checkout = steps.find((s) => (s.uses ?? "").startsWith("actions/checkout"));
    expect(checkout?.with?.ref).toBe("${{ github.ref }}");
  });

  it("files a failure on main and closes the issue on a green run on main, and nowhere else", () => {
    expect(steps.find((s) => s.name === OPEN_ISSUE)?.if).toBe("failure() && github.ref == 'refs/heads/main'");
    expect(steps.find((s) => s.name === CLOSE_ISSUE)?.if).toBe("success() && github.ref == 'refs/heads/main'");
    expect(steps.find((s) => s.id === "verify")?.name).toBe("Re-verify every evidence link");
    expect(doc.permissions?.issues).toBe("write");
  });
});

describe.skipIf(!HAS_JQ)("verify-adopters.yml: failures are filed and closed", () => {
  const open = runBlock(WORKFLOW, JOB, OPEN_ISSUE);
  const close = runBlock(WORKFLOW, JOB, CLOSE_ISSUE);
  const drifted = verification("2026-10-19", [{ name: "xlabs-club/awesome-x-ops", declared: "shipped", observed: "api-404" }]);

  it("opens an issue naming the drifted entries when none is open", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: verification("2026-10-12") });
    put(sb.work, DATA, drifted);
    const res = runStep(sb, open, { GITHUB_EVENT_NAME: "schedule", RUN_URL: "https://example.invalid/run/1", VERIFY_OUTCOME: "success" });
    expect(res.status, res.stderr).toBe(0);
    const calls = ghCalls(sb);
    expect(calls).toMatch(/issue create --title ADOPTERS\.md evidence no longer matches GitHub[\s\S]*--label auto-generated/);
    expect(calls).toMatch(/xlabs-club\/awesome-x-ops: declared shipped, observed api-404/);
  });

  it("does not list drift from a verification that did not finish", () => {
    // The data file is then the last committed one; on main it carried the
    // xlabs drift from 2026-10-12 to 10-19.
    const sb = sandbox("adopters-wf-", { [DATA]: drifted });
    const res = runStep(sb, open, { GITHUB_EVENT_NAME: "push", RUN_URL: "u", VERIFY_OUTCOME: "failure" });
    expect(res.status, res.stderr).toBe(0);
    const calls = ghCalls(sb);
    expect(calls).toMatch(/issue create/);
    expect(calls).toMatch(/the verification itself did not finish \(failure\)/);
    expect(calls).not.toMatch(/xlabs-club/);
  });

  it("rewrites the open issue instead of opening another", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: drifted });
    const res = runStep(sb, open, { FAKE_GH_ISSUES: issues(sb, [UNRELATED, OURS]), GITHUB_EVENT_NAME: "push", RUN_URL: "u", VERIFY_OUTCOME: "success" });
    expect(res.status, res.stderr).toBe(0);
    expect(ghCalls(sb)).toMatch(/issue edit 42 /);
    expect(ghCalls(sb)).not.toMatch(/issue create/);
  });

  it("never touches another auto-generated issue with a different title", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: drifted });
    const file = issues(sb, [UNRELATED]);
    expect(runStep(sb, open, { FAKE_GH_ISSUES: file, GITHUB_EVENT_NAME: "push", RUN_URL: "u", VERIFY_OUTCOME: "success" }).status).toBe(0);
    expect(runStep(sb, close, { FAKE_GH_ISSUES: file, RUN_URL: "u" }).status).toBe(0);
    expect(ghCalls(sb)).toMatch(/issue create/);
    expect(ghCalls(sb)).not.toMatch(/issue (edit|close) 82/);
  });

  it("closes the open issue on a green run, and does nothing when none is open", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: verification("2026-10-19") });
    expect(runStep(sb, close, { FAKE_GH_ISSUES: issues(sb, [UNRELATED, OURS]), RUN_URL: "u" }).status).toBe(0);
    expect(ghCalls(sb)).toMatch(/issue close 42 /);
    const quiet = sandbox("adopters-wf-", { [DATA]: verification("2026-10-19") });
    expect(runStep(quiet, close, { RUN_URL: "u" }).status).toBe(0);
    expect(ghCalls(quiet)).not.toMatch(/issue close/);
  });
});
