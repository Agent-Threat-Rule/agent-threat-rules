/**
 * Tests for .github/workflows/verify-adopters.yml — the shell around
 * scripts/verify-adopters.mjs. Steps run verbatim against a throwaway origin and
 * a stand-in gh (see tests/workflow-step-harness.ts).
 *
 * - The job commits the refreshed data/adopters-verification.json straight to
 *   main. It pushed with a plain `git push`, so a run that started before some
 *   other commit landed on main was rejected ("fetch first") and failed red
 *   with nothing wrong in ADOPTERS.md: 2026-10-07 and 2026-10-15. It now
 *   rebases its one-file commit onto the moved main and retries.
 * - Four red runs in a row (2026-10-12 to 10-15) went unnoticed for days. A
 *   failure on main now opens one tracking issue, or rewrites the open one, and
 *   the next green run closes it, as verify-red-team-links.yml does.
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

  it("rebases and pushes when main moved after checkout (the 2026-10-07 and 10-15 failures)", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: verification("2026-10-12"), "README.md": "a\n" });
    advanceMain(sb, "README.md", "b\n");
    put(sb.work, DATA, verification("2026-10-19"));
    const res = runStep(sb, block);
    expect(res.status, res.stderr).toBe(0);
    expect(originSubjects(sb).slice(0, 2)).toEqual([BOT_SUBJECT, "someone else"]);
    expect(output(sb)).toMatch(/committed=true/);
  });

  it("fails rather than looping when the push keeps being rejected", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: verification("2026-10-12"), "README.md": "a\n" });
    put(sb.work, DATA, verification("2026-10-19"));
    // Make every push fail the way a rejected push does.
    writeFileSync(join(sb.origin, "hooks", "pre-receive"), "#!/bin/sh\necho rejected >&2\nexit 1\n", { mode: 0o755 });
    const res = runStep(sb, block);
    expect(res.status).not.toBe(0);
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

describe("verify-adopters.yml: failures are filed and closed", () => {
  const doc = workflowDoc(WORKFLOW) as {
    concurrency?: { group?: string; "cancel-in-progress"?: boolean };
    permissions?: Record<string, string>;
    jobs: Record<string, { steps: { name?: string; if?: string; run?: string }[] }>;
  };
  const steps = doc.jobs[JOB].steps;
  const open = steps.find((s) => s.name === OPEN_ISSUE);
  const close = steps.find((s) => s.name === CLOSE_ISSUE);

  it("files on a failure on main and closes on a green run on main", () => {
    expect(open?.if).toMatch(/failure\(\)/);
    expect(close?.if).toMatch(/success\(\)/);
    for (const step of [open, close]) {
      expect(step?.if).toMatch(/github\.ref == 'refs\/heads\/main'/);
      expect(step?.run).toMatch(/gh issue list[^\n]*--label auto-generated/);
    }
    expect(doc.permissions?.issues).toBe("write");
  });

  it("never runs two verifications at once, so its own pushes cannot race", () => {
    expect(doc.concurrency?.group).toBeTruthy();
    expect(doc.concurrency?.["cancel-in-progress"]).toBe(false);
  });

  it.skipIf(!HAS_JQ)("opens an issue naming the drifted entries when none is open", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: verification("2026-10-12") });
    put(sb.work, DATA, verification("2026-10-19", [{ name: "xlabs-club/awesome-x-ops", declared: "shipped", observed: "api-404" }]));
    const res = runStep(sb, runBlock(WORKFLOW, JOB, OPEN_ISSUE), { GITHUB_EVENT_NAME: "schedule", RUN_URL: "https://example.invalid/run/1" });
    expect(res.status, res.stderr).toBe(0);
    const calls = ghCalls(sb);
    expect(calls).toMatch(/issue create --title ADOPTERS\.md evidence no longer matches GitHub[\s\S]*--label auto-generated/);
    expect(calls).toMatch(/xlabs-club\/awesome-x-ops/);
  });

  it.skipIf(!HAS_JQ)("rewrites the open issue instead of opening another", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: verification("2026-10-19", [{ name: "x", declared: "shipped", observed: "closed" }]) });
    const issues = join(sb.root, "issues.json");
    writeFileSync(issues, JSON.stringify([{ number: 42, state: "OPEN", labels: ["auto-generated"] }]));
    const res = runStep(sb, runBlock(WORKFLOW, JOB, OPEN_ISSUE), { FAKE_GH_ISSUES: issues, GITHUB_EVENT_NAME: "push", RUN_URL: "u" });
    expect(res.status, res.stderr).toBe(0);
    expect(ghCalls(sb)).toMatch(/issue edit 42 /);
    expect(ghCalls(sb)).not.toMatch(/issue create/);
  });

  it.skipIf(!HAS_JQ)("closes the open issue on a green run, and does nothing when none is open", () => {
    const sb = sandbox("adopters-wf-", { [DATA]: verification("2026-10-19") });
    const issues = join(sb.root, "issues.json");
    writeFileSync(issues, JSON.stringify([{ number: 42, state: "OPEN", labels: ["auto-generated"] }]));
    expect(runStep(sb, runBlock(WORKFLOW, JOB, CLOSE_ISSUE), { FAKE_GH_ISSUES: issues, RUN_URL: "u" }).status).toBe(0);
    expect(ghCalls(sb)).toMatch(/issue close 42 /);
    const quiet = sandbox("adopters-wf-", { [DATA]: verification("2026-10-19") });
    expect(runStep(quiet, runBlock(WORKFLOW, JOB, CLOSE_ISSUE), { RUN_URL: "u" }).status).toBe(0);
    expect(ghCalls(quiet)).not.toMatch(/issue close/);
  });
});
