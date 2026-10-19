/**
 * Tests for scripts/verify-status-claims.mjs, the weekly check of
 * website/data/status-claims.json against GitHub, and its workflow.
 *
 * The script first checks the list and the files offline (the same checks
 * tests/status-claims.test.ts runs in npm test), then asks GitHub for the
 * state of every claim. A failure is drift (GitHub disagrees with what the
 * files say: fix them), gone (404/410) or unverified (GitHub could not be
 * asked); unverified is never a pass.
 *
 * Nothing here touches the network: GitHub is a fake fetch.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import yaml from "js-yaml";
// @ts-expect-error -- stdlib-only .mjs script, no type declarations (it runs in
// CI without npm install, so it must not depend on the TypeScript toolchain).
import { main, report, verifyClaims } from "../scripts/verify-status-claims.mjs";

const REPO_ROOT = resolve(__dirname, "..");
const SCRIPT = join(REPO_ROOT, "scripts", "verify-status-claims.mjs");
const WORKFLOW = join(REPO_ROOT, ".github", "workflows", "verify-status-claims.yml");
const NO_WAIT = { sleep: async () => undefined };

type Reply = { status: number; body?: unknown };

function fakeGitHub(routes: Record<string, Reply>) {
  const asked: string[] = [];
  const impl = async (url: string) => {
    const path = url.replace("https://api.github.com", "");
    asked.push(path);
    const reply = routes[path];
    if (!reply) throw new Error(`unexpected request ${url}`);
    return { ok: reply.status < 300, status: reply.status, json: async () => reply.body };
  };
  return { impl, asked };
}

const OPEN = "https://github.com/o/open/pull/1";
const CLOSED = "https://github.com/o/closed/issues/2";
const GITHUB_AGREES = {
  "/repos/o/open/pulls/1": { status: 200, body: { state: "open", merged_at: null } },
  "/repos/o/closed/issues/2": { status: 200, body: { state: "closed" } },
};

/** A throwaway repository with a list, the files it names, and README's review section. */
function fixture(registry: unknown, files: Record<string, string> = {}): string {
  const root = mkdtempSync(join(tmpdir(), "status-claims-"));
  const all = {
    "website/data/status-claims.json": typeof registry === "string" ? registry : JSON.stringify(registry),
    "README.md": `# x\n### Under maintainer review (open PRs)\n\n${OPEN}\n\n### Later\n${CLOSED}\n`,
    "ADOPTERS.md": "# ADOPTERS\n",
    ...files,
  };
  for (const [rel, text] of Object.entries(all)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}

const GOOD = {
  claims: [
    { url: OPEN, state: "open", files: ["README.md"] },
    { url: CLOSED, state: "closed", files: ["README.md"] },
  ],
};

function quiet() {
  const out: string[] = [];
  vi.spyOn(console, "log").mockImplementation((...a: unknown[]) => void out.push(a.join(" ")));
  vi.spyOn(console, "error").mockImplementation((...a: unknown[]) => void out.push(a.join(" ")));
  return out;
}

afterEach(() => vi.restoreAllMocks());

describe("verifyClaims", () => {
  it("asks GitHub once per claim and compares the answer with the claim", async () => {
    const gh = fakeGitHub({ ...GITHUB_AGREES, "/repos/o/closed/issues/2": { status: 200, body: { state: "open" } } });
    const results = await verifyClaims(GOOD.claims, { fetchImpl: gh.impl, ...NO_WAIT });
    expect(gh.asked).toEqual(["/repos/o/open/pulls/1", "/repos/o/closed/issues/2"]);
    expect(results).toEqual([
      { url: OPEN, declared: "open", observed: "open", ok: true, files: ["README.md"] },
      { url: CLOSED, declared: "closed", observed: "open", ok: false, files: ["README.md"] },
    ]);
  });
});

describe("report", () => {
  const result = (url: string, declared: string, observed: string, files = ["README.md"]) => ({ url, declared, observed, ok: declared === observed, files });

  it("returns 0 and says so when every claim matches", () => {
    const out = quiet();
    expect(report([result(OPEN, "open", "open")])).toBe(0);
    expect(out.join("\n")).toMatch(/1\/1 status claims match GitHub/);
  });

  it("returns 1 and names the files to fix for each kind of failure", () => {
    const out = quiet();
    const code = report([
      result(OPEN, "open", "merged", ["README.md", "website/app/x.tsx"]),
      result(CLOSED, "closed", "api-404"),
      result("https://github.com/o/r/pull/3", "merged", "api-403"),
    ]);
    expect(code).toBe(1);
    const text = out.join("\n");
    expect(text).toMatch(/\[FAIL\].*o\/open\/pull\/1.*claimed open, observed merged.*README\.md, website\/app\/x\.tsx/);
    expect(text).toMatch(/drift: https:\/\/github\.com\/o\/open\/pull\/1/);
    expect(text).toMatch(/gone: https:\/\/github\.com\/o\/closed\/issues\/2/);
    expect(text).toMatch(/unverified: https:\/\/github\.com\/o\/r\/pull\/3/);
    expect(text).toMatch(/not a pass/);
  });
});

describe("main", () => {
  it("passes when the list, the files and GitHub agree", async () => {
    quiet();
    const gh = fakeGitHub(GITHUB_AGREES);
    expect(await main({ root: fixture(GOOD), fetchImpl: gh.impl, ...NO_WAIT })).toBe(0);
    expect(gh.asked).toHaveLength(2);
  });

  it("fails on drift", async () => {
    quiet();
    const gh = fakeGitHub({ ...GITHUB_AGREES, "/repos/o/open/pulls/1": { status: 200, body: { state: "closed", merged_at: "2026-10-20T00:00:00Z" } } });
    expect(await main({ root: fixture(GOOD), fetchImpl: gh.impl, ...NO_WAIT })).toBe(1);
  });

  it("fails before asking GitHub when the list cannot be read or is malformed", async () => {
    const out = quiet();
    const gh = fakeGitHub(GITHUB_AGREES);
    expect(await main({ root: fixture("{ not json"), fetchImpl: gh.impl, ...NO_WAIT })).toBe(1);
    expect(await main({ root: fixture({ claims: [{ ...GOOD.claims[0], state: "in-review" }] }), fetchImpl: gh.impl, ...NO_WAIT })).toBe(1);
    expect(gh.asked).toEqual([]);
    expect(out.join("\n")).toMatch(/unknown state "in-review"/);
  });

  it("fails before asking GitHub when the files and the list disagree", async () => {
    const out = quiet();
    const gh = fakeGitHub(GITHUB_AGREES);
    const root = fixture(GOOD, { "website/app/page.tsx": "see https://github.com/o/unlisted/pull/9" });
    expect(await main({ root, fetchImpl: gh.impl, ...NO_WAIT })).toBe(1);
    expect(gh.asked).toEqual([]);
    expect(out.join("\n")).toMatch(/website\/app\/page\.tsx: links o\/unlisted#9/);
  });

  it("checks only the list and the files with --offline", async () => {
    quiet();
    const gh = fakeGitHub({});
    expect(await main({ root: fixture(GOOD), offline: true, fetchImpl: gh.impl })).toBe(0);
    expect(gh.asked).toEqual([]);
  });
});

describe("running the script", () => {
  it("checks the committed repository offline, also through a symlink", () => {
    const direct = spawnSync(process.execPath, [SCRIPT, "--offline"], { encoding: "utf8" });
    expect(direct.status, direct.stderr + direct.stdout).toBe(0);
    const link = join(mkdtempSync(join(tmpdir(), "status-claims-link-")), "verify.mjs");
    symlinkSync(SCRIPT, link);
    const viaLink = spawnSync(process.execPath, [link, "--offline"], { encoding: "utf8" });
    expect(viaLink.status, viaLink.stderr + viaLink.stdout).toBe(0);
    expect(viaLink.stdout).toBe(direct.stdout);
  });

  it("rejects an argument it does not know, rather than running a different check", () => {
    const res = spawnSync(process.execPath, [SCRIPT, "--ofline"], { encoding: "utf8" });
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/unknown argument "--ofline"/);
  });
});

describe("verify-status-claims.yml", () => {
  type Step = { name?: string; id?: string; if?: string; run?: string; uses?: string; with?: Record<string, unknown>; env?: Record<string, string> };
  const doc = yaml.load(readFileSync(WORKFLOW, "utf8")) as {
    on: Record<string, { paths?: string[]; branches?: string[] } | unknown>;
    permissions: Record<string, string>;
    jobs: { verify: { permissions: Record<string, string>; steps: Step[] } };
  };
  const steps = doc.jobs.verify.steps;
  const step = (pattern: RegExp) => steps.find((s) => pattern.test(s.name ?? ""));

  it("runs when the list or the checker changes, weekly, and on demand", () => {
    const watched = ["website/data/status-claims.json", "scripts/verify-status-claims.mjs", "scripts/lib/status-claims.mjs", "scripts/lib/github-link-state.mjs", ".github/workflows/verify-status-claims.yml"];
    for (const trigger of ["pull_request", "push"]) {
      expect((doc.on[trigger] as { paths: string[] }).paths, trigger).toEqual(expect.arrayContaining(watched));
    }
    expect(doc.on.schedule).toBeTruthy();
    expect("workflow_dispatch" in doc.on).toBe(true);
  });

  it("reads with a read-only token and writes only issues", () => {
    expect(doc.permissions).toEqual({ contents: "read" });
    expect(doc.jobs.verify.permissions).toEqual({ contents: "read", issues: "write" });
    const checkout = steps.find((s) => (s.uses ?? "").startsWith("actions/checkout"));
    expect(checkout?.with?.["persist-credentials"]).toBe(false);
  });

  it("keeps the checker's exit code through tee", () => {
    const verify = steps.find((s) => s.id === "verify");
    expect(verify?.run).toMatch(/set -o pipefail/);
    expect(verify?.run).toMatch(/node scripts\/verify-status-claims\.mjs 2>&1 \| tee /);
  });

  it("files a failure on main as one tracking issue, and closes it on a green run", () => {
    const open = step(/^Open or update the tracking issue/);
    const close = step(/^Close the tracking issue/);
    expect(open?.if).toMatch(/failure\(\) && steps\.verify\.outcome == 'failure'/);
    expect(close?.if).toMatch(/success\(\)/);
    for (const s of [open, close]) {
      expect(s?.if).toMatch(/github\.event_name != 'pull_request'/);
      expect(s?.if).toMatch(/github\.ref == 'refs\/heads\/main'/);
      expect(s?.run).toMatch(/gh issue list --state open --label auto-generated/);
    }
    expect(open?.run).toMatch(/gh issue create --title "\$title" --body "\$body" --label auto-generated/);
  });
});
