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
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import yaml from "js-yaml";
// @ts-expect-error -- stdlib-only .mjs script, no type declarations (it runs in
// CI without npm install, so it must not depend on the TypeScript toolchain).
import { main, report, verifyClaims } from "../scripts/verify-status-claims.mjs";
import { HAS_JQ, cleanSandboxes, ghCalls, runBlock, runStep, sandbox, type Sandbox } from "./workflow-step-harness.js";

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

  it("fails when README's review section lists a claim that is not open", async () => {
    const out = quiet();
    const readme = `# x\n### Under maintainer review (open PRs)\n\n${OPEN}\n${CLOSED}\n`;
    expect(await main({ root: fixture(GOOD, { "README.md": readme }), offline: true })).toBe(1);
    expect(out.join("\n")).toMatch(/lists o\/closed#2, which is closed, not open/);
  });

  it("checks only the list and the files with --offline", async () => {
    quiet();
    const gh = fakeGitHub({});
    expect(await main({ root: fixture(GOOD), offline: true, fetchImpl: gh.impl })).toBe(0);
    expect(gh.asked).toEqual([]);
  });
});

// Isolated from the user's git config (signing, hooks).
const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1", GIT_AUTHOR_NAME: "f", GIT_AUTHOR_EMAIL: "f@example.invalid", GIT_COMMITTER_NAME: "f", GIT_COMMITTER_EMAIL: "f@example.invalid" };
const gitIn = (root: string, ...args: string[]) => execFileSync("git", args, { cwd: root, env: GIT_ENV, encoding: "utf8" }).trim();

/** A git repository holding fixture(registry, files) at one commit; returns the root and that commit. */
function gitFixture(registry: unknown = GOOD, files: Record<string, string> = {}): { root: string; base: string } {
  const root = fixture(registry, files);
  gitIn(root, "init", "--quiet", "-b", "main");
  gitIn(root, "add", "-A");
  gitIn(root, "commit", "--quiet", "-m", "base");
  return { root, base: gitIn(root, "rev-parse", "HEAD") };
}

describe("main --base: a changed state needs its files changed too", () => {
  const reopened = { claims: [GOOD.claims[0], { ...GOOD.claims[1], state: "open" }] };

  it("fails when the list changes a state and a file it named is left as it was", async () => {
    const out = quiet();
    const { root, base } = gitFixture();
    writeFileSync(join(root, "website/data/status-claims.json"), JSON.stringify(reopened));
    expect(await main({ root, base, offline: true })).toBe(1);
    expect(out.join("\n")).toMatch(/README\.md: o\/closed#2 changed from closed to open, but this file\b.* is unchanged/);
  });

  it("passes when every file the list named changed with it", async () => {
    quiet();
    const { root, base } = gitFixture();
    writeFileSync(join(root, "website/data/status-claims.json"), JSON.stringify(reopened));
    writeFileSync(join(root, "README.md"), `# x\n### Under maintainer review (open PRs)\n\n${OPEN}\n${CLOSED}\n`);
    expect(await main({ root, base, offline: true })).toBe(0);
  });

  // A page long enough that a one-line edit keeps git's rename detection.
  const PAGE_TEXT = [...Array.from({ length: 12 }, (_, i) => `line ${i} of the page`), `${CLOSED} closed`].join("\n") + "\n";
  const reopenWithPage = (page: string) => ({ claims: [GOOD.claims[0], { ...GOOD.claims[1], state: "open", files: ["README.md", page] }] });
  const README_REWORDED = `# x\n### Under maintainer review (open PRs)\n\n${OPEN}\n${CLOSED}\n`;

  it("does not count a file that was only renamed: its text still says the old state", async () => {
    const out = quiet();
    const page = "website/app/page.tsx";
    const { root, base } = gitFixture({ claims: [GOOD.claims[0], { ...GOOD.claims[1], files: ["README.md", page] }] }, { [page]: PAGE_TEXT });
    gitIn(root, "mv", page, "website/app/moved.tsx");
    writeFileSync(join(root, "website/data/status-claims.json"), JSON.stringify(reopenWithPage("website/app/moved.tsx")));
    writeFileSync(join(root, "README.md"), README_REWORDED);
    expect(await main({ root, base, offline: true })).toBe(1);
    expect(out.join("\n")).toMatch(/website\/app\/page\.tsx: o\/closed#2 changed from closed to open/);
    // Renamed and edited: both paths count.
    writeFileSync(join(root, "website/app/moved.tsx"), PAGE_TEXT.replace(`${CLOSED} closed`, `${CLOSED} reopened`));
    expect(await main({ root, base, offline: true })).toBe(0);
  });

  it("does not count a change of file mode: the text still says the old state", async () => {
    const out = quiet();
    const page = "website/app/page.tsx";
    const { root, base } = gitFixture({ claims: [GOOD.claims[0], { ...GOOD.claims[1], files: ["README.md", page] }] }, { [page]: PAGE_TEXT });
    chmodSync(join(root, page), 0o755);
    writeFileSync(join(root, "website/data/status-claims.json"), JSON.stringify(reopenWithPage(page)));
    writeFileSync(join(root, "README.md"), README_REWORDED);
    expect(await main({ root, base, offline: true })).toBe(1);
    expect(out.join("\n")).toMatch(/website\/app\/page\.tsx: o\/closed#2 changed from closed to open/);
  });

  it("fails closed on a base it cannot read, or whose list is broken, and has nothing to compare when the base has no list", async () => {
    const out = quiet();
    const { root } = gitFixture();
    expect(await main({ root, base: "0000000000000000000000000000000000000000", offline: true })).toBe(1);
    expect(out.join("\n")).toMatch(/cannot read the base commit/);
    for (const [broken, message] of [["{ not json", /is not JSON/], [JSON.stringify({ claims: [] }), /is malformed/]] as const) {
      const bad = gitFixture(broken);
      writeFileSync(join(bad.root, "website/data/status-claims.json"), JSON.stringify(GOOD));
      expect(await main({ root: bad.root, base: bad.base, offline: true }), String(message)).toBe(1);
      expect(out.join("\n")).toMatch(message);
    }
    const fresh = gitFixture();
    gitIn(fresh.root, "rm", "--quiet", "--cached", "website/data/status-claims.json");
    gitIn(fresh.root, "commit", "--quiet", "-m", "no list");
    expect(await main({ root: fresh.root, base: gitIn(fresh.root, "rev-parse", "HEAD"), offline: true })).toBe(0);
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
    for (const args of [["--offline", "--base"], ["--base", "-x"], ["--base", "--output=/tmp/x"]]) {
      const bad = spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8" });
      expect(bad.status, args.join(" ")).toBe(2);
      expect(bad.stderr).toMatch(/--base needs a commit/);
    }
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
    expect(verify?.run).toMatch(/node scripts\/verify-status-claims\.mjs[^\n]*2>&1 \| tee /);
  });

  it("on a pull request, compares the list with the base branch's", () => {
    const verify = steps.find((s) => s.id === "verify");
    expect(verify?.env?.BASE_SHA).toBe("${{ github.event.pull_request.base.sha }}");
    expect(verify?.run).toContain('git fetch --quiet --depth=1 origin "$BASE_SHA"');
    expect(verify?.run).toContain('node scripts/verify-status-claims.mjs --base "$BASE_SHA" 2>&1 | tee "$RUNNER_TEMP/status-claims.txt"');
  });

  it("files a failure of the check on main as one tracking issue, and closes it on a green run on main", () => {
    // Exact strings: a looser match let `always() && ...` through in #724's review.
    const open = step(/^Open or update the tracking issue/);
    const close = step(/^Close the tracking issue/);
    expect(open?.if).toBe("failure() && steps.verify.outcome == 'failure' && github.event_name != 'pull_request' && github.ref == 'refs/heads/main'");
    expect(close?.if).toBe("success() && github.event_name != 'pull_request' && github.ref == 'refs/heads/main'");
    expect(open?.run).toContain('gh issue create --title "$title" --body "$body" --label auto-generated');
  });

  it("looks up only its own open issue: open, labelled auto-generated, with its title", () => {
    const lookup = `gh issue list --state open --label auto-generated --search "$title in:title" --json number --jq '.[0].number // empty'`;
    for (const s of [step(/^Open or update the tracking issue/), step(/^Close the tracking issue/)]) {
      expect(s?.run).toContain('title="Status claims no longer match GitHub"');
      expect(s?.run).toContain(lookup);
    }
  });
});

describe.skipIf(!HAS_JQ)("verify-status-claims.yml: failures are filed and closed", () => {
  const open = runBlock(WORKFLOW, "verify", "Open or update the tracking issue");
  const close = runBlock(WORKFLOW, "verify", "Close the tracking issue once every claim matches again");
  const TITLE = "Status claims no longer match GitHub";
  const OURS = { number: 42, title: TITLE, labels: ["auto-generated"], state: "OPEN" };
  // A real open issue on the repository, also labelled auto-generated.
  const UNRELATED = { number: 82, title: "ATR: proposals awaiting human PoC", labels: ["auto-generated"], state: "OPEN" };
  const REPORT = "[FAIL]  https://github.com/o/r/pull/1 — claimed open, observed merged; files: README.md\n";

  /** The checker's report where the workflow tees it, and the open issues gh can find. */
  function env(sb: Sandbox, list: object[] = []): Record<string, string> {
    writeFileSync(join(sb.root, "status-claims.txt"), REPORT);
    const file = join(sb.root, "issues.json");
    writeFileSync(file, JSON.stringify(list));
    return { FAKE_GH_ISSUES: file, GITHUB_EVENT_NAME: "schedule", RUN_URL: "https://example.invalid/run/1" };
  }

  afterEach(cleanSandboxes);

  it("opens one issue carrying the checker's report", () => {
    const sb = sandbox("status-wf-", { "README.md": "x\n" });
    const res = runStep(sb, open, env(sb));
    expect(res.status, res.stderr).toBe(0);
    expect(ghCalls(sb)).toMatch(/issue create --title Status claims no longer match GitHub[\s\S]*claimed open, observed merged[\s\S]*--label auto-generated/);
  });

  it("rewrites the open issue, and never touches another auto-generated one", () => {
    const sb = sandbox("status-wf-", { "README.md": "x\n" });
    expect(runStep(sb, open, env(sb, [UNRELATED, OURS])).status).toBe(0);
    expect(ghCalls(sb)).toMatch(/issue edit 42 /);
    expect(ghCalls(sb)).not.toMatch(/issue (create|edit 82|close)/);
  });

  it("closes its own issue on a green run, and only its own", () => {
    const sb = sandbox("status-wf-", { "README.md": "x\n" });
    expect(runStep(sb, close, env(sb, [UNRELATED, OURS])).status).toBe(0);
    expect(ghCalls(sb)).toMatch(/issue close 42 /);
    expect(ghCalls(sb)).not.toMatch(/issue close 82/);
    const quiet = sandbox("status-wf-", { "README.md": "x\n" });
    expect(runStep(quiet, close, env(quiet, [UNRELATED])).status).toBe(0);
    expect(ghCalls(quiet)).not.toMatch(/issue close/);
  });
});
