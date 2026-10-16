/**
 * Tests for scripts/verify-red-team-links.mjs and the data the /red-team page
 * renders from.
 *
 * WHY THIS EXISTS
 *   The red-team page's lists of integrations and open proposals were written
 *   by hand inside the page. NVIDIA/garak#1676 was withdrawn on 2026-08-04 and
 *   stayed listed as under review for ten weeks; nothing noticed until a
 *   person read every link (#688). The list now lives in
 *   website/data/red-team-tools.json, and CI re-checks every status label
 *   against GitHub the way scripts/verify-adopters.mjs re-checks ADOPTERS.md:
 *     - in-review     -> the linked PR or issue must be OPEN
 *     - in-production -> the linked PR must be MERGED and its stillPresent
 *                        file must still mention ATR upstream
 *     - corpus        -> the linked PR must be MERGED
 *   A failure is drift (fix the list), gone (404/410) or unverified (GitHub
 *   could not be asked). Unverified is never a pass.
 *
 * Nothing here touches the network: GitHub is a fake fetch.
 */
import { describe, it, expect } from "vitest";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import yaml from "js-yaml";
// @ts-expect-error -- stdlib-only .mjs script, deliberately untyped (it runs in
// CI without npm install, so it must not depend on the TypeScript toolchain).
import { classifyLink, verdict, validateTools, verifyTools, failureKind, main } from "../scripts/verify-red-team-links.mjs";

const REPO_ROOT = resolve(__dirname, "..");
const DATA = join(REPO_ROOT, "website", "data", "red-team-tools.json");
const PAGE = join(REPO_ROOT, "website", "app", "[locale]", "red-team", "page.tsx");
const WORKFLOW = join(REPO_ROOT, ".github", "workflows", "verify-red-team-links.yml");
const API = "https://api.github.com/repos";
const NO_WAIT = { sleep: async () => undefined };

type Status = "in-production" | "in-review" | "corpus";
type Reply = { status?: number; body?: unknown; throws?: boolean; badJson?: boolean };

function tool(status: Status, prUrl?: string, name = "Example", extra: Record<string, unknown> = {}) {
  return {
    name,
    org: "Example Org",
    status,
    homepage: "https://example.org",
    ...(prUrl === undefined ? {} : { prUrl }),
    hook: "hook",
    what_atr_did: "what ATR did",
    ...extra,
  };
}

/** A fetch stand-in answering GitHub API URLs from a table; a list answers successive calls. */
function fakeFetch(table: Record<string, Reply | Reply[]>) {
  const calls: string[] = [];
  const inits: { signal?: unknown }[] = [];
  const seen = new Map<string, number>();
  const impl = async (url: string, init: { signal?: unknown } = {}) => {
    calls.push(url);
    inits.push(init);
    const entry = table[url];
    const n = seen.get(url) ?? 0;
    seen.set(url, n + 1);
    const reply: Reply = Array.isArray(entry) ? entry[Math.min(n, entry.length - 1)] : (entry ?? { status: 404 });
    if (reply.throws) throw new TypeError("fetch failed");
    const status = reply.status ?? 200;
    return {
      ok: status < 400,
      status,
      json: async () => {
        if (reply.badJson) throw new SyntaxError("Unexpected token <");
        return "body" in reply ? reply.body : {};
      },
    };
  };
  return { impl, calls, inits };
}

const base64 = (s: string) => Buffer.from(s, "utf8").toString("base64");
const file = (text: string) => ({ body: { type: "file", encoding: "base64", content: base64(text) } });
const PYRIT_SPEC = 'pyrit/loader.py contains "Agent-Threat-Rule/agent-threat-rules"';
const pyrit = tool("in-production", "https://github.com/microsoft/PyRIT/pull/1715", "PyRIT", { stillPresent: PYRIT_SPEC });
const review = tool("in-review", "https://github.com/QData/TextAttack/issues/824", "TextAttack");
const closedProposal = tool("in-review", "https://github.com/NVIDIA/garak/pull/1676", "garak");
const MERGED = { body: { state: "closed", merged_at: "2026-05-27T13:10:48Z" } };

describe("classifyLink", () => {
  it("recognises a pull request and an issue", () => {
    expect(classifyLink("https://github.com/promptfoo/promptfoo/pull/8529")).toEqual({
      kind: "pr", owner: "promptfoo", repo: "promptfoo", number: 8529,
    });
    expect(classifyLink("https://github.com/QData/TextAttack/issues/824")).toEqual({
      kind: "issue", owner: "QData", repo: "TextAttack", number: 824,
    });
  });

  it("accepts the forms people paste", () => {
    for (const url of [
      "https://github.com/promptfoo/promptfoo/pull/8529/",
      "https://github.com/promptfoo/promptfoo/pull/8529/files",
      "https://github.com/promptfoo/promptfoo/pull/8529?notification_referrer_id=x",
      "https://github.com/promptfoo/promptfoo/pull/8529#issuecomment-1",
      "https://GitHub.com/promptfoo/promptfoo/pull/8529",
      "https://www.github.com/promptfoo/promptfoo/pull/8529",
    ]) {
      expect(classifyLink(url)).toEqual({ kind: "pr", owner: "promptfoo", repo: "promptfoo", number: 8529 });
    }
  });

  it("calls anything else unverifiable", () => {
    for (const url of [
      "https://hackaprompt.com",
      "https://github.com/NVIDIA/garak",
      "http://github.com/a/b/pull/1",
      "https://github.com/../x/pull/1",
      "https://github.com/o/r%3F/pull/1",
      "https://gist.github.com/a/b/pull/1",
      "not a url",
    ]) {
      expect(classifyLink(url).kind).toBe("other");
    }
  });
});

describe("verdict", () => {
  it("in-review needs an open PR or an open issue", () => {
    expect(verdict("in-review", "pr", "open")).toBe(true);
    expect(verdict("in-review", "issue", "open")).toBe(true);
    expect(verdict("in-review", "pr", "closed")).toBe(false);
    expect(verdict("in-review", "issue", "closed")).toBe(false);
  });

  it("a merged PR is no longer under review", () => {
    expect(verdict("in-review", "pr", "merged")).toBe(false);
  });

  it("in-production and corpus need a merged PR", () => {
    expect(verdict("in-production", "pr", "merged")).toBe(true);
    expect(verdict("corpus", "pr", "merged")).toBe(true);
    expect(verdict("in-production", "pr", "open")).toBe(false);
    expect(verdict("corpus", "pr", "closed")).toBe(false);
    expect(verdict("in-production", "issue", "open")).toBe(false);
  });

  it("an API error or an unverifiable link is never ok", () => {
    expect(verdict("in-review", "pr", "api-403")).toBe(false);
    expect(verdict("in-production", "pr", "network-error")).toBe(false);
    expect(verdict("in-review", "other", "open")).toBe(false);
  });
});

describe("validateTools", () => {
  it("accepts well-formed entries", () => {
    expect(validateTools([review, pyrit, tool("corpus", "https://github.com/Agent-Threat-Rule/agent-threat-rules/pull/51", "HackAPrompt")])).toEqual([]);
  });

  it("rejects an empty list: a checker that checks nothing must not pass", () => {
    expect(validateTools([]).join("\n")).toMatch(/empty/);
  });

  it("rejects an unknown status and an unknown field", () => {
    expect(validateTools([{ ...review, status: "under-review" }]).join("\n")).toMatch(/status/);
    const { prUrl, ...rest } = review;
    expect(validateTools([{ ...rest, prURL: prUrl }]).join("\n")).toMatch(/unknown field "prURL"/);
  });

  it("rejects any entry with nothing CI can check", () => {
    for (const status of ["in-review", "in-production", "corpus"] as const) {
      expect(validateTools([tool(status, undefined, "X", { stillPresent: PYRIT_SPEC })]).join("\n")).toMatch(/prUrl/);
    }
  });

  it("needs a pull request behind in-production and corpus", () => {
    const issueBacked = tool("in-production", "https://github.com/a/b/issues/3", "X", { stillPresent: PYRIT_SPEC });
    expect(validateTools([issueBacked]).join("\n")).toMatch(/pull request/);
    expect(validateTools([tool("corpus", "https://hackaprompt.com", "Y")]).join("\n")).toMatch(/pull request/);
  });

  it("needs a well-formed stillPresent on in-production", () => {
    const merged = tool("in-production", "https://github.com/a/b/pull/2", "X");
    expect(validateTools([merged]).join("\n")).toMatch(/stillPresent/);
    expect(validateTools([{ ...merged, stillPresent: "loader.py has ATR" }]).join("\n")).toMatch(/stillPresent/);
    for (const path of ["../../orgs/x", "/abs/path.py", "a//b.py", "a/./b.py"]) {
      expect(validateTools([{ ...merged, stillPresent: `${path} contains "ATR"` }]).join("\n")).toMatch(/stillPresent/);
    }
  });

  it("rejects a missing required field and duplicate names", () => {
    const { hook: _hook, ...noHook } = review;
    expect(validateTools([noHook]).join("\n")).toMatch(/hook/);
    expect(validateTools([review, { ...review }]).join("\n")).toMatch(/duplicate/);
  });
});

describe("the committed data", () => {
  const tools = JSON.parse(readFileSync(DATA, "utf8"));

  it("is valid", () => {
    expect(validateTools(tools)).toEqual([]);
  });

  it("is what the page renders: no PR or issue link is written inline in the page", () => {
    const page = readFileSync(PAGE, "utf8");
    expect(page).toMatch(/from "@\/lib\/red-team-tools"/);
    expect(page).not.toMatch(/github\.com\/[^/\s"'`]+\/[^/\s"'`]+\/(pull|issues)\/\d+/);
  });
});

describe("verifyTools", () => {
  it("passes open proposals and merged integrations whose upstream file still mentions ATR", async () => {
    const { impl } = fakeFetch({
      [`${API}/QData/TextAttack/issues/824`]: { body: { state: "open" } },
      [`${API}/microsoft/PyRIT/pulls/1715`]: MERGED,
      [`${API}/microsoft/PyRIT/contents/pyrit/loader.py`]: file("url = 'https://github.com/Agent-Threat-Rule/agent-threat-rules'"),
    });
    const results = await verifyTools([review, pyrit], impl, NO_WAIT);
    expect(results.map((r: { ok: boolean }) => r.ok)).toEqual([true, true]);
    expect(results[1]).toMatchObject({ observed: "merged", content: "present" });
  });

  it("flags a merged integration whose upstream file dropped ATR (a revert)", async () => {
    const { impl } = fakeFetch({
      [`${API}/microsoft/PyRIT/pulls/1715`]: MERGED,
      [`${API}/microsoft/PyRIT/contents/pyrit/loader.py`]: file("nothing here"),
    });
    const [result] = await verifyTools([pyrit], impl, NO_WAIT);
    expect(result).toMatchObject({ content: "absent", ok: false });
    expect(failureKind(result)).toBe("drift");
  });

  it("calls a removed upstream file gone", async () => {
    const { impl } = fakeFetch({ [`${API}/microsoft/PyRIT/pulls/1715`]: MERGED });
    const [result] = await verifyTools([pyrit], impl, NO_WAIT);
    expect(result).toMatchObject({ content: "gone", ok: false });
    expect(failureKind(result)).toBe("gone");
  });

  it("calls a removed or vanished upstream file gone, including a 410", async () => {
    for (const reply of [{ status: 404 }, { status: 410 }] as Reply[]) {
      const { impl } = fakeFetch({ [`${API}/microsoft/PyRIT/pulls/1715`]: MERGED, [`${API}/microsoft/PyRIT/contents/pyrit/loader.py`]: reply });
      const [result] = await verifyTools([pyrit], impl, NO_WAIT);
      expect(result).toMatchObject({ content: "gone", ok: false });
      expect(failureKind(result)).toBe("gone");
    }
  });

  it("does not read a directory or an unreadable file as present", async () => {
    const dir = fakeFetch({ [`${API}/microsoft/PyRIT/pulls/1715`]: MERGED, [`${API}/microsoft/PyRIT/contents/pyrit/loader.py`]: { body: [{ name: "a.py" }] } });
    const [asDir] = await verifyTools([pyrit], dir.impl, NO_WAIT);
    expect(asDir).toMatchObject({ content: "not-a-file", ok: false });
    expect(failureKind(asDir)).toBe("drift");
    // GitHub serves files over 1 MB with an empty content and encoding "none".
    const big = fakeFetch({ [`${API}/microsoft/PyRIT/pulls/1715`]: MERGED, [`${API}/microsoft/PyRIT/contents/pyrit/loader.py`]: { body: { type: "file", encoding: "none", content: "" } } });
    const [tooBig] = await verifyTools([pyrit], big.impl, NO_WAIT);
    expect(tooBig).toMatchObject({ content: "bad-response", ok: false });
    expect(failureKind(tooBig)).toBe("unverified");
  });

  it("never passes an in-production entry on its PR state alone", async () => {
    const { stillPresent: _spec, ...unasserted } = pyrit;
    const { impl } = fakeFetch({ [`${API}/microsoft/PyRIT/pulls/1715`]: MERGED });
    const [result] = await verifyTools([unasserted], impl, NO_WAIT);
    expect(result).toMatchObject({ content: "no-assertion", ok: false });
  });

  it("flags a proposal that was closed without merging", async () => {
    const { impl } = fakeFetch({ [`${API}/NVIDIA/garak/pulls/1676`]: { body: { state: "closed", merged_at: null } } });
    const [result] = await verifyTools([closedProposal], impl, NO_WAIT);
    expect(result).toMatchObject({ name: "garak", declared: "in-review", observed: "closed", ok: false });
    expect(failureKind(result)).toBe("drift");
  });

  it("calls a 404 or 410 gone, not unverified", async () => {
    for (const status of [404, 410]) {
      const { impl } = fakeFetch({ [`${API}/NVIDIA/garak/pulls/1676`]: { status } });
      const [result] = await verifyTools([closedProposal], impl, NO_WAIT);
      expect(result).toMatchObject({ observed: `api-${status}`, ok: false });
      expect(failureKind(result)).toBe("gone");
    }
  });

  it("treats rate limits, thrown fetches and unreadable bodies as unverified, never as a pass", async () => {
    for (const reply of [{ status: 401 }, { status: 403 }, { status: 429 }, { status: 502 }, { throws: true }, { badJson: true }, { body: null }, { body: [] }, { body: "x" }] as Reply[]) {
      const { impl } = fakeFetch({ [`${API}/QData/TextAttack/issues/824`]: reply });
      const [result] = await verifyTools([review], impl, NO_WAIT);
      expect(result.ok).toBe(false);
      expect(failureKind(result)).toBe("unverified");
    }
  });

  it("retries a transient failure and passes when GitHub recovers", async () => {
    const { impl, calls } = fakeFetch({
      [`${API}/QData/TextAttack/issues/824`]: [{ status: 502 }, { throws: true }, { body: { state: "open" } }],
    });
    const [result] = await verifyTools([review], impl, NO_WAIT);
    expect(result).toMatchObject({ observed: "open", ok: true });
    expect(calls).toHaveLength(3);
  });

  it("retries a rate limit, and waits between attempts", async () => {
    const waits: number[] = [];
    const { impl, calls } = fakeFetch({ [`${API}/QData/TextAttack/issues/824`]: [{ status: 429 }, { body: { state: "open" } }] });
    const [result] = await verifyTools([review], impl, { sleep: async (ms: number) => { waits.push(ms); } });
    expect(result).toMatchObject({ observed: "open", ok: true });
    expect(calls).toHaveLength(2);
    expect(waits).toHaveLength(1);
    expect(waits[0]).toBeGreaterThan(0);
  });

  it("gives every request a timeout", async () => {
    const { impl, inits } = fakeFetch({ [`${API}/QData/TextAttack/issues/824`]: { body: { state: "open" } } });
    await verifyTools([review], impl, NO_WAIT);
    expect(inits[0].signal).toBeInstanceOf(AbortSignal);
  });

  it("does not retry a 404", async () => {
    const { impl, calls } = fakeFetch({});
    await verifyTools([review], impl, NO_WAIT);
    expect(calls).toEqual([`${API}/QData/TextAttack/issues/824`]);
  });

  it("asks the pulls endpoint for a PR and the issues endpoint for an issue", async () => {
    const { impl, calls } = fakeFetch({});
    await verifyTools([review, closedProposal], impl, NO_WAIT);
    expect(calls).toEqual([`${API}/QData/TextAttack/issues/824`, `${API}/NVIDIA/garak/pulls/1676`]);
  });

  it("fails an entry with no link instead of passing it unchecked", async () => {
    const { impl, calls } = fakeFetch({});
    const [result] = await verifyTools([tool("corpus")], impl, NO_WAIT);
    expect(calls).toEqual([]);
    expect(result).toMatchObject({ kind: "none", ok: false });
  });
});

describe("main", () => {
  function dataFile(content: unknown): string {
    const dir = mkdtempSync(join(tmpdir(), "red-team-links-"));
    const path = join(dir, "red-team-tools.json");
    writeFileSync(path, typeof content === "string" ? content : JSON.stringify(content));
    return path;
  }
  const quiet = async (fn: () => Promise<number>) => {
    const log = console.log;
    const error = console.error;
    console.log = () => undefined;
    console.error = () => undefined;
    try {
      return await fn();
    } finally {
      console.log = log;
      console.error = error;
    }
  };

  it("exits 0 when every entry matches", async () => {
    const { impl } = fakeFetch({ [`${API}/QData/TextAttack/issues/824`]: { body: { state: "open" } } });
    expect(await quiet(() => main({ dataPath: dataFile([review]), fetchImpl: impl, ...NO_WAIT }))).toBe(0);
  });

  it("exits 1 on drift, on unverified lookups, on a malformed list and on an unreadable file", async () => {
    const closed = fakeFetch({ [`${API}/NVIDIA/garak/pulls/1676`]: { body: { state: "closed" } } }).impl;
    const limited = fakeFetch({ [`${API}/QData/TextAttack/issues/824`]: { status: 403 } }).impl;
    expect(await quiet(() => main({ dataPath: dataFile([closedProposal]), fetchImpl: closed, ...NO_WAIT }))).toBe(1);
    expect(await quiet(() => main({ dataPath: dataFile([review]), fetchImpl: limited, ...NO_WAIT }))).toBe(1);
    expect(await quiet(() => main({ dataPath: dataFile([]), fetchImpl: limited, ...NO_WAIT }))).toBe(1);
    expect(await quiet(() => main({ dataPath: dataFile("{not json"), fetchImpl: limited, ...NO_WAIT }))).toBe(1);
    expect(await quiet(() => main({ dataPath: join(tmpdir(), "no-such-red-team-file.json"), fetchImpl: limited, ...NO_WAIT }))).toBe(1);
  });

  it("runs when node is pointed at the file directly or through a symlink, and fails on an empty list", () => {
    const root = mkdtempSync(join(tmpdir(), "red-team-invoke-"));
    mkdirSync(join(root, "scripts"));
    mkdirSync(join(root, "website", "data"), { recursive: true });
    copyFileSync(join(REPO_ROOT, "scripts", "verify-red-team-links.mjs"), join(root, "scripts", "verify-red-team-links.mjs"));
    writeFileSync(join(root, "website", "data", "red-team-tools.json"), "[]\n");
    symlinkSync(join(root, "scripts", "verify-red-team-links.mjs"), join(root, "alias.mjs"));
    for (const target of [join(root, "scripts", "verify-red-team-links.mjs"), join(root, "alias.mjs")]) {
      const run = spawnSync(process.execPath, [target], { encoding: "utf8", env: { ...process.env, GITHUB_TOKEN: "" } });
      expect(run.status).toBe(1);
      expect(run.stderr).toMatch(/list is empty/);
    }
  });
});

describe(".github/workflows/verify-red-team-links.yml", () => {
  const doc = yaml.load(readFileSync(WORKFLOW, "utf8")) as Record<string, any>;
  const on = doc.on ?? doc[true as unknown as string];
  const job = doc.jobs.verify as { "timeout-minutes"?: number; steps: { uses?: string; with?: Record<string, unknown>; run?: string; if?: string; env?: Record<string, string> }[] };

  it("runs on pull requests and pushes that touch the list or the checker, and weekly", () => {
    for (const trigger of ["pull_request", "push"]) {
      expect(on[trigger].paths).toEqual(
        expect.arrayContaining(["website/data/red-team-tools.json", "scripts/verify-red-team-links.mjs"]),
      );
    }
    expect(on.schedule?.[0]?.cron).toBeTruthy();
  });

  it("runs the checker with a token, without npm install, with a time limit", () => {
    const check = job.steps.find((s) => s.run?.includes("node scripts/verify-red-team-links.mjs"));
    expect(check?.env?.GITHUB_TOKEN).toMatch(/secrets\.GITHUB_TOKEN/);
    expect(job.steps.some((s) => /npm (ci|install)/.test(s.run ?? ""))).toBe(false);
    expect(job["timeout-minutes"]).toBeGreaterThan(0);
    expect(job.steps.find((s) => s.uses?.startsWith("actions/checkout"))?.with?.["persist-credentials"]).toBe(false);
  });

  it("does not let tee hide the checker's exit code", () => {
    const check = job.steps.find((s) => s.run?.includes("node scripts/verify-red-team-links.mjs")) as { id?: string; shell?: string; run?: string };
    expect(check.id).toBe("verify");
    expect(check.shell).toBe("bash");
    expect(check.run).toMatch(/set -o pipefail/);
  });

  it("files an issue for a failure on main outside pull requests, and closes it when green", () => {
    const open = job.steps.find((s) => s.run?.includes("gh issue create"));
    const close = job.steps.find((s) => s.run?.includes("gh issue close"));
    expect(open?.if).toMatch(/failure\(\)/);
    expect(open?.if).toMatch(/steps\.verify\.outcome == 'failure'/);
    expect(close?.if).toMatch(/success\(\)/);
    for (const step of [open, close]) {
      expect(step?.if).toMatch(/github\.event_name != 'pull_request'/);
      expect(step?.if).toMatch(/github\.ref == 'refs\/heads\/main'/);
      expect(step?.run).toMatch(/gh issue list[^\n]*--label auto-generated/);
    }
  });
});
