/**
 * Tests for scripts/lib/github-link-state.mjs: what GitHub says a pull request
 * or issue is (open, closed or merged), asked with retries and a timeout, and
 * how a failed answer is classified.
 *
 * Nothing here touches the network: GitHub is a fake fetch.
 */
import { describe, it, expect } from "vitest";
// @ts-expect-error -- stdlib-only .mjs module, no type declarations (it runs in
// CI without npm install, so it must not depend on the TypeScript toolchain).
import { classifyLink, linkKey, canonicalUrl, fetchState, failureKind, RETRIES } from "../scripts/lib/github-link-state.mjs";

type Reply = { status: number; body?: unknown; raw?: string } | "network-error";
type Call = { url: string; init: { headers: Record<string, string>; signal?: unknown } };

/** A fetch that answers from a queue of replies per API path; the last reply repeats. */
function fakeGitHub(routes: Record<string, Reply[]>) {
  const calls: Call[] = [];
  const impl = async (url: string, init: Call["init"]) => {
    calls.push({ url, init });
    const queue = routes[url.replace("https://api.github.com", "")];
    if (!queue || queue.length === 0) throw new Error(`unexpected request ${url}`);
    const reply = queue.length > 1 ? queue.shift()! : queue[0];
    if (reply === "network-error") throw new TypeError("fetch failed");
    return {
      ok: reply.status >= 200 && reply.status < 300,
      status: reply.status,
      json: async () => (reply.raw !== undefined ? JSON.parse(reply.raw) : reply.body),
    };
  };
  return { impl, calls };
}

function recorder() {
  const waits: number[] = [];
  return { waits, sleep: async (ms: number) => void waits.push(ms) };
}

const PR = classifyLink("https://github.com/o/r/pull/5");
const ISSUE = classifyLink("https://github.com/o/r/issues/7");

describe("classifyLink", () => {
  it("reads pull requests and issues", () => {
    expect(PR).toEqual({ kind: "pr", owner: "o", repo: "r", number: 5 });
    expect(ISSUE).toEqual({ kind: "issue", owner: "o", repo: "r", number: 7 });
  });

  it("accepts what people paste: a fragment, a query, /files, www. and an upper-case host", () => {
    for (const url of [
      "https://github.com/o/r/pull/5#issuecomment-1",
      "https://github.com/o/r/pull/5?w=1",
      "https://github.com/o/r/pull/5/files",
      "https://www.github.com/o/r/pull/5",
      "https://GitHub.com/o/r/pull/5",
    ]) {
      expect(classifyLink(url), url).toMatchObject({ kind: "pr", number: 5 });
    }
  });

  it("reads a commit URL as a commit", () => {
    expect(classifyLink("https://github.com/o/r/commit/ABCDEF1")).toEqual({ kind: "commit", owner: "o", repo: "r", sha: "abcdef1" });
  });

  it("rejects anything else", () => {
    for (const url of [
      "http://github.com/o/r/pull/5",
      "https://gitlab.com/o/r/pull/5",
      "https://github.com/o/r/pull/five",
      "https://github.com/o/r/discussions/5",
      "https://github.com/o/../pull/5",
      "https://github.com/o",
      "not a url",
    ]) {
      expect(classifyLink(url).kind, url).toBe("other");
    }
  });
});

describe("linkKey and canonicalUrl", () => {
  it("gives a pull request and an issue of the same number one key, ignoring case", () => {
    // Pull requests and issues share one number space, and owner and repository
    // names are case-insensitive, so all four name the same thing.
    const keys = [
      "https://github.com/O/R/pull/5",
      "https://github.com/o/r/issues/5",
      "https://github.com/o/R/pull/5/files",
      "https://www.github.com/o/r/pull/5#top",
    ].map((u) => linkKey(classifyLink(u)));
    expect(new Set(keys)).toEqual(new Set(["o/r#5"]));
  });

  it("writes the plain form of a link", () => {
    expect(canonicalUrl(classifyLink("https://www.github.com/O/R/pull/5/files?w=1#x"))).toBe("https://github.com/O/R/pull/5");
    expect(canonicalUrl(ISSUE)).toBe("https://github.com/o/r/issues/7");
  });
});

describe("fetchState", () => {
  const quick = (extra = {}) => ({ sleep: async () => undefined, ...extra });

  it("reads a pull request from the pulls endpoint: open, closed or merged", async () => {
    for (const [body, want] of [
      [{ state: "open", merged_at: null }, "open"],
      [{ state: "closed", merged_at: null }, "closed"],
      [{ state: "closed", merged_at: "2026-05-11T00:00:00Z" }, "merged"],
    ] as const) {
      const gh = fakeGitHub({ "/repos/o/r/pulls/5": [{ status: 200, body }] });
      expect(await fetchState(PR, quick({ fetchImpl: gh.impl }))).toBe(want);
    }
  });

  it("reads an issue from the issues endpoint", async () => {
    for (const [body, want] of [
      [{ state: "open" }, "open"],
      [{ state: "closed", state_reason: "completed" }, "closed"],
    ] as const) {
      const gh = fakeGitHub({ "/repos/o/r/issues/7": [{ status: 200, body }] });
      expect(await fetchState(ISSUE, quick({ fetchImpl: gh.impl }))).toBe(want);
    }
  });

  it("sees a merged pull request behind an /issues/ link", async () => {
    // github.com/<o>/<r>/issues/N redirects to the pull request when N is one,
    // so pages link PRs that way; the issues endpoint says merged only through
    // pull_request.merged_at.
    const merged = fakeGitHub({ "/repos/o/r/issues/7": [{ status: 200, body: { state: "closed", pull_request: { merged_at: "2026-05-11T00:00:00Z" } } }] });
    expect(await fetchState(ISSUE, quick({ fetchImpl: merged.impl }))).toBe("merged");
    const unmerged = fakeGitHub({ "/repos/o/r/issues/7": [{ status: 200, body: { state: "closed", pull_request: { merged_at: null } } }] });
    expect(await fetchState(ISSUE, quick({ fetchImpl: unmerged.impl }))).toBe("closed");
  });

  it("asks once for a 404, a 410 or a 403, and reports the status", async () => {
    for (const status of [404, 410, 403]) {
      const gh = fakeGitHub({ "/repos/o/r/pulls/5": [{ status }] });
      expect(await fetchState(PR, quick({ fetchImpl: gh.impl }))).toBe(`api-${status}`);
      expect(gh.calls).toHaveLength(1);
    }
  });

  it("retries a rate limit, a server error and a network error, waiting longer each time", async () => {
    const t = recorder();
    const gh = fakeGitHub({ "/repos/o/r/pulls/5": [{ status: 429 }, "network-error", { status: 200, body: { state: "open" } }] });
    expect(await fetchState(PR, { fetchImpl: gh.impl, sleep: t.sleep })).toBe("open");
    expect(gh.calls).toHaveLength(3);
    expect(t.waits).toEqual([1000, 2000]);
  });

  it("gives up after the retries and reports the last error", async () => {
    const t = recorder();
    const gh = fakeGitHub({ "/repos/o/r/pulls/5": [{ status: 502 }] });
    expect(await fetchState(PR, { fetchImpl: gh.impl, sleep: t.sleep })).toBe("api-502");
    expect(gh.calls).toHaveLength(RETRIES + 1);
    const down = fakeGitHub({ "/repos/o/r/pulls/5": ["network-error"] });
    expect(await fetchState(PR, quick({ fetchImpl: down.impl }))).toBe("network-error");
  });

  it("reports a body it cannot read as bad-response, never as a state", async () => {
    for (const reply of [{ status: 200, raw: "<html>" }, { status: 200, body: null }, { status: 200, body: { title: "no state" } }]) {
      const gh = fakeGitHub({ "/repos/o/r/pulls/5": [reply] });
      expect(await fetchState(PR, quick({ fetchImpl: gh.impl })), JSON.stringify(reply)).toBe("bad-response");
    }
  });

  it("sends a timeout signal, a User-Agent, and the token only when there is one", async () => {
    const gh = fakeGitHub({ "/repos/o/r/pulls/5": [{ status: 200, body: { state: "open" } }] });
    await fetchState(PR, quick({ fetchImpl: gh.impl, token: "t0ken" }));
    await fetchState(PR, quick({ fetchImpl: gh.impl, token: "" }));
    const [withToken, without] = gh.calls;
    expect(withToken.init.signal).toBeInstanceOf(AbortSignal);
    expect(withToken.init.headers["User-Agent"]).toBeTruthy();
    expect(withToken.init.headers.Authorization).toBe("Bearer t0ken");
    expect(without.init.headers.Authorization).toBeUndefined();
  });

  it("refuses to ask about something that is not a pull request or an issue", async () => {
    const gh = fakeGitHub({});
    expect(await fetchState(classifyLink("https://github.com/o/r/commit/abcdef1"), quick({ fetchImpl: gh.impl }))).toBe("unverifiable");
    expect(gh.calls).toHaveLength(0);
  });
});

describe("failureKind", () => {
  it("calls a 404 or a 410 gone", () => {
    expect(failureKind("api-404")).toBe("gone");
    expect(failureKind("api-410")).toBe("gone");
  });

  it("calls anything GitHub could not answer unverified, never a pass or drift", () => {
    for (const observed of ["api-401", "api-403", "api-429", "api-500", "network-error", "bad-response", "unverifiable"]) {
      expect(failureKind(observed), observed).toBe("unverified");
    }
  });

  it("calls a real state that differs from the claim drift", () => {
    for (const observed of ["open", "closed", "merged"]) expect(failureKind(observed)).toBe("drift");
  });
});
