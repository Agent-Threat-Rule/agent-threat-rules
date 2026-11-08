/**
 * Tests for scripts/verify-adopters.mjs, which re-checks every ADOPTERS.md
 * evidence link against GitHub and writes data/adopters-verification.json.
 *
 * It used to call fetch with no retry, no timeout and no try/catch: a rate
 * limit or a 5xx was recorded as drift ("observed api-403"), and a network
 * error crashed the run. Since PR #724 a failure on main opens a tracking
 * issue titled "ADOPTERS.md evidence no longer matches GitHub", so an API
 * problem filed a misleading drift issue. GitHub is now asked through
 * scripts/lib/github-link-state.mjs, every failure is drift, gone or
 * unverified, and a run with an unverified entry writes nothing: an API
 * problem must not change what the website publishes.
 *
 * Nothing here touches the network: GitHub is a fake fetch.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
// @ts-expect-error -- stdlib-only .mjs script, no type declarations (it runs in
// CI without npm install, so it must not depend on the TypeScript toolchain).
import { evidenceUrls, main, parseAdopters, verifyAdopters } from "../scripts/verify-adopters.mjs";

type Reply = { status: number; body?: unknown } | "network-error";

/** GitHub's API by path, and any other URL by its full text; a list replies in turn, the last repeating. */
function fakeWeb(routes: Record<string, Reply | Reply[]>) {
  const asked: string[] = [];
  const impl = async (url: string) => {
    const key = url.startsWith("https://api.github.com") ? url.slice("https://api.github.com".length) : url;
    asked.push(key);
    const route = routes[key];
    if (route === undefined) throw new Error(`unexpected request ${url}`);
    const queue = Array.isArray(route) ? route : [route];
    const reply = queue.length > 1 ? queue.shift()! : queue[0];
    if (reply === "network-error") throw new TypeError("fetch failed");
    return { ok: reply.status < 300, status: reply.status, json: async () => reply.body };
  };
  return { impl, asked };
}

const NO_WAIT = { sleep: async () => undefined, token: "" };
const merged = { status: 200, body: { state: "closed", merged_at: "2026-05-10T00:00:00Z" } };
const open = { status: 200, body: { state: "open", merged_at: null } };
const closed = { status: 200, body: { state: "closed", merged_at: null } };
const file = (text: string) => ({ status: 200, body: { type: "file", encoding: "base64", content: Buffer.from(text).toString("base64") } });

function adopters(...blocks: string[]): string {
  return ["# ADOPTERS", "## Schema", "### Project Name", "- **Evidence**: <https://github.com/x/template/pull/1>", "## Tier 1 — Production", ...blocks, "## Removed entries", "### Gone", "- **Evidence**: <https://github.com/x/removed/pull/2>"].join("\n");
}
const entry = (name: string, evidence: string, extra: string[] = []) => [`### ${name}`, `- **Evidence**: ${evidence}`, ...extra].join("\n");

afterEach(() => vi.restoreAllMocks());

describe("evidenceUrls", () => {
  it("takes every link in the field, in order, once", () => {
    expect(evidenceUrls("<https://github.com/a/b/pull/1> and <https://github.com/c/d/pull/2>")).toEqual([
      "https://github.com/a/b/pull/1",
      "https://github.com/c/d/pull/2",
    ]);
    expect(evidenceUrls("[merged PR](https://github.com/a/b/pull/1), see https://example.com/x.")).toEqual(["https://github.com/a/b/pull/1", "https://example.com/x"]);
    expect(evidenceUrls("<https://github.com/a/b/pull/1> (also https://github.com/a/b/pull/1)")).toEqual(["https://github.com/a/b/pull/1"]);
  });
});

describe("parseAdopters", () => {
  it("reads the entries under the tiers only, with every evidence link", () => {
    const parsed = parseAdopters(adopters(entry("MISP", "<https://github.com/MISP/misp-taxonomies/pull/323> and <https://github.com/MISP/misp-galaxy/pull/1207>", ["- **Status**: shipped"])));
    expect(parsed).toEqual([
      {
        name: "MISP",
        tier: "1",
        evidence: "https://github.com/MISP/misp-taxonomies/pull/323",
        evidenceUrls: ["https://github.com/MISP/misp-taxonomies/pull/323", "https://github.com/MISP/misp-galaxy/pull/1207"],
        status: "shipped",
        stillPresent: undefined,
      },
    ]);
  });
});

describe("verifyAdopters", () => {
  async function one(text: string, routes: Record<string, Reply | Reply[]>) {
    const web = fakeWeb(routes);
    const [result] = await verifyAdopters(parseAdopters(adopters(text)), { fetchImpl: web.impl, ...NO_WAIT });
    return { result, asked: web.asked };
  }

  it("holds shipped to merged and in-review to open", async () => {
    const shipped = entry("A", "<https://github.com/o/a/pull/1>");
    expect((await one(shipped, { "/repos/o/a/pulls/1": merged })).result).toMatchObject({ ok: true, failure: null, declared: "shipped", kind: "pr", observed: "merged" });
    expect((await one(shipped, { "/repos/o/a/pulls/1": open })).result).toMatchObject({ ok: false, failure: "drift", observed: "open" });
    const review = entry("B", "<https://github.com/o/b/pull/2>", ["- **Status**: in-review"]);
    expect((await one(review, { "/repos/o/b/pulls/2": open })).result).toMatchObject({ ok: true, failure: null });
    expect((await one(review, { "/repos/o/b/pulls/2": merged })).result).toMatchObject({ ok: false, failure: "drift" });
  });

  it("holds an issue to open, whatever the status", async () => {
    const text = entry("C", "<https://github.com/o/c/issues/3>");
    expect((await one(text, { "/repos/o/c/issues/3": open })).result).toMatchObject({ ok: true, kind: "issue" });
    expect((await one(text, { "/repos/o/c/issues/3": closed })).result).toMatchObject({ ok: false, failure: "drift" });
  });

  it("calls a 404 gone, and an API problem unverified, never drift", async () => {
    const text = entry("D", "<https://github.com/o/d/pull/4>");
    expect((await one(text, { "/repos/o/d/pulls/4": { status: 404 } })).result).toMatchObject({ ok: false, failure: "gone", observed: "api-404" });
    expect((await one(text, { "/repos/o/d/pulls/4": { status: 403 } })).result).toMatchObject({ ok: false, failure: "unverified" });
    expect((await one(text, { "/repos/o/d/pulls/4": { status: 502 } })).result).toMatchObject({ ok: false, failure: "unverified", observed: "api-502" });
    // A network error used to crash the run; now it is an answer like any other.
    expect((await one(text, { "/repos/o/d/pulls/4": "network-error" })).result).toMatchObject({ ok: false, failure: "unverified", observed: "network-error" });
  });

  it("retries a rate limit before answering", async () => {
    const { result, asked } = await one(entry("E", "<https://github.com/o/e/pull/5>"), { "/repos/o/e/pulls/5": [{ status: 429 }, merged] });
    expect(result).toMatchObject({ ok: true });
    expect(asked).toEqual(["/repos/o/e/pulls/5", "/repos/o/e/pulls/5"]);
  });

  it("checks every evidence link of an entry (MISP gives two)", async () => {
    const text = entry("MISP", "<https://github.com/MISP/misp-taxonomies/pull/323> and <https://github.com/MISP/misp-galaxy/pull/1207>");
    const both = await one(text, { "/repos/MISP/misp-taxonomies/pulls/323": merged, "/repos/MISP/misp-galaxy/pulls/1207": merged });
    expect(both.result).toMatchObject({ ok: true, failure: null });
    expect(both.result.checks).toHaveLength(2);
    const second = await one(text, { "/repos/MISP/misp-taxonomies/pulls/323": merged, "/repos/MISP/misp-galaxy/pulls/1207": closed });
    expect(second.result).toMatchObject({ ok: false, failure: "drift", observed: "closed", evidence: "https://github.com/MISP/misp-taxonomies/pull/323" });
  });

  it("reports a definite finding before an unanswered one", async () => {
    const text = entry("F", "<https://github.com/o/f/pull/6> and <https://github.com/o/g/pull/7>");
    const { result } = await one(text, { "/repos/o/f/pulls/6": { status: 500 }, "/repos/o/g/pulls/7": open });
    expect(result).toMatchObject({ ok: false, failure: "drift" });
  });

  it("asserts a still-present file, and tells a missing file from an unanswered request", async () => {
    const text = entry("G", "<https://github.com/o/h/pull/8>", ['- **Still-present**: README.md contains "Agent Threat Rules"']);
    const pr = { "/repos/o/h/pulls/8": merged };
    expect((await one(text, { ...pr, "/repos/o/h/contents/README.md": file("uses Agent Threat Rules") })).result).toMatchObject({ ok: true, content: "present" });
    expect((await one(text, { ...pr, "/repos/o/h/contents/README.md": file("nothing") })).result).toMatchObject({ ok: false, failure: "drift", content: "absent" });
    expect((await one(text, { ...pr, "/repos/o/h/contents/README.md": { status: 404 } })).result).toMatchObject({ ok: false, failure: "drift", content: "path-missing" });
    expect((await one(text, { ...pr, "/repos/o/h/contents/README.md": { status: 500 } })).result).toMatchObject({ ok: false, failure: "unverified", content: "api-500" });
  });

  it("checks a link that is not a pull request or an issue by fetching it", async () => {
    const url = "https://example.org/adopters/atr";
    const text = entry("H", `<${url}>`);
    expect((await one(text, { [url]: { status: 200 } })).result).toMatchObject({ ok: true, kind: "link", observed: "reachable" });
    expect((await one(text, { [url]: { status: 404 } })).result).toMatchObject({ ok: false, failure: "gone", observed: "http-404" });
    expect((await one(text, { [url]: { status: 503 } })).result).toMatchObject({ ok: false, failure: "unverified" });
    expect((await one(text, { [url]: { status: 403 } })).result).toMatchObject({ ok: false, failure: "unverified" });
    expect((await one(text, { [url]: "network-error" })).result).toMatchObject({ ok: false, failure: "unverified" });
  });
});

describe("main", () => {
  function setup(text: string) {
    const dir = mkdtempSync(join(tmpdir(), "verify-adopters-"));
    const adoptersPath = join(dir, "ADOPTERS.md");
    const outPath = join(dir, "adopters-verification.json");
    writeFileSync(adoptersPath, adopters(text));
    return { adoptersPath, outPath };
  }
  const quiet = () => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(console, "error").mockImplementation(() => undefined);
  };

  it("writes the fields the website reads, and exits 0 when every entry checks out", async () => {
    quiet();
    const paths = setup(entry("A", "<https://github.com/o/a/pull/1>"));
    const web = fakeWeb({ "/repos/o/a/pulls/1": merged });
    expect(await main({ ...paths, fetchImpl: web.impl, ...NO_WAIT, today: "2026-11-08" })).toBe(0);
    const out = JSON.parse(readFileSync(paths.outPath, "utf8"));
    expect(out).toMatchObject({ verified_at: "2026-11-08", total: 1, ok: 1, drift: [] });
    expect(out.results[0]).toMatchObject({ name: "A", ok: true });
  });

  it("writes drift as data and exits 0, so the honest state is published", async () => {
    quiet();
    const paths = setup(entry("A", "<https://github.com/o/a/pull/1>"));
    const web = fakeWeb({ "/repos/o/a/pulls/1": { status: 404 } });
    expect(await main({ ...paths, fetchImpl: web.impl, ...NO_WAIT, today: "2026-11-08" })).toBe(0);
    const out = JSON.parse(readFileSync(paths.outPath, "utf8"));
    expect(out.drift).toEqual([{ name: "A", declared: "shipped", observed: "api-404", content: null, evidence: "https://github.com/o/a/pull/1", failure: "gone" }]);
  });

  it("writes nothing and exits 1 when GitHub could not be asked about an entry", async () => {
    quiet();
    const paths = setup([entry("A", "<https://github.com/o/a/pull/1>"), entry("B", "<https://github.com/o/b/pull/2>")].join("\n"));
    writeFileSync(paths.outPath, "previous");
    const web = fakeWeb({ "/repos/o/a/pulls/1": merged, "/repos/o/b/pulls/2": "network-error" });
    expect(await main({ ...paths, fetchImpl: web.impl, ...NO_WAIT, today: "2026-11-08" })).toBe(1);
    expect(readFileSync(paths.outPath, "utf8")).toBe("previous");
  });

  it("exits 1 without writing when ADOPTERS.md cannot be read", async () => {
    quiet();
    const dir = mkdtempSync(join(tmpdir(), "verify-adopters-"));
    const outPath = join(dir, "out.json");
    expect(await main({ adoptersPath: join(dir, "missing.md"), outPath, fetchImpl: fakeWeb({}).impl, ...NO_WAIT })).toBe(1);
    expect(existsSync(outPath)).toBe(false);
  });
});
