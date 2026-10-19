/**
 * Tests for website/data/status-claims.json and scripts/lib/status-claims.mjs.
 *
 * WHY THIS EXISTS
 *   The site, README.md, DEPLOYMENTS.md and STANDARDIZATION-STATUS.md state
 *   the current state of pull requests and issues in other repositories, by
 *   hand. Nothing checked those statements: the three /threats actor pages
 *   showed NousResearch/hermes-agent#9809 as OPEN for six months after it was
 *   closed on 2026-04-15. status-claims.json now records every such link with
 *   the state the pages assert and the files that assert it;
 *   scripts/verify-status-claims.mjs checks each state against GitHub weekly.
 *   These tests hold the files and the list to each other, with no network:
 *     - every listed file still mentions its link (or one of its refs);
 *     - every pull request or issue the pages link or name as owner/repo#N is
 *       listed for that file, unless it is merged ADOPTERS.md evidence, which
 *       scripts/verify-adopters.mjs already checks;
 *     - every page that mentions a listed claim by one of its refs is listed;
 *     - README's "Under maintainer review" section lists only open claims;
 *     - the actor pages' report statuses are the states on the list.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  OPEN_ONLY_SECTIONS,
  REGISTRY_PATH,
  adoptersShippedKeys,
  fileProblems,
  listScopedFiles,
  scanKeys,
  sectionText,
  validateRegistry,
  // @ts-expect-error -- stdlib-only .mjs module, no type declarations (the
  // workflow runs it without npm install).
} from "../scripts/lib/status-claims.mjs";
// @ts-expect-error -- stdlib-only .mjs module, no type declarations.
import { classifyLink, linkKey } from "../scripts/lib/github-link-state.mjs";
import { ACTORS, type ThreatActor } from "../website/lib/actors";

const REPO_ROOT = resolve(__dirname, "..");

type Claim = { url: string; state: string; files: string[]; refs?: string[] };
type Registry = { claims: Claim[] };

const claim = (url: string, state: string, files: string[], refs?: string[]): Claim =>
  refs === undefined ? { url, state, files } : { url, state, files, refs };

/** A repository in memory: `scoped` are the files the checks scan. */
function repo(texts: Record<string, string>, opts: { scoped?: string[]; adopters?: string; sections?: unknown[] } = {}) {
  return {
    files: opts.scoped ?? Object.keys(texts),
    read: (path: string) => (path in texts ? texts[path] : null),
    adoptersText: opts.adopters ?? "",
    openOnlySections: opts.sections ?? [],
  };
}

describe("validateRegistry", () => {
  const ok = { claims: [claim("https://github.com/o/r/pull/1", "open", ["README.md"])] };

  it("accepts a well-formed list, with or without a comment and refs", () => {
    expect(validateRegistry(ok)).toEqual([]);
    expect(validateRegistry({ $comment: "why", claims: [claim("https://github.com/o/r/issues/2", "closed", ["a.md", "b.md"], ["PR #2", "(#2)"])] })).toEqual([]);
  });

  it("rejects a list that is not an object with a non-empty claims array", () => {
    for (const doc of [null, [], "x", {}, { claims: {} }, { claims: [] }]) {
      expect(validateRegistry(doc).length, JSON.stringify(doc)).toBeGreaterThan(0);
    }
  });

  it("rejects unknown fields, so a typo cannot drop a claim silently", () => {
    expect(validateRegistry({ ...ok, claim: [] })).toEqual([expect.stringMatching(/unknown top-level field "claim"/)]);
    const typo = { claims: [{ ...ok.claims[0], status: "open" }] };
    expect(validateRegistry(typo)).toEqual([expect.stringMatching(/unknown field "status"/)]);
  });

  it("rejects a missing or unknown state", () => {
    const { state: _drop, ...noState } = ok.claims[0];
    expect(validateRegistry({ claims: [noState] })).toEqual([expect.stringMatching(/state/)]);
    expect(validateRegistry({ claims: [{ ...ok.claims[0], state: "in-review" }] })).toEqual([
      expect.stringMatching(/unknown state "in-review".*open, closed, merged/),
    ]);
  });

  it("rejects a link that is not a GitHub pull request or issue", () => {
    for (const url of ["https://github.com/o/r/commit/abcdef1", "https://gitlab.com/o/r/pull/1", "https://github.com/o/r", 42]) {
      expect(validateRegistry({ claims: [{ ...ok.claims[0], url }] }), String(url)).toEqual([expect.stringMatching(/pull request or issue/)]);
    }
  });

  it("asks for the plain form of a link, so the list reads the same everywhere", () => {
    expect(validateRegistry({ claims: [{ ...ok.claims[0], url: "https://github.com/o/r/pull/1/files" }] })).toEqual([
      expect.stringMatching(/write it as https:\/\/github\.com\/o\/r\/pull\/1/),
    ]);
  });

  it("rejects files that are missing, empty, absolute, escaping or repeated", () => {
    for (const files of [undefined, "README.md", [], [""], ["/etc/passwd"], ["../x.md"], ["a\\b.md"], ["a.md", "a.md"], [3]]) {
      expect(validateRegistry({ claims: [{ ...ok.claims[0], files }] }).length, JSON.stringify(files)).toBeGreaterThan(0);
    }
  });

  it("rejects refs that do not name the claim's number, so a ref cannot match unrelated text", () => {
    for (const refs of [[], ["PR #12"], ["oscal"], ["#1", "#1"], "#1"]) {
      expect(validateRegistry({ claims: [{ ...ok.claims[0], refs }] }).length, JSON.stringify(refs)).toBeGreaterThan(0);
    }
    expect(validateRegistry({ claims: [{ ...ok.claims[0], refs: ["PR #1"] }] })).toEqual([]);
  });

  it("rejects the same pull request listed twice, whatever the link's form", () => {
    const twice = { claims: [ok.claims[0], claim("https://github.com/O/R/issues/1", "open", ["b.md"])] };
    expect(validateRegistry(twice)).toEqual([expect.stringMatching(/o\/r#1.*listed twice/)]);
  });
});

describe("scanKeys", () => {
  const keys = (text: string) => [...scanKeys(text)].sort();

  it("finds pull requests and issues by link, whatever the link's form", () => {
    expect(keys("[x](https://github.com/O/R/pull/5) and https://www.github.com/o/r/issues/5#c1 and https://github.com/o/r/pull/5/files")).toEqual(["o/r#5"]);
    expect(keys('href="https://github.com/a/b/issues/12"')).toEqual(["a/b#12"]);
  });

  it("finds owner/repo#N references written without a link", () => {
    expect(keys("offered as usnistgov/oscal-content#338, awaiting review (see o/r#9).")).toEqual(["o/r#9", "usnistgov/oscal-content#338"]);
  });

  it("ignores commits, files, anchors and paths that only look like references", () => {
    expect(
      keys(
        [
          "https://github.com/o/r/commit/abcdef1",
          "https://github.com/o/r/blob/main/x.md#L5",
          "[arch](docs/ARCHITECTURE.md#2-layers)",
          "a/b/c#3",
          "example.com/page#12",
        ].join("\n"),
      ),
    ).toEqual([]);
  });
});

describe("adoptersShippedKeys", () => {
  const adopters = [
    "# ADOPTERS",
    "## Schema",
    "### Project Name",
    "- **Evidence**: <https://github.com/x/template/pull/9>",
    "## Tier 1 — Production deployments",
    "### Shipped",
    "- **Evidence**: <https://github.com/a/shipped/pull/1>",
    "- **Status**: shipped",
    "### Review",
    "- **Evidence**: <https://github.com/a/review/pull/2>",
    "- **Status**: in-review",
    "### No status",
    "- **Evidence**: [merged PR](https://github.com/A/Default/pull/3)",
    "## Removed entries",
    "### Gone",
    "- **Evidence**: <https://github.com/a/removed/pull/4>",
    "- **Status**: shipped",
  ].join("\n");

  it("collects shipped evidence under the tier headings only", () => {
    // Status defaults to shipped, as in scripts/verify-adopters.mjs; the schema
    // example and removed entries are not adopters.
    expect([...adoptersShippedKeys(adopters)].sort()).toEqual(["a/default#3", "a/shipped#1"]);
  });
});

describe("sectionText", () => {
  const md = "# T\n### Under review\nalpha\n#### detail\nbeta\n### Next\ngamma\n";

  it("returns a section up to the next heading of its level or higher", () => {
    expect(sectionText(md, "### Under review")).toBe("alpha\n#### detail\nbeta");
  });

  it("returns null when the heading is gone", () => {
    expect(sectionText(md, "### Under maintainer review")).toBeNull();
  });
});

describe("fileProblems", () => {
  const OPEN = "https://github.com/o/open/pull/1";
  const MERGED = "https://github.com/o/merged/pull/2";
  const base: Registry = { claims: [claim(OPEN, "open", ["README.md"]), claim(MERGED, "merged", ["page.tsx"])] };

  it("passes when the files and the list agree", () => {
    expect(fileProblems(base, repo({ "README.md": `see ${OPEN}`, "page.tsx": `<a href="${MERGED}">` }))).toEqual([]);
  });

  it("reports a listed file that is gone or no longer mentions the link", () => {
    expect(fileProblems(base, repo({ "README.md": "rewritten" }, { scoped: ["README.md"] }))).toEqual([
      expect.stringMatching(/README\.md: listed for https:\/\/github\.com\/o\/open\/pull\/1, but mentions neither/),
      expect.stringMatching(/page\.tsx: listed for https:\/\/github\.com\/o\/merged\/pull\/2, but does not exist/),
    ]);
  });

  it("accepts a ref where the file names the claim without a link", () => {
    const reg: Registry = { claims: [claim(OPEN, "open", ["about.tsx"], ["PR #1"])] };
    expect(fileProblems(reg, repo({ "about.tsx": "the open PR #1 at o/open" }))).toEqual([]);
  });

  it("reports a link the list does not cover (how #9809 would have been caught)", () => {
    const text = 'url: "https://github.com/NousResearch/hermes-agent/issues/9809", status: "open"';
    expect(fileProblems(base, repo({ "README.md": OPEN, "page.tsx": MERGED, "actors.ts": text }))).toEqual([
      expect.stringMatching(/actors\.ts: links nousresearch\/hermes-agent#9809\b.*not listed/),
    ]);
  });

  it("does not take PR #12 for a mention of PR #1", () => {
    const reg: Registry = { claims: [claim(OPEN, "open", ["README.md"], ["PR #1"])] };
    expect(fileProblems(reg, repo({ "README.md": OPEN, "other.tsx": "see PR #12 and PR #100" }))).toEqual([]);
    expect(fileProblems(reg, repo({ "README.md": "only PR #12" }))).toEqual([expect.stringMatching(/README\.md: listed for .*mentions neither/)]);
  });

  it("covers an owner/repo#N reference the same way as a link", () => {
    expect(fileProblems(base, repo({ "README.md": OPEN, "page.tsx": MERGED, "about.tsx": "see o/elsewhere#7" }))).toEqual([
      expect.stringMatching(/about\.tsx: links o\/elsewhere#7/),
    ]);
  });

  it("lets merged ADOPTERS.md evidence through, but not evidence still in review", () => {
    const adopters = "## Tier 2\n### A\n- **Evidence**: <https://github.com/a/shipped/pull/1>\n### B\n- **Evidence**: <https://github.com/a/review/pull/2>\n- **Status**: in-review\n";
    const files = { "README.md": OPEN, "page.tsx": `${MERGED} https://github.com/a/shipped/pull/1 https://github.com/a/review/pull/2` };
    expect(fileProblems(base, repo(files, { adopters }))).toEqual([expect.stringMatching(/page\.tsx: links a\/review#2/)]);
  });

  it("reports a file that links a listed claim but is not among its files", () => {
    expect(fileProblems(base, repo({ "README.md": `${OPEN} ${MERGED}`, "page.tsx": MERGED }))).toEqual([
      expect.stringMatching(/README\.md: links o\/merged#2, which is listed for page\.tsx only/),
    ]);
  });

  it("reports a file that names a claim by one of its refs but is not among its files", () => {
    const reg: Registry = { claims: [claim(OPEN, "open", ["README.md"], ["PR #1"])] };
    expect(fileProblems(reg, repo({ "README.md": OPEN, "compliance.tsx": "two profiles in PR #1, awaiting review" }))).toEqual([
      expect.stringMatching(/compliance\.tsx: mentions "PR #1" .*o\/open#1/),
    ]);
  });

  it("checks listed files outside the scanned set, without requiring them to be scanned", () => {
    const reg: Registry = { claims: [claim(OPEN, "open", ["README.md", "docs/x.md"])] };
    expect(fileProblems(reg, repo({ "README.md": OPEN, "docs/x.md": "o/open#1 is open" }, { scoped: ["README.md"] }))).toEqual([]);
    expect(fileProblems(reg, repo({ "README.md": OPEN, "docs/x.md": "nothing" }, { scoped: ["README.md"] }))).toEqual([
      expect.stringMatching(/docs\/x\.md: listed for/),
    ]);
  });

  describe("open-only sections", () => {
    const sections = [{ file: "README.md", heading: "### Under maintainer review (open PRs)" }];
    const adopters = "## Tier 2\n### A\n- **Evidence**: <https://github.com/a/shipped/pull/1>\n";
    const readme = (links: string) => `## Adoption\n### Under maintainer review (open PRs)\n\n${links}\n\n### Integrating\n${MERGED}\n`;
    const reg: Registry = { claims: [claim(OPEN, "open", ["README.md"]), claim(MERGED, "merged", ["README.md"])] };

    it("accept open claims", () => {
      expect(fileProblems(reg, repo({ "README.md": readme(OPEN) }, { sections, adopters }))).toEqual([]);
    });

    it("reject a merged claim or merged ADOPTERS evidence left under review", () => {
      expect(fileProblems(reg, repo({ "README.md": readme(`${OPEN} · ${MERGED} · https://github.com/a/shipped/pull/1`) }, { sections, adopters }))).toEqual([
        expect.stringMatching(/README\.md: "### Under maintainer review \(open PRs\)" lists o\/merged#2, which is merged/),
        expect.stringMatching(/README\.md: "### Under maintainer review \(open PRs\)" lists a\/shipped#1, which is not an open claim/),
      ]);
    });

    it("fail loudly when the heading is renamed, instead of checking nothing", () => {
      expect(fileProblems(reg, repo({ "README.md": `${OPEN} ${MERGED}` }, { sections, adopters }))).toEqual([
        expect.stringMatching(/README\.md: heading "### Under maintainer review \(open PRs\)" not found/),
      ]);
    });
  });
});

// ---------------------------------------------------------------------------
// The committed repository.
// ---------------------------------------------------------------------------

function loadRegistry(): Registry {
  return JSON.parse(readFileSync(join(REPO_ROOT, REGISTRY_PATH), "utf8"));
}

function readRepoFile(path: string): string | null {
  try {
    return readFileSync(join(REPO_ROOT, path), "utf8");
  } catch {
    return null;
  }
}

/** Each actor report that links a GitHub issue or pull request must show the state on the list. */
function actorReportProblems(actors: ThreatActor[], registry: Registry): string[] {
  const byKey = new Map(registry.claims.map((c) => [linkKey(classifyLink(c.url)), c]));
  return actors.flatMap((actor) =>
    actor.reports.flatMap((report) => {
      const link = report.url === undefined ? { kind: "other" } : classifyLink(report.url);
      if (link.kind !== "pr" && link.kind !== "issue") return [];
      const listed = byKey.get(linkKey(link));
      if (listed === undefined) return [`${actor.slug}: report ${report.url} is not in ${REGISTRY_PATH}`];
      return listed.state === report.status
        ? []
        : [`${actor.slug}: report ${report.url} shows ${report.status}, the list says ${listed.state}`];
    }),
  );
}

describe("the committed repository", () => {
  it("has a well-formed list", () => {
    expect(validateRegistry(loadRegistry())).toEqual([]);
  });

  it("scans the pages people read as current, and skips dated records and the red-team list", () => {
    const scoped = listScopedFiles(REPO_ROOT);
    for (const path of ["README.md", "DEPLOYMENTS.md", "STANDARDIZATION-STATUS.md", "website/app/[locale]/page.tsx", "website/lib/actors.ts"]) {
      expect(scoped, path).toContain(path);
    }
    for (const path of [REGISTRY_PATH, "website/data/errata.json", "website/app/[locale]/red-team/page.tsx", "ADOPTERS.md", "CHANGELOG.md"]) {
      expect(scoped, path).not.toContain(path);
    }
    expect(scoped.filter((p: string) => /(^|\/)(node_modules|public|\.next)\//.test(p))).toEqual([]);
  });

  it("agrees with the files that make the claims", () => {
    const problems = fileProblems(loadRegistry(), {
      files: listScopedFiles(REPO_ROOT),
      read: readRepoFile,
      adoptersText: readRepoFile("ADOPTERS.md") ?? "",
      openOnlySections: OPEN_ONLY_SECTIONS,
    });
    expect(problems).toEqual([]);
  });

  it("shows each threat-actor report with the state on the list", () => {
    expect(actorReportProblems(ACTORS, loadRegistry())).toEqual([]);
  });

  it("would have flagged #9809 shown as open on the actor pages", () => {
    const registry: Registry = { claims: [claim("https://github.com/NousResearch/hermes-agent/issues/9809", "closed", ["website/lib/actors.ts"])] };
    const actor = { slug: "x", reports: [{ platform: "p", url: "https://github.com/NousResearch/hermes-agent/issues/9809", status: "open" }] } as unknown as ThreatActor;
    expect(actorReportProblems([actor], registry)).toEqual([expect.stringMatching(/shows open, the list says closed/)]);
  });
});
