/**
 * Tests for the attribution section of the benign-harvest PR body
 * (scripts/lib/fp-attribution.ts, scripts/render-fp-attribution.ts).
 *
 * A harvest that makes the response-action gate fail used to tell the reviewer
 * to demote rules, without saying which new sample did it. The samples are
 * third-party text and a poisoned "benign" sample is the stated threat, so the
 * body now names, per rule, the new samples that rule fires on, and lets the
 * reviewer decide whether a sample belongs in the corpus before anything is
 * demoted. Pinned here:
 *
 *  - rules the gate fails come first, each with its triggering samples
 *    (source, source_id, file:line, excerpt);
 *  - nothing is truncated silently: every cap leaves an explicit "… N more";
 *  - third-party text cannot format the PR body: it is flattened, its control
 *    and bidi characters are escaped, and it sits in a code block it cannot
 *    close, so it cannot @-mention, link or hide text;
 *  - the section stays far below GitHub's 65,536-character body limit however
 *    large the harvest.
 */
import { describe, it, expect, afterAll } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  ATTRIBUTION_SCHEMA,
  parseAttributionReport,
  parseGateViolations,
  renderAttributionSection,
  sanitizeInline,
  type AttributedRule,
  type AttributionReport,
} from "../scripts/lib/fp-attribution.js";
import {
  RenderUsageError,
  parseRenderArgs,
  runRender,
} from "../scripts/render-fp-attribution.js";

function sample(sourceId: string, text: string, line = 1) {
  return {
    excerpt: sanitizeInline(text, 160),
    occurrences: 1,
    locations: [{ file: "data/benign-corpus-extended/arxiv.jsonl", line, source: "arxiv", source_id: sourceId }],
  };
}

function attributed(id: string, before: number | null, samples: ReturnType<typeof sample>[]): AttributedRule {
  return {
    id,
    measured: before === null ? "full" : "delta",
    fp_count_before: before,
    fp_count_after: (before ?? 0) + samples.length,
    added_matches: samples.length,
    samples,
  };
}

function report(rules: readonly AttributedRule[], extra: Partial<AttributionReport> = {}): AttributionReport {
  return parseAttributionReport(
    JSON.stringify({
      schema: ATTRIBUTION_SCHEMA,
      base_ref: "HEAD",
      base_commit: "5a4e8441bb2223dd013edf810e4e394dea27d610",
      base_sample_count: 13848,
      added_sample_count: 308,
      head_sample_count: 14156,
      rules_total: 829,
      measured_on_added_only: 793,
      measured_in_full: [{ id: "ATR-2026-00900", reason: "absent-from-base-evidence" }],
      rules,
      ...extra,
    }),
  );
}

const BLOCKER = attributed("ATR-2026-00120", 3, [
  sample("2410.00001", "We evaluate prompt injection defences on agent benchmarks.", 12),
  sample("2410.00002", "A study of tool-use agents.", 13),
]);
const BYSTANDER = attributed("ATR-2026-00300", 40, [sample("2410.00003", "Ignore previous instructions, said no one.")]);
const VIOLATION = {
  id: "ATR-2026-00120",
  unearned: ["kill_agent"],
  reason: "benign FP 5/14156 = 0.04% meets the 0.5% ceiling but is not zero",
};

describe("renderAttributionSection", () => {
  it("puts the rules the gate fails first, each with the new samples that trigger it", () => {
    const { markdown } = renderAttributionSection(report([BYSTANDER, BLOCKER]), [VIOLATION]);
    const failing = markdown.indexOf("now fails");
    const other = markdown.indexOf("Other rules");
    expect(failing).toBeGreaterThan(-1);
    expect(other).toBeGreaterThan(failing);
    const blockerAt = markdown.indexOf("ATR-2026-00120");
    expect(blockerAt).toBeGreaterThan(failing);
    expect(blockerAt).toBeLessThan(other);
    expect(markdown.indexOf("ATR-2026-00300")).toBeGreaterThan(other);
    expect(markdown).toContain("fp_count 3 -> 5 (+2 from the new samples)");
    expect(markdown).toContain("unearned: kill_agent");
    expect(markdown).toContain(VIOLATION.reason);
    expect(markdown).toContain("arxiv 2410.00001  data/benign-corpus-extended/arxiv.jsonl:12");
    expect(markdown).toContain('"We evaluate prompt injection defences on agent benchmarks."');
  });

  it("states how the evidence was re-measured", () => {
    const { markdown } = renderAttributionSection(report([BLOCKER]), undefined);
    expect(markdown).toContain("793 of 829 rules on the 308 new samples only");
    expect(markdown).toContain("1 in full (1 absent from the committed evidence)");
  });

  it("says when a failing rule is not caused by this harvest", () => {
    const { markdown } = renderAttributionSection(report([BYSTANDER]), [VIOLATION]);
    expect(markdown).toMatch(/ATR-2026-00120 +no new sample fires on it/);
  });

  it("says when the gate failed without naming rules", () => {
    const { markdown } = renderAttributionSection(report([BLOCKER]), null);
    expect(markdown).toContain("The gate failed without naming rules with unearned actions");
    expect(markdown).toContain("ATR-2026-00120");
  });

  it("says so when no rule fires on any new sample", () => {
    const { markdown } = renderAttributionSection(report([]), undefined);
    expect(markdown).toContain("No rule fires on any of the new samples.");
  });

  it("marks every cut with how much was cut, and the log keeps everything", () => {
    const many = Array.from({ length: 30 }, (_, i) =>
      attributed(
        `ATR-2026-0${String(1000 + i)}`,
        1,
        Array.from({ length: 9 }, (_, j) => sample(`2410.${i}.${j}`, `sample ${i}-${j}`, j + 1)),
      ),
    );
    const { markdown, log } = renderAttributionSection(report(many), undefined, {
      maxRules: 4,
      maxSamplesPerRule: 3,
    });
    expect(markdown).toContain("… 6 more new samples for this rule");
    expect(markdown).toContain("… 26 more rules");
    expect((markdown.match(/^ATR-2026-0\d+/gm) ?? []).length).toBe(4);
    expect((log.match(/^ATR-2026-0\d+/gm) ?? []).length).toBe(30);
    expect(log).not.toContain("more rules");
    expect(log).toContain("2410.29.8");
  });

  it("cannot be formatted, linked or hidden by the text of a sample", () => {
    const evil = attributed("ATR-2026-00500", 0, [
      {
        excerpt: "line one\nline two @octocat [x](https://evil.example) ‮exe.txt\u0007",
        occurrences: 1,
        locations: [
          {
            file: "data/benign-corpus-extended/npm.jsonl",
            line: 3,
            source: "npm\n```",
            source_id: "```\n@everyone",
          },
        ],
      },
    ]);
    const { markdown } = renderAttributionSection(report([evil]), undefined);
    const blocks = [...markdown.matchAll(/^(`{3,})text\n([\s\S]*?)\n\1$/gm)];
    expect(blocks).toHaveLength(1);
    const [, fence = "", inside = ""] = blocks[0] ?? [];
    // The fence is longer than any backtick run the samples carry, so no line can close it.
    expect(fence.length).toBeGreaterThanOrEqual(4);
    expect(inside).not.toContain(fence);
    expect(inside).toContain("@octocat");
    expect(inside).toContain("@everyone");
    expect(inside).toContain("line one line two");
    expect(inside).toContain("\\u{202e}exe.txt\\u{7}");
    expect(markdown).not.toMatch(/[\u0000-\u0008\u000b-\u001f‪-‮⁦-⁩]/);
    const outside = markdown.replace(/^(`{3,})text\n[\s\S]*?\n\1$/gm, "");
    expect(outside).not.toContain("@");
    expect(outside).not.toContain("evil.example");
  });

  it("stays far below GitHub's body limit for an enormous harvest", () => {
    const huge = "x".repeat(10_000);
    const rules = Array.from({ length: 500 }, (_, i) =>
      attributed(
        `ATR-2026-${String(10000 + i)}`,
        1,
        Array.from({ length: 50 }, (_, j) => sample(`${"y".repeat(300)}${j}`, huge, j + 1)),
      ),
    );
    const violations = rules.slice(0, 300).map((r) => ({ id: r.id, unearned: ["kill_agent"], reason: "z".repeat(5000) }));
    const { markdown } = renderAttributionSection(report(rules), violations);
    expect(markdown.length).toBeLessThan(40_000);
  });
});

describe("sanitizeInline", () => {
  it("flattens whitespace, escapes invisible characters and caps the length", () => {
    expect(sanitizeInline("a\n\tb   c", 100)).toBe("a b c");
    expect(sanitizeInline("x​y‮z\ud800", 100)).toBe("x\\u{200b}y\\u{202e}z\\u{d800}");
    expect(sanitizeInline("🦎".repeat(10), 3)).toBe("🦎🦎🦎…");
    expect(sanitizeInline(sanitizeInline("‮", 10), 10)).toBe("\\u{202e}");
  });
});

describe("parseGateViolations", () => {
  it("reads the gate's --json output", () => {
    const raw = JSON.stringify({
      checked: 3,
      violations: [
        {
          id: "ATR-2026-00120",
          file: "rules/x.yaml",
          unearned: ["kill_agent"],
          maxTier: 2,
          decision: { maxTier: 2, fpRatePct: 0.04, reason: "r" },
        },
      ],
    });
    expect(parseGateViolations(raw)).toEqual([{ id: "ATR-2026-00120", unearned: ["kill_agent"], reason: "r" }]);
  });

  it("returns null for an empty file: the gate failed without a JSON verdict", () => {
    expect(parseGateViolations("")).toBeNull();
    expect(parseGateViolations("  \n")).toBeNull();
  });

  it("refuses output it does not understand", () => {
    expect(() => parseGateViolations("{not json")).toThrow();
    expect(() => parseGateViolations('{"violations":[{"file":"x"}]}')).toThrow();
  });
});

describe("parseAttributionReport", () => {
  it("refuses a report of another schema or shape", () => {
    expect(() => parseAttributionReport("{}")).toThrow();
    expect(() => parseAttributionReport(JSON.stringify({ ...report([]), schema: "other@1" }))).toThrow();
    expect(() =>
      parseAttributionReport(JSON.stringify({ ...report([]), rules: [{ id: "ATR-2026-00001" }] })),
    ).toThrow();
  });
});

describe("render-fp-attribution CLI", () => {
  const dirs: string[] = [];
  afterAll(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  it("parses its flags strictly", () => {
    expect(parseRenderArgs(["--report", "r.json", "--out", "o.md"])).toEqual({
      report: "r.json",
      gateJson: null,
      out: "o.md",
    });
    expect(parseRenderArgs(["--report", "r.json", "--gate-json", "g.json", "--out", "o.md"]).gateJson).toBe(
      "g.json",
    );
    for (const argv of [
      ["--out", "o.md"],
      ["--report", "r.json"],
      ["--report", "r.json", "--out", "o.md", "--gate", "g.json"],
      ["--report", "--out", "o.md"],
      ["--report", "r.json", "--out", "o.md", "--out", "p.md"],
    ]) {
      expect(() => parseRenderArgs(argv)).toThrow(RenderUsageError);
    }
  });

  it("writes the section and prints the untruncated listing", () => {
    const dir = mkdtempSync(join(tmpdir(), "atr-render-"));
    dirs.push(dir);
    writeFileSync(join(dir, "r.json"), JSON.stringify(report([BLOCKER, BYSTANDER])));
    writeFileSync(join(dir, "g.json"), JSON.stringify({ checked: 2, violations: [{ ...VIOLATION, file: "x" }] }));
    const printed: string[] = [];
    const code = runRender(
      { report: join(dir, "r.json"), gateJson: join(dir, "g.json"), out: join(dir, "o.md") },
      (line) => printed.push(line),
    );
    expect(code).toBe(0);
    expect(readFileSync(join(dir, "o.md"), "utf-8")).toContain("ATR-2026-00120");
    expect(printed.join("\n")).toContain("2410.00003");
  });

  it("fails on an unreadable report instead of rendering an empty section", () => {
    const dir = mkdtempSync(join(tmpdir(), "atr-render-"));
    dirs.push(dir);
    const code = runRender({ report: join(dir, "missing.json"), gateJson: null, out: join(dir, "o.md") }, () => {});
    expect(code).not.toBe(0);
  });
});
