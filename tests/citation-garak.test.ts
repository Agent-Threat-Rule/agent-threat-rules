/**
 * Tests for scripts/lib/citation-garak.ts and scripts/sync-citation-garak.ts —
 * the garak sentence in CITATION.cff's abstract, rendered from root stats.json.
 *
 * CITATION.cff is what a paper cites. It said "92.3% recall on the 650-prompt
 * garak in-the-wild jailbreak corpus, measured at ATR 3.5.12": no lane, no
 * enforce figure, no word that the corpus is partly closed-book, and a version
 * that sync-stats.ts had stopped updating because its regex no longer matched
 * the wrapped text. The sentence is now generated whole, and a missing sentence
 * fails instead of freezing.
 */
import { describe, it, expect, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { garakSentence, syncGarakSentence, wrapAbstract } from "../scripts/lib/citation-garak.js";

const REPO = resolve(__dirname, "..");
const SCRIPT = resolve(REPO, "scripts", "sync-citation-garak.ts");
const TSX = resolve(REPO, "node_modules", ".bin", "tsx");

const GARAK = { recall: 92.3, enforceLaneRecall: 0.9, samples: 650, atr_version: "4.1.5" };

const ABSTRACT = (sentenceLines: string[]): string =>
  [
    "cff-version: 1.2.0",
    "abstract: >",
    "  ATR is an open-source detection rule set. Rules are hand-authored from real",
    "  attack payloads.",
    ...sentenceLines,
    "  Rule counts change daily.",
    "type: software",
    "",
  ].join("\n");

const STALE = [
  "  On the 650-prompt garak in-the-wild jailbreak corpus, measured at ATR 3.5.12,",
  "  recall is 91.5% in the hunt lane (README section 8).",
];

describe("garakSentence", () => {
  it("names both lanes, the version measured, and the closed-book caveat", () => {
    const s = garakSentence(GARAK, "9.9.9");
    expect(s).toContain("On the 650-prompt garak in-the-wild jailbreak corpus, measured at ATR 4.1.5,");
    expect(s).toContain("92.3% in the hunt lane");
    expect(s).toContain("0.9% in the enforce lane");
    expect(s).toMatch(/partly closed-book/);
    expect(s.endsWith("(README section 8).")).toBe(true);
  });

  it("keeps a decimal on whole figures and the decimals that keep a small rate above 0%", () => {
    expect(garakSentence({ ...GARAK, recall: 100, enforceLaneRecall: 0 }, "x")).toMatch(
      /100\.0% in the hunt lane .* 0\.0% in the enforce lane/s,
    );
    expect(garakSentence({ ...GARAK, enforceLaneRecall: 0.03 }, "x")).toContain("0.03% in the enforce lane");
  });

  it("says so when no enforce-lane figure is recorded, rather than leaving the hunt figure alone", () => {
    const { enforceLaneRecall: _omit, ...hunt } = GARAK;
    expect(garakSentence(hunt, "x")).toMatch(/no enforce-lane figure is recorded/);
  });

  it("falls back to the package version when the block names none", () => {
    const { atr_version: _omit, ...unversioned } = GARAK;
    expect(garakSentence(unversioned, "4.1.6")).toContain("measured at ATR 4.1.6,");
  });
});

describe("wrapAbstract", () => {
  it("wraps to the abstract's two-space indent within 80 columns", () => {
    const lines = wrapAbstract(garakSentence(GARAK, "x"));
    expect(lines.length).toBeGreaterThan(1);
    for (const l of lines) {
      expect(l.startsWith("  ")).toBe(true);
      expect(l.length).toBeLessThanOrEqual(80);
    }
    expect(lines.map((l) => l.trim()).join(" ")).toBe(garakSentence(GARAK, "x"));
  });
});

describe("syncGarakSentence", () => {
  it("replaces the sentence whole and leaves every other line alone", () => {
    const before = ABSTRACT(STALE);
    const after = syncGarakSentence(before, GARAK, "x");
    expect(after).toBe(ABSTRACT(wrapAbstract(garakSentence(GARAK, "x"))));
    expect(syncGarakSentence(after, GARAK, "x")).toBe(after);
  });

  it("throws when the abstract has no garak sentence, instead of freezing an old one", () => {
    expect(() => syncGarakSentence(ABSTRACT([]), GARAK, "x")).toThrow(/garak sentence/);
  });
});

describe("CLI", () => {
  const roots: string[] = [];
  afterEach(() => {
    for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true });
  });
  function fixture(abstract: string): string {
    const r = mkdtempSync(join(tmpdir(), "citation-garak-"));
    roots.push(r);
    writeFileSync(join(r, "stats.json"), JSON.stringify({ version: "4.1.5", benchmarks: { garak: GARAK } }));
    writeFileSync(join(r, "CITATION.cff"), abstract);
    return r;
  }
  const run = (args: string[]) => spawnSync(TSX, [SCRIPT, ...args], { encoding: "utf-8" });

  it("--check fails while CITATION.cff disagrees with stats.json, and passes after a sync", () => {
    const r = fixture(ABSTRACT(STALE));
    expect(run(["--root", r, "--check"]).status).toBe(1);
    expect(run(["--root", r]).status).toBe(0);
    expect(readFileSync(join(r, "CITATION.cff"), "utf-8")).toContain("0.9% in the enforce lane");
    expect(run(["--root", r, "--check"]).status).toBe(0);
  });

  it("fails when the sentence is missing", () => {
    expect(run(["--root", fixture(ABSTRACT([])), "--check"]).status).toBe(1);
  });
});
