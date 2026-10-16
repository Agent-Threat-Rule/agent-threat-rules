/**
 * Tests for scripts/render-recall-citations.ts — the recall figures that
 * Markdown documents outside README quote (LIMITATIONS.md, docs/…), rendered
 * between `<!-- recall:<source>[:<format>] -->` markers from the measurement
 * file each source's latest.json points at.
 *
 * What matters here: a rendered recall always names its lane and carries the
 * enforce figure the measurement records (the rule check-benchmark-citations.ts
 * holds README's table to), nothing outside a marker moves, and a marker the
 * renderer cannot back is reported instead of being left looking current.
 */
import { describe, it, expect, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

import { checkRecallCell } from "../scripts/check-benchmark-citations.js";
import {
  DOCUMENTS,
  findSpans,
  loadLaneMeasurement,
  renderDocument,
  renderFigure,
  renderRepoDocuments,
  type LaneMeasurement,
} from "../scripts/render-recall-citations.js";

const REPO = resolve(__dirname, "..");
const SCRIPT = resolve(REPO, "scripts", "render-recall-citations.ts");
const TSX = resolve(REPO, "node_modules", ".bin", "tsx");

const roots: string[] = [];
afterEach(() => {
  for (const r of roots.splice(0)) rmSync(r, { recursive: true, force: true });
});

interface SourceFixture {
  source: string;
  tp: number;
  fn: number;
  fp?: number;
  tn?: number;
  /** Detected by the enforce lane; null = the measurement records no enforce lane. */
  enforce?: number | null;
  precision?: number;
  fpRate?: number;
  f1?: number;
  byCategory?: { category: string; tp: number; fn: number; tn?: number }[];
  atrVersion?: string;
  measuredAt?: string;
  /** What latest.json mirrors; defaults to the measurement's own recall. */
  pointerRecall?: number;
}

function measurement(f: SourceFixture): Record<string, unknown> {
  const fp = f.fp ?? 0;
  const tn = f.tn ?? 0;
  const attacks = f.tp + f.fn;
  const breakdown: Record<string, unknown> = {};
  if (f.enforce !== null && f.enforce !== undefined) {
    breakdown.enforce_lane = {
      lane: "enforce",
      detected: f.enforce,
      attacks,
      recall: f.enforce / attacks,
      rules_in_lane: 103,
      note: "fixture",
    };
  }
  if (f.byCategory !== undefined) {
    breakdown.by_category = f.byCategory.map((c) => ({
      category: c.category,
      metrics: {
        recall: c.tp + c.fn === 0 ? 1 : c.tp / (c.tp + c.fn),
        confusion: { tp: c.tp, fp: 0, tn: c.tn ?? 0, fn: c.fn },
        sampleCount: c.tp + c.fn + (c.tn ?? 0),
      },
    }));
  }
  return {
    schema_version: "1",
    source: f.source,
    source_version: "v1",
    atr_version: f.atrVersion ?? "4.1.5",
    atr_commit: "abc1234",
    rules_loaded: 830,
    measured_at: f.measuredAt ?? "2026-10-15T04:06:07.927Z",
    samples: attacks + fp + tn,
    metrics: {
      recall: f.tp / attacks,
      precision: f.precision ?? 1,
      f1: f.f1 ?? 0.5,
      fp_rate: f.fpRate ?? 0,
    },
    confusion: { tp: f.tp, fp, tn, fn: f.fn },
    breakdown,
  };
}

function writeSource(root: string, f: SourceFixture): void {
  const dir = join(root, "data", "measurements", f.source);
  mkdirSync(dir, { recursive: true });
  const m = measurement(f);
  const file = `2026-10-15_${f.source}-v1_atr-4-1-5.json`;
  writeFileSync(join(dir, file), JSON.stringify(m, null, 2));
  const metrics = m.metrics as Record<string, number>;
  writeFileSync(
    join(dir, "latest.json"),
    JSON.stringify({
      source: f.source,
      file,
      measured_at: m.measured_at,
      metrics: { ...metrics, recall: f.pointerRecall ?? metrics.recall },
      source_version: "v1",
      atr_version: m.atr_version,
      samples: m.samples,
    }),
  );
}

const PINT: SourceFixture = {
  source: "pint",
  tp: 295,
  fn: 156,
  tn: 399,
  enforce: 2,
  f1: 0.7908847184986595,
  byCategory: [
    { category: "benign", tp: 0, fn: 0, tn: 399 },
    { category: "prompt-injection", tp: 148, fn: 113 },
    { category: "jailbreak", tp: 147, fn: 43 },
  ],
};
const SKILL: SourceFixture = {
  source: "skill-benchmark",
  tp: 32,
  fn: 0,
  fp: 1,
  tn: 465,
  enforce: 0,
  precision: 0.97,
  fpRate: 0.002,
};
const HACKAPROMPT: SourceFixture = {
  source: "hackaprompt",
  tp: 3327,
  fn: 1453,
  enforce: null,
  atrVersion: "3.5.0",
  measuredAt: "2026-06-16T00:00:00.000Z",
};
const GARAK_FULL: SourceFixture = { source: "garak-full", tp: 1987, fn: 1488, enforce: 1 };

function fixtureRoot(sources: SourceFixture[] = [PINT, SKILL, HACKAPROMPT, GARAK_FULL]): string {
  const root = mkdtempSync(join(tmpdir(), "recall-citations-"));
  roots.push(root);
  for (const s of sources) writeSource(root, s);
  return root;
}

function loaderFor(root: string): (source: string) => LaneMeasurement {
  return (source) => loadLaneMeasurement(root, source);
}

const span = (source: string, body: string, format?: string): string =>
  `<!-- recall:${source}${format === undefined ? "" : `:${format}`} -->${body}<!-- /recall -->`;

describe("renderFigure", () => {
  const root = (): string => fixtureRoot();

  it("cites both lanes, hunt first, where the measurement records the enforce lane", () => {
    const m = loadLaneMeasurement(root(), "pint");
    expect(renderFigure(m, "lanes")).toBe("65.4% (hunt) / 0.4% (enforce)");
  });

  it("is exactly what the README checker accepts for the same measurement", () => {
    const r = root();
    for (const source of ["pint", "skill-benchmark", "hackaprompt", "garak-full"]) {
      const m = loadLaneMeasurement(r, source);
      expect(checkRecallCell(renderFigure(m, "lanes"), m.recall, m.enforce?.recall ?? null)).toBeNull();
    }
  });

  it("never rounds a non-zero enforce figure to 0%", () => {
    const m = loadLaneMeasurement(root(), "garak-full");
    expect(renderFigure(m, "lanes")).toBe("57.2% (hunt) / 0.03% (enforce)");
  });

  it("names only the hunt lane when the measurement predates the enforce record", () => {
    const m = loadLaneMeasurement(root(), "hackaprompt");
    expect(renderFigure(m, "lanes")).toBe("69.6% (hunt)");
    expect(renderFigure(m, "counts")).toBe("3,327 of 4,780 (hunt)");
  });

  it("renders counts, stamp, file and corpus sizes from the measurement file", () => {
    const m = loadLaneMeasurement(root(), "pint");
    expect(renderFigure(m, "counts")).toBe("295 of 451 (hunt) / 2 of 451 (enforce)");
    expect(renderFigure(m, "stamp")).toBe("ATR 4.1.5, measured 2026-10-15");
    expect(renderFigure(m, "file")).toBe("`data/measurements/pint/2026-10-15_pint-v1_atr-4-1-5.json`");
    expect(renderFigure(m, "samples")).toBe("850");
    expect(renderFigure(m, "attacks")).toBe("451");
    expect(renderFigure(m, "benign")).toBe("399");
  });

  it("labels precision, F1 and false-positive figures as the hunt lane", () => {
    const pint = loadLaneMeasurement(root(), "pint");
    expect(renderFigure(pint, "precision")).toBe("100.0% (hunt)");
    expect(renderFigure(pint, "f1")).toBe("79.1% (hunt)");
    const skill = loadLaneMeasurement(root(), "skill-benchmark");
    expect(renderFigure(skill, "precision")).toBe("97.0% (hunt)");
    expect(renderFigure(skill, "fp-rate")).toBe("0.20% (hunt)");
    expect(renderFigure(skill, "fp-counts")).toBe("1 of 466 (hunt)");
  });

  it("renders the per-category table from the measurement, with the overall enforce figure beside it", () => {
    const m = loadLaneMeasurement(root(), "pint");
    const block = renderFigure(m, "categories");
    expect(block).toContain("| Category | Attack samples | Recall (hunt) |");
    expect(block).toContain("| Prompt-injection | 261 | 56.7% |");
    expect(block).toContain("| Jailbreak | 190 | 77.4% |");
    // The benign control has no attack samples, so it has no recall to show.
    expect(block).not.toMatch(/\| Benign \|/);
    expect(block).toContain("2 of 451 (0.4%)");
    expect(block.startsWith("\n")).toBe(true);
    expect(block.endsWith("\n")).toBe(true);
  });

  it("reads the measurement file latest.json points at, not the pointer's mirror", () => {
    const r = fixtureRoot([{ ...PINT, pointerRecall: 0.99 }]);
    expect(renderFigure(loadLaneMeasurement(r, "pint"), "lanes")).toBe("65.4% (hunt) / 0.4% (enforce)");
  });

  it("throws on a format it does not know, and on one the measurement cannot back", () => {
    const m = loadLaneMeasurement(root(), "hackaprompt");
    expect(() => renderFigure(m, "lane")).toThrow(/unknown format/);
    expect(() => renderFigure(m, "categories")).toThrow(/by_category/);
  });
});

describe("loadLaneMeasurement", () => {
  it("throws when the source has no latest.json", () => {
    expect(() => loadLaneMeasurement(fixtureRoot(), "garak")).toThrow(/latest\.json/);
  });

  it("throws when latest.json points at a file that does not exist", () => {
    const r = fixtureRoot([PINT]);
    const pointer = join(r, "data", "measurements", "pint", "latest.json");
    const p = JSON.parse(readFileSync(pointer, "utf-8")) as Record<string, unknown>;
    writeFileSync(pointer, JSON.stringify({ ...p, file: "missing.json" }));
    expect(() => loadLaneMeasurement(r, "pint")).toThrow(/missing\.json/);
  });
});

describe("findSpans", () => {
  it("finds source and format, defaulting the format to lanes", () => {
    const spans = findSpans(`a ${span("pint", "x")} b ${span("pint", "y", "counts")} c`);
    expect(spans.map((s) => [s.source, s.format, s.body])).toEqual([
      ["pint", "lanes", "x"],
      ["pint", "counts", "y"],
    ]);
  });
});

describe("renderDocument", () => {
  it("rewrites only what sits between markers", () => {
    const r = fixtureRoot();
    const before = [
      "Prose quoting 12.3% recall outside a marker stays as it is.",
      `PINT-format recall: ${span("pint", "92.0%")} (${span("pint", "ATR 3.5.12, measured 2026-08-15", "stamp")}).`,
      "",
    ].join("\n");
    const { text, problems } = renderDocument(before, loaderFor(r));
    expect(problems).toEqual([]);
    expect(text).toBe(
      [
        "Prose quoting 12.3% recall outside a marker stays as it is.",
        `PINT-format recall: ${span("pint", "65.4% (hunt) / 0.4% (enforce)")} (${span(
          "pint",
          "ATR 4.1.5, measured 2026-10-15",
          "stamp",
        )}).`,
        "",
      ].join("\n"),
    );
  });

  it("is idempotent", () => {
    const r = fixtureRoot();
    const once = renderDocument(`${span("skill-benchmark", "")} and ${span("pint", "", "categories")}`, loaderFor(r)).text;
    expect(renderDocument(once, loaderFor(r)).text).toBe(once);
  });

  it("reports a source with no measurement and leaves its span untouched", () => {
    const r = fixtureRoot();
    const before = `x ${span("garak", "92.3%")} y`;
    const { text, problems } = renderDocument(before, loaderFor(r));
    expect(text).toBe(before);
    expect(problems.join("\n")).toMatch(/garak/);
  });

  it("reports an unknown format", () => {
    const { problems } = renderDocument(span("pint", "x", "headline"), loaderFor(fixtureRoot()));
    expect(problems.join("\n")).toMatch(/unknown format "headline"/);
  });

  it("ends a compact marker at its own closing comment", () => {
    const { text, problems } = renderDocument("<!--recall:pint-->x<!--/recall-->", loaderFor(fixtureRoot()));
    expect(problems).toEqual([]);
    expect(text).toBe("<!--recall:pint-->65.4% (hunt) / 0.4% (enforce)<!--/recall-->");
  });

  it("reports an opening marker that is never closed, and a closing marker with no opener", () => {
    const r = fixtureRoot();
    expect(renderDocument("<!-- recall:pint -->65.4% and no close", loaderFor(r)).problems.join("\n")).toMatch(
      /not closed/,
    );
    expect(renderDocument("stray <!-- /recall --> here", loaderFor(r)).problems.join("\n")).toMatch(/no opening/);
    expect(
      renderDocument(`<!-- recall:pint -->a ${span("pint", "b")}`, loaderFor(r)).problems.join("\n"),
    ).toMatch(/not closed/);
  });
});

describe("renderRepoDocuments", () => {
  it("reports a listed document with no marker, and one that is missing", () => {
    const r = fixtureRoot();
    writeFileSync(join(r, "a.md"), "no markers here\n");
    const { problems } = renderRepoDocuments(r, ["a.md", "b.md"]);
    expect(problems.join("\n")).toMatch(/a\.md.*no recall marker/);
    expect(problems.join("\n")).toMatch(/b\.md.*does not exist/);
  });

  it("lists every document the renderer owns", () => {
    expect(DOCUMENTS).toContain("LIMITATIONS.md");
    expect(new Set(DOCUMENTS).size).toBe(DOCUMENTS.length);
  });
});

describe("CLI", () => {
  function fixtureWithDocuments(body: string): string {
    const r = fixtureRoot();
    for (const doc of DOCUMENTS) {
      mkdirSync(dirname(join(r, doc)), { recursive: true });
      writeFileSync(join(r, doc), `# ${doc}\n\nRecall: ${body}\n`);
    }
    return r;
  }
  const run = (args: string[]) => spawnSync(TSX, [SCRIPT, ...args], { encoding: "utf-8" });

  it("--check fails on a stale figure, and passes once the documents are rendered", () => {
    const r = fixtureWithDocuments(span("pint", "92.0%"));
    const stale = run(["--root", r, "--check"]);
    expect(stale.status).toBe(1);
    expect(stale.stderr).toMatch(/LIMITATIONS\.md/);

    expect(run(["--root", r]).status).toBe(0);
    expect(readFileSync(join(r, "LIMITATIONS.md"), "utf-8")).toContain(span("pint", "65.4% (hunt) / 0.4% (enforce)"));
    expect(run(["--root", r, "--check"]).status).toBe(0);
  });

  it("lists what it could not render in --review-notes, and still exits 0 in write mode", () => {
    const r = fixtureWithDocuments(span("pint", "x", "headline"));
    const notes = join(r, "notes.md");
    writeFileSync(notes, "");
    expect(run(["--root", r, "--review-notes", notes]).status).toBe(0);
    expect(readFileSync(notes, "utf-8")).toMatch(/### Recall citations not re-rendered[\s\S]*unknown format "headline"/);
  });

  it("--check fails on a marker it cannot render, even when nothing would change", () => {
    const r = fixtureWithDocuments(span("pint", "x", "headline"));
    expect(run(["--root", r, "--check"]).status).toBe(1);
  });
});
