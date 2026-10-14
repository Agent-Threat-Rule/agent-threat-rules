/**
 * Tests for scripts/render-benchmark-table.ts — re-rendering README's benchmark
 * table and root stats.json's garak / pint citations from latest.json.
 *
 * The weekly measure-all PR (#656) failed check-benchmark-citations.ts with 45
 * mismatches because nothing regenerated README. What matters here is that the
 * rendered documents pass that exact check, and that nothing outside the
 * measured cells moves: these are public numbers, and a renderer that rewrote
 * a label, a footnote or a lane annotation would be a new way to get them wrong.
 */
import { describe, it, expect, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import {
  type BenchmarkEntry,
  EXEMPT_SOURCES,
  LABEL_TO_SOURCE,
  findCitationProblems,
} from "../scripts/check-benchmark-citations.js";
import { renderReadme, renderRootStats, renderRepo } from "../scripts/render-benchmark-table.js";
import { aggregateMeasurements, projectForStats } from "../scripts/measurement/aggregate.js";

const REPO = resolve(__dirname, "..");
const SCRIPT = resolve(REPO, "scripts", "render-benchmark-table.ts");
const TSX = resolve(REPO, "node_modules", ".bin", "tsx");

/** Labels as README writes them, footnote markers included. */
const FOOTNOTES: Readonly<Record<string, string>> = {
  "hh-rlhf": " [^stdcorpora]",
  pint: " [^pint]",
  "skill-benchmark": " [^skilllane]",
  "wild-scan": " [^wildscan]",
};

const HEADER = [
  "| Source | Source version | Samples | Recall | Precision | FP rate | ATR version | Measured |",
  "|---|---|---:|---:|---:|---:|---|---|",
];

/** A stale row as a hand-edited README has it. */
function staleRow(label: string, source: string): string {
  const name = `${label}${FOOTNOTES[source] ?? ""}`;
  if (source === "wild-scan") {
    return `| ${name} | full-scan-v2 | 101,280 | — | not measured | 1.42% flag rate | 2.0.0 | 2026-04-13 |`;
  }
  if (source === "skill-benchmark") {
    return `| ${name} | internal-498 | 498 | 100.0% (hunt) / 0.0% (enforce) | 97.0% | 0.20% | 3.5.12 | 2026-08-15 |`;
  }
  return `| ${name} | v-old | 1,054 | 12.3% | 100.0% | 0.0% | 3.5.0 | 2026-06-16 |`;
}

function fixtureReadme(): string {
  const rows = [...LABEL_TO_SOURCE].map(([label, source]) => staleRow(label, source));
  return [
    "# ATR",
    "",
    "Prose above the table quoting 12.3% must not move.",
    "",
    ...HEADER,
    ...rows,
    "",
    "Prose below: re-measured against ATR 3.5.0 on 2026-06-16.",
    "",
    "[^pint]: Footnote text with 65.4% in it.",
    "",
  ].join("\n");
}

function entry(source: string, i: number): BenchmarkEntry {
  return {
    source,
    source_version: `upstream-2026-10-12`,
    atr_version: "4.1.5",
    measured_at: "2026-10-12",
    samples: 1000 + i * 37,
    recall: (i + 1) / 40,
    precision: source === "skill-benchmark" ? 0.97 : 1,
    fp_rate: source === "skill-benchmark" ? 0.004 : 0,
  };
}

/** One measured entry for every mapped, non-exempt source. */
function fixtureEntries(): BenchmarkEntry[] {
  return [...new Set(LABEL_TO_SOURCE.values())]
    .filter((s) => !EXEMPT_SOURCES.has(s))
    .map((s, i) => entry(s, i));
}

const ROOT_STATS = {
  version: "4.1.5",
  benchmarks: {
    garak: { recall: 92.3, samples: 650, detected: 600, missed: 50, atr_version: "3.5.12", measured: "2026-08-15" },
    skill: { recall: 100, atr_version: "3.5.12", measured: "2026-08-15" },
    pint: { recall: 65.4, precision: 100, fpRate: 0, samples: 850, atr_version: "3.5.12", measured: "2026-08-15" },
  },
};

const tableLineNos = (readme: string): Set<number> => {
  const lines = readme.split("\n");
  const start = lines.indexOf(HEADER[0]) + 2;
  return new Set(lines.map((_, i) => i).filter((i) => i >= start && lines[i].startsWith("|")));
};

describe("renderReadme", () => {
  it("produces a README and stats.json the citation check accepts, from ones it rejects", () => {
    const readme = fixtureReadme();
    const entries = fixtureEntries();
    const before = findCitationProblems(readme, { benchmarks: entries }, ROOT_STATS);
    expect(before.problems.length).toBeGreaterThan(0);

    const rendered = renderReadme(readme, entries);
    const rootStats = renderRootStats(ROOT_STATS, entries);
    const after = findCitationProblems(rendered, { benchmarks: entries }, rootStats);
    expect(after.fatal).toBeNull();
    expect(after.problems).toEqual([]);
    expect(after.rowCount).toBe(LABEL_TO_SOURCE.size);
  });

  it("leaves every line outside the measured rows byte-identical, labels and footnotes included", () => {
    const readme = fixtureReadme();
    const rendered = renderReadme(readme, fixtureEntries());
    const a = readme.split("\n");
    const b = rendered.split("\n");
    expect(b).toHaveLength(a.length);
    const rowLines = tableLineNos(readme);
    a.forEach((line, i) => {
      if (!rowLines.has(i)) expect(b[i]).toBe(line);
      else expect(b[i].split("|")[1]).toBe(line.split("|")[1]);
    });
    expect(rendered).toContain("| hh-rlhf (Anthropic red-team-attempts) [^stdcorpora] |");
  });

  it("is idempotent", () => {
    const entries = fixtureEntries();
    const once = renderReadme(fixtureReadme(), entries);
    expect(renderReadme(once, entries)).toBe(once);
  });

  it("leaves a row with no measurement, and the exempt wild-scan row, exactly as they were", () => {
    const readme = fixtureReadme();
    const entries = fixtureEntries().filter((e) => e.source !== "autoresearch");
    const rendered = renderReadme(readme, [...entries, entry("wild-scan", 99)]);
    for (const label of ["autoresearch", "Wild scan (OpenClaw + Skills.sh + Hermes + ClawHub)"]) {
      const line = readme.split("\n").find((l) => l.startsWith(`| ${label}`));
      expect(line).toBeDefined();
      expect(rendered.split("\n")).toContain(line);
    }
  });

  it("rewrites only the leading recall of a lane-annotated cell and keeps each cell's decimals", () => {
    const rendered = renderReadme(fixtureReadme(), fixtureEntries());
    const skill = rendered.split("\n").find((l) => l.startsWith("| SKILL.md benchmark"));
    const i = fixtureEntries().findIndex((e) => e.source === "skill-benchmark");
    const recall = `${(((i + 1) / 40) * 100).toFixed(1)}%`;
    expect(skill).toBe(
      `| SKILL.md benchmark (internal) [^skilllane] | upstream-2026-10-12 | ${(1000 + i * 37).toLocaleString("en-US")} | ` +
        `${recall} (hunt) / 0.0% (enforce) | 97.0% | 0.40% | 4.1.5 | 2026-10-12 |`,
    );
  });

  it("keeps the padding of cells whose value did not change", () => {
    const readme = [...HEADER, "| atr-self-test |   internal   | 341 | 96.6% | 100.0% | 0.0% | 3.5.12 | 2026-08-15 |", ""].join("\n");
    const e = { ...entry("atr-self-test", 0), source_version: "internal", samples: 341, recall: 0.966 };
    expect(renderReadme(readme, [e]).split("\n")[2]).toBe(
      "| atr-self-test |   internal   | 341 | 96.6% | 100.0% | 0.0% | 4.1.5 | 2026-10-12 |",
    );
  });

  it("renders the committed README into one the citation check accepts", () => {
    const readme = readFileSync(resolve(REPO, "README.md"), "utf8");
    const dataStats = JSON.parse(readFileSync(resolve(REPO, "data", "stats.json"), "utf8"));
    const rootStats = JSON.parse(readFileSync(resolve(REPO, "stats.json"), "utf8"));
    const rendered = renderReadme(readme, dataStats.benchmarks);
    const check = findCitationProblems(rendered, dataStats, renderRootStats(rootStats, dataStats.benchmarks));
    expect(check.fatal).toBeNull();
    expect(check.problems).toEqual([]);
  });
});

describe("renderRootStats", () => {
  it("rewrites the garak and pint keys that exist, adds none, and leaves other blocks alone", () => {
    const entries = fixtureEntries();
    const counts = new Map([["garak", { detected: 610, missed: 40 }]]);
    const out = renderRootStats(ROOT_STATS, entries, counts) as typeof ROOT_STATS;
    const garak = entries.find((e) => e.source === "garak")!;
    expect(out.benchmarks.garak).toEqual({
      recall: Number((garak.recall! * 100).toFixed(1)),
      samples: garak.samples,
      detected: 610,
      missed: 40,
      atr_version: "4.1.5",
      measured: "2026-10-12",
    });
    expect(Object.keys(out.benchmarks.pint)).toEqual(Object.keys(ROOT_STATS.benchmarks.pint));
    expect(out.benchmarks.skill).toBe(ROOT_STATS.benchmarks.skill);
    expect(out.version).toBe("4.1.5");
    expect(ROOT_STATS.benchmarks.garak.atr_version).toBe("3.5.12");
  });
});

// ── CLI against a fixture checkout ────────────────────────────────────────────

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function write(root: string, rel: string, text: string): void {
  mkdirSync(dirname(join(root, rel)), { recursive: true });
  writeFileSync(join(root, rel), text);
}

/** A checkout with a pint measurement newer than what README and stats.json cite. */
function fixtureCheckout(): string {
  const root = mkdtempSync(join(tmpdir(), "render-bench-"));
  dirs.push(root);
  const file = "2026-10-12_pint-v1_atr-4-1-5.json";
  const metrics = { recall: 0.6, precision: 1, f1: 0.75, fp_rate: 0 };
  const base = { source: "pint", source_version: "v1", atr_version: "4.1.5", measured_at: "2026-10-12T12:51:13.373Z", samples: 850 };
  write(root, `data/measurements/pint/${file}`, JSON.stringify({ ...base, metrics, confusion: { tp: 271, fp: 0, tn: 399, fn: 180 } }));
  write(root, "data/measurements/pint/latest.json", JSON.stringify({ ...base, file, metrics }, null, 2) + "\n");
  const projection = projectForStats(aggregateMeasurements(join(root, "data", "measurements")));
  write(root, "data/stats.json", JSON.stringify({ benchmarks: projection.benchmarks }, null, 2) + "\n");
  write(root, "README.md", [...HEADER, staleRow("PINT-format (deepset + Lakera Gandalf)", "pint"), ""].join("\n"));
  write(root, "stats.json", JSON.stringify({ benchmarks: { pint: ROOT_STATS.benchmarks.pint } }, null, 2) + "\n");
  return root;
}

const cli = (root: string, ...args: string[]) =>
  spawnSync(TSX, [SCRIPT, "--root", root, ...args], { cwd: REPO, encoding: "utf8" });

describe("CLI", () => {
  it("--check fails on a stale checkout, a write fixes it, and --check then passes", () => {
    const root = fixtureCheckout();
    expect(cli(root, "--check").status).toBe(1);
    const rendered = cli(root);
    expect(rendered.status, rendered.stderr).toBe(0);
    const check = cli(root, "--check");
    expect(check.status, check.stderr).toBe(0);
    expect(readFileSync(join(root, "README.md"), "utf8")).toContain(
      "| PINT-format (deepset + Lakera Gandalf) [^pint] | v1 | 850 | 60.0% | 100.0% | 0.0% | 4.1.5 | 2026-10-12 |",
    );
    expect(JSON.parse(readFileSync(join(root, "stats.json"), "utf8")).benchmarks.pint).toMatchObject({
      recall: 60,
      atr_version: "4.1.5",
      measured: "2026-10-12",
    });
  });

  it("refuses to render when data/stats.json is not the projection of latest.json", () => {
    const root = fixtureCheckout();
    write(root, "data/stats.json", '{ "benchmarks": [] }\n');
    const before = readFileSync(join(root, "README.md"), "utf8");
    const res = cli(root);
    expect(res.status).toBe(2);
    expect(res.stderr).toMatch(/sync-stats-from-measurements/);
    expect(readFileSync(join(root, "README.md"), "utf8")).toBe(before);
  });

  it("reports what rendering cannot fix without blocking the write", () => {
    const root = fixtureCheckout();
    const result = renderRepo(root);
    // The fixture README has only the pint row; the checker wants every mapped source.
    expect(result.residual.some((p) => /has no row for "garak"/.test(p))).toBe(true);
    expect(result.readme.after).not.toBe(result.readme.before);
  });
});
