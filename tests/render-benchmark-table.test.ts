/**
 * Tests for scripts/render-benchmark-table.ts — re-rendering README's benchmark
 * table and root stats.json's garak / pint / skill citations from latest.json.
 *
 * The weekly measure-all PR (#656) failed check-benchmark-citations.ts with 45
 * mismatches because nothing regenerated README. What matters here is that the
 * rendered documents pass that exact check, and that nothing outside the
 * measured cells moves: these are public numbers, and a renderer that rewrote
 * a label, a footnote or a lane annotation would be a new way to get them wrong.
 *
 * The converse matters as much: a figure no measurement backs must never pick
 * up a new version stamp. A re-stamped block or row either recomputes each
 * version-bound value from the measurement or drops it.
 */
import { describe, it, expect, afterEach } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import {
  type BenchmarkEntry,
  EXEMPT_SOURCES,
  LABEL_TO_SOURCE,
  checkRecallCell,
  enforceRecallBySource,
  findCitationProblems,
  pctLane,
} from "../scripts/check-benchmark-citations.js";
import {
  DROPPABLE_FIELDS,
  renderReadme,
  renderReadmeDetailed,
  renderRootStats,
  renderRepo,
} from "../scripts/render-benchmark-table.js";
import { findProseToReview, formatReviewNotes } from "../scripts/lib/benchmark-review-notes.js";
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

const SKILL_LABEL = "SKILL.md benchmark (internal) [^skilllane]";

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

const pctOf = (n: number) => `${(n * 100).toFixed(1)}%`;
const fixtureEntry = (source: string) => fixtureEntries().find((e) => e.source === source)!;

/**
 * Each fixture source's enforce-lane recall, as breakdown.enforce_lane records
 * it: a tenth of its hunt figure, so the two can never be confused, and 0 for
 * SKILL.md, which is what the enforce lane scores there.
 */
function fixtureEnforce(): Map<string, number> {
  return new Map(
    fixtureEntries().map((e) => [e.source, e.source === "skill-benchmark" ? 0 : e.recall! / 10] as [string, number]),
  );
}

/**
 * Honesty disclosures outward material relies on. They describe the corpus or
 * the method, not a run, so no render may drop or reword them. The em dash and
 * quotes make a byte-level change visible.
 */
const PINT_DISCLAIMER =
  "NOT a run of Lakera's official PINT benchmark, whose corpus is private and roughly 5x larger.";
const PINT_CAVEAT = "This corpus exercises only the prompt-injection rule family. It is not a measure of overall coverage.";
const SKILL_CAVEAT =
  "The enforce (auto-block) lane loads only maturity: stable. Quoting this recall without the lane sets a wrong expectation for enforce deployments — \"hunt\" is the default.";

/** Root stats.json as it stood at 3.5.12, with the fields that cannot be re-measured. */
const ROOT_STATS = {
  version: "4.1.5",
  benchmarks: {
    garak: {
      recall: 92.3,
      samples: 650,
      source: "NVIDIA garak in-the-wild jailbreak corpus",
      perFamily: { latentinjection: 34.4, syspromptExtraction: 96.4, dan: 92.5 },
      detected: 600,
      missed: 50,
      atr_version: "3.5.12",
      measured: "2026-08-15",
    },
    skill: {
      recall: 100,
      precision: 97,
      fpRate: 0.2,
      samples: 498,
      source: "Internal labeled SKILL.md corpus",
      lane: "hunt",
      caveat: SKILL_CAVEAT,
      enforceLaneRecall: 0,
      enforceLaneNote: "detects 0 of 32 malicious samples",
      atr_version: "3.5.12",
      measured: "2026-08-15",
    },
    pint: {
      recall: 65.4,
      precision: 100,
      fpRate: 0,
      samples: 850,
      detected: 295,
      missed: 156,
      atr_version: "3.5.12",
      measured: "2026-08-15",
      tiers: ["tier2-regex", "tier2.5-embedding"],
      source: "Self-built 850-sample PINT-FORMAT corpus",
      notOfficialPint: true,
      disclaimer: PINT_DISCLAIMER,
      caveat: PINT_CAVEAT,
      comment: "62 of 784 rules fire on it and ATR-2026-00001 accounts for 226 of the 295 detections.",
    },
    hackaprompt: { recall: 69.6, samples: 4780 },
  },
};

type Blocks = typeof ROOT_STATS.benchmarks;
const blocksOf = (stats: Record<string, unknown>) => stats.benchmarks as Blocks;

/** garak-full's per-family recall at the same ATR version as garak's run. */
const GARAK_FULL_DETAIL = new Map([
  ["garak-full", { byFamily: { latentinjection: 0.3, sysprompt_extraction: 0.9, dan: 0.95, gcg: 0.1 } }],
]);

const tableLineNos = (readme: string): Set<number> => {
  const lines = readme.split("\n");
  const start = lines.indexOf(HEADER[0]) + 2;
  return new Set(lines.map((_, i) => i).filter((i) => i >= start && lines[i].startsWith("|")));
};

describe("renderReadme", () => {
  it("produces a README and stats.json the citation check accepts, from ones it rejects", () => {
    const readme = fixtureReadme();
    const entries = fixtureEntries();
    const enforce = fixtureEnforce();
    const before = findCitationProblems(readme, { benchmarks: entries }, ROOT_STATS, enforce);
    expect(before.problems.length).toBeGreaterThan(0);

    const rendered = renderReadme(readme, entries, enforce);
    const rootStats = renderRootStats(ROOT_STATS, entries, GARAK_FULL_DETAIL, enforce).stats;
    const after = findCitationProblems(rendered, { benchmarks: entries }, rootStats, enforce);
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
    const enforce = enforceRecallBySource(REPO, dataStats.benchmarks);
    const rendered = renderReadme(readme, dataStats.benchmarks, enforce);
    const check = findCitationProblems(
      rendered,
      dataStats,
      renderRootStats(rootStats, dataStats.benchmarks, new Map(), enforce).stats,
      enforce,
    );
    expect(check.fatal).toBeNull();
    expect(check.problems).toEqual([]);
  });

  it("is already rendered: the committed README and stats.json cite every enforce figure the measurements record", () => {
    const readme = readFileSync(resolve(REPO, "README.md"), "utf8");
    const dataStats = JSON.parse(readFileSync(resolve(REPO, "data", "stats.json"), "utf8"));
    const rootStats = JSON.parse(readFileSync(resolve(REPO, "stats.json"), "utf8"));
    const enforce = enforceRecallBySource(REPO, dataStats.benchmarks);
    expect(enforce.size).toBeGreaterThan(0);
    const check = findCitationProblems(readme, dataStats, rootStats, enforce);
    expect(check.problems).toEqual([]);
  });
});

describe("lane figures no measurement backs", () => {
  it("drops a second lane's figure when the row is re-stamped, keeping the measured lane's annotation", () => {
    const rendered = renderReadme(fixtureReadme(), fixtureEntries());
    const skill = rendered.split("\n").find((l) => l.startsWith(`| ${SKILL_LABEL}`));
    const e = fixtureEntry("skill-benchmark");
    expect(skill).toBe(
      `| ${SKILL_LABEL} | upstream-2026-10-12 | ${e.samples.toLocaleString("en-US")} | ` +
        `${pctOf(e.recall!)} (hunt) | 97.0% | 0.40% | 4.1.5 | 2026-10-12 |`,
    );
  });

  it("keeps a second lane's figure while the row's stamp does not move", () => {
    const row = `| ${SKILL_LABEL} | internal-498 | 498 | 100.0% (hunt) / 0.0% (enforce) | 97.0% | 0.20% | 3.5.12 | 2026-08-15 |`;
    const readme = [...HEADER, row, ""].join("\n");
    const e: BenchmarkEntry = {
      source: "skill-benchmark",
      source_version: "internal-498",
      atr_version: "3.5.12",
      measured_at: "2026-08-15",
      samples: 498,
      recall: 1,
      precision: 0.97,
      fp_rate: 0.002,
    };
    expect(renderReadme(readme, [e])).toBe(readme);
  });

  it("re-stamps the root skill block with the README row, recomputing its enforce figure and dropping the note", () => {
    const entries = fixtureEntries();
    const { stats, dropped } = renderRootStats(ROOT_STATS, entries, GARAK_FULL_DETAIL, fixtureEnforce());
    const e = fixtureEntry("skill-benchmark");
    expect(blocksOf(stats).skill).toEqual({
      recall: Number((e.recall! * 100).toFixed(1)),
      precision: 97,
      fpRate: 0.4,
      samples: e.samples,
      source: ROOT_STATS.benchmarks.skill.source,
      lane: "hunt",
      caveat: SKILL_CAVEAT,
      enforceLaneRecall: 0,
      atr_version: "4.1.5",
      measured: "2026-10-12",
    });
    expect(dropped).toContain("benchmarks.skill.enforceLaneNote");
    expect(dropped).not.toContain("benchmarks.skill.enforceLaneRecall");
    const row = renderReadme(fixtureReadme(), entries)
      .split("\n")
      .find((l) => l.startsWith(`| ${SKILL_LABEL}`))!;
    expect(row.split("|")[7].trim()).toBe(blocksOf(stats).skill.atr_version);
  });
});

describe("enforce-lane figures", () => {
  const GARAK_LABEL = "garak (in-the-wild jailbreaks)";
  const garak: BenchmarkEntry = {
    source: "garak",
    source_version: "inthewild-jailbreak-corpus-650",
    atr_version: "4.1.5",
    measured_at: "2026-10-15",
    samples: 650,
    recall: 600 / 650,
    precision: 1,
    fp_rate: 0,
  };
  const ENFORCE = new Map([["garak", 6 / 650]]);
  const garakRow = (recall: string, stamp = "4.1.5 | 2026-10-15") =>
    `| ${GARAK_LABEL} | inthewild-jailbreak-corpus-650 | 650 | ${recall} | 100.0% | 0.0% | ${stamp} |`;
  const table = (...rows: string[]) => [...HEADER, ...rows, ""].join("\n");

  describe("checkRecallCell", () => {
    it("accepts the hunt figure first and the recorded enforce figure second", () => {
      expect(checkRecallCell("92.3% (hunt) / 0.9% (enforce)", 600 / 650, 6 / 650)).toBeNull();
    });

    it("rejects an enforce figure that differs from the recorded one", () => {
      expect(checkRecallCell("92.3% (hunt) / 1.5% (enforce)", 600 / 650, 6 / 650)).toMatch(/enforce lane.*0\.9%/);
    });

    it("rejects a hunt figure quoted alone once the measurement records the enforce lane", () => {
      expect(checkRecallCell("92.3%", 600 / 650, 6 / 650)).toMatch(/omits the enforce-lane figure/);
      expect(checkRecallCell("92.3% (hunt)", 600 / 650, 6 / 650)).toMatch(/omits the enforce-lane figure/);
    });

    it("rejects an enforce figure no measurement records", () => {
      expect(checkRecallCell("100.0% (hunt) / 0.0% (enforce)", 1, null)).toMatch(/records none/);
      // A cell with no enforce figure is fine while nothing records one.
      expect(checkRecallCell("100.0%", 1, null)).toBeNull();
    });

    it("rejects a leading figure labelled with another lane, and a lane no run measures", () => {
      expect(checkRecallCell("92.3% (enforce) / 0.9% (hunt)", 600 / 650, 6 / 650)).toMatch(/hunt/);
      expect(checkRecallCell("92.3% (hunt) / 50.0% (alert)", 600 / 650, 6 / 650)).toMatch(/alert/);
    });

    it("never reads a non-zero enforce figure as zero", () => {
      expect(pctLane(0)).toBe("0.0%");
      expect(pctLane(6 / 650)).toBe("0.9%");
      expect(pctLane(1 / 3475)).toBe("0.03%");
      expect(pctLane(3474 / 3475)).toBe("99.97%");
      expect(checkRecallCell("57.2% (hunt) / 0.0% (enforce)", 0.572, 1 / 3475)).toMatch(/0\.03%/);
      expect(checkRecallCell("57.2% (hunt) / 0.03% (enforce)", 0.572, 1 / 3475)).toBeNull();
    });
  });

  it("renders the recorded enforce figure beside the hunt figure", () => {
    expect(renderReadme(table(garakRow("92.3%", "4.1.5 | 2026-10-14")), [garak], ENFORCE).split("\n")[2]).toBe(
      garakRow("92.3% (hunt) / 0.9% (enforce)"),
    );
  });

  it("adds the enforce figure even when the row's stamp does not move", () => {
    expect(renderReadme(table(garakRow("92.3%")), [garak], ENFORCE).split("\n")[2]).toBe(
      garakRow("92.3% (hunt) / 0.9% (enforce)"),
    );
  });

  it("keeps footnote markers and replaces any other wording in the recall cell", () => {
    const skill: BenchmarkEntry = { ...garak, source: "skill-benchmark", source_version: "internal-498", samples: 498, recall: 1, precision: 0.97, fp_rate: 0.002 };
    const row = `| ${SKILL_LABEL} | internal-498 | 498 | 100.0% (hunt); not an enforce figure [^skilllane] | 97.0% (hunt) | 0.20% (hunt) | 4.1.5 | 2026-10-14 |`;
    expect(renderReadme(table(row), [skill], new Map([["skill-benchmark", 0]])).split("\n")[2]).toBe(
      `| ${SKILL_LABEL} | internal-498 | 498 | 100.0% (hunt) / 0.0% (enforce) [^skilllane] | 97.0% (hunt) | 0.20% (hunt) | 4.1.5 | 2026-10-15 |`,
    );
  });

  it("is idempotent, and its output passes the citation check", () => {
    const entries = fixtureEntries();
    const enforce = fixtureEnforce();
    const once = renderReadme(fixtureReadme(), entries, enforce);
    expect(renderReadme(once, entries, enforce)).toBe(once);
    const rootStats = renderRootStats(ROOT_STATS, entries, GARAK_FULL_DETAIL, enforce).stats;
    expect(findCitationProblems(once, { benchmarks: entries }, rootStats, enforce).problems).toEqual([]);
  });

  it("leaves a row whose measurement records no enforce figure as it was", () => {
    const row = garakRow("92.3%");
    expect(renderReadme(table(row), [garak], new Map()).split("\n")[2]).toBe(row);
  });

  it("fails the check when a row quotes the hunt figure alone beside a recorded enforce figure", () => {
    const check = findCitationProblems(table(garakRow("92.3%")), { benchmarks: [garak] }, ROOT_STATS, ENFORCE);
    expect(check.problems.join("\n")).toMatch(/garak.*omits the enforce-lane figure/);
  });

  describe("root stats.json", () => {
    const withEnforce = {
      ...ROOT_STATS,
      benchmarks: {
        ...ROOT_STATS.benchmarks,
        garak: { ...ROOT_STATS.benchmarks.garak, enforceLaneRecall: 50 },
        pint: { ...ROOT_STATS.benchmarks.pint, enforceLaneRecall: 50 },
      },
    };

    it("recomputes every enforceLaneRecall it cites, never rounding a non-zero figure to 0", () => {
      const enforce = new Map([...fixtureEnforce(), ["pint", 1 / 3475]]);
      const { stats, held } = renderRootStats(withEnforce, fixtureEntries(), GARAK_FULL_DETAIL, enforce);
      expect(held).toEqual([]);
      expect(blocksOf(stats).garak).toMatchObject({ enforceLaneRecall: Number((enforce.get("garak")! * 100).toFixed(1)) });
      expect((blocksOf(stats).pint as Record<string, unknown>).enforceLaneRecall).toBe(0.03);
      expect((blocksOf(stats).skill as Record<string, unknown>).enforceLaneRecall).toBe(0);
    });

    it("adds the recorded enforce figure, right after recall, to a block that does not cite one yet", () => {
      const enforce = fixtureEnforce();
      const { stats } = renderRootStats(ROOT_STATS, fixtureEntries(), GARAK_FULL_DETAIL, enforce);
      const garak = blocksOf(stats).garak as Record<string, unknown>;
      expect(garak.enforceLaneRecall).toBe(Number((enforce.get("garak")! * 100).toFixed(1)));
      const keys = Object.keys(garak);
      expect(keys.indexOf("enforceLaneRecall")).toBe(keys.indexOf("recall") + 1);
      // ...and nothing when the measurement records none.
      const { stats: none } = renderRootStats(ROOT_STATS, fixtureEntries(), GARAK_FULL_DETAIL, new Map());
      expect(blocksOf(none).garak).not.toHaveProperty("enforceLaneRecall");
    });

    it("fails the check when stats.json leaves out an enforce figure the measurement records", () => {
      const check = findCitationProblems(
        renderReadme(fixtureReadme(), fixtureEntries(), fixtureEnforce()),
        { benchmarks: fixtureEntries() },
        ROOT_STATS,
        fixtureEnforce(),
      );
      expect(check.problems.join("\n")).toMatch(/benchmarks\.garak omits enforceLaneRecall/);
    });

    it("holds a block whose enforce figure this run's measurement does not record, and says why", () => {
      const { stats, held } = renderRootStats(withEnforce, fixtureEntries(), GARAK_FULL_DETAIL, new Map());
      expect(blocksOf(stats).garak).toEqual(withEnforce.benchmarks.garak);
      expect(held.join("\n")).toMatch(/benchmarks\.garak.*enforceLaneRecall/);
    });

    it("fails the check on an enforce figure that disagrees with the measurement, or that none records", () => {
      const entries = fixtureEntries();
      const readme = renderReadme(fixtureReadme(), entries, fixtureEnforce());
      const rendered = renderRootStats(withEnforce, entries, GARAK_FULL_DETAIL, fixtureEnforce()).stats;
      expect(findCitationProblems(readme, { benchmarks: entries }, rendered, fixtureEnforce()).problems).toEqual([]);
      const wrong = { benchmarks: { ...blocksOf(rendered), garak: { ...blocksOf(rendered).garak, enforceLaneRecall: 12.5 } } };
      expect(findCitationProblems(readme, { benchmarks: entries }, wrong, fixtureEnforce()).problems.join("\n")).toMatch(
        /benchmarks\.garak\.enforceLaneRecall = 12\.5/,
      );
      const unrecorded = new Map([...fixtureEnforce()].filter(([k]) => k !== "pint"));
      const problems = findCitationProblems(readme, { benchmarks: entries }, rendered, unrecorded).problems.join("\n");
      expect(problems).toMatch(/benchmarks\.pint\.enforceLaneRecall.*records no enforce/);
    });
  });
});

describe("renderRootStats", () => {
  it("recomputes garak.perFamily from garak-full measured at the same ATR version", () => {
    const { stats, dropped } = renderRootStats(ROOT_STATS, fixtureEntries(), GARAK_FULL_DETAIL);
    expect(blocksOf(stats).garak.perFamily).toEqual({ latentinjection: 30, syspromptExtraction: 90, dan: 95 });
    expect(dropped).not.toContain("benchmarks.garak.perFamily");
  });

  it("drops garak.perFamily when garak-full was not measured at the version garak is stamped with", () => {
    const entries = fixtureEntries().map((e) => (e.source === "garak-full" ? { ...e, atr_version: "4.1.4" } : e));
    const { stats, dropped } = renderRootStats(ROOT_STATS, entries, GARAK_FULL_DETAIL);
    expect(blocksOf(stats).garak).not.toHaveProperty("perFamily");
    expect(blocksOf(stats).garak.atr_version).toBe("4.1.5");
    expect(dropped).toContain("benchmarks.garak.perFamily");
  });

  it("drops pint.comment on re-stamp, keeps the descriptors, and recomputes the rest", () => {
    const counts = new Map([["pint", { detected: 271, missed: 180 }]]);
    const { stats, dropped } = renderRootStats(ROOT_STATS, fixtureEntries(), counts);
    const pint = blocksOf(stats).pint;
    expect(pint).not.toHaveProperty("comment");
    expect(dropped).toContain("benchmarks.pint.comment");
    expect(pint.tiers).toEqual(ROOT_STATS.benchmarks.pint.tiers);
    expect(pint.notOfficialPint).toBe(true);
    expect(pint.source).toBe(ROOT_STATS.benchmarks.pint.source);
    expect(pint).toMatchObject({ detected: 271, missed: 180, atr_version: "4.1.5", measured: "2026-10-12" });
    const { comment: _comment, ...rest } = ROOT_STATS.benchmarks.pint;
    expect(Object.keys(pint)).toEqual(Object.keys(rest));
  });

  it("keeps every block's disclaimer and caveat byte-for-byte through a re-stamp", () => {
    const { stats, dropped } = renderRootStats(ROOT_STATS, fixtureEntries(), GARAK_FULL_DETAIL);
    expect(blocksOf(stats).pint.disclaimer).toBe(PINT_DISCLAIMER);
    expect(blocksOf(stats).pint.caveat).toBe(PINT_CAVEAT);
    expect(blocksOf(stats).pint.notOfficialPint).toBe(true);
    expect(blocksOf(stats).skill.caveat).toBe(SKILL_CAVEAT);
    expect(blocksOf(stats).pint.atr_version).toBe("4.1.5");
    expect(dropped.filter((d) => /\.(disclaimer|caveat|notOfficialPint)$/.test(d))).toEqual([]);
  });

  it("keeps the lane descriptor on garak, pint and skill through a re-stamp", () => {
    // Each block's recall is the hunt lane; the label must survive every weekly
    // re-stamp, or a block carrying it would be held as holding an unknown field.
    const labelled = {
      ...ROOT_STATS,
      benchmarks: {
        ...ROOT_STATS.benchmarks,
        garak: { ...ROOT_STATS.benchmarks.garak, lane: "hunt" },
        pint: { ...ROOT_STATS.benchmarks.pint, lane: "hunt" },
      },
    };
    const { stats, held } = renderRootStats(labelled, fixtureEntries(), GARAK_FULL_DETAIL, fixtureEnforce());
    expect(held).toEqual([]);
    for (const block of ["garak", "pint", "skill"] as const) {
      expect((blocksOf(stats)[block] as Record<string, unknown>).lane).toBe("hunt");
      expect(blocksOf(stats)[block].atr_version).toBe("4.1.5");
    }
  });

  it("keeps a disclaimer on any rendered block, even one it was never written for", () => {
    const garak = { ...ROOT_STATS.benchmarks.garak, disclaimer: "Not NVIDIA's own garak scoring." };
    const withGarak = { ...ROOT_STATS, benchmarks: { ...ROOT_STATS.benchmarks, garak } };
    // The fixture's skill block cites an enforce figure, so this run records one.
    const { stats, held } = renderRootStats(withGarak, fixtureEntries(), GARAK_FULL_DETAIL, fixtureEnforce());
    expect(held).toEqual([]);
    expect((blocksOf(stats).garak as typeof garak).disclaimer).toBe("Not NVIDIA's own garak scoring.");
    expect(blocksOf(stats).garak.atr_version).toBe("4.1.5");
  });

  it("keeps the committed PINT disclaimer and the skill lane caveat when the next run re-stamps them", () => {
    const committed = JSON.parse(readFileSync(resolve(REPO, "stats.json"), "utf8")) as Record<string, unknown>;
    const pint = blocksOf(committed).pint;
    expect(pint.disclaimer).toBe(PINT_DISCLAIMER);
    expect(pint.notOfficialPint).toBe(true);
    const next = (source: string, samples: number, recall: number): BenchmarkEntry => ({
      source,
      source_version: "next",
      atr_version: "99.0.0",
      measured_at: "2099-01-01",
      samples,
      recall,
      precision: 1,
      fp_rate: 0,
    });
    const enforce = new Map([
      ["pint", 0.01],
      ["skill-benchmark", 0],
      ["garak", 0.009],
    ]);
    const { stats } = renderRootStats(
      committed,
      [next("pint", 850, 0.6), next("skill-benchmark", 498, 1), next("garak", 650, 0.9)],
      new Map(),
      enforce,
    );
    expect(blocksOf(stats).pint.disclaimer).toBe(pint.disclaimer);
    expect(blocksOf(stats).pint.caveat).toBe(pint.caveat);
    expect(blocksOf(stats).pint.notOfficialPint).toBe(true);
    expect(blocksOf(stats).pint).not.toHaveProperty("comment");
    expect(blocksOf(stats).skill.caveat).toBe(blocksOf(committed).skill.caveat);
    expect(typeof blocksOf(stats).skill.caveat).toBe("string");
    expect(blocksOf(stats).skill).not.toHaveProperty("enforceLaneNote");
    // Each enforce figure the committed file cites is re-derived from the run, never carried over.
    for (const [block, source] of [["garak", "garak"], ["pint", "pint"], ["skill", "skill-benchmark"]] as const) {
      if ((blocksOf(committed)[block] as Record<string, unknown>).enforceLaneRecall === undefined) continue;
      expect((blocksOf(stats)[block] as Record<string, unknown>).enforceLaneRecall).toBe(
        Number((enforce.get(source)! * 100).toFixed(1)),
      );
    }
  });

  it("keeps every field while the stamp does not move", () => {
    const pintAt3512: BenchmarkEntry = {
      source: "pint",
      source_version: "v1",
      atr_version: "3.5.12",
      measured_at: "2026-08-15",
      samples: 850,
      recall: 0.6541019955654102,
      precision: 1,
      fp_rate: 0,
    };
    const { stats, dropped } = renderRootStats(ROOT_STATS, [pintAt3512]);
    expect(blocksOf(stats).pint).toEqual(ROOT_STATS.benchmarks.pint);
    expect(dropped).toEqual([]);
  });

  it("does not re-stamp a block holding a field it has no rule for, and says why", () => {
    const withExtra = {
      ...ROOT_STATS,
      benchmarks: { ...ROOT_STATS.benchmarks, garak: { ...ROOT_STATS.benchmarks.garak, newFigure: 12.5 } },
    };
    const { stats, held } = renderRootStats(withExtra, fixtureEntries(), GARAK_FULL_DETAIL);
    expect(blocksOf(stats).garak).toEqual(withExtra.benchmarks.garak);
    expect(held.join("\n")).toMatch(/benchmarks\.garak.*newFigure/);
  });

  it("leaves blocks it does not render, and the input object, untouched", () => {
    const { stats } = renderRootStats(ROOT_STATS, fixtureEntries(), GARAK_FULL_DETAIL);
    expect(blocksOf(stats).hackaprompt).toBe(ROOT_STATS.benchmarks.hackaprompt);
    expect((stats as typeof ROOT_STATS).version).toBe("4.1.5");
    expect(ROOT_STATS.benchmarks.garak.atr_version).toBe("3.5.12");
    expect(ROOT_STATS.benchmarks.pint.comment).toBeDefined();
  });

  // Dropping is only safe while nothing reads these fields. If this fails,
  // something started reading one: recompute it from a measurement instead.
  it.skipIf(spawnSync("git", ["rev-parse"], { cwd: REPO }).status !== 0)(
    "drops only fields no tracked code reads",
    () => {
      // A distinctive camelCase name is searched alone; a common word only as
      // `<block>.<field>`, or "precision" would match half the repo.
      const distinctive = (f: string) => /[A-Z]/.test(f) && f.length > 8;
      const patterns = [...DROPPABLE_FIELDS].flatMap(([block, fields]) =>
        fields.map((f) => (distinctive(f) ? `\\b${f}\\b` : `\\b${block}\\??\\.${f}\\b`)),
      );
      // An empty alternation would match every line and prove nothing.
      expect(patterns.length).toBeGreaterThan(0);
      const res = spawnSync(
        "git",
        ["grep", "-n", "-I", "-E", patterns.join("|"), "--", ".", ":!data/**", ":!tests/**", ":!*.md", ":!*.json", ":!*.jsonl", ":!scripts/render-benchmark-table.ts"],
        { cwd: REPO, encoding: "utf8" },
      );
      expect(res.status, res.stdout).toBe(1);
    },
  );
});

describe("rounding", () => {
  const row = "| atr-self-test | internal | 341 | 96.6% | 100.0% | 0.0% | 3.5.12 | 2026-08-15 |";
  const e: BenchmarkEntry = {
    source: "atr-self-test",
    source_version: "internal",
    atr_version: "4.1.5",
    measured_at: "2026-10-12",
    samples: 341,
    recall: 0.966,
    precision: 0.9996,
    fp_rate: 0.0004,
  };

  it("never writes a non-zero rate as zero, or a precision below one as 100%", () => {
    expect(renderReadme([...HEADER, row, ""].join("\n"), [e]).split("\n")[2]).toBe(
      "| atr-self-test | internal | 341 | 96.6% | 99.96% | 0.04% | 4.1.5 | 2026-10-12 |",
    );
  });

  it("applies the same rule to stats.json", () => {
    const pint: BenchmarkEntry = { ...e, source: "pint", precision: 0.9996, fp_rate: 0.00004, recall: 0.6 };
    const { stats } = renderRootStats(ROOT_STATS, [pint]);
    expect(blocksOf(stats).pint).toMatchObject({ precision: 99.96, fpRate: 0.004 });
  });
});

describe("README prose to review", () => {
  const readme = [
    "# ATR", // 1
    "", // 2
    "## 7. Coverage", // 3
    "", // 4
    "Coverage prose citing ATR 3.5.0 and 12.3% is another section.", // 5
    "", // 6
    "## 8. Evaluation", // 7
    "", // 8
    "Intro with no figures.", // 9
    "", // 10
    ...HEADER, // 11, 12
    "| PINT-format (deepset + Lakera Gandalf) [^pint] | v1 | 850 | 60.0% | 100.0% | 0.0% | 4.1.5 | 2026-10-12 |", // 13
    "| atr-self-test [^far] | internal | 341 | 96.6% | 100.0% | 0.0% | 4.1.5 | 2026-10-12 |", // 14
    "", // 15
    "All corpora were measured against ATR 3.5.0 on 2026-06-16.", // 16
    "The garak trend ends at 92.3% (3.5.12).", // 17
    "A line with no figure at all.", // 18
    "", // 19
    "[^pint]: The row moved 63.6% → 65.4%", // 20
    "    between releases.", // 21
    "", // 22
    "### 8.1 Method", // 23
    "", // 24
    "Subsection prose citing 40.0% belongs to the section.", // 25
    "", // 26
    "## 9. Governance", // 27
    "", // 28
    "Governance prose citing 3.5.0.", // 29
    "", // 30
    "[^far]: A footnote far from the table, citing 41.0%.", // 31
    "[^unused]: Not referenced by the table, citing 42.0%.", // 32
    "",
  ].join("\n");

  it("lists the section's and the referenced footnotes' lines that cite a version or a percentage", () => {
    const lines = findProseToReview(readme, ["3.5.0", "65.4%"]);
    expect(lines.map((l) => l.lineNo)).toEqual([16, 17, 20, 25, 31]);
    expect(lines.filter((l) => l.citesReplaced).map((l) => l.lineNo)).toEqual([16, 20]);
    expect(lines[0].text).toBe("All corpora were measured against ATR 3.5.0 on 2026-06-16.");
  });

  it("formats notes for the PR body, and nothing when there is nothing to check", () => {
    const notes = formatReviewNotes({
      prose: findProseToReview(readme, ["3.5.0"]),
      dropped: ["benchmarks.pint.comment"],
      held: [],
    });
    expect(notes).toMatch(/^- README\.md:16 — All corpora were measured against ATR 3\.5\.0 on 2026-06-16\.$/m);
    expect(notes).toMatch(/README\.md:31/);
    expect(notes).toMatch(/benchmarks\.pint\.comment/);
    expect(formatReviewNotes({ prose: [], dropped: [], held: [] })).toBe("");
  });

  it("collects the values a render replaced, so the lines citing them come first", () => {
    const { replaced } = renderReadmeDetailed(fixtureReadme(), fixtureEntries());
    expect(replaced).toEqual(expect.arrayContaining(["3.5.0", "3.5.12", "2026-06-16", "12.3%", "0.20%"]));
    // The exempt wild-scan row is never rendered, so nothing of it is replaced.
    expect(replaced).not.toContain("1.42%");
    expect(replaced).not.toContain("2.0.0");
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
function fixtureCheckout(opts: { enforceDetected?: number } = {}): string {
  const root = mkdtempSync(join(tmpdir(), "render-bench-"));
  dirs.push(root);
  const file = "2026-10-12_pint-v1_atr-4-1-5.json";
  const metrics = { recall: 0.6, precision: 1, f1: 0.75, fp_rate: 0 };
  const base = { source: "pint", source_version: "v1", atr_version: "4.1.5", measured_at: "2026-10-12T12:51:13.373Z", samples: 850 };
  const breakdown =
    opts.enforceDetected === undefined
      ? {}
      : {
          breakdown: {
            enforce_lane: {
              lane: "enforce",
              detected: opts.enforceDetected,
              attacks: 451,
              recall: opts.enforceDetected / 451,
              rules_in_lane: 103,
              note: "fixture",
            },
          },
        };
  write(
    root,
    `data/measurements/pint/${file}`,
    JSON.stringify({ ...base, metrics, confusion: { tp: 271, fp: 0, tn: 399, fn: 180 }, ...breakdown }),
  );
  write(root, "data/measurements/pint/latest.json", JSON.stringify({ ...base, file, metrics }, null, 2) + "\n");
  const projection = projectForStats(aggregateMeasurements(join(root, "data", "measurements")));
  write(root, "data/stats.json", JSON.stringify({ benchmarks: projection.benchmarks }, null, 2) + "\n");
  write(
    root,
    "README.md",
    ["## 8. Evaluation", "", ...HEADER, staleRow("PINT-format (deepset + Lakera Gandalf)", "pint"), "", "Measured against ATR 3.5.0.", ""].join("\n"),
  );
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
      detected: 271,
      missed: 180,
      atr_version: "4.1.5",
      measured: "2026-10-12",
    });
  });

  it("renders the enforce figure a measurement records into README and stats.json, then --check passes", () => {
    const root = fixtureCheckout({ enforceDetected: 9 });
    const stats = JSON.parse(readFileSync(join(root, "stats.json"), "utf8"));
    stats.benchmarks.pint.enforceLaneRecall = 0;
    write(root, "stats.json", JSON.stringify(stats, null, 2) + "\n");
    const rendered = cli(root);
    expect(rendered.status, rendered.stderr).toBe(0);
    expect(readFileSync(join(root, "README.md"), "utf8")).toContain(
      "| PINT-format (deepset + Lakera Gandalf) [^pint] | v1 | 850 | 60.0% (hunt) / 2.0% (enforce) | 100.0% | 0.0% | 4.1.5 | 2026-10-12 |",
    );
    expect(JSON.parse(readFileSync(join(root, "stats.json"), "utf8")).benchmarks.pint.enforceLaneRecall).toBe(2);
    const check = cli(root, "--check");
    expect(check.status, check.stderr).toBe(0);
  });

  it("writes the disclaimer's stats.json line back byte-for-byte", () => {
    const root = fixtureCheckout();
    const before = readFileSync(join(root, "stats.json"), "utf8");
    const line = before.split("\n").find((l) => l.includes('"disclaimer"'));
    expect(line).toBeDefined();
    expect(cli(root).status).toBe(0);
    const after = readFileSync(join(root, "stats.json"), "utf8");
    expect(after).not.toBe(before);
    expect(after.split("\n")).toContain(line);
  });

  it("writes review notes when it changed README, and an empty file when it did not", () => {
    const root = fixtureCheckout();
    const notes = join(root, "review.md");
    expect(cli(root, "--review-notes", notes).status).toBe(0);
    const text = readFileSync(notes, "utf8");
    expect(text).toMatch(/README\.md:7 — Measured against ATR 3\.5\.0\./);
    expect(text).toMatch(/benchmarks\.pint\.comment/);
    expect(cli(root, "--review-notes", notes).status).toBe(0);
    expect(existsSync(notes) && readFileSync(notes, "utf8")).toBe("");
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
