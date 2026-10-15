/**
 * How the site quotes a recall figure.
 *
 * Recall depends on the detection lane. A measurement's headline
 * (`metrics.recall`) is the hunt lane: the engine default, which loads every
 * rule maturity. `breakdown.enforce_lane` is the same attack samples through
 * the same loop on an engine that loads only stable rules, the lane to run
 * with blocking on. At ATR 4.1.5 the garak corpus scored 600/650 in the first
 * and 6/650 in the second, so a hunt figure quoted alone tells anyone who
 * deploys blocking the opposite of the truth.
 *
 * Every page therefore takes its figures from lib/stats.ts `benchmarks` (the
 * measurement files) through these helpers, never as typed numbers, and quotes
 * both lanes wherever the measurement records both. The formats match README's
 * table: one decimal for the hunt figure; for the enforce figure, as many as it
 * takes for a non-zero rate never to read 0%.
 */
import type { BenchmarkMeasurement, SiteStats } from "./stats";

/** README section 8: the lanes, and the footnotes behind each closed-book note. */
export const EVALUATION_URL = "https://github.com/Agent-Threat-Rule/agent-threat-rules#8-evaluation";

/** The measurement for `source`, or null when there is none (the page then shows no figure). */
export function findBenchmark(stats: Pick<SiteStats, "benchmarks">, source: string): BenchmarkMeasurement | null {
  return stats.benchmarks.find((b) => b.source === source) ?? null;
}

const MAX_DECIMALS = 8;

/** Mirrors scripts/check-benchmark-citations.ts decimalsFor. */
function decimalsFor(value: number, min: number): number {
  const shown = (d: number) => Number((value * 100).toFixed(d));
  let d = min;
  while (d < MAX_DECIMALS && ((value !== 0 && shown(d) === 0) || (value !== 1 && shown(d) === 100))) d += 1;
  return d;
}

/** A hunt-lane recall, as README prints it: `0.923` -> `92.3%`. */
export const pctHunt = (fraction: number): string => `${(fraction * 100).toFixed(1)}%`;

/** Any other rate: never `0%` when it is not zero, never `100%` when it is not one. */
export const pct = (fraction: number, minDecimals = 1): string =>
  `${(fraction * 100).toFixed(decimalsFor(fraction, minDecimals))}%`;

export const count = (n: number): string => n.toLocaleString("en-US");

/** `92.3% (hunt) / 0.9% (enforce)`; hunt alone only when the measurement records no enforce lane. */
export function recallLanes(m: BenchmarkMeasurement): string {
  const hunt = `${pctHunt(m.recall)} (hunt)`;
  return m.enforce === null ? hunt : `${hunt} / ${pct(m.enforce.recall)} (enforce)`;
}

/** `ATR 4.1.5, measured 2026-10-15`; `fullWidth` for zh text set in full-width punctuation. */
export function measuredStamp(m: BenchmarkMeasurement, zh: boolean, fullWidth = false): string {
  if (!zh) return `ATR ${m.atr_version}, measured ${m.measured_date}`;
  return `ATR ${m.atr_version}${fullWidth ? "，" : ","}量測於 ${m.measured_date}`;
}

/** One stamp for figures measured together; otherwise each source's own. */
export function commonStamp(ms: readonly BenchmarkMeasurement[], zh: boolean, fullWidth = false): string {
  const stamps = [...new Set(ms.map((m) => measuredStamp(m, zh, fullWidth)))];
  if (stamps.length === 1) return stamps[0];
  return ms.map((m) => `${m.source}: ${measuredStamp(m, zh, fullWidth)}`).join(zh ? (fullWidth ? "；" : ";") : "; ");
}

const FULL_WIDTH: Readonly<Record<string, string>> = { ",": "，", ":": "：", ";": "；", "(": "（", ")": "）" };

/**
 * The zh wording below is set in half-width punctuation, as most pages are; a
 * page set in full-width punctuation converts it. Prose only: a figure such as
 * `65.4% (hunt)` keeps README's form.
 */
export const toFullWidth = (zh: string): string => zh.replace(/[,:;()]/g, (c) => FULL_WIDTH[c] ?? c);

/** What the two lanes are. */
export const LANES_EXPLAINED = {
  en: "The hunt lane is the engine default and loads every rule maturity; the enforce lane, the one to run with blocking on, loads only stable rules, so its figure is the one to read before turning blocking on.",
  zh: "hunt lane 是引擎預設,載入所有成熟度的規則;enforce lane 只載入 stable 規則,是開啟封鎖時要用的 lane,所以要開封鎖之前,該看的是它的數字。",
} as const;

/** Both garak corpora (README section 8, footnote garakcorpus). */
export const GARAK_CLOSED_BOOK = {
  en: "Partly closed-book: many of the rules that fire on this corpus were written from it, so the hunt figure is not an out-of-sample result.",
  zh: "這份語料部分屬於 closed-book(等於看過考題):在它上面開火的規則,有不少正是從它寫出來的,所以 hunt 數字不是樣本外的成績。",
} as const;

/** garak and garak-full quoted together. */
export const GARAK_BOTH_CLOSED_BOOK = {
  en: "Both are partly closed-book: many of the rules that fire on them were written from them, and the full suite contains the in-the-wild set twice, so neither hunt figure is an out-of-sample result.",
  zh: "兩份都部分屬於 closed-book(等於看過考題):在上面開火的規則有不少正是從它們寫出來的,完整套件還把 in-the-wild 集收了兩次,所以兩個 hunt 數字都不是樣本外的成績。",
} as const;

/** PINT-format (verified from rule YAML: ATR-2026-02002, 02005, 02230-02232 cite its false negatives; none is stable). */
export const PINT_CLOSED_BOOK = {
  en: "Partly closed-book: some hunt-lane rules were mined from this corpus's own misses, so the hunt figure is not fully out-of-sample.",
  zh: "部分屬於 closed-book:有幾條 hunt lane 規則正是從這份語料漏抓的樣本挖出來的,所以 hunt 數字不完全是樣本外成績。",
} as const;

/** HackAPrompt (ATR-2026-00452..00456 and others were written from its clusters, some of them stable). */
export const HACKAPROMPT_CLOSED_BOOK = {
  en: "Partly closed-book: rules were written from this corpus's attack clusters, some of them stable, so the figure is not an out-of-sample result.",
  zh: "部分屬於 closed-book:有規則正是從這份語料的攻擊群集寫出來的,其中幾條是 stable,所以這個數字不是樣本外成績。",
} as const;

/** A measurement taken before the enforce lane was recorded (hackaprompt, autoresearch). */
export const NO_ENFORCE_RECORD = {
  en: "this measurement predates the enforce-lane record, so there is no enforce figure for it",
  zh: "這次量測早於 enforce lane 開始記錄的時間,所以沒有 enforce 數字",
} as const;

/**
 * " Current recall, hunt lane … / enforce lane …: <label> (<n> samples): <hunt> / <enforce>; …"
 * for the given sources, read from their measurement files, or "" when none has
 * a measurement. English: the red-team entries it extends are English only.
 */
export function currentRecallSentence(
  stats: Pick<SiteStats, "benchmarks">,
  figures: readonly { source: string; label: string }[],
): string {
  const found = figures.flatMap(({ source, label }) => {
    const m = findBenchmark(stats, source);
    return m ? [{ m, label }] : [];
  });
  if (found.length === 0) return "";
  const parts = found.map(({ m, label }) => `${label} (${count(m.samples)} samples): ${recallLanes(m)}`);
  const missing = found.some(({ m }) => m.enforce === null) ? `; ${NO_ENFORCE_RECORD.en}` : "";
  return (
    " Current recall, hunt lane (every rule maturity) / enforce lane (stable rules only, the one for blocking): " +
    `${parts.join("; ")} (${commonStamp(found.map((f) => f.m), false)})${missing}.`
  );
}
