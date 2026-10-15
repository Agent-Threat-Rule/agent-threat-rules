/**
 * scripts/lib/benchmark-review-notes.ts
 *
 * What a benchmark-table refresh cannot fix by itself, written up for the
 * rolling measurement PR's body.
 *
 * scripts/render-benchmark-table.ts re-renders README's benchmark table from
 * data/measurements/. The prose and footnotes around that table quote the same
 * numbers ("measured against ATR 3.5.0", "fell 99.1% -> 1.5%"), and they are
 * deliberately not rewritten: a sentence is a claim, and which claims still
 * hold after a refresh is a human call. What can be automated is pointing at
 * them. This module lists every line in the table's section — plus the
 * footnotes the table's rows reference, wherever they are defined — that cites
 * an ATR version or a percentage, and marks the ones citing a value the refresh
 * just replaced, since those are the lines most likely to contradict the table.
 */

import { parseBenchmarkTable } from "../check-benchmark-citations.js";

const VERSION = /\b\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?\b/g;
const PERCENT = /\d+(?:\.\d+)?\s?%/g;
const DATE = /\b\d{4}-\d{2}-\d{2}\b/g;
const HEADING = /^(#{1,6})\s/;
const FENCE = /^\s*(```|~~~)/;
const FOOTNOTE_DEF = /^\[\^[^\]]+\]:/;
const FOOTNOTE_REF = /\[\^([^\]]+)\]/g;
const MAX_TEXT = 160;

/** A README line to read again after a refresh. `lineNo` is 1-based. */
export interface ProseLine {
  lineNo: number;
  text: string;
  /** Cites a version, percentage or date that the refresh replaced in the table. */
  citesReplaced: boolean;
}

/**
 * The versions, percentages and dates a piece of text cites, in a form two
 * texts can be compared by: `3.5.12`, `91.5%`, `2026-08-15`. Token-wise, so
 * `3.5.1` is not found inside `3.5.12`.
 */
export function citedTokens(text: string): string[] {
  return [
    ...(text.match(VERSION) ?? []),
    ...(text.match(PERCENT) ?? []).map((p) => p.replace(/\s/g, "")),
    ...(text.match(DATE) ?? []),
  ];
}

const citesVersionOrPercent = (text: string): boolean =>
  new RegExp(VERSION.source).test(text) || new RegExp(PERCENT.source).test(text);

/** Headings inside fenced code (a `# comment` in a shell block) are not headings. */
function headingLevels(lines: readonly string[]): (number | null)[] {
  let inFence = false;
  return lines.map((line) => {
    if (FENCE.test(line)) {
      inFence = !inFence;
      return null;
    }
    if (inFence) return null;
    return HEADING.exec(line)?.[1].length ?? null;
  });
}

/** [first, last] indices of the contiguous `|` block holding the benchmark table. */
function tableBlock(lines: readonly string[], firstRowIdx: number, lastRowIdx: number): [number, number] {
  let first = firstRowIdx;
  while (first > 0 && lines[first - 1].startsWith("|")) first -= 1;
  let last = lastRowIdx;
  while (last + 1 < lines.length && lines[last + 1].startsWith("|")) last += 1;
  return [first, last];
}

/** [heading, end) of the section enclosing the table: up to the next heading at its level or above. */
function sectionAround(levels: readonly (number | null)[], tableFirst: number): [number, number] {
  let heading = -1;
  for (let i = tableFirst - 1; i >= 0; i--) {
    if (levels[i] !== null) {
      heading = i;
      break;
    }
  }
  const level = heading === -1 ? 0 : (levels[heading] as number);
  let end = levels.length;
  for (let i = tableFirst + 1; i < levels.length; i++) {
    const l = levels[i];
    if (l !== null && heading !== -1 && l <= level) {
      end = i;
      break;
    }
  }
  return [heading, end];
}

/** Indices of a footnote definition and its continuation lines. */
function footnoteParagraph(lines: readonly string[], levels: readonly (number | null)[], defIdx: number): number[] {
  const out = [defIdx];
  for (let j = defIdx + 1; j < lines.length; j++) {
    const line = lines[j];
    if (line.trim() === "") {
      // A blank line ends the footnote unless the next line is indented into it.
      if (!/^( {4}|\t)/.test(lines[j + 1] ?? "")) break;
      continue;
    }
    if (FOOTNOTE_DEF.test(line) || levels[j] !== null) break;
    out.push(j);
  }
  return out;
}

function clip(text: string): string {
  // The PR body is rendered as Markdown; a README line must not open HTML in it.
  const safe = text.replace(/</g, "&lt;");
  return safe.length > MAX_TEXT ? `${safe.slice(0, MAX_TEXT - 1)}…` : safe;
}

/**
 * README lines to re-read after the benchmark table changed: those in the
 * table's section (outside the table) and in the footnotes its rows reference,
 * that cite an ATR version or a percentage. Returns [] when there is no table.
 */
export function findProseToReview(readme: string, replaced: readonly string[]): ProseLine[] {
  const lines = readme.split("\n");
  const rows = parseBenchmarkTable(readme);
  if (rows.length === 0) return [];
  const [tableFirst, tableLast] = tableBlock(lines, rows[0].lineNo - 1, rows[rows.length - 1].lineNo - 1);
  const levels = headingLevels(lines);
  const [heading, end] = sectionAround(levels, tableFirst);

  const picked = new Set<number>();
  for (let i = heading + 1; i < end; i++) {
    if (i < tableFirst || i > tableLast) picked.add(i);
  }
  const labels = new Set(
    lines.slice(tableFirst, tableLast + 1).flatMap((l) => [...l.matchAll(FOOTNOTE_REF)].map((m) => m[1])),
  );
  for (const label of labels) {
    const defIdx = lines.findIndex((l) => l.startsWith(`[^${label}]:`));
    if (defIdx !== -1) for (const i of footnoteParagraph(lines, levels, defIdx)) picked.add(i);
  }

  const replacedSet = new Set(replaced);
  return [...picked]
    .sort((a, b) => a - b)
    .filter((i) => citesVersionOrPercent(lines[i]))
    .map((i) => ({
      lineNo: i + 1,
      text: clip(lines[i].trim()),
      citesReplaced: citedTokens(lines[i]).some((t) => replacedSet.has(t)),
    }));
}

export interface ReviewInput {
  prose: readonly ProseLine[];
  /** stats.json fields removed because no measurement carries them, as `benchmarks.<block>.<field>`. */
  dropped: readonly string[];
  /** stats.json blocks left on their old stamp, with the reason. */
  held: readonly string[];
}

const proseItem = (l: ProseLine) => `- README.md:${l.lineNo} — ${l.text}`;

/** Markdown for the rolling PR body; "" when there is nothing for a human to check. */
export function formatReviewNotes({ prose, dropped, held }: ReviewInput): string {
  const parts: string[] = [];
  if (prose.length > 0) {
    const primary = prose.filter((l) => l.citesReplaced);
    const rest = prose.filter((l) => !l.citesReplaced);
    parts.push(
      "### README prose to check by hand",
      "",
      "The benchmark table was re-rendered from `data/measurements/`; the prose and footnotes " +
        "around it were not. These lines cite an ATR version or a percentage and may now " +
        "contradict the table.",
      "",
    );
    if (primary.length > 0) parts.push("Citing a value this refresh replaced:", "", ...primary.map(proseItem), "");
    if (rest.length > 0) {
      parts.push(
        `<details><summary>Other lines citing a version or a percentage (${rest.length})</summary>`,
        "",
        ...rest.map(proseItem),
        "",
        "</details>",
        "",
      );
    }
  }
  if (dropped.length > 0) {
    parts.push(
      "### stats.json fields dropped",
      "",
      "No measurement file carries these, so they were removed rather than left under the new " +
        "version stamp. Re-add any that are still wanted, from a measurement:",
      "",
      ...dropped.map((d) => `- \`${d}\``),
      "",
    );
  }
  if (held.length > 0) parts.push("### stats.json blocks not re-stamped", "", ...held.map((h) => `- ${h}`), "");
  return parts.join("\n");
}
