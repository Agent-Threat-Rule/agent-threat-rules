/**
 * scripts/lib/citation-garak.ts
 *
 * The garak sentence in CITATION.cff's abstract, rendered from the
 * `benchmarks.garak` block of root stats.json (which render-benchmark-table.ts
 * renders from data/measurements/garak/ and check-benchmark-citations.ts holds
 * to it).
 *
 * The sentence is generated whole and wrapped to the abstract's indent, then
 * swapped in between fixed anchors: it starts a line with "On the <n>-prompt
 * garak in-the-wild jailbreak corpus," and ends with "(README section 8).".
 * Patching numbers inside hand-wrapped prose is what froze it before: once the
 * text wrapped differently, the version regex stopped matching and the abstract
 * cited ATR 3.5.12 for months. If the anchors are not found this throws.
 *
 * Used by sync-stats.ts (every rules-merge release) and sync-citation-garak.ts
 * (the weekly measurement run, and CI's --check).
 */

export interface GarakCitation {
  /** Hunt-lane recall, in percent (stats.json `recall`). */
  recall: number;
  /** Enforce-lane recall, in percent; absent when the measurement records none. */
  enforceLaneRecall?: number;
  samples: number;
  atr_version?: string;
}

/** 92.3 -> "92.3%", 100 -> "100.0%", 0.03 -> "0.03%": whole numbers keep one decimal. */
const pct = (n: number): string => `${Number.isInteger(n) ? n.toFixed(1) : String(n)}%`;

export function garakSentence(g: GarakCitation, fallbackVersion: string): string {
  const hunt = `${pct(g.recall)} in the hunt lane (the engine default, which loads every rule maturity)`;
  const lanes =
    g.enforceLaneRecall === undefined
      ? `recall is ${hunt}; no enforce-lane figure is recorded for this measurement.`
      : `recall is ${hunt} and ${pct(g.enforceLaneRecall)} in the enforce lane (stable rules only, ` +
        "the lane to run with blocking on).";
  return (
    `On the ${g.samples.toLocaleString("en-US")}-prompt garak in-the-wild jailbreak corpus, ` +
    `measured at ATR ${g.atr_version ?? fallbackVersion}, ${lanes} The hunt figure is partly ` +
    "closed-book: many of the rules that fire on this corpus were written from it (README section 8)."
  );
}

/** Greedy word wrap at the abstract's two-space indent, at most `width` columns. */
export function wrapAbstract(sentence: string, width = 80): string[] {
  const indent = "  ";
  const lines: string[] = [];
  let line = "";
  for (const word of sentence.split(/\s+/).filter((w) => w.length > 0)) {
    if (line !== "" && indent.length + line.length + 1 + word.length > width) {
      lines.push(indent + line);
      line = word;
    } else {
      line = line === "" ? word : `${line} ${word}`;
    }
  }
  if (line !== "") lines.push(indent + line);
  return lines;
}

const SENTENCE = /^ {2}On the [\d,]+-prompt garak in-the-wild jailbreak corpus,[\s\S]*?\(README section 8\)\.\n/m;

/** Replace the garak sentence in a CITATION.cff text. Throws when it is not there. */
export function syncGarakSentence(text: string, g: GarakCitation, fallbackVersion: string): string {
  if (!SENTENCE.test(text)) {
    throw new Error(
      "CITATION.cff: no garak sentence found (a line starting " +
        '"On the <n>-prompt garak in-the-wild jailbreak corpus," and ending "(README section 8)."). ' +
        "Restore it in the abstract rather than letting the figure freeze.",
    );
  }
  return text.replace(SENTENCE, `${wrapAbstract(garakSentence(g, fallbackVersion)).join("\n")}\n`);
}
