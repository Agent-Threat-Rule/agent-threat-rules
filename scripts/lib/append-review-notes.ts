/**
 * scripts/lib/append-review-notes.ts
 *
 * The weekly measure-all run collects what its renderers could not do into one
 * Markdown file (`--review-notes`), which goes into the rolling PR's body.
 * render-benchmark-table.ts writes it first; the renderers after it append.
 */
import { appendFileSync } from "node:fs";

/** Append a `### heading` section listing `items`. Nothing is written when there are none. */
export function appendReviewNotes(path: string, heading: string, intro: string, items: readonly string[]): void {
  if (items.length === 0) return;
  appendFileSync(path, ["", `### ${heading}`, "", intro, "", ...items.map((item) => `- ${item}`), ""].join("\n"));
}
