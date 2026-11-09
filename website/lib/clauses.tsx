import type { ReactNode } from "react";

/**
 * Keeps each Chinese clause on one line: the text may wrap only after a
 * full-width comma or full stop, so a heading never breaks mid-phrase.
 */
export function clauses(text: string): ReactNode {
  const parts = text.split(/(?<=[，。])/).filter(Boolean);
  if (parts.length < 2) return text;
  return parts.map((part, i) => (
    <span key={i} className="inline-block">
      {part}
    </span>
  ));
}
