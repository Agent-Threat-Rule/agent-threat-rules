/**
 * garak `badchars` probe transforms, ported from upstream.
 *
 * UPSTREAM: NVIDIA/garak @ 7ff1f2778e4d6ca6dc25ba8e17d8dfa520003ee0,
 * file `garak/probes/badchars.py`. Every function below names the exact lines
 * it reproduces. Nothing here is invented; where this port deliberately
 * narrows the upstream search space (only ever to bound variant COUNT, never to
 * change the transformation itself) the deviation is stated in the doc comment
 * and surfaced in the emitted corpus metadata.
 *
 * Paper: Boucher et al., "Bad Characters: Imperceptible NLP Attacks",
 * arXiv:2106.09898 — cited by badchars.py:5 and :121.
 */
import { GARAK_HOMOGLYPH_MAP } from "./garak-homoglyphs.js";

/** badchars.py:21 — `ASCII_PRINTABLE = tuple(chr(i) for i in range(0x20, 0x7F))` */
const ASCII_PRINTABLE: readonly string[] = Object.freeze(
  Array.from({ length: 0x7f - 0x20 }, (_, i) => String.fromCharCode(0x20 + i)),
);

/** badchars.py:22 — `DEFAULT_INVISIBLE = ("​", "‌", "‍")` (ZWSP, ZWNJ, ZWJ) */
export const DEFAULT_INVISIBLE: readonly string[] = Object.freeze([
  "​",
  "‌",
  "‍",
]);

/** badchars.py:23-30 — `BIDI_CONTROLS` */
const BIDI = Object.freeze({
  PDF: "‬",
  LRO: "‭",
  RLO: "‮",
  LRI: "⁦",
  RLI: "⁧",
  PDI: "⁩",
});

/**
 * badchars.py:350-380 — `_select_positions`. Reproduced exactly, including the
 * `cap == 1` special case and the fill-from-the-front top-up loop.
 */
export function selectPositions(
  length: number,
  cap: number,
  includeEndpoint = true,
): readonly number[] {
  const positions = Array.from(
    { length: length + (includeEndpoint ? 1 : 0) },
    (_, i) => i,
  );
  if (cap <= 0 || positions.length <= cap) return Object.freeze(positions);
  if (cap === 1) return Object.freeze([positions[0]]);

  const step = (positions.length - 1) / (cap - 1);
  const seen = new Set<number>();
  const selected: number[] = [];
  for (let idx = 0; idx < cap; idx++) {
    const value = positions[pythonRound(idx * step)];
    if (seen.has(value)) continue;
    selected.push(value);
    seen.add(value);
  }
  for (const value of positions) {
    if (selected.length >= cap) break;
    if (seen.has(value)) continue;
    selected.push(value);
    seen.add(value);
  }
  return Object.freeze([...selected].sort((a, b) => a - b));
}

/**
 * Python's `round()` is banker's rounding (round-half-to-even); JS `Math.round`
 * is round-half-up. `_select_positions` calls `round(idx * step)`, so the port
 * has to match Python or the selected offsets drift by one.
 */
function pythonRound(value: number): number {
  const floor = Math.floor(value);
  const diff = value - floor;
  if (diff > 0.5) return floor + 1;
  if (diff < 0.5) return floor;
  return floor % 2 === 0 ? floor : floor + 1;
}

/** badchars.py:382-388 — `_select_ascii`. */
export function selectAscii(limit: number): readonly string[] {
  if (limit <= 0 || limit >= ASCII_PRINTABLE.length) return ASCII_PRINTABLE;
  const step = Math.max(
    1,
    Math.floor((ASCII_PRINTABLE.length - 1) / (limit - 1)),
  );
  const selected: string[] = [];
  for (let i = 0; i < ASCII_PRINTABLE.length; i += step)
    selected.push(ASCII_PRINTABLE[i]);
  return Object.freeze(selected.slice(0, limit));
}

/** badchars.py:323-330 — `_inject_sequences`. Returns a new string; never mutates. */
export function injectSequences(
  payload: string,
  insertions: readonly (readonly [number, string])[],
): string {
  const ordered = [...insertions].sort((a, b) => a[0] - b[0]);
  let result = payload;
  let offset = 0;
  for (const [position, value] of ordered) {
    const idx = Math.min(Math.max(position + offset, 0), result.length);
    result = result.slice(0, idx) + value + result.slice(idx);
    offset += value.length;
  }
  return result;
}

/**
 * badchars.py:41-74 (`_render_swaps`) + :332-344 (`_apply_swaps`), flattened.
 *
 * A single swap of the code points at `index` and `index+1` is rendered as the
 * 12-element bidi sandwich from `_render_swaps`, which makes the pair display in
 * reverse order while confining the directionality change.
 */
export function applyBidiSwap(payload: string, index: number): string {
  const chars = Array.from(payload);
  if (index < 0 || index >= chars.length - 1) return payload;
  const first = chars[index];
  const second = chars[index + 1];
  const swapped =
    BIDI.LRO +
    BIDI.LRI +
    BIDI.RLO +
    BIDI.LRI +
    second +
    BIDI.PDI +
    BIDI.LRI +
    first +
    BIDI.PDI +
    BIDI.PDF +
    BIDI.PDI +
    BIDI.PDF;
  return (
    chars.slice(0, index).join("") + swapped + chars.slice(index + 2).join("")
  );
}

/**
 * badchars.py:244-258 — `_generate_invisible_variants` at the shipped default
 * `perturbation_budget = 1` (badchars.py:139) and
 * `max_position_candidates = 24` (badchars.py:143).
 */
export function invisibleVariants(
  payload: string,
  maxPositions = 24,
): readonly string[] {
  const positions = selectPositions(payload.length, maxPositions);
  const out: string[] = [];
  for (const pos of positions) {
    for (const ch of DEFAULT_INVISIBLE)
      out.push(injectSequences(payload, [[pos, ch]]));
  }
  return Object.freeze([...new Set(out)]);
}

/**
 * badchars.py:303-321 — `_generate_deletion_variants`: insert a printable ASCII
 * character immediately followed by U+0008 BACKSPACE, so a terminal renders the
 * original text while the byte stream carries an extra glyph.
 *
 * DEVIATION (bounding only): upstream's `max_ascii_variants` defaults to all 95
 * printable ASCII characters (badchars.py:145), giving 24 x 95 = 2280 variants
 * per payload. This port defaults to 8 ASCII candidates chosen by upstream's own
 * `_select_ascii`. The transformation is identical; only the number of injected
 * characters tried at each position changes, and the detection question
 * ("does an inserted char+backspace at offset p break the match?") does not
 * depend on WHICH printable character was inserted.
 */
export function deletionVariants(
  payload: string,
  maxPositions = 24,
  maxAsciiVariants = 8,
): readonly string[] {
  const positions = selectPositions(payload.length, maxPositions);
  const asciiCandidates = selectAscii(maxAsciiVariants);
  const out: string[] = [];
  for (const pos of positions) {
    for (const ch of asciiCandidates)
      out.push(injectSequences(payload, [[pos, `${ch}\b`]]));
  }
  return Object.freeze([...new Set(out)]);
}

/**
 * badchars.py:286-301 — `_generate_reordering_variants` at
 * `perturbation_budget = 1`, `max_reorder_candidates = 24` (badchars.py:144).
 */
export function reorderingVariants(
  payload: string,
  maxPositions = 24,
): readonly string[] {
  if (payload.length < 2) return Object.freeze([]);
  const candidates = selectPositions(payload.length - 1, maxPositions, false);
  const out = candidates
    .filter((idx) => idx < payload.length - 1)
    .map((idx) => applyBidiSwap(payload, idx));
  return Object.freeze([...new Set(out)]);
}

/**
 * badchars.py:260-284 — `_generate_homoglyph_variants` at
 * `perturbation_budget = 1`: every position whose character has an entry in the
 * Unicode intentional-confusables table, crossed with every replacement.
 */
export function homoglyphVariants(payload: string): readonly string[] {
  const out: string[] = [];
  for (let idx = 0; idx < payload.length; idx++) {
    const options = GARAK_HOMOGLYPH_MAP[payload[idx]];
    if (!options) continue;
    for (const replacement of options) {
      out.push(payload.slice(0, idx) + replacement + payload.slice(idx + 1));
    }
  }
  return Object.freeze([...new Set(out)]);
}
