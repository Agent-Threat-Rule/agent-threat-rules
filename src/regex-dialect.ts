/**
 * The regular-expression dialect of a pattern condition (SPEC.md §6.4).
 *
 * Kept free of other imports so the converters, including the published
 * subpath export agent-threat-rules/converters/sage, can apply it without
 * loading the engine. src/engine.ts compiles conditions through
 * regexConditionSpec() and re-exports it.
 *
 * @module agent-threat-rules/regex-dialect
 */

/** A leading inline flag group as rule authors write it: (?i), (?is), (?im), ... */
const LEADING_INLINE_FLAGS = /^\(\?([imsx]+)\)/;

/**
 * Strip inline flags like (?i) from regex patterns.
 * JavaScript RegExp uses flags as a constructor parameter, not inline.
 */
export function normalizeRegex(pattern: string): string {
  return pattern.replace(LEADING_INLINE_FLAGS, '');
}

/** How the engine compiles one array-format `operator: regex` condition. */
export interface RegexConditionSpec {
  /** The pattern handed to RegExp: the condition's value minus a leading inline flag group. */
  readonly source: string;
  /** The letters of that stripped group ("i", "is", ...), or "" when there was none. Stripped, not applied. */
  readonly inlineFlags: string;
  /** Always `i` -- this condition shape has no case-sensitive mode -- plus `u` when the pattern needs it. */
  readonly flags: 'i' | 'iu';
}

/**
 * The single definition of how an array-format `operator: regex` condition is
 * compiled (SPEC §6.4). Both compile sites in ATREngine reach it through
 * compileRegexCondition() in src/engine.ts (compilePatterns() and the on-the-fly
 * fallback in evaluateArrayCondition()), so does ShadowEvaluator, the converters
 * in src/converters use it to translate a condition for another regex engine, and
 * scripts/gate-case-sensitivity.ts imports it, because it has to see each pattern
 * exactly as the engine does. That gate used to keep its own copy of this logic,
 * and the copy went stale when needsUnicodeFlag() started setting `u` for astral
 * literals. Other scripts still re-derive it by hand and could import it too.
 *
 * Two consequences rule authors cannot see from the pattern:
 *   - `i` is applied whether or not the author wrote (?i), so letter case never
 *     distinguishes anything: [A-Z] also matches a-z.
 *   - A stripped (?s), (?m) or (?x) is NOT applied.
 */
export function regexConditionSpec(value: string): RegexConditionSpec {
  const inline = LEADING_INLINE_FLAGS.exec(value);
  const source = normalizeRegex(value);
  return { source, inlineFlags: inline?.[1] ?? '', flags: needsUnicodeFlag(source) ? 'iu' : 'i' };
}

/**
 * Does this pattern need the RegExp `u` flag?
 *
 * `\\u{...}` and `\\p{...}` require it by syntax, and so does a literal astral
 * character: without `u`, JavaScript reads a surrogate pair, and a class range
 * written with literals -- [<U+E0000>-<U+E007F>] -- is a SyntaxError rather than
 * a range.
 *
 * The literal form matters because it is the only spelling the three consuming
 * engines share. `\\u{...}` is JS-only: Python re needs `\\U000E0000`, Go needs
 * `\\x{E0000}`, and neither of those is valid JavaScript. Sixteen conditions
 * across ten rules used it, which made those rules uncompilable from the Python
 * and Go channels; they are literals now, and this is what keeps them working
 * here.
 */
export function needsUnicodeFlag(pattern: string): boolean {
  if (pattern.includes('\\u{') || pattern.includes('\\p{')) return true;
  for (const ch of pattern) {
    const cp = ch.codePointAt(0);
    if (cp !== undefined && cp > 0xffff) return true;
  }
  return false;
}

/**
 * A condition as a single pattern for a regex engine that only takes inline
 * flags, such as PCRE (Splunk), Python `re` or Go RE2: the leading flag group
 * replaced by `(?i)`, since SPEC §6.4 matches every condition
 * case-insensitively and gives `m`, `s` and `x` no effect. The `u` case has
 * no inline form; callers whose target cannot express it should check
 * regexConditionSpec(value).flags.
 */
export function inlineCaseInsensitive(value: string): string {
  return `(?i)${regexConditionSpec(value).source}`;
}
