/**
 * Deterministic YAML emitter for the Cisco Skill Scanner ATR pack.
 *
 * The pack that ships inside cisco-ai-defense/skill-scanner was produced by a
 * converter that lives outside this repository, so its exact output style is
 * treated here as a fixed target format rather than as a free choice. The
 * style rules below were reverse engineered from the vendored pack and are
 * verified byte-for-byte by scripts/cisco-pack/verify-reproduction.ts.
 *
 * Style rules (in priority order) for a scalar string:
 *   1. empty string                       -> ''
 *   2. contains a character that cannot   -> double quoted, JSON-style escapes
 *      survive an unquoted scalar
 *      (control, zero width, BOM)
 *   3. leading or trailing whitespace     -> double quoted
 *   4. longer than FOLD_THRESHOLD         -> block folded (>-) on the next line
 *   5. plain-safe                         -> plain
 *   6. otherwise                          -> single quoted
 *
 * Block folded scalars are never re-wrapped: the payload is written on a
 * single indented line. That is what the vendored pack does, and re-wrapping
 * would produce a whole-file diff on every refresh.
 */

import yaml from 'js-yaml';

export const FOLD_THRESHOLD = 70;

/** A value this emitter knows how to write. */
export type YamlValue = string | boolean | number | YamlValue[] | { [key: string]: YamlValue };

/** Scalars that are written as-is, with no quoting or style decision. */
function isLiteralScalar(value: YamlValue): value is boolean | number {
  return typeof value === 'boolean' || typeof value === 'number';
}

export interface EmitOptions {
  /**
   * Keys whose array value should be emitted once with a YAML anchor and
   * referenced by alias afterwards. Maps key name -> anchor name.
   */
  readonly anchoredKeys?: Readonly<Record<string, string>>;
}

const PLAIN_UNSAFE_FIRST = new Set([
  '?',
  ':',
  ',',
  '[',
  ']',
  '{',
  '}',
  '#',
  '&',
  '*',
  '!',
  '|',
  '>',
  "'",
  '"',
  '%',
  '@',
  '`',
]);

/**
 * Characters that no unquoted YAML scalar may carry through a round trip.
 * A line feed is not one of them: a block scalar carries line feeds, and a
 * few regexes legitimately contain one inside a character class.
 */
export function hasUnquotableChar(value: string): boolean {
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (code === 0x0a) continue;
    const isC0 = code < 0x20;
    const isDelOrC1 = code === 0x7f || (code >= 0x80 && code <= 0x9f);
    const isZeroWidth =
      code === 0x00ad ||
      code === 0x180e ||
      (code >= 0x200b && code <= 0x200f) ||
      (code >= 0x2028 && code <= 0x202e) ||
      (code >= 0x2060 && code <= 0x2064) ||
      code === 0xfeff;
    if (isC0 || isDelOrC1 || isZeroWidth) return true;
  }
  return false;
}

/**
 * True when a plain scalar would round-trip to a different value — a regex
 * such as `0x5d5acA289F2A9E481fa2aEaD3FA465880Df84354` resolves as a hex
 * integer, so writing it unquoted silently changes the pattern's type.
 */
function resolvesToNonString(value: string): boolean {
  try {
    return yaml.load(value) !== value;
  } catch {
    return true;
  }
}

/** True when the value can be written without any quoting or block header. */
export function isPlainSafe(value: string): boolean {
  if (value.length === 0) return false;
  if (PLAIN_UNSAFE_FIRST.has(value[0])) return false;
  // A leading "-" is only an indicator when it opens a sequence entry or a
  // document marker. Several regexes start with "--" (a CLI flag or an SQL
  // comment) and are written plain; "-----BEGIN PRIVATE KEY-----" is not.
  if (value.startsWith('---') || /^-\s/.test(value)) return false;
  const last = value[value.length - 1];
  if (last === ':' || last === ' ') return false;
  if (value.includes(': ') || value.includes(' #')) return false;
  if (value.includes('\n')) return false;
  return !resolvesToNonString(value);
}

/**
 * Escape only what a double-quoted scalar cannot carry literally. Zero-width
 * joiners and friends stay raw — they are printable as far as YAML is
 * concerned, and escaping them would rewrite patterns that deliberately match
 * invisible-character smuggling. U+FEFF is the exception: it is excluded from
 * the printable set, so it has to be written as an escape.
 */
function escapeDoubleQuoted(value: string): string {
  let out = '';
  for (const char of value) {
    const code = char.codePointAt(0) ?? 0;
    if (char === '\\') out += '\\\\';
    else if (char === '"') out += '\\"';
    else if (char === '\n') out += '\\n';
    else if (char === '\t') out += '\\t';
    else if (code < 0x20 || code === 0x7f) out += `\\x${code.toString(16).padStart(2, '0')}`;
    else if ((code >= 0x80 && code <= 0x9f) || code === 0xfeff) {
      out += `\\u${code.toString(16).toUpperCase().padStart(4, '0')}`;
    } else out += char;
  }
  return `"${out}"`;
}

export type ScalarStyle = 'empty' | 'double' | 'folded' | 'plain' | 'single';

/** A folded scalar cannot represent a line that starts or ends with a space. */
function hasUnfoldableLines(value: string): boolean {
  return value.split('\n').some((line) => line.length === 0 || /^[ \t]|[ \t]$/.test(line));
}

export function chooseScalarStyle(value: string): ScalarStyle {
  if (value.length === 0) return 'empty';
  if (hasUnquotableChar(value)) return 'double';
  if (value !== value.trim()) return 'double';
  if (value.includes('\n')) return hasUnfoldableLines(value) ? 'double' : 'folded';
  if (value.length > FOLD_THRESHOLD) return 'folded';
  return isPlainSafe(value) ? 'plain' : 'single';
}

/**
 * Render a scalar. Folded scalars return a multi-line chunk starting with
 * ">-", so the caller must place them after "key:" with no trailing space.
 */
function renderScalar(value: string, indent: number): string {
  const style = chooseScalarStyle(value);
  const pad = ' '.repeat(indent + 2);
  switch (style) {
    case 'empty':
      return "''";
    case 'double':
      return escapeDoubleQuoted(value);
    case 'folded':
      // A line feed inside a folded scalar is written as a blank line: the
      // reader folds one break into a space and keeps the second.
      return `>-\n${pad}${value.split('\n').join(`\n\n${pad}`)}`;
    case 'plain':
      return value;
    case 'single':
      return `'${value.replace(/'/g, "''")}'`;
  }
}

interface EmitState {
  readonly anchoredKeys: Readonly<Record<string, string>>;
  readonly emitted: Set<string>;
}

function emitArray(key: string, items: YamlValue[], indent: number, state: EmitState): string[] {
  const anchor = state.anchoredKeys[key];
  if (anchor && state.emitted.has(anchor)) return [`${' '.repeat(indent)}${key}: *${anchor}`];
  const header = anchor
    ? `${' '.repeat(indent)}${key}: &${anchor}`
    : `${' '.repeat(indent)}${key}:`;
  if (anchor) state.emitted.add(anchor);
  return [header, ...items.flatMap((item) => emitSequenceItem(item, indent + 2, state))];
}

function emitSequenceItem(item: YamlValue, indent: number, state: EmitState): string[] {
  const dash = `${' '.repeat(indent)}- `;
  if (isLiteralScalar(item)) return [`${dash}${String(item)}`];
  if (typeof item === 'string') return [`${dash}${renderScalar(item, indent)}`];
  if (Array.isArray(item)) throw new Error('nested sequences are not supported by this emitter');
  const lines = emitMapping(item, indent + 2, state);
  return [dash + lines[0].slice(indent + 2), ...lines.slice(1)];
}

function emitMapping(node: Record<string, YamlValue>, indent: number, state: EmitState): string[] {
  return Object.entries(node).flatMap(([key, value]) => {
    if (isLiteralScalar(value)) return [`${' '.repeat(indent)}${key}: ${String(value)}`];
    if (typeof value === 'string') {
      return [`${' '.repeat(indent)}${key}: ${renderScalar(value, indent)}`];
    }
    if (Array.isArray(value)) return emitArray(key, value, indent, state);
    return [`${' '.repeat(indent)}${key}:`, ...emitMapping(value, indent + 2, state)];
  });
}

/** Emit a document. Always ends with exactly one newline. */
export function emitYaml(root: Record<string, YamlValue>, options: EmitOptions = {}): string {
  const state: EmitState = { anchoredKeys: options.anchoredKeys ?? {}, emitted: new Set() };
  return `${emitMapping(root, 0, state).join('\n')}\n`;
}
