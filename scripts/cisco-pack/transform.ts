import { regexConditionSpec } from '../../src/engine.js';
import { extractPatterns, type AtrRule, type LoadedRule } from './load-rules.js';

/** Field widths the vendored pack truncates to. */
export const DESCRIPTION_MAX = 300;
export const REMEDIATION_MAX = 200;

export const FILE_TYPES: readonly string[] = ['markdown', 'json', 'text', 'yaml'];

export interface CiscoSignature {
  readonly id: string;
  readonly atr_id: string;
  readonly atr_url: string;
  readonly category: string;
  readonly severity: string;
  readonly maturity?: string;
  readonly patterns: readonly string[];
  readonly file_types: readonly string[];
  readonly description: string;
  readonly remediation: string;
}

export interface TransformOptions {
  /** Git ref used in the atr_url permalink. */
  readonly ref: string;
  readonly repoUrl: string;
  /**
   * Omit the `maturity` field, which the pack vendored downstream does not
   * carry. Only set when reproducing that pack byte for byte.
   */
  readonly omitMaturity?: boolean;
  /**
   * Copy each regex exactly as the rule writes it instead of through
   * toScannerPattern(). The pack vendored downstream was built that way.
   * Only set when reproducing that pack byte for byte.
   */
  readonly verbatimPatterns?: boolean;
  /**
   * Highest severity a signature may carry; rules above it are written at it.
   * Skill Scanner fails a skill on any HIGH or CRITICAL finding by default, so
   * a cap of `LOW` lets the pack report without changing that verdict.
   */
  readonly maxSeverity?: string;
}

/** Skill Scanner's severities, most severe first. */
export const SEVERITIES: readonly string[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/** `severity` lowered to `cap` when it is more severe; both upper-case. */
export function capSeverity(severity: string, cap: string | undefined): string {
  if (cap === undefined) return severity;
  const capRank = SEVERITIES.indexOf(cap);
  if (capRank === -1) throw new Error(`unknown severity cap: ${cap}`);
  const rank = SEVERITIES.indexOf(severity);
  if (rank === -1) throw new Error(`unknown severity: ${severity}`);
  return rank < capRank ? cap : severity;
}

export const DEFAULT_REPO_URL = 'https://github.com/Agent-Threat-Rule/agent-threat-rules';

/** "tool-poisoning" -> "tool_poisoning". */
export function toSignatureCategory(category: string): string {
  return category.replace(/-/g, '_');
}

/** "ATR-2026-00072" -> "ATR_2026_00072". */
export function toSignatureId(ruleId: string): string {
  return ruleId.replace(/-/g, '_');
}

/**
 * A rule's regex condition written with the flags ATR's engine applies. The
 * scanner still matches most patterns one line at a time, which the engine
 * does not, and Python `re` differs from ECMAScript in places.
 *
 * ATR's engine matches every regex condition case-insensitively and removes
 * a leading flag group such as `(?im)` without applying its `m`, `s` or `x`
 * (SPEC.md §6.4). The scanner compiles each pattern with `re.compile(pattern)`
 * and no flags, so a condition copied as written would be case-sensitive
 * there unless the rule happened to write `(?i)`, and a group such as `(?im)`
 * would be applied. The pattern is therefore `(?i)` followed by the source
 * the engine itself compiles, from regexConditionSpec() in src/engine.ts.
 */
export function toScannerPattern(value: string): string {
  return `(?i)${regexConditionSpec(value).source}`;
}

/**
 * True when every condition must match: `condition: all` (or `and`). SPEC.md
 * §6.1 makes `any` the default when the combinator is left out.
 */
export function requiresAllConditions(rule: AtrRule): boolean {
  const condition = rule.detection?.condition;
  return condition === 'all' || condition === 'and';
}

/**
 * The patterns a rule contributes to the pack.
 *
 * The scanner reports a finding when any one pattern matches, so a rule whose
 * conditions must all match cannot be written as one pattern per condition:
 * that turns AND into OR and fires on half of the signal. Such a rule becomes
 * a single pattern of anchored lookaheads, one per condition, which matches
 * only where every condition does. The lookaheads use `[\s\S]` so they span
 * whatever text the scanner hands the pattern. Skill Scanner hands it one line
 * at a time unless the pattern contains `\n`, so there the conditions have to
 * meet on one line: narrower than ATR's engine, never broader.
 */
export function toScannerPatterns(rule: AtrRule): string[] {
  const sources = extractPatterns(rule).map((value) => regexConditionSpec(value).source);
  if (sources.length > 1 && requiresAllConditions(rule)) {
    return [`(?i)\\A${sources.map((source) => `(?=[\\s\\S]*?(?:${source}))`).join('')}`];
  }
  return sources.map((source) => `(?i)${source}`);
}

/**
 * Put the prose on one line, then truncate.
 *
 * Only line breaks are replaced. Runs of spaces are left alone on purpose:
 * several rules write "sentence.  Next sentence." with two spaces, and
 * collapsing them shifts every following character, which moves the
 * truncation point and rewrites the field for no reason.
 *
 * Truncation counts code points, not UTF-16 code units. Several rules quote
 * emoji from garak jailbreak probes; slicing by code unit would cut one
 * character short of the already published field and split a surrogate pair.
 */
function flatten(text: string | undefined, max: number): string {
  const oneLine = String(text ?? '')
    .replace(/\r\n?/g, '\n')
    .replace(/\n/g, ' ')
    .trim();
  const codePoints = Array.from(oneLine);
  return codePoints.length <= max ? oneLine : codePoints.slice(0, max).join('');
}

export function toSignature(loaded: LoadedRule, options: TransformOptions): CiscoSignature {
  const { category, fileName, rule } = loaded;
  return {
    id: toSignatureId(rule.id),
    atr_id: rule.id,
    atr_url: `${options.repoUrl}/blob/${options.ref}/rules/${category}/${fileName}`,
    category: toSignatureCategory(category),
    severity: capSeverity(rule.severity.toUpperCase(), options.maxSeverity),
    ...(options.omitMaturity ? {} : { maturity: rule.maturity ?? 'experimental' }),
    patterns: options.verbatimPatterns
      ? extractPatterns(rule)
      : toScannerPatterns(rule),
    file_types: FILE_TYPES,
    description: flatten(rule.description, DESCRIPTION_MAX),
    remediation: flatten(rule.remediation, REMEDIATION_MAX),
  };
}

export interface SignatureFile {
  /** Category directory name, e.g. "tool-poisoning". */
  readonly category: string;
  /** Path relative to the pack root, e.g. "signatures/atr_tool_poisoning.yaml". */
  readonly path: string;
  readonly signatures: readonly CiscoSignature[];
}

export function signatureFilePath(category: string): string {
  return `signatures/atr_${toSignatureCategory(category)}.yaml`;
}

/** Group rules into one signature file per category, both sorted by id. */
export function buildSignatureFiles(
  rules: readonly LoadedRule[],
  options: TransformOptions,
): SignatureFile[] {
  const byCategory = new Map<string, LoadedRule[]>();
  for (const loaded of rules) {
    const bucket = byCategory.get(loaded.category);
    if (bucket) bucket.push(loaded);
    else byCategory.set(loaded.category, [loaded]);
  }
  return [...byCategory.keys()].sort().map((category) => ({
    category,
    path: signatureFilePath(category),
    signatures: [...(byCategory.get(category) ?? [])]
      .sort((a, b) => a.rule.id.localeCompare(b.rule.id))
      .map((loaded) => toSignature(loaded, options)),
  }));
}
