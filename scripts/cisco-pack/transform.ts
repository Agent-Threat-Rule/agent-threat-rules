import { extractPatterns, type LoadedRule } from './load-rules.js';

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
    severity: rule.severity.toUpperCase(),
    ...(options.omitMaturity ? {} : { maturity: rule.maturity ?? 'experimental' }),
    patterns: extractPatterns(rule),
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
