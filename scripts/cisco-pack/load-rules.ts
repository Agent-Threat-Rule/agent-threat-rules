import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import yaml from 'js-yaml';

export interface AtrCondition {
  readonly field?: string;
  readonly operator?: string;
  readonly value?: unknown;
}

export interface AtrRule {
  readonly id: string;
  readonly severity: string;
  readonly description?: string;
  readonly remediation?: string;
  readonly status?: string;
  readonly maturity?: string;
  readonly detection?: {
    readonly method?: string;
    readonly conditions?: readonly AtrCondition[];
  };
}

export interface LoadedRule {
  /** Category directory name as it appears on disk, e.g. "tool-poisoning". */
  readonly category: string;
  /** File name only, e.g. "ATR-2026-00072-model-behavior-extraction.yaml". */
  readonly fileName: string;
  readonly rule: AtrRule;
}

export interface LoadOptions {
  /**
   * Keep rules ATR has withdrawn. ATR's own `hunt` lane is "everything except
   * deprecated", so a pack that ships them is broader than any lane ATR
   * publishes. Only set when reproducing the pack already vendored downstream.
   */
  readonly includeDeprecated?: boolean;
}

export interface LoadResult {
  readonly rules: readonly LoadedRule[];
  /** Rules found on disk but excluded from the pack, with the reason. */
  readonly excluded: readonly { readonly id: string; readonly reason: string }[];
  /** Number of rule files seen per category directory, before exclusions. */
  readonly filesPerCategory: Readonly<Record<string, number>>;
}

/**
 * The pack is a static signature format: it can only evaluate regular
 * expressions against file content. Rules whose detection method needs
 * runtime state (session windows, event counts, trace joins) are dropped.
 */
export const UNSUPPORTED_DETECTION_METHODS: readonly string[] = ['behavioral'];

function isRuleFile(name: string): boolean {
  return name.endsWith('.yaml') || name.endsWith('.yml');
}

function parseRule(path: string): AtrRule {
  const parsed = yaml.load(readFileSync(path, 'utf8'));
  if (!parsed || typeof parsed !== 'object') throw new Error(`not a YAML mapping: ${path}`);
  const rule = parsed as AtrRule;
  if (typeof rule.id !== 'string' || rule.id.length === 0) throw new Error(`missing rule id: ${path}`);
  if (typeof rule.severity !== 'string' || rule.severity.length === 0) {
    throw new Error(`missing severity: ${rule.id} (${path})`);
  }
  return rule;
}

function listCategories(rulesDir: string): string[] {
  return readdirSync(rulesDir)
    .filter((name) => statSync(join(rulesDir, name)).isDirectory())
    .sort();
}

/** Read every ATR rule under `rulesDir`, keeping only pack-supportable ones. */
export function loadRules(rulesDir: string, options: LoadOptions = {}): LoadResult {
  const rules: LoadedRule[] = [];
  const excluded: { id: string; reason: string }[] = [];
  const filesPerCategory: Record<string, number> = {};

  for (const category of listCategories(rulesDir)) {
    const dir = join(rulesDir, category);
    const fileNames = readdirSync(dir).filter(isRuleFile).sort();
    filesPerCategory[category] = fileNames.length;
    for (const fileName of fileNames) {
      const rule = parseRule(join(dir, fileName));
      const method = rule.detection?.method;
      if (method && UNSUPPORTED_DETECTION_METHODS.includes(method)) {
        excluded.push({ id: rule.id, reason: `detection.method: ${method}` });
        continue;
      }
      if (rule.status === 'deprecated' && !options.includeDeprecated) {
        excluded.push({ id: rule.id, reason: 'status: deprecated' });
        continue;
      }
      if (extractPatterns(rule).length === 0) {
        excluded.push({ id: rule.id, reason: 'no regex conditions' });
        continue;
      }
      rules.push({ category, fileName, rule });
    }
  }
  return { rules, excluded, filesPerCategory };
}

/**
 * Regex literals in source order, verbatim.
 *
 * Non-regex operators are not representable in a signature pack. Duplicates
 * are deliberately kept: a rule may carry the same regex against two
 * different `field`s, the pack has no field concept, and dropping the second
 * copy would silently make the exported pack disagree with the rule it claims
 * to be a verbatim copy of.
 */
export function extractPatterns(rule: AtrRule): string[] {
  const conditions = rule.detection?.conditions ?? [];
  return conditions
    .filter((c) => c.operator === 'regex' && typeof c.value === 'string')
    .map((c) => c.value as string);
}
