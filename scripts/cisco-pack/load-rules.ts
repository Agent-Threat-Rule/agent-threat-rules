import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import yaml from 'js-yaml';
import { withoutSlowConditions } from './slow-conditions.js';

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
    readonly condition?: string;
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
  /**
   * Keep rules with a regex condition on a field a skill package does not
   * carry (see STATIC_TEXT_FIELDS). Only set when reproducing the pack already
   * vendored downstream.
   */
  readonly includeRuntimeFields?: boolean;
  /**
   * Rules to leave out, with the reason, e.g. the rules the benign gate found
   * blocking a benign skill (scripts/cisco-pack/benign-gate.py).
   */
  readonly exclude?: ReadonlyMap<string, string>;
  /**
   * Conditions to leave out as `<rule id>#<index>`, the slow ones listed in
   * data/redos-baseline.json (see scripts/cisco-pack/slow-conditions.ts).
   */
  readonly slow?: ReadonlySet<string>;
}

export interface LoadResult {
  readonly rules: readonly LoadedRule[];
  /** Rules found on disk but excluded from the pack, with the reason. */
  readonly excluded: readonly { readonly id: string; readonly reason: string }[];
  /** Rules exported without some of their conditions, with the indices left out. */
  readonly trimmed: readonly { readonly id: string; readonly conditions: readonly number[] }[];
  /** Number of rule files seen per category directory, before exclusions. */
  readonly filesPerCategory: Readonly<Record<string, number>>;
}

/**
 * The pack is a static signature format: it can only evaluate regular
 * expressions against file content. Rules whose detection method needs
 * runtime state (session windows, event counts, trace joins) are dropped.
 */
export const UNSUPPORTED_DETECTION_METHODS: readonly string[] = ['behavioral'];

/**
 * Condition fields whose text a skill package carries, so a pattern written
 * for them means the same thing over a skill's files.
 *
 * Every other field exists only at runtime: `tool_name` and `tool_args` of a
 * call being made, a `tool_response`, the agent's own output, trace fields.
 * The pack has no field concept and Skill Scanner applies each pattern to
 * every line of every file, so a condition on such a field matches whatever
 * text happens to look like it. ATR-2026-00099 shows the cost: it fires when
 * the tool being called is named like `delete` or `format`, and as a line
 * pattern it matched almost every benign skill, because skills say "delete".
 * A rule with any regex condition outside this list is therefore left out;
 * dropping only that condition would broaden a `condition: all` rule.
 */
export const STATIC_TEXT_FIELDS: readonly string[] = ['content', 'user_input', 'tool_description'];

/** The runtime-only fields a rule's regex conditions read, sorted. */
export function runtimeOnlyFields(rule: AtrRule): string[] {
  const fields = (rule.detection?.conditions ?? [])
    .filter((c) => c.operator === 'regex' && typeof c.value === 'string')
    .map((c) => String(c.field ?? ''))
    .filter((field) => !STATIC_TEXT_FIELDS.includes(field));
  return [...new Set(fields)].sort();
}

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
  const trimmed: { id: string; conditions: readonly number[] }[] = [];
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
      const runtimeFields = runtimeOnlyFields(rule);
      if (runtimeFields.length > 0 && !options.includeRuntimeFields) {
        excluded.push({ id: rule.id, reason: `runtime-only field: ${runtimeFields.join(', ')}` });
        continue;
      }
      const excludedBy = options.exclude?.get(rule.id);
      if (excludedBy !== undefined) {
        excluded.push({ id: rule.id, reason: excludedBy });
        continue;
      }
      const checked = options.slow ? withoutSlowConditions(rule, options.slow) : { kind: 'unchanged' as const, rule };
      if (checked.kind === 'excluded') {
        excluded.push({ id: rule.id, reason: checked.reason });
        continue;
      }
      if (checked.kind === 'trimmed') trimmed.push({ id: rule.id, conditions: checked.dropped });
      rules.push({ category, fileName, rule: checked.rule });
    }
  }
  return { rules, excluded, trimmed, filesPerCategory };
}

/**
 * The rule's regex condition values in source order, exactly as the rule
 * writes them. transform.ts decides how each is written into the pack.
 *
 * Non-regex operators are not representable in a signature pack. Duplicates
 * are deliberately kept: a rule may carry the same regex against two
 * different `field`s, the pack has no field concept, and dropping the second
 * copy would silently make the exported pack disagree with the rule it links
 * to.
 */
export function extractPatterns(rule: AtrRule): string[] {
  const conditions = rule.detection?.conditions ?? [];
  return conditions
    .filter((c) => c.operator === 'regex' && typeof c.value === 'string')
    .map((c) => c.value as string);
}
