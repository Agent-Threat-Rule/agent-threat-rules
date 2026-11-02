/**
 * ATR-to-Generic-Regex Converter
 *
 * Exports ATR rules as a flat list of regex patterns with metadata.
 * Designed for consumption by any security tool that supports regex matching.
 * Format: JSON array of { id, title, severity, category, patterns[] }
 *
 * Each pattern is `{ field, regex, flags, description }` for a consumer that
 * compiles `new RegExp(regex, flags)`. Per SPEC §6.4, `regex` is the condition
 * without its leading flag group and `flags` is always `i`, or `iu` when the
 * pattern needs Unicode mode: every condition matches case-insensitively, and
 * `m`, `s` and `x` have no effect.
 *
 * @module agent-threat-rules/converters/generic-regex
 */

import type { ATRRule, ATRSeverity, ATRReferences } from '../types.js';
import { regexConditionSpec } from '../regex-dialect.js';

export interface GenericRegexRule {
  readonly id: string;
  readonly title: string;
  readonly severity: ATRSeverity;
  readonly category: string;
  readonly subcategory: string;
  readonly scan_target: string;
  readonly patterns: readonly GenericRegexPattern[];
  readonly references: ATRReferences | undefined;
}

export interface GenericRegexPattern {
  readonly field: string;
  readonly regex: string;
  readonly flags: string;
  readonly description: string;
}

/**
 * Convert a single ATR rule to generic regex format.
 */
export function ruleToGenericRegex(rule: ATRRule): GenericRegexRule {
  const patterns: GenericRegexPattern[] = [];

  // ATRConditions can be an array or a named record
  const conditions = Array.isArray(rule.detection.conditions)
    ? rule.detection.conditions
    : Object.values(rule.detection.conditions);

  for (const condition of conditions) {
    if ('operator' in condition && condition.operator === 'regex' && 'value' in condition && condition.value) {
      // SPEC §6.4. This used to copy the group's letters into `flags`, so a
      // condition without (?i) exported flags "" (case-sensitive) and (?im) or
      // (?is) turned on multiline or dotAll in the consumer.
      const spec = regexConditionSpec(condition.value);

      patterns.push({
        field: 'field' in condition ? condition.field : 'content',
        regex: spec.source,
        flags: spec.flags,
        description: ('description' in condition ? condition.description : '') ?? '',
      });
    }
  }

  return {
    id: rule.id,
    title: rule.title,
    severity: rule.severity,
    category: rule.tags.category,
    subcategory: rule.tags.subcategory ?? '',
    scan_target: rule.tags.scan_target ?? 'mcp',
    patterns,
    references: rule.references ?? {},
  };
}

/**
 * Convert all ATR rules to a single generic regex export.
 */
export function rulesToGenericRegex(rules: readonly ATRRule[]): readonly GenericRegexRule[] {
  return rules
    .filter((r) => r.status !== 'deprecated')
    .map(ruleToGenericRegex)
    .filter((r) => r.patterns.length > 0);
}
