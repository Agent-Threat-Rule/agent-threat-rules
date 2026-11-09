/**
 * Leave conditions that backtrack badly out of the pack.
 *
 * Skill Scanner compiles every pattern with Python's `re`, a backtracking
 * engine. data/redos-baseline.json lists the conditions scripts/gate-redos.py
 * measured as slow on adversarial input with that engine; the gate lets them
 * through as known debt, but a scanner that runs them on untrusted files
 * inherits the stall. Keys are `<rule id>#<index>`, the index counting every
 * condition of the rule, regex or not, in source order.
 *
 * A rule that matches when any condition does keeps its other conditions. A
 * rule whose conditions must all match is left out entirely: dropping one of
 * its conditions would make the exported signature broader than the rule.
 */

import { readFileSync } from 'node:fs';
import type { AtrRule } from './load-rules.js';

/** The `known` keys of a data/redos-baseline.json file. */
export function readSlowConditions(path: string): ReadonlySet<string> {
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as { known?: Record<string, unknown> };
  if (!parsed.known || typeof parsed.known !== 'object') {
    throw new Error(`${path} has no "known" object`);
  }
  return new Set(Object.keys(parsed.known));
}

export type SlowConditionResult =
  | { readonly kind: 'unchanged'; readonly rule: AtrRule }
  | { readonly kind: 'trimmed'; readonly rule: AtrRule; readonly dropped: readonly number[] }
  | { readonly kind: 'excluded'; readonly reason: string };

function isRegex(condition: { operator?: unknown; value?: unknown }): boolean {
  return condition.operator === 'regex' && typeof condition.value === 'string';
}

/** The rule without its slow conditions, or the reason it cannot be exported. */
export function withoutSlowConditions(rule: AtrRule, slow: ReadonlySet<string>): SlowConditionResult {
  const conditions = rule.detection?.conditions ?? [];
  const dropped = conditions.flatMap((_, index) => (slow.has(`${rule.id}#${index}`) ? [index] : []));
  if (dropped.length === 0) return { kind: 'unchanged', rule };

  const reason = `slow on a backtracking regex engine: condition ${dropped.map((i) => `#${i}`).join(', ')}`;
  const combinator = rule.detection?.condition;
  if (combinator === 'all' || combinator === 'and') return { kind: 'excluded', reason };

  const kept = conditions.filter((_, index) => !dropped.includes(index));
  if (!kept.some(isRegex)) return { kind: 'excluded', reason };
  return { kind: 'trimmed', rule: { ...rule, detection: { ...rule.detection, conditions: kept } }, dropped };
}
