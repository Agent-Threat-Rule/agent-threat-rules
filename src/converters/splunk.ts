/**
 * ATR-to-Splunk SPL Converter
 *
 * Converts ATR YAML rules into Splunk Search Processing Language (SPL) queries
 * that a SOC analyst can use as a starting point for threat hunting.
 *
 * @module agent-threat-rules/converters/splunk
 */

import type { ATRRule, ATRArrayCondition } from '../types.js';
import { inlineCaseInsensitive } from '../regex-dialect.js';

/**
 * A regex condition as a PCRE pattern for SPL's `regex` command and match().
 * PCRE applies a leading inline group itself, so the condition's own group
 * used to reach Splunk unchanged: a pattern without (?i) matched
 * case-sensitively and (?im) or (?is) turned on multiline or dotall. SPEC
 * §6.4 matches every condition case-insensitively and gives m, s and x no
 * effect, so the group is replaced by (?i). PCRE still differs from
 * ECMAScript in places ($ also matches before a final newline, . also
 * matches \r, U+2028 and U+2029).
 */
function splRegex(value: string): string {
  return escapeForSPL(inlineCaseInsensitive(value));
}

/**
 * Escape a string for use in Splunk SPL double-quoted values.
 */
function escapeForSPL(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Convert a single ATR array condition to an SPL clause.
 *
 * Supports operators: regex, contains, exact, starts_with, gt, lt, gte, lte, eq
 */
function conditionToSPL(cond: ATRArrayCondition): string {
  const field = cond.field;
  const value = cond.value;

  switch (cond.operator) {
    case 'regex':
      return `| regex ${field}="${splRegex(value)}"`;

    case 'contains':
      return `${field}="*${escapeForSPL(value)}*"`;

    case 'exact':
      return `${field}="${escapeForSPL(value)}"`;

    case 'starts_with':
      return `${field}="${escapeForSPL(value)}*"`;

    case 'gt':
      return `| where ${field} > ${Number(value)}`;

    case 'lt':
      return `| where ${field} < ${Number(value)}`;

    case 'gte':
      return `| where ${field} >= ${Number(value)}`;

    case 'lte':
      return `| where ${field} <= ${Number(value)}`;

    case 'eq':
      return `| where ${field} == ${Number(value)}`;

    default:
      // Fallback: treat unknown operators as a contains search
      return `${field}="*${escapeForSPL(value)}*"`;
  }
}

/**
 * Convert an ATR rule to a Splunk SPL query string.
 *
 * The generated query includes:
 * - Comment header with rule metadata
 * - Index/sourcetype base search (generic, analyst should customize)
 * - Condition clauses joined with appropriate logic
 */
export function ruleToSPL(rule: ATRRule): string {
  const conditions = rule.detection.conditions;
  const logic = rule.detection.condition; // "any" or "all"

  const lines: string[] = [];

  // Comment header with rule metadata
  lines.push(`\`\`\` ATR Rule: ${rule.id} \`\`\``);
  lines.push(`\`\`\` Title: ${rule.title} \`\`\``);
  lines.push(`\`\`\` Severity: ${rule.severity} | Category: ${rule.tags.category} \`\`\``);
  lines.push(`\`\`\` Source: ${rule.agent_source.type} | Condition logic: ${logic} \`\`\``);
  lines.push('');

  // Base search -- analyst should adjust index and sourcetype
  lines.push('index=ai_agent_logs sourcetype=agent_events');

  if (!Array.isArray(conditions)) {
    // Named-map format: not common in current rules, emit a placeholder
    lines.push('```` Warning: Named-map conditions not fully supported. Review manually. ````');
    return lines.join('\n');
  }

  const arrayConditions = conditions as ATRArrayCondition[];

  if (arrayConditions.length === 0) {
    return lines.join('\n');
  }

  // For "any" logic with regex conditions, we can combine them using
  // a single regex with OR (|) alternation where possible, or use
  // multiple search branches.
  // For clarity and analyst usability, we emit each condition separately.

  if (logic === 'all') {
    // AND logic: chain all conditions sequentially
    for (const cond of arrayConditions) {
      lines.push(conditionToSPL(cond));
    }
  } else {
    // OR logic ("any"): use Splunk's multisearch or OR-joined search
    // For regex conditions, wrap in a single eval+match approach
    // For simplicity and readability, use OR-joined subsearches
    const regexConditions = arrayConditions.filter(c => c.operator === 'regex');
    const otherConditions = arrayConditions.filter(c => c.operator !== 'regex');

    if (regexConditions.length > 0 && otherConditions.length === 0) {
      // All regex: combine with OR in eval/match
      lines.push('| where (');
      const regexClauses = regexConditions.map((cond, i) => {
        const prefix = i === 0 ? '    ' : '    OR ';
        return `${prefix}match(${cond.field}, "${splRegex(cond.value)}")`;
      });
      lines.push(...regexClauses);
      lines.push(')');
    } else {
      // Mixed operators: emit each as separate OR clause
      lines.push('| where (');
      const clauses: string[] = [];
      for (const cond of arrayConditions) {
        switch (cond.operator) {
          case 'regex':
            clauses.push(`match(${cond.field}, "${splRegex(cond.value)}")`);
            break;
          case 'contains':
            clauses.push(`like(${cond.field}, "%${escapeForSPL(cond.value)}%")`);
            break;
          case 'exact':
            clauses.push(`${cond.field}="${escapeForSPL(cond.value)}"`);
            break;
          case 'starts_with':
            clauses.push(`like(${cond.field}, "${escapeForSPL(cond.value)}%")`);
            break;
          case 'gt':
            clauses.push(`${cond.field} > ${Number(cond.value)}`);
            break;
          case 'lt':
            clauses.push(`${cond.field} < ${Number(cond.value)}`);
            break;
          case 'gte':
            clauses.push(`${cond.field} >= ${Number(cond.value)}`);
            break;
          case 'lte':
            clauses.push(`${cond.field} <= ${Number(cond.value)}`);
            break;
          case 'eq':
            clauses.push(`${cond.field} == ${Number(cond.value)}`);
            break;
          default:
            clauses.push(`like(${cond.field}, "%${escapeForSPL(cond.value)}%")`);
        }
      }
      lines.push(clauses.map((c, i) => (i === 0 ? `    ${c}` : `    OR ${c}`)).join('\n'));
      lines.push(')');
    }
  }

  // Add a table output for the analyst
  const fields = [...new Set(arrayConditions.map(c => c.field))];
  lines.push(`| table _time ${fields.join(' ')} source`);

  return lines.join('\n');
}
