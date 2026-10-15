/**
 * ATR Rule Validation Script
 *
 * Validates all ATR YAML rules in the rules/ directory against the schema.
 * Run with: pnpm run validate (uses tsx)
 * Or as part of test suite: pnpm test
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, extname, relative } from 'node:path';
import yaml from 'js-yaml';
import { validateContract } from '../src/quality/rule-contract.js';

const RULES_DIR = join(import.meta.dirname ?? '.', '..', 'rules');

interface ValidationResult {
  file: string;
  ruleId: string;
  valid: boolean;
  errors: string[];
  warnings: string[];
}

const VALID_STATUSES = ['draft', 'experimental', 'stable', 'deprecated'];
const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
const VALID_CATEGORIES = [
  'prompt-injection', 'tool-poisoning', 'context-exfiltration',
  'agent-manipulation', 'privilege-escalation', 'excessive-autonomy',
  'data-poisoning', 'model-abuse', 'model-security', 'skill-compromise',
];
const VALID_SOURCE_TYPES = [
  'llm_io', 'tool_call', 'mcp_exchange', 'agent_behavior',
  'multi_agent_comm', 'context_window', 'memory_access',
  'skill_lifecycle', 'skill_permission', 'skill_chain',
  'agent_trace',
];
const VALID_METHODS = ['pattern', 'signature', 'semantic', 'behavioral', 'trace'];
const VALID_ACTIONS = [
  // v1.0 vocabulary
  'block_input', 'block_output', 'block_tool', 'quarantine_session',
  'reset_context', 'alert', 'snapshot', 'escalate', 'reduce_permissions',
  'kill_agent',
  // SPEC.md Appendix A canonical action vocabulary (v1.0+)
  'block_request', 'log_alert', 'quarantine_artifact', 'require_human_review',
  'redact_match', 'rate_limit_source', 'revoke_credential', 'notify_operator',
];

function collectYamlFiles(dir: string): string[] {
  const files: string[] = [];
  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      const fullPath = join(dir, entry);
      const stat = statSync(fullPath);
      if (stat.isDirectory()) {
        files.push(...collectYamlFiles(fullPath));
      } else if (stat.isFile() && (extname(entry) === '.yaml' || extname(entry) === '.yml')) {
        files.push(fullPath);
      }
    }
  } catch {
    // Directory may not exist
  }
  return files;
}

function validateRule(filePath: string): ValidationResult {
  const relPath = relative(RULES_DIR, filePath);
  const errors: string[] = [];
  const warnings: string[] = [];
  let ruleId = 'unknown';

  try {
    const content = readFileSync(filePath, 'utf-8');
    const rule = yaml.load(content) as Record<string, unknown>;

    if (!rule || typeof rule !== 'object') {
      errors.push('File does not contain a valid YAML object');
      return { file: relPath, ruleId, valid: false, errors, warnings };
    }

    // Required fields
    const required = ['title', 'id', 'status', 'description', 'author', 'date', 'severity', 'tags', 'agent_source', 'detection', 'response'];
    for (const field of required) {
      if (!rule[field]) {
        errors.push(`Missing required field: ${field}`);
      }
    }

    // ID format
    if (typeof rule['id'] === 'string') {
      ruleId = rule['id'];
      if (!/^ATR-\d{4}-\d{5}$/.test(ruleId)) {
        errors.push(`Invalid id format: ${ruleId} (expected ATR-YYYY-NNNNN)`);
      }
    }

    // Status
    if (typeof rule['status'] === 'string' && !VALID_STATUSES.includes(rule['status'])) {
      errors.push(`Invalid status: ${rule['status']}`);
    }

    // Contract-level fields (maturity enum + confirm) — single source of truth.
    for (const e of validateContract(rule as { maturity?: unknown; confirm?: unknown; detection?: { method?: string } })) {
      errors.push(e);
    }

    // Severity
    if (typeof rule['severity'] === 'string' && !VALID_SEVERITIES.includes(rule['severity'])) {
      errors.push(`Invalid severity: ${rule['severity']}`);
    }

    // Tags
    const tags = rule['tags'] as Record<string, unknown> | undefined;
    if (tags) {
      if (!tags['category']) {
        errors.push('Missing tags.category');
      } else if (typeof tags['category'] === 'string' && !VALID_CATEGORIES.includes(tags['category'])) {
        errors.push(`Invalid tags.category: ${tags['category']}`);
      }
    }

    // Agent source
    const agentSource = rule['agent_source'] as Record<string, unknown> | undefined;
    if (agentSource) {
      if (!agentSource['type']) {
        errors.push('Missing agent_source.type');
      } else if (typeof agentSource['type'] === 'string' && !VALID_SOURCE_TYPES.includes(agentSource['type'])) {
        errors.push(`Invalid agent_source.type: ${agentSource['type']}`);
      }
    }

    // Detection
    const detection = rule['detection'] as Record<string, unknown> | undefined;
    if (detection) {
      // v1.1: method-based detection. method defaults to "pattern" if absent.
      const method = (detection['method'] as string | undefined) ?? 'pattern';
      if (!VALID_METHODS.includes(method)) {
        errors.push(`Invalid detection.method: ${method} (expected one of ${VALID_METHODS.join(', ')})`);
      }

      if (method === 'pattern') {
        // v1.0 pattern method: conditions + condition required.
        if (!detection['conditions']) {
          errors.push('Missing detection.conditions (required for method=pattern)');
        }
        if (!detection['condition']) {
          errors.push('Missing detection.condition (boolean expression, required for method=pattern)');
        }
      } else if (method === 'signature') {
        // §5: detection.signature.indicators required.
        const sig = detection['signature'] as Record<string, unknown> | undefined;
        if (!sig) {
          errors.push('Missing detection.signature (required for method=signature)');
        } else {
          const indicators = sig['indicators'] as unknown[] | undefined;
          if (!Array.isArray(indicators) || indicators.length === 0) {
            errors.push('detection.signature.indicators must be a non-empty array');
          }
        }
      } else if (method === 'semantic') {
        // §6: detection.semantic.prompt_template + threshold + judge_model_class required.
        const sem = detection['semantic'] as Record<string, unknown> | undefined;
        if (!sem) {
          errors.push('Missing detection.semantic (required for method=semantic)');
        } else {
          for (const field of ['judge_model_class', 'prompt_template', 'threshold']) {
            if (sem[field] === undefined) {
              errors.push(`Missing detection.semantic.${field}`);
            }
          }
        }
      } else if (method === 'trace') {
        // §8: detection.trace with at least one of forbid/require/invariant.
        const trace = detection['trace'] as Record<string, unknown> | undefined;
        if (!trace) {
          errors.push('Missing detection.trace (required for method=trace)');
        } else {
          const hasPrimitive = ['forbid', 'require', 'invariant'].some(
            (p) => Array.isArray(trace[p]) && (trace[p] as unknown[]).length > 0
          );
          if (!hasPrimitive) {
            errors.push('detection.trace requires at least one non-empty primitive (forbid/require/invariant)');
          }
        }
      } else if (method === 'behavioral') {
        // §7: detection.behavioral requires metric, aggregation, window, operator, threshold.
        const beh = detection['behavioral'] as Record<string, unknown> | undefined;
        if (!beh) {
          errors.push('Missing detection.behavioral (required for method=behavioral)');
        } else {
          for (const field of ['metric', 'aggregation', 'window', 'operator', 'threshold']) {
            if (beh[field] === undefined) {
              errors.push(`Missing detection.behavioral.${field}`);
            }
          }
          const validAgg = ['count', 'sum', 'avg', 'max', 'distinct_count', 'rate'];
          if (beh['aggregation'] && !validAgg.includes(beh['aggregation'] as string)) {
            errors.push(`Invalid detection.behavioral.aggregation: ${beh['aggregation']}`);
          }
          const validOp = ['gt', 'lt', 'gte', 'lte', 'eq', 'deviation_from_baseline'];
          if (beh['operator'] && !validOp.includes(beh['operator'] as string)) {
            errors.push(`Invalid detection.behavioral.operator: ${beh['operator']}`);
          }
          if (beh['operator'] === 'deviation_from_baseline' && !beh['baseline']) {
            errors.push('detection.behavioral.baseline required when operator=deviation_from_baseline');
          }
        }
      }
    }

    // Response
    const response = rule['response'] as Record<string, unknown> | undefined;
    if (response) {
      const actions = response['actions'] as string[] | undefined;
      if (!Array.isArray(actions) || actions.length === 0) {
        errors.push('Missing or empty response.actions');
      } else {
        for (const action of actions) {
          if (!VALID_ACTIONS.includes(action)) {
            errors.push(`Invalid response action: ${action}`);
          }
        }
      }
    }

    // Test cases (warning if missing)
    const testCases = rule['test_cases'] as Record<string, unknown> | undefined;
    if (!testCases) {
      warnings.push('Missing test_cases (recommended)');
    } else {
      const tp = testCases['true_positives'] as unknown[];
      const tn = testCases['true_negatives'] as unknown[];
      if (!Array.isArray(tp) || tp.length < 2) {
        warnings.push('test_cases.true_positives should have at least 2 entries');
      }
      if (!Array.isArray(tn) || tn.length < 2) {
        warnings.push('test_cases.true_negatives should have at least 2 entries');
      }
    }

    // References (warning if missing)
    if (!rule['references']) {
      warnings.push('Missing references (OWASP LLM / MITRE ATLAS mapping recommended)');
    } else {
      // Every reference list must hold plain strings. spec/schema/rule.schema.json
      // already says items: {type: string}, but nothing enforced it here, so an
      // unquoted framework title containing ": " parsed as a YAML map instead of a
      // string and shipped to main. The website renders these straight into JSX,
      // where a map is not a valid React child, and every deploy after it failed
      // at prerender for three days while validate stayed green. Error, not warning.
      const references = rule['references'] as Record<string, unknown>;
      for (const [field, value] of Object.entries(references)) {
        if (!Array.isArray(value)) continue;
        value.forEach((entry, i) => {
          if (typeof entry !== 'string') {
            errors.push(
              `references.${field}[${i}] must be a string, got ${
                Array.isArray(entry) ? 'array' : typeof entry
              } (${JSON.stringify(entry)}). A value containing ": " needs quoting in YAML.`
            );
          }
        });
      }
    }

    // Validate regex patterns don't cause errors
    if (detection?.['conditions']) {
      const conditions = detection['conditions'];
      if (Array.isArray(conditions)) {
        // Array format: [{field, operator, value, description?}, ...]
        for (const cond of conditions as Array<Record<string, unknown>>) {
          if (cond['operator'] === 'regex' && typeof cond['value'] === 'string') {
            let pattern = cond['value'];
            // Strip leading inline flags (JS uses RegExp flags instead)
            pattern = pattern.replace(/^\(\?[imsx]+\)/, '');
            try {
              // Use 'u' when the pattern needs it. \u{...} and \p{...} need it by
              // syntax; so does a literal astral character, because without 'u' a
              // class range written with literals is a SyntaxError rather than a
              // range. Literals are the spelling ATR rules use, since \u{...} is
              // JS-only and unusable from the Python and Go channels — keep this
              // in step with needsUnicodeFlag in src/engine.ts.
              const needsUnicode =
                /\\u\{|\\p\{/.test(pattern) ||
                [...pattern].some((ch) => (ch.codePointAt(0) ?? 0) > 0xffff);
              new RegExp(pattern, needsUnicode ? 'u' : '');
            } catch (e) {
              const desc = cond['description'] ?? cond['field'] ?? 'unknown';
              errors.push(`Invalid regex in condition (${desc}): ${cond['value']} (${e instanceof Error ? e.message : String(e)})`);
            }
          }
        }
      } else {
        // Named-map format: {condName: {patterns, match_type, ...}, ...}
        const namedConditions = conditions as Record<string, Record<string, unknown>>;
        for (const [condName, condDef] of Object.entries(namedConditions)) {
          const patterns = condDef['patterns'] as string[] | undefined;
          const matchType = condDef['match_type'] as string | undefined;
          if (patterns && matchType === 'regex') {
            for (const pattern of patterns) {
              try {
                new RegExp(pattern, 'i');
              } catch (e) {
                errors.push(`Invalid regex in ${condName}: ${pattern} (${e instanceof Error ? e.message : String(e)})`);
              }
            }
          }
        }
      }
    }

  } catch (e) {
    errors.push(`YAML parse error: ${e instanceof Error ? e.message : String(e)}`);
  }

  return { file: relPath, ruleId, valid: errors.length === 0, errors, warnings };
}

// Main execution
const files = collectYamlFiles(RULES_DIR);
const results: ValidationResult[] = files.map(validateRule);

let hasErrors = false;
const ids = new Set<string>();

console.log(`\nATR Rule Validation: ${files.length} files found\n`);
console.log('='.repeat(60));

for (const result of results) {
  // Check for duplicate IDs
  if (ids.has(result.ruleId)) {
    result.errors.push(`Duplicate rule ID: ${result.ruleId}`);
    result.valid = false;
  }
  ids.add(result.ruleId);

  if (!result.valid) {
    hasErrors = true;
    console.log(`\n[FAIL] ${result.file} (${result.ruleId})`);
    for (const err of result.errors) {
      console.log(`  ERROR: ${err}`);
    }
  } else {
    console.log(`[PASS] ${result.file} (${result.ruleId})`);
  }

  for (const warn of result.warnings) {
    console.log(`  WARN: ${warn}`);
  }
}

console.log('\n' + '='.repeat(60));
const passed = results.filter((r) => r.valid).length;
const failed = results.filter((r) => !r.valid).length;
console.log(`Results: ${passed} passed, ${failed} failed, ${files.length} total`);

if (hasErrors) {
  console.log('\nValidation FAILED');
  process.exit(1);
} else {
  console.log('\nAll rules valid');
}
