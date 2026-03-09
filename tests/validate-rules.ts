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
  'data-poisoning', 'model-abuse', 'skill-compromise',
];
const VALID_SOURCE_TYPES = [
  'llm_io', 'tool_call', 'mcp_exchange', 'agent_behavior',
  'multi_agent_comm', 'context_window', 'memory_access',
  'skill_lifecycle', 'skill_permission', 'skill_chain',
];
const VALID_ACTIONS = [
  'block_input', 'block_output', 'block_tool', 'quarantine_session',
  'reset_context', 'alert', 'snapshot', 'escalate', 'reduce_permissions',
  'kill_agent',
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
      if (!/^ATR-\d{4}-\d{3}$/.test(ruleId)) {
        errors.push(`Invalid id format: ${ruleId} (expected ATR-YYYY-NNN)`);
      }
    }

    // Status
    if (typeof rule['status'] === 'string' && !VALID_STATUSES.includes(rule['status'])) {
      errors.push(`Invalid status: ${rule['status']}`);
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
      if (!detection['conditions']) {
        errors.push('Missing detection.conditions');
      }
      if (!detection['condition']) {
        errors.push('Missing detection.condition (boolean expression)');
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
    }

    // Validate regex patterns don't cause errors
    if (detection?.['conditions']) {
      const conditions = detection['conditions'] as Record<string, Record<string, unknown>>;
      for (const [condName, condDef] of Object.entries(conditions)) {
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
