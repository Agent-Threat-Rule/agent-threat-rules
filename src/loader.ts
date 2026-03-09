/**
 * ATR Rule Loader - Reads and parses ATR YAML rule files
 * @module agent-threat-rules/loader
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import yaml from 'js-yaml';
import type { ATRRule } from './types.js';

/**
 * Load a single ATR rule from a YAML file.
 */
export function loadRuleFile(filePath: string): ATRRule {
  const content = readFileSync(filePath, 'utf-8');
  const parsed = yaml.load(content) as ATRRule;

  if (!parsed.id || !parsed.title || !parsed.detection) {
    throw new Error(`Invalid ATR rule in ${filePath}: missing required fields (id, title, detection)`);
  }

  return parsed;
}

/**
 * Recursively load all ATR YAML rules from a directory.
 */
export function loadRulesFromDirectory(dirPath: string): ATRRule[] {
  const rules: ATRRule[] = [];

  const entries = readdirSync(dirPath);
  for (const entry of entries) {
    const fullPath = join(dirPath, entry);
    const stat = statSync(fullPath);

    if (stat.isDirectory()) {
      rules.push(...loadRulesFromDirectory(fullPath));
    } else if (stat.isFile() && (extname(entry) === '.yaml' || extname(entry) === '.yml')) {
      try {
        rules.push(loadRuleFile(fullPath));
      } catch {
        // Skip invalid rule files — logged at caller level
      }
    }
  }

  return rules;
}

/**
 * Validate that a parsed object conforms to the ATR rule schema (basic checks).
 */
export function validateRule(rule: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  const r = rule as Record<string, unknown>;

  // Required fields
  const required = ['title', 'id', 'status', 'description', 'author', 'date', 'severity', 'tags', 'agent_source', 'detection', 'response'];
  for (const field of required) {
    if (!r[field]) {
      errors.push(`Missing required field: ${field}`);
    }
  }

  // ID format
  if (typeof r['id'] === 'string' && !/^ATR-\d{4}-\d{3}$/.test(r['id'])) {
    errors.push(`Invalid id format: ${r['id']} (expected ATR-YYYY-NNN)`);
  }

  // Status enum
  const validStatuses = ['draft', 'experimental', 'stable', 'deprecated'];
  if (typeof r['status'] === 'string' && !validStatuses.includes(r['status'])) {
    errors.push(`Invalid status: ${r['status']}`);
  }

  // Severity enum
  const validSeverities = ['critical', 'high', 'medium', 'low', 'informational'];
  if (typeof r['severity'] === 'string' && !validSeverities.includes(r['severity'])) {
    errors.push(`Invalid severity: ${r['severity']}`);
  }

  // Tags category
  const tags = r['tags'] as Record<string, unknown> | undefined;
  if (tags) {
    const validCategories = [
      'prompt-injection', 'tool-poisoning', 'context-exfiltration',
      'agent-manipulation', 'privilege-escalation', 'excessive-autonomy',
      'data-poisoning', 'model-abuse', 'skill-compromise',
    ];
    if (typeof tags['category'] === 'string' && !validCategories.includes(tags['category'])) {
      errors.push(`Invalid tags.category: ${tags['category']}`);
    }
  }

  // Agent source type
  const agentSource = r['agent_source'] as Record<string, unknown> | undefined;
  if (agentSource) {
    const validTypes = [
      'llm_io', 'tool_call', 'mcp_exchange', 'agent_behavior',
      'multi_agent_comm', 'context_window', 'memory_access',
      'skill_lifecycle', 'skill_permission', 'skill_chain',
    ];
    if (typeof agentSource['type'] === 'string' && !validTypes.includes(agentSource['type'])) {
      errors.push(`Invalid agent_source.type: ${agentSource['type']}`);
    }
  }

  // Detection must have conditions and condition
  const detection = r['detection'] as Record<string, unknown> | undefined;
  if (detection) {
    if (!detection['conditions']) {
      errors.push('Missing detection.conditions');
    }
    if (!detection['condition']) {
      errors.push('Missing detection.condition');
    }
  }

  // Response must have actions
  const response = r['response'] as Record<string, unknown> | undefined;
  if (response) {
    if (!Array.isArray(response['actions']) || response['actions'].length === 0) {
      errors.push('Missing or empty response.actions');
    }
  }

  // Test cases validation
  const testCases = r['test_cases'] as Record<string, unknown> | undefined;
  if (testCases) {
    const tp = testCases['true_positives'];
    const tn = testCases['true_negatives'];
    if (!Array.isArray(tp) || tp.length === 0) {
      errors.push('test_cases.true_positives must have at least one entry');
    }
    if (!Array.isArray(tn) || tn.length === 0) {
      errors.push('test_cases.true_negatives must have at least one entry');
    }
  }

  return { valid: errors.length === 0, errors };
}
