/**
 * Fixture rules for the blocking-eligibility tests.
 *
 * Each rule matches its own harmless marker string, so a test can pick exactly
 * which (maturity, severity, status) combination fires without depending on
 * the real rule set — whose maturities move as rules are promoted. The rules
 * read `content`, declare `scan_target: both` (so the SKILL.md path runs them)
 * and `agent_source.type: llm_io`.
 *
 * Not a test file: vitest only collects *.test.ts.
 */

import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ATRMatch, ATRRule } from '../../src/types.js';

export interface BlockingFixture {
  readonly id: string;
  readonly marker: string;
  readonly maturity: string;
  readonly severity: string;
  readonly status: string;
  readonly confirm?: string;
}

function fixture(
  suffix: string,
  maturity: string,
  severity: string,
  status = 'experimental',
  confirm?: string,
): BlockingFixture {
  return {
    id: `ATR-2026-092${suffix}`,
    marker: `blocking_fixture_${maturity}_${severity}_${status}${confirm ? '_confirm' : ''}`,
    maturity,
    severity,
    status,
    ...(confirm ? { confirm } : {}),
  };
}

/** The combinations every blocking surface is tested against. */
export const FIXTURES = Object.freeze({
  stableCritical: fixture('01', 'stable', 'critical'),
  stableHigh: fixture('02', 'stable', 'high'),
  stableMedium: fixture('03', 'stable', 'medium'),
  testCritical: fixture('04', 'test', 'critical'),
  experimentalCritical: fixture('05', 'experimental', 'critical'),
  draftStatusStableCritical: fixture('06', 'stable', 'critical', 'draft'),
});

/**
 * A rule object for ATREngine({ rules }) or for a hand-built match.
 * `sourceType` llm_io runs on llm_input/llm_output (and tool_response) events;
 * mcp_exchange runs on the tool_call and tool_response events the guard hook builds.
 */
export function fixtureRule(
  f: BlockingFixture,
  actions: readonly string[] = ['block_tool', 'alert'],
  sourceType: 'llm_io' | 'mcp_exchange' = 'llm_io',
): ATRRule {
  return {
    title: `Blocking fixture ${f.id}`,
    id: f.id,
    status: f.status,
    description: 'Fixture rule for blocking-eligibility tests.',
    author: 'ATR Community',
    date: '2026/11/04',
    schema_version: '0.1',
    maturity: f.maturity,
    severity: f.severity,
    ...(f.confirm ? { confirm: f.confirm } : {}),
    tags: { category: 'excessive-autonomy', subcategory: 'fixture', scan_target: 'both', confidence: 'high' },
    agent_source: { type: sourceType, framework: ['any'], provider: ['any'] },
    detection: {
      method: 'pattern',
      condition: 'any',
      conditions: [{ field: 'content', operator: 'regex', value: f.marker, description: 'fixture' }],
    },
    response: { actions: [...actions], message_template: 'fixture' },
  } as unknown as ATRRule;
}

/** A match of a fixture rule, as the engine would build it. */
export function fixtureMatch(
  f: BlockingFixture,
  overrides: Partial<ATRMatch> = {},
  actions?: readonly string[],
): ATRMatch {
  return {
    rule: fixtureRule(f, actions),
    matchedConditions: ['content'],
    matchedPatterns: [f.marker],
    confidence: 0.9,
    timestamp: new Date().toISOString(),
    scan_context: 'native',
    decidedBy: 'pattern',
    ...overrides,
  };
}

function fixtureYaml(f: BlockingFixture): string {
  return [
    `title: "Blocking fixture ${f.id}"`,
    `id: ${f.id}`,
    'rule_version: 1',
    `status: ${f.status}`,
    'description: "Fixture rule for blocking-eligibility tests."',
    'author: "ATR Community"',
    'date: "2026/11/04"',
    'schema_version: "0.1"',
    `maturity: ${f.maturity}`,
    `severity: ${f.severity}`,
    ...(f.confirm ? [`confirm: ${f.confirm}`] : []),
    'tags:',
    '  category: excessive-autonomy',
    '  subcategory: fixture',
    '  scan_target: both',
    '  confidence: high',
    'agent_source:',
    '  type: llm_io',
    '  framework: [any]',
    '  provider: [any]',
    'detection:',
    '  method: pattern',
    '  condition: any',
    '  conditions:',
    '    - field: content',
    '      operator: regex',
    `      value: "${f.marker}"`,
    '      description: "fixture"',
    'response:',
    '  actions: [block_tool, alert]',
    '  message_template: "fixture"',
    'test_cases:',
    '  true_positives:',
    `    - input: "${f.marker}"`,
    '      expected: triggered',
    '  true_negatives:',
    '    - input: "nothing to see"',
    '      expected: not_triggered',
    '',
  ].join('\n');
}

/** Write every fixture to a fresh rules directory. Call cleanup() when done. */
export function writeBlockingRulesDir(
  fixtures: readonly BlockingFixture[] = Object.values(FIXTURES),
): { readonly dir: string; cleanup(): void } {
  const root = mkdtempSync(join(tmpdir(), 'atr-blocking-rules-'));
  const dir = join(root, 'rules');
  mkdirSync(join(dir, 'excessive-autonomy'), { recursive: true });
  for (const f of fixtures) {
    writeFileSync(join(dir, 'excessive-autonomy', `${f.id}.yaml`), fixtureYaml(f));
  }
  return { dir, cleanup: () => rmSync(root, { recursive: true, force: true }) };
}
