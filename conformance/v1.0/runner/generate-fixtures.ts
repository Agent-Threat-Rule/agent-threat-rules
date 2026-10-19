#!/usr/bin/env tsx
/**
 * Generate ATR Conformance Test Suite v1.0 TP and TN fixtures from the
 * embedded `test_cases` blocks in each rule YAML. Each rule already
 * ships ≥5 TP + ≥5 TN test cases per the SPEC §5.1 contract; this
 * script lifts a deterministic subset of those into standalone
 * conformance fixtures.
 *
 * Strategy: walk rules/<category>/*.yaml in lexicographic order; for
 * each category, take the first N rules (where N is the per-category
 * quota); for each selected rule, take its first TP and first TN test
 * case and write them to fixtures/tp/<rule_id>/{input,expect} and
 * fixtures/tn/<rule_id>/{input,expect}.
 *
 * Never overwrites: a fixture directory that already has an input.yaml is
 * left as it is, so manually authored fixtures (ATR-2026-00451, -00523,
 * -00524) and published fixtures stay stable. To regenerate one, remove its
 * directory first.
 *
 * Rules are skipped when the reference runner cannot exercise them:
 *   - status draft or deprecated, or maturity deprecated: the reference
 *     Engine does not evaluate them (src/engine.ts evaluates());
 *   - a detection.method other than pattern: an Engine that does not
 *     implement the method skips the Rule (SPEC §6.6), and the runner drives
 *     neither semantic judges nor traces;
 *   - a scan target other than skill or both, with an agent_source.type the
 *     reference Engine admits on none of the runner's MCP channels
 *     (sourceTypeAdmits() in src/engine.ts, MCP_CHANNELS in channels.ts).
 *     Since #701 that leaves out memory_access, which the Engine withholds
 *     from typed events, but not context_window, which runs where llm_io
 *     rules run.
 *
 * The fixture `input` carries the test case's payload under the keys
 * src/testcase-event.ts reads. A test case that is only a string `input`
 * stays a plain string; anything else becomes a mapping that
 * run-conformance.ts passes on as event fields. A selected test case with no
 * payload at all is an error, not an empty fixture: before 2026-10, 41
 * fixtures were written with no payload because only `input` was read.
 *
 * Usage: tsx conformance/v1.0/runner/generate-fixtures.ts
 */

import { readFileSync, writeFileSync, readdirSync, mkdirSync, existsSync, statSync, realpathSync } from 'node:fs';
import { join, dirname, basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';
import { EVENT_TYPE_TO_SOURCE, sourceTypeAdmits } from '../../../src/engine.js';
import { MCP_CHANNELS } from './channels.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');
const RULES_ROOT = join(REPO_ROOT, 'rules');
const FIXTURE_ROOT = join(REPO_ROOT, 'conformance', 'v1.0', 'fixtures');

type TestCase = Record<string, unknown> & { description?: string };

interface RuleYaml {
  id: string;
  title: string;
  status?: string;
  maturity?: string;
  detection?: { method?: string };
  agent_source?: { type?: string };
  tags?: { category?: string; scan_target?: string };
  test_cases?: {
    true_positives?: TestCase[];
    true_negatives?: TestCase[];
  };
}

// Per-category quotas summing to ~100 fixtures. Tunable.
const QUOTAS: Record<string, number> = {
  'prompt-injection': 25,
  'agent-manipulation': 20,
  'skill-compromise': 12,
  'context-exfiltration': 12,
  'tool-poisoning': 10,
  'privilege-escalation': 8,
  'model-abuse': 6,
  'excessive-autonomy': 4,
  'model-security': 2,
  'data-poisoning': 1,
};

function loadRule(path: string): RuleYaml | null {
  try {
    const text = readFileSync(path, 'utf8');
    const doc = yaml.load(text) as RuleYaml;
    return doc && typeof doc === 'object' && typeof doc.id === 'string' ? doc : null;
  } catch {
    return null;
  }
}

function listRules(category: string): string[] {
  const dir = join(RULES_ROOT, category);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.yaml') && statSync(join(dir, f)).isFile())
    .sort()
    .map((f) => join(dir, f));
}

/** Statuses the reference Engine skips (src/engine.ts evaluates()), so their fixtures cannot pass against it. */
const SKIPPED_STATUSES = new Set(['draft', 'deprecated']);

/**
 * Whether the reference Engine admits a rule of this agent_source.type on at
 * least one of the events the runner presents an mcp payload as. Asked of the
 * Engine's own source filter, so the picks follow it when it changes.
 */
function admittedOnMcpChannels(sourceType: string): boolean {
  return MCP_CHANNELS.some((channel) => sourceTypeAdmits(sourceType, EVENT_TYPE_TO_SOURCE[channel]));
}

/** Test-case keys that carry a payload, as src/testcase-event.ts reads them. */
const PAYLOAD_KEYS = [
  'tool_name',
  'tool_args',
  'tool_response',
  'agent_output',
  'agent_message',
  'tool_description',
  'content',
] as const;

function asText(v: unknown): string {
  if (v === undefined || v === null) return '';
  return typeof v === 'string' ? v : JSON.stringify(v);
}

/**
 * The fixture `input` for a test case, or null when it carries no payload.
 * Reads the same payload keys as buildEventFromTestCase() in
 * src/testcase-event.ts. The event the runner builds from it differs in one
 * respect: buildEventFromTestCase also copies `input` into tool_args when a
 * test case has none, which the runner does not. As there: a `tool_call`
 * mapping supplies tool_name/tool_args, an object-valued `input` supplies
 * tool_name/tool_args/tool_response (`response` is an alias), and a string
 * `input` (or `user_input`) next to other payload keys becomes `user_input`.
 */
export function fixtureInputOf(tc: TestCase): string | Record<string, string> | null {
  const out: Record<string, string> = {};
  for (const key of PAYLOAD_KEYS) {
    const value = asText(tc[key]);
    if (value) out[key] = value;
  }
  const call = tc['tool_call'];
  if (call !== null && typeof call === 'object' && !Array.isArray(call)) {
    const c = call as Record<string, unknown>;
    if (c['name'] && !out.tool_name) out.tool_name = asText(c['name']);
    if (c['args'] && !out.tool_args) out.tool_args = asText(c['args']);
  }
  const raw = tc['input'] ?? tc['user_input'];
  if (raw !== null && typeof raw === 'object' && !Array.isArray(raw)) {
    const o = raw as Record<string, unknown>;
    if (o['tool_name'] && !out.tool_name) out.tool_name = asText(o['tool_name']);
    if (o['tool_args'] && !out.tool_args) out.tool_args = asText(o['tool_args']);
    const response = o['tool_response'] ?? o['response'];
    if (response && !out.tool_response) out.tool_response = asText(response);
    if (!out.tool_args && !out.tool_response) out.user_input = asText(raw);
  } else {
    const text = asText(raw);
    if (text && Object.keys(out).length === 0) return text;
    if (text) out.user_input = text;
  }
  return Object.keys(out).length > 0 ? out : null;
}

/**
 * The scan target a rule's fixtures declare: its tags.scan_target, or mcp,
 * which is also what run-conformance.ts assumes when a fixture has none.
 */
export function scanTargetOf(rule: RuleYaml): string {
  return rule.tags?.scan_target ?? 'mcp';
}

/** Why the reference runner cannot exercise a rule, or null when it can. */
export function unpassableReason(rule: RuleYaml): string | null {
  const status = rule.status ?? 'experimental';
  if (SKIPPED_STATUSES.has(status)) return `status ${status}`;
  if (rule.maturity === 'deprecated') return 'maturity deprecated';
  const method = rule.detection?.method ?? 'pattern';
  if (method !== 'pattern') return `detection.method ${method}`;
  const scanTarget = scanTargetOf(rule);
  const source = rule.agent_source?.type ?? 'llm_io';
  if (scanTarget !== 'skill' && scanTarget !== 'both' && !admittedOnMcpChannels(source)) {
    return `agent_source ${source} is admitted on none of the runner's MCP channels`;
  }
  return null;
}

function writeFixture(
  category: 'tp' | 'tn',
  ruleId: string,
  scanTarget: string,
  testCase: TestCase,
  payload: string | Record<string, string>,
): boolean {
  const dir = join(FIXTURE_ROOT, category, ruleId);
  if (existsSync(join(dir, 'input.yaml'))) return false;
  mkdirSync(dir, { recursive: true });
  const input: Record<string, unknown> = {
    scan_target: scanTarget,
    input: payload,
  };
  if (testCase.description) input.rationale = testCase.description;
  writeFileSync(join(dir, 'input.yaml'), yaml.dump(input, { lineWidth: -1 }));
  const expect = {
    outcome: category === 'tp' ? 'match' : 'no_match',
    rule_id: ruleId,
    ...(category === 'tp' ? { min_match_count: 1 } : {}),
  };
  writeFileSync(join(dir, 'expect.json'), JSON.stringify(expect, null, 2) + '\n');
  return true;
}

function main(): void {
  let tpWritten = 0;
  let tnWritten = 0;
  let tpSkipped = 0;
  let tnSkipped = 0;
  for (const [category, quota] of Object.entries(QUOTAS)) {
    let picked = 0;
    for (const path of listRules(category)) {
      if (picked >= quota) break;
      const rule = loadRule(path);
      if (!rule || !rule.test_cases) continue;
      if (unpassableReason(rule) !== null) continue;
      const tps = rule.test_cases.true_positives ?? [];
      const tns = rule.test_cases.true_negatives ?? [];
      if (tps.length === 0 || tns.length === 0) continue;
      const scanTarget = scanTargetOf(rule);
      // Both payloads first, so a test case without one cannot leave an
      // unpaired fixture behind.
      const tpPayload = fixtureInputOf(tps[0]!);
      const tnPayload = fixtureInputOf(tns[0]!);
      if (tpPayload === null || tnPayload === null) {
        throw new Error(`${rule.id}: its first ${tpPayload === null ? 'true positive' : 'true negative'} has no payload`);
      }
      const tpDone = writeFixture('tp', rule.id, scanTarget, tps[0]!, tpPayload);
      const tnDone = writeFixture('tn', rule.id, scanTarget, tns[0]!, tnPayload);
      if (tpDone) tpWritten++;
      else tpSkipped++;
      if (tnDone) tnWritten++;
      else tnSkipped++;
      picked++;
    }
    console.log(`  ${category}: picked ${picked}/${quota}`);
  }
  console.log(
    `[generate-fixtures] TP: ${tpWritten} written, ${tpSkipped} skipped (existed); TN: ${tnWritten} written, ${tnSkipped} skipped`,
  );
}

// Compare real paths: macOS reaches /tmp and /var through symlinks, and a
// script run through one must still run.
if (process.argv[1] && realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))) main();
