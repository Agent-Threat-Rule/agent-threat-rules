#!/usr/bin/env node
/**
 * ATR CLI - Command-line interface for Agent Threat Rules
 *
 * Usage:
 *   npx agent-threat-rules scan <events.json>     Scan events against all rules
 *   npx agent-threat-rules validate <rule.yaml>    Validate a rule file
 *   npx agent-threat-rules test <rule.yaml>        Run a rule's test cases
 *   npx agent-threat-rules stats                   Show rule collection stats
 */

import { readFileSync, writeFileSync, readdirSync, existsSync, statSync, mkdirSync } from 'node:fs';
import { resolve, dirname, join, sep } from 'node:path';
import { homedir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { ATREngine } from './engine.js';
import { loadRuleFile, loadRulesFromDirectory, validateRule } from './loader.js';
import type { AgentEvent, ATRMatch, ATRRule } from './types.js';
import { generateBadgeSvg, generateBadgeEndpoint, lookupPackageScan, generateBadgeMarkdown } from './badge.js';
import { cmdScanUnified } from './cli/scan-handler.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const RULES_DIR = resolve(__dirname, '..', 'rules');

const SEVERITY_COLORS: Record<string, string> = {
  critical: '\x1b[91m',  // bright red
  high: '\x1b[31m',       // red
  medium: '\x1b[33m',     // yellow
  low: '\x1b[36m',        // cyan
  informational: '\x1b[37m', // white
};
const RESET = '\x1b[0m';
const GREEN = '\x1b[32m';
const RED = '\x1b[31m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';

function printUsage(): void {
  console.log(`
${BOLD}ATR - Agent Threat Rules${RESET}
Open detection rules for AI agent security threats.

${BOLD}Usage:${RESET}
  atr scan <file|dir> [--rules <dir>]       Auto-detect and scan (JSON=MCP, .md=SKILL.md)
  atr scan-skill <SKILL.md|dir>            Scan SKILL.md files (alias for scan)
  atr validate <rule.yaml|dir>             Validate rule file(s)
  atr test <rule.yaml|dir>                 Run embedded test cases
  atr stats [--rules <dir>]                Show rule collection statistics
  atr convert <splunk|elastic> [--rules <dir>] [--output <file>]
                                           Convert rules to SIEM query format
  atr guard [--rules <dir>] [--dry-run]    Start as Claude Code hook (stdio)
  atr init [--global]                      Setup ATR guard hook for Claude Code
  atr mcp                                  Start MCP server (stdio transport)
  atr scaffold                             Interactive rule scaffolding
  atr scaffold-semantic                    Interactive semantic rule scaffolding
  atr badge <package> [--data <audit.json>] [--svg] [--json]
                                           Generate ATR Scanned badge for a package

${BOLD}Threat Cloud Pipeline:${RESET}
  atr tc status                            Show TC state (rules, proposals, threats)
  atr tc sync [--tc-key <key>]             Push repo rules → TC (updates metrics + website)
  atr tc pull [--since <ISO>]              Pull confirmed TC rules → repo (validate + write)
  atr tc crystallize                       Send missed attacks → TC LLM → new proposals

${BOLD}Options:${RESET}
  --rules <dir>    Custom rules directory (default: bundled rules)
  --json           Output results as JSON
  --sarif          Output results as SARIF v2.1.0 (GitHub Security tab)
  --output <file>  Write output to file instead of stdout (convert)
  --severity <s>   Minimum severity to report (critical|high|medium|low|informational)
  --semantic       Enable method=semantic rules using an OpenAI-compatible judge
  --semantic-api-key <key>       Judge API key (or ATR_SEMANTIC_API_KEY / LLM_API_KEY)
  --semantic-base-url <url>      Judge API base URL (or ATR_SEMANTIC_BASE_URL / LLM_BASE_URL)
  --semantic-model <model>       Judge model (or ATR_SEMANTIC_MODEL / LLM_MODEL)
  --semantic-timeout <ms>        Judge request timeout (or ATR_SEMANTIC_TIMEOUT_MS)
  --semantic-no-json-mode        Do not send OpenAI JSON-mode response_format
  --no-report        Disable anonymous Threat Cloud reporting (enabled by default)
  --tc-url <url>     Threat Cloud endpoint (default: https://tc.panguard.ai)
  --dry-run        Log actions without executing (guard mode)
  --fail-open      Default to allow on errors (guard mode, default: true)
  --timeout <ms>   Evaluation timeout in ms (guard mode, default: 5000)
  --global         Write hook to ~/.claude/settings.json instead of project (init)
  --help           Show this help message

${BOLD}Examples:${RESET}
  ${DIM}# Scan agent events for threats${RESET}
  atr scan events.json

  ${DIM}# Validate a custom rule${RESET}
  atr validate my-rules/custom-rule.yaml

  ${DIM}# Test all rules against their embedded test cases${RESET}
  atr test rules/

  ${DIM}# Show stats for bundled rules${RESET}
  atr stats

  ${DIM}# One-command Claude Code hook setup${RESET}
  atr init

  ${DIM}# Run as a Claude Code guard hook${RESET}
  atr guard --rules ./my-rules

  ${DIM}# Start MCP server for AI agent integration${RESET}
  atr mcp

  ${DIM}# Convert all rules to Splunk SPL${RESET}
  atr convert splunk --output splunk-queries.txt

  ${DIM}# Convert all rules to Elasticsearch Query DSL${RESET}
  atr convert elastic --json --output elastic-queries.json

  ${DIM}# Interactively scaffold a new rule${RESET}
  atr scaffold
`);
}

function parseArgs(argv: string[]): { command: string; target: string; options: Record<string, string> } {
  const args = argv.slice(2);
  const command = args[0] ?? 'help';
  const options: Record<string, string> = {};
  let target = '';

  for (let i = 1; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      if (key === 'json' || key === 'sarif' || key === 'help' || key === 'dry-run' || key === 'fail-open' || key === 'global' || key === 'svg' || key === 'no-report' || key === 'report-to-cloud' || key === 'semantic' || key === 'semantic-no-json-mode') {
        options[key] = 'true';
      } else {
        options[key] = args[++i] ?? '';
      }
    } else if (!target) {
      target = args[i];
    }
  }

  return { command, target, options };
}

// --- VALIDATE command ---

function cmdValidate(target: string, options: Record<string, string>): void {
  if (!target) {
    console.error(`${RED}Error: Missing rule file/directory. Usage: atr validate <rule.yaml|dir>${RESET}`);
    process.exit(1);
  }

  const targetPath = resolve(target);
  if (!existsSync(targetPath)) {
    console.error(`${RED}Error: Not found: ${targetPath}${RESET}`);
    process.exit(1);
  }

  const jsonOutput = options['json'] === 'true';
  const files: string[] = [];

  if (statSync(targetPath).isDirectory()) {
    collectYamlFiles(targetPath, files);
  } else {
    files.push(targetPath);
  }

  let passed = 0;
  let failed = 0;
  const results: Array<{ file: string; valid: boolean; errors: string[] }> = [];

  for (const file of files) {
    try {
      const rule = loadRuleFile(file);
      const result = validateRule(rule);
      results.push({ file, valid: result.valid, errors: result.errors });
      if (result.valid) {
        passed++;
      } else {
        failed++;
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      results.push({ file, valid: false, errors: [msg] });
      failed++;
    }
  }

  if (jsonOutput) {
    console.log(JSON.stringify({ total: files.length, passed, failed, results }, null, 2));
    return;
  }

  console.log(`\n${BOLD}ATR Rule Validation${RESET}`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);

  for (const r of results) {
    const icon = r.valid ? `${GREEN}PASS${RESET}` : `${RED}FAIL${RESET}`;
    const shortPath = r.file.replace(process.cwd() + '/', '');
    console.log(`  ${icon}  ${shortPath}`);
    if (!r.valid) {
      for (const err of r.errors) {
        console.log(`       ${RED}${err}${RESET}`);
      }
    }
  }

  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(`  ${GREEN}${passed} passed${RESET}  ${failed > 0 ? RED + failed + ' failed' + RESET : ''}\n`);

  if (failed > 0) process.exit(1);
}

function collectYamlFiles(dir: string, out: string[]): void {
  const entries = readdirSync(dir);
  for (const entry of entries) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      collectYamlFiles(full, out);
    } else if (full.endsWith('.yaml') || full.endsWith('.yml')) {
      out.push(full);
    }
  }
}

// --- TEST command ---

async function cmdTest(target: string, options: Record<string, string>): Promise<void> {
  if (!target) {
    // Default: test bundled rules
    target = RULES_DIR;
  }

  const targetPath = resolve(target);
  if (!existsSync(targetPath)) {
    console.error(`${RED}Error: Not found: ${targetPath}${RESET}`);
    process.exit(1);
  }

  const jsonOutput = options['json'] === 'true';
  const rules: ATRRule[] = [];

  if (statSync(targetPath).isDirectory()) {
    rules.push(...loadRulesFromDirectory(targetPath));
  } else {
    rules.push(loadRuleFile(targetPath));
  }

  let totalTests = 0;
  let passed = 0;
  let failed = 0;
  const failures: Array<{ ruleId: string; testType: string; input: string; expected: string; got: string }> = [];

  // Map extended agent_source types to basic event-compatible source types
  // so the engine's source type filter doesn't skip rules during testing.
  // The engine only recognizes: llm_io, tool_call, mcp_exchange, agent_behavior, multi_agent_comm
  const EXTENDED_SOURCE_TO_BASE: Record<string, string> = {
    context_window: 'llm_io',
    memory_access: 'llm_io',
    skill_lifecycle: 'tool_call',
    skill_permission: 'tool_call',
    skill_chain: 'tool_call',
  };

  for (const rule of rules) {
    if (!rule.test_cases) continue;

    // For testing, normalize extended source types so the engine doesn't filter them out
    const originalSourceType = rule.agent_source?.type;
    const baseSourceType = EXTENDED_SOURCE_TO_BASE[originalSourceType ?? ''];

    // Override status so draft/deprecated rules are not skipped during testing
    const testRule = {
      ...rule,
      status: 'experimental' as const,
      ...(baseSourceType
        ? { agent_source: { ...rule.agent_source, type: baseSourceType as ATRRule['agent_source']['type'] } }
        : {}),
    };

    const engine = new ATREngine({ rules: [testRule] });
    await engine.loadRules();

    const tp = rule.test_cases.true_positives ?? [];
    const tn = rule.test_cases.true_negatives ?? [];

    // Test via both evaluate() and scanSkill() — pass if either detects
    const runTest = (tcObj: Record<string, unknown>): boolean => {
      const event = buildEventFromTestCase(tcObj, rule);
      const mcpHit = engine.evaluate(event).some(m => m.rule.id === rule.id);
      if (mcpHit) return true;
      const input = String(tcObj['input'] ?? tcObj['tool_response'] ?? tcObj['agent_output'] ?? '');
      if (input) {
        const skillHit = engine.scanSkill(input).some(m => m.rule.id === rule.id);
        if (skillHit) return true;
      }
      return false;
    };

    for (const tc of tp) {
      totalTests++;
      const triggered = runTest(tc as unknown as Record<string, unknown>);
      if (triggered) {
        passed++;
      } else {
        failed++;
        failures.push({
          ruleId: rule.id,
          testType: 'true_positive',
          input: String(tc.input ?? tc.tool_response ?? tc.agent_output ?? '').slice(0, 100),
          expected: 'triggered',
          got: 'not_triggered',
        });
      }
    }

    for (const tc of tn) {
      totalTests++;
      const triggered = runTest(tc as unknown as Record<string, unknown>);
      if (!triggered) {
        passed++;
      } else {
        failed++;
        failures.push({
          ruleId: rule.id,
          testType: 'true_negative',
          input: String(tc.input ?? tc.tool_response ?? tc.agent_output ?? '').slice(0, 100),
          expected: 'not_triggered',
          got: 'triggered',
        });
      }
    }
  }

  if (jsonOutput) {
    console.log(JSON.stringify({ totalRules: rules.length, totalTests, passed, failed, failures }, null, 2));
    return;
  }

  console.log(`\n${BOLD}ATR Test Runner${RESET}`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(`  Rules tested:    ${rules.length}`);
  console.log(`  Test cases:      ${totalTests}`);
  console.log(`  ${GREEN}Passed:${RESET}          ${passed}`);
  if (failed > 0) {
    console.log(`  ${RED}Failed:${RESET}          ${failed}`);
  }
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);

  if (failures.length > 0) {
    console.log(`\n${RED}Failures:${RESET}\n`);
    for (const f of failures) {
      console.log(`  ${RED}FAIL${RESET} ${f.ruleId} [${f.testType}]`);
      console.log(`    ${DIM}Input: "${f.input}..."${RESET}`);
      console.log(`    Expected: ${f.expected}, Got: ${f.got}\n`);
    }
    process.exit(1);
  } else {
    console.log(`\n${GREEN}All tests passed.${RESET}\n`);
  }
}

function buildEventFromTestCase(
  tc: Record<string, unknown>,
  rule: ATRRule,
): AgentEvent {
  // Stringify any object values
  const str = (v: unknown): string => {
    if (v === undefined || v === null) return '';
    if (typeof v === 'string') return v;
    return JSON.stringify(v);
  };

  // Extract fields, handling multiple test case formats:
  // Object-style: input: { tool_name: "...", tool_args: "...", response: "..." }
  // Flat-style: input: "...", tool_response: "...", tool_name: "..."
  // Tool-call-style: tool_call: { name: "...", args: "..." }
  const rawInput = tc['input'];
  let input = '';
  let toolName = str(tc['tool_name']);
  let toolArgs = str(tc['tool_args']);
  let toolResponse = str(tc['tool_response']);
  const agentOutput = str(tc['agent_output']);
  const toolDescription = str(tc['tool_description']);
  const rawContent = str(tc['content']);

  // Handle tool_call: { name, args } format (used by tool_call rules like ATR-2026-00098)
  const rawToolCall = tc['tool_call'];
  if (rawToolCall !== null && rawToolCall !== undefined && typeof rawToolCall === 'object' && !Array.isArray(rawToolCall)) {
    const tcObj = rawToolCall as Record<string, unknown>;
    if (tcObj['name'] && !toolName) toolName = str(tcObj['name']);
    if (tcObj['args'] && !toolArgs) toolArgs = str(tcObj['args']);
  }

  if (rawInput !== null && rawInput !== undefined && typeof rawInput === 'object' && !Array.isArray(rawInput)) {
    const inputObj = rawInput as Record<string, unknown>;
    if (inputObj['tool_name'] && !toolName) toolName = str(inputObj['tool_name']);
    if (inputObj['tool_args'] && !toolArgs) toolArgs = str(inputObj['tool_args']);
    // Handle 'response' as alias for 'tool_response' (used in ATR-065 etc.)
    if (inputObj['response'] && !toolResponse) toolResponse = str(inputObj['response']);
    if (inputObj['tool_response'] && !toolResponse) toolResponse = str(inputObj['tool_response']);
    // For object inputs, use tool_args as the primary string input.
    // If no tool_args, only use JSON-stringified input as fallback when there's
    // no other meaningful field (tool_response/response) extracted.
    if (toolArgs) {
      input = toolArgs;
    } else if (!toolResponse) {
      input = str(rawInput);
    }
  } else {
    input = str(rawInput);
  }

  // Infer event type from rule's agent_source and test case structure
  const sourceType = rule.agent_source?.type ?? 'llm_io';

  const SOURCE_TO_EVENT: Record<string, AgentEvent['type']> = {
    llm_io: 'llm_input',
    tool_call: 'tool_call',
    mcp_exchange: 'tool_response',
    agent_behavior: 'agent_behavior',
    multi_agent_comm: 'multi_agent_message',
    context_window: 'llm_input',
    memory_access: 'llm_input',
    skill_lifecycle: 'tool_call',
    skill_permission: 'tool_call',
    skill_chain: 'tool_call',
  };

  let type: AgentEvent['type'] = SOURCE_TO_EVENT[sourceType] ?? 'llm_input';

  // If rule expects tool_call but test case has only plain text input
  // (no tool_name, tool_args, or tool_response), use llm_input event type
  // since the content is natural language, not a tool invocation.
  // This prevents the engine's tool_name fallback from treating text as a tool name.
  if (type === 'tool_call' && !toolName && !toolArgs && !toolResponse && !toolDescription) {
    type = 'llm_input';
  }

  // Determine the primary content based on what the rule conditions check
  // Problem 2 & 3: For rules that check tool_response, the tool_response
  // should be the primary content when the event type resolves tool_response from content
  let content: string;
  if (toolResponse && type === 'tool_response') {
    // If event type is tool_response, engine resolves field:tool_response from event.content
    content = toolResponse;
  } else {
    content = input || toolDescription || rawContent || toolResponse || agentOutput || '';
  }

  const fields: Record<string, string> = {};

  // Populate ALL known field aliases so the engine can resolve any field name
  if (input) fields['user_input'] = input;
  if (toolResponse) fields['tool_response'] = toolResponse;
  if (agentOutput) fields['agent_output'] = agentOutput;
  if (toolDescription) fields['tool_description'] = toolDescription;
  // Always set tool_name (even empty) to prevent engine fallback
  // from using event.content as tool_name for tool_call events
  fields['tool_name'] = toolName;
  if (toolArgs) fields['tool_args'] = toolArgs;

  // For content-based rules, set content and agent_message fields
  fields['content'] = content;
  fields['agent_message'] = content;


  return {
    type,
    timestamp: new Date().toISOString(),
    content,
    fields,
    sessionId: 'test-session',
    agentId: 'test-agent',
  };
}

// --- STATS command ---

function cmdStats(options: Record<string, string>): void {
  const rulesDir = options['rules'] ? resolve(options['rules']) : RULES_DIR;
  const jsonOutput = options['json'] === 'true';
  const rules = loadRulesFromDirectory(rulesDir);

  const byCategory: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  const byMaturity: Record<string, number> = {};
  const byTier: Record<string, number> = {};
  let totalTP = 0;
  let totalTN = 0;
  let totalEvasion = 0;
  let withCVE = 0;

  for (const rule of rules) {
    const cat = rule.tags?.category ?? 'unknown';
    byCategory[cat] = (byCategory[cat] ?? 0) + 1;
    bySeverity[rule.severity] = (bySeverity[rule.severity] ?? 0) + 1;

    const maturity = rule.maturity ?? 'experimental';
    byMaturity[maturity] = (byMaturity[maturity] ?? 0) + 1;

    const tier = rule.detection_tier ?? 'pattern';
    byTier[tier] = (byTier[tier] ?? 0) + 1;

    if (rule.test_cases) {
      totalTP += rule.test_cases.true_positives?.length ?? 0;
      totalTN += rule.test_cases.true_negatives?.length ?? 0;
    }

    const evasion = (rule as unknown as Record<string, unknown>)['evasion_tests'];
    if (Array.isArray(evasion)) totalEvasion += evasion.length;

    if (rule.references?.cve && rule.references.cve.length > 0) withCVE++;
  }

  if (jsonOutput) {
    console.log(JSON.stringify({
      totalRules: rules.length,
      byCategory, bySeverity, byMaturity, byTier,
      testCases: { truePositives: totalTP, trueNegatives: totalTN, evasionTests: totalEvasion },
      rulesWithCVE: withCVE,
    }, null, 2));
    return;
  }

  console.log(`\n${BOLD}ATR Rule Collection Statistics${RESET}`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(`  Total rules:     ${rules.length}`);
  console.log(`  True positives:  ${totalTP}`);
  console.log(`  True negatives:  ${totalTN}`);
  console.log(`  Evasion tests:   ${totalEvasion}`);
  console.log(`  Rules with CVE:  ${withCVE}`);

  console.log(`\n  ${BOLD}By Category:${RESET}`);
  for (const [cat, count] of Object.entries(byCategory).sort((a, b) => b[1] - a[1])) {
    console.log(`    ${cat.padEnd(24)} ${count}`);
  }

  console.log(`\n  ${BOLD}By Severity:${RESET}`);
  for (const sev of ['critical', 'high', 'medium', 'low', 'informational']) {
    if (bySeverity[sev]) {
      const color = SEVERITY_COLORS[sev] ?? '';
      console.log(`    ${color}${sev.padEnd(24)}${RESET} ${bySeverity[sev]}`);
    }
  }

  console.log(`\n  ${BOLD}By Maturity:${RESET}`);
  for (const [mat, count] of Object.entries(byMaturity).sort((a, b) => b[1] - a[1])) {
    console.log(`    ${mat.padEnd(24)} ${count}`);
  }

  console.log(`\n  ${BOLD}By Detection Tier:${RESET}`);
  for (const [tier, count] of Object.entries(byTier).sort((a, b) => b[1] - a[1])) {
    console.log(`    ${tier.padEnd(24)} ${count}`);
  }

  console.log('');
}

// --- GUARD command ---

async function cmdGuard(options: Record<string, string>): Promise<void> {
  const rulesDir = options['rules'] ? resolve(options['rules']) : RULES_DIR;
  const dryRun = options['dry-run'] === 'true';
  const failOpen = options['fail-open'] !== 'false';
  const parsedTimeout = options['timeout'] ? parseInt(options['timeout'], 10) : 5000;
  const timeoutMs = (Number.isFinite(parsedTimeout) && parsedTimeout > 0) ? parsedTimeout : 5000;

  const { ActionExecutor } = await import('./action-executor.js');
  const { StdioAdapter } = await import('./adapters/stdio-adapter.js');
  const { HookHandler } = await import('./hook-handler.js');

  const engine = new ATREngine({ rulesDir });
  const ruleCount = await engine.loadRules();

  const adapter = new StdioAdapter();
  const executor = new ActionExecutor({ adapter, dryRun });
  const handler = new HookHandler({ engine, executor, timeoutMs, failOpen });

  process.stderr.write(
    `[atr-guard] Loaded ${ruleCount} rules from ${rulesDir}` +
    `${dryRun ? ' (dry-run)' : ''}\n`
  );

  await handler.startStdioLoop();
}

// --- MCP command ---

async function cmdMcp(): Promise<void> {
  const { startMCPServer } = await import('./mcp-server.js');
  await startMCPServer();
}

// --- SCAFFOLD command ---

async function cmdScaffold(): Promise<void> {
  const { createInterface } = await import('node:readline');
  const { RuleScaffolder } = await import('./rule-scaffolder.js');

  const rl = createInterface({ input: process.stdin, output: process.stdout });

  const ask = (question: string): Promise<string> =>
    new Promise((resolve) => rl.question(question, resolve));

  console.log(`\n${BOLD}ATR Rule Scaffolder${RESET}`);
  console.log(`${DIM}Generate a draft ATR detection rule interactively.${RESET}\n`);

  const title = await ask('Rule title: ');
  if (!title.trim()) {
    console.error(`${RED}Error: Title is required.${RESET}`);
    rl.close();
    process.exit(1);
  }

  const categories = [
    'prompt-injection', 'tool-poisoning', 'context-exfiltration',
    'agent-manipulation', 'privilege-escalation', 'excessive-autonomy',
    'data-poisoning', 'model-abuse', 'skill-compromise',
  ];
  console.log(`\nCategories: ${categories.join(', ')}`);
  const category = await ask('Category: ');
  if (!categories.includes(category.trim())) {
    console.error(`${RED}Error: Invalid category.${RESET}`);
    rl.close();
    process.exit(1);
  }

  const attackDescription = await ask('Attack description: ');
  if (!attackDescription.trim()) {
    console.error(`${RED}Error: Description is required.${RESET}`);
    rl.close();
    process.exit(1);
  }

  console.log('\nEnter example payloads (one per line, empty line to finish):');
  const payloads: string[] = [];
  while (true) {
    const payload = await ask(`  Payload ${payloads.length + 1}: `);
    if (!payload.trim()) break;
    payloads.push(payload.trim());
  }

  if (payloads.length === 0) {
    console.error(`${RED}Error: At least one example payload is required.${RESET}`);
    rl.close();
    process.exit(1);
  }

  const severities = ['critical', 'high', 'medium', 'low', 'informational'];
  const severity = await ask(`Severity [${severities.join('/')}] (default: medium): `);
  const finalSeverity = severity.trim() && severities.includes(severity.trim())
    ? severity.trim()
    : 'medium';

  rl.close();

  const scaffolder = new RuleScaffolder();
  const result = scaffolder.scaffold({
    title: title.trim(),
    category: category.trim() as import('./types.js').ATRCategory,
    attackDescription: attackDescription.trim(),
    examplePayloads: payloads,
    severity: finalSeverity as import('./types.js').ATRSeverity,
  });

  console.log(`\n${GREEN}Generated rule ${result.id}:${RESET}\n`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(result.yaml);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);

  if (result.warnings.length > 0) {
    console.log(`\n${BOLD}Warnings:${RESET}`);
    for (const w of result.warnings) {
      console.log(`  - ${w}`);
    }
  }

  console.log(`\n${DIM}Copy this YAML to a .yaml file in rules/${category.trim()}/ and validate with: atr validate <file>${RESET}\n`);
}

async function cmdScaffoldSemantic(): Promise<void> {
  const { createInterface } = await import('node:readline');
  const { RuleScaffolder } = await import('./rule-scaffolder.js');

  const rl = createInterface({ input: process.stdin, output: process.stdout });

  const ask = (question: string): Promise<string> =>
    new Promise((resolve) => rl.question(question, resolve));

  console.log(`\n${BOLD}ATR Semantic Rule Scaffolder${RESET}`);
  console.log(`${DIM}Generate a draft method=semantic ATR rule interactively.${RESET}\n`);

  const title = await ask('Rule title: ');
  if (!title.trim()) {
    console.error(`${RED}Error: Title is required.${RESET}`);
    rl.close();
    process.exit(1);
  }

  const categories = [
    'prompt-injection', 'tool-poisoning', 'context-exfiltration',
    'agent-manipulation', 'privilege-escalation', 'excessive-autonomy',
    'data-poisoning', 'model-abuse', 'skill-compromise',
  ];
  console.log(`\nCategories: ${categories.join(', ')}`);
  const category = await ask('Category: ');
  if (!categories.includes(category.trim())) {
    console.error(`${RED}Error: Invalid category.${RESET}`);
    rl.close();
    process.exit(1);
  }

  const attackDescription = await ask('Attack description: ');
  if (!attackDescription.trim()) {
    console.error(`${RED}Error: Description is required.${RESET}`);
    rl.close();
    process.exit(1);
  }

  const notDetectedDescription = await ask('What is NOT detected by this rule: ');
  if (!notDetectedDescription.trim()) {
    console.error(`${RED}Error: Non-detection scope is required for semantic rules.${RESET}`);
    rl.close();
    process.exit(1);
  }

  console.log('\nEnter malicious examples / true positives (at least 5, one per line, empty line to finish):');
  const positives: string[] = [];
  while (true) {
    const payload = await ask(`  Positive ${positives.length + 1}: `);
    if (!payload.trim()) break;
    positives.push(payload.trim());
  }

  if (positives.length < 5) {
    console.error(`${RED}Error: At least 5 positive examples are required for promotion-ready semantic rules.${RESET}`);
    rl.close();
    process.exit(1);
  }

  console.log('\nEnter benign examples / true negatives (at least 5, include near-misses, empty line to finish):');
  const negatives: string[] = [];
  while (true) {
    const payload = await ask(`  Negative ${negatives.length + 1}: `);
    if (!payload.trim()) break;
    negatives.push(payload.trim());
  }

  if (negatives.length < 5) {
    console.error(`${RED}Error: At least 5 negative examples are required for promotion-ready semantic rules.${RESET}`);
    rl.close();
    process.exit(1);
  }

  console.log('\nEnter evasion tests (at least 3). Leave input empty after 3 to finish.');
  const evasionTests: import('./rule-scaffolder.js').ScaffoldEvasionTestInput[] = [];
  while (true) {
    const input = await ask(`  Evasion ${evasionTests.length + 1} input: `);
    if (!input.trim()) break;
    const bypass = await ask('    bypass_technique: ');
    if (!bypass.trim()) {
      console.error(`${RED}Error: Each evasion test requires bypass_technique.${RESET}`);
      rl.close();
      process.exit(1);
    }
    const expected = await ask('    expected [triggered/not_triggered] (default: triggered): ');
    const normalizedExpected = expected.trim() === 'not_triggered' ? 'not_triggered' : 'triggered';
    const notes = await ask('    notes (optional): ');
    evasionTests.push({
      input: input.trim(),
      expected: normalizedExpected,
      bypass_technique: bypass.trim(),
      ...(notes.trim() ? { notes: notes.trim() } : {}),
    });
  }

  if (evasionTests.length < 3) {
    console.error(`${RED}Error: At least 3 evasion tests are required for promotion-ready semantic rules.${RESET}`);
    rl.close();
    process.exit(1);
  }

  console.log('\nEnter known false-positive edge cases (at least 1, empty line to finish):');
  const falsePositiveScenarios: string[] = [];
  while (true) {
    const scenario = await ask(`  False positive ${falsePositiveScenarios.length + 1}: `);
    if (!scenario.trim()) break;
    falsePositiveScenarios.push(scenario.trim());
  }

  if (falsePositiveScenarios.length === 0) {
    console.error(`${RED}Error: At least one false-positive edge case is required.${RESET}`);
    rl.close();
    process.exit(1);
  }

  const owaspRefsRaw = await ask('OWASP refs, comma-separated (for example LLM01:2025, ASI01): ');
  const owaspRefs = owaspRefsRaw.split(',').map((ref) => ref.trim()).filter(Boolean);
  if (owaspRefs.length === 0) {
    console.error(`${RED}Error: At least one OWASP reference is required.${RESET}`);
    rl.close();
    process.exit(1);
  }

  const mitreRefsRaw = await ask('MITRE refs, comma-separated (for example AML.T0051): ');
  const mitreRefs = mitreRefsRaw.split(',').map((ref) => ref.trim()).filter(Boolean);
  if (mitreRefs.length === 0) {
    console.error(`${RED}Error: At least one MITRE reference is required.${RESET}`);
    rl.close();
    process.exit(1);
  }

  const severities = ['critical', 'high', 'medium', 'low', 'informational'];
  const severity = await ask(`Severity [${severities.join('/')}] (default: medium): `);
  const finalSeverity = severity.trim() && severities.includes(severity.trim())
    ? severity.trim()
    : 'medium';

  const thresholdRaw = await ask('Semantic threshold 0.0-1.0 (default: 0.7): ');
  const threshold = thresholdRaw.trim() ? Number.parseFloat(thresholdRaw.trim()) : 0.7;

  const fallbackRaw = await ask('Use generated pattern fallback? [Y/n]: ');
  const includePatternFallback = !['n', 'no'].includes(fallbackRaw.trim().toLowerCase());

  rl.close();

  const scaffolder = new RuleScaffolder();
  const result = scaffolder.scaffoldSemantic({
    title: title.trim(),
    category: category.trim() as import('./types.js').ATRCategory,
    attackDescription: attackDescription.trim(),
    notDetectedDescription: notDetectedDescription.trim(),
    examplePayloads: positives,
    negativePayloads: negatives,
    evasionTests,
    falsePositiveScenarios,
    owaspRefs,
    mitreRefs,
    severity: finalSeverity as import('./types.js').ATRSeverity,
    detectionMethod: 'semantic',
    semantic: {
      threshold,
      includePatternFallback,
      fallbackMethod: includePatternFallback ? 'pattern' : 'none',
    },
  });

  console.log(`\n${GREEN}Generated semantic rule ${result.id}:${RESET}\n`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(result.yaml);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);

  if (result.warnings.length > 0) {
    console.log(`\n${BOLD}Warnings:${RESET}`);
    for (const w of result.warnings) {
      console.log(`  - ${w}`);
    }
  }

  console.log(`\n${DIM}Place draft YAML in proposals/semantic/ first, then validate with: atr validate <file>${RESET}`);
  console.log(`${DIM}For live local-model smoke tests, run with --semantic and an Ollama/OpenAI-compatible judge.${RESET}\n`);
}

// --- INIT command ---

function cmdInit(options: Record<string, string>): void {
  const isGlobal = options['global'] === 'true';
  const cwd = process.cwd();

  // Detect Claude Code project (unless --global)
  if (!isGlobal) {
    const hasClaudeDir = existsSync(join(cwd, '.claude'));
    const hasClaudeMd = existsSync(join(cwd, 'CLAUDE.md'));
    if (!hasClaudeDir && !hasClaudeMd) {
      console.error(
        `${RED}Error: Not a Claude Code project (no .claude/ directory or CLAUDE.md found).${RESET}\n` +
        `Run this command from your project root, or use ${BOLD}atr init --global${RESET} to configure globally.`
      );
      process.exit(1);
    }
  }

  const hookEntry = {
    // Empty matcher means "match all tools" in Claude Code hooks —
    // this is intentional so every tool call is scanned against ATR rules.
    matcher: '',
    command: 'npx agent-threat-rules guard',
  };

  // Determine target settings file
  const settingsPath = isGlobal
    ? join(homedir(), '.claude', 'settings.json')
    : join(cwd, '.claude', 'settings.local.json');

  // Ensure parent directory exists
  const settingsDir = dirname(settingsPath);
  if (!existsSync(settingsDir)) {
    mkdirSync(settingsDir, { recursive: true });
  }

  // Read existing settings or start fresh
  let settings: Record<string, unknown> = {};
  if (existsSync(settingsPath)) {
    let raw: string;
    try {
      raw = readFileSync(settingsPath, 'utf-8');
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      console.error(`${RED}Error: Cannot read ${settingsPath} (${code ?? 'permission denied'}). Check file permissions.${RESET}`);
      process.exit(1);
    }
    try {
      settings = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      console.error(`${RED}Error: Invalid JSON in ${settingsPath}. Fix the syntax manually or delete it and retry.${RESET}`);
      process.exit(1);
    }
  }

  // Navigate into hooks.PreToolUse, creating structure as needed
  if (!settings['hooks'] || typeof settings['hooks'] !== 'object') {
    settings['hooks'] = {};
  }
  const hooks = settings['hooks'] as Record<string, unknown>;

  if (!Array.isArray(hooks['PreToolUse'])) {
    hooks['PreToolUse'] = [];
  }
  const preToolUse = hooks['PreToolUse'] as Array<Record<string, unknown>>;

  // Check if hook is already configured (validate each element is an object before accessing .command)
  const alreadyConfigured = preToolUse.some(
    (entry: unknown) =>
      typeof entry === 'object' &&
      entry !== null &&
      !Array.isArray(entry) &&
      (entry as Record<string, unknown>)['command'] === hookEntry.command
  );

  if (alreadyConfigured) {
    console.log(`${GREEN}ATR guard hook already configured${RESET} in ${settingsPath}`);
    return;
  }

  // Add the hook entry
  preToolUse.push(hookEntry);

  // Write back
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n', 'utf-8');

  const relPath = settingsPath.startsWith(cwd + sep)
    ? settingsPath.slice(cwd.length + 1)
    : settingsPath;

  console.log(`\n${GREEN}ATR guard hook configured successfully.${RESET}\n`);
  console.log(`  File: ${relPath}`);
  console.log(`  Hook: PreToolUse -> npx agent-threat-rules guard\n`);
  console.log(`${DIM}Every tool call Claude Code makes will now be scanned against ATR`);
  console.log(`threat detection rules before execution. Suspicious actions will be`);
  console.log(`flagged with severity and recommendation.${RESET}\n`);
}

// --- CONVERT command ---

async function cmdConvert(target: string, options: Record<string, string>): Promise<void> {
  const validFormats = ['splunk', 'elastic', 'generic-regex'];
  if (!target || !validFormats.includes(target)) {
    console.error(`${RED}Error: Specify format: atr convert <splunk|elastic|generic-regex>${RESET}`);
    process.exit(1);
  }

  const rulesDir = options['rules'] ? resolve(options['rules']) : RULES_DIR;
  const outputFile = options['output'];
  const jsonOutput = options['json'] === 'true';

  // Generic regex export (JSON array of regex patterns with metadata)
  if (target === 'generic-regex') {
    const { loadRulesFromDirectory } = await import('./loader.js');
    const { rulesToGenericRegex } = await import('./converters/generic-regex.js');
    const rules = loadRulesFromDirectory(rulesDir);
    const exported = rulesToGenericRegex(rules);

    if (exported.length === 0) {
      console.error(`${RED}Error: No rules with regex patterns found in ${rulesDir}${RESET}`);
      process.exit(1);
    }

    const output = JSON.stringify(exported, null, 2);
    if (outputFile) {
      writeFileSync(resolve(outputFile), output, 'utf-8');
      console.log(`${GREEN}Exported ${exported.length} rules (${exported.reduce((n, r) => n + r.patterns.length, 0)} patterns) to generic-regex format.${RESET}`);
      console.log(`  Output: ${resolve(outputFile)}`);
    } else {
      console.log(output);
    }
    return;
  }

  const format = target as 'splunk' | 'elastic';

  const { convertAllRules } = await import('./converters/index.js');

  const results = convertAllRules(rulesDir, format);

  if (results.length === 0) {
    console.error(`${RED}Error: No rules found in ${rulesDir}${RESET}`);
    process.exit(1);
  }

  let output: string;

  if (jsonOutput) {
    output = JSON.stringify(results, null, 2);
  } else if (format === 'elastic') {
    // For Elastic, JSON output is the natural format
    output = JSON.stringify(results.map(r => JSON.parse(r.query)), null, 2);
  } else {
    // For Splunk, emit each query separated by blank lines
    output = results.map(r => r.query).join('\n\n' + '='.repeat(80) + '\n\n');
  }

  if (outputFile) {
    writeFileSync(resolve(outputFile), output, 'utf-8');
    console.log(`${GREEN}Converted ${results.length} rules to ${format} format.${RESET}`);
    console.log(`  Output: ${resolve(outputFile)}`);
  } else {
    console.log(output);
  }
}

// --- Badge command ---

function cmdBadge(target: string, options: Record<string, string | boolean>): void {
  if (!target) {
    console.error(`${RED}Usage: atr badge <package-name> [--data <audit.json>] [--svg] [--json]${RESET}`);
    process.exit(1);
  }

  // Find audit data
  const dataPath = typeof options['data'] === 'string'
    ? resolve(options['data'])
    : resolve(__dirname, '..', 'data', 'audit-v3-full.json');

  const altDataPath = resolve(__dirname, '..', 'data', 'audit-v3-sample.json');

  let summary = null;
  if (existsSync(dataPath)) {
    summary = lookupPackageScan(dataPath, target);
  }
  if (!summary && existsSync(altDataPath)) {
    summary = lookupPackageScan(altDataPath, target);
  }

  const outputSvg = options['svg'] === 'true';
  const outputJson = options['json'] === 'true';

  if (outputSvg) {
    console.log(generateBadgeSvg(summary));
    return;
  }

  if (outputJson) {
    console.log(JSON.stringify(generateBadgeEndpoint(summary), null, 2));
    return;
  }

  // Default: human-readable output
  const endpoint = generateBadgeEndpoint(summary);

  console.log(`\n${BOLD}ATR Badge: ${target}${RESET}`);
  console.log(`${'─'.repeat(50)}`);

  if (summary) {
    const colorMap: Record<string, string> = {
      '#2ea44f': GREEN,
      '#dfb317': '\x1b[33m',
      '#e05d44': RED,
      '#9f9f9f': DIM,
    };
    const termColor = colorMap[endpoint.color] ?? '';
    console.log(`  Status:    ${termColor}${endpoint.message}${RESET}`);
    console.log(`  Package:   ${summary.packageName}@${summary.version ?? 'unknown'}`);
    console.log(`  Risk:      ${summary.riskLevel} (score: ${summary.riskScore})`);
    console.log(`  Findings:  critical=${summary.findings.critical} high=${summary.findings.high} medium=${summary.findings.medium} low=${summary.findings.low}`);
    if (summary.scannedAt) {
      console.log(`  Scanned:   ${summary.scannedAt}`);
    }
  } else {
    console.log(`  ${DIM}No scan data found for "${target}"${RESET}`);
    console.log(`  ${DIM}Run: atr badge ${target} --data <audit-results.json>${RESET}`);
  }

  console.log(`\n${BOLD}Embed:${RESET}`);
  console.log(`  ${DIM}Markdown:${RESET}  ${generateBadgeMarkdown(target)}`);
  console.log(`  ${DIM}SVG:${RESET}       atr badge ${target} --svg > badge.svg`);
  console.log(`  ${DIM}JSON:${RESET}      atr badge ${target} --json`);
  console.log();
}

// --- Main ---

async function main(): Promise<void> {
  const { command, target, options } = parseArgs(process.argv);

  if (command === 'help' || command === '--help' || command === '-h' || options['help']) {
    printUsage();
    return;
  }

  if (command === 'version' || command === '--version' || command === '-v') {
    const pkgPath = resolve(__dirname, '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
    console.log(pkg.version);
    return;
  }

  const rulesDir = options['rules'] ? resolve(options['rules']) : RULES_DIR;

  switch (command) {
    case 'scan':
      await cmdScanUnified(target, rulesDir, {
        json: options['json'] === 'true',
        sarif: options['sarif'] === 'true',
        severity: options['severity'],
        reportToCloud: options['no-report'] !== 'true',
        tcUrl: options['tc-url'],
        semantic: options['semantic'] === 'true',
        semanticApiKey: options['semantic-api-key'],
        semanticBaseUrl: options['semantic-base-url'],
        semanticModel: options['semantic-model'],
        semanticTimeout: options['semantic-timeout'],
        semanticNoJsonMode: options['semantic-no-json-mode'] === 'true',
      });
      break;
    case 'scan-skill':
      await cmdScanUnified(target, rulesDir, {
        json: options['json'] === 'true',
        sarif: options['sarif'] === 'true',
        severity: options['severity'],
        forceType: 'skill',
        reportToCloud: options['no-report'] !== 'true',
        tcUrl: options['tc-url'],
        semantic: options['semantic'] === 'true',
        semanticApiKey: options['semantic-api-key'],
        semanticBaseUrl: options['semantic-base-url'],
        semanticModel: options['semantic-model'],
        semanticTimeout: options['semantic-timeout'],
        semanticNoJsonMode: options['semantic-no-json-mode'] === 'true',
      });
      break;
    case 'validate':
      cmdValidate(target, options);
      break;
    case 'test':
      await cmdTest(target, options);
      break;
    case 'stats':
      cmdStats(options);
      break;
    case 'convert':
      await cmdConvert(target, options);
      break;
    case 'guard':
      await cmdGuard(options);
      break;
    case 'init':
      cmdInit(options);
      break;
    case 'mcp':
      await cmdMcp();
      break;
    case 'scaffold':
      await cmdScaffold();
      break;
    case 'scaffold-semantic':
      await cmdScaffoldSemantic();
      break;
    case 'badge':
      cmdBadge(target, options);
      break;
    case 'tc': {
      const { cmdTCSync, cmdTCPull, cmdTCCrystallize, cmdTCStatus } = await import('./cli/tc-pipeline.js');
      const subcommand = target;
      switch (subcommand) {
        case 'status':
          await cmdTCStatus(options);
          break;
        case 'sync':
          await cmdTCSync(options);
          break;
        case 'pull':
          await cmdTCPull(options);
          break;
        case 'crystallize':
          await cmdTCCrystallize(options);
          break;
        default:
          console.error(`${RED}Unknown tc subcommand: ${subcommand}. Use: status, sync, pull, crystallize${RESET}`);
          process.exit(1);
      }
      break;
    }
    default:
      console.error(`${RED}Unknown command: ${command}${RESET}`);
      printUsage();
      process.exit(1);
  }
}

main().catch(err => {
  console.error(`${RED}Error: ${err instanceof Error ? err.message : String(err)}${RESET}`);
  process.exit(1);
});
