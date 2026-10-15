/**
 * Unified scan handler for ATR CLI.
 * Auto-detects input type: JSON → MCP scan, .md → SKILL.md scan.
 *
 * @module agent-threat-rules/cli/scan-handler
 */

import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { ATREngine } from '../engine.js';
import type { AgentEvent, ATRMatch, ScanResult, ScanType } from '../types.js';
import type { Lane } from '../quality/rule-contract.js';
import { scanResultToSARIF } from '../converters/sarif.js';
import { createTCReporter, resolveTcUrl } from '../tc-reporter.js';
import { createSemanticJudgeFromConfig } from './semantic-judge-config.js';

const SEVERITY_ORDER = ['informational', 'low', 'medium', 'high', 'critical'] as const;

// ANSI colors
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '\x1b[91m',
  high: '\x1b[31m',
  medium: '\x1b[33m',
  low: '\x1b[36m',
  informational: '\x1b[37m',
};

export interface ScanOptions {
  readonly rules?: string;
  readonly json?: boolean;
  readonly sarif?: boolean;
  readonly severity?: string;
  readonly forceType?: ScanType;
  readonly failOn?: string;
  readonly reportToCloud?: boolean;
  readonly tcUrl?: string;
  readonly semantic?: boolean;
  readonly semanticApiKey?: string;
  readonly semanticBaseUrl?: string;
  readonly semanticModel?: string;
  readonly semanticTimeout?: string;
  readonly semanticNoJsonMode?: boolean;
  /**
   * Detection lane (which rule maturities may fire). Undefined means the
   * engine's built-in default; `src/cli.ts` resolves `--lane` and `ATR_LANE`
   * and always passes an explicit value, because the engine itself no longer
   * reads the environment. Scanning never blocks anything, so the blocking
   * opt-in has no meaning here; only the lane does.
   */
  readonly lane?: Lane;
}

/** Detect whether the target is an MCP event JSON or SKILL.md file/directory. */
export function detectInputType(targetPath: string): ScanType {
  if (targetPath.endsWith('.md')) return 'skill';
  if (targetPath.endsWith('.json')) return 'mcp';

  // Directory: inspect contents to decide
  if (existsSync(targetPath) && statSync(targetPath).isDirectory()) {
    const entries = readdirSync(targetPath);
    const hasJson = entries.some((e) => e.endsWith('.json'));
    const hasMd = entries.some(
      (e) => e.endsWith('.md') || e.toLowerCase() === 'skill.md',
    );
    if (hasMd) return 'skill';
    if (hasJson) return 'mcp';
    return 'skill'; // default for empty or non-matching directories
  }

  // Attempt to detect by reading first bytes
  if (existsSync(targetPath)) {
    const head = readFileSync(targetPath, 'utf-8').slice(0, 100).trimStart();
    if (head.startsWith('{') || head.startsWith('[')) return 'mcp';
    if (head.startsWith('#') || head.startsWith('---')) return 'skill';
  }

  throw new Error(
    `Cannot determine scan type for "${targetPath}". Use .json for MCP events or .md for SKILL.md files.`,
  );
}

/** Unified scan command: auto-detects MCP vs SKILL.md and runs the appropriate scan path. */
export async function cmdScanUnified(
  target: string,
  rulesDir: string,
  options: ScanOptions,
): Promise<void> {
  if (!target) {
    console.error(`${RED}Error: Missing target. Usage: atr scan <file|directory>${RESET}`);
    process.exit(1);
  }

  const targetPath = resolve(target);
  if (!existsSync(targetPath)) {
    console.error(`${RED}Error: Path not found: ${targetPath}${RESET}`);
    process.exit(1);
  }

  // Threat Cloud reporting is OFF by default. Scanning is a local operation, and a
  // scan of internal material must not leave the machine because of a default. Opt in
  // explicitly with --report-to-cloud.
  let reporter: ReturnType<typeof createTCReporter> | undefined;
  if (options.reportToCloud === true) {
    try {
      reporter = createTCReporter({
        tcUrl: options.tcUrl,
        onError: (err) => console.error(`${DIM}TC upload: ${err.message}${RESET}`),
      });
    } catch (err) {
      // No endpoint configured. Refusing here is the point: the alternative is
      // picking a recipient for the operator, which is what a built-in default
      // did. Fail with the fix in the message rather than a stack trace.
      console.error(`${RED}Error: ${err instanceof Error ? err.message : String(err)}${RESET}`);
      process.exit(1);
    }
  }
  if (reporter) {
    console.error(`${DIM}Threat Cloud: anonymous reporting enabled via --report-to-cloud${RESET}`);
  }

  if (options.failOn !== undefined && !SEVERITY_ORDER.includes(options.failOn as typeof SEVERITY_ORDER[number])) {
    console.error(`${RED}Error: --fail-on must be one of: ${SEVERITY_ORDER.join(', ')}${RESET}`);
    process.exit(1);
  }

  const scanType = options.forceType ?? detectInputType(targetPath);

  let failHits = 0;
  try {
    if (scanType === 'skill') {
      failHits = await scanSkillFiles(targetPath, rulesDir, options, reporter);
    } else {
      failHits = await scanMcpEvents(targetPath, rulesDir, options, reporter);
    }
  } finally {
    // Flush remaining events before exit
    if (reporter) {
      await reporter.destroy();
      if (!options.json && !options.sarif) {
        console.log(`${DIM}  Threat Cloud: detections reported to ${resolveTcUrl(options.tcUrl)}${RESET}`);
      }
    }
  }

  // --fail-on: non-zero exit when matches at/above the threshold were found
  // (lets pre-commit hooks and CI gates actually block on detections)
  if (failHits > 0) {
    process.exitCode = 1;
  }
}

// ── MCP Event Scan ─────────────────────────────────────────────

/**
 * A `.mcp.json` is a configuration document, not an event.
 *
 * `atr scan .mcp.json` — the invocation the README shows — parsed the file, wrapped it as one
 * event, found no `content` on it and skipped it, while the summary still said one event had been
 * scanned. The rules never saw a single server, so a config that sets `NODE_OPTIONS` to a require
 * payload came back as `threats_detected: 0` instead of as an error.
 *
 * Each server becomes its own event, with the config as its content, which is the shape the MCP
 * rules evaluate (ATR-2026-02300, the rule written for exactly this `.mcp.json` env-block surface,
 * fires on it — see tests/cli-mcp-config-scan.test.ts). One event per server also keeps a finding
 * attributable to a server name.
 */
function configDocumentToEvents(parsed: unknown): AgentEvent[] | null {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  const servers = (parsed as { mcpServers?: unknown }).mcpServers;
  if (!servers || typeof servers !== 'object' || Array.isArray(servers)) return null;
  const timestamp = new Date().toISOString();
  const events: AgentEvent[] = [];
  for (const [name, config] of Object.entries(servers as Record<string, unknown>)) {
    events.push({
      type: 'mcp_exchange',
      timestamp,
      content: JSON.stringify({ mcpServers: { [name]: config } }),
    });
  }
  return events.length > 0 ? events : null;
}

async function scanMcpEvents(
  eventsPath: string,
  rulesDir: string,
  options: ScanOptions,
  reporter?: ReturnType<typeof createTCReporter>,
): Promise<number> {
  const fileStat = statSync(eventsPath);
  if (fileStat.size > 50 * 1024 * 1024) {
    console.error(`${RED}Error: Events file exceeds 50MB limit${RESET}`);
    process.exit(1);
  }

  const raw = readFileSync(eventsPath, 'utf-8');
  let events: AgentEvent[];
  try {
    const parsed = JSON.parse(raw);
    // A config document becomes one event per server; every other input is unchanged.
    events = configDocumentToEvents(parsed) ?? (Array.isArray(parsed) ? parsed : [parsed]);
  } catch {
    console.error(`${RED}Error: Invalid JSON in ${eventsPath}${RESET}`);
    process.exit(1);
  }

  const semantic = createSemanticJudgeFromScanOptions(options);
  const engine = new ATREngine({
    rulesDir,
    reporter,
    semanticJudge: semantic.judge,
    ...(options.lane ? { lane: options.lane } : {}),
  });
  await engine.loadRules();
  if (semantic.enabled && !options.json && !options.sarif) {
    console.error(`${DIM}Semantic judge: enabled for method=semantic rules${RESET}`);
  }

  const minIdx = SEVERITY_ORDER.indexOf(
    (options.severity ?? 'informational') as typeof SEVERITY_ORDER[number],
  );

  const failIdx = options.failOn !== undefined ? SEVERITY_ORDER.indexOf(options.failOn as typeof SEVERITY_ORDER[number]) : -1;
  const allResults: Array<{ event: AgentEvent; result: ScanResult; filtered: ATRMatch[] }> = [];
  let totalThreats = 0;
  let failHits = 0;
  let eventsEvaluated = 0;
  let eventsSkipped = 0;

  for (const event of events) {
    if (!event.content) {
      eventsSkipped += 1; // skip malformed events, but never silently
      continue;
    }
    eventsEvaluated += 1;
    const result = semantic.enabled
      ? await engine.evaluateFullAsync(event, eventsPath)
      : engine.evaluateFull(event, eventsPath);
    const filtered = result.matches.filter(
      (m) => SEVERITY_ORDER.indexOf(m.rule.severity) >= minIdx,
    );
    if (filtered.length > 0) {
      allResults.push({ event, result, filtered });
      totalThreats += filtered.length;
      if (failIdx >= 0) {
        failHits += filtered.filter((m) => SEVERITY_ORDER.indexOf(m.rule.severity) >= failIdx).length;
      }
    }
  }

  // An event that never reached the engine is not a clean result, and the counts have to say so:
  // `events_scanned` used to be `events.length`, computed before the skip.
  if (eventsEvaluated === 0) {
    console.error(`${RED}Error: nothing was scanned — ${eventsSkipped} event(s) had no content${RESET}`);
  } else if (eventsSkipped > 0) {
    console.error(`${DIM}Warning: ${eventsSkipped} event(s) had no content and were not scanned${RESET}`);
  }
  if (options.sarif) {
    const sarifResults: ScanResult[] = allResults.map(({ result, filtered }) => ({
      ...result,
      matches: filtered,
      threat_count: filtered.length,
    }));
    const version = process.env['npm_package_version'] ?? '1.0.0';
    console.log(JSON.stringify(scanResultToSARIF(sarifResults, version), null, 2));
    return eventsEvaluated === 0 ? 1 : failHits;
  }

  if (options.json) {
    console.log(JSON.stringify({
      scan_type: 'mcp',
      events_scanned: eventsEvaluated,
      events_skipped: eventsSkipped,
      threats_detected: totalThreats,
      rules_loaded: engine.getRuleCount(),
      results: allResults.map(({ event, result, filtered }) => ({
        content_hash: result.content_hash,
        event: {
          type: event.type,
          timestamp: event.timestamp,
          content_preview: event.content.slice(0, 100),
        },
        matches: filtered.map(formatMatchJson),
      })),
    }, null, 2));
    return eventsEvaluated === 0 ? 1 : failHits;
  }

  printScanHeader('MCP', eventsEvaluated, engine.getRuleCount(), totalThreats);

  if (totalThreats === 0) {
    console.log(eventsEvaluated === 0
      ? `${RED}Nothing was scanned.${RESET}\n`
      : `${GREEN}No threats detected.${RESET}\n`);
    return eventsEvaluated === 0 ? 1 : failHits;
  }

  for (const { event, filtered } of allResults) {
    const preview = event.content.slice(0, 80).replace(/\n/g, ' ');
    console.log(`  ${DIM}Event: [${event.type}] "${preview}..."${RESET}`);
    for (const m of filtered) {
      printMatch(m);
    }
    console.log('');
  }
  return failHits;
}

// ── SKILL.md Scan ──────────────────────────────────────────────

async function scanSkillFiles(
  targetPath: string,
  rulesDir: string,
  options: ScanOptions,
  reporter?: ReturnType<typeof createTCReporter>,
): Promise<number> {
  const skillFiles = collectSkillFiles(targetPath);

  if (skillFiles.length === 0) {
    console.error(`${RED}Error: No SKILL.md files found in ${targetPath}${RESET}`);
    process.exit(1);
  }

  const semantic = createSemanticJudgeFromScanOptions(options);
  const engine = new ATREngine({
    rulesDir,
    reporter,
    semanticJudge: semantic.judge,
    ...(options.lane ? { lane: options.lane } : {}),
  });
  await engine.loadRules();
  if (semantic.enabled && !options.json && !options.sarif) {
    console.error(`${DIM}Semantic judge: enabled for method=semantic rules${RESET}`);
  }

  const minIdx = SEVERITY_ORDER.indexOf(
    (options.severity ?? 'informational') as typeof SEVERITY_ORDER[number],
  );

  const failIdx = options.failOn !== undefined ? SEVERITY_ORDER.indexOf(options.failOn as typeof SEVERITY_ORDER[number]) : -1;
  const allResults: Array<{ file: string; result: ScanResult; filtered: ATRMatch[] }> = [];
  let totalThreats = 0;
  let failHits = 0;

  for (const file of skillFiles) {
    const fileSize = statSync(file).size;
    if (fileSize > 1 * 1024 * 1024) {
      console.error(`${RED}Warning: Skipping ${file} (${Math.round(fileSize / 1024)}KB exceeds 1MB limit)${RESET}`);
      continue;
    }
    const content = readFileSync(file, 'utf-8');
    const result = semantic.enabled
      ? await engine.scanSkillFullAsync(content, file)
      : engine.scanSkillFull(content, file);
    const filtered = result.matches.filter(
      (m) => SEVERITY_ORDER.indexOf(m.rule.severity) >= minIdx,
    );
    if (filtered.length > 0) {
      allResults.push({ file, result, filtered });
      totalThreats += filtered.length;
      if (failIdx >= 0) {
        failHits += filtered.filter((m) => SEVERITY_ORDER.indexOf(m.rule.severity) >= failIdx).length;
      }
    }
  }

  if (options.sarif) {
    const sarifResults: ScanResult[] = allResults.map(({ result, filtered }) => ({
      ...result,
      matches: filtered,
      threat_count: filtered.length,
    }));
    const version = process.env['npm_package_version'] ?? '1.0.0';
    console.log(JSON.stringify(scanResultToSARIF(sarifResults, version), null, 2));
    return failHits;
  }

  if (options.json) {
    console.log(JSON.stringify({
      scan_type: 'skill',
      skills_scanned: skillFiles.length,
      threats_detected: totalThreats,
      rules_loaded: engine.getRuleCount(),
      results: allResults.map(({ file, result, filtered }) => ({
        file,
        content_hash: result.content_hash,
        matches: filtered.map(formatMatchJson),
      })),
    }, null, 2));
    return failHits;
  }

  printScanHeader('SKILL', skillFiles.length, engine.getRuleCount(), totalThreats);

  if (totalThreats === 0) {
    console.log(`  ${GREEN}No threats detected.${RESET}\n`);
    return failHits;
  }

  for (const { file, filtered } of allResults) {
    const relPath = file.replace(process.cwd() + '/', '');
    console.log(`  ${BOLD}${relPath}${RESET}`);
    for (const m of filtered) {
      printMatch(m);
    }
    console.log('');
  }
  return failHits;
}

function createSemanticJudgeFromScanOptions(options: ScanOptions) {
  return createSemanticJudgeFromConfig({
    ...(options.semantic ? { semantic: 'true' } : {}),
    ...(options.semanticApiKey ? { 'semantic-api-key': options.semanticApiKey } : {}),
    ...(options.semanticBaseUrl ? { 'semantic-base-url': options.semanticBaseUrl } : {}),
    ...(options.semanticModel ? { 'semantic-model': options.semanticModel } : {}),
    ...(options.semanticTimeout ? { 'semantic-timeout': options.semanticTimeout } : {}),
    ...(options.semanticNoJsonMode ? { 'semantic-no-json-mode': 'true' } : {}),
  });
}

// ── Shared Helpers ─────────────────────────────────────────────

function collectSkillFiles(targetPath: string): string[] {
  const files: string[] = [];
  const stat = statSync(targetPath);
  if (stat.isDirectory()) {
    walkForSkills(targetPath, files);
  } else {
    files.push(targetPath);
  }
  return files;
}

function walkForSkills(dir: string, out: string[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = resolve(dir, entry.name);
    if (entry.isDirectory()) {
      walkForSkills(full, out);
    } else if (entry.name === 'SKILL.md' || entry.name === 'skill.md') {
      out.push(full);
    }
  }
}

function formatMatchJson(m: ATRMatch) {
  return {
    rule_id: m.rule.id,
    title: m.rule.title,
    severity: m.rule.severity,
    confidence: m.confidence,
    matched_conditions: m.matchedConditions,
  };
}

function printScanHeader(
  type: string,
  scanned: number,
  rulesLoaded: number,
  threats: number,
): void {
  const label = type === 'MCP' ? 'Events' : 'Skills';
  console.log(`\n${BOLD}ATR ${type} Scan Results${RESET}`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(`  ${label} scanned:  ${scanned}`);
  console.log(`  Rules loaded:    ${rulesLoaded}`);
  console.log(`  Threats found:   ${threats > 0 ? RED + threats + RESET : GREEN + '0' + RESET}`);
  console.log(`${DIM}${'─'.repeat(60)}${RESET}`);
  console.log(`${DIM}  Open source (MIT). Star: https://github.com/Agent-Threat-Rule/agent-threat-rules${RESET}`);
  console.log('');
}

function printMatch(m: ATRMatch): void {
  const color = SEVERITY_COLORS[m.rule.severity] ?? '';
  console.log(
    `    ${color}${m.rule.severity.toUpperCase().padEnd(13)}${RESET} ${m.rule.id} - ${m.rule.title}`,
  );
  console.log(
    `    ${DIM}Confidence: ${(m.confidence * 100).toFixed(0)}% | Conditions: ${m.matchedConditions.join(', ')}${RESET}`,
  );
}
