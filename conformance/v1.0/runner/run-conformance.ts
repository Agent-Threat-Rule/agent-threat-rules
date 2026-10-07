#!/usr/bin/env tsx
/**
 * ATR Conformance Test Suite — reference runner v1.0
 *
 * Executes the suite against any engine whose CLI exposes the canonical
 * `scan <file> --rules <dir> --json` entrypoint and emits Match output per
 * SPEC §7.
 *
 * Exit codes:
 *   0   full pass at the declared level
 *   1   one or more fixtures failed
 *   2   runner-internal error (bad engine path, unreadable fixture, engine
 *       that could not be spawned at all)
 *
 * A fixture is never failed silently because the harness itself broke: a
 * harness fault is recorded as `harness_error` and forces exit 2. An engine
 * that fails is never folded into `no_match` either — a clean non-zero exit
 * is `graceful_error`, while a signal, a hang or unreadable output is
 * `engine_error`, which no edge fixture accepts.
 *
 * The runner is deterministic, network-free (it always passes `--no-report`
 * so fixture payloads are never uploaded anywhere) and writes a JSON report
 * conforming to runner/report-schema.json.
 */

import { readFileSync, readdirSync, writeFileSync, existsSync, statSync, mkdtempSync } from 'node:fs';
import { join, dirname, resolve, extname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import yaml from 'js-yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SUITE_ROOT = join(__dirname, '..');
const FIXTURE_ROOT = join(SUITE_ROOT, 'fixtures');

const SUITE_VERSION = 'v1.0.0';
const SPEC_VERSION = '1.0.0';

/** Fixed so two runs of the same fixture produce byte-identical engine input. */
const FIXTURE_TIMESTAMP = '2026-01-01T00:00:00Z';

/**
 * MCP event channels a `scan_target: mcp` payload is presented on.
 *
 * A fixture declares a scan target, not a channel, so the runner materialises
 * the payload once per channel and asks the engine about the batch. A TP
 * fixture passes when the Rule fires on at least one channel; a TN fixture
 * passes only when it fires on none — the same normalisation, applied in both
 * directions, so it cannot be used to launder a false positive.
 */
const MCP_CHANNELS = [
  'llm_input',
  'llm_output',
  'tool_call',
  'tool_response',
  'multi_agent_message',
] as const;

type Outcome = 'match' | 'no_match' | 'graceful_error' | 'graceful_error_or_no_match';
type ObservedKind = 'match' | 'no_match' | 'graceful_error' | 'engine_error' | 'harness_error';
type Category = 'tp' | 'tn' | 'edge';

interface ExpectFile {
  outcome: Outcome;
  rule_id?: string;
  min_match_count?: number;
  matched_selectors_must_include?: string[];
  error_kind_allowed?: string[];
  error_kind_must_include?: string[];
  max_runtime_ms?: number;
}

interface Args {
  engine: string;
  rules: string;
  level: 'L1' | 'L2' | 'L3';
  out: string;
}

interface FixtureResult {
  fixture: string;
  category: Category;
  rule_id?: string;
  expected: Outcome;
  observed: ObservedKind;
  passed: boolean;
  runtime_ms: number;
  failure_reason?: string;
}

interface Report {
  suite_version: string;
  spec_version: string;
  engine: string;
  rules: string;
  level: string;
  generated_at: string;
  totals: { total: number; passed: number; failed: number; harness_errors: number };
  results: FixtureResult[];
}

/** How to invoke the engine: a program plus the arguments that precede `scan`. */
interface EngineCommand {
  readonly command: string;
  readonly baseArgs: readonly string[];
  readonly display: string;
}

interface EngineMatch {
  readonly rule_id: string;
  readonly matched_selectors: readonly string[];
}

/**
 * `crashed` separates an engine that failed *gracefully* — it exited non-zero
 * on its own and said why — from one that died (signal), hung until the
 * harness killed it, or emitted something that is not the documented JSON.
 * Only the graceful kind may satisfy an edge fixture's `graceful_error`.
 */
type EngineRun =
  | { kind: 'ok'; matches: readonly EngineMatch[]; runtimeMs: number }
  | { kind: 'engine_error'; message: string; crashed: boolean; runtimeMs: number }
  | { kind: 'harness_error'; message: string; runtimeMs: number };

function fail(message: string): never {
  console.error(`[conformance] ${message}`);
  process.exit(2);
}

function parseArgs(argv: readonly string[]): Args {
  const args: Partial<Args> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--engine') args.engine = argv[++i];
    else if (a === '--rules') args.rules = argv[++i];
    else if (a === '--level') args.level = argv[++i] as Args['level'];
    else if (a === '--out') args.out = argv[++i];
  }
  if (!args.engine || !args.rules) {
    console.error('Usage: run-conformance.ts --engine <path> --rules <path> [--level L1|L2|L3] [--out <path>]');
    process.exit(2);
  }
  args.level ??= 'L2';
  // A report is a certification artefact; it must not carry a level nobody defined.
  if (!['L1', 'L2', 'L3'].includes(args.level)) {
    console.error(`[conformance] --level must be one of L1, L2, L3 (got "${args.level}")`);
    process.exit(2);
  }
  args.out ??= join(process.cwd(), `conformance-report-${Date.now()}.json`);
  return args as Args;
}

/**
 * Resolve `--engine` to something actually executable.
 *
 * `--engine ./dist` (a build output directory, which is what the README tells
 * people to pass) resolves to `./dist/cli.js`; a path to an executable is used
 * as given. A `.js` entrypoint is run through the current Node binary so the
 * suite does not depend on the file's exec bit or shebang.
 */
function resolveEngineCommand(enginePath: string): EngineCommand {
  const abs = resolve(enginePath);
  if (!existsSync(abs)) fail(`--engine path does not exist: ${abs}`);

  let entry = abs;
  if (statSync(abs).isDirectory()) {
    const candidate = join(abs, 'cli.js');
    if (!existsSync(candidate)) {
      fail(
        `--engine ${abs} is a directory but contains no cli.js. ` +
          `Point --engine at the engine's build output directory (which must contain cli.js) ` +
          `or directly at its executable.`,
      );
    }
    entry = candidate;
  }

  const ext = extname(entry);
  if (ext === '.js' || ext === '.mjs' || ext === '.cjs') {
    return { command: process.execPath, baseArgs: [entry], display: entry };
  }
  return { command: entry, baseArgs: [], display: entry };
}

function listFixtures(category: Category): string[] {
  const root = join(FIXTURE_ROOT, category);
  if (!existsSync(root)) return [];
  return readdirSync(root)
    .filter((name) => statSync(join(root, name)).isDirectory())
    .sort()
    .map((name) => join(root, name));
}

function loadExpect(fixturePath: string): ExpectFile {
  return JSON.parse(readFileSync(join(fixturePath, 'expect.json'), 'utf8')) as ExpectFile;
}

interface Fixture {
  readonly scanTarget: string;
  readonly input: unknown;
}

function loadFixture(fixturePath: string): Fixture {
  const doc = yaml.load(readFileSync(join(fixturePath, 'input.yaml'), 'utf8'));
  if (doc === null || typeof doc !== 'object') {
    throw new Error('input.yaml did not parse to a mapping');
  }
  const record = doc as Record<string, unknown>;
  const scanTarget = typeof record['scan_target'] === 'string' ? (record['scan_target'] as string) : 'mcp';
  return { scanTarget, input: record['input'] ?? null };
}

function stringifyFields(map: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(map).map(([k, v]) => [k, typeof v === 'string' ? v : JSON.stringify(v)]),
  );
}

/** Flatten a structured fixture input into the plain text a SKILL.md scan sees. */
function toText(input: unknown): string {
  if (input === null || input === undefined) return '';
  if (typeof input === 'string') return input;
  if (typeof input === 'object' && !Array.isArray(input)) {
    return Object.entries(stringifyFields(input as Record<string, unknown>))
      .map(([k, v]) => `${k}: ${v}`)
      .join('\n');
  }
  return String(input);
}

/**
 * Materialise a fixture payload as the MCP event batch the engine scans.
 *
 * A mapping-valued `input` carries its keys through as event `fields` (that is
 * how the tool_name / tool_args fixtures express themselves); a scalar `input`
 * becomes the event content.
 */
function buildMcpEvents(input: unknown): ReadonlyArray<Record<string, unknown>> {
  const isMapping = input !== null && typeof input === 'object' && !Array.isArray(input);
  const fields = isMapping ? stringifyFields(input as Record<string, unknown>) : undefined;
  if (fields && fields['response'] !== undefined && fields['tool_response'] === undefined) {
    fields['tool_response'] = fields['response'];
  }
  const content = toText(input);
  return MCP_CHANNELS.map((type) => ({
    type,
    timestamp: FIXTURE_TIMESTAMP,
    content,
    scanContext: 'mcp',
    ...(fields ? { fields } : {}),
  }));
}

/**
 * Pull Match objects out of engine stdout.
 *
 * Accepts the ATR CLI's scan envelope (`{ results: [{ matches: [...] }] }`),
 * a bare `Match[]` as SPEC §7 describes it, and `{ matches: [...] }`.
 */
function extractMatches(parsed: unknown): readonly EngineMatch[] {
  const asMatch = (m: unknown): EngineMatch | null => {
    if (m === null || typeof m !== 'object') return null;
    const rec = m as Record<string, unknown>;
    const id = rec['rule_id'] ?? rec['ruleId'];
    if (typeof id !== 'string') return null;
    const selectors = rec['matched_selectors'] ?? rec['matched_conditions'] ?? [];
    return { rule_id: id, matched_selectors: Array.isArray(selectors) ? selectors.map(String) : [] };
  };
  const collect = (items: readonly unknown[]): EngineMatch[] =>
    items.map(asMatch).filter((m): m is EngineMatch => m !== null);

  if (Array.isArray(parsed)) return collect(parsed);
  if (parsed === null || typeof parsed !== 'object') return [];
  const rec = parsed as Record<string, unknown>;
  if (Array.isArray(rec['matches'])) return collect(rec['matches'] as unknown[]);
  if (Array.isArray(rec['results'])) {
    return (rec['results'] as unknown[]).flatMap((r) => {
      const inner = r !== null && typeof r === 'object' ? (r as Record<string, unknown>)['matches'] : null;
      return Array.isArray(inner) ? collect(inner as unknown[]) : [];
    });
  }
  return [];
}

/** Tolerate engines that print a banner before the JSON document. */
function parseEngineStdout(stdout: string): unknown {
  try {
    return JSON.parse(stdout);
  } catch {
    const start = stdout.search(/^[[{]/m);
    if (start < 0) throw new Error('no JSON document found in stdout');
    return JSON.parse(stdout.slice(start));
  }
}

const ENGINE_TIMEOUT_MS = 30_000;

function runEngineOnce(engine: EngineCommand, rulesDir: string, inputPath: string): EngineRun {
  const start = Date.now();
  const result = spawnSync(
    engine.command,
    [...engine.baseArgs, 'scan', inputPath, '--rules', rulesDir, '--json', '--no-report'],
    { timeout: ENGINE_TIMEOUT_MS, encoding: 'utf8', shell: false, maxBuffer: 64 * 1024 * 1024 },
  );
  const runtimeMs = Date.now() - start;

  if (result.error) {
    const code = (result.error as NodeJS.ErrnoException).code;
    // A hang the harness had to kill is the engine's problem, but it is not a
    // graceful failure. Every other spawn-level fault (ENOENT, EACCES, EMFILE,
    // ENOBUFS, ...) is the harness's problem and says nothing about the engine.
    if (code === 'ETIMEDOUT') {
      return {
        kind: 'engine_error',
        message: `engine timed out after ${ENGINE_TIMEOUT_MS} ms`,
        crashed: true,
        runtimeMs,
      };
    }
    return {
      kind: 'harness_error',
      message: `cannot execute engine (${code ?? 'unknown'}): ${engine.display} — ${result.error.message}`,
      runtimeMs,
    };
  }
  if (result.signal) {
    return { kind: 'engine_error', message: `engine killed by signal ${result.signal}`, crashed: true, runtimeMs };
  }
  if (result.status !== 0) {
    const stderr = (result.stderr ?? '').trim().replace(/\s+/g, ' ').slice(0, 300);
    return { kind: 'engine_error', message: `engine exited ${result.status}: ${stderr}`, crashed: false, runtimeMs };
  }
  try {
    return { kind: 'ok', matches: extractMatches(parseEngineStdout(result.stdout ?? '')), runtimeMs };
  } catch (e) {
    return {
      kind: 'engine_error',
      message: `engine output not valid JSON: ${(e as Error).message}`,
      crashed: true,
      runtimeMs,
    };
  }
}

/**
 * Write the fixture payload in a shape the engine's `scan` command accepts.
 *
 * `scan` dispatches on file extension (.json → MCP events, .md → SKILL.md), so
 * the fixture's own `input.yaml` cannot be handed over directly. Paths are
 * reused across fixtures so a full run leaves two scratch files behind, not
 * one per fixture.
 */
function materialise(scratchDir: string, target: 'mcp' | 'skill', input: unknown): string {
  if (target === 'skill') {
    const path = join(scratchDir, 'SKILL.md');
    writeFileSync(path, toText(input));
    return path;
  }
  const path = join(scratchDir, 'events.json');
  writeFileSync(path, JSON.stringify(buildMcpEvents(input)));
  return path;
}

/** Which representations a fixture's scan_target asks the engine to be shown. */
function targetsFor(scanTarget: string): ReadonlyArray<'mcp' | 'skill'> {
  if (scanTarget === 'skill') return ['skill'];
  if (scanTarget === 'both') return ['mcp', 'skill'];
  return ['mcp'];
}

interface Observation {
  readonly matches: readonly EngineMatch[];
  readonly error?: string;
  /** True when `error` came from a crash, a hang or unreadable output rather than a clean non-zero exit. */
  readonly errorCrashed?: boolean;
  readonly harnessError?: string;
  readonly runtimeMs: number;
}

function observe(
  engine: EngineCommand,
  rulesDir: string,
  scratchDir: string,
  fixture: Fixture,
): Observation {
  const matches: EngineMatch[] = [];
  let runtimeMs = 0;
  for (const target of targetsFor(fixture.scanTarget)) {
    const inputPath = materialise(scratchDir, target, fixture.input);
    const run = runEngineOnce(engine, rulesDir, inputPath);
    runtimeMs += run.runtimeMs;
    if (run.kind === 'harness_error') return { matches: [], harnessError: run.message, runtimeMs };
    if (run.kind === 'engine_error') {
      return { matches: [], error: run.message, errorCrashed: run.crashed, runtimeMs };
    }
    matches.push(...run.matches);
  }
  return { matches, runtimeMs };
}

/**
 * The observed label for a fixture the engine errored on. The same vocabulary
 * is used in every category so one report never calls the same engine
 * behaviour two different things.
 */
function errorKindOf(observed: Observation): ObservedKind {
  return observed.errorCrashed ? 'engine_error' : 'graceful_error';
}

function evaluateTp(expected: ExpectFile, observed: Observation): Omit<FixtureResult, 'fixture' | 'category'> {
  const ruleId = expected.rule_id ?? '';
  const hits = observed.matches.filter((m) => !ruleId || m.rule_id === ruleId);
  const want = expected.min_match_count ?? 1;
  const selectors = new Set(hits.flatMap((m) => m.matched_selectors));
  const missingSelectors = (expected.matched_selectors_must_include ?? []).filter((s) => !selectors.has(s));
  const countOk = hits.length >= want;
  const passed = observed.error === undefined && countOk && missingSelectors.length === 0;
  const reason = observed.error
    ? `engine error instead of a match for ${ruleId}: ${observed.error}`
    : !countOk
      ? `expected >=${want} match(es) for ${ruleId}; got ${hits.length}`
      : `matched selectors missing for ${ruleId}: ${missingSelectors.join(', ')}`;
  return {
    rule_id: ruleId,
    expected: 'match',
    observed: observed.error ? errorKindOf(observed) : hits.length > 0 ? 'match' : 'no_match',
    passed,
    runtime_ms: observed.runtimeMs,
    failure_reason: passed ? undefined : reason,
  };
}

function evaluateTn(expected: ExpectFile, observed: Observation): Omit<FixtureResult, 'fixture' | 'category'> {
  const ruleId = expected.rule_id ?? '';
  const hits = observed.matches.filter((m) => !ruleId || m.rule_id === ruleId);
  const passed = observed.error === undefined && hits.length === 0;
  const reason = observed.error
    ? `engine error instead of a clean no-match for ${ruleId}: ${observed.error}`
    : `expected no match for ${ruleId}; got ${hits.length}`;
  return {
    rule_id: ruleId,
    expected: 'no_match',
    observed: observed.error ? errorKindOf(observed) : hits.length === 0 ? 'no_match' : 'match',
    passed,
    runtime_ms: observed.runtimeMs,
    failure_reason: passed ? undefined : reason,
  };
}

function evaluateEdge(expected: ExpectFile, observed: Observation): Omit<FixtureResult, 'fixture' | 'category'> {
  // An engine that died, hung, or emitted unreadable output did not handle the
  // payload gracefully, so it is `engine_error` — which no edge expectation
  // accepts. Only a clean non-zero exit counts as `graceful_error`.
  const observedKind: ObservedKind = observed.error
    ? errorKindOf(observed)
    : observed.matches.length === 0
      ? 'no_match'
      : 'match';
  const okOutcomes: readonly ObservedKind[] =
    expected.outcome === 'graceful_error'
      ? ['graceful_error']
      : expected.outcome === 'no_match'
        ? ['no_match']
        : ['no_match', 'graceful_error'];
  const allowed = expected.error_kind_allowed ?? [];
  const required = expected.error_kind_must_include ?? [];
  const errorText = (observed.error ?? '').toLowerCase();
  const errorKindOk =
    observed.error === undefined
      ? true
      : (allowed.length === 0 || allowed.some((k) => errorText.includes(k))) &&
        required.every((k) => errorText.includes(k));
  const withinBudget = expected.max_runtime_ms ? observed.runtimeMs <= expected.max_runtime_ms : true;
  const passed = okOutcomes.includes(observedKind) && errorKindOk && withinBudget;
  return {
    expected: expected.outcome,
    observed: observedKind,
    passed,
    runtime_ms: observed.runtimeMs,
    failure_reason: passed
      ? undefined
      : `edge fixture: observed=${observedKind} (expected ${okOutcomes.join('|')})` +
        `${observedKind === 'engine_error' ? `, engine did not fail gracefully: ${observed.error}` : ''}` +
        `${errorKindOk ? '' : `, error kind "${observed.error}" not among [${allowed.join(', ')}]`}` +
        `, runtime=${observed.runtimeMs}ms budget=${expected.max_runtime_ms ?? 'none'}ms`,
  };
}

function evaluateFixture(category: Category, expected: ExpectFile, observed: Observation): Omit<FixtureResult, 'fixture' | 'category'> {
  if (category === 'tp') return evaluateTp(expected, observed);
  if (category === 'tn') return evaluateTn(expected, observed);
  return evaluateEdge(expected, observed);
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const engine = resolveEngineCommand(args.engine);
  const rulesDir = resolve(args.rules);
  if (!existsSync(rulesDir)) fail(`--rules path does not exist: ${rulesDir}`);

  const scratchDir = mkdtempSync(join(tmpdir(), 'atr-conformance-'));
  const results: FixtureResult[] = [];
  const harnessErrors: string[] = [];

  for (const category of ['tp', 'tn', 'edge'] as const) {
    for (const fixturePath of listFixtures(category)) {
      const relative = fixturePath.replace(SUITE_ROOT, '');
      let expected: ExpectFile;
      let fixture: Fixture;
      try {
        expected = loadExpect(fixturePath);
        fixture = loadFixture(fixturePath);
      } catch (e) {
        const message = `${relative}: ${(e as Error).message}`;
        harnessErrors.push(message);
        results.push({
          fixture: relative,
          category,
          expected: 'match',
          observed: 'harness_error',
          passed: false,
          runtime_ms: 0,
          failure_reason: `runner could not read the fixture: ${message}`,
        });
        continue;
      }

      const observed = observe(engine, rulesDir, scratchDir, fixture);
      if (observed.harnessError) {
        harnessErrors.push(`${relative}: ${observed.harnessError}`);
        results.push({
          fixture: relative,
          category,
          rule_id: expected.rule_id,
          expected: expected.outcome,
          observed: 'harness_error',
          passed: false,
          runtime_ms: observed.runtimeMs,
          failure_reason: `runner could not run the engine: ${observed.harnessError}`,
        });
        continue;
      }
      results.push({ fixture: relative, category, ...evaluateFixture(category, expected, observed) });
    }
  }

  const totals = {
    total: results.length,
    passed: results.filter((r) => r.passed).length,
    failed: results.filter((r) => !r.passed).length,
    harness_errors: harnessErrors.length,
  };
  const report: Report = {
    suite_version: SUITE_VERSION,
    spec_version: SPEC_VERSION,
    engine: engine.display,
    rules: rulesDir,
    level: args.level,
    generated_at: new Date().toISOString(),
    totals,
    results,
  };
  writeFileSync(args.out, JSON.stringify(report, null, 2) + '\n');

  for (const category of ['tp', 'tn', 'edge'] as const) {
    const slice = results.filter((r) => r.category === category);
    if (slice.length > 0) {
      console.log(`[conformance] ${category}: ${slice.filter((r) => r.passed).length}/${slice.length} passed`);
    }
  }
  console.log(`[conformance] ${totals.passed}/${totals.total} passed at ${args.level}`);
  console.log(`[conformance] report: ${args.out}`);

  if (harnessErrors.length > 0) {
    console.error(`[conformance] ${harnessErrors.length} runner-internal error(s); the run is inconclusive:`);
    for (const message of harnessErrors.slice(0, 10)) console.error(`  - ${message}`);
    process.exit(2);
  }
  process.exit(totals.failed > 0 ? 1 : 0);
}

try {
  main();
} catch (e) {
  // Exit 1 means "fixtures failed". An unwritable --out path, or any other
  // internal fault, is not that and must never be readable as a verdict.
  fail(`runner-internal error, the run is inconclusive: ${(e as Error).message}`);
}
