#!/usr/bin/env npx tsx
/**
 * scripts/mcp-tools-list/measure-tools-list-benign.ts
 *
 * False-positive measurement of `atr scan` on MCP tools/list documents, on a benign corpus of tool
 * definitions extracted from pinned official / vendor MCP servers
 * (data/test-corpora/mcp-tools-list-benign/, built by fetch-tools-list-corpus.py).
 *
 * Event shapes, per tool definition `t` (both carry the same content and fields; only the type differs):
 *   mcp_exchange   what `atr scan <tools/list document>` builds (PR #737, src/cli/mcp-tools-document.ts at
 *                  51be1a1c): content = JSON.stringify(t), fields.tool_name = t.name,
 *                  fields.tool_description = t.description. The type maps to no source type, so every
 *                  rule runs, and field resolution falls back to content only for `content` and the
 *                  fields set above.
 *   tool_response  the same content and fields, typed tool_response (the type `atr test` builds for an
 *                  mcp_exchange rule): only mcp_exchange, llm_io and context_window rules run, and
 *                  user_input / agent_output / tool_response resolve to the content.
 * toolDefinitionToEvent() below is a copy of the PR #737 function; this branch is cut from main, which
 * does not have it yet. Replace the copy with the import once that PR is merged.
 *
 * Lanes: hunt (engine default, every maturity), alert (stable + test), enforce (stable). Engines are
 * constructed with { rulesDir, lane } and nothing else: regex tier only, no embedding or semantic judge,
 * which is also what `atr scan` runs without --semantic-judge. Detection = engine.evaluate(event)
 * non-empty, the same call `atr scan` makes (evaluateFull = evaluate + a content hash).
 *
 * Every corpus tool is benign by construction (sources.json inclusion_policy), so every flag is counted
 * as a false positive; fp-classification.json says, per (rule, tool), why the rule fired and whether
 * the flag is arguably a true positive. A flag the classification does not cover is listed as
 * unclassified and fails --check.
 *
 * Output: data/measurements/mcp-tools-list-benign/benign-fp_<date>_<source-version>_atr-<version>.json.
 * Not a schema.ts Measurement (that schema is recall-centred; a benign-only corpus has no recall), the
 * same way data/measurements/clawhub-benign/ records its benign scan; named so verify.ts does not take it
 * for one.
 *
 * Usage:
 *   npx tsx scripts/mcp-tools-list/measure-tools-list-benign.ts                 # measure, print summary
 *   npx tsx scripts/mcp-tools-list/measure-tools-list-benign.ts --write         # also write the report
 *   npx tsx scripts/mcp-tools-list/measure-tools-list-benign.ts --check         # exit 1 on unclassified flags
 *   npx tsx scripts/mcp-tools-list/measure-tools-list-benign.ts --cli-results <dir>
 *        <dir>/<lane>/<server>.json = `atr scan <doc> --no-report --json --lane <lane>` output from a build
 *        that has PR #737; the report then records whether the CLI flagged exactly the same tools.
 *   --dump <path>   write the report to <path> as well (inspection; not a measurement file)
 *   --scoped-cli-results <dir> --scoped-cli-repo <checkout>
 *        the tool-definition context of PR #737 (engine option toolDefinitions, src/tool-definition-scope.ts):
 *        `atr scan` output, same layout as --cli-results, from a build of <checkout>, whose commit and rules
 *        tree the report records. When this checkout's own engine has the option (src/tool-definition-scope.ts
 *        exists), the context is measured in-process instead and these flags are not needed.
 *   --label <text>  appended to the report file name (a second report on the same date)
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ATREngine, RUNTIME_SOURCE_TYPE, compileRegexCondition, foldConfusables, normalizeUnicode } from '../../src/engine.js';
import { rulesInLane } from '../../src/measurement/enforce-lane.js';
import type { AgentEvent, ATRMatch, ATRRule } from '../../src/types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const RULES_DIR = resolve(REPO_ROOT, 'rules');
const CORPUS_DIR = resolve(REPO_ROOT, 'data/test-corpora/mcp-tools-list-benign');
const MANIFEST_PATH = resolve(CORPUS_DIR, 'manifest.json');
const CLASSIFICATION_PATH = resolve(CORPUS_DIR, 'fp-classification.json');
const CACHE_DOCS = resolve(process.env['MCP_TOOLS_LIST_CACHE'] ?? resolve(REPO_ROOT, '.cache/mcp-tools-list'), 'documents');
const OUT_DIR = resolve(REPO_ROOT, 'data/measurements/mcp-tools-list-benign');
const PR_737_COMMIT = '51be1a1c664f5f431c31d5b7800e21b10cfa4518';
const EXCERPT_RADIUS = 40;

type Lane = 'hunt' | 'alert' | 'enforce';
const LANES: readonly Lane[] = ['hunt', 'alert', 'enforce'];
type Shape = 'mcp_exchange' | 'tool_response';
const SHAPES: readonly Shape[] = ['mcp_exchange', 'tool_response'];

const argValue = (flag: string): string | undefined => {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
};
const WRITE = process.argv.includes('--write');
const CHECK = process.argv.includes('--check');
const CLI_RESULTS = argValue('--cli-results');
const DUMP = argValue('--dump'); // write the report to this path instead (inspection; not a measurement file)
const SCOPED_CLI_RESULTS = argValue('--scoped-cli-results');
const SCOPED_CLI_REPO = argValue('--scoped-cli-repo');
const LABEL = argValue('--label');

// ------------------------------------------------------------------ corpus

interface ServerEntry {
  readonly id: string;
  readonly repo: string;
  readonly commit: string;
  readonly license: string;
  readonly redistributed: boolean;
  readonly document: string | null;
  readonly document_sha256: string;
  readonly tools: number;
  readonly provenance: readonly { name: string; path: string; line: number; definition_sha256: string }[];
}

interface Manifest {
  readonly counts: Record<string, number>;
  readonly servers: readonly ServerEntry[];
}

type Tool = Record<string, unknown> & { name: string };

/** Wilson score interval, 95%. */
function wilson(k: number, n: number): [number, number] {
  const z = 1.959963984540054;
  const p = k / n;
  const den = 1 + (z * z) / n;
  const mid = (p + (z * z) / (2 * n)) / den;
  const half = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / den;
  return [Math.max(0, mid - half), Math.min(1, mid + half)];
}

const sha256 = (text: string): string => createHash('sha256').update(text, 'utf-8').digest('hex');

function loadDocuments(manifest: Manifest): Map<string, readonly Tool[]> {
  const out = new Map<string, readonly Tool[]>();
  for (const s of manifest.servers) {
    const path = s.document ? resolve(CORPUS_DIR, s.document) : resolve(CACHE_DOCS, `${s.id}.json`);
    if (!existsSync(path)) {
      throw new Error(`${path} missing — run python3 scripts/mcp-tools-list/fetch-tools-list-corpus.py first`);
    }
    const text = readFileSync(path, 'utf-8');
    if (sha256(text) !== s.document_sha256) {
      throw new Error(`${path}: sha256 differs from manifest.json — corpus edited by hand, or the cache is stale`);
    }
    const doc = JSON.parse(text) as { tools: Tool[] };
    if (doc.tools.length !== s.tools) throw new Error(`${s.id}: ${doc.tools.length} tools, manifest says ${s.tools}`);
    out.set(s.id, doc.tools);
  }
  return out;
}

// ------------------------------------------------------------------ events (PR #737 copy)

/** Copy of toolDefinitionToEvent() from PR #737 (src/cli/mcp-tools-document.ts at 51be1a1c). */
function toolDefinitionToEvent(tool: Record<string, unknown>, timestamp: string): AgentEvent {
  const name = tool['name'];
  const description = tool['description'];
  const fields: Record<string, string> = {
    ...(typeof name === 'string' && name !== '' ? { tool_name: name } : {}),
    ...(typeof description === 'string' && description !== '' ? { tool_description: description } : {}),
  };
  return {
    type: 'mcp_exchange',
    timestamp,
    content: JSON.stringify(tool),
    ...(Object.keys(fields).length > 0 ? { fields } : {}),
  };
}

function eventFor(tool: Tool, shape: Shape, timestamp: string): AgentEvent {
  const ev = toolDefinitionToEvent(tool, timestamp);
  return shape === 'mcp_exchange' ? ev : { ...ev, type: 'tool_response' };
}

/** The content_hash `atr scan --json` prints for an event (src/engine.ts evaluateFull). */
function cliContentHash(ev: AgentEvent): string {
  return sha256(ev.fields ? `${ev.content}\0${JSON.stringify(ev.fields)}` : ev.content);
}

// ------------------------------------------------------------------ witness (what text matched)

interface Witness {
  readonly condition: string;
  readonly field: string;
  readonly resolved_from: string;
  readonly offset: number;
  readonly matched: string;
  readonly excerpt?: string;
}

type ConditionLike = { field?: string; operator?: string; value?: string; patterns?: string[]; match_type?: string };

function conditionsOf(rule: ATRRule): [string, ConditionLike][] {
  const c = rule.detection.conditions as unknown;
  if (Array.isArray(c)) return c.map((x, i) => [String(i), x as ConditionLike]);
  if (c && typeof c === 'object') return Object.entries(c as Record<string, ConditionLike>);
  return [];
}

/** Which event property the engine read for `field` (mirrors ATREngine.resolveField, which is private). */
function resolvedFrom(field: string, ev: AgentEvent): string {
  if (ev.fields?.[field]) return `fields.${field}`;
  return 'content';
}

/**
 * The text each regex / contains condition of a matched rule matches on this event. Diagnostic only:
 * whether the rule fired is engine.evaluate()'s decision; this re-runs the rule's own patterns on the
 * value the engine resolves the field to, compiled with compileRegexCondition() and normalised with
 * normalizeUnicode() + foldConfusables() as the engine does, to say which words fired it.
 */
function witnesses(engine: ATREngine, rule: ATRRule, ev: AgentEvent, quote: boolean): Witness[] {
  const resolve = (engine as unknown as { resolveField(f: string, e: AgentEvent): string | undefined }).resolveField.bind(engine);
  const out: Witness[] = [];
  for (const [name, cond] of conditionsOf(rule)) {
    if (!cond.field) continue;
    const raw = resolve(cond.field, ev);
    if (!raw) continue;
    const value = foldConfusables(normalizeUnicode(raw));
    const patterns = cond.patterns ?? (cond.value !== undefined ? [cond.value] : []);
    const op = cond.match_type ?? cond.operator ?? 'regex';
    for (const p of patterns) {
      let at = -1;
      let len = 0;
      if (op === 'regex') {
        const re = compileRegexCondition(p, rule.id);
        const m = re ? re.exec(value) : null;
        if (m) {
          at = m.index;
          len = m[0].length;
        }
      } else if (op === 'contains') {
        at = value.toLowerCase().indexOf(p.toLowerCase());
        len = p.length;
      }
      if (at < 0) continue;
      const matched = value.slice(at, at + Math.min(len, 160));
      out.push({
        condition: name,
        field: cond.field,
        resolved_from: resolvedFrom(cond.field, ev),
        offset: at,
        matched: quote ? matched : `<${len} chars, not redistributed>`,
        ...(quote ? { excerpt: value.slice(Math.max(0, at - EXCERPT_RADIUS), at + len + EXCERPT_RADIUS) } : {}),
      });
      break;
    }
  }
  return out;
}

// ------------------------------------------------------------------ classification

interface Classification {
  readonly rule_id: string;
  readonly tools: readonly string[]; // "<server>/<tool>" or "*" (every flag of this rule)
  readonly cause: 'rule_too_broad' | 'event_type' | 'arguably_true_positive';
  readonly condition?: string;
  readonly explanation: string;
}

function loadClassification(): readonly Classification[] {
  if (!existsSync(CLASSIFICATION_PATH)) return [];
  return (JSON.parse(readFileSync(CLASSIFICATION_PATH, 'utf-8')) as { classifications: Classification[] }).classifications;
}

function classify(all: readonly Classification[], ruleId: string, toolKey: string): Classification | undefined {
  return (
    all.find((c) => c.rule_id === ruleId && c.tools.includes(toolKey)) ??
    all.find((c) => c.rule_id === ruleId && c.tools.includes('*'))
  );
}

// ------------------------------------------------------------------ measurement

interface Flag {
  readonly rule_id: string;
  readonly title: string;
  readonly severity: string;
  readonly maturity: string;
  readonly status: string;
  readonly agent_source: string;
  readonly confidence: number;
  readonly matched_conditions: readonly string[];
  readonly witnesses: readonly Witness[];
}

interface ToolResult {
  readonly server: string;
  readonly tool: string;
  readonly definition_sha256: string;
  readonly cli_content_hash: string;
  readonly flags: Record<Lane, Record<Shape, readonly Flag[]>>;
}

function flagOf(engine: ATREngine, m: ATRMatch, ev: AgentEvent, quote: boolean): Flag {
  const r = m.rule;
  return {
    rule_id: r.id,
    title: r.title,
    severity: r.severity,
    maturity: String(r.maturity ?? 'unset'),
    status: String(r.status ?? 'unset'),
    agent_source: String(r.agent_source?.type ?? 'unset'),
    confidence: m.confidence,
    matched_conditions: m.matchedConditions,
    witnesses: witnesses(engine, r, ev, quote),
  };
}

async function main(): Promise<void> {
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf-8')) as Manifest;
  const docs = loadDocuments(manifest);
  const classifications = loadClassification();
  const timestamp = new Date().toISOString();

  const engines = new Map<Lane, ATREngine>();
  const lanesLoaded: Record<string, number> = {};
  for (const lane of LANES) {
    const engine = new ATREngine({ rulesDir: RULES_DIR, lane });
    await engine.loadRules();
    engines.set(lane, engine);
    lanesLoaded[lane] = rulesInLane(engine.getRules(), lane);
  }

  const results: ToolResult[] = [];
  for (const s of manifest.servers) {
    const prov = new Map(s.provenance.map((p) => [p.name, p]));
    for (const tool of docs.get(s.id)!) {
      const flags = {} as Record<Lane, Record<Shape, Flag[]>>;
      for (const lane of LANES) {
        const engine = engines.get(lane)!;
        flags[lane] = { mcp_exchange: [], tool_response: [] };
        for (const shape of SHAPES) {
          const ev = eventFor(tool, shape, timestamp);
          flags[lane][shape] = engine.evaluate(ev).map((m) => flagOf(engine, m, ev, s.redistributed));
        }
      }
      results.push({
        server: s.id,
        tool: tool.name,
        definition_sha256: prov.get(tool.name)?.definition_sha256 ?? '',
        cli_content_hash: cliContentHash(eventFor(tool, 'mcp_exchange', timestamp)),
        flags,
      });
    }
  }

  // ---- aggregation
  const total = results.length;
  const uniqueDefs = new Set(results.map((r) => r.definition_sha256)).size;
  const perLane: Record<string, unknown> = {};
  for (const lane of LANES) {
    const byShape: Record<string, unknown> = {};
    for (const shape of SHAPES) {
      const flagged = results.filter((r) => r.flags[lane][shape].length > 0);
      const flaggedDefs = new Set(flagged.map((r) => r.definition_sha256));
      const byRule = new Map<string, { tools: number; maturity: string; agent_source: string; severity: string }>();
      for (const r of flagged) {
        for (const f of r.flags[lane][shape]) {
          const cur = byRule.get(f.rule_id) ?? { tools: 0, maturity: f.maturity, agent_source: f.agent_source, severity: f.severity };
          byRule.set(f.rule_id, { ...cur, tools: cur.tools + 1 });
        }
      }
      const byServer = Object.fromEntries(
        manifest.servers.map((s) => {
          const rs = results.filter((r) => r.server === s.id);
          return [s.id, { tools: rs.length, flagged: rs.filter((r) => r.flags[lane][shape].length > 0).length }];
        }),
      );
      byShape[shape] = {
        tools_scanned: total,
        tools_flagged: flagged.length,
        fp_rate: flagged.length / total,
        fp_rate_wilson95: wilson(flagged.length, total),
        // what `atr scan --fail-on high` would fail on (the adapters that block by default block at high)
        tools_flagged_high_or_critical: flagged.filter((r) => r.flags[lane][shape].some((f) => f.severity === 'high' || f.severity === 'critical')).length,
        unique_definitions: uniqueDefs,
        unique_definitions_flagged: flaggedDefs.size,
        unique_fp_rate: flaggedDefs.size / uniqueDefs,
        servers_with_a_flag: Object.values(byServer).filter((v) => v.flagged > 0).length,
        by_rule: Object.fromEntries([...byRule.entries()].sort((a, b) => b[1].tools - a[1].tools || a[0].localeCompare(b[0]))),
        by_server: byServer,
      };
    }
    const onlyExchange = results.filter((r) => r.flags[lane].mcp_exchange.length > 0 && r.flags[lane].tool_response.length === 0);
    const onlyResponse = results.filter((r) => r.flags[lane].tool_response.length > 0 && r.flags[lane].mcp_exchange.length === 0);
    const ruleSet = (r: ToolResult, shape: Shape) => new Set(r.flags[lane][shape].map((f) => f.rule_id));
    const extraRuleHits = results.flatMap((r) =>
      [...ruleSet(r, 'mcp_exchange')].filter((id) => !ruleSet(r, 'tool_response').has(id)).map((id) => `${r.server}/${r.tool}:${id}`),
    );
    const missingRuleHits = results.flatMap((r) =>
      [...ruleSet(r, 'tool_response')].filter((id) => !ruleSet(r, 'mcp_exchange').has(id)).map((id) => `${r.server}/${r.tool}:${id}`),
    );
    // Derived: the mcp_exchange flags of rules that are not tool_call rules (agent_source tool_call, or a
    // skill_* type the engine runs where tool_call rules run). Rules are evaluated independently, so this is
    // what the same events would flag if those rules did not run on a tools/list document.
    const isToolCallRule = (src: string) => (Object.hasOwn(RUNTIME_SOURCE_TYPE, src) ? RUNTIME_SOURCE_TYPE[src] : src) === 'tool_call';
    const withoutToolCall = results.filter((r) => r.flags[lane].mcp_exchange.some((f) => !isToolCallRule(f.agent_source)));
    perLane[lane] = {
      rules_in_lane: lanesLoaded[lane],
      ...byShape,
      derived_mcp_exchange_without_tool_call_rules: {
        tools_flagged: withoutToolCall.length,
        fp_rate: withoutToolCall.length / total,
        unique_definitions_flagged: new Set(withoutToolCall.map((r) => r.definition_sha256)).size,
        note: 'mcp_exchange flags minus every match of a rule whose agent_source (after RUNTIME_SOURCE_TYPE) is tool_call',
      },
      shape_difference: {
        tools_flagged_only_as_mcp_exchange: onlyExchange.map((r) => `${r.server}/${r.tool}`),
        tools_flagged_only_as_tool_response: onlyResponse.map((r) => `${r.server}/${r.tool}`),
        rule_hits_only_as_mcp_exchange: extraRuleHits,
        rule_hits_only_as_tool_response: missingRuleHits,
      },
    };
  }

  // ---- per-flag listing with classification
  const flaggedTools = results
    .filter((r) => LANES.some((l) => SHAPES.some((s) => r.flags[l][s].length > 0)))
    .map((r) => {
      const ids = new Set(LANES.flatMap((l) => SHAPES.flatMap((s) => r.flags[l][s].map((f) => f.rule_id))));
      const rules = [...ids].sort().map((id) => {
        const f = LANES.flatMap((l) => SHAPES.flatMap((s) => r.flags[l][s])).find((x) => x.rule_id === id)!;
        const c = classify(classifications, id, `${r.server}/${r.tool}`);
        return {
          rule_id: id,
          title: f.title,
          severity: f.severity,
          maturity: f.maturity,
          agent_source: f.agent_source,
          fires: Object.fromEntries(LANES.map((l) => [l, SHAPES.filter((s) => r.flags[l][s].some((x) => x.rule_id === id))])),
          witnesses: (r.flags.hunt.mcp_exchange.find((x) => x.rule_id === id) ?? f).witnesses,
          classification: c ? { cause: c.cause, ...(c.condition ? { condition: c.condition } : {}), explanation: c.explanation } : null,
        };
      });
      return { server: r.server, tool: r.tool, definition_sha256: r.definition_sha256, cli_content_hash: r.cli_content_hash, rules };
    });
  const unclassified = flaggedTools.flatMap((t) => t.rules.filter((x) => x.classification === null).map((x) => `${t.server}/${t.tool}:${x.rule_id}`));

  // ---- what each shape lets the tool-description rules see (attack side, rules' own true positives)
  // Every rule whose conditions read tool_description: each of its test_cases.true_positives becomes a tool
  // definition { name, description: <case text>, inputSchema: {} } scanned in both shapes in the hunt lane.
  const hunt = engines.get('hunt')!;
  const descRules = hunt.getRules().filter((r) => conditionsOf(r).some(([, c]) => c.field === 'tool_description'));
  const coverage = { rules: descRules.map((r) => r.id).sort(), cases: 0, own_rule_fires: { mcp_exchange: 0, tool_response: 0 } };
  for (const rule of descRules) {
    const tps = ((rule as unknown as { test_cases?: { true_positives?: unknown[] } }).test_cases?.true_positives ?? []);
    for (const tp of tps) {
      const input = (tp as { input?: unknown }).input ?? tp;
      const obj = typeof input === 'object' && input !== null ? (input as Record<string, unknown>) : {};
      const description = typeof input === 'string' ? input : String(obj['tool_description'] ?? obj['description'] ?? obj['content'] ?? JSON.stringify(input));
      const name = typeof obj['tool_name'] === 'string' ? (obj['tool_name'] as string) : 'helper_tool';
      const tool: Tool = { name, description, inputSchema: { type: 'object', properties: {} } };
      coverage.cases += 1;
      for (const shape of SHAPES) {
        if (hunt.evaluate(eventFor(tool, shape, timestamp)).some((m) => m.rule.id === rule.id)) coverage.own_rule_fires[shape] += 1;
      }
    }
  }

  // ---- CLI cross-check
  let cliCrosscheck: unknown = null;
  if (CLI_RESULTS) {
    const perLaneCheck: Record<string, unknown> = {};
    for (const lane of LANES) {
      const cliFlagged = new Set<string>();
      let scanned = 0;
      for (const s of manifest.servers) {
        const out = JSON.parse(readFileSync(join(CLI_RESULTS, lane, `${s.id}.json`), 'utf-8')) as {
          events_scanned: number;
          results: { content_hash: string; matches: { rule_id: string }[] }[];
        };
        scanned += out.events_scanned;
        for (const res of out.results) for (const m of res.matches) cliFlagged.add(`${res.content_hash}:${m.rule_id}`);
      }
      const ours = new Set(results.flatMap((r) => r.flags[lane].mcp_exchange.map((f) => `${r.cli_content_hash}:${f.rule_id}`)));
      perLaneCheck[lane] = {
        cli_events_scanned: scanned,
        cli_rule_hits: cliFlagged.size,
        script_rule_hits: ours.size,
        identical: cliFlagged.size === ours.size && [...ours].every((x) => cliFlagged.has(x)),
      };
    }
    cliCrosscheck = { cli_build: `PR #737 head ${PR_737_COMMIT}`, per_lane: perLaneCheck };
  }

  // ---- the tool-definition context (PR #737 engine option toolDefinitions)
  const toolDefinitionContext = await measureToolDefinitionContext(manifest, results, classifications, timestamp, docs);

  const atrVersion = (JSON.parse(readFileSync(resolve(REPO_ROOT, 'package.json'), 'utf-8')) as { version: string }).version;
  const atrCommit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO_ROOT }).toString().trim();
  const rulesTree = execFileSync('git', ['rev-parse', 'HEAD:rules'], { cwd: REPO_ROOT }).toString().trim();
  const sourceVersion = 'pinned-2026-10-22';
  const report = {
    kind: 'benign-fp',
    source: 'mcp-tools-list-benign',
    source_version: sourceVersion,
    atr_version: atrVersion,
    atr_commit: atrCommit,
    rules_tree_sha: rulesTree,
    measured_at: timestamp,
    corpus: {
      manifest: 'data/test-corpora/mcp-tools-list-benign/manifest.json',
      manifest_sha256: sha256(readFileSync(MANIFEST_PATH, 'utf-8')),
      servers: manifest.servers.length,
      tools: total,
      unique_definitions: uniqueDefs,
      label: 'benign (every tool); see sources.json inclusion_policy',
    },
    method: {
      shapes: {
        mcp_exchange: `atr scan on a tools/list document (PR #737, ${PR_737_COMMIT}): content = JSON of the tool definition, fields tool_name + tool_description; type mcp_exchange (no source-type filter)`,
        tool_response: 'the same content and fields, typed tool_response (the type atr test builds for mcp_exchange rules)',
      },
      engine: "new ATREngine({ rulesDir, lane }): regex tier only, no embedding / semantic judge (what atr scan runs without --semantic-judge); detection = engine.evaluate(event) non-empty",
      fp_definition: 'a corpus tool with at least one rule match; fp_rate = tools_flagged / tools_scanned; unique_* counts each distinct definition (sha256) once, since some servers share tools',
      witnesses: 'matched text re-derived per condition for diagnosis (excerpts only for redistributable sources)',
      reproduce: `git checkout ${atrCommit} && npm ci && bash scripts/mcp-tools-list/reproduce.sh --write`,
    },
    lanes: perLane,
    flagged_tools: flaggedTools,
    unclassified_flags: unclassified,
    tool_description_rule_coverage: {
      ...coverage,
      agent_source_of_these_rules: [...new Set(descRules.map((r) => String(r.agent_source?.type)))],
      note: 'Each true positive of a rule that reads tool_description, as a one-tool definition, scanned in the hunt lane: how many fire their own rule in each shape. These rules are agent_source tool_call; the tool_response shape does not admit tool_call rules.',
    },
    cli_crosscheck: cliCrosscheck,
    tool_definition_context: toolDefinitionContext,
  };

  for (const lane of LANES) {
    const l = perLane[lane] as Record<Shape, { tools_flagged: number; unique_definitions_flagged: number; fp_rate: number }>;
    console.log(
      `${lane.padEnd(7)} mcp_exchange ${l.mcp_exchange.tools_flagged}/${total} (${(100 * l.mcp_exchange.fp_rate).toFixed(2)}%)` +
        `  tool_response ${l.tool_response.tools_flagged}/${total} (${(100 * l.tool_response.fp_rate).toFixed(2)}%)` +
        `  unique mcp_exchange ${l.mcp_exchange.unique_definitions_flagged}/${uniqueDefs}` +
        `  mcp_exchange w/o tool_call rules ${(perLane[lane] as { derived_mcp_exchange_without_tool_call_rules: { tools_flagged: number } }).derived_mcp_exchange_without_tool_call_rules.tools_flagged}`,
    );
  }
  if (toolDefinitionContext) {
    const ctx = toolDefinitionContext as { per_lane: Record<string, { tools_flagged: number }> ; measured_with: string };
    console.log(`tool-definition context (${ctx.measured_with}): ` + LANES.map((l) => `${l} ${ctx.per_lane[l]!.tools_flagged}/${total}`).join('  '));
  }
  if (cliCrosscheck) console.log(`CLI cross-check: ${JSON.stringify((cliCrosscheck as { per_lane: unknown }).per_lane)}`);
  if (unclassified.length > 0) console.log(`unclassified flags (${unclassified.length}): ${unclassified.join(', ')}`);

  if (DUMP) writeFileSync(DUMP, `${JSON.stringify(report, null, 2)}\n`);
  if (WRITE) {
    mkdirSync(OUT_DIR, { recursive: true });
    const date = timestamp.slice(0, 10);
    const file = join(OUT_DIR, `benign-fp_${date}_${sourceVersion}_atr-${atrVersion.replace(/\./g, '-')}${LABEL ? `_${LABEL}` : ''}.json`);
    if (existsSync(file)) throw new Error(`${file} exists: measurement files are append-only`);
    writeFileSync(file, `${JSON.stringify(report, null, 2)}\n`);
    console.log(`wrote ${file}`);
  }
  const ctxUnclassified = (toolDefinitionContext as { unclassified_flags?: string[] } | null)?.unclassified_flags ?? [];
  if (CHECK && (unclassified.length > 0 || ctxUnclassified.length > 0)) process.exitCode = 1;
}

// ------------------------------------------------------------------ tool-definition context

interface ScopedLane {
  tools_flagged: number;
  fp_rate: number;
  fp_rate_wilson95: [number, number];
  tools_flagged_high_or_critical: number;
  by_rule: Record<string, number>;
  flagged: { server: string; tool: string; rules: string[] }[];
}

/**
 * Flags per lane with the PR #737 tool-definition scope: measured in-process when this checkout's
 * engine has the option, else read from `atr scan` output of a PR build (--scoped-cli-results).
 */
async function measureToolDefinitionContext(
  manifest: Manifest,
  results: readonly ToolResult[],
  classifications: readonly Classification[],
  timestamp: string,
  docs: Map<string, readonly Tool[]>,
): Promise<unknown> {
  const total = results.length;
  const perLane: Record<string, ScopedLane> = {};
  let measuredWith: string;
  let code: Record<string, unknown>;
  const scopeModule = resolve(REPO_ROOT, 'src/tool-definition-scope.ts');
  const severityOf = new Map<string, string>();
  if (existsSync(scopeModule)) {
    measuredWith = "in-process: new ATREngine({ rulesDir, lane, toolDefinitions: true })";
    code = { commit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO_ROOT }).toString().trim() };
    for (const lane of LANES) {
      const engine = new ATREngine({ rulesDir: RULES_DIR, lane, toolDefinitions: true } as ConstructorParameters<typeof ATREngine>[0]);
      await engine.loadRules();
      const flagged: ScopedLane['flagged'] = [];
      for (const s of manifest.servers) {
        for (const tool of docs.get(s.id)!) {
          const ms = engine.evaluate(eventFor(tool, 'mcp_exchange', timestamp));
          ms.forEach((m) => severityOf.set(m.rule.id, m.rule.severity));
          if (ms.length > 0) flagged.push({ server: s.id, tool: tool.name, rules: [...new Set(ms.map((m) => m.rule.id))].sort() });
        }
      }
      perLane[lane] = summarise(flagged, total, severityOf);
    }
  } else if (SCOPED_CLI_RESULTS && SCOPED_CLI_REPO) {
    const git = (...a: string[]) => execFileSync('git', a, { cwd: SCOPED_CLI_REPO }).toString().trim();
    measuredWith = 'atr scan <document> --no-report --json --lane <lane>, built from the commit below';
    code = {
      commit: git('rev-parse', 'HEAD'),
      rules_tree_sha: git('rev-parse', 'HEAD:rules'),
      src_and_rules_clean: git('status', '--porcelain', '--', 'src', 'rules') === '',
    };
    const byHash = new Map(results.map((r) => [r.cli_content_hash, r]));
    for (const lane of LANES) {
      const flagged: ScopedLane['flagged'] = [];
      let scanned = 0;
      for (const s of manifest.servers) {
        const out = JSON.parse(readFileSync(join(SCOPED_CLI_RESULTS, lane, `${s.id}.json`), 'utf-8')) as {
          events_scanned: number;
          results: { content_hash: string; matches: { rule_id: string; severity: string }[] }[];
        };
        scanned += out.events_scanned;
        for (const res of out.results) {
          const r = byHash.get(res.content_hash);
          if (!r) throw new Error(`${lane}/${s.id}: content_hash ${res.content_hash} is not a corpus tool`);
          res.matches.forEach((m) => severityOf.set(m.rule_id, m.severity));
          flagged.push({ server: r.server, tool: r.tool, rules: [...new Set(res.matches.map((m) => m.rule_id))].sort() });
        }
      }
      if (scanned !== total) throw new Error(`${lane}: the CLI scanned ${scanned} tools, the corpus has ${total}`);
      perLane[lane] = summarise(flagged, total, severityOf);
    }
  } else {
    return null;
  }
  const remaining = new Map<string, { server: string; tool: string; rules: string[] }>();
  for (const lane of LANES) for (const f of perLane[lane]!.flagged) remaining.set(`${f.server}/${f.tool}`, f);
  const remainingFlags = [...remaining.values()].map((f) => ({
    ...f,
    lanes: LANES.filter((l) => perLane[l]!.flagged.some((x) => x.server === f.server && x.tool === f.tool)),
    classification: f.rules.map((id) => {
      const c = classify(classifications, id, `${f.server}/${f.tool}`);
      return { rule_id: id, cause: c?.cause ?? null, explanation: c?.explanation ?? null };
    }),
  }));
  return {
    measured_with: measuredWith,
    code,
    scope: 'a rule with agent_source.type tool_call runs only if a condition reads tool_description or it is in TOOL_IDENTITY_RULES (ATR-2026-00060); every other rule runs as on the plain mcp_exchange event',
    per_lane: perLane,
    remaining_flags: remainingFlags,
    unclassified_flags: remainingFlags.flatMap((f) => f.classification.filter((c) => c.cause === null).map((c) => `${f.server}/${f.tool}:${c.rule_id}`)),
  };
}

function summarise(flagged: ScopedLane['flagged'], total: number, severityOf: Map<string, string>): ScopedLane {
  const byRule: Record<string, number> = {};
  for (const f of flagged) for (const id of f.rules) byRule[id] = (byRule[id] ?? 0) + 1;
  return {
    tools_flagged: flagged.length,
    fp_rate: flagged.length / total,
    fp_rate_wilson95: wilson(flagged.length, total),
    tools_flagged_high_or_critical: flagged.filter((f) => f.rules.some((id) => ['high', 'critical'].includes(severityOf.get(id) ?? ''))).length,
    by_rule: byRule,
    flagged,
  };
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
