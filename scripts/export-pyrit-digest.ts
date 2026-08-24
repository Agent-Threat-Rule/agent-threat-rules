#!/usr/bin/env node
/**
 * Emit a precompiled rule digest for PyRIT's AgentThreatRulesScorer.
 *
 * PyRIT reverted the first version of that scorer (microsoft/PyRIT#2410) because
 * it added `pyatr` as a dependency. The replacement subclasses PyRIT's existing
 * `RegexScorer`, which takes `dict[name, regex]` and compiles each with a plain
 * `re.compile(pattern)` -- no flags, no engine. This file produces that dict.
 *
 * TWO THINGS ARE BAKED IN HERE RATHER THAN LEFT TO THE CONSUMER
 *
 * Case sensitivity. The ATR engine compiles case-insensitively unless a
 * condition sets `case_sensitive`, but `RegexScorer` passes no flags. Measured
 * on the current rule set, 1,078 of 3,315 regex conditions (32.5%) carry no
 * `(?i)` prefix of their own and would silently become case-sensitive on the
 * other side. Each emitted pattern therefore carries the flag the engine would
 * have applied, so the digest means the same thing wherever it is compiled. A
 * condition that opted out is emitted with `case_sensitive: true` instead, so a
 * missing flag is always attributable rather than ambiguous.
 *
 * Astral escapes. `\u{...}` is JavaScript-only and does not compile under Python
 * `re`; the rules use literal characters for exactly this reason (see
 * needsUnicodeFlag in src/engine.ts). Nothing to translate, but patterns are
 * still test-compiled below and anything that fails is dropped with its reason
 * recorded rather than shipped broken.
 *
 * WHAT THE CONSUMER STILL HAS TO DO: SELECT FIELDS
 *
 * ATR conditions are written against a named field -- `agent_output`,
 * `tool_args`, `tool_name`, and so on -- and the engine only ever applies a
 * condition to the field it names. A consumer that sees one undifferentiated
 * string has no such routing, so handing it every pattern evaluates tool-call
 * conditions against prose they were never written for.
 *
 * Measured on 600 ordinary conversations at `llm_output` shape, against the
 * engine loading the same rules: selecting `default_fields` flags 0.7% and
 * agrees with the engine on all 600 samples. Taking every field instead flags
 * 21.7% with no severity floor applied, or 7.5% at the `medium` floor a
 * consumer is likely to set -- the gap between those two is almost entirely
 * ATR-2026-00099, a low-severity rule whose conditions name `tool_name` and
 * `tool_args`. Quoting either figure without naming the floor misstates the
 * cost, so scripts/measure-digest-parity.py reports both.
 *
 * So every condition is emitted carrying its `field`, and `default_fields` names
 * the scope a consumer scoring an agent's text output should select. Conditions
 * for the other fields are present for consumers that genuinely hold that
 * content; selecting them is a deliberate act, not the default. There is
 * deliberately no ready-made flat `{name: pattern}` map in the artifact, because
 * the shape that is convenient to pass straight to a scorer is exactly the shape
 * that produces the 21.7%.
 *
 * WHAT IS NOT REPRESENTABLE AT ALL
 *
 * A pure OR across independent patterns cannot express a rule whose conditions
 * must ALL hold. Those rules are excluded and listed in the digest's `excluded`
 * block, because a rule silently downgraded from AND to OR is a false-positive
 * generator, not a rule.
 *
 * WHY EXCLUSIONS ARE GATED RATHER THAN JUST RECORDED
 *
 * Recording a dropped pattern is only half of it: a digest that quietly loses
 * rules between releases looks identical to one that does not. Microsoft's own
 * weekly ATR sync in agent-governance-toolkit runs without `--strict-regex` and
 * skips invalid patterns with a warning, so an unknown number of rules are
 * missing from a shipped product and nobody downstream can tell which. This
 * exporter therefore diffs the exclusion set against a checked-in baseline and
 * fails when it changes. Known breakage stays visible, new breakage stops the
 * build, and accepting a change is a deliberate `--update-baseline` commit.
 *
 * Usage:
 *   npx tsx scripts/export-pyrit-digest.ts --out data/pyrit-digest.json
 *   npx tsx scripts/export-pyrit-digest.ts --out ... --default-fields agent_output,content
 *   npx tsx scripts/export-pyrit-digest.ts --out ... --update-baseline
 *   npx tsx scripts/export-pyrit-digest.ts --out ... --strict   // any exclusion fails
 */
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { load as parseYaml } from 'js-yaml';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const RULES = join(ROOT, 'rules');
const SCHEMA = 1;

/** The scope a consumer scoring an agent's text output should select. */
const DEFAULT_FIELDS = ['agent_output', 'content'];

interface Emitted {
  readonly rule_id: string;
  readonly pattern: string;
  readonly field: string;
  readonly category: string;
  readonly severity: string;
  /** Present only when the rule opted out of the engine's default folding. */
  readonly case_sensitive?: true;
}

function ruleFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const f = join(dir, e);
    if (statSync(f).isDirectory()) out.push(...ruleFiles(f));
    else if (e.endsWith('.yaml') || e.endsWith('.yml')) out.push(f);
  }
  return out;
}

/**
 * Names of the patterns that will not compile under Python `re`.
 *
 * One subprocess for the whole set: the check has to run in the engine the
 * consumer uses, but it does not have to run 3,300 times.
 */
function compileFailures(patterns: Record<string, string>): string[] {
  const names = Object.keys(patterns);
  if (names.length === 0) return [];
  const probe = [
    'import json,re,sys',
    'items = json.load(sys.stdin)',
    'bad = []',
    'for name, pat in items.items():',
    '    try:',
    '        re.compile(pat)',
    '    except re.error:',
    '        bad.append(name)',
    'print(json.dumps(bad))',
  ].join('\n');
  const outText = execFileSync('python3', ['-c', probe], {
    input: JSON.stringify(patterns),
    encoding: 'utf-8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return JSON.parse(outText) as string[];
}

function main(argv: readonly string[]): number {
  const outIdx = argv.indexOf('--out');
  const out = outIdx >= 0 ? argv[outIdx + 1] : undefined;
  const defIdx = argv.indexOf('--default-fields');
  // Recorded, not applied. Everything is emitted; this names the scope a
  // consumer that cannot route by field should select, and the count of rules
  // that scope reaches is published alongside it.
  const defaultFields =
    defIdx >= 0 ? argv[defIdx + 1].split(',').map((f) => f.trim()) : [...DEFAULT_FIELDS];
  const baselineIdx = argv.indexOf('--baseline');
  const baseline =
    baselineIdx >= 0 ? argv[baselineIdx + 1] : join(ROOT, 'data', 'pyrit-digest-exclusions.json');
  const updateBaseline = argv.includes('--update-baseline');
  const strict = argv.includes('--strict');
  if (!out) {
    console.error(
      'usage: export-pyrit-digest.ts --out <path> [--default-fields agent_output,content] ' +
        '[--baseline <path>] [--update-baseline] [--strict]',
    );
    return 2;
  }

  const patterns: Record<string, string> = {};
  const meta: Record<string, Emitted> = {};
  const excluded: Record<string, string> = {};
  let rulesSeen = 0;
  let rulesEmitted = 0;

  for (const file of ruleFiles(RULES).sort()) {
    let doc: unknown;
    try {
      doc = parseYaml(readFileSync(file, 'utf-8'));
    } catch (e) {
      excluded[file] = `unparseable: ${String(e).slice(0, 60)}`;
      continue;
    }
    const r = doc as Record<string, any>;
    if (typeof r?.id !== 'string') continue;

    // Exactly the engine's own test -- src/engine.ts and pyatr both gate on
    // status alone. A rule the engine will never fire must not reach a consumer
    // that has no such gate, and widening this (on maturity, say) would make the
    // digest quietly stricter than the engine it stands in for.
    const status = String(r.status ?? '');
    if (status === 'draft' || status === 'deprecated') continue;
    rulesSeen += 1;

    const det = r.detection ?? {};
    if (String(det.condition ?? 'any') === 'all') {
      excluded[r.id] = 'condition: all -- RegexScorer is a pure OR and cannot express it';
      continue;
    }

    const category = String(r.tags?.category ?? '');
    const severity = String(r.severity ?? '').toLowerCase();
    let emittedForRule = 0;

    for (const [idx, cond] of (det.conditions ?? []).entries()) {
      if (String(cond?.operator ?? '') !== 'regex') continue;
      const raw = String(cond.value ?? '');
      if (!raw) continue;
      const field = String(cond.field ?? 'content');

      // Bake in the flag the engine would have applied.
      const caseSensitive = Boolean(cond.case_sensitive);
      const alreadyInline = /^\(\?[imsx]+\)/.test(raw);
      const pattern = caseSensitive || alreadyInline ? raw : `(?i)${raw}`;

      const name = `${r.id}#${idx}`;
      patterns[name] = pattern;
      meta[name] = {
        rule_id: r.id,
        pattern,
        field,
        category,
        severity,
        ...(caseSensitive ? { case_sensitive: true as const } : {}),
      };
      emittedForRule += 1;
    }
    if (emittedForRule > 0) rulesEmitted += 1;
  }

  // Ship nothing that does not compile where it will be used. Checked in one
  // batch rather than a subprocess per pattern: at ~3,300 conditions the
  // per-pattern spawn dominated the run and made this too slow to sit in CI,
  // which would have quietly turned the guarantee into an optional step.
  for (const name of compileFailures(patterns)) {
    excluded[name] = 'does not compile under Python re';
    delete patterns[name];
    delete meta[name];
  }
  rulesEmitted = new Set(Object.values(meta).map((m) => m.rule_id)).size;

  let commit = 'unknown';
  try {
    commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf-8' }).trim();
  } catch {
    /* not a checkout */
  }
  const version = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf-8')).version;

  const byField: Record<string, number> = {};
  const rulesInDefault = new Set<string>();
  for (const m of Object.values(meta)) {
    byField[m.field] = (byField[m.field] ?? 0) + 1;
    if (defaultFields.includes(m.field)) rulesInDefault.add(m.rule_id);
  }

  const digest = {
    _comment:
      'Precompiled ATR rule digest for consumers that cannot take a dependency on an ATR engine. ' +
      'Each pattern carries its own inline flags and compiles under Python re as-is. Each condition ' +
      'carries the field it was written against; a consumer that cannot route by field should select ' +
      'default_fields, because applying tool-call patterns to prose is a false-positive generator. ' +
      'Generated by scripts/export-pyrit-digest.ts -- do not hand-edit.',
    schema: SCHEMA,
    atr_version: version,
    atr_commit: commit,
    default_fields: [...defaultFields].sort(),
    rules_seen: rulesSeen,
    rules_emitted: rulesEmitted,
    rules_in_default_fields: rulesInDefault.size,
    condition_count: Object.keys(meta).length,
    conditions_by_field: Object.fromEntries(
      Object.entries(byField).sort(([a], [b]) => a.localeCompare(b)),
    ),
    conditions: meta,
    // Sorted so a reordered walk does not show up as a diff in a committed
    // artifact. The batch compile check appends its failures at the end, which
    // would otherwise churn this block on every refactor.
    excluded: Object.fromEntries(Object.entries(excluded).sort(([a], [b]) => a.localeCompare(b))),
  };
  writeFileSync(out, JSON.stringify(digest, null, 2) + '\n');
  console.log(
    `[pyrit-digest] ${rulesEmitted}/${rulesSeen} rules, ${Object.keys(meta).length} conditions, ` +
      `${rulesInDefault.size} in default fields, ${Object.keys(excluded).length} excluded -> ${out}`,
  );

  // Order-independent shape so a reordered walk is not mistaken for drift.
  const current = Object.entries(excluded)
    .map(([name, reason]) => `${name}\t${reason}`)
    .sort();

  if (updateBaseline) {
    writeFileSync(
      baseline,
      JSON.stringify(
        {
          _comment:
            'Known exclusions from the PyRIT digest. The export fails when this set changes; ' +
            'update it deliberately so a rule that stops shipping is a reviewed decision.',
          exclusions: current,
        },
        null,
        2,
      ) + '\n',
    );
    console.log(`[pyrit-digest] baseline updated -- ${current.length} known exclusions`);
    return 0;
  }

  if (strict && current.length > 0) {
    console.error(`[pyrit-digest] STRICT: ${current.length} exclusion(s); every rule must be representable`);
    return 1;
  }

  let known: string[];
  try {
    known = JSON.parse(readFileSync(baseline, 'utf-8')).exclusions ?? [];
  } catch {
    // Absent baseline is a failure, not a default-permissive path: the whole
    // point is that nothing drops without a recorded decision.
    console.error(`[pyrit-digest] no baseline at ${baseline} -- run once with --update-baseline`);
    return 1;
  }

  const added = current.filter((x) => !known.includes(x));
  const removed = known.filter((x) => !current.includes(x));
  if (added.length > 0 || removed.length > 0) {
    console.error('[pyrit-digest] EXCLUSION SET CHANGED -- failing rather than skipping quietly.');
    for (const x of added) console.error(`  + ${x.replace('\t', '  ')}`);
    for (const x of removed) console.error(`  - ${x.replace('\t', '  ')}  (fixed -- rerun with --update-baseline)`);
    return 1;
  }

  console.log(`[pyrit-digest] exclusions match baseline (${known.length})`);
  return 0;
}

const DIRECT =
  process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (DIRECT) process.exitCode = main(process.argv.slice(2));
