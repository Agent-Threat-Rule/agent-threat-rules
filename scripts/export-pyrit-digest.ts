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
 * on the current rule set, 1,082 of 3,322 regex conditions (32.6%) carry no
 * `(?i)` prefix and would silently become case-sensitive on the other side. Each
 * emitted pattern therefore carries its own `(?i)` unless the condition opted
 * out, so the digest means the same thing wherever it is compiled.
 *
 * Astral escapes. `\u{...}` is JavaScript-only and does not compile under Python
 * `re`; the rules use literal characters for exactly this reason (see
 * needsUnicodeFlag in src/engine.ts). Nothing to translate, but patterns are
 * still test-compiled below and anything that fails is dropped with its reason
 * recorded rather than shipped broken.
 *
 * WHAT IS NOT REPRESENTABLE
 *
 * `RegexScorer` is a pure OR across every pattern, so a rule whose conditions
 * must ALL hold cannot be expressed. Four rules use `condition: all`; they are
 * excluded and listed in the digest's `excluded` block, because a rule silently
 * downgraded from AND to OR is a false-positive generator, not a rule.
 *
 * Field routing is likewise absent: the scorer sees one string, so a condition
 * written against `tool_args` is applied to whatever it is given. That is a
 * property of the consumer, and the digest records each pattern's field so the
 * caller can filter if it ever gains the context to.
 *
 * Usage:
 *   npx tsx scripts/export-pyrit-digest.ts --out data/pyrit-digest.json
 */
import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { load as parseYaml } from 'js-yaml';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const RULES = join(ROOT, 'rules');

interface Emitted {
  readonly rule_id: string;
  readonly pattern: string;
  readonly field: string;
  readonly category: string;
  readonly severity: string;
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

function main(argv: readonly string[]): number {
  const outIdx = argv.indexOf('--out');
  const out = outIdx >= 0 ? argv[outIdx + 1] : undefined;
  const fieldIdx = argv.indexOf('--fields');
  // Which fields the consumer can actually present. A scorer that sees a model
  // response can offer agent_output and content and nothing else; emitting a
  // condition written against tool_args means applying it to prose it was never
  // meant for. Measured on 600 ordinary conversations: the unfiltered digest
  // flags 23.5% where the engine flags 0.8%, and 122 of the 141 extra come from
  // one rule whose conditions name tool_name and tool_args.
  const fields = new Set(
    (fieldIdx >= 0 ? argv[fieldIdx + 1] : 'agent_output,content').split(',').map((f) => f.trim()),
  );
  if (!out) {
    console.error('usage: export-pyrit-digest.ts --out <path> [--fields agent_output,content]');
    return 2;
  }

  const patterns: Record<string, string> = {};
  const meta: Record<string, Emitted> = {};
  const excluded: Record<string, string> = {};
  let rulesSeen = 0;
  let rulesEmitted = 0;
  let outOfScope = 0;

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

    const status = String(r.status ?? '');
    const maturity = String(r.maturity ?? '');
    // Inert rules never fire in the engine either.
    if (status === 'draft' || status === 'deprecated' || maturity === 'deprecated') continue;
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
      if (!fields.has(field)) {
        outOfScope += 1;
        continue;
      }

      // Bake in the flag the engine would have applied.
      const alreadyInline = /^\(\?[imsx]+\)/.test(raw);
      const pattern = cond.case_sensitive || alreadyInline ? raw : `(?i)${raw}`;

      // Ship nothing that does not compile where it will be used.
      try {
        execFileSync('python3', ['-c', 'import re,sys; re.compile(sys.argv[1])', pattern], {
          stdio: 'pipe',
        });
      } catch {
        excluded[`${r.id}#${idx}`] = 'does not compile under Python re';
        continue;
      }

      const name = `${r.id}#${idx}`;
      patterns[name] = pattern;
      meta[name] = {
        rule_id: r.id,
        pattern,
        field: String(cond.field ?? 'content'),
        category,
        severity,
      };
      emittedForRule += 1;
    }
    if (emittedForRule > 0) rulesEmitted += 1;
  }

  let commit = 'unknown';
  try {
    commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: ROOT, encoding: 'utf-8' }).trim();
  } catch {
    /* not a checkout */
  }
  const version = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf-8')).version;

  const digest = {
    _comment:
      'Precompiled ATR rule digest for consumers that cannot take a dependency on an ATR engine. ' +
      'Each pattern carries its own inline flags and compiles under Python re as-is. ' +
      'Generated by scripts/export-pyrit-digest.ts -- do not hand-edit.',
    atr_version: version,
    atr_commit: commit,
    fields_in_scope: [...fields].sort(),
    conditions_out_of_scope: outOfScope,
    rules_seen: rulesSeen,
    rules_emitted: rulesEmitted,
    pattern_count: Object.keys(patterns).length,
    patterns,
    meta,
    excluded,
  };
  writeFileSync(out, JSON.stringify(digest, null, 2) + '\n');
  console.log(
    `[pyrit-digest] ${rulesEmitted}/${rulesSeen} rules, ${Object.keys(patterns).length} patterns, ` +
      `${Object.keys(excluded).length} excluded, ${outOfScope} out of field scope -> ${out}`,
  );
  return 0;
}

const DIRECT =
  process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (DIRECT) process.exitCode = main(process.argv.slice(2));
