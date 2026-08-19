#!/usr/bin/env npx tsx
/**
 * scripts/measure-rule-against-samples.ts
 *
 * Measure one rule (or a few) against a JSONL sample file, on the SAME event
 * shape set the benign false-positive gate charges rules on
 * (src/corpus-event.ts corpusShapes + scanSkill). A rule can therefore never
 * earn its detection credit on a wider presentation than the one it pays its
 * false positives on.
 *
 * WHY THIS EXISTS
 *   gate-promotion-fp.ts answers "does this rule fire on the committed benign
 *   corpus". It cannot answer "does this rule fire on the most plausible
 *   legitimate sentence a reviewer can invent", and docs/DETECTION-BOUNDARY.md
 *   §3 shows that the second question is the one that overturns rules: five
 *   rules passed the corpus gate at 0 FP and then fired on 20-57% of
 *   hand-written benign samples. This script runs a rule against such a set
 *   directly, so the answer arrives before shipping instead of after.
 *
 * CONTROL — runs before any number is printed; on failure it exits 1 having
 * printed no measurement at all:
 *   - the rule must load and compile (count check against the files given);
 *   - every true_positive the rule declares must fire it;
 *   - every true_negative the rule declares must NOT fire it.
 * A rule whose own fixtures do not behave cannot be measured, so it is not.
 *
 * Loading only the named rule files is deliberate and safe: the engine's Tier-2
 * loop evaluates each rule independently, so a per-rule verdict is identical to
 * the full-set verdict and a 36k-sample scan costs one rule instead of 785.
 *
 * Usage:
 *   npx tsx scripts/measure-rule-against-samples.ts \
 *     --rule rules/prompt-injection/ATR-2026-02500-....yaml \
 *     --samples data/measurements/atr-2026-02500/benign-adversarial.jsonl \
 *     [--expect-fire | --expect-silent] [--group-by group] [--json out.json]
 *
 * Sample file: JSONL, one object per line with a `text` field; optional `id`
 * and any grouping fields.
 *
 * Exit codes: 0 measured (and expectation met, if one was given), 1 control
 * failure / usage error / expectation not met.
 */
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import yaml from 'js-yaml';
import { ATREngine } from '../src/engine.js';
import { matchedRuleIds } from '../src/corpus-event.js';

interface Sample { readonly id?: string; readonly text: string; readonly [k: string]: unknown }
interface Fixtures { readonly id: string; readonly truePositives: readonly string[]; readonly trueNegatives: readonly string[] }

function readFlag(argv: readonly string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('--')) throw new Error(`${name} needs a value`);
  return value;
}

function fixturesOf(path: string): Fixtures {
  const doc = yaml.load(readFileSync(path, 'utf8')) as Record<string, unknown>;
  const cases = (doc.test_cases ?? {}) as Record<string, { input?: unknown }[]>;
  const inputs = (key: string): string[] => (cases[key] ?? []).map((c) => String(c.input));
  return { id: String(doc.id), truePositives: inputs('true_positives'), trueNegatives: inputs('true_negatives') };
}

function stageRules(rulePaths: readonly string[]): string {
  const dir = mkdtempSync(join(tmpdir(), 'atr-measure-'));
  mkdirSync(join(dir, 'staged'), { recursive: true });
  for (const path of rulePaths) copyFileSync(path, join(dir, 'staged', basename(path)));
  return dir;
}

function fail(message: string): never {
  process.stderr.write(`${message}\nNo measurement printed.\n`);
  process.exit(1);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const rulePaths = (readFlag(argv, '--rule') ?? '').split(',').filter((s) => s.length > 0);
  if (rulePaths.length === 0) fail('usage: --rule <path.yaml>[,<path.yaml>] [--samples <file.jsonl>]');

  const engine = new ATREngine({ rulesDir: stageRules(rulePaths) });
  const loaded = await engine.loadRules();
  process.stderr.write(`control: loaded ${loaded} rule file(s)\n`);
  if (loaded !== rulePaths.length) fail(`control FAIL: expected ${rulePaths.length} rule(s), engine compiled ${loaded}`);

  const watched: string[] = [];
  for (const path of rulePaths) {
    const fixture = fixturesOf(path);
    watched.push(fixture.id);
    if (fixture.truePositives.length === 0) fail(`control FAIL: ${fixture.id} declares no true_positives`);
    const tpHits = fixture.truePositives.filter((t) => matchedRuleIds(engine, t).has(fixture.id)).length;
    const tnHits = fixture.trueNegatives.filter((t) => matchedRuleIds(engine, t).has(fixture.id)).length;
    process.stderr.write(
      `control: ${fixture.id} own fixtures — true_positives fired ${tpHits}/${fixture.truePositives.length}, ` +
        `true_negatives fired ${tnHits}/${fixture.trueNegatives.length}\n`,
    );
    if (tpHits !== fixture.truePositives.length || tnHits !== 0) fail('control FAIL: the rule does not behave on its own fixtures');
  }

  const samplesPath = readFlag(argv, '--samples');
  if (samplesPath === undefined) { process.stderr.write('control OK (no --samples given)\n'); return; }

  const groupBy = readFlag(argv, '--group-by');
  const samples: Sample[] = readFileSync(samplesPath, 'utf8')
    .split('\n')
    .filter((line) => line.trim().length > 0)
    .map((line) => JSON.parse(line) as Sample);

  const firedIds = new Map<string, string[]>(watched.map((id) => [id, []]));
  const groups = new Map<string, { total: number; fired: number }>();
  samples.forEach((sample, index) => {
    const sampleId = sample.id ?? `line-${index}`;
    const hits = matchedRuleIds(engine, sample.text);
    const anyFired = watched.some((id) => hits.has(id));
    for (const id of watched) if (hits.has(id)) firedIds.get(id)!.push(sampleId);
    if (groupBy !== undefined) {
      const key = String(sample[groupBy] ?? 'ungrouped');
      const current = groups.get(key) ?? { total: 0, fired: 0 };
      groups.set(key, { total: current.total + 1, fired: current.fired + (anyFired ? 1 : 0) });
    }
  });

  const report = {
    samples: samplesPath,
    sampleCount: samples.length,
    shapes: 'wide-raw, pre-tool-json-arg, pre-tool-json-both, post-tool-json, skill',
    perRule: Object.fromEntries([...firedIds].map(([id, ids]) => [id, { fired: ids.length, sampleIds: ids }])),
    ...(groupBy === undefined ? {} : { byGroup: Object.fromEntries(groups) }),
  };
  const out = readFlag(argv, '--json');
  if (out !== undefined) writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);

  const totalFired = [...firedIds.values()].reduce((sum, ids) => sum + ids.length, 0);
  if (argv.includes('--expect-silent') && totalFired > 0) fail(`expectation FAIL: expected silence, ${totalFired} sample(s) fired`);
  if (argv.includes('--expect-fire') && totalFired === 0) fail('expectation FAIL: expected at least one firing, got none');
}

main().catch((error) => { process.stderr.write(`measure-rule-against-samples failed: ${(error as Error).message}\n`); process.exit(1); });
