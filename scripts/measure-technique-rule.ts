#!/usr/bin/env npx tsx
/**
 * Measure one hand-written candidate rule for the technique-first pilot
 * (issue #848): recall by derived family, outside the corpora its author
 * looked at, and false positives on every benign corpus fn-mine gates on.
 *
 *   npx tsx scripts/measure-technique-rule.ts --rule path/to/rule.yaml \
 *     --looked-at mosscap,web-agent-attack [--json]
 *
 * --looked-at names the corpora read while writing the rule, before anything
 * is measured (`none` if there were none). Those corpora and their derived
 * families (DERIVED_FROM) do not count, and neither does a hit whose sample a
 * looked-at corpus also holds (sampleKey). See scripts/lib/technique-harness.ts.
 *
 * What it runs: the rule alone, through the same eval harness fn-mine uses
 * (detectionsByRule), each corpus presented as its registered event type.
 * Attack texts are the out-of-sample pool as the fn-mine gate reads it
 * (readOutOfSample: scoring strings removed). Benign corpora:
 *   - data/benign-corpus-extended/*.jsonl, as user input;
 *   - data/fn-mine-benign/hard-negatives/<id>, as the source's event type;
 *   - the #829 user-request set (user-input-business), as user input;
 *   - the benign tool-output corpora (emails, pages, records, tasks,
 *     business-system outputs), as tool output.
 *
 * Known limitations (documented, not fixed here):
 *   - The derived-family list is maintained by hand (DERIVED_FROM in
 *     scripts/lib/fn-mine-generalization.ts). An unlisted derived corpus
 *     counts as an independent family.
 *   - The republished-sample key is the first 200 characters (sampleKey). A
 *     payload wrapped in new text by another corpus counts as new evidence.
 *   - Event types are assigned per corpus, not observed: the corpora are bare
 *     texts, so recall does not show that a channel property helps.
 *   - "0 of N" means none of those N texts, in that event type. It is not a
 *     deployment false-positive rate.
 */
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import yaml from 'js-yaml';
import { CORPORA, corpusById, type DeliveryShape } from './lib/fn-corpora.js';
import { readOutOfSample, readUserInputBenign } from './lib/fn-mine-generalization.js';
import { detectionsByRule } from './lib/fn-mine-input.js';
import { oosSource } from './lib/fn-mine-oos.js';
import { readToolOutputBenign } from './lib/fn-mine-tool-benign.js';
import {
  benignLines,
  excludedCorpora,
  familyRecall,
  meetsPilotBar,
  type BenignResult,
  type CorpusHits,
} from './lib/technique-harness.js';

const ROOT = resolve(import.meta.dirname, '..');

interface Corpus {
  readonly id: string;
  readonly shape: DeliveryShape;
  readonly texts: readonly string[];
}

function attackShape(id: string): DeliveryShape {
  return oosSource(id)?.shape ?? corpusById(id)?.eventShape ?? 'llm_input';
}

function readJsonlTexts(file: string): string[] {
  const out: string[] = [];
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    try {
      const rec = JSON.parse(line);
      const t = typeof rec === 'string' ? rec : (rec.text ?? rec.content);
      if (typeof t === 'string' && t) out.push(t);
    } catch {
      // A malformed line is skipped, as fn-mine's loader does.
    }
  }
  return out;
}

function hardNegativeShapes(): ReadonlyMap<string, DeliveryShape> {
  const manifest = JSON.parse(readFileSync(join(ROOT, 'data/fn-mine-oos/SOURCES.json'), 'utf8')) as {
    sources: readonly { id: string; shape: DeliveryShape }[];
  };
  return new Map(manifest.sources.map((s) => [s.id, s.shape]));
}

function benignCorpora(): Corpus[] {
  const out: Corpus[] = [];
  const ext = join(ROOT, 'data/benign-corpus-extended');
  for (const f of readdirSync(ext).filter((f) => f.endsWith('.jsonl')).sort()) {
    out.push({ id: `benign-corpus-extended/${basename(f, '.jsonl')}`, shape: 'llm_input', texts: readJsonlTexts(join(ext, f)) });
  }
  const shapes = hardNegativeShapes();
  const hn = join(ROOT, 'data/fn-mine-benign/hard-negatives');
  for (const id of readdirSync(hn).sort()) {
    const file = join(hn, id, 'corpus.json');
    if (!existsSync(file)) continue;
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { samples?: { text?: unknown }[] };
    const texts = (doc.samples ?? []).map((s) => s.text).filter((t): t is string => typeof t === 'string');
    out.push({ id: `hard-negatives/${id}`, shape: shapes.get(id) ?? 'llm_input', texts });
  }
  out.push({ id: 'user-input-business', shape: 'llm_input', texts: readUserInputBenign(ROOT) });
  const tool = readToolOutputBenign(ROOT);
  if ('problem' in tool) throw new Error(`benign tool-output corpora: ${tool.problem}`);
  for (const [name, texts] of Object.entries(tool.corpus)) {
    out.push({ id: `tool-output/${name}`, shape: 'tool_response', texts });
  }
  return out.filter((c) => c.texts.length > 0);
}

/** The rule in a rules directory of its own, so the harness evaluates nothing else. */
function stageRule(ruleFile: string): { dir: string; id: string } {
  const doc = yaml.load(readFileSync(ruleFile, 'utf8')) as { id?: unknown };
  if (typeof doc?.id !== 'string') throw new Error(`${ruleFile} has no rule id`);
  const dir = mkdtempSync(join(tmpdir(), 'technique-rule-'));
  mkdirSync(join(dir, 'candidate'));
  cpSync(ruleFile, join(dir, 'candidate', basename(ruleFile)));
  return { dir, id: doc.id };
}

async function hitsIn(dir: string, ruleId: string, c: Corpus): Promise<readonly string[]> {
  const byRule = await detectionsByRule(dir, c.texts, c.shape);
  return (byRule.get(ruleId) ?? []).map((i) => c.texts[i]);
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: { rule: { type: 'string' }, 'looked-at': { type: 'string' }, json: { type: 'boolean', default: false } },
  });
  if (!values.rule || values['looked-at'] === undefined) {
    process.stderr.write('usage: measure-technique-rule.ts --rule <rule.yaml> --looked-at <corpus,...|none> [--json]\n');
    process.exit(2);
  }
  const pool = readOutOfSample(ROOT);
  const known = new Set([...pool.map((c) => c.id), ...CORPORA.map((c) => c.id)]);
  const lookedAt = values['looked-at'] === 'none' ? [] : values['looked-at'].split(',').map((s) => s.trim()).filter(Boolean);
  const unknown = lookedAt.filter((id) => !known.has(id));
  if (unknown.length > 0) {
    process.stderr.write(`unknown corpus id(s) in --looked-at: ${unknown.join(', ')}\n`);
    process.exit(2);
  }

  const { dir, id } = stageRule(resolve(values.rule));
  try {
    const excluded = excludedCorpora(lookedAt);
    const attacks: CorpusHits[] = [];
    for (const c of pool) {
      if (excluded.has(c.id)) continue;
      const corpus = { id: c.id, shape: attackShape(c.id), texts: c.texts };
      attacks.push({ id: c.id, shape: corpus.shape, total: c.texts.length, hits: await hitsIn(dir, id, corpus) });
    }
    const lookedAtTexts = pool.filter((c) => lookedAt.includes(c.id)).flatMap((c) => c.texts);
    const recall = familyRecall(attacks, lookedAt, lookedAtTexts);
    const benign: BenignResult[] = [];
    for (const c of benignCorpora()) benign.push({ id: c.id, shape: c.shape, total: c.texts.length, hits: await hitsIn(dir, id, c) });
    const pass = meetsPilotBar(recall, benign);

    if (values.json) {
      const corpora = attacks.map((a) => ({ id: a.id, shape: a.shape, total: a.total, hits: a.hits.length }));
      const fp = benign.map((b) => ({ id: b.id, shape: b.shape, total: b.total, hits: b.hits.length }));
      process.stdout.write(`${JSON.stringify({ rule: id, lookedAt, recall, corpora, benign: fp, meetsPilotBar: pass }, null, 2)}\n`);
      return;
    }
    const lines = [
      `rule ${id}`,
      `looked at: ${lookedAt.join(', ') || 'none'}`,
      `not counted (looked at, and their derived families): ${recall.excluded.join(', ') || 'none'}`,
      `hits dropped as republished samples of a looked-at corpus: ${recall.droppedAsRepublished}`,
      '',
      'attack corpora (event type, hits of total):',
      ...attacks.map((a) => `  ${a.id} (${a.shape}): ${a.hits.length} of ${a.total}`),
      '',
      'recall by derived family (distinct hits):',
      ...(recall.families.length === 0
        ? ['  none']
        : recall.families.map((f) => `  ${f.family}: ${f.distinct}  ${JSON.stringify(f.corpora)}`)),
      '',
      'benign corpora (event type, hits of total):',
      ...benignLines(benign),
      '',
      `pilot bar (2+ families outside the excluded ones, 0 benign hits everywhere): ${pass ? 'met' : 'not met'}`,
    ];
    process.stdout.write(`${lines.join('\n')}\n`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  process.stderr.write(`${e instanceof Error ? e.message : String(e)}\n`);
  process.exit(1);
});
