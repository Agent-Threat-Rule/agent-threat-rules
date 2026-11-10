#!/usr/bin/env -S npx tsx
/**
 * scripts/fn-mine-generalization-check.ts
 *
 * Re-runs the FN-mine generalization gates (scripts/lib/fn-mine-generalization.ts)
 * and the tool-output benign gate (scripts/lib/fn-mine-tool-benign.ts) on rules
 * that are already written, for a reviewer: what the lane would decide about
 * them today. Each regex condition is judged on its own, against the attacks it
 * matches in the corpus it was mined from.
 *
 *   npx tsx scripts/fn-mine-generalization-check.ts --corpus nemotron-agentic-ipi rules/x.yaml [...]
 *
 * Prints one verdict per rule and exits 1 when any fails, so it can gate a PR.
 */
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import yaml from 'js-yaml';
import { CORPORA } from './lib/fn-corpora.js';
import { compileEngineAccurate } from './lib/fn-mine-candidate-gate.js';
import { generalizationVerdict, readOutOfSample, readUserInputBenign } from './lib/fn-mine-generalization.js';
import { oosSource, readOosTexts } from './lib/fn-mine-oos.js';
import { requireToolOutputBenign, toolOutputVerdicts } from './lib/fn-mine-tool-benign.js';
import { MINED_CORPORA } from './lib/fn-mine-corpora.js';

interface RuleRegex {
  readonly file: string;
  readonly id: string;
  readonly regex: string;
}

function ruleRegexes(file: string): RuleRegex[] {
  const doc = yaml.load(readFileSync(file, 'utf8')) as {
    id?: string;
    detection?: { conditions?: { operator?: string; value?: string }[] };
  };
  return (doc.detection?.conditions ?? [])
    .filter((c) => c.operator === 'regex' && typeof c.value === 'string')
    .map((c) => ({ file, id: String(doc.id), regex: c.value as string }));
}

/** The attacks of a registry corpus or of a vendored out-of-sample corpus. */
function corpusAttacks(root: string, corpusId: string): readonly string[] {
  const def = CORPORA.find((c) => c.id === corpusId);
  if (def) return def.load(root).filter((s) => s.label === 'attack').map((s) => s.text);
  const source = oosSource(corpusId);
  if (!source) throw new Error(`unknown corpus ${corpusId}`);
  const read = readOosTexts(root, source);
  if ('problem' in read) throw new Error(read.problem);
  return read.texts;
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({ allowPositionals: true, options: { corpus: { type: 'string' } } });
  const corpusId = values.corpus;
  if (!corpusId || positionals.length === 0) {
    throw new Error('usage: fn-mine-generalization-check.ts --corpus <mined corpus id> <rule.yaml> [...]');
  }
  const root = process.cwd();
  const attacks = corpusAttacks(root, corpusId);
  const shape = MINED_CORPORA.find((c) => c.name === corpusId)?.shape ?? 'llm_input';
  const userBenign = shape === 'llm_input' ? readUserInputBenign(root) : [];
  const oos = readOutOfSample(root);
  const benign = requireToolOutputBenign(root);
  const regexes = positionals.flatMap(ruleRegexes);
  const benignVerdicts = await toolOutputVerdicts(
    regexes.map((r) => {
      const re = compileEngineAccurate(r.regex);
      return { regex: r.regex, own: re ? attacks.filter((t) => re.test(t)).slice(0, 20) : [] };
    }),
    benign,
  );

  let failed = 0;
  regexes.forEach((r, i) => {
    const re = compileEngineAccurate(r.regex);
    const recovered = re ? attacks.filter((t) => re.test(t)) : [];
    const v = generalizationVerdict({ regex: r.regex, recovered, minedFrom: corpusId, shape }, oos);
    const b = benignVerdicts[i];
    const failures: Record<string, string> = { ...v.failures };
    if (b && b.benignHits > 0) failures['tool-output-benign'] = `fires on ${b.benignHits} benign tool output(s), first: ${b.firstHit}`;
    const userHits = re ? userBenign.filter((t) => re.test(t)) : [];
    if (userHits.length > 0) {
      failures['user-input-benign'] = `fires on ${userHits.length} benign user request(s), first: ${JSON.stringify(userHits[0])}`;
    }
    const pass = Object.keys(failures).length === 0;
    if (!pass) failed += 1;
    console.log(`${pass ? 'PASS' : 'FAIL'} ${r.id} (${r.file}): recovers ${recovered.length} in ${corpusId}, out of sample ${JSON.stringify(v.outOfSample)}`);
    for (const [gate, why] of Object.entries(failures)) console.log(`  ${gate}: ${why}`);
  });
  console.log(`${regexes.length - failed} of ${regexes.length} regex condition(s) pass.`);
  if (failed > 0) process.exitCode = 1;
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});
