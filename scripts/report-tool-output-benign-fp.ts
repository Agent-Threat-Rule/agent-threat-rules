#!/usr/bin/env npx tsx
/**
 * report-tool-output-benign-fp.ts
 *
 * Informational, NOT a gate: runs every rule under rules/ against the benign
 * tool-output corpora the FN-mine gate uses (data/fn-mine-benign: real emails
 * and benign web pages), each presented to the engine as tool_response exactly
 * as the FN-mine lane presents LLMail and BrowseSafe, and writes how many rules
 * fire on how many samples, with the worst offenders, to
 * data/fn-mining/tool-output-benign-fp-report.json.
 *
 * These corpora gate the FN-mine lane's new candidates only. Whether the rules
 * already on main should be held to them too (a repo-wide gate, baseline or
 * threshold) is a separate decision; this report is its input. The engine runs
 * as in production: default lane, draft rules skipped.
 *
 * Usage:
 *   npx tsx scripts/report-tool-output-benign-fp.ts [--top 15] [--out <file>]
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { parseArgs } from 'node:util';
import { loadRulesFromDirectory } from '../src/loader.js';
import { detectionsByRule } from './lib/fn-mine-input.js';
import { readToolOutputBenign } from './lib/fn-mine-tool-benign.js';
import { BENIGN_EMAILS, BENIGN_PAGES } from './lib/tool-output-benign.js';
import { corpusFpSection, ruleInfo, summaryLine, type CorpusFpSection, type RuleInfo } from './lib/tool-output-fp-report.js';

const REPO_ROOT = process.cwd();
const DEFAULT_OUT = 'data/fn-mining/tool-output-benign-fp-report.json';

function commit(): string {
  try {
    return execFileSync('git', ['rev-parse', '--short', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

async function section(name: string, texts: readonly string[], rules: ReadonlyMap<string, RuleInfo>, top: number): Promise<CorpusFpSection> {
  console.log(`[tool-output-benign-fp] ${name}: ${texts.length} samples through every rule...`);
  const hits = await detectionsByRule(join(REPO_ROOT, 'rules'), texts, 'tool_response');
  return corpusFpSection(name, texts, hits, rules, top);
}

async function main(): Promise<void> {
  const { values } = parseArgs({ options: { top: { type: 'string', default: '15' }, out: { type: 'string', default: DEFAULT_OUT } } });
  const top = parseInt(values.top as string, 10);
  const read = readToolOutputBenign(REPO_ROOT);
  if ('problem' in read) throw new Error(read.problem);
  const loaded = loadRulesFromDirectory(join(REPO_ROOT, 'rules'));
  const rules = new Map(loaded.map((r) => [r.id, ruleInfo(r)]));
  const sections = [
    await section('emails', read.corpus.emails, rules, top),
    await section('pages', read.corpus.pages, rules, top),
  ];
  const report = {
    note:
      'Informational, not a gate. Every rule under rules/ (drafts skipped, default lane, as in production) run on ' +
      'benign emails and web pages presented as tool_response. These corpora gate FN-mine candidates only. ' +
      'BrowseSafe labels a page benign when it holds no injection; its benign pages still carry the phishing-style ' +
      'banners ("ACTION REQUIRED: ...") the benchmark plants as distractors, so a hit on a page may be a hit on one.',
    atr_commit: commit(),
    measured_at: new Date().toISOString(),
    rules_on_disk: loaded.length,
    shape: 'tool_response',
    corpora: { emails: `${BENIGN_EMAILS.path}@${BENIGN_EMAILS.revision}`, pages: `${BENIGN_PAGES.path}@${BENIGN_PAGES.revision}` },
    sections,
  };
  const out = join(REPO_ROOT, values.out as string);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);
  console.log(summaryLine(loaded.length, sections));
  console.log(`[tool-output-benign-fp] wrote ${values.out}`);
}

main().catch((err) => {
  console.error(`[tool-output-benign-fp] FATAL: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
