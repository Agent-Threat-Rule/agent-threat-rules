/**
 * Tests for the out-of-sample attack corpora and the business-API benign text
 * vendored by scripts/sync-oos-corpora.py.
 *
 * Why they exist: after PR #824 every FN-mine candidate must recover an attack
 * outside the corpus it was mined from. The eight LLMail rules on main
 * recovered none, including the forged chat-template turn rule
 * (ATR-2026-02862), because no other vendored corpus carried that technique.
 * The benign enterprise corpus was mostly JSON records, so a regex on the
 * action an injection asks for ("delete user", "send email") had little prose
 * to fire on.
 */
import { describe, it, expect } from 'vitest';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import yaml from 'js-yaml';
import { OOS_CORPORA, outOfSampleRecoveries, readOutOfSample } from '../scripts/lib/fn-mine-generalization.js';
import { BENIGN_API_DOCS, BENIGN_ENTERPRISE, readToolOutputBenign } from '../scripts/lib/fn-mine-tool-benign.js';
import { compileEngineAccurate } from '../scripts/lib/fn-mine-candidate-gate.js';

const REPO_ROOT = resolve(__dirname, '..');
const ADDED = ['spikee', 'asb', 'bipia', 'gentel', 'gandalf', 'mosscap', 'deepset', 'jailbreak-cls'];
const PII = /[\w.+-]+@[\w-]+\.[a-z]{2,}|\+?\d[\d\s().-]{8,}\d/i;

interface Doc {
  readonly count: number;
  readonly samples: readonly { readonly text: string; readonly source?: string; readonly attack?: string }[];
}
const load = (rel: string): Doc => JSON.parse(readFileSync(join(REPO_ROOT, rel), 'utf8')) as Doc;

describe('out-of-sample corpora from sync-oos-corpora.py', () => {
  it('registers every added corpus with the gate', () => {
    const ids = OOS_CORPORA.map((c) => c.id);
    for (const id of ADDED) expect(ids).toContain(id);
    const pool = readOutOfSample(REPO_ROOT).map((c) => c.id);
    for (const id of ADDED) expect(pool).toContain(id);
  });

  it.each(ADDED)('%s: count matches, provenance and license ship with it, no contact details', (id) => {
    const entry = OOS_CORPORA.find((c) => c.id === id);
    expect(entry).toBeDefined();
    const dir = dirname(join(REPO_ROOT, entry!.path));
    const doc = load(entry!.path);
    expect(doc.samples.length).toBeGreaterThan(0);
    expect(doc.count).toBe(doc.samples.length);
    expect(existsSync(join(dir, 'SOURCE.md'))).toBe(true);
    expect(readdirSync(dir).some((f) => f.startsWith('LICENSE'))).toBe(true);
    for (const s of doc.samples) {
      expect(typeof s.text).toBe('string');
      expect(PII.test(s.text)).toBe(false);
    }
  });

  it('gives the forged chat-template turn rule its first evidence outside LLMail', () => {
    const rule = yaml.load(
      readFileSync(join(REPO_ROOT, 'rules/prompt-injection/ATR-2026-02862-fake-chat-template-turn-injection.yaml'), 'utf8'),
    ) as { detection: { conditions: { operator: string; value: string }[] } };
    const regex = rule.detection.conditions.find((c) => c.operator === 'regex')!.value;
    const hits = outOfSampleRecoveries(regex, readOutOfSample(REPO_ROOT), 'llmail-inject');
    expect(hits.mosscap ?? 0).toBeGreaterThan(0);
  });

  it('keeps the rare forged-boundary and role-tag prompts from Mosscap before plain overrides', () => {
    const doc = load('data/fn-mine-oos/mosscap/corpus.json');
    const boundary = doc.samples.filter((s) => s.attack === 'forged-boundary-or-role').length;
    expect(boundary).toBeGreaterThan(500);
  });
});

describe('business API documentation as benign tool output', () => {
  it('is read with the enterprise outputs', () => {
    const r = readToolOutputBenign(REPO_ROOT);
    expect('corpus' in r).toBe(true);
    if (!('corpus' in r)) return;
    const enterpriseOnly = load(BENIGN_ENTERPRISE.path).count;
    const apiDocs = load(BENIGN_API_DOCS.path).count;
    expect(apiDocs).toBeGreaterThan(1000);
    expect(r.corpus.enterprise.length).toBe(enterpriseOnly + apiDocs);
  });

  it('holds the action wording a request-only regex keys on, which the JSON records lack', () => {
    const regex = '(?i)\\b(delete|remove|terminate)s?\\b[\\s\\S]{0,30}\\b(employee|user|member|account)\\b';
    const re = compileEngineAccurate(regex)!;
    const api = load(BENIGN_API_DOCS.path).samples.filter((s) => re.test(s.text)).length;
    const records = load(BENIGN_ENTERPRISE.path).samples.filter((s) => re.test(s.text)).length;
    expect(api).toBeGreaterThan(0);
    expect(records).toBe(0);
  });

  it('has no contact details', () => {
    for (const s of load(BENIGN_API_DOCS.path).samples) expect(PII.test(s.text)).toBe(false);
  });
});
