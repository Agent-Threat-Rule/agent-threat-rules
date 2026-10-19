import { mkdirSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  loadManifest,
  rulesDirWithout,
  rulesNamingHackaPrompt,
  sha256File,
  verifyCorpusAgainstManifest,
} from '../src/eval/hackaprompt-provenance.js';

function fixture(): { root: string; rules: string } {
  const root = mkdtempSync(join(tmpdir(), 'hap-prov-test-'));
  const rules = join(root, 'rules');
  mkdirSync(join(rules, 'prompt-injection'), { recursive: true });
  writeFileSync(join(rules, 'prompt-injection', 'a.yaml'), 'id: ATR-2026-00001\ndescription: plain\n');
  writeFileSync(join(rules, 'prompt-injection', 'b.yaml'), 'id: "ATR-2026-00002"\ndescription: from the HackAPrompt corpus\n');
  writeFileSync(join(rules, 'prompt-injection', 'c.yaml'), "id: 'ATR-2026-00003'\ndescription: hackaprompt level 7\n");
  return { root, rules };
}

function manifestFor(corpusPath: string, samples: number) {
  return {
    dataset_id: 'hackaprompt/hackaprompt-dataset',
    dataset_revision: 'rev',
    split: 'train',
    rows_total: 10,
    selection: 'x',
    seed: 1,
    requested: samples,
    dropped_short_or_empty: 0,
    filter: 'x',
    samples,
    corpus_sha256: sha256File(corpusPath),
    sample_ids_sha256: 'ids',
    row_indices: Array.from({ length: samples }, (_, i) => i),
  };
}

describe('hackaprompt provenance', () => {
  it('finds rules whose YAML names HackAPrompt, case-insensitively', () => {
    const { rules } = fixture();
    expect(rulesNamingHackaPrompt(rules)).toEqual(['ATR-2026-00002', 'ATR-2026-00003']);
  });

  it('copies the rules tree without the excluded ids and leaves the source intact', () => {
    const { rules } = fixture();
    const { dir, removed } = rulesDirWithout(rules, ['ATR-2026-00002']);
    expect(removed).toEqual(['ATR-2026-00002']);
    expect(readdirSync(join(dir, 'prompt-injection')).sort()).toEqual(['a.yaml', 'c.yaml']);
    expect(readdirSync(join(rules, 'prompt-injection')).sort()).toEqual(['a.yaml', 'b.yaml', 'c.yaml']);
  });

  it('refuses to claim removal of a rule id that has no file', () => {
    const { rules } = fixture();
    expect(() => rulesDirWithout(rules, ['ATR-2026-09999'])).toThrow(/no rule file/);
  });

  it('accepts a corpus matching the manifest digest and rejects any other', () => {
    const { root } = fixture();
    const corpus = join(root, 'corpus.json');
    writeFileSync(corpus, '[{"id":"hap-0000001"}]');
    const manifestPath = join(root, 'manifest.json');
    writeFileSync(manifestPath, JSON.stringify(manifestFor(corpus, 1)));
    const manifest = loadManifest(manifestPath);
    expect(verifyCorpusAgainstManifest(corpus, manifest)).toBe(manifest.corpus_sha256);
    writeFileSync(corpus, '[{"id":"hap-0000002"}]');
    expect(() => verifyCorpusAgainstManifest(corpus, manifest)).toThrow(/manifest expects/);
  });

  it('rejects a manifest whose row indices do not match its sample count', () => {
    const { root } = fixture();
    const corpus = join(root, 'corpus.json');
    writeFileSync(corpus, '[]');
    const manifestPath = join(root, 'manifest.json');
    writeFileSync(manifestPath, JSON.stringify({ ...manifestFor(corpus, 2), row_indices: [0] }));
    expect(() => loadManifest(manifestPath)).toThrow(/row_indices/);
  });

  it('the committed manifest pins the published 4,780-sample set', () => {
    const m = loadManifest(join(import.meta.dirname, '..', 'data', 'hackaprompt', 'hackaprompt-corpus.manifest.json'));
    expect(m.dataset_revision).toBe('25b87fbedfb86840abaf8cd09af7a029208a971a');
    expect(m.samples).toBe(4780);
    expect(m.seed).toBe(20260511);
    expect(m.corpus_sha256).toBe('e7c3886d320e0c28f4569d06e544f2589bc58a5f7edd8c3e8d0a3707d1596364');
  });
});
