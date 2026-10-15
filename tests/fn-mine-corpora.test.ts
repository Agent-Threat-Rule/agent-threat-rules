/**
 * Tests for scripts/lib/fn-mine-corpora.ts and the corpora it mines.
 *
 * HackAPrompt and PINT were exhausted: the lane's last run on them proposed 40
 * candidates and none recovered 8 misses. LLMail-Inject and BrowseSafe-Bench
 * were vendored to replace them (scripts/sync-agent-attack-corpora.ts). These
 * tests pin what the miner reads from them: the registry entries, the shape
 * their samples reach an agent as, and how much model time each may cost.
 */
import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { CORPORA, corpusById } from '../scripts/lib/fn-corpora.js';
import {
  MINED_CORPORA,
  channelNote,
  falseNegatives,
  planChunks,
  unseenFirst,
  vendoredProblem,
  type VendoredCorpusSpec,
} from '../scripts/lib/fn-mine-corpora.js';
import { hasBenchmarkArtifacts } from '../scripts/lib/fn-mine-quality.js';

const REPO_ROOT = resolve(__dirname, '..');
const AGENT_CORPORA = ['llmail-inject', 'browsesafe-bench'];

describe('registry entries for the vendored agent corpora', () => {
  for (const id of AGENT_CORPORA) {
    it(`${id} is a usable, labelled prompt-channel corpus delivered as tool output`, () => {
      const def = corpusById(id);
      expect(def).toBeDefined();
      expect(def?.channel).toBe('prompt');
      expect(def?.eventShape).toBe('tool_response');
      expect(def?.usable).toBe(true);
      expect(def?.labelled).toBe(true);
      expect(def?.note).toMatch(/OUTPUT/);
    });

    it(`${id} loads attack samples with ids, text and the upstream family`, () => {
      const samples = corpusById(id)?.load(REPO_ROOT) ?? [];
      expect(samples.length).toBeGreaterThan(500);
      expect(samples.length).toBeLessThanOrEqual(3000);
      expect(new Set(samples.map((s) => s.label))).toEqual(new Set(['attack']));
      expect(new Set(samples.map((s) => s.id)).size).toBe(samples.length);
      for (const s of samples) expect(s.text.length).toBeGreaterThanOrEqual(12);
    });
  }

  it('LLMail families are phase/level, so the sample is visibly spread across the grid', () => {
    const families = new Set((corpusById('llmail-inject')?.load(REPO_ROOT) ?? []).map((s) => s.family));
    for (const f of families) expect(f).toMatch(/^phase[12]\/level[1-4][a-v]$/);
    expect([...families].filter((f) => f.startsWith('phase2')).length).toBeGreaterThan(0);
    expect(new Set([...families].map((f) => f.slice(7, 13)))).toEqual(new Set(['level1', 'level2', 'level3', 'level4']));
  });

  it('leaves every corpus registered before it on the default llm_input shape', () => {
    const others = CORPORA.filter((c) => !AGENT_CORPORA.includes(c.id));
    expect(others.every((c) => c.eventShape === undefined)).toBe(true);
  });
});

describe('MINED_CORPORA', () => {
  it('mines HackAPrompt and PINT from their reports as user input, and the agent corpora as tool output', () => {
    expect(MINED_CORPORA.map((s) => [s.name, s.kind, s.shape])).toEqual([
      ['hackaprompt', 'report', 'llm_input'],
      ['pint', 'report', 'llm_input'],
      ['llmail-inject', 'vendored', 'tool_response'],
      ['browsesafe-bench', 'vendored', 'tool_response'],
    ]);
  });

  it('points each vendored spec at a usable registry entry with the same shape', () => {
    for (const spec of MINED_CORPORA.filter((s): s is VendoredCorpusSpec => s.kind === 'vendored')) {
      const def = corpusById(spec.registryId);
      expect(def?.usable, spec.name).toBe(true);
      expect(def?.eventShape, spec.name).toBe(spec.shape);
      expect(vendoredProblem(spec, REPO_ROOT), spec.name).toBeNull();
    }
  });

  // Each chunk is one model call; round 1 and the residual round each take at
  // most maxChunksPerRound, so a run costs at most 6 mining calls per corpus.
  it('bounds model cost: at most 3 chunks a round, and a prompt no larger than the original 300 x 300', () => {
    for (const { name, budget } of MINED_CORPORA) {
      expect(budget.maxChunksPerRound, name).toBeLessThanOrEqual(3);
      expect(budget.chunkSize * budget.promptChars, name).toBeLessThanOrEqual(90_000);
    }
  });

  it('tells the model the scoring strings of every benchmark whose artifacts the gate removes', () => {
    for (const spec of MINED_CORPORA.filter((s) => s.kind === 'vendored')) {
      expect(hasBenchmarkArtifacts(spec.name), spec.name).toBe(true);
      expect(spec.goalNote, spec.name).toBeTruthy();
    }
  });
});

describe('planChunks', () => {
  const budget = { chunkSize: 2, promptChars: 10, maxChunksPerRound: 2 };

  it('stops at the cap and labels each chunk by its slice', () => {
    expect(planChunks('x', ['a', 'b', 'c', 'd', 'e'], budget)).toEqual([
      { label: 'x[0:2]', texts: ['a', 'b'] },
      { label: 'x[2:4]', texts: ['c', 'd'] },
    ]);
  });

  it('plans nothing for nothing', () => {
    expect(planChunks('x', [], budget)).toEqual([]);
  });
});

// The residual round re-planned from index 0: with no survivor in round 1 (the
// usual week) it re-sent round 1's chunks verbatim, and the FNs past the cap
// were never shown to the model in any run.
describe('unseenFirst', () => {
  const budget = { chunkSize: 2, promptChars: 10, maxChunksPerRound: 2 };
  const fn = ['a', 'b', 'c', 'd', 'e', 'f', 'g'];

  it('shows the residual round what round 1 could not, before what it already saw', () => {
    const shown = planChunks('x', fn, budget).flatMap((c) => c.texts);
    const residual = planChunks('x-residual', unseenFirst(fn, shown), budget).flatMap((c) => c.texts);
    expect(residual).toEqual(['e', 'f', 'g', 'a']);
    expect(new Set([...shown, ...residual])).toEqual(new Set(fn));
  });

  it('keeps the order within each group and drops nothing', () => {
    expect(unseenFirst(['a', 'b', 'c', 'd'], ['b', 'd'])).toEqual(['a', 'c', 'b', 'd']);
    expect(unseenFirst(['a', 'b'], [])).toEqual(['a', 'b']);
  });
});

describe('channelNote', () => {
  it('names the tool output as the channel for tool_response corpora', () => {
    expect(channelNote('tool_response')).toMatch(/TOOL's OUTPUT/);
    expect(channelNote('llm_input')).toMatch(/user's prompt/);
  });
});

describe('falseNegatives for a vendored corpus', () => {
  const tmp: string[] = [];
  afterEach(() => {
    for (const d of tmp.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  const RULE = (id: string, value: string) =>
    [
      `title: "fixture ${id}"`, `id: ${id}`, 'status: experimental', 'maturity: test', 'severity: high',
      'tags:', '  category: prompt-injection', '  confidence: high', 'agent_source:', '  type: llm_io',
      'detection:', '  conditions:', '    - field: user_input', '      operator: regex', `      value: ${value}`,
      '  condition: any', 'response:', '  actions: [alert]', '',
    ].join('\n');

  function fixtureRoot(texts: readonly string[]): string {
    const root = mkdtempSync(join(tmpdir(), 'fn-mine-corpora-'));
    tmp.push(root);
    mkdirSync(join(root, 'data/test-corpora/llmail-inject'), { recursive: true });
    const attacks = texts.map((text) => ({ text, label: 'attack', attack_family: 'phase1/level1a' }));
    writeFileSync(join(root, 'data/test-corpora/llmail-inject/corpus.json'), JSON.stringify({ attacks }));
    mkdirSync(join(root, 'rules/prompt-injection'), { recursive: true });
    writeFileSync(join(root, 'rules/prompt-injection/control.yaml'), RULE('ATR-2026-90101', '"(?i)ignore\\\\s+all\\\\s+previous\\\\s+instructions"'));
    writeFileSync(join(root, 'rules/prompt-injection/known.yaml'), RULE('ATR-2026-90102', '"(?i)known\\\\s+trick"'));
    return root;
  }

  it('is what the live rules miss on the tool-response event, logged with the shape', async () => {
    const root = fixtureRoot(['a known trick in an email body', 'a new trick nobody detects yet']);
    const spec = MINED_CORPORA.find((s) => s.name === 'llmail-inject');
    const lines: string[] = [];
    const fn = await falseNegatives(spec!, root, (l) => lines.push(l));
    expect(fn).toEqual(['a new trick nobody detects yet']);
    expect(lines.join('\n')).toMatch(/2 attacks presented as tool_response, 1 missed/);
  });

  // A truncated or emptied corpus.json loaded as 0 attacks, reported 0 FN, and
  // the run ended as a green "nothing to mine".
  it('reports a corpus that is not valid JSON, holds no attacks, or disagrees with its count', () => {
    const spec = MINED_CORPORA.find((s): s is VendoredCorpusSpec => s.name === 'llmail-inject');
    const root = fixtureRoot(['a new trick nobody detects yet']);
    const file = join(root, 'data/test-corpora/llmail-inject/corpus.json');
    expect(vendoredProblem(spec!, root)).toBeNull();
    writeFileSync(file, '{"attacks": [');
    expect(vendoredProblem(spec!, root)).toMatch(/not valid JSON/);
    writeFileSync(file, JSON.stringify({ count: 0, attacks: [] }));
    expect(vendoredProblem(spec!, root)).toMatch(/no attack/);
    writeFileSync(file, JSON.stringify({ count: 2, attacks: [{ text: 'a new trick nobody detects yet', label: 'attack' }] }));
    expect(vendoredProblem(spec!, root)).toMatch(/declares 2.*1/);
  });

  it('reports a corpus missing from disk instead of mining nothing quietly', () => {
    const spec = MINED_CORPORA.find((s): s is VendoredCorpusSpec => s.kind === 'vendored');
    const empty = mkdtempSync(join(tmpdir(), 'fn-mine-empty-'));
    tmp.push(empty);
    expect(vendoredProblem(spec!, empty)).toMatch(/missing/);
  });
});
