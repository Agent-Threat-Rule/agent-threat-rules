/**
 * The ablation reference (breakdown.in_sample_ablation[reference]) travels with
 * the headline: root stats.json must cite it at the recorded values, so a
 * re-measurement cannot leave it stale.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseAblationReference } from '../src/measurement/in-sample-ablation.js';
import { ablationBySource, findAblationCitationProblems } from '../scripts/check-benchmark-citations.js';

const REPO = join(import.meta.dirname, '..');

const lane = (detected: number, attacks = 4780) => ({ lane: 'x', detected, attacks, recall: detected / attacks });
const breakdown = {
  in_sample_ablation: {
    note: 'n',
    reference: 'without_rules_naming_source',
    without_rules_naming_source: {
      description: 'd',
      removed_rule_ids: ['ATR-2026-00001', 'ATR-2026-00002'],
      lanes: { hunt: lane(1372), enforce: lane(32) },
    },
  },
};

describe('parseAblationReference', () => {
  it('reads the cited ablation', () => {
    const a = parseAblationReference(breakdown)!;
    expect(a.key).toBe('without_rules_naming_source');
    expect(a.removed_rule_ids).toHaveLength(2);
    expect(a.hunt.detected).toBe(1372);
    expect(a.enforce.recall).toBeCloseTo(32 / 4780);
  });

  it('returns null when none is recorded and throws on a malformed record', () => {
    expect(parseAblationReference({})).toBeNull();
    expect(() => parseAblationReference({ in_sample_ablation: { note: 'x' } })).toThrow(/reference/);
    const bad = structuredClone(breakdown);
    bad.in_sample_ablation.without_rules_naming_source.lanes.hunt.recall = 0.9;
    expect(() => parseAblationReference(bad)).toThrow(/malformed/);
  });
});

describe('findAblationCitationProblems', () => {
  const ablations = new Map([['hackaprompt', parseAblationReference(breakdown)!]]);
  const enforce = new Map([['hackaprompt', 0.4901673640167364]]);
  const cite = (over: Record<string, unknown> = {}) => ({
    benchmarks: {
      hackaprompt: {
        enforceLaneRecall: 49,
        recallWithoutSourceNamedRules: { hunt: 28.7, enforce: 0.7, rulesRemoved: 2, measurementKey: 'without_rules_naming_source', ...over },
      },
    },
  });

  it('passes when stats.json cites the recorded ablation and enforce lane', () => {
    expect(findAblationCitationProblems(cite(), ablations, enforce)).toEqual([]);
  });

  it('fails on a stale or missing ablation figure, and on a stale enforce figure', () => {
    expect(findAblationCitationProblems(cite({ hunt: 30 }), ablations, enforce).join('\n')).toMatch(/hunt = 30/);
    expect(findAblationCitationProblems(cite({ rulesRemoved: 20 }), ablations, enforce).join('\n')).toMatch(/rulesRemoved/);
    expect(findAblationCitationProblems({ benchmarks: { hackaprompt: { enforceLaneRecall: 49 } } }, ablations, enforce).join('\n')).toMatch(/omits/);
    expect(findAblationCitationProblems({ benchmarks: { hackaprompt: { ...cite().benchmarks.hackaprompt, enforceLaneRecall: 48 } } }, ablations, enforce).join('\n')).toMatch(/enforceLaneRecall = 48/);
  });

  it('fails when stats.json cites an ablation no measurement records', () => {
    expect(findAblationCitationProblems(cite(), new Map(), enforce).join('\n')).toMatch(/records no breakdown.in_sample_ablation/);
  });

  it('the committed root stats.json matches the committed HackAPrompt measurement', () => {
    const data = JSON.parse(readFileSync(join(REPO, 'data', 'stats.json'), 'utf-8')) as { benchmarks: { source: string; measurement_file: string }[] };
    const root = JSON.parse(readFileSync(join(REPO, 'stats.json'), 'utf-8'));
    const recorded = ablationBySource(REPO, data.benchmarks);
    expect(recorded.get('hackaprompt')?.key).toBe('without_rules_naming_source');
    expect(findAblationCitationProblems(root, recorded, new Map())).toEqual([]);
    expect(root.benchmarks.hackaprompt.precision).toBeNull();
  });
});
