/**
 * The digest must mean what the engine means, on the path it is used.
 *
 * A consumer like PyRIT's RegexScorer applies every pattern it is given to one
 * string, with no field routing and no engine. The digest therefore carries the
 * field each condition was written against, and names in `default_fields` the
 * scope a consumer scoring an agent's text output should select. Selecting
 * everything instead flags 21.7% of ordinary conversation with no severity
 * floor, or 7.5% at a medium floor, where the engine flags 0.7%; most of the
 * difference between those two is one low-severity rule whose conditions name
 * tool_name and tool_args.
 *
 * These assertions exist because each of those failures is silent: a digest
 * selected wrongly still loads, still compiles, and still returns matches.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { needsUnicodeFlag } from '../src/engine.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIGEST = join(ROOT, 'data/pyrit-digest.json');
const INLINE_FLAGS = /^\(\?[imsx]+\)/;

/** The levels a consumer can rank; anything else is unrankable and drops. */
const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);

interface Condition {
  readonly rule_id: string;
  readonly field: string;
  readonly pattern: string;
  readonly category: string;
  readonly severity: string;
  readonly case_sensitive?: true;
}

interface Digest {
  readonly schema: number;
  readonly atr_version: string;
  readonly atr_commit: string;
  readonly default_fields: readonly string[];
  readonly rules_seen: number;
  readonly rules_emitted: number;
  readonly rules_in_default_fields: number;
  readonly condition_count: number;
  readonly conditions_by_field: Record<string, number>;
  readonly conditions: Record<string, Condition>;
  readonly excluded: Record<string, string>;
}

describe('the PyRIT digest', () => {
  const d: Digest = JSON.parse(readFileSync(DIGEST, 'utf-8'));
  const entries = Object.entries(d.conditions);

  it('exists and carries the bulk of the rule set', () => {
    expect(existsSync(DIGEST)).toBe(true);
    expect(d.schema).toBe(1);
    expect(entries).toHaveLength(d.condition_count);
    expect(d.condition_count).toBeGreaterThan(2000);
    // A large drop here means something upstream stopped emitting, not that the
    // rule set got smaller.
    expect(d.rules_emitted).toBeGreaterThan(d.rules_seen * 0.9);
  });

  it('gives every condition the field it was written against', () => {
    const fieldless = entries.filter(([, c]) => !c.field).map(([k]) => k);
    expect(fieldless, 'conditions with no field cannot be routed or selected').toEqual([]);
    const counted = Object.values(d.conditions_by_field).reduce((a, b) => a + b, 0);
    expect(counted).toBe(d.condition_count);
  });

  it('declares a default scope that is a real narrowing, not the whole file', () => {
    // If default_fields covered every field, selecting it would be a no-op and
    // the 21.7% failure would be back with these tests still green.
    expect(d.default_fields.length).toBeGreaterThan(0);
    for (const f of d.default_fields) expect(Object.keys(d.conditions_by_field)).toContain(f);
    const scope = new Set(d.default_fields);
    const selected = entries.filter(([, c]) => scope.has(c.field));
    expect(selected.length).toBeGreaterThan(0);
    expect(selected.length).toBeLessThan(d.condition_count);
    expect(new Set(selected.map(([, c]) => c.rule_id)).size).toBe(d.rules_in_default_fields);
  });

  it('leaves no pattern whose case behaviour is unattributable', () => {
    // A consumer calls re.compile(pattern) with no flags, so a pattern that
    // expected the engine's default folding would quietly become
    // case-sensitive. Every pattern must therefore either carry an inline flag
    // or be marked as having opted out.
    const ambiguous = entries
      .filter(([, c]) => !INLINE_FLAGS.test(c.pattern) && !c.case_sensitive)
      .map(([k]) => k);
    expect(ambiguous, 'patterns with neither an inline flag nor a case_sensitive marker').toEqual(
      [],
    );
  });

  it('every pattern compiles as JavaScript under the flags the engine would pick', () => {
    // needsUnicodeFlag, not a blanket 'iu'. Forcing u on every pattern is
    // stricter than the engine and rejects patterns it accepts, because u-mode
    // disallows identity escapes that are legal without it. The assertion is
    // that the digest compiles the way the engine compiles it.
    const broken: string[] = [];
    for (const [name, c] of entries) {
      const body = c.pattern.replace(INLINE_FLAGS, '');
      const flags = needsUnicodeFlag(body) ? 'iu' : 'i';
      try {
        new RegExp(body, flags);
      } catch {
        broken.push(name);
      }
    }
    expect(broken).toEqual([]);
  });

  it('gives every condition a severity a consumer can rank', () => {
    // A minimum-severity filter compares against a fixed ladder and treats
    // anything unknown as the floor, so an unexpected string silently removes
    // the rule rather than failing.
    const unrankable = entries
      .filter(([, c]) => !SEVERITIES.has(c.severity))
      .map(([k, c]) => `${k}=${c.severity}`);
    expect(unrankable).toEqual([]);
  });

  it('records why anything was left out instead of dropping it silently', () => {
    for (const [key, reason] of Object.entries(d.excluded)) {
      expect(reason, `${key} excluded with no reason`).toBeTruthy();
      expect(reason.length).toBeGreaterThan(10);
    }
  });

  it('is stamped with the version and commit it was built from', () => {
    expect(d.atr_version).toMatch(/^\d+\.\d+\.\d+/);
    expect(d.atr_commit).toMatch(/^[0-9a-f]{7,40}$/);
  });
});
