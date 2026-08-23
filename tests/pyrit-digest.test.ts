/**
 * The digest must mean what the engine means, on the path it is used.
 *
 * PyRIT's RegexScorer applies every pattern it is given to one string, with no
 * field routing and no engine. That is fine only because the digest is scoped at
 * emission: it carries the conditions written against agent_output and content,
 * and nothing else. Without that scoping the same consumer flagged 23.5% of
 * ordinary conversation where the engine flags 0.8%, and 122 of the 141 extra
 * matches came from one rule whose conditions name tool_name and tool_args.
 *
 * These assertions exist because that failure is silent: an unscoped digest
 * still loads, still compiles, and still returns matches.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { needsUnicodeFlag } from '../src/engine.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DIGEST = join(ROOT, 'data/pyrit-digest.json');

interface Digest {
  readonly atr_version: string;
  readonly atr_commit: string;
  readonly fields_in_scope: readonly string[];
  readonly pattern_count: number;
  readonly patterns: Record<string, string>;
  readonly meta: Record<string, { rule_id: string; field: string }>;
  readonly excluded: Record<string, string>;
}

describe('the PyRIT digest', () => {
  const d: Digest = JSON.parse(readFileSync(DIGEST, 'utf-8'));

  it('exists and is not empty', () => {
    expect(existsSync(DIGEST)).toBe(true);
    expect(d.pattern_count).toBeGreaterThan(500);
    expect(Object.keys(d.patterns)).toHaveLength(d.pattern_count);
  });

  it('carries only fields a response-scoring consumer can present', () => {
    // The load-bearing property. A tool_args condition applied to prose is the
    // 23.5% failure described above.
    const scope = new Set(d.fields_in_scope);
    const strays = Object.entries(d.meta)
      .filter(([, m]) => !scope.has(m.field))
      .map(([k, m]) => `${k} (${m.field})`);
    expect(strays, 'patterns whose field is outside the declared scope').toEqual([]);
  });

  it('bakes case-insensitivity into each pattern rather than relying on flags', () => {
    // RegexScorer calls re.compile(pattern) with no flags. A pattern that
    // expected the engine's default would quietly become case-sensitive.
    const bare = Object.entries(d.patterns)
      .filter(([, p]) => !/^\(\?[imsx]+\)/.test(p))
      .map(([k]) => k);
    // Some conditions genuinely opt out via case_sensitive; those are the only
    // ones allowed to arrive without an inline flag.
    expect(bare.length, `patterns with no inline flags: ${bare.slice(0, 5).join(', ')}`).toBeLessThan(
      Math.ceil(d.pattern_count * 0.02),
    );
  });

  it('every pattern compiles as JavaScript under the flags the engine would pick', () => {
    // needsUnicodeFlag, not a blanket 'iu'. Forcing u on every pattern is
    // stricter than the engine and rejects twelve patterns it accepts, because
    // u-mode disallows identity escapes that are legal without it. The
    // assertion is that the digest compiles the way the engine compiles it.
    const broken: string[] = [];
    for (const [name, p] of Object.entries(d.patterns)) {
      const body = p.replace(/^\(\?[imsx]+\)/, '');
      const flags = needsUnicodeFlag(body) ? 'iu' : 'i';
      try {
        new RegExp(body, flags);
      } catch {
        broken.push(name);
      }
    }
    expect(broken).toEqual([]);
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
