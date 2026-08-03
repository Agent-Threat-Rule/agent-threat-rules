/**
 * Shared fixtures for the per-rule latency ratchet tests.
 *
 * Not a .test.ts file, so vitest does not collect it; it exists because the
 * gate's tests split across two files (tests/gate-rule-latency.test.ts for the
 * metric and its verdicts, tests/gate-rule-latency-guards.test.ts for the parts
 * that touch a real engine, a real git repo or the committed baseline) and a
 * synthetic profile builder copied into both would drift.
 *
 * @module tests/rule-latency-fixtures
 */
import { baselineFrom, relativeCosts, renderGate, type Baseline, type Profile } from "../scripts/gate-rule-latency.js";

export const BASE_SHAPE = 1.92;

/** Median rule cost of every synthetic profile, in milliseconds. */
export const MEDIAN_MS = 0.1;

/**
 * A profile shaped like the real one: a dense cluster of ordinary rules around
 * the median plus a short expensive tail. `extra` adds rules at a chosen
 * multiple of the median, `scale` simulates a slower machine.
 *
 * The ordinary rules are laid out symmetrically -- matched pairs below (down to
 * 0.6x) and above (up to 3.0x) around a small plateau at exactly 1.0x. The
 * plateau is sized to cover however many expensive rules the caller adds, so
 * the median is exactly MEDIAN_MS whatever the test does and an assertion can
 * name an exact multiple. The upper tail reaching 3.0x mirrors the real corpus,
 * whose p90 is 4.22x of its median.
 */
export function makeProfile(
  extra: Record<string, number> = {},
  ordinary = 201,
  scale = 1,
  samples = 341
): Profile {
  const plateau = 2 * Object.keys(extra).length + 3;
  const pairs = Math.max(1, Math.floor((ordinary - plateau) / 2));
  const spreads = Array.from({ length: plateau }, () => 1);
  for (let k = 1; k <= pairs; k++) {
    spreads.push(1 - (0.4 * k) / pairs, 1 + (2 * k) / pairs);
  }

  const costs: Record<string, { ms: number; file: string }> = {};
  for (const [i, spread] of spreads.entries()) {
    costs[`ATR-ORD-${String(i).padStart(4, "0")}`] = {
      ms: MEDIAN_MS * spread * scale,
      file: `rules/synthetic/ord-${i}.yaml`,
    };
  }
  for (const [id, rel] of Object.entries(extra)) {
    costs[id] = { ms: MEDIAN_MS * rel * scale, file: `rules/synthetic/${id}.yaml` };
  }
  return {
    generatedAt: "2026-08-03T00:00:00.000Z",
    rules: Object.keys(costs).length,
    samples,
    medianRuleMs: MEDIAN_MS * scale,
    skippedRuleIds: [],
    unprofilableRuleIds: [],
    unparsedFiles: 0,
    dirtyRulePaths: [],
    costs,
    latencyShape: BASE_SHAPE,
    latencyP50Ms: 7.6 * scale,
    latencyP95Ms: 7.6 * BASE_SHAPE * scale,
  };
}

/** Multiply every measured quantity by k -- i.e. run the same corpus on a slower box. */
export function onSlowerRunner(profile: Profile, k: number): Profile {
  const costs = Object.fromEntries(
    Object.entries(profile.costs).map(([id, c]) => [id, { ...c, ms: c.ms * k }])
  );
  return {
    ...profile,
    costs,
    medianRuleMs: profile.medianRuleMs * k,
    latencyP50Ms: profile.latencyP50Ms * k,
    latencyP95Ms: profile.latencyP95Ms * k,
    // Shape is a ratio of two numbers that both scaled, so it does not move.
    latencyShape: profile.latencyShape,
  };
}

/**
 * Append `count` brand-new rules at `rel` times the profile's own median, leaving
 * every existing rule's measured cost untouched. This is what a week of
 * CVE-collector output looks like, and the thing an earlier draft got wrong.
 */
export function withNewRules(profile: Profile, count: number, rel: number): Profile {
  const values = Object.values(profile.costs).map((c) => c.ms).sort((a, b) => a - b);
  const mid = values.length % 2 === 1
    ? values[Math.floor(values.length / 2)]!
    : (values[values.length / 2 - 1]! + values[values.length / 2]!) / 2;
  const unit = mid * rel;
  const costs = { ...profile.costs };
  for (let i = 0; i < count; i++) {
    costs[`ATR-NEW-${String(i).padStart(4, "0")}`] = { ms: unit, file: `rules/synthetic/new-${i}.yaml` };
  }
  return { ...profile, rules: Object.keys(costs).length, costs };
}

/** Drop rules from a profile, as deleting or drafting them would. */
export function withoutRules(profile: Profile, ids: readonly string[]): Profile {
  const costs = Object.fromEntries(Object.entries(profile.costs).filter(([id]) => !ids.includes(id)));
  return { ...profile, rules: Object.keys(costs).length, costs };
}

export function baselineOf(profile: Profile): Baseline {
  return baselineFrom(profile, relativeCosts(profile));
}

export function verdict(profile: Profile, base: Baseline): number {
  return renderGate(profile, relativeCosts(profile, base), base).exitCode;
}

export function report(profile: Profile, base: Baseline): string {
  return renderGate(profile, relativeCosts(profile, base), base).lines.join("\n");
}

export function relOf(profile: Profile, base: Baseline, ruleId: string): number {
  return relativeCosts(profile, base).find((c) => c.ruleId === ruleId)!.rel;
}

/**
 * A schema-valid rule whose single condition is a regex over the event content.
 * `(?:[a-z]+\s*){0,6}` is the construct isReDoSSafe() in src/engine.ts
 * explicitly permits -- a bounded outer quantifier around an unbounded inner
 * one -- and which measures 175ms against a single 61-character sample.
 */
export function fixtureRule(id: string, pattern: string, sourceType = "llm_io"): string {
  return [
    `title: 'Latency fixture ${id}'`,
    `id: ${id}`,
    "rule_version: 1",
    "status: experimental",
    "description: 'Fixture rule used by the rule-latency gate tests.'",
    "author: 'ATR tests'",
    'date: "2026/08/03"',
    'schema_version: "0.1"',
    "detection_tier: pattern",
    "maturity: test",
    "severity: low",
    "tags:",
    "  category: prompt-injection",
    "  scan_target: both",
    "  confidence: low",
    "agent_source:",
    `  type: ${sourceType}`,
    "  framework: [any]",
    "  provider: [any]",
    "detection:",
    "  conditions:",
    "    - field: content",
    "      operator: regex",
    `      value: '${pattern}'`,
    "      description: 'fixture'",
    "  condition: any",
    "response:",
    "  actions: [alert]",
    `  message_template: '[${id}] fixture'`,
    "",
  ].join("\n");
}
