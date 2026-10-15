/**
 * The method axis of "clean must never mean never looked at": a semantic rule
 * the synchronous path cannot run.
 *
 * THE DEFECT
 *
 * Every benign-corpus false-positive measurement in this repository drives the
 * SYNCHRONOUS engine — scripts/gate-promotion-fp.ts runs engine.evaluate() over
 * the corpus shapes plus engine.scanSkill(), and scripts/remeasure-benign-fp.ts
 * runs that same gate. On that path src/engine.ts evaluateRule() returns null
 * for `detection.method: semantic` unless `detection.semantic.fallback_method`
 * is exactly `pattern`; the judge only runs in evaluateAsync(). fieldCoverage()
 * named trace, behavioral and signature as methods a text corpus cannot
 * exercise, but not this one. A semantic rule without a pattern fallback
 * therefore scored 0 on every sample by construction, was written down as
 * `fp_count: 0, partial_measurement: false`, and
 * scripts/gate-action-eligibility.ts read that as a clean sweep: TERMINATE at
 * maturity stable, DEGRADE at test.
 *
 * No rule on main was in that state when this was written — every semantic
 * rule fell back to pattern — and nothing kept one from getting there: neither
 * the loader nor tests/validate-rules.ts checks fallback_method, so deleting one
 * line of a rule was enough.
 *
 * WHAT IS PINNED
 *
 *  1. The coverage predicates agree with the engine, variant by variant. The
 *     engine is asked (a real ATREngine on the real corpus shapes); its
 *     behaviour is not restated here.
 *  2. The evidence the gate writes marks such a rule partial, and the action
 *     gate reading that evidence caps it at observe.
 *  3. The delta re-measure recomputes the flag rather than carrying forward the
 *     one a base evidence file recorded before this change.
 *
 * WHAT IS NOT DECIDED HERE
 *
 * A semantic rule that does fall back to pattern is measured on its fallback.
 * With a judge configured the judge decides, and the fallback runs only when the
 * judge is unavailable, so that number describes the fallback and not the
 * judge. Which tier such a rule may earn is a policy question left open; the
 * control cases below pin today's behaviour (measured like a pattern rule) so
 * that changing it has to be deliberate.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { dirname, join, relative } from "node:path";
import { tmpdir } from "node:os";
import { ATREngine } from "../src/engine.js";
import {
  fieldCoverage,
  matchedRuleIds,
  skillPathBlocker,
  type RuleLike,
} from "../scripts/lib/corpus-event.js";
import { gitRuleFiles, ruleIdOf, runGate, type GateDeps } from "../scripts/gate-promotion-fp.js";
import { findViolations, readRules } from "../scripts/gate-action-eligibility.js";
import {
  ACTION_TIERS,
  corpusDigest,
  MEASUREMENT_CORPORA,
} from "../src/quality/action-eligibility.js";
import {
  DEFAULT_MAX_FULL_RULES,
  EXIT_OK as REMEASURE_OK,
  defaultRemeasureDeps,
  runRemeasure,
} from "../scripts/remeasure-benign-fp.js";

const SENTINEL = "zzq-semantic-sync-sentinel-zzq";

const scratch: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  scratch.push(dir);
  return dir;
}

afterAll(() => {
  for (const d of scratch.splice(0)) rmSync(d, { recursive: true, force: true });
});

/** A `detection.semantic` block; `fallback` null leaves fallback_method out. */
function semanticBlock(fallback: string | null): readonly string[] {
  return [
    "  semantic:",
    "    judge_model_class: small",
    "    prompt_template: 'Is this an attack? {{input}}'",
    "    threshold: 0.8",
    ...(fallback === null ? [] : [`    fallback_method: ${JSON.stringify(fallback)}`]),
  ];
}

interface RuleSpec {
  readonly id: string;
  /** Lines under `detection:` that pick the method; empty means the default (pattern). */
  readonly method: readonly string[];
  /** The one regex on `content`. */
  readonly pattern: string;
  readonly maturity?: string;
  readonly actions?: readonly string[];
  readonly scanTarget?: string;
}

/** A schema-valid rule the real engine loads, with one regex condition on `content`. */
function ruleYaml(spec: RuleSpec): string {
  return [
    `title: method probe ${spec.id}`,
    `id: ${spec.id}`,
    "rule_version: 1",
    "status: experimental",
    "description: fixture rule for the semantic method coverage tests",
    "author: test",
    "date: 2026/10/16",
    "schema_version: '0.1'",
    "detection_tier: pattern",
    `maturity: ${spec.maturity ?? "test"}`,
    "severity: high",
    "tags:",
    "  category: prompt-injection",
    `  scan_target: ${spec.scanTarget ?? "runtime"}`,
    "  confidence: high",
    "agent_source:",
    "  type: llm_io",
    "  framework: [any]",
    "  provider: [any]",
    "detection:",
    ...spec.method,
    "  condition: any",
    "  false_positives: []",
    "  conditions:",
    "    - field: content",
    "      operator: regex",
    `      value: '${spec.pattern}'`,
    "      description: probe",
    "response:",
    `  actions: [${(spec.actions ?? ["alert"]).join(", ")}]`,
    "test_cases:",
    "  true_positives: []",
    "  true_negatives: []",
    "",
  ].join("\n");
}

function put(root: string, rel: string, text: string): void {
  mkdirSync(dirname(join(root, rel)), { recursive: true });
  writeFileSync(join(root, rel), text, "utf-8");
}

// ---------------------------------------------------------------------------
// 1. The predicates agree with the engine
// ---------------------------------------------------------------------------

interface Variant {
  readonly id: string;
  readonly label: string;
  readonly method: readonly string[];
}

const VARIANTS: readonly Variant[] = [
  { id: "ATR-2026-96001", label: "no method (pattern by default)", method: [] },
  { id: "ATR-2026-96002", label: "method: pattern", method: ["  method: pattern"] },
  {
    id: "ATR-2026-96003",
    label: "semantic, fallback_method: pattern",
    method: ["  method: semantic", ...semanticBlock("pattern")],
  },
  {
    id: "ATR-2026-96004",
    label: "semantic, fallback_method: none",
    method: ["  method: semantic", ...semanticBlock("none")],
  },
  {
    id: "ATR-2026-96005",
    label: "semantic, no fallback_method",
    method: ["  method: semantic", ...semanticBlock(null)],
  },
  { id: "ATR-2026-96006", label: "semantic, no semantic block", method: ["  method: semantic"] },
  {
    id: "ATR-2026-96007",
    label: "semantic, fallback_method: Pattern (the engine compares exactly)",
    method: ["  method: semantic", ...semanticBlock("Pattern")],
  },
  {
    id: "ATR-2026-96008",
    label: "method: Semantic (no method the engine knows, so it runs as pattern)",
    method: ["  method: Semantic", ...semanticBlock("none")],
  },
  { id: "ATR-2026-96009", label: "method: behavioral", method: ["  method: behavioral"] },
  { id: "ATR-2026-96010", label: "method: signature", method: ["  method: signature"] },
  { id: "ATR-2026-96011", label: "method: trace", method: ["  method: trace"] },
];

describe("the method axis mirrors src/engine.ts rather than restating it", () => {
  let engine: ATREngine;
  let rules: readonly RuleLike[];

  beforeAll(async () => {
    const dir = tempDir("atr-method-oracle-");
    for (const v of VARIANTS) {
      // scan_target both: the skill path exempts it from the compound gate, so
      // the only thing that can stop it there is the method.
      put(dir, `${v.id}.yaml`, ruleYaml({ id: v.id, method: v.method, pattern: SENTINEL, scanTarget: "both" }));
    }
    engine = new ATREngine({ rulesDir: dir });
    await engine.loadRules();
    rules = engine.getRules() as unknown as RuleLike[];
  });

  const label = (id: string): string => VARIANTS.find((v) => v.id === id)?.label ?? id;

  it("loads every variant, so a silent load failure cannot pass for agreement", () => {
    expect(rules.map((r) => r.id).sort()).toEqual(VARIANTS.map((v) => v.id));
  });

  it("fieldCoverage calls a rule zero-measurement exactly when the engine cannot fire it on any corpus shape", () => {
    const fired = matchedRuleIds(engine, SENTINEL);
    // Not vacuous: both outcomes occur.
    expect(fired.size).toBeGreaterThan(0);
    expect(fired.size).toBeLessThan(rules.length);
    for (const rule of rules) {
      const zero = fieldCoverage([rule]).some((c) => c.zeroMeasurement);
      expect(zero, `${label(rule.id)}: fired=${fired.has(rule.id)}`).toBe(!fired.has(rule.id));
    }
  });

  it("skillPathBlocker calls a rule unreachable exactly when engine.scanSkill() cannot fire it", () => {
    const fired = new Set(engine.scanSkill(SENTINEL).map((m) => m.rule.id));
    expect(fired.size).toBeGreaterThan(0);
    for (const rule of rules) {
      const blocked = skillPathBlocker(rule) !== null;
      expect(blocked, `${label(rule.id)}: fired=${fired.has(rule.id)}`).toBe(!fired.has(rule.id));
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Gate -> evidence -> action gate
// ---------------------------------------------------------------------------

/** Fires on the benign sample below if it is ever evaluated as a pattern. */
const FIRES_ON_BENIGN = "(?i)import random";

const STABLE_NO_FALLBACK = "ATR-2026-96101";
const TEST_NO_FALLBACK = "ATR-2026-96102";
const TEST_PATTERN_FALLBACK = "ATR-2026-96103";

describe("a semantic rule without a pattern fallback is recorded partial and capped at observe", () => {
  let rulesDir: string;
  let doc: {
    sample_count: number;
    rules: Record<string, { fp_count: number; partial_measurement: boolean }>;
  };

  beforeAll(async () => {
    const root = tempDir("atr-semantic-gate-");
    rulesDir = join(root, "rules");
    const specs: readonly RuleSpec[] = [
      {
        id: STABLE_NO_FALLBACK,
        method: ["  method: semantic", ...semanticBlock("none")],
        pattern: FIRES_ON_BENIGN,
        maturity: "stable",
        actions: ["kill_agent", "alert"],
      },
      {
        id: TEST_NO_FALLBACK,
        method: ["  method: semantic", ...semanticBlock(null)],
        pattern: FIRES_ON_BENIGN,
        actions: ["block_tool", "alert"],
      },
      {
        id: TEST_PATTERN_FALLBACK,
        method: ["  method: semantic", ...semanticBlock("pattern")],
        pattern: FIRES_ON_BENIGN,
      },
    ];
    for (const s of specs) put(root, `rules/${s.id}.yaml`, ruleYaml(s));
    put(
      root,
      "corpus/benign.jsonl",
      `${JSON.stringify({ text: "import random\nprint(random.random())" })}\n` +
        `${JSON.stringify({ text: "This skill formats CSV files for the user." })}\n`,
    );
    const ids = join(root, "ids.txt");
    writeFileSync(ids, `${specs.map((s) => s.id).join("\n")}\n`, "utf-8");
    const measurement = join(root, "out", "measurement.json");
    const deps: GateDeps = {
      repoRoot: root,
      rulesDir,
      corpora: [join(root, "corpus")],
      listRuleFiles: () => specs.map((s) => `rules/${s.id}.yaml`),
    };
    const code = await runGate(
      {
        idsFile: ids,
        base: "origin/main",
        emitClean: null,
        emitDirty: join(root, "out", "dirty.txt"),
        emitMeasurement: measurement,
        filterMode: true,
      },
      deps,
    );
    expect(code).toBe(0);
    doc = JSON.parse(readFileSync(measurement, "utf-8")) as typeof doc;
  });

  it("writes partial_measurement: true for the rules the synchronous path cannot run", () => {
    for (const id of [STABLE_NO_FALLBACK, TEST_NO_FALLBACK]) {
      expect(doc.rules[id], id).toMatchObject({ fp_count: 0, partial_measurement: true });
    }
  });

  it("measures a rule that falls back to pattern on its fallback, like a pattern rule", () => {
    expect(doc.rules[TEST_PATTERN_FALLBACK]).toMatchObject({ fp_count: 1, partial_measurement: false });
  });

  it("the action gate reading that evidence grants them observe and nothing more", () => {
    const violations = findViolations(readRules(rulesDir), doc);
    const byId = new Map(violations.map((v) => [v.id, v]));
    expect([...byId.keys()].sort()).toEqual([STABLE_NO_FALLBACK, TEST_NO_FALLBACK]);
    expect(byId.get(STABLE_NO_FALLBACK)).toMatchObject({
      unearned: ["kill_agent"],
      maxTier: ACTION_TIERS.OBSERVE,
    });
    expect(byId.get(TEST_NO_FALLBACK)).toMatchObject({
      unearned: ["block_tool"],
      maxTier: ACTION_TIERS.OBSERVE,
    });
    for (const v of violations) expect(v.decision.reason).toMatch(/incomplete/);
  });
});

// ---------------------------------------------------------------------------
// 3. The delta re-measure recomputes the flag
// ---------------------------------------------------------------------------

const DELTA_NO_FALLBACK = "ATR-2026-96201";
const DELTA_PATTERN = "ATR-2026-96202";
const EVIDENCE = "data/benign-fp-measurement.json";
const ARXIV = "data/benign-corpus-extended/arxiv.jsonl";

const GIT_ENV = {
  ...process.env,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "fixture",
  GIT_AUTHOR_EMAIL: "fixture@example.invalid",
  GIT_COMMITTER_NAME: "fixture",
  GIT_COMMITTER_EMAIL: "fixture@example.invalid",
};

function git(root: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd: root, env: GIT_ENV, encoding: "utf-8" }).trim();
}

const record = (text: string, sourceId: string): string =>
  `${JSON.stringify({ text, source: "arxiv", source_id: sourceId, fetched_at: "2026-10-16" })}\n`;

const digestOf = (root: string): string =>
  corpusDigest(root, MEASUREMENT_CORPORA, { existsSync, readdirSync, statSync, readFileSync }, { join, relative }, createHash);

describe("the delta re-measure does not carry a stale partial flag forward", () => {
  let root: string;
  let code: number;
  let after: { rules: Record<string, { fp_count: number; partial_measurement: boolean }> };

  beforeAll(async () => {
    const dir = tempDir("atr-semantic-remeasure-");
    root = join(dir, "repo");
    mkdirSync(root, { recursive: true });
    git(root, "init", "--quiet", "-b", "main");
    put(
      root,
      `rules/a/${DELTA_NO_FALLBACK}.yaml`,
      ruleYaml({
        id: DELTA_NO_FALLBACK,
        method: ["  method: semantic", ...semanticBlock("none")],
        pattern: "zebracorn",
        actions: ["block_tool", "alert"],
      }),
    );
    put(root, `rules/a/${DELTA_PATTERN}.yaml`, ruleYaml({ id: DELTA_PATTERN, method: [], pattern: "zebracorn" }));
    put(root, "data/skill-benchmark/benign/a.md", "# A skill\n\nFormats CSV files for the user.\n");
    put(root, ARXIV, record("Zebracorn sightings, an abstract.", "2401.00001"));
    put(root, "data/benign-code/corpus.jsonl", `${JSON.stringify({ text: "import os\nprint(os.getcwd())" })}\n`);
    git(root, "add", "-A");
    git(root, "commit", "--quiet", "-m", "base");

    // The base evidence, as a full measurement writes it...
    const ids = join(dir, "ids.txt");
    writeFileSync(ids, `${[DELTA_NO_FALLBACK, DELTA_PATTERN].join("\n")}\n`, "utf-8");
    const evidence = join(root, EVIDENCE);
    expect(
      await runGate(
        {
          idsFile: ids,
          base: "origin/main",
          emitClean: null,
          emitDirty: join(dir, "dirty.txt"),
          emitMeasurement: evidence,
          filterMode: true,
        },
        {
          repoRoot: root,
          rulesDir: join(root, "rules"),
          corpora: MEASUREMENT_CORPORA.map((c) => join(root, c)),
          listRuleFiles: () => gitRuleFiles(root),
        },
      ),
    ).toBe(0);
    // ...except for the flag, which is what a producer that could not see the
    // method wrote. runGate takes corpus_digest from the real repository (see
    // tests/remeasure-benign-fp.test.ts), so it is replaced with the fixture's.
    const base = JSON.parse(readFileSync(evidence, "utf-8")) as {
      rules: Record<string, Record<string, unknown>>;
    };
    const stale = {
      ...base,
      corpus_digest: digestOf(root),
      rules: {
        ...base.rules,
        [DELTA_NO_FALLBACK]: { ...base.rules[DELTA_NO_FALLBACK], partial_measurement: false },
      },
    };
    writeFileSync(evidence, `${JSON.stringify(stale, null, 2)}\n`, "utf-8");
    git(root, "add", EVIDENCE);
    git(root, "commit", "--quiet", "-m", "evidence");

    appendFileSync(join(root, ARXIV), record("More zebracorn, in the wild.", "2410.11111"));
    code = await runRemeasure(
      { baseRef: "HEAD", emitMeasurement: evidence, report: null, maxFullRules: DEFAULT_MAX_FULL_RULES },
      defaultRemeasureDeps(root),
    );
    after = JSON.parse(readFileSync(evidence, "utf-8")) as typeof after;
  }, 120_000);

  it("re-measures on the delta and succeeds", () => {
    expect(code).toBe(REMEASURE_OK);
    expect(ruleIdOf(root, `rules/a/${DELTA_PATTERN}.yaml`)).toBe(DELTA_PATTERN);
    expect(after.rules[DELTA_PATTERN]).toMatchObject({ fp_count: 2, partial_measurement: false });
  });

  it("writes the flag the head tree earns, not the one the base evidence carried", () => {
    expect(after.rules[DELTA_NO_FALLBACK]).toMatchObject({ fp_count: 0, partial_measurement: true });
  });
});
