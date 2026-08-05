/**
 * Tests for src/quality/wild-measurement.ts — a wild_fp_rate must come from a
 * measurement.
 *
 * THE BUG THESE TESTS EXIST TO PREVENT
 *
 * scripts/compute-confidence.ts scored every rule against a wild-scan report:
 *
 *     const fireCount = ruleHitMap.get(baseMetadata.id) ?? 0;
 *     const wildFpRate = fireCount > 0 ? (fireCount / wildSampleCount) * 100 : 0;
 *
 * The report's `rule_hits` names the rules that FIRED. It carries a
 * `rules_loaded` COUNT and no roster, so a rule's absence from that list is
 * equally consistent with "evaluated and stayed clean" and with "never loaded,
 * or structurally unable to match this event shape". `?? 0` collapsed the two
 * and wrote the second as a perfect precision score.
 *
 * 230 rules on disk carried a zero from that collapse. wild_fp_rate gates
 * promotion into the enforce (auto-block) lane, so 38 of them were one
 * `--promote` run away from auto-blocking user traffic on a number nobody had
 * measured, and 2 were already at maturity: stable.
 *
 * ATR-2026-00061 is the worked example that this is not a hypothetical: it
 * declared wild_fp_rate: 0 and false-positived on 2,814 of 5,352 benign samples
 * (52.58%) the first time it was put on a corpus it could actually match. It
 * was silent in the wild scan because that scan walked SKILL.md bodies while
 * the rule reads tool_args/tool_response — the same zero-measurement blindness
 * that tests/corpus-event-shapes.test.ts pins for fields and
 * tests/skill-path-coverage.test.ts pins for the SKILL.md path.
 *
 * The load-bearing assertion is the on-disk one: no rule may declare
 * `wild_fp_rate: 0` unless a scan report actually names it. Everything else
 * pins the encoding (`undefined`, never `null`) and the default-deny direction
 * of each gate that reads the field.
 */

import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  isMeasuredFpRate,
  isMeasuredSampleCount,
  unmeasuredFpReason,
  deriveWildFpRate,
  parseATRRule,
  canPromote,
  validateRuleMeetsStandard,
  computeConfidence,
  getRequirements,
  type RuleMetadata,
  type WildScanHit,
} from "../src/quality/index.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(REPO_ROOT, "rules");
const MEGA_SCAN = join(REPO_ROOT, "data", "mega-scan-report.json");

/**
 * Counts measured on this branch after the repair, re-derived below from the
 * rules on disk. A RATCHET, not a specification: the corpus grows daily, so the
 * assertions are invariants and bounds, and this block exists so a reader can
 * tell whether a change moved a number and by how much.
 */
const MEASURED_ON_BRANCH = Object.freeze({
  rules: 783,
  carryingWildFpRate: 11,
  declaredZero: 0,
  strippedByRepair: 230,
});

function ruleFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...ruleFiles(full));
    else if (full.endsWith(".yaml") || full.endsWith(".yml")) out.push(full);
  }
  return out;
}

const WILD_FP_LINE = /^wild_fp_rate:[ \t]*(\S+)[ \t]*$/m;
const ID_LINE = /^id:[ \t]*["']?([^"'\s]+)["']?[ \t]*$/m;

interface OnDisk {
  readonly id: string;
  readonly file: string;
  readonly value: number;
}

function onDiskRates(): OnDisk[] {
  const out: OnDisk[] = [];
  for (const file of ruleFiles(RULES_DIR)) {
    const content = readFileSync(file, "utf-8");
    const m = WILD_FP_LINE.exec(content);
    if (m === null) continue;
    out.push({
      id: ID_LINE.exec(content)?.[1] ?? "(unknown)",
      file: file.replace(`${REPO_ROOT}/`, ""),
      value: Number(m[1]),
    });
  }
  return out;
}

function scanHits(): WildScanHit[] {
  const report = JSON.parse(readFileSync(MEGA_SCAN, "utf-8")) as {
    rule_hits: WildScanHit[];
  };
  return report.rule_hits;
}

/** A minimal rule that clears every stable gate except the one under test. */
function stableCandidate(over: Partial<RuleMetadata> = {}): RuleMetadata {
  return {
    id: "ATR-TEST-00001",
    maturity: "experimental",
    conditions: 5,
    truePositives: 5,
    trueNegatives: 5,
    evasionTests: 2,
    hasOwaspRef: true,
    hasMitreRef: true,
    hasFalsePositiveDocs: true,
    wildSamples: 96096,
    wildValidatedAt: "2026/01/01",
    ...over,
  } as unknown as RuleMetadata;
}

describe("on disk — no rule may claim a false-positive rate nobody measured", () => {
  it("declares zero only for rules a scan report actually names", () => {
    const hits = scanHits();
    const named = new Set(hits.map((h) => h.id));

    // A zero is the maximally self-serving value the field can take: it buys
    // the stable gate, the single-pattern exception and a 100 precision score.
    // A non-zero rate costs the rule on all three, so nobody fabricates one —
    // which is why only zeros need positive evidence to stand.
    const unearned = onDiskRates().filter(
      (r) => r.value === 0 && !named.has(r.id),
    );

    expect(
      unearned.map((r) => `${r.id} (${r.file})`),
      "wild_fp_rate: 0 on a rule no scan report names. Absence from rule_hits " +
        "cannot tell 'evaluated and clean' from 'never evaluated' — omit the " +
        "field instead, and let the gates default to blocking.",
    ).toEqual([]);
    expect(unearned.length).toBe(MEASURED_ON_BRANCH.declaredZero);
  });

  it("contradicts no scan report — a rule that fired cannot also read 0%", () => {
    const hits = scanHits();
    const byId = new Map(hits.map((h) => [h.id, h.count]));
    const contradicted = onDiskRates().filter(
      (r) => r.value === 0 && (byId.get(r.id) ?? 0) > 0,
    );
    expect(
      contradicted.map(
        (r) => `${r.id} fired ${byId.get(r.id)}x yet declares 0%`,
      ),
    ).toEqual([]);
  });

  it("keeps the measurements that do exist — the repair must not delete data", () => {
    const rates = onDiskRates();
    expect(rates.length).toBe(MEASURED_ON_BRANCH.carryingWildFpRate);
    // Every surviving value is a real observation, so every one is non-zero.
    expect(rates.every((r) => r.value > 0)).toBe(true);
    // The 52.58% that started this line must still be on disk: re-zeroing it
    // is the regression that would put ATR-2026-00061 back in the promotion queue.
    expect(rates.find((r) => r.id === "ATR-2026-00061")?.value).toBe(52.58);
  });

  it("every rate on disk parses as a measured rate", () => {
    for (const r of onDiskRates()) {
      expect(isMeasuredFpRate(r.value), `${r.id} -> ${r.value}`).toBe(true);
    }
  });
});

describe("deriveWildFpRate — silence is not a measurement", () => {
  const hits: WildScanHit[] = [{ id: "ATR-FIRED", count: 209 }];

  it("refuses to produce a rate for a rule the report does not name", () => {
    const d = deriveWildFpRate(hits, "ATR-SILENT", 96096);
    expect(d.substantiated).toBe(false);
    expect(d.fpRate).toBeNull();
    expect(d.reason).toContain("rule_hits");
  });

  it("produces the measured rate for a rule the report names", () => {
    const d = deriveWildFpRate(hits, "ATR-FIRED", 96096);
    expect(d.substantiated).toBe(true);
    expect(d.fpRate).toBeCloseTo(0.2175, 4);
  });

  it("refuses when the report has no usable denominator", () => {
    expect(deriveWildFpRate(hits, "ATR-FIRED", 0).fpRate).toBeNull();
    expect(deriveWildFpRate(hits, "ATR-FIRED", Number.NaN).fpRate).toBeNull();
  });

  it("never returns 0 for an unnamed rule — the `?? 0` regression", () => {
    for (const id of ["a", "b", "ATR-2026-00061"]) {
      expect(deriveWildFpRate(hits, id, 96096).fpRate).not.toBe(0);
    }
  });
});

describe("the encoding — omission, never null", () => {
  it("treats only a finite percentage as measured", () => {
    expect(isMeasuredFpRate(0)).toBe(true);
    expect(isMeasuredFpRate(52.58)).toBe(true);
    expect(isMeasuredFpRate(100)).toBe(true);
    for (const bad of [
      undefined,
      null,
      Number.NaN,
      Infinity,
      "0",
      -1,
      101,
      {},
    ]) {
      expect(isMeasuredFpRate(bad), `${JSON.stringify(bad)}`).toBe(false);
    }
  });

  it("treats only a finite non-negative number as a measured sample count", () => {
    expect(isMeasuredSampleCount(0)).toBe(true);
    expect(isMeasuredSampleCount(96096)).toBe(true);
    for (const bad of [undefined, null, Number.NaN, "96096", -1]) {
      expect(isMeasuredSampleCount(bad)).toBe(false);
    }
  });

  it("explains an unmeasured value and stays quiet about a measured one", () => {
    expect(unmeasuredFpReason(0)).toBeNull();
    expect(unmeasuredFpReason(undefined)).toContain("absent");
    expect(unmeasuredFpReason(null)).toContain("unmeasured");
  });

  it("drops a null rate at the adapter so it can never reach a gate", () => {
    // The reason omission is the encoding: `null === undefined` is false and
    // `null > 0.5` is false, so a null that survived parsing would satisfy
    // BOTH halves of the stable gate's disjunction and promote silently.
    expect((null as unknown as number) > 0.5).toBe(false);
    const yamlNull = [
      "id: ATR-TEST-NULL",
      "name: x",
      'version: "1.0.0"',
      "status: experimental",
      "maturity: experimental",
      "severity: high",
      "wild_fp_rate: null",
      "wild_samples: null",
      "detection:",
      "  method: pattern",
      "  condition: any",
      "  conditions:",
      "    - field: content",
      '      regex: "x"',
      "test_cases:",
      "  true_positives: []",
      "  true_negatives: []",
      "",
    ].join("\n");
    const parsed = parseATRRule(yamlNull);
    expect(parsed.wildFpRate).toBeUndefined();
    expect(parsed.wildSamples).toBeUndefined();
  });
});

describe("the gates default to blocking when the measurement is missing", () => {
  it("blocks stable promotion on an absent rate", () => {
    const d = canPromote(stableCandidate({ wildFpRate: undefined }), "stable");
    expect(d.eligible).toBe(false);
    expect(d.blockers.some((b) => b.includes("wild_fp_rate unmeasured"))).toBe(
      true,
    );
  });

  it("blocks stable promotion on a null rate — not just an absent one", () => {
    const d = canPromote(
      stableCandidate({ wildFpRate: null as unknown as number }),
      "stable",
    );
    expect(d.eligible).toBe(false);
    expect(d.blockers.some((b) => b.includes("wild_fp_rate"))).toBe(true);
  });

  it("still blocks a measured rate that is simply too high", () => {
    const d = canPromote(stableCandidate({ wildFpRate: 52.58 }), "stable");
    expect(d.eligible).toBe(false);
    expect(d.blockers.some((b) => b.includes("above threshold"))).toBe(true);
  });

  it("never grants the single-pattern exception, measured or not — it is currently dead code", () => {
    // Documented here because it changes what the RFC-001 v1.1 §1.1 exception
    // is worth today, and because the hardening in quality-gate.ts is otherwise
    // untestable through the public surface.
    //
    // The exception is consulted only inside `if (rule.conditions <
    // req.minConditions)`, and it requires `rule.conditions >= 1`. RFC-001 v1.1
    // lowered experimental.minConditions to 1 for contribution velocity, so the
    // guard now reads `conditions < 1 && conditions >= 1` — unsatisfiable. A
    // 1-condition rule passes outright without needing the exception, and a
    // 0-condition rule is rejected as invalid.
    //
    // This test is a tripwire: raise minConditions above 1 and it goes red,
    // which forces whoever does that to confirm the exception still demands a
    // MEASURED zero rather than an absent one.
    for (const wildFpRate of [0, undefined]) {
      for (const conditions of [0, 1, 2]) {
        const r = validateRuleMeetsStandard(
          stableCandidate({ conditions, wildFpRate, wildSamples: 60000 }),
          "experimental",
        );
        expect(
          r.warnings.some((w) => w.includes("single-pattern exception")),
          `conditions=${conditions} wildFpRate=${String(wildFpRate)}`,
        ).toBe(false);
      }
    }
    // And the shape of the gate that makes it dead, pinned directly.
    expect(getRequirements().experimental.minConditions).toBe(1);
  });

  it("does not award a perfect precision score for a missing measurement", () => {
    // Few test cases, so the honest fallback (test-case depth) is visibly
    // weaker than the 100 a measured 0% earns. With 10+ test cases the
    // fallback also reaches 100, which is why this fixture uses 3.
    const thin = { truePositives: 2, trueNegatives: 1 };
    const measured = computeConfidence(
      stableCandidate({ ...thin, wildFpRate: 0 }),
    ).precisionScore;
    const absent = computeConfidence(
      stableCandidate({ ...thin, wildFpRate: undefined }),
    ).precisionScore;
    const nulled = computeConfidence(
      stableCandidate({ ...thin, wildFpRate: null as unknown as number }),
    ).precisionScore;

    expect(measured).toBe(100);
    // The bug: `null` used to reach Math.min(100, null) as 0 and score 100 —
    // top marks for the absence of a measurement.
    expect(absent).toBeLessThan(100);
    expect(nulled).toBe(absent);
  });
});
