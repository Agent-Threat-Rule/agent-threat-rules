/**
 * Tests for the response-action eligibility policy and its gate.
 *
 * THE RATCHET IS `repository conformance` AT THE BOTTOM.
 *
 * The unit tests below pin the policy's shape. The repository test pins the
 * repository: every live rule on disk must declare only actions its measured
 * false-positive evidence earns. Adding `kill_agent` to a rule that has never
 * been measured, or to one that false-positives, turns this test red — which is
 * the whole point, because the runtime has no such check. `src/action-executor.ts`
 * filters on neither lane nor maturity; an unearned action in a rule file IS an
 * unearned action at runtime.
 *
 * A ratchet nobody has watched fail is not a ratchet. This one was broken on
 * purpose before it was committed: `ATR-2026-00062` had `kill_agent` re-added,
 * the repository test failed naming that rule, and the change was reverted.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { load as parseYaml } from "js-yaml";
import {
  ACTION_TIERS,
  actionTier,
  detectionFingerprint,
  DEMOTION_FP_PCT,
  eligibleActions,
  highestTier,
  ineligibleActions,
  isMeasured,
  maxTierFor,
  STABLE_FP_CEILING_PCT,
  TIERED_ACTIONS,
} from "../src/quality/action-eligibility.js";
import { ACTION_METHOD_MAP } from "../src/action-executor.js";
import { findViolations, isInert } from "../scripts/gate-action-eligibility.js";
import { rewriteActions } from "../scripts/downgrade-unearned-actions.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

describe("action tiers", () => {
  it("ranks by blast radius, not by executor priority", () => {
    // kill_agent runs FIRST in src/action-executor.ts (priority 0) but is the
    // most destructive, not the least. The two orderings must not be confused.
    expect(actionTier("kill_agent")).toBe(ACTION_TIERS.TERMINATE);
    expect(actionTier("quarantine_session")).toBe(ACTION_TIERS.TERMINATE);
    expect(actionTier("reduce_permissions")).toBe(ACTION_TIERS.DEGRADE);
    expect(actionTier("reset_context")).toBe(ACTION_TIERS.DEGRADE);
    expect(actionTier("block_tool")).toBe(ACTION_TIERS.INTERRUPT);
    expect(actionTier("block_input")).toBe(ACTION_TIERS.INTERRUPT);
    expect(actionTier("block_output")).toBe(ACTION_TIERS.INTERRUPT);
    expect(actionTier("alert")).toBe(ACTION_TIERS.OBSERVE);
    expect(actionTier("snapshot")).toBe(ACTION_TIERS.OBSERVE);
    expect(actionTier("escalate")).toBe(ACTION_TIERS.OBSERVE);
    expect(actionTier("shadow")).toBe(ACTION_TIERS.OBSERVE);
  });

  it("ranks exactly the actions the executor can dispatch", () => {
    // If someone implements a new PlatformAdapter method, this fails until its
    // blast radius is stated. A dispatchable action with no tier would silently
    // default to observe and bypass the whole policy.
    expect([...TIERED_ACTIONS].sort()).toEqual(
      Object.keys(ACTION_METHOD_MAP).sort(),
    );
  });

  it("treats an action the executor cannot dispatch as observe", () => {
    // require_human_review / quarantine_artifact / rate_limit_source / log_alert
    // are on disk but absent from ACTION_METHOD_MAP: the executor returns
    // "Unknown action" without dispatching. Inert, not destructive.
    expect(actionTier("require_human_review")).toBe(ACTION_TIERS.OBSERVE);
    expect(actionTier("rate_limit_source")).toBe(ACTION_TIERS.OBSERVE);
  });

  it("highestTier takes the worst action in the list", () => {
    expect(highestTier(["alert", "block_tool", "snapshot"])).toBe(
      ACTION_TIERS.INTERRUPT,
    );
    expect(highestTier(["alert", "kill_agent"])).toBe(ACTION_TIERS.TERMINATE);
    expect(highestTier([])).toBe(ACTION_TIERS.OBSERVE);
  });
});

describe("measurement predicate", () => {
  it("refuses an absent, partial or denominator-less measurement", () => {
    expect(isMeasured({})).toBe(false);
    expect(isMeasured({ fpCount: 0 })).toBe(false); // no denominator
    expect(isMeasured({ sampleCount: 5352 })).toBe(false); // no count
    expect(isMeasured({ fpCount: 0, sampleCount: 5352, partial: true })).toBe(
      false,
    );
    // A partial run that DID find false positives is evidence: they happened,
    // and completing the measurement can only make the rate worse.
    expect(isMeasured({ fpCount: 9, sampleCount: 5352, partial: true })).toBe(
      true,
    );
    expect(isMeasured({ fpCount: 0, sampleCount: 5352 })).toBe(true);
  });

  it("does not accept a stringified or non-finite count", () => {
    // The `?? 0` collapse that put wild_fp_rate: 0 on 230 never-measured rules
    // is the reason every one of these must read as "no measurement".
    expect(
      isMeasured({ fpCount: "0" as unknown as number, sampleCount: 5352 }),
    ).toBe(false);
    expect(isMeasured({ fpCount: NaN, sampleCount: 5352 })).toBe(false);
    expect(isMeasured({ fpCount: 0, sampleCount: 0 })).toBe(false);
  });
});

describe("policy", () => {
  const N = 5352;
  /** Largest FP count still at or below `pct` on a corpus of N. */
  const at = (pct: number) => Math.floor((pct / 100) * N);

  it("grades a partial run on the hits it did find, but never up to terminate", () => {
    const d = maxTierFor({
      fpCount: 5,
      sampleCount: N,
      partial: true,
      maturity: "stable",
    });
    expect(d.maxTier).toBe(ACTION_TIERS.DEGRADE);
    expect(d.reason).toContain("lower bound");
    // 0 hits on a partial run stays at observe — it cannot reach terminate.
    expect(
      maxTierFor({
        fpCount: 0,
        sampleCount: N,
        partial: true,
        maturity: "stable",
      }).maxTier,
    ).toBe(ACTION_TIERS.OBSERVE);
  });

  it("caps an unmeasured rule at observe — absence of evidence is not evidence", () => {
    expect(maxTierFor({ maturity: "stable" }).maxTier).toBe(
      ACTION_TIERS.OBSERVE,
    );
    expect(
      maxTierFor({ fpCount: 0, sampleCount: N, partial: true }).maxTier,
    ).toBe(ACTION_TIERS.OBSERVE);
  });

  it("caps a rule above the standard's demotion line at observe", () => {
    const d = maxTierFor({
      fpCount: at(DEMOTION_FP_PCT) + 1,
      sampleCount: N,
      maturity: "stable",
    });
    expect(d.maxTier).toBe(ACTION_TIERS.OBSERVE);
    expect(d.reason).toContain("demotion");
  });

  it("puts the two published lines exactly where the standard puts them", () => {
    // 0.5% and 2% of 5,352 are 26 and 107 samples. One either side of each.
    const tier = (fp: number) =>
      maxTierFor({ fpCount: fp, sampleCount: N, maturity: "stable" }).maxTier;
    expect(at(STABLE_FP_CEILING_PCT)).toBe(26);
    expect(at(DEMOTION_FP_PCT)).toBe(107);
    expect(tier(26)).toBe(ACTION_TIERS.DEGRADE);
    expect(tier(27)).toBe(ACTION_TIERS.INTERRUPT);
    expect(tier(107)).toBe(ACTION_TIERS.INTERRUPT);
    expect(tier(108)).toBe(ACTION_TIERS.OBSERVE);
  });

  it("allows a recoverable interrupt between the production ceiling and the demotion line", () => {
    const d = maxTierFor({
      fpCount: at(1.0),
      sampleCount: N,
      maturity: "stable",
    });
    expect(d.maxTier).toBe(ACTION_TIERS.INTERRUPT);
  });

  it("allows degrade at or below the production ceiling but never terminate", () => {
    const d = maxTierFor({
      fpCount: at(STABLE_FP_CEILING_PCT),
      sampleCount: N,
      maturity: "stable",
    });
    expect(d.maxTier).toBe(ACTION_TIERS.DEGRADE);
  });

  it("earns terminate only with a clean sweep AND maturity stable", () => {
    expect(
      maxTierFor({ fpCount: 0, sampleCount: N, maturity: "stable" }).maxTier,
    ).toBe(ACTION_TIERS.TERMINATE);
    // Clean, but the lane the standard rates for blocking is `stable` alone.
    expect(
      maxTierFor({ fpCount: 0, sampleCount: N, maturity: "test" }).maxTier,
    ).toBe(ACTION_TIERS.DEGRADE);
    expect(
      maxTierFor({ fpCount: 0, sampleCount: N, maturity: "experimental" })
        .maxTier,
    ).toBe(ACTION_TIERS.DEGRADE);
  });

  it("is monotonic — more false positives never buy a higher tier", () => {
    let prev: number = ACTION_TIERS.TERMINATE;
    for (const pct of [0, 0.1, 0.5, 0.9, 2.0, 2.1, 10, 50]) {
      const t = maxTierFor({
        fpCount: at(pct),
        sampleCount: N,
        maturity: "stable",
      }).maxTier;
      expect(t).toBeLessThanOrEqual(prev);
      prev = t;
    }
  });
});

describe("action filtering", () => {
  it("names exactly the actions above the ceiling, in declaration order", () => {
    const actions = [
      "block_tool",
      "quarantine_session",
      "alert",
      "snapshot",
      "kill_agent",
    ];
    expect(ineligibleActions(actions, ACTION_TIERS.INTERRUPT)).toEqual([
      "quarantine_session",
      "kill_agent",
    ]);
    expect(ineligibleActions(actions, ACTION_TIERS.TERMINATE)).toEqual([]);
  });

  it("never leaves a rule with nothing to do", () => {
    expect(eligibleActions(["kill_agent"], ACTION_TIERS.OBSERVE)).toEqual([
      "alert",
    ]);
    expect(
      eligibleActions(["block_tool", "alert"], ACTION_TIERS.OBSERVE),
    ).toEqual(["alert"]);
  });
});

describe("detection fingerprint", () => {
  const base = {
    detection: {
      conditions: [{ field: "tool_args", operator: "regex", value: "a|b" }],
      condition: "any",
    },
    tags: { scan_target: "mcp" },
    agent_source: { type: "tool_call" },
  };

  it("is stable under key reordering — YAML tidying must not void a measurement", () => {
    const reordered = {
      agent_source: { type: "tool_call" },
      tags: { scan_target: "mcp" },
      detection: {
        condition: "any",
        conditions: [{ value: "a|b", operator: "regex", field: "tool_args" }],
      },
    };
    expect(detectionFingerprint(reordered)).toBe(detectionFingerprint(base));
  });

  it("changes when the pattern changes — a measurement of a different detection is void", () => {
    const edited = {
      ...base,
      detection: {
        ...base.detection,
        conditions: [{ field: "tool_args", operator: "regex", value: "a|b|c" }],
      },
    };
    expect(detectionFingerprint(edited)).not.toBe(detectionFingerprint(base));
  });

  it("changes when scan_target changes — it selects the skill compound gate", () => {
    expect(
      detectionFingerprint({ ...base, tags: { scan_target: "skill" } }),
    ).not.toBe(detectionFingerprint(base));
  });
});

describe("gate", () => {
  const measurement = {
    sample_count: 5352,
    rules: {
      "ATR-TEST-0001": {
        fp_count: 0,
        maturity: "stable",
        detection_fingerprint: "aaaa",
        partial_measurement: false,
      },
      "ATR-TEST-0002": {
        fp_count: 300,
        maturity: "test",
        detection_fingerprint: "bbbb",
        partial_measurement: false,
      },
    },
  };
  const rule = (o: Partial<Record<string, unknown>>) =>
    ({
      file: "rules/x.yaml",
      id: "ATR-TEST-0001",
      maturity: "stable",
      status: "experimental",
      actions: ["alert"],
      fingerprint: "aaaa",
      ...o,
    }) as never;

  it("passes a rule whose actions are within its earned tier", () => {
    expect(
      findViolations([rule({ actions: ["kill_agent", "alert"] })], measurement),
    ).toEqual([]);
  });

  it("fails an unmeasured rule that declares a destructive action", () => {
    const v = findViolations(
      [rule({ id: "ATR-TEST-9999", actions: ["block_tool"] })],
      measurement,
    );
    expect(v).toHaveLength(1);
    expect(v[0]!.unearned).toEqual(["block_tool"]);
    expect(v[0]!.decision.reason).toContain("no FP measurement");
  });

  it("fails a rule whose detection changed since the measurement", () => {
    const v = findViolations(
      [rule({ actions: ["kill_agent"], fingerprint: "zzzz" })],
      measurement,
    );
    expect(v).toHaveLength(1);
    expect(v[0]!.decision.reason).toContain("detection changed");
  });

  it("fails a rule measured above the demotion line that still blocks", () => {
    const v = findViolations(
      [
        rule({
          id: "ATR-TEST-0002",
          maturity: "test",
          fingerprint: "bbbb",
          actions: ["block_tool", "alert"],
        }),
      ],
      measurement,
    );
    expect(v).toHaveLength(1);
    expect(v[0]!.unearned).toEqual(["block_tool"]);
  });

  it("skips rules the engine never loads", () => {
    expect(isInert("draft", "test")).toBe(true);
    expect(isInert("deprecated", "test")).toBe(true);
    expect(isInert("experimental", "deprecated")).toBe(true);
    expect(isInert("experimental", "test")).toBe(false);
    expect(
      findViolations(
        [
          rule({
            id: "ATR-TEST-9999",
            status: "draft",
            actions: ["kill_agent"],
          }),
        ],
        measurement,
      ),
    ).toEqual([]);
  });
});

describe("YAML rewrite", () => {
  const yaml = [
    "title: x",
    "id: ATR-TEST-0001",
    "detection:",
    "  conditions:",
    "    - field: tool_args",
    "response:",
    "  actions:",
    "    - block_tool",
    "    - kill_agent",
    "    - alert",
    "  message_template: hi",
    "",
  ].join("\n");

  it("keeps only the eligible actions and records why, as a field", () => {
    const out = rewriteActions(yaml, ["block_tool", "alert"], "because 3 FP")!;
    expect(out).toContain("    - block_tool");
    expect(out).toContain("    - alert");
    expect(out).not.toContain("kill_agent");
    expect(out).toContain("  actions_rationale: >-");
    expect(out).toContain("  message_template: hi");
    // A comment would be erased by quality-upgrade.ts's yaml.dump round-trip.
    expect(out).not.toContain("  # because");
    const doc = parseYaml(out) as {
      response: { actions: string[]; actions_rationale: string };
    };
    expect(doc.response.actions).toEqual(["block_tool", "alert"]);
    expect(doc.response.actions_rationale).toContain("because 3 FP");
    expect(doc.response.message_template).toBeDefined();
  });

  it("replaces an existing rationale instead of stacking a second one", () => {
    const once = rewriteActions(yaml, ["block_tool", "alert"], "first reason")!;
    const twice = rewriteActions(once, ["alert"], "second reason")!;
    expect(twice.match(/actions_rationale:/g)).toHaveLength(1);
    const doc = parseYaml(twice) as {
      response: { actions: string[]; actions_rationale: string };
    };
    expect(doc.response.actions).toEqual(["alert"]);
    expect(doc.response.actions_rationale).toContain("second reason");
    expect(doc.response.message_template).toBe("hi");
  });

  it("refuses a file whose response block is not the expected shape", () => {
    expect(
      rewriteActions("response: {actions: [alert]}\n", ["alert"], "r"),
    ).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// THE RATCHET
// ---------------------------------------------------------------------------

describe("repository conformance", () => {
  function walk(dir: string): string[] {
    const out: string[] = [];
    for (const e of readdirSync(dir)) {
      const full = join(dir, e);
      if (statSync(full).isDirectory()) out.push(...walk(full));
      else if (full.endsWith(".yaml") || full.endsWith(".yml")) out.push(full);
    }
    return out;
  }

  it("every live rule declares only actions its measured evidence earns", () => {
    const measurement = JSON.parse(
      readFileSync(join(REPO_ROOT, "data/benign-fp-measurement.json"), "utf-8"),
    ) as Parameters<typeof findViolations>[1];

    const rules = walk(join(REPO_ROOT, "rules")).flatMap((file) => {
      const doc = parseYaml(readFileSync(file, "utf-8")) as {
        id?: string;
        status?: string;
        maturity?: string;
        response?: { actions?: unknown };
      };
      if (typeof doc?.id !== "string") return [];
      return [
        {
          file: relative(REPO_ROOT, file),
          id: doc.id,
          maturity: doc.maturity ?? null,
          status: doc.status ?? null,
          actions: Array.isArray(doc.response?.actions)
            ? (doc.response.actions as unknown[]).filter(
                (a): a is string => typeof a === "string",
              )
            : [],
          fingerprint: detectionFingerprint(doc as never),
        },
      ];
    });

    const violations = findViolations(rules as never, measurement);
    const rendered = violations
      .map((v) => `${v.id}: ${v.unearned.join(",")} — ${v.decision.reason}`)
      .join("\n");
    expect(rendered).toBe("");
  });
});
