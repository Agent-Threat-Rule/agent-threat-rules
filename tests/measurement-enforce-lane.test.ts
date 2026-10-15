/**
 * Tests for the enforce-lane half of a measurement: `breakdown.enforce_lane`.
 *
 * WHY THIS FILE EXISTS
 *
 * Every measurement's `metrics.recall` is a hunt-lane figure — the runners
 * build `new ATREngine({ rulesDir })`, and an engine given no lane loads every
 * maturity. The enforce lane, the one to run with blocking on, loads only
 * `maturity: stable`. On ATR 4.1.5 the headline garak corpus scored 600/650 in
 * hunt and 6/650 in enforce (one-off replays of each benchmark's own detection
 * loop), and nothing recorded the second figure, so the README could only
 * carry it as a replay nobody refreshed.
 *
 * The runners now re-run their own detection loop on an enforce-lane engine and
 * record the result beside the headline. These tests pin what that record is
 * allowed to say: a figure whose denominator is not the headline's, whose
 * recall disagrees with its own counts, or that came from an engine in another
 * lane, is a number with nothing behind it.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { ATREngine } from "../src/engine.js";
import { detectedOnPromptChannels, promptChannelShapes } from "../src/corpus-event.js";
import {
  MeasurementSchemaError,
  parseEnforceLaneRecall,
  parseMeasurement,
} from "../src/measurement/schema.js";
import {
  ENFORCE_LANE_NOTE,
  enforceLaneRecall,
  enforceLaneRecallOf,
  loadEnforceLaneEngine,
  rulesInLane,
  type EnforceLaneEngine,
} from "../src/measurement/enforce-lane.js";

const REPO = resolve(__dirname, "..");
const RULES = join(REPO, "rules");

/** A measurement the schema accepted before this change, plus an enforce_lane. */
function measurement(enforce: unknown, confusion = { tp: 600, fp: 0, tn: 0, fn: 50 }): Record<string, unknown> {
  return {
    schema_version: "1",
    source: "garak",
    source_version: "inthewild-jailbreak-corpus-650",
    atr_version: "4.1.5",
    atr_commit: "abc1234",
    rules_loaded: 830,
    measured_at: "2026-10-15T05:00:00.000Z",
    samples: 650,
    metrics: { recall: 600 / 650, precision: 1, f1: 0.96, fp_rate: 0 },
    confusion,
    breakdown: { family: "inthewild", enforce_lane: enforce },
  };
}

const record = (over: Record<string, unknown> = {}) => ({
  lane: "enforce",
  detected: 6,
  attacks: 650,
  recall: 6 / 650,
  rules_in_lane: 103,
  note: ENFORCE_LANE_NOTE,
  ...over,
});

describe("enforceLaneRecall", () => {
  it("records detected over attacks, the lane, the rules the lane loads, and what the figure is", () => {
    expect(enforceLaneRecall({ detected: 6, attacks: 650, rulesInLane: 103 })).toEqual(record());
  });

  it("refuses counts that cannot describe a run", () => {
    expect(() => enforceLaneRecall({ detected: 651, attacks: 650, rulesInLane: 1 })).toThrow(/detected/);
    expect(() => enforceLaneRecall({ detected: -1, attacks: 650, rulesInLane: 1 })).toThrow();
    expect(() => enforceLaneRecall({ detected: 1.5, attacks: 650, rulesInLane: 1 })).toThrow();
    expect(() => enforceLaneRecall({ detected: 0, attacks: 650, rulesInLane: -1 })).toThrow();
  });

  it("refuses an empty attack set: 0 of 0 is not a recall", () => {
    expect(() => enforceLaneRecall({ detected: 0, attacks: 0, rulesInLane: 10 })).toThrow(/attacks/);
  });

  it("says in the record itself that it is not the headline", () => {
    expect(ENFORCE_LANE_NOTE).toMatch(/metrics\.recall/);
    expect(ENFORCE_LANE_NOTE).toMatch(/hunt/);
    expect(ENFORCE_LANE_NOTE).toMatch(/stable/);
  });
});

describe("parseEnforceLaneRecall / parseMeasurement", () => {
  it("accepts a well-formed record and returns it unchanged", () => {
    expect(parseEnforceLaneRecall(record())).toEqual(record());
    const m = parseMeasurement(measurement(record()));
    expect((m.breakdown as Record<string, unknown>).enforce_lane).toEqual(record());
  });

  it("still accepts a measurement with no enforce_lane (history is immutable)", () => {
    const old = measurement(undefined);
    delete (old.breakdown as Record<string, unknown>).enforce_lane;
    expect(() => parseMeasurement(old)).not.toThrow();
  });

  it.each([
    ["a lane other than enforce", { lane: "hunt" }],
    ["a recall that disagrees with its own counts", { recall: 0.5 }],
    ["more detections than attacks", { detected: 700, recall: 700 / 650 }],
    ["a non-integer count", { detected: 6.5, recall: 6.5 / 650 }],
    ["no attacks", { attacks: 0, detected: 0, recall: 0 }],
    ["a missing rule count", { rules_in_lane: undefined }],
    ["no note", { note: "" }],
  ])("rejects %s", (_name, over) => {
    expect(() => parseEnforceLaneRecall(record(over))).toThrow(MeasurementSchemaError);
    expect(() => parseMeasurement(measurement(record(over)))).toThrow(MeasurementSchemaError);
  });

  it("rejects an enforce figure measured over a different sample set than the headline", () => {
    // tp + fn is the headline's attack count; the enforce run must cover the same samples.
    expect(() => parseMeasurement(measurement(record({ attacks: 640, recall: 6 / 640 })))).toThrow(
      /enforce_lane\.attacks/,
    );
  });

  it("names the field that failed", () => {
    try {
      parseMeasurement(measurement(record({ lane: "alert" })));
      expect.unreachable();
    } catch (err) {
      expect((err as MeasurementSchemaError).path).toBe("$.breakdown.enforce_lane.lane");
    }
  });
});

describe("rulesInLane", () => {
  const rules = [
    { maturity: "stable", status: "experimental" },
    { maturity: " stable ", status: "stable" },
    { maturity: "test", status: "experimental" },
    { maturity: "experimental", status: "experimental" },
    { maturity: "stable", status: "draft" },
    { maturity: "stable", status: "deprecated" },
    { maturity: "deprecated", status: "stable" },
    { maturity: undefined, status: "experimental" },
    { maturity: "needs-human-poc", status: "experimental" },
  ];

  it("counts what the engine's own gates admit: status not draft/deprecated, maturity stable", () => {
    expect(rulesInLane(rules, "enforce")).toBe(2);
    expect(rulesInLane(rules, "alert")).toBe(3);
    // hunt admits every maturity but a retired one, and never a skipped status.
    expect(rulesInLane(rules, "hunt")).toBe(6);
  });
});

describe("loadEnforceLaneEngine", () => {
  let lane: EnforceLaneEngine;
  let hunt: ATREngine;
  let prompts: string[];

  beforeAll(async () => {
    lane = await loadEnforceLaneEngine({ rulesDir: RULES });
    hunt = new ATREngine({ rulesDir: RULES });
    await hunt.loadRules();
    const corpus = JSON.parse(
      readFileSync(join(REPO, "data", "test-corpora", "garak-full", "inthewild.json"), "utf8"),
    ) as { prompts: string[] };
    // The whole corpus: only a handful of its prompts reach a stable rule at
    // all, and a slice that reaches none would let both tests below pass
    // without asserting anything. The enforce engine evaluates 1 rule in 8,
    // so this stays cheap; hunt runs only on the prompts enforce detects.
    prompts = corpus.prompts;
  });

  it("returns an engine pinned to the enforce lane, with every rule loaded", () => {
    expect(lane.engine.getLane()).toBe("enforce");
    expect(lane.engine.getRuleCount()).toBe(hunt.getRuleCount());
    expect(lane.rulesInLane).toBe(rulesInLane(lane.engine.getRules(), "enforce"));
    expect(lane.rulesInLane).toBeGreaterThan(0);
    expect(lane.rulesInLane).toBeLessThan(lane.engine.getRuleCount());
  });

  it("fires only rules counted in the lane", () => {
    const inLane = new Set(
      lane.engine
        .getRules()
        .filter((r) => rulesInLane([r], "enforce") === 1)
        .map((r) => r.id),
    );
    let fired = 0;
    for (const prompt of prompts) {
      for (const shape of promptChannelShapes(prompt)) {
        for (const m of lane.engine.evaluate(shape.event)) {
          fired += 1;
          expect(inLane.has(m.rule.id), m.rule.id).toBe(true);
        }
      }
    }
    // Not vacuous: some stable rule must fire, or nothing above was checked.
    expect(fired).toBeGreaterThan(0);
  });

  it("detects a subset of what the same loop detects in hunt", () => {
    const detected = prompts.filter((p) => detectedOnPromptChannels(lane.engine, p));
    expect(detected.length).toBeGreaterThan(0);
    for (const prompt of detected) expect(detectedOnPromptChannels(hunt, prompt)).toBe(true);
  });

  it("refuses a rules directory that loads nothing, rather than reporting 0 recall", async () => {
    const empty = mkdtempSync(join(tmpdir(), "enforce-lane-empty-"));
    try {
      await expect(loadEnforceLaneEngine({ rulesDir: empty })).rejects.toThrow(/no rules/i);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });
});

describe("enforceLaneRecallOf", () => {
  it("runs the caller's own detection predicate on the enforce engine, once per sample", () => {
    const engine = { getLane: () => "enforce" } as unknown as ATREngine;
    const seen: unknown[] = [];
    const out = enforceLaneRecallOf(
      ["a", "bb", "ccc", "dddd"],
      (e, s) => {
        seen.push(e);
        return s.length % 2 === 0;
      },
      { engine, rulesInLane: 7 },
    );
    expect(seen).toHaveLength(4);
    expect(seen.every((e) => e === engine)).toBe(true);
    expect(out).toEqual(enforceLaneRecall({ detected: 2, attacks: 4, rulesInLane: 7 }));
  });

  it("refuses an engine that is not in the enforce lane", () => {
    const engine = { getLane: () => "hunt" } as unknown as ATREngine;
    expect(() => enforceLaneRecallOf(["a"], () => true, { engine, rulesInLane: 1 })).toThrow(/enforce/);
  });
});
