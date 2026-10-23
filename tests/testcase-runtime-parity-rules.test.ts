/**
 * No true positive of a rule in rules/ passes only through a copy the test event
 * makes.
 *
 * `atr test` passes a case on the wide event buildEventFromTestCase builds
 * (src/testcase-event.ts), which offers the input under every alias a rule might
 * read. caseMatchesAtRuntime runs it on what the producers put on an event of
 * each type, the engine deciding which types the rule runs on. A true positive
 * that passes the first and not the second matches only through a value no event
 * carries where the rule reads it; `atr test` lists it under harnessOnly and
 * still passes it. This test fails on it, so a new rule or a rule edit cannot
 * add one. The fix is the case's or the rule's: name the field the payload
 * arrives in, or read the field it does.
 *
 * It does not reach a true positive its rule matches as a skill document
 * (scan_target skill or both), which a skill scan does present, nor a trace
 * rule's: the case's trace rides on an event of every type, though no producer
 * in this repository attaches one.
 *
 * Each rule is put alone in an engine the way `atr test` puts it there
 * (asTestedRule, status experimental); the engine runs an extended
 * agent_source type where its base type runs. A rule of a type the engine
 * withholds from typed events (WITHHELD_SOURCE_TYPES in src/engine.ts) is left
 * out, as `atr test` reports it unevaluable rather than running its cases.
 * `atr test` also loads the bundled rules beside it, which a verdict filtered to
 * the rule's id does not depend on.
 */
import { describe, it, expect } from "vitest";
import { ATREngine, WITHHELD_SOURCE_TYPES } from "../src/engine.js";
import { loadRulesFromDirectory } from "../src/loader.js";
import { asTestedRule, caseLabel, caseMatches, caseMatchesAtRuntime } from "../src/testcase-event.js";

const RULES_DIR = new URL("../rules", import.meta.url).pathname;

describe("the true positives of the rules in rules/", () => {
  it("all match on an event a producer could build, not only through the test event's copies", () => {
    const harnessOnly: string[] = [];
    let checked = 0;
    for (const r of loadRulesFromDirectory(RULES_DIR)) {
      if (r.detection?.method === "behavioral" || !r.test_cases) continue;
      const sourceType = r.agent_source?.type;
      if (typeof sourceType === "string" && Object.hasOwn(WITHHELD_SOURCE_TYPES, sourceType)) continue;
      const engine = new ATREngine();
      engine.addRule(asTestedRule(r));
      for (const raw of r.test_cases.true_positives ?? []) {
        const tc = raw as unknown as Record<string, unknown>;
        checked++;
        if (caseMatches(engine, r, tc) && !caseMatchesAtRuntime(engine, r, tc)) {
          harnessOnly.push(`${r.id}: ${caseLabel(tc).slice(0, 100)}`);
        }
      }
    }
    expect(checked, "no true positive was checked: did rules/ load?").toBeGreaterThan(0);
    expect(
      harnessOnly,
      "these true positives match only through a copy the test event makes (src/testcase-event.ts " +
        "caseMatchesAtRuntime): name the field the payload arrives in, or fix the rule",
    ).toEqual([]);
  });
});
