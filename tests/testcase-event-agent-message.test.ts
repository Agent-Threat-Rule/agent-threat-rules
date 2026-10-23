/**
 * A test case's own agent_message is the one its event carries.
 *
 * buildEventFromTestCase (src/testcase-event.ts) set agent_message from the case
 * and then copied the event's content over it, so a case that names an
 * agent_message beside its input was run on the input there: a true negative
 * whose agent_message holds an attack passed without that text being read. No
 * case on main names an agent_message.
 */
import { describe, it, expect } from "vitest";
import { ATREngine } from "../src/engine.js";
import { buildEventFromTestCase } from "../src/testcase-event.js";
import type { ATRRule } from "../src/types.js";

const keyedOnMessage = {
  id: "ATR-2026-97103",
  title: "test-event probe",
  status: "experimental",
  maturity: "test",
  severity: "high",
  description: "fixture rule for the test-case event",
  author: "test",
  date: "2026/10/19",
  tags: { category: "prompt-injection", scan_target: "runtime", confidence: "high" },
  agent_source: { type: "llm_io", framework: ["any"], provider: ["any"] },
  detection: {
    condition: "any",
    conditions: [{ field: "agent_message", operator: "regex", value: "zebracorn", description: "probe" }],
  },
  response: { actions: ["alert"] },
} as unknown as ATRRule;

describe("a test case's own agent_message", () => {
  const tc = { input: "nothing to see here", agent_message: "a zebracorn attack" };

  it("is the agent_message of its event", () => {
    expect(buildEventFromTestCase(tc, keyedOnMessage).fields?.["agent_message"]).toBe("a zebracorn attack");
  });

  it("is read by a rule keyed on it", () => {
    const engine = new ATREngine();
    engine.addRule(keyedOnMessage);
    const fired = engine.evaluate(buildEventFromTestCase(tc, keyedOnMessage)).some((m) => m.rule.id === keyedOnMessage.id);
    expect(fired).toBe(true);
  });

  it("falls back to the content when the case names none", () => {
    expect(buildEventFromTestCase({ input: "plain text" }, keyedOnMessage).fields?.["agent_message"]).toBe("plain text");
  });
});
