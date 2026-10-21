/**
 * The bundled rule set scans long inputs in bounded time.
 *
 * A field longer than MAX_EVAL_LENGTH used to be skipped, so what a rule cost on
 * a long input was never paid. It is now searched in windows, each costing what
 * a 100,000-character input does, so a condition that is quadratic on some text
 * costs that on every window, up to 12 per search. Two inputs are the shapes on
 * which bundled conditions were quadratic when windowing was added: a long run
 * of one character (conformance edge-020's input), and a long text of
 * space-separated words. The third is a text NFKC lengthens past
 * MAX_SCAN_LENGTH, which takes every condition through its third search. The
 * budget is conformance's own 10,000 ms, several times the measured time, so it
 * fails on a regression of that order rather than on a slow machine.
 */
import { describe, it, expect, beforeAll } from "vitest";
import { join } from "node:path";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent } from "../src/types.js";

const RULES_DIR = join(__dirname, "..", "rules");
const BUDGET_SECONDS = 10;

let engine: ATREngine;

beforeAll(async () => {
  engine = new ATREngine({ rulesDir: RULES_DIR });
  await engine.loadRules();
});

function seconds(run: () => void): number {
  const start = performance.now();
  run();
  return (performance.now() - start) / 1000;
}

describe("the bundled rule set on long inputs", () => {
  it("scans a 1,000,000-character run of one character as a SKILL.md within budget", () => {
    expect(seconds(() => engine.scanSkill("a".repeat(1_000_000)))).toBeLessThan(BUDGET_SECONDS);
  }, 300_000);

  it("scans a 300,000-character tool output of space-separated words within budget", () => {
    const unit = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor ";
    const text = unit.repeat(Math.ceil(300_000 / unit.length)).slice(0, 300_000);
    const event: AgentEvent = {
      type: "tool_response",
      timestamp: "2026-10-20T00:00:00.000Z",
      content: text,
      fields: { tool_name: "Read", tool_args: "{}", content: text, tool_response: text },
    };
    expect(seconds(() => engine.evaluate(event))).toBeLessThan(BUDGET_SECONDS);
  }, 300_000);

  it("scans a 1,000,000-character Chinese text that NFKC lengthens, as a SKILL.md, within budget", () => {
    // each sentence ends in an ellipsis, which NFKC turns into three characters, and
    // a no-break space; the normalised text is 1,086,956 characters long
    const sentence = String.fromCodePoint(
      0x9019, 0x662f, 0x4e00, 0x6bb5, 0x5f88, 0x9577, 0x7684, 0x4e2d, 0x6587, 0x6587, 0x5b57, 0xff0c,
      0x7528, 0x4f86, 0x6e2c, 0x8a66, 0x6383, 0x63cf, 0x7684, 0x6210, 0x672c, 0x2026, 0x00a0,
    );
    const text = sentence.repeat(Math.ceil(1_000_000 / sentence.length)).slice(0, 1_000_000);
    expect(seconds(() => engine.scanSkill(text))).toBeLessThan(BUDGET_SECONDS);
  }, 300_000);
});
