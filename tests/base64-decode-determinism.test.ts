/**
 * decodeBase64Blocks() must return the same blocks for the same content,
 * whatever it decoded before (SPEC §6.5: a given engine version, rule and input
 * give one match outcome).
 *
 * It searched with a module-level /g regex and left the loop at the fifth
 * decoded block without resetting lastIndex, so the next call started where the
 * previous one stopped. A document with more blocks than the cap decoded its
 * first five blocks on one call and only the blocks after the sixth on the
 * next; a document decoded after it lost some or all of its own blocks. Through
 * scanSkill() and scanSkillAsync() that made the [decoded:base64] matches come
 * and go between two scans of the same text, and made one sample's result
 * depend on the samples scanned before it.
 *
 * Each test loads a fresh copy of the engine module, so it sees only the calls
 * it makes itself. The defect was state carried from one call to the next; a
 * test that inherited the previous test's state could pass or fail for a reason
 * of its neighbour's making.
 */
import { beforeEach, describe, it, expect, vi } from "vitest";
import type { ATRRule } from "../src/types.js";

type EngineModule = typeof import("../src/engine.js");

/** The cap in src/engine.ts. The fix must not move it. */
const MAX_DECODE_BLOCKS = 5;

let engineModule: EngineModule;

beforeEach(async () => {
  vi.resetModules();
  engineModule = await import("../src/engine.js");
});

const toBase64 = (text: string): string => Buffer.from(text, "utf-8").toString("base64");

/**
 * A document of `count` base64 blocks, one per line, and each block's plaintext
 * in document order. Every plaintext is printable ASCII and encodes to far more
 * than the 32 characters the block pattern needs.
 */
function documentWithBlocks(
  label: string,
  count: number,
  plaintextOf: (n: number) => string = (n) => `${label} block ${n}: plain text that decodes cleanly`,
): { readonly text: string; readonly plaintexts: readonly string[] } {
  const plaintexts = Array.from({ length: count }, (_, i) => plaintextOf(i + 1));
  const text = plaintexts.map((p, i) => `Line ${i + 1}: ${toBase64(p)}`).join("\n");
  return { text, plaintexts };
}

describe("decodeBase64Blocks determinism", () => {
  it("decodes the same first five blocks on every call with the same content", () => {
    const { decodeBase64Blocks } = engineModule;
    const doc = documentWithBlocks("same", MAX_DECODE_BLOCKS + 2);
    const expected = doc.plaintexts.slice(0, MAX_DECODE_BLOCKS);

    const calls = [1, 2, 3].map(() => decodeBase64Blocks(doc.text));

    calls.forEach((decoded, i) => expect(decoded, `call ${i + 1}`).toEqual(expected));
  });

  it.each([
    ["shorter", 2],
    ["longer", MAX_DECODE_BLOCKS + 4],
  ])(
    "decodes a %s document after one with more blocks than the cap as it does on its own",
    (label, count) => {
      const { decodeBase64Blocks } = engineModule;
      const earlier = documentWithBlocks("earlier", MAX_DECODE_BLOCKS + 1);
      const later = documentWithBlocks(label, count);
      // On its own a document decodes its first blocks, up to the cap.
      const alone = later.plaintexts.slice(0, MAX_DECODE_BLOCKS);

      decodeBase64Blocks(earlier.text);

      expect(decodeBase64Blocks(later.text)).toEqual(alone);
    },
  );
});

describe("scanSkill decoded-base64 matches are deterministic", () => {
  const RULE_ID = "ATR-2026-99050";
  const MARKER = "decoded-only-marker";

  /** A SKILL.md rule whose only possible hit is inside a decoded block. */
  const markerRule = {
    title: "base64 determinism fixture",
    id: RULE_ID,
    status: "experimental",
    description: "fixture",
    author: "test",
    date: "2026-11-01",
    severity: "high",
    tags: {
      category: "prompt-injection",
      subcategory: "test",
      confidence: "medium",
      scan_target: "skill",
    },
    agent_source: { type: "llm_io" },
    detection: {
      condition: "any",
      conditions: [{ field: "content", operator: "regex", value: MARKER, description: "fixture" }],
    },
    response: { actions: ["alert"] },
  } as unknown as ATRRule;

  // The marker sits in the first block, which every correct scan decodes; the
  // blocks after the cap are filler.
  const doc = documentWithBlocks("skill", MAX_DECODE_BLOCKS + 2, (n) =>
    n === 1
      ? `first block carries the ${MARKER} for the fixture rule`
      : `skill block ${n}: plain filler text that decodes cleanly`,
  );

  it.each(["scanSkill", "scanSkillAsync"] as const)(
    "%s reports the decoded match on every scan of the same text",
    async (method) => {
      const engine = new engineModule.ATREngine();
      engine.addRule(markerRule);

      for (const scan of [1, 2, 3]) {
        const matches =
          method === "scanSkill" ? engine.scanSkill(doc.text) : await engine.scanSkillAsync(doc.text);
        expect(
          matches.map((m) => m.rule.id),
          `scan ${scan}`,
        ).toEqual([RULE_ID]);
        expect(matches[0]?.matchedPatterns, `scan ${scan}`).toContain("[decoded:base64]");
      }
    },
  );
});
