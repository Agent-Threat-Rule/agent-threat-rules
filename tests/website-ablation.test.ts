/**
 * The site quotes the ablation reference from the measurement file
 * (website/lib/stats.ts ablationOf), never as a typed number, in the same form
 * README and root stats.json use.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { ablationOf, populationOf } from "../website/lib/stats.js";
import { ablationLanes } from "../website/lib/ablation.js";
import { parseAblationReference } from "../src/measurement/in-sample-ablation.js";

const REPO = join(import.meta.dirname, "..");

function latest(source: string): { breakdown: Record<string, unknown> } {
  const dir = join(REPO, "data", "measurements", source);
  const { file } = JSON.parse(readFileSync(join(dir, "latest.json"), "utf-8")) as { file: string };
  return JSON.parse(readFileSync(join(dir, file), "utf-8"));
}

describe("website ablation reference", () => {
  it("reads the HackAPrompt ablation reference and population from the measurement file", () => {
    const m = latest("hackaprompt");
    const a = ablationOf(m.breakdown.in_sample_ablation)!;
    const src = parseAblationReference(m.breakdown)!;
    expect(a.key).toBe(src.key);
    expect(a.rulesRemoved).toBe(src.removed_rule_ids.length);
    expect(a.hunt).toEqual(src.hunt);
    expect(a.enforce).toEqual(src.enforce);
    expect(populationOf(m.breakdown.provenance)).toBe(601757);
  });

  it("formats it as README's prose and root stats.json cite it", () => {
    const m = latest("hackaprompt");
    const root = JSON.parse(readFileSync(join(REPO, "stats.json"), "utf-8"));
    const cite = root.benchmarks.hackaprompt.recallWithoutSourceNamedRules;
    const text = ablationLanes({ ablation: ablationOf(m.breakdown.in_sample_ablation) });
    expect(text).toBe(`${cite.hunt.toFixed(1)}% (hunt) / ${cite.enforce}% (enforce)`);
    expect(readFileSync(join(REPO, "README.md"), "utf-8")).toContain(text!);
  });

  it("returns null without a record and throws on a malformed one", () => {
    expect(ablationOf(undefined)).toBeNull();
    expect(ablationLanes({ ablation: null })).toBeNull();
    expect(() => ablationOf({ note: "x" })).toThrow(/reference/);
    expect(() => ablationOf({ reference: "a", a: { removed_rule_ids: [], lanes: { hunt: {}, enforce: {} } } })).toThrow(/malformed/);
    expect(populationOf({})).toBeNull();
  });

  it("the coverage page takes the HackAPrompt figures from the measurement, not typed numbers", () => {
    const page = readFileSync(join(REPO, "website", "app", "[locale]", "coverage", "page.tsx"), "utf-8");
    expect(page).toContain("ablationLanes(hack)");
    expect(page).toContain("count(hack.population)");
    expect(page).not.toMatch(/28\.7%|601,757|4,780/);
  });
});
