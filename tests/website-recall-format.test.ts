/**
 * website/lib/recall.ts prints recall for the site; scripts/check-benchmark-citations.ts
 * prints it for README, and CI fails there on any other form. The site keeps its
 * own copy of the formatting (it is a separate package and cannot import from
 * scripts/), so this holds the two to the same output: the same measurement must
 * not read 0.9% on README and 1% on the home page.
 */
import { describe, it, expect } from "vitest";

import { checkRecallCell, pct1, pctLane } from "../scripts/check-benchmark-citations.js";
import { pct, pctHunt, recallLanes, toFullWidth } from "../website/lib/recall.js";
import type { BenchmarkMeasurement } from "../website/lib/stats.js";

const RATES = [0, 1, 0.5, 0.97, 0.002, 0.923, 600 / 650, 6 / 650, 19 / 3475, 1 / 3475, 2 / 451, 0.0001, 0.9995, 0.99999];

const measurement = (recall: number, enforce: number | null): BenchmarkMeasurement =>
  ({
    recall,
    enforce: enforce === null ? null : { recall: enforce, detected: 1, attacks: 1, rulesInLane: 1 },
  }) as BenchmarkMeasurement;

describe("website/lib/recall.ts", () => {
  it("prints a hunt recall exactly as README's table does", () => {
    for (const v of RATES) expect(pctHunt(v)).toBe(pct1(v));
  });

  it("prints an enforce recall exactly as README's table does", () => {
    for (const v of RATES) expect(pct(v)).toBe(pctLane(v));
  });

  it("quotes both lanes in the form README's check accepts, and hunt alone only without an enforce record", () => {
    for (const hunt of RATES) {
      for (const enforce of [null, ...RATES.filter((e) => e <= hunt)]) {
        const cell = recallLanes(measurement(hunt, enforce));
        expect(checkRecallCell(cell, hunt, enforce)).toBeNull();
      }
    }
    expect(recallLanes(measurement(0.696, null))).toBe("69.6% (hunt)");
  });

  it("converts prose punctuation to full width and leaves everything else alone", () => {
    expect(toFullWidth("hunt lane 是引擎預設,載入規則;enforce(stable):")).toBe("hunt lane 是引擎預設，載入規則；enforce（stable）：");
    expect(toFullWidth("ATR 4.1.5 2026-10-15 92.3%")).toBe("ATR 4.1.5 2026-10-15 92.3%");
  });
});
