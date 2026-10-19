/**
 * website/lib/recall.ts prints recall for the site; scripts/check-benchmark-citations.ts
 * prints it for README, and CI fails there on any other form. The site keeps its
 * own copy of the formatting (it is a separate package and cannot import from
 * scripts/), so this holds the two to the same output: the same measurement must
 * not read 0.9% on README and 1% on the home page.
 */
import { describe, it, expect } from "vitest";

import { checkRecallCell, pct1, pctLane } from "../scripts/check-benchmark-citations.js";
import { currentRecallSentence, figureMeasurements, pct, pctHunt, recallLanes, toFullWidth } from "../website/lib/recall.js";
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

  describe("currentRecallSentence", () => {
    const base = {
      atr_version: "4.1.5",
      measured_date: "2026-10-19",
      measurement_file: "data/measurements/x/2026-10-19_x.json",
    };
    const attackOnly = {
      ...base,
      source: "hackaprompt",
      samples: 4780,
      recall: 3972 / 4780,
      attacks: 4780,
      benign: 0,
      falsePositives: 0,
      enforce: { recall: 2343 / 4780, detected: 2343, attacks: 4780, rulesInLane: 103 },
    } as BenchmarkMeasurement;
    const withBenign = {
      ...base,
      source: "vendor-guardrail-suites",
      samples: 146,
      recall: 97 / 126,
      attacks: 126,
      benign: 20,
      falsePositives: 1,
      enforce: { recall: 7 / 126, detected: 7, attacks: 126, rulesInLane: 103 },
    } as BenchmarkMeasurement;
    const stats = { benchmarks: [attackOnly, withBenign] };

    it("counts attack samples, and adds the hunt lane's benign flags only where the corpus has benign samples", () => {
      expect(currentRecallSentence(stats, [{ source: "hackaprompt", label: "HackAPrompt" }])).toContain(
        "HackAPrompt (4,780 attack samples): 83.1% (hunt) / 49.0% (enforce) (ATR 4.1.5, measured 2026-10-19).",
      );
      expect(currentRecallSentence(stats, [{ source: "vendor-guardrail-suites", label: "Vendor" }])).toContain(
        "Vendor (126 attack samples): 77.0% (hunt) / 5.6% (enforce), 1 of 20 benign samples flagged (hunt) (ATR 4.1.5",
      );
    });

    it("says nothing for a source with no measurement, and lists only the measurements that exist", () => {
      expect(currentRecallSentence(stats, [{ source: "absent", label: "Absent" }])).toBe("");
      const found = figureMeasurements(stats, [
        { source: "absent", label: "Absent" },
        { source: "vendor-guardrail-suites", label: "Vendor" },
      ]);
      expect(found.map((f) => f.label)).toEqual(["Vendor"]);
    });
  });
});
