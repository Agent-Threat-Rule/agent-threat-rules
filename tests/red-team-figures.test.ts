/**
 * The /red-team page quotes measured figures only through the measurement
 * files: the ablation reference beside each corpus's recall comes from
 * breakdown.in_sample_ablation, so a re-measurement cannot leave a typed copy
 * stale. The sprint section's gate figures come from a committed re-run record.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { ablationClause, currentRecallSentence } from "../website/lib/recall.js";
import { ablationOf, type BenchmarkMeasurement } from "../website/lib/stats.js";

const REPO = join(import.meta.dirname, "..");
const read = (...p: string[]) => readFileSync(join(REPO, ...p), "utf-8");

/** The newest run on main of a batch in the gate re-run record (labels are "main <date>"). */
function latestMainRun<T extends { label: string; run_on: string }>(runs: readonly T[]): T {
  const main = runs.filter((r) => r.label.startsWith("main ")).sort((a, b) => a.run_on.localeCompare(b.run_on));
  return main[main.length - 1]!;
}

function latest(source: string): { file: string; m: { breakdown: Record<string, unknown> } } {
  const dir = join(REPO, "data", "measurements", source);
  const { file } = JSON.parse(read("data", "measurements", source, "latest.json")) as { file: string };
  return { file, m: JSON.parse(readFileSync(join(dir, file), "utf-8")) };
}

const tools = JSON.parse(read("website", "data", "red-team-tools.json")) as {
  name: string; hook: string; what_atr_did: string; figures?: { source: string; label: string }[];
}[];

function measurement(over: Partial<BenchmarkMeasurement>): BenchmarkMeasurement {
  return {
    source: "x", source_version: "v", atr_version: "4.1.5", measured_at: "2026-10-19T00:00:00Z", measured_date: "2026-10-19",
    samples: 100, recall: 0.5, precision: 1, f1: 0.6, fp_rate: 0, detected: 50, attacks: 100, benign: 0, falsePositives: 0,
    enforce: { recall: 0.1, detected: 10, attacks: 100, rulesInLane: 1 }, ablation: null, population: null, layers: null,
    measurement_file: "data/measurements/x/f.json", ...over,
  };
}

describe("red-team figures", () => {
  it("red-team-tools.json types no lane figure and no out-of-sample claim", () => {
    for (const t of tools) {
      for (const text of [t.hook, t.what_atr_did]) {
        expect(text, t.name).not.toMatch(/\d+(\.\d+)?%\s*\((hunt|alert|enforce)\)/);
        expect(text, t.name).not.toMatch(/out-of-sample reference/);
      }
    }
  });

  it("the HackAPrompt and vendor entries cite measurements that record an ablation reference", () => {
    for (const source of ["hackaprompt", "vendor-guardrail-suites"]) {
      expect(tools.some((t) => t.figures?.some((f) => f.source === source)), source).toBe(true);
      expect(ablationOf(latest(source).m.breakdown.in_sample_ablation), source).not.toBeNull();
    }
  });

  it("the sentence after an entry carries the ablation reference from the measurement and follows it when it changes", () => {
    const a = ablationOf(latest("hackaprompt").m.breakdown.in_sample_ablation)!;
    const m = measurement({ source: "hackaprompt", ablation: a });
    const sentence = currentRecallSentence({ benchmarks: [m] }, [{ source: "hackaprompt", label: "HackAPrompt" }]);
    expect(sentence).toContain(ablationClause(m));
    expect(sentence).toContain(`${(a.hunt.recall * 100).toFixed(1)}% (hunt)`);
    expect(sentence).toContain(`without the ${a.rulesRemoved} rules`);
    const moved = measurement({ source: "hackaprompt", ablation: { ...a, hunt: { ...a.hunt, recall: 0.5 } } });
    expect(currentRecallSentence({ benchmarks: [moved] }, [{ source: "hackaprompt", label: "HackAPrompt" }])).toContain("50.0% (hunt) / ");
    expect(ablationClause(measurement({}))).toBe("");
  });

  it("the paper is described as listed under Best Paper Awards, not as having received one", () => {
    const hack = tools.find((t) => t.name === "HackAPrompt")!;
    expect(hack.hook).toContain("listed under Best Paper Awards at EMNLP 2023");
    expect(hack.hook).not.toMatch(/received a Best Paper/);
  });

  it("the sprint and mega-scan gate figures on the page are the committed re-run record's", () => {
    const page = read("website", "app", "[locale]", "red-team", "page.tsx");
    const record = JSON.parse(read("data", "gate-reruns", "2026-10-19_red-team-rule-batches.json")) as {
      batches: { rules: { count: number }; runs: { label: string; run_on: string; commit: string; rules_failing: number; rules_flagging_a_benign_sample: number; lanes_of_rules_flagging_a_benign_sample?: Record<string, number> }[] }[];
    };
    expect(page).toContain("data/gate-reruns/2026-10-19_red-team-rule-batches.json");
    const [sprint, mega] = record.batches;
    const then = sprint!.runs.find((r) => r.label === "as of the sprint")!;
    const now = latestMainRun(sprint!.runs);
    expect(page).toContain(`added ${sprint!.rules.count} rule files`);
    expect(page).toContain(`${then.rules_failing} fail, all for missing one of their own true positives`);
    expect(page).toContain(`${now.rules_failing} fail; ${now.rules_flagging_a_benign_sample} flag at least one benign sample`);
    expect(page).toContain(`${now.lanes_of_rules_flagging_a_benign_sample!["alert+hunt"]} load in the alert and hunt lanes, ${now.lanes_of_rules_flagging_a_benign_sample!["hunt"]} in the hunt lane only`);
    expect(page).toContain(`None of the ${mega!.rules.count} flags any`);
    const megaNow = latestMainRun(mega!.runs);
    expect(page).toContain(`${megaNow.rules_failing} fail, ${megaNow.rules_flagging_a_benign_sample} of them flagging`);
    // The page names the run it quotes: its date and commit.
    for (const r of [now, megaNow]) {
      expect(page).toContain(`main ${r.commit.slice(0, 8)}`);
      expect(page).toContain(r.run_on);
    }
    const sprintMains = sprint!.runs.filter((r) => r.label.startsWith("main "));
    expect(sprintMains.length).toBeGreaterThanOrEqual(2);
    expect(page).not.toMatch(/all passing the 6-gate quality process|All 75 rules passed|All passed the 6-gate/);
  });

  it("states the import audit as occurrences in the named vendor file, and the 66.2% as not reproduced at the sprint commits", () => {
    const page = read("website", "app", "[locale]", "red-team", "page.tsx");
    expect(page).toContain("79 occur verbatim in the vendor file they name");
    expect(page).toContain("79 筆與其標示的廠商檔案逐字相同");
    expect(page).not.toContain("79 found verbatim in the vendor repos");
    expect(page).toContain("could not be reproduced at the sprint commits e9efefdd and 92c0d0fe (66.0% at best)");
    const vendor = tools.find((t) => t.name === "Promptfoo + llm-guard")!;
    expect(vendor.what_atr_did).toContain("79 occur verbatim in the vendor file they name");
  });

  it("the page's benign-FP magnitudes and mega-scan maturities are the re-run record's", () => {
    const page = read("website", "app", "[locale]", "red-team", "page.tsx");
    type Run = { label: string; run_on: string; by_check: Record<string, { flagged_samples_by_rule?: Record<string, number> }>; corpora: Record<string, number> };
    const record = JSON.parse(read("data", "gate-reruns", "2026-10-19_red-team-rule-batches.json")) as {
      batches: { runs: Run[]; rule_status_maturity_at_main: Record<string, { maturity: string }> }[];
    };
    const [sprint, mega] = record.batches;
    const now = latestMainRun(sprint!.runs);
    const flagged = (check: string) => now.by_check[check]?.flagged_samples_by_rule ?? {};
    const skill = flagged("benign_skill_corpus_fp")["ATR-2026-00454"]!;
    const extended = flagged("extended_benign_fp")["ATR-2026-00454"]!;
    expect(page).toContain(`ATR-2026-00454 (maturity test, alert and hunt lanes): ${skill} of the ${now.corpora.benign_skill_files} SKILL.md files and ${extended.toLocaleString("en-US")} of the ${now.corpora.extended_benign_samples.toLocaleString("en-US")} extended samples`);
    expect(sprint!.rule_status_maturity_at_main["ATR-2026-00454"]!.maturity).toBe("test");
    const others = Object.entries(now.by_check)
      .filter(([k]) => k.endsWith("_fp"))
      .flatMap(([, v]) => Object.entries(v.flagged_samples_by_rule ?? {}))
      .filter(([id]) => id !== "ATR-2026-00454")
      .map(([, n]) => n);
    expect(page).toContain(`every other rule flags at most ${Math.max(...others)} samples on any corpus`);
    const report = JSON.parse(read("data", "hackaprompt", "hackaprompt-eval-report.json")) as {
      ruleQuality: { topRules: { ruleId: string; tpCount: number }[] };
    };
    const tp = report.ruleQuality.topRules.find((r) => r.ruleId === "ATR-2026-00454")!.tpCount;
    expect(page).toContain(`it matches ${tp} of the 4,780 prompts in the hunt lane`);
    const maturities: Record<string, number> = {};
    for (const r of Object.values(mega!.rule_status_maturity_at_main)) maturities[r.maturity] = (maturities[r.maturity] ?? 0) + 1;
    expect(page).toContain(
      `${maturities.stable} stable, ${maturities.test} test, ${maturities.experimental} experimental, ${maturities.draft} draft`,
    );
    expect(page).not.toContain("maturity spans stable and experimental");
    expect(page).not.toContain("the same gate every rule in the standard had to clear");
    expect(page).toContain("80dbd0ab");
    expect(page).not.toMatch(/added the day before|前一天/);
  });

  it("names what the vendor ablation removed", () => {
    const a = ablationOf(latest("vendor-guardrail-suites").m.breakdown.in_sample_ablation)!;
    const clause = ablationClause({ source: "vendor-guardrail-suites", ablation: a });
    expect(clause).toContain(`without the ${a.rulesRemoved} rules that name llm-guard, promptfoo or NeMo Guardrails or carry the vendor-corpus-import tag`);
    const hack = ablationOf(latest("hackaprompt").m.breakdown.in_sample_ablation)!;
    expect(ablationClause({ source: "hackaprompt", ablation: hack })).toContain(`without the ${hack.rulesRemoved} rules whose YAML names it`);
  });

  it("says the latest gate run matched the previous one only while the record shows it did", () => {
    const page = read("website", "app", "[locale]", "red-team", "page.tsx");
    type Run = { label: string; run_on: string; rules_failing_ids: string[]; rules_flagging_a_benign_sample_ids: string[];
      by_check: Record<string, { flagged_samples_by_rule?: Record<string, number> }> };
    const record = JSON.parse(read("data", "gate-reruns", "2026-10-19_red-team-rule-batches.json")) as { batches: { runs: Run[] }[] };
    const fp = (r: Run) => JSON.stringify(Object.entries(r.by_check).filter(([k]) => k.endsWith("_fp")).sort());
    for (const b of record.batches) {
      const mains = b.runs.filter((r) => r.label.startsWith("main ")).sort((x, y) => x.run_on.localeCompare(y.run_on));
      const [prev, last] = mains.slice(-2);
      expect(last!.rules_failing_ids).toEqual(prev!.rules_failing_ids);
      expect(last!.rules_flagging_a_benign_sample_ids).toEqual(prev!.rules_flagging_a_benign_sample_ids);
      expect(fp(last!)).toBe(fp(prev!));
      expect(page).toContain(prev!.run_on);
    }
  });
});

