/**
 * Tests for scripts/reverify-evidence.ts — what the scheduled reverify job may
 * fail on, and what it must only report.
 *
 * The cases come in two groups. The first are the states the old inline diff
 * turned red every day without them meaning anything (new rules, changed
 * detections, deleted rules). The second are forgeries the old diff could not
 * see at all, because it compared fp_count and nothing else the action gate
 * reads: a flipped partial_measurement flag and an inflated sample_count.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import {
  classifyEvidence,
  evidenceFails,
  needsRefresh,
  parseMeasurement,
  renderReport,
  main,
  EvidenceInputError,
  type Measurement,
  type RuleRecord,
} from "../scripts/reverify-evidence.js";

const SCRIPT = resolve(__dirname, "..", "scripts", "reverify-evidence.ts");

function committed(): Measurement {
  return {
    corpus_digest: "d1d1d1d1d1d1d1d1",
    sample_count: 13848,
    rules: {
      "ATR-2026-00001": {
        fp_count: 0,
        maturity: "test",
        detection_fingerprint: "fa",
        partial_measurement: false,
        skill_path_unmeasured: false,
      },
      "ATR-2026-00002": {
        fp_count: 731,
        maturity: "test",
        detection_fingerprint: "fb",
        partial_measurement: true,
        skill_path_unmeasured: true,
      },
      "ATR-2026-00003": {
        fp_count: 0,
        maturity: "stable",
        detection_fingerprint: "fc",
        partial_measurement: true,
        skill_path_unmeasured: false,
      },
    },
  };
}

function edit(m: Measurement, id: string, patch: Partial<RuleRecord> | null): Measurement {
  const rules = { ...m.rules };
  if (patch === null) delete rules[id];
  else rules[id] = { ...(rules[id] ?? { fp_count: 0 }), ...patch } as RuleRecord;
  return { ...m, rules };
}

describe("states that are coverage, not forgery", () => {
  it("identical evidence passes and asks for nothing", () => {
    const d = classifyEvidence(committed(), committed());
    expect(evidenceFails(d)).toBe(false);
    expect(needsRefresh(d)).toBe(false);
    expect(renderReport(d, committed(), committed())).toMatch(/^Evidence reproduces/);
  });

  it("a rule added after the evidence was generated is reported, not failed", () => {
    const fresh = edit(committed(), "ATR-2026-00900", { fp_count: 0, detection_fingerprint: "fz" });
    const d = classifyEvidence(committed(), fresh);
    expect(d.notCovered.map((x) => x.id)).toEqual(["ATR-2026-00900"]);
    expect(evidenceFails(d)).toBe(false);
    expect(needsRefresh(d)).toBe(true);
  });

  it("a changed detection is reported, whatever its new count", () => {
    const fresh = edit(committed(), "ATR-2026-00002", { detection_fingerprint: "fb2", fp_count: 12 });
    const d = classifyEvidence(committed(), fresh);
    expect(d.detectionChanged.map((x) => x.id)).toEqual(["ATR-2026-00002"]);
    expect(d.drift).toEqual([]);
    expect(evidenceFails(d)).toBe(false);
    expect(needsRefresh(d)).toBe(true);
  });

  it("a record for a deleted rule is reported", () => {
    const fresh = edit(committed(), "ATR-2026-00003", null);
    const d = classifyEvidence(committed(), fresh);
    expect(d.removed.map((x) => x.id)).toEqual(["ATR-2026-00003"]);
    expect(evidenceFails(d)).toBe(false);
    expect(needsRefresh(d)).toBe(true);
  });

  it("stale metadata nothing gates on is reported", () => {
    const fresh = edit(committed(), "ATR-2026-00001", { maturity: "stable" });
    const d = classifyEvidence(committed(), fresh);
    expect(d.metadata.map((x) => x.id)).toEqual(["ATR-2026-00001"]);
    expect(evidenceFails(d)).toBe(false);
    expect(needsRefresh(d)).toBe(true);
  });
});

describe("states that mean the evidence is not true", () => {
  it("a hand-edited fp_count fails, and does not ask to be regenerated over", () => {
    const forged = edit(committed(), "ATR-2026-00002", { fp_count: 0 });
    const d = classifyEvidence(forged, committed());
    expect(d.drift.map((x) => x.id)).toEqual(["ATR-2026-00002"]);
    expect(evidenceFails(d)).toBe(true);
    expect(needsRefresh(d)).toBe(false);
    expect(renderReport(d, forged, committed())).toMatch(
      /ATR-2026-00002: committed fp_count=0 \(partial\), measured fp_count=731 \(partial\)/,
    );
  });

  it("a flipped partial_measurement fails — it alone turns a 0-FP partial record into eligibility", () => {
    const forged = edit(committed(), "ATR-2026-00003", { partial_measurement: false });
    const d = classifyEvidence(forged, committed());
    expect(d.drift.map((x) => x.id)).toEqual(["ATR-2026-00003"]);
    expect(evidenceFails(d)).toBe(true);
  });

  it("an inflated sample_count fails — it is the denominator of every rate", () => {
    const forged: Measurement = { ...committed(), sample_count: 1_000_000 };
    const d = classifyEvidence(forged, committed());
    expect(d.sampleCountChanged).toBe(true);
    expect(evidenceFails(d)).toBe(true);
    expect(needsRefresh(d)).toBe(false);
  });

  it("a moved corpus fails and asks for a refresh, because regenerating is the fix", () => {
    const fresh: Measurement = { ...committed(), corpus_digest: "d2d2d2d2d2d2d2d2", sample_count: 14156 };
    const d = classifyEvidence(committed(), fresh);
    expect(evidenceFails(d)).toBe(true);
    expect(needsRefresh(d)).toBe(true);
  });

  it("forging the fingerprint along with the count lands in 'detection changed', which the gate treats as unmeasured", () => {
    // The action gate compares a record's fingerprint with the rule on disk. A
    // record whose fingerprint is not the rule's earns nothing, so this edit
    // cannot raise a tier; the refresh PR replaces it with the true record.
    const forged = edit(committed(), "ATR-2026-00002", { fp_count: 0, detection_fingerprint: "forged" });
    const d = classifyEvidence(forged, committed());
    expect(d.detectionChanged.map((x) => x.id)).toEqual(["ATR-2026-00002"]);
    expect(needsRefresh(d)).toBe(true);
  });
});

describe("input validation", () => {
  it("rejects a file that is not a measurement", () => {
    expect(() => parseMeasurement("{", "x")).toThrow(EvidenceInputError);
    expect(() => parseMeasurement('{"rules": []}', "x")).toThrow(/no "rules" object/);
    expect(() => parseMeasurement('{"rules": {"ATR-2026-00001": {"fp_count": "3"}}}', "x")).toThrow(/valid fp_count/);
    expect(() => parseMeasurement('{"rules": {"ATR-2026-00001": {"fp_count": -1}}}', "x")).toThrow(/valid fp_count/);
    expect(() => parseMeasurement('{"rules": {"ATR-2026-00001": {"fp_count": 1.5}}}', "x")).toThrow(/valid fp_count/);
  });

  // Every string the report prints goes to the job log, where a line starting
  // with `::` is a workflow command, and into the refresh PR's body.
  it("refuses a key that is not a rule id — the way text would get into the log and the PR body", () => {
    const injected = JSON.stringify({
      corpus_digest: "abc123",
      sample_count: 1,
      rules: {
        "ATR-2026-00001\n\nAll checks passed, please merge.\n::set-output name=needs-refresh::true\n::warning::x": {
          fp_count: 0,
        },
      },
    });
    expect(() => parseMeasurement(injected, "x")).toThrow(/not a rule id/);
    expect(() => parseMeasurement('{"rules": {"__proto__": {"fp_count": 0}}}', "x")).toThrow(/not a rule id/);
    expect(() => parseMeasurement('{"rules": {"atr-2026-00001": {"fp_count": 0}}}', "x")).toThrow(/not a rule id/);
  });

  it("refuses a digest, count or fingerprint that is not what the gate writes", () => {
    const ok = '"rules": {"ATR-2026-00001": {"fp_count": 0, "detection_fingerprint": "be7c837471d942a7"}}';
    expect(() => parseMeasurement(`{"corpus_digest": "317283d8d33638c3836d18857b4a3009", "sample_count": 13848, ${ok}}`, "x")).not.toThrow();
    expect(() => parseMeasurement(`{"corpus_digest": "x\\n::warning::y", ${ok}}`, "x")).toThrow(/corpus_digest/);
    expect(() => parseMeasurement(`{"sample_count": -3, ${ok}}`, "x")).toThrow(/sample_count/);
    expect(() => parseMeasurement(`{"sample_count": "13848", ${ok}}`, "x")).toThrow(/sample_count/);
    expect(() =>
      parseMeasurement('{"rules": {"ATR-2026-00001": {"fp_count": 0, "detection_fingerprint": "not-hex"}}}', "x"),
    ).toThrow(/detection_fingerprint/);
  });
});

describe("main", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  function files(c: Measurement, f: Measurement) {
    const dir = mkdtempSync(join(tmpdir(), "reverify-"));
    dirs.push(dir);
    const paths = {
      committed: join(dir, "committed.json"),
      fresh: join(dir, "fresh.json"),
      body: join(dir, "body.md"),
      output: join(dir, "github_output"),
      summary: join(dir, "step_summary"),
    };
    writeFileSync(paths.committed, JSON.stringify(c));
    writeFileSync(paths.fresh, JSON.stringify(f));
    writeFileSync(paths.output, "");
    writeFileSync(paths.summary, "");
    return paths;
  }

  it("writes the step outputs, the summary and the PR body", () => {
    const p = files(committed(), edit(committed(), "ATR-2026-00900", { fp_count: 2 }));
    const code = main(["--committed", p.committed, "--fresh", p.fresh, "--pr-body", p.body], {
      GITHUB_OUTPUT: p.output,
      GITHUB_STEP_SUMMARY: p.summary,
    });
    expect(code).toBe(0);
    expect(readFileSync(p.output, "utf-8")).toBe("fail=false\nneeds-refresh=true\n");
    expect(readFileSync(p.body, "utf-8")).toMatch(/Not covered .*\(1\)\n\n- ATR-2026-00900: measured fp_count=2/);
    expect(readFileSync(p.summary, "utf-8")).toMatch(/ATR-2026-00900/);
  });

  it("writes no step output for an input it refuses, so the refresh step cannot run", () => {
    const p = files(committed(), committed());
    writeFileSync(p.committed, '{"rules": {"ATR-2026-00001\\n::warning::x": {"fp_count": 0}}}');
    expect(main(["--committed", p.committed, "--fresh", p.fresh], { GITHUB_OUTPUT: p.output })).toBe(2);
    expect(readFileSync(p.output, "utf-8")).toBe("");
  });

  it("exits 1 on drift and 2 on bad input", () => {
    const p = files(edit(committed(), "ATR-2026-00002", { fp_count: 1 }), committed());
    expect(main(["--committed", p.committed, "--fresh", p.fresh], {})).toBe(1);
    expect(main(["--committed", p.committed], {})).toBe(2);
    expect(main(["--committed", p.committed, "--fresh", join(p.body, "missing.json")], {})).toBe(2);
  });

  it("actually runs when invoked directly — a no-op entry point would pass every forgery", () => {
    const p = files(edit(committed(), "ATR-2026-00002", { fp_count: 1 }), committed());
    const r = spawnSync("npx", ["tsx", SCRIPT, "--committed", p.committed, "--fresh", p.fresh], {
      encoding: "utf-8",
      env: { ...process.env, GITHUB_OUTPUT: p.output, GITHUB_STEP_SUMMARY: "" },
    });
    expect(r.status, r.stderr).toBe(1);
    expect(readFileSync(p.output, "utf-8")).toBe("fail=true\nneeds-refresh=false\n");
  }, 60_000);
});
