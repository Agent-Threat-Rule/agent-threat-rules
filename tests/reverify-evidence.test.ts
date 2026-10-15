/**
 * Tests for scripts/reverify-evidence.ts — what the scheduled reverify job may
 * fail on, and what it must only report.
 *
 * Three groups. Coverage states the old inline diff turned red every day without
 * meaning anything (new rules, changed detections, deleted rules). Forgeries the
 * old diff could not see, because it compared fp_count and nothing else the
 * action gate reads. And the forgeries an adversarial review of this script
 * found against its first version: a trusted record whose rule the measurement
 * never listed, and an edited corpus list that made an edited digest look valid.
 */
import { describe, it, expect, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import {
  classifyEvidence,
  diskRules,
  evidenceFails,
  needsRefresh,
  parseMeasurement,
  renderReport,
  main,
  EvidenceInputError,
  type DiskRule,
  type Measurement,
  type RuleRecord,
} from "../scripts/reverify-evidence.js";
import { MEASUREMENT_CORPORA } from "../src/quality/action-eligibility.js";

const REPO = resolve(__dirname, "..");
const SCRIPT = join(REPO, "scripts", "reverify-evidence.ts");

function committed(): Measurement {
  return {
    corpora: [...MEASUREMENT_CORPORA],
    corpus_digest: "d1d1d1d1d1d1d1d1",
    sample_count: 13848,
    rules: {
      "ATR-2026-00001": { fp_count: 0, maturity: "test", detection_fingerprint: "fa", partial_measurement: false, skill_path_unmeasured: false },
      "ATR-2026-00002": { fp_count: 731, maturity: "test", detection_fingerprint: "fb", partial_measurement: true, skill_path_unmeasured: true },
      "ATR-2026-00003": { fp_count: 0, maturity: "stable", detection_fingerprint: "fc", partial_measurement: true, skill_path_unmeasured: false },
    },
  };
}

/** The rule files the fixture evidence describes, as the action gate would read them. */
function disk(): DiskRule[] {
  return [
    { id: "ATR-2026-00001", status: "experimental", maturity: "test", fingerprint: "fa" },
    { id: "ATR-2026-00002", status: "experimental", maturity: "test", fingerprint: "fb" },
    { id: "ATR-2026-00003", status: "experimental", maturity: "stable", fingerprint: "fc" },
    { id: "ATR-2026-00900", status: "experimental", maturity: "test", fingerprint: "f9" },
  ];
}

function edit(m: Measurement, id: string, patch: Partial<RuleRecord> | null): Measurement {
  const rules = { ...m.rules };
  if (patch === null) delete rules[id];
  else rules[id] = { ...(rules[id] ?? { fp_count: 0 }), ...patch } as RuleRecord;
  return { ...m, rules };
}

const diskWith = (id: string, patch: Partial<DiskRule>): DiskRule[] =>
  disk().map((r) => (r.id === id ? { ...r, ...patch } : r));

describe("states that are coverage, not forgery", () => {
  it("identical evidence passes and asks for nothing", () => {
    const d = classifyEvidence(committed(), committed(), disk());
    expect(evidenceFails(d)).toBe(false);
    expect(needsRefresh(d)).toBe(false);
    expect(renderReport(d, committed(), committed())).toMatch(/^Evidence reproduces/);
  });

  it("a rule added after the evidence was generated is reported, not failed", () => {
    const fresh = edit(committed(), "ATR-2026-00900", { fp_count: 0, detection_fingerprint: "f9" });
    const d = classifyEvidence(committed(), fresh, disk());
    expect(d.notCovered.map((x) => x.id)).toEqual(["ATR-2026-00900"]);
    expect(evidenceFails(d)).toBe(false);
    expect(needsRefresh(d)).toBe(true);
  });

  it("a record whose rule changed detection since is reported — the gate does not trust it", () => {
    const fresh = edit(committed(), "ATR-2026-00002", { detection_fingerprint: "fb2", fp_count: 12 });
    const d = classifyEvidence(committed(), fresh, diskWith("ATR-2026-00002", { fingerprint: "fb2" }));
    expect(d.detectionChanged.map((x) => x.id)).toEqual(["ATR-2026-00002"]);
    expect(d.drift).toEqual([]);
    expect(evidenceFails(d)).toBe(false);
    expect(needsRefresh(d)).toBe(true);
  });

  it("a record for a rule id no file carries is reported", () => {
    const gone = disk().filter((r) => r.id !== "ATR-2026-00003");
    const d = classifyEvidence(committed(), edit(committed(), "ATR-2026-00003", null), gone);
    expect(d.removed.map((x) => x.id)).toEqual(["ATR-2026-00003"]);
    expect(evidenceFails(d)).toBe(false);
    expect(needsRefresh(d)).toBe(true);
  });

  it("a changed record for a deprecated rule is reported — the gate skips the rule", () => {
    const d = classifyEvidence(
      committed(),
      edit(committed(), "ATR-2026-00001", { fp_count: 4 }),
      diskWith("ATR-2026-00001", { status: "deprecated" }),
    );
    expect(d.inert.map((x) => x.id)).toEqual(["ATR-2026-00001"]);
    expect(evidenceFails(d)).toBe(false);
  });

  it("stale metadata nothing gates on is reported", () => {
    const fresh = edit(committed(), "ATR-2026-00001", { maturity: "stable" });
    const d = classifyEvidence(committed(), fresh, disk());
    expect(d.metadata.map((x) => x.id)).toEqual(["ATR-2026-00001"]);
    expect(evidenceFails(d)).toBe(false);
    expect(needsRefresh(d)).toBe(true);
  });
});

describe("states that mean the evidence is not true", () => {
  it("a hand-edited fp_count fails, and does not ask to be regenerated over", () => {
    const forged = edit(committed(), "ATR-2026-00002", { fp_count: 0 });
    const d = classifyEvidence(forged, committed(), disk());
    expect(d.drift.map((x) => x.id)).toEqual(["ATR-2026-00002"]);
    expect(evidenceFails(d)).toBe(true);
    expect(needsRefresh(d)).toBe(false);
    expect(renderReport(d, forged, committed())).toMatch(
      /ATR-2026-00002: committed fp_count=0 \(partial\), measured fp_count=731 \(partial\)/,
    );
  });

  it("a flipped partial_measurement fails — it alone turns a 0-FP partial record into eligibility", () => {
    const forged = edit(committed(), "ATR-2026-00003", { partial_measurement: false });
    expect(evidenceFails(classifyEvidence(forged, committed(), disk()))).toBe(true);
  });

  it("an inflated sample_count fails — it is the denominator of every rate", () => {
    const d = classifyEvidence({ ...committed(), sample_count: 1_000_000 }, committed(), disk());
    expect(d.sampleCountChanged).toBe(true);
    expect(evidenceFails(d)).toBe(true);
    expect(needsRefresh(d)).toBe(false);
  });

  it("a trusted record the measurement did not reproduce at all fails", () => {
    // The rule is live and its fingerprint matches, so the gate grants on this
    // record; a listing that skipped the rule (a quoted id, a symlink) left the
    // fresh file without it. A first version of this script read that as
    // "rule removed".
    const d = classifyEvidence(committed(), edit(committed(), "ATR-2026-00001", null), disk());
    expect(d.drift.map((x) => x.id)).toEqual(["ATR-2026-00001"]);
    expect(evidenceFails(d)).toBe(true);
    expect(renderReport(d, committed(), committed())).toMatch(
      /ATR-2026-00001: committed fp_count=0, measured no record/,
    );
  });

  it("a trusted record the measurement reproduced under another detection fails", () => {
    const fresh = edit(committed(), "ATR-2026-00001", { detection_fingerprint: "ff" });
    expect(evidenceFails(classifyEvidence(committed(), fresh, disk()))).toBe(true);
  });

  it("a moved corpus fails and asks for no refresh", () => {
    const fresh: Measurement = { ...committed(), corpus_digest: "d2d2d2d2d2d2d2d2" };
    const d = classifyEvidence(committed(), fresh, disk());
    expect(evidenceFails(d)).toBe(true);
    expect(needsRefresh(d)).toBe(false);
  });

  it("an edited corpus list fails — the gate recomputes the digest over whatever list the file names", () => {
    const forged: Measurement = { ...committed(), corpora: [...MEASUREMENT_CORPORA, "data/does-not-exist"] };
    const d = classifyEvidence(forged, committed(), disk());
    expect(d.corporaChanged).toBe(true);
    expect(evidenceFails(d)).toBe(true);
    expect(needsRefresh(d)).toBe(false);
    expect(evidenceFails(classifyEvidence({ ...committed(), corpora: undefined }, committed(), disk()))).toBe(true);
  });

  it("forging the fingerprint along with the count earns nothing: the gate no longer trusts the record", () => {
    const forged = edit(committed(), "ATR-2026-00002", { fp_count: 0, detection_fingerprint: "0f0f" });
    const d = classifyEvidence(forged, committed(), disk());
    expect(d.detectionChanged.map((x) => x.id)).toEqual(["ATR-2026-00002"]);
  });
});

describe("against the repository itself", () => {
  it("the engine and the gate's reader fingerprint every rule the same way", async () => {
    // Fresh records carry fingerprints computed on engine-loaded rules; trust is
    // decided on fingerprints the gate computes on js-yaml documents. If those
    // ever diverged, every affected record would sit in "detection changed"
    // forever: never trusted, never red.
    const { ATREngine } = await import("../src/engine.js");
    const { detectionFingerprint } = await import("../src/quality/action-eligibility.js");
    const engine = new ATREngine({ rulesDir: join(REPO, "rules") });
    expect(await engine.loadRules()).toBeGreaterThan(800);
    const byEngine = new Map(engine.getRules().map((r) => [r.id, detectionFingerprint(r as never)]));
    const mismatched = diskRules(join(REPO, "rules"))
      .filter((r) => byEngine.has(r.id) && byEngine.get(r.id) !== r.fingerprint)
      .map((r) => r.id);
    expect(mismatched).toEqual([]);
  });

  it("the committed evidence reproduces against itself under the gate's own reader", () => {
    const rules = diskRules(join(REPO, "rules"));
    expect(rules.length).toBeGreaterThan(800);
    const evidence = parseMeasurement(
      readFileSync(join(REPO, "data/benign-fp-measurement.json"), "utf-8"),
      "evidence",
    );
    const d = classifyEvidence(evidence, evidence, rules);
    expect(evidenceFails(d)).toBe(false);
    expect(d.drift).toEqual([]);
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

  it("refuses a digest, count, fingerprint or corpus list that is not what the gate writes", () => {
    const ok = '"rules": {"ATR-2026-00001": {"fp_count": 0, "detection_fingerprint": "be7c837471d942a7"}}';
    expect(() =>
      parseMeasurement(`{"corpus_digest": "317283d8d33638c3836d18857b4a3009", "sample_count": 13848, ${ok}}`, "x"),
    ).not.toThrow();
    expect(() => parseMeasurement(`{"corpus_digest": "not hex", ${ok}}`, "x")).toThrow(/corpus_digest/);
    expect(() => parseMeasurement(`{"sample_count": -3, ${ok}}`, "x")).toThrow(/sample_count/);
    expect(() => parseMeasurement(`{"sample_count": "13848", ${ok}}`, "x")).toThrow(/sample_count/);
    expect(() => parseMeasurement(`{"corpora": "data", ${ok}}`, "x")).toThrow(/corpora/);
    expect(() =>
      parseMeasurement('{"rules": {"ATR-2026-00001": {"fp_count": 0, "detection_fingerprint": "not-hex"}}}', "x"),
    ).toThrow(/detection_fingerprint/);
  });

  it("quotes the parse error, so raw characters near the error cannot reach the log", () => {
    expect(() => parseMeasurement('{"rules": {"a\n::error::x', "x")).toThrow(EvidenceInputError);
    try {
      parseMeasurement('{"rules": {"a\n::error::x', "x");
    } catch (e) {
      expect((e as Error).message).not.toMatch(/\n/);
    }
  });
});

describe("main", () => {
  const dirs: string[] = [];
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });

  function workspace(c: Measurement, f: Measurement) {
    const dir = mkdtempSync(join(tmpdir(), "reverify-"));
    dirs.push(dir);
    const rules = join(dir, "rules");
    mkdirSync(join(rules, "a"), { recursive: true });
    // Fixture rules written the ways a grep for `^id: ATR-` would miss.
    writeFileSync(join(rules, "a", "one.yaml"), "id: 'ATR-2026-00001'\ndetection: {}\n");
    writeFileSync(join(rules, "a", "two.yaml"), 'id:  "ATR-2026-00002"\ndetection: {}\n');
    const paths = {
      dir,
      rules,
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

  const real = (): Measurement =>
    parseMeasurement(readFileSync(join(REPO, "data/benign-fp-measurement.json"), "utf-8"), "evidence");
  const withCount = (): [string, RuleRecord] =>
    Object.entries(real().rules).find(([, r]) => r.fp_count > 0) as [string, RuleRecord];

  it("--list-ids names a rule whose id the evidence parser would refuse", () => {
    const p = workspace(committed(), committed());
    writeFileSync(join(p.rules, "a", "odd.yaml"), "id: ATR-26-1\ndetection: {}\n");
    const r = spawnSync("npx", ["tsx", SCRIPT, "--list-ids", "--rules", p.rules], { encoding: "utf-8" });
    expect(r.status).toBe(2);
    expect(r.stderr).toMatch(/odd\.yaml: id "ATR-26-1" is not ATR-YYYY-NNNNN/);
  }, 60_000);

  it("--list-ids lists what the gate's reader sees, quoted ids included", () => {
    const p = workspace(committed(), committed());
    const r = spawnSync("npx", ["tsx", SCRIPT, "--list-ids", "--rules", p.rules], { encoding: "utf-8" });
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toBe("ATR-2026-00001\nATR-2026-00002\n");
  }, 60_000);

  it("writes the step outputs, the summary and the PR body", () => {
    const empty: Measurement = { ...committed(), rules: {} };
    const p = workspace(empty, edit(empty, "ATR-2026-00900", { fp_count: 2 }));
    const code = main(
      ["--committed", p.committed, "--fresh", p.fresh, "--rules", p.rules, "--pr-body", p.body],
      { GITHUB_OUTPUT: p.output, GITHUB_STEP_SUMMARY: p.summary },
    );
    expect(code).toBe(0);
    expect(readFileSync(p.output, "utf-8")).toBe("fail=false\nneeds-refresh=true\n");
    expect(readFileSync(p.body, "utf-8")).toMatch(/Not covered .*\(1\)\n\n- ATR-2026-00900: measured fp_count=2/);
    expect(readFileSync(p.summary, "utf-8")).toMatch(/ATR-2026-00900/);
  });

  it("writes no step output for an input it refuses, so the refresh job cannot run", () => {
    const p = workspace(committed(), committed());
    writeFileSync(p.committed, '{"rules": {"ATR-2026-00001\\n::warning::x": {"fp_count": 0}}}');
    expect(main(["--committed", p.committed, "--fresh", p.fresh, "--rules", p.rules], { GITHUB_OUTPUT: p.output })).toBe(2);
    expect(readFileSync(p.output, "utf-8")).toBe("");
  });

  it("exits 1 on a forged number on a trusted record and 2 on bad input", () => {
    const [id, record] = withCount();
    const p = workspace(edit(real(), id, { fp_count: record.fp_count + 1 }), real());
    expect(main(["--committed", p.committed, "--fresh", p.fresh], {})).toBe(1);
    expect(main(["--committed", p.committed], {})).toBe(2);
    expect(main(["--committed", p.committed, "--fresh", join(p.dir, "missing.json")], {})).toBe(2);
  });

  it("actually runs when invoked directly — a no-op entry point would pass every forgery", () => {
    const [id, record] = withCount();
    const p = workspace(edit(real(), id, { fp_count: record.fp_count + 1 }), real());
    const r = spawnSync("npx", ["tsx", SCRIPT, "--committed", p.committed, "--fresh", p.fresh], {
      encoding: "utf-8",
      env: { ...process.env, GITHUB_OUTPUT: p.output, GITHUB_STEP_SUMMARY: "" },
    });
    expect(r.status, r.stderr).toBe(1);
    expect(readFileSync(p.output, "utf-8")).toBe("fail=true\nneeds-refresh=false\n");
  }, 60_000);
});
