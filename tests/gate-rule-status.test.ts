/**
 * Tests for scripts/gate-rule-status.ts — the ratchet that stops new rules
 * from shipping inert.
 *
 * WHAT IS BEING PROTECTED
 *   `status: draft` means the engine never evaluates the rule, in any lane
 *   (src/engine.ts drops draft and deprecated before the lane gate). A rule
 *   authored as draft validates, tests green, and detects nothing. The gate
 *   makes that state unreachable for anything not already recorded as debt.
 *
 * Contracts pinned here:
 *   1. A draft rule with no baseline entry fails, and the failure message says
 *      what draft means and what to write instead.
 *   2. A rule flipped INTO draft fails too — the baseline records ids, so a
 *      previously live rule that turns draft is simply not in it.
 *   3. Baselined drafts pass. That is the existing backlog, and failing it
 *      would stop all rule work (same reasoning as the maturity-FP and RE2
 *      ratchets).
 *   4. --write-baseline can only SHRINK. Widening is the one edit that would
 *      make this gate lie, so it is not automatable.
 *   5. An unreadable rule file fails. "Cannot determine the status" must never
 *      be reported as "not draft".
 *   6. The engine line numbers in the message are read from src/engine.ts, not
 *      hardcoded, so the message cannot rot into a lie.
 *
 * The gate runs against a fixture rules/ tree, so it never depends on the
 * current state of the real corpus.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  parseCliOptions,
  scanCorpus,
  parseBaseline,
  loadBaseline,
  compareToBaseline,
  tightenBaseline,
  findEngineSkip,
  draftExplanation,
  resolveExitCode,
  runGate,
  main,
  StatusGateUsageError,
  EXIT_OK,
  EXIT_FAIL,
  EXIT_USAGE,
  type StatusGateDeps,
  type StatusGateOptions,
} from "../scripts/gate-rule-status.js";

const OPTIONS: StatusGateOptions = {
  writeBaseline: false,
  strictSuspicious: false,
  json: false,
};

/** A minimal rule document. Only the fields this gate reads have to be real. */
function fixtureRule(
  id: string,
  status: string,
  extra: { maturity?: string; severity?: string; tps?: number } = {},
): string {
  const tps = extra.tps ?? 0;
  return [
    `id: ${id}`,
    `title: fixture ${id}`,
    `status: ${status}`,
    `maturity: ${extra.maturity ?? "test"}`,
    `severity: ${extra.severity ?? "high"}`,
    "test_cases:",
    "  true_positives:",
    ...Array.from({ length: tps }, (_, i) => `    - "attack sample ${i}"`),
    "  true_negatives:",
    '    - "benign sample"',
    "",
  ].join("\n");
}

interface Fixture {
  readonly root: string;
  readonly deps: StatusGateDeps;
}

let fixture: Fixture;

function makeFixture(): Fixture {
  const root = mkdtempSync(join(tmpdir(), "atr-status-gate-"));
  mkdirSync(join(root, "rules", "prompt-injection"), { recursive: true });
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(
    join(root, "src", "engine.ts"),
    [
      "// line 1",
      "// line 2",
      "      if (rule.status === 'deprecated' || rule.status === 'draft') continue;",
      "",
    ].join("\n"),
    "utf-8",
  );
  return {
    root,
    deps: {
      repoRoot: root,
      rulesDir: join(root, "rules"),
      baselinePath: join(root, "baseline.json"),
      enginePath: join(root, "src", "engine.ts"),
      now: () => "2026-07-29T00:00:00.000Z",
    },
  };
}

function addRule(
  id: string,
  status: string,
  extra: { maturity?: string; severity?: string; tps?: number } = {},
): void {
  writeFileSync(
    join(fixture.root, "rules", "prompt-injection", `${id}-fixture.yaml`),
    fixtureRule(id, status, extra),
    "utf-8",
  );
}

function writeBaselineFile(ids: readonly string[]): void {
  writeFileSync(
    fixture.deps.baselinePath,
    `${JSON.stringify({ generatedAt: "", note: "", corpus: { rules: 0, draftRules: ids.length }, knownDraft: ids }, null, 2)}\n`,
    "utf-8",
  );
}

function readBaselineFile(): { knownDraft: string[] } {
  return JSON.parse(readFileSync(fixture.deps.baselinePath, "utf-8"));
}

beforeEach(() => {
  fixture = makeFixture();
});

afterEach(() => {
  rmSync(fixture.root, { recursive: true, force: true });
});

describe("parseCliOptions", () => {
  it("defaults to gate semantics", () => {
    expect(parseCliOptions([])).toEqual({
      writeBaseline: false,
      strictSuspicious: false,
      json: false,
    });
  });

  it("parses each flag", () => {
    const o = parseCliOptions(["--write-baseline", "--strict-suspicious", "--json"]);
    expect(o).toEqual({ writeBaseline: true, strictSuspicious: true, json: true });
  });

  it("rejects an unknown flag rather than silently ignoring it", () => {
    expect(() => parseCliOptions(["--no-really-pass"])).toThrow(StatusGateUsageError);
  });
});

describe("corpus scan", () => {
  it("reads status, maturity, severity and TP count from each rule", () => {
    addRule("ATR-2026-90001", "experimental", { maturity: "stable", severity: "critical", tps: 2 });
    const scan = scanCorpus(fixture.deps.rulesDir, fixture.root);
    expect(scan.rules).toHaveLength(1);
    expect(scan.rules[0]).toMatchObject({
      id: "ATR-2026-90001",
      status: "experimental",
      maturity: "stable",
      severity: "critical",
      truePositives: 2,
    });
    expect(scan.unreadable).toHaveLength(0);
  });

  it("reports an unparsable file instead of dropping it from the scan", () => {
    writeFileSync(
      join(fixture.root, "rules", "prompt-injection", "broken.yaml"),
      "id: ATR-2026-90002\nstatus: [unclosed\n",
      "utf-8",
    );
    const scan = scanCorpus(fixture.deps.rulesDir, fixture.root);
    expect(scan.rules).toHaveLength(0);
    expect(scan.unreadable).toHaveLength(1);
    expect(scan.unreadable[0].reason).toMatch(/parse failed/i);
  });

  it("reports a rule with no status field — absence is not 'live'", () => {
    writeFileSync(
      join(fixture.root, "rules", "prompt-injection", "nostatus.yaml"),
      "id: ATR-2026-90003\ntitle: no status here\n",
      "utf-8",
    );
    const scan = scanCorpus(fixture.deps.rulesDir, fixture.root);
    expect(scan.unreadable[0].reason).toMatch(/no `status:` field/);
  });
});

describe("baseline parsing", () => {
  it("refuses a baseline whose knownDraft is not a string array", () => {
    expect(() => parseBaseline('{"knownDraft": {"a": 1}}', "x")).toThrow(StatusGateUsageError);
    expect(() => parseBaseline('{"knownDraft": [1, 2]}', "x")).toThrow(StatusGateUsageError);
  });

  it("refuses malformed JSON rather than reading as an empty baseline", () => {
    expect(() => parseBaseline("{not json", "x")).toThrow(StatusGateUsageError);
  });

  it("treats a missing baseline file as empty (first run has no debt recorded)", () => {
    expect(loadBaseline(join(fixture.root, "nope.json")).knownDraft).toEqual([]);
  });
});

describe("runGate", () => {
  it("fails on a new draft rule and explains what draft means", () => {
    addRule("ATR-2026-90001", "draft");
    writeBaselineFile([]);
    const { code, lines, comparison } = runGate(OPTIONS, fixture.deps);
    expect(code).toBe(EXIT_FAIL);
    expect(comparison.newDrafts.map((r) => r.id)).toEqual(["ATR-2026-90001"]);
    const text = lines.join("\n");
    expect(text).toContain("never evaluated by the engine");
    expect(text).toContain("status: experimental");
    expect(text).toContain("ATR-2026-90001");
  });

  it("fails a live rule that was flipped to draft", () => {
    addRule("ATR-2026-90001", "experimental");
    writeBaselineFile([]);
    expect(runGate(OPTIONS, fixture.deps).code).toBe(EXIT_OK);
    addRule("ATR-2026-90001", "draft");
    expect(runGate(OPTIONS, fixture.deps).code).toBe(EXIT_FAIL);
  });

  it("passes a baselined draft rule — the recorded backlog is not a build break", () => {
    addRule("ATR-2026-90001", "draft");
    writeBaselineFile(["ATR-2026-90001"]);
    const { code, comparison } = runGate(OPTIONS, fixture.deps);
    expect(code).toBe(EXIT_OK);
    expect(comparison.grandfathered.map((r) => r.id)).toEqual(["ATR-2026-90001"]);
  });

  it("passes when no rule is draft at all", () => {
    addRule("ATR-2026-90001", "experimental");
    addRule("ATR-2026-90002", "stable");
    writeBaselineFile([]);
    const { code, lines } = runGate(OPTIONS, fixture.deps);
    expect(code).toBe(EXIT_OK);
    expect(lines.join("\n")).toContain("GATE PASS");
  });

  it("does not gate `deprecated` — that status is dead on purpose", () => {
    addRule("ATR-2026-90001", "deprecated");
    writeBaselineFile([]);
    expect(runGate(OPTIONS, fixture.deps).code).toBe(EXIT_OK);
  });

  it("fails on an unreadable rule file even when nothing is draft", () => {
    addRule("ATR-2026-90001", "experimental");
    writeFileSync(
      join(fixture.root, "rules", "prompt-injection", "broken.yaml"),
      "status: [unclosed\n",
      "utf-8",
    );
    writeBaselineFile([]);
    const { code, lines } = runGate(OPTIONS, fixture.deps);
    expect(code).toBe(EXIT_FAIL);
    expect(lines.join("\n")).toContain("no determinable status");
  });

  it("warns (does not fail) on a baselined draft rule carrying true_positives", () => {
    addRule("ATR-2026-90001", "draft", { tps: 3 });
    writeBaselineFile(["ATR-2026-90001"]);
    const { code, lines, comparison } = runGate(OPTIONS, fixture.deps);
    expect(code).toBe(EXIT_OK);
    expect(comparison.suspicious.map((r) => r.id)).toEqual(["ATR-2026-90001"]);
    expect(lines.join("\n")).toContain("WARN");
  });

  it("--strict-suspicious turns that warning into a failure", () => {
    addRule("ATR-2026-90001", "draft", { tps: 3 });
    writeBaselineFile(["ATR-2026-90001"]);
    const { code } = runGate({ ...OPTIONS, strictSuspicious: true }, fixture.deps);
    expect(code).toBe(EXIT_FAIL);
  });

  it("reports baselined rules that left draft so the ratchet can be tightened", () => {
    addRule("ATR-2026-90001", "experimental");
    writeBaselineFile(["ATR-2026-90001", "ATR-2026-90099"]);
    const { code, comparison, lines } = runGate(OPTIONS, fixture.deps);
    expect(code).toBe(EXIT_OK);
    expect(comparison.resolved).toEqual(["ATR-2026-90001", "ATR-2026-90099"]);
    expect(lines.join("\n")).toContain("RATCHET");
  });

  it("--json emits machine-readable output and the same verdict", () => {
    addRule("ATR-2026-90001", "draft");
    writeBaselineFile([]);
    const { code, lines } = runGate({ ...OPTIONS, json: true }, fixture.deps);
    expect(code).toBe(EXIT_FAIL);
    const doc = JSON.parse(lines.join("\n"));
    expect(doc.newDrafts.map((r: { id: string }) => r.id)).toEqual(["ATR-2026-90001"]);
  });
});

describe("--write-baseline is tighten-only", () => {
  it("drops entries whose rule left draft", () => {
    addRule("ATR-2026-90001", "experimental");
    addRule("ATR-2026-90002", "draft");
    writeBaselineFile(["ATR-2026-90001", "ATR-2026-90002"]);
    runGate({ ...OPTIONS, writeBaseline: true }, fixture.deps);
    expect(readBaselineFile().knownDraft).toEqual(["ATR-2026-90002"]);
  });

  it("never adds a new draft rule — widening is what would make the gate lie", () => {
    addRule("ATR-2026-90003", "draft");
    writeBaselineFile([]);
    const { lines } = runGate({ ...OPTIONS, writeBaseline: true }, fixture.deps);
    expect(readBaselineFile().knownDraft).toEqual([]);
    expect(lines.join("\n")).toContain("were NOT added");
    // And the gate still fails on the next run — writing the baseline did not
    // launder the new draft rule into acceptance.
    expect(runGate(OPTIONS, fixture.deps).code).toBe(EXIT_FAIL);
  });

  it("is a pure shrink of the id set", () => {
    addRule("ATR-2026-90002", "draft");
    const before = ["ATR-2026-90001", "ATR-2026-90002"];
    writeBaselineFile(before);
    const scan = scanCorpus(fixture.deps.rulesDir, fixture.root);
    const next = tightenBaseline(
      { generatedAt: "", note: "", corpus: { rules: 0, draftRules: 0 }, knownDraft: before },
      scan,
      "now",
    );
    expect(next.knownDraft.every((id) => before.includes(id))).toBe(true);
    expect(next.knownDraft.length).toBeLessThanOrEqual(before.length);
  });
});

describe("engine self-check", () => {
  it("reads the real line number of the draft skip out of engine source", () => {
    const src = ["a", "b", "if (rule.status === 'draft') continue;"].join("\n");
    expect(findEngineSkip(src).lines).toEqual([3]);
  });

  it("finds both evaluation paths when both carry the skip", () => {
    const src = [
      "if (rule.status === 'deprecated' || rule.status === 'draft') continue;",
      "x",
      "if (rule.status === 'deprecated' || rule.status === 'draft') continue;",
    ].join("\n");
    expect(findEngineSkip(src).lines).toEqual([1, 3]);
  });

  it("says the skip is gone rather than asserting a line that no longer exists", () => {
    expect(draftExplanation({ lines: [] })).toContain("GONE");
    expect(draftExplanation({ lines: [382, 533] })).toContain("src/engine.ts:382 and :533");
  });

  it("quotes the engine's actual line numbers in the failure message", () => {
    addRule("ATR-2026-90001", "draft");
    writeBaselineFile([]);
    const { lines } = runGate(OPTIONS, fixture.deps);
    // The fixture engine puts the skip on line 3.
    expect(lines.join("\n")).toContain("src/engine.ts:3");
  });
});

describe("resolveExitCode", () => {
  const empty = { rules: [], unreadable: [] };
  const clean = { newDrafts: [], grandfathered: [], suspicious: [], resolved: [] };

  it("passes on a clean comparison", () => {
    expect(resolveExitCode(empty, clean, false)).toBe(EXIT_OK);
  });

  it("fails when a file could not be read", () => {
    expect(
      resolveExitCode({ rules: [], unreadable: [{ file: "x", reason: "y" }] }, clean, false),
    ).toBe(EXIT_FAIL);
  });
});

describe("main", () => {
  it("returns a usage code for a bad flag instead of pretending to pass", () => {
    expect(main(["--nonsense"], fixture.deps)).toBe(EXIT_USAGE);
  });

  it("returns a usage code for a corrupt baseline instead of an empty one", () => {
    addRule("ATR-2026-90001", "draft");
    writeFileSync(fixture.deps.baselinePath, "{ not json", "utf-8");
    expect(main([], fixture.deps)).toBe(EXIT_USAGE);
  });

  it("returns the gate verdict", () => {
    addRule("ATR-2026-90001", "draft");
    writeBaselineFile([]);
    expect(main([], fixture.deps)).toBe(EXIT_FAIL);
    writeBaselineFile(["ATR-2026-90001"]);
    expect(main([], fixture.deps)).toBe(EXIT_OK);
  });
});
