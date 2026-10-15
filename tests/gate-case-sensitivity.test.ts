/**
 * Tests for scripts/gate-case-sensitivity.ts -- the ratchet against regex
 * conditions whose letter case means nothing at runtime.
 *
 * WHAT IS BEING PROTECTED
 *   src/engine.ts compiles every array-format `operator: regex` condition with
 *   the `i` flag, whether or not the author wrote (?i). A condition that keeps
 *   one of its own benign samples out only by letter case therefore lets it in.
 *   The gate reports exactly that, and fails only on findings the committed
 *   baseline does not already record.
 *
 * Contracts pinned here:
 *   1. The gate compiles every condition exactly as the engine does -- same
 *      source, same flags, same refusals. The first version kept its own copy of
 *      the engine's flag selection; the engine later started setting `u` for
 *      literal astral characters and the copy did not follow, so the gate
 *      silently skipped every condition written that way. The corpus-wide test
 *      below fails the moment the two disagree again, whichever side moves.
 *   2. The premise holds: the engine really fires on the benign sample the gate
 *      flags. If the engine ever starts honouring letter case, these fail and
 *      the gate has to be rethought rather than left asserting something false.
 *   3. A finding is a benign sample the condition matches only under the
 *      engine's flags. A condition that already matches the sample as written is
 *      not a finding -- that was the case-permutation noise of the first version.
 *   4. Ratchet semantics shared with gate-rule-status.ts / gate-re2-portability.ts:
 *      new or worse fails, recorded debt passes, --write-baseline only shrinks,
 *      an unreadable rule or a corrupt baseline is never reported as a pass.
 *
 * The ratchet runs against a fixture rules/ tree, so it never depends on the
 * current state of the real corpus. Only contract 1 reads the real corpus, and
 * it asserts a property of code, not of any rule.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dump as yamlDump } from "js-yaml";
import { ATREngine } from "../src/engine.js";
import { buildEventFromTestCase } from "../src/testcase-event.js";
import type { ATRRule } from "../src/types.js";
import {
  parseCliOptions,
  compileCondition,
  engineRegex,
  benignSamples,
  scanRule,
  scanCorpus,
  parseBaseline,
  loadBaseline,
  compareToBaseline,
  tightenBaseline,
  runGate,
  main,
  CaseGateUsageError,
  EXIT_OK,
  EXIT_FAIL,
  EXIT_USAGE,
  type CaseGateDeps,
  type CaseGateOptions,
} from "../scripts/gate-case-sensitivity.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const OPTIONS: CaseGateOptions = { writeBaseline: false, json: false };

/** A literal Unicode tag-character class: needs `u`, and is a SyntaxError without it. */
const TAG_CLASS = "[\u{E0020}-\u{E007E}]";

interface FixtureCondition {
  readonly value: string;
  readonly field?: string;
}

/** A rule object in the shape the engine loads. Only the fields this gate and the engine read are real. */
function ruleObject(
  id: string,
  conditions: readonly FixtureCondition[],
  negatives: readonly unknown[],
): ATRRule {
  return {
    title: `fixture ${id}`,
    id,
    status: "experimental",
    maturity: "test",
    severity: "high",
    description: "fixture",
    author: "test",
    date: "2026/10/16",
    tags: { category: "prompt-injection", confidence: "high" },
    agent_source: { type: "llm_io" },
    detection: {
      condition: "any",
      conditions: conditions.map((c) => ({
        field: c.field ?? "user_input",
        operator: "regex",
        value: c.value,
      })),
    },
    response: { actions: ["alert"] },
    test_cases: {
      true_positives: [{ input: "attack sample", expected: "triggered" }],
      true_negatives: negatives,
    },
  } as unknown as ATRRule;
}

/** Does the real engine fire this rule on the event its own test run would build for `sample`? */
async function engineFires(rule: ATRRule, sample: string): Promise<boolean> {
  const engine = new ATREngine({ rules: [rule], rulesDir: join(tmpdir(), "atr-case-gate-no-rules") });
  await engine.loadRules();
  const event = buildEventFromTestCase({ input: sample }, rule);
  return engine.evaluate(event).some((m) => m.rule.id === rule.id);
}

// ---------------------------------------------------------------------------
// Fixture tree for the ratchet
// ---------------------------------------------------------------------------

interface Fixture {
  readonly root: string;
  readonly deps: CaseGateDeps;
}

let fixture: Fixture;

function makeFixture(): Fixture {
  const root = mkdtempSync(join(tmpdir(), "atr-case-gate-"));
  mkdirSync(join(root, "rules", "prompt-injection"), { recursive: true });
  return {
    root,
    deps: {
      repoRoot: root,
      rulesDir: join(root, "rules"),
      baselinePath: join(root, "baseline.json"),
      now: () => "2026-10-16T00:00:00.000Z",
    },
  };
}

function addRule(id: string, conditions: readonly FixtureCondition[], negatives: readonly unknown[]): void {
  writeFileSync(
    join(fixture.root, "rules", "prompt-injection", `${id}-fixture.yaml`),
    yamlDump(ruleObject(id, conditions, negatives)),
    "utf-8",
  );
}

/** One rule with one condition that keeps its lowercase benign sample out only by case. */
function addCaseReliantRule(id: string, conditionCount = 1): void {
  const conditions = Array.from({ length: conditionCount }, (_, i) => ({ value: `\\bDROP\\s+TABLE${i}\\b` }));
  const negatives = Array.from({ length: conditionCount }, (_, i) => ({
    input: `how do I drop table${i} partitions safely`,
    expected: "not_triggered",
  }));
  addRule(id, conditions, negatives);
}

function writeBaselineFile(entries: Readonly<Record<string, number>>): void {
  const knownCaseReliant = Object.fromEntries(Object.entries(entries).map(([id, n]) => [id, { conditions: n }]));
  writeFileSync(
    fixture.deps.baselinePath,
    `${JSON.stringify({ generatedAt: "", note: "", corpus: { rules: 0, regexConditions: 0 }, knownCaseReliant }, null, 2)}\n`,
    "utf-8",
  );
}

function readBaselineFile(): { knownCaseReliant: Record<string, { conditions: number }> } {
  return JSON.parse(readFileSync(fixture.deps.baselinePath, "utf-8"));
}

beforeEach(() => {
  fixture = makeFixture();
});

afterEach(() => {
  rmSync(fixture.root, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// 1. Same pattern as the engine
// ---------------------------------------------------------------------------

describe("the gate compiles every condition exactly as the engine does", () => {
  it("agrees with the engine's own compiled regex on every condition in the corpus", async () => {
    const engine = new ATREngine({ rulesDir: join(REPO_ROOT, "rules") });
    await engine.loadRules();
    const compiled = (engine as unknown as {
      compiledPatterns: ReadonlyMap<string, ReadonlyMap<string, readonly RegExp[]>>;
    }).compiledPatterns;
    // If this internal moves, fail loudly rather than compare against nothing.
    expect(compiled).toBeInstanceOf(Map);

    const mismatches: string[] = [];
    let compared = 0;
    for (const rule of engine.getRules()) {
      const conditions = rule.detection.conditions;
      if (!Array.isArray(conditions)) continue;
      conditions.forEach((raw, i) => {
        const c = raw as unknown as { operator?: unknown; value?: unknown };
        if (c.operator !== "regex" || typeof c.value !== "string") return;
        compared++;
        const gate = engineRegex(c.value);
        const ours = compiled.get(rule.id)?.get(String(i))?.[0] ?? null;
        const same =
          gate === null || ours === null
            ? gate === ours
            : gate.source === ours.source && gate.flags === ours.flags;
        if (!same) {
          mismatches.push(
            `${rule.id} condition[${i}]: gate=${gate ? `/${gate.flags}` : "not compiled"} ` +
              `engine=${ours ? `/${ours.flags}` : "not compiled"}`,
          );
        }
      });
    }
    expect(compared).toBeGreaterThan(1000);
    expect(mismatches).toEqual([]);
  });

  it("compiles a literal astral character class with u, as the engine does", () => {
    // The first version chose `u` only for \u{...} and \p{...}. Without `u`, a
    // class range written with astral literals is a SyntaxError, and the gate
    // skipped the condition without saying so.
    const view = compileCondition(`tag${TAG_CLASS}{2}`);
    expect(view.kind).toBe("compared");
    if (view.kind !== "compared") return;
    expect(view.engine.flags).toBe("iu");
    expect(view.written.flags).toBe("u");
  });

  it("compiles as written with the engine's flags minus i", () => {
    const view = compileCondition("\\bDROP\\s+TABLE\\b");
    expect(view.kind).toBe("compared");
    if (view.kind !== "compared") return;
    expect(view.engine.flags).toBe("i");
    expect(view.written.flags).toBe("");
    expect(view.written.source).toBe(view.engine.source);
  });

  it("treats a leading group containing i as declared -- (?i), (?is), (?im), (?si)", () => {
    for (const value of ["(?i)drop", "(?is)drop", "(?im)drop", "(?si)drop"]) {
      expect(compileCondition(value).kind, value).toBe("declared");
    }
  });

  it("does not read a leading (?s) as case-insensitive -- the engine strips it and applies only i", () => {
    const view = compileCondition("(?s)DROP.TABLE");
    expect(view.kind).toBe("compared");
    if (view.kind !== "compared") return;
    expect(view.engine.source).toBe("DROP.TABLE");
    expect(view.engine.flags).toBe("i");
  });

  it("reports a pattern the engine refuses as not compiled, never as a finding", () => {
    expect(compileCondition("(a+)+b").kind).toBe("uncompiled"); // ReDoS gate
    expect(compileCondition("(unclosed").kind).toBe("uncompiled"); // SyntaxError
    expect(engineRegex("(a+)+b")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 2. The premise
// ---------------------------------------------------------------------------

describe("the engine really ignores the case distinction the gate flags", () => {
  it("fires on the benign sample the gate reports", async () => {
    const sample = "how do I drop table partitions safely";
    const rule = ruleObject("ATR-2026-99001", [{ value: "\\bDROP\\s+TABLE\\b" }], [{ input: sample }]);
    expect(scanRule(rule, "fixture.yaml").findings).toHaveLength(1);
    expect(await engineFires(rule, sample)).toBe(true);
  });

  it("fires on an astral-literal condition the first version could not compile", async () => {
    const sample = "TAG\u{E0041}\u{E0042}";
    const rule = ruleObject("ATR-2026-99002", [{ value: `tag${TAG_CLASS}{2}` }], [{ input: sample }]);
    expect(scanRule(rule, "fixture.yaml").findings).toHaveLength(1);
    expect(await engineFires(rule, sample)).toBe(true);
  });

  it("compiles the same way on the engine's on-the-fly path as on the precompiled one", async () => {
    // evaluateArrayCondition() falls back to compiling on the fly when a rule has no
    // precompiled entry. Reach that path by handing the engine an uncompiled rule.
    const sample = "how do I drop table partitions safely";
    const rule = ruleObject("ATR-2026-99003", [{ value: "\\bDROP\\s+TABLE\\b" }], [{ input: sample }]);
    const engine = new ATREngine({ rulesDir: join(tmpdir(), "atr-case-gate-no-rules") });
    await engine.loadRules();
    (engine as unknown as { rules: ATRRule[] }).rules = [rule];
    const fired = engine.evaluate(buildEventFromTestCase({ input: sample }, rule));
    expect(fired.map((m) => m.rule.id)).toEqual([rule.id]);
  });
});

// ---------------------------------------------------------------------------
// 3. What a finding is
// ---------------------------------------------------------------------------

describe("benign samples", () => {
  it("reads what the rule's own test run reads -- object inputs, tool_response, user_input", () => {
    const rule = ruleObject("ATR-2026-99010", [{ value: "x" }], [
      "plain string sample",
      { input: { tool_name: "shell", tool_args: "ARGS IN AN OBJECT" } },
      { tool_response: "TEXT RETURNED BY A TOOL" },
      { user_input: "USER INPUT ALIAS" },
    ]);
    const texts = benignSamples(rule).map((s) => s.texts.join("\n"));
    expect(texts[0]).toContain("plain string sample");
    expect(texts[1]).toContain("ARGS IN AN OBJECT");
    expect(texts[1]).not.toContain("[object Object]");
    expect(texts[2]).toContain("TEXT RETURNED BY A TOOL");
    expect(texts[3]).toContain("USER INPUT ALIAS");
  });
});

describe("findings", () => {
  it("flags a condition that keeps one of its own benign samples out only by letter case", () => {
    const rule = ruleObject("ATR-2026-99020", [{ value: "\\bDROP\\s+TABLE\\b" }], [
      { input: "nothing relevant" },
      { input: "how do I drop table partitions safely" },
    ]);
    const { findings } = scanRule(rule, "rules/x.yaml");
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "ATR-2026-99020", condition: 0, sample: 1, flags: "i" });
  });

  it("does not flag a condition that already matches the sample as written", () => {
    // The first version also probed each sample upper-cased. Under the engine's
    // flags a case variant matches exactly when the original does, so a variant
    // only ever added a finding here -- where the pattern keeps nothing out.
    const rule = ruleObject("ATR-2026-99021", [{ value: "\\bsocket\\.connect\\(" }], [
      { input: "s = socket.socket(); s.connect((host, 443))" },
    ]);
    expect(scanRule(rule, "rules/x.yaml").findings).toEqual([]);
  });

  it("does not flag a condition that declares (?i)", () => {
    const rule = ruleObject("ATR-2026-99022", [{ value: "(?i)\\bDROP\\s+TABLE\\b" }], [
      { input: "how do I drop table partitions safely" },
    ]);
    const scan = scanRule(rule, "rules/x.yaml");
    expect(scan.findings).toEqual([]);
    expect(scan.declared).toBe(1);
  });

  it("does not flag a sample that neither reading matches", () => {
    const rule = ruleObject("ATR-2026-99023", [{ value: "\\bDROP\\s+TABLE\\b" }], [{ input: "select 1" }]);
    expect(scanRule(rule, "rules/x.yaml").findings).toEqual([]);
  });

  it("counts a refused pattern as not compiled instead of failing the rule", () => {
    const rule = ruleObject("ATR-2026-99024", [{ value: "(A+)+b" }], [{ input: "aaab" }]);
    const scan = scanRule(rule, "rules/x.yaml");
    expect(scan.findings).toEqual([]);
    expect(scan.uncompiled).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// 4. Ratchet
// ---------------------------------------------------------------------------

describe("parseCliOptions", () => {
  it("defaults to gate semantics", () => {
    expect(parseCliOptions([])).toEqual(OPTIONS);
  });

  it("rejects an unknown flag rather than silently ignoring it", () => {
    expect(() => parseCliOptions(["--write-baselines"])).toThrow(CaseGateUsageError);
  });
});

describe("corpus scan", () => {
  it("groups findings by rule and counts conditions, not samples", () => {
    addRule("ATR-2026-90001", [{ value: "\\bDROP\\s+TABLE\\b" }], [
      { input: "drop table one" },
      { input: "drop table two" },
    ]);
    const scan = scanCorpus(fixture.deps.rulesDir, fixture.root);
    expect(scan.affected.get("ATR-2026-90001")?.conditions).toBe(1);
    expect(scan.affected.get("ATR-2026-90001")?.findings).toHaveLength(2);
  });

  it("reports an unparsable file instead of dropping it from the scan", () => {
    writeFileSync(join(fixture.root, "rules", "prompt-injection", "broken.yaml"), "id: [unclosed\n", "utf-8");
    const scan = scanCorpus(fixture.deps.rulesDir, fixture.root);
    expect(scan.unreadable.map((u) => u.file)).toEqual(["rules/prompt-injection/broken.yaml"]);
  });
});

describe("baseline parsing", () => {
  it("refuses a baseline whose knownCaseReliant is not an object of counts", () => {
    const bad = [
      { knownCaseReliant: ["ATR-2026-90001"] },
      { knownCaseReliant: { "ATR-2026-90001": 1 } },
      { knownCaseReliant: { "ATR-2026-90001": { conditions: -1 } } },
      {},
    ];
    for (const doc of bad) {
      expect(() => parseBaseline(JSON.stringify(doc), "b.json"), JSON.stringify(doc)).toThrow(CaseGateUsageError);
    }
  });

  it("refuses malformed JSON rather than reading it as an empty baseline", () => {
    expect(() => parseBaseline("{ nope", "b.json")).toThrow(CaseGateUsageError);
  });

  it("treats a missing baseline file as empty", () => {
    expect(loadBaseline(join(fixture.root, "absent.json")).knownCaseReliant).toEqual({});
  });
});

describe("runGate", () => {
  it("fails on a new rule with a finding, and says what the engine does and how to fix it", () => {
    addCaseReliantRule("ATR-2026-90001");
    writeBaselineFile({});
    const { code, lines, comparison } = runGate(OPTIONS, fixture.deps);
    expect(code).toBe(EXIT_FAIL);
    expect(comparison.added.map((r) => r.ruleId)).toEqual(["ATR-2026-90001"]);
    const text = lines.join("\n");
    expect(text).toContain("GATE FAIL");
    expect(text).toContain("ATR-2026-90001");
    expect(text).toContain("condition[0]");
    expect(text).toContain("true_negatives[0]");
    expect(text).toContain("regexConditionSpec");
    expect(text).toContain("(?i)");
  });

  it("passes a baselined rule at its recorded count -- recorded debt is not a build break", () => {
    addCaseReliantRule("ATR-2026-90001");
    writeBaselineFile({ "ATR-2026-90001": 1 });
    const { code, lines } = runGate(OPTIONS, fixture.deps);
    expect(code).toBe(EXIT_OK);
    expect(lines.join("\n")).toContain("GATE PASS");
    // The register is reprinted, so it cannot become a hiding place.
    expect(lines.join("\n")).toContain("ATR-2026-90001");
  });

  it("fails a baselined rule that gained a case-reliant condition", () => {
    addCaseReliantRule("ATR-2026-90001", 2);
    writeBaselineFile({ "ATR-2026-90001": 1 });
    const { code, comparison } = runGate(OPTIONS, fixture.deps);
    expect(code).toBe(EXIT_FAIL);
    expect(comparison.worsened.map((w) => w.rule.ruleId)).toEqual(["ATR-2026-90001"]);
  });

  it("reports baselined rules that improved or were fixed, so the ratchet can be tightened", () => {
    addCaseReliantRule("ATR-2026-90001", 1);
    addRule("ATR-2026-90002", [{ value: "(?i)\\bDROP\\b" }], [{ input: "drop it" }]);
    writeBaselineFile({ "ATR-2026-90001": 2, "ATR-2026-90002": 1 });
    const { code, lines, comparison } = runGate(OPTIONS, fixture.deps);
    expect(code).toBe(EXIT_OK);
    expect(comparison.improved).toEqual(["ATR-2026-90001"]);
    expect(comparison.resolved).toEqual(["ATR-2026-90002"]);
    expect(lines.join("\n")).toContain("--write-baseline");
  });

  it("fails on an unreadable rule file even with no finding anywhere", () => {
    writeFileSync(join(fixture.root, "rules", "prompt-injection", "broken.yaml"), "id: [unclosed\n", "utf-8");
    writeBaselineFile({});
    expect(runGate(OPTIONS, fixture.deps).code).toBe(EXIT_FAIL);
  });

  it("--json emits machine-readable output and the same verdict", () => {
    addCaseReliantRule("ATR-2026-90001");
    writeBaselineFile({});
    const { code, lines } = runGate({ ...OPTIONS, json: true }, fixture.deps);
    expect(code).toBe(EXIT_FAIL);
    const doc = JSON.parse(lines.join("\n"));
    expect(doc.added).toEqual(["ATR-2026-90001"]);
    expect(doc.findings[0]).toMatchObject({ ruleId: "ATR-2026-90001", condition: 0, sample: 0 });
  });
});

describe("--write-baseline is tighten-only", () => {
  it("drops fixed rules and lowers improved counts", () => {
    addCaseReliantRule("ATR-2026-90001", 1);
    writeBaselineFile({ "ATR-2026-90001": 3, "ATR-2026-90009": 1 });
    runGate({ ...OPTIONS, writeBaseline: true }, fixture.deps);
    expect(readBaselineFile().knownCaseReliant).toEqual({ "ATR-2026-90001": { conditions: 1 } });
  });

  it("never adds a rule or raises a count -- widening is what would make the gate lie", () => {
    addCaseReliantRule("ATR-2026-90001", 2);
    addCaseReliantRule("ATR-2026-90002", 1);
    writeBaselineFile({ "ATR-2026-90001": 1 });
    const { lines } = runGate({ ...OPTIONS, writeBaseline: true }, fixture.deps);
    expect(readBaselineFile().knownCaseReliant).toEqual({ "ATR-2026-90001": { conditions: 1 } });
    expect(lines.join("\n")).toContain("NOT added");
    // Writing the baseline did not launder the new findings into acceptance.
    expect(runGate(OPTIONS, fixture.deps).code).toBe(EXIT_FAIL);
  });

  it("is a pure shrink", () => {
    addCaseReliantRule("ATR-2026-90001", 1);
    const before = { "ATR-2026-90001": { conditions: 2 }, "ATR-2026-90002": { conditions: 1 } };
    const scan = scanCorpus(fixture.deps.rulesDir, fixture.root);
    const next = tightenBaseline(
      { generatedAt: "", note: "", corpus: { rules: 0, regexConditions: 0 }, knownCaseReliant: before },
      scan,
      "now",
    );
    for (const [id, entry] of Object.entries(next.knownCaseReliant)) {
      expect(before[id as keyof typeof before]).toBeDefined();
      expect(entry.conditions).toBeLessThanOrEqual(before[id as keyof typeof before].conditions);
    }
  });
});

describe("compareToBaseline", () => {
  it("is empty on a clean corpus with an empty baseline", () => {
    const scan = scanCorpus(fixture.deps.rulesDir, fixture.root);
    const c = compareToBaseline(scan, loadBaseline(fixture.deps.baselinePath));
    expect(c).toEqual({ added: [], worsened: [], improved: [], resolved: [] });
  });
});

describe("main", () => {
  it("returns a usage code for a bad flag instead of pretending to pass", () => {
    expect(main(["--nonsense"], fixture.deps)).toBe(EXIT_USAGE);
  });

  it("returns a usage code for a corrupt baseline instead of reading it as empty", () => {
    addCaseReliantRule("ATR-2026-90001");
    writeFileSync(fixture.deps.baselinePath, "{ not json", "utf-8");
    expect(main([], fixture.deps)).toBe(EXIT_USAGE);
  });

  it("returns the gate verdict", () => {
    addCaseReliantRule("ATR-2026-90001");
    writeBaselineFile({});
    expect(main([], fixture.deps)).toBe(EXIT_FAIL);
    writeBaselineFile({ "ATR-2026-90001": 1 });
    expect(main([], fixture.deps)).toBe(EXIT_OK);
  });
});
