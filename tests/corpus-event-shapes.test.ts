/**
 * Tests for scripts/lib/corpus-event.ts — the event shapes every FP/TP
 * measurement must use.
 *
 * THE BUG THESE TESTS EXIST TO PREVENT
 *
 * A rule condition names a field. The engine resolves that name against the
 * event the harness built. If the harness cannot resolve it, the condition is
 * false for every sample, the rule never fires, and the FP gate reports it
 * CLEAN — a zero-measurement PASS that is indistinguishable in the output from
 * a rule that was measured and found innocent.
 *
 * That shipped: the gate built one `mcp_exchange` event with only tool_name /
 * tool_input / tool_response / user_input, so `field: tool_args` resolved to
 * undefined. 40 rules detect on tool_args, 3 of them maturity:stable (the
 * auto-blocking enforce lane). None of their tool_args conditions had ever been
 * measured against a benign sample.
 *
 * The load-bearing test here is "every field the engine can resolve is either
 * measured or explicitly declared unmeasurable", and it derives the field list
 * FROM src/engine.ts rather than from a hand-written copy. Adding a new field to
 * resolveField without teaching the harness about it turns this test red — which
 * is the only way this class of blindness gets caught at the moment it is
 * introduced rather than months later in production.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, rmSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent } from "../src/types.js";
import {
  corpusShapes,
  shapeNames,
  conditionFields,
  fieldCoverage,
  isMeasurableField,
  unmeasurableReason,
  CORPUS_TOOL_NAME,
  MEASURED_FIELDS,
  UNMEASURABLE_FIELDS,
  type RuleLike,
} from "../scripts/lib/corpus-event.js";
import { runGate, EXIT_FAIL, EXIT_OK, type GateDeps } from "../scripts/gate-promotion-fp.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SENTINEL = "zzq-reachability-sentinel-zzq";

/** A schema-valid one-condition rule whose regex is `pattern` on `field`. */
function ruleYaml(
  id: string,
  field: string,
  pattern: string,
  source = "llm_io",
  scanTarget = "runtime",
): string {
  return [
    `title: probe ${field}`,
    `id: ${id}`,
    "rule_version: 1",
    "status: experimental",
    "description: fixture rule for the corpus event shape tests",
    "author: test",
    "date: 2026/07/29",
    "schema_version: '0.1'",
    "detection_tier: pattern",
    "maturity: test",
    "severity: high",
    "tags:",
    "  category: tool-poisoning",
    `  scan_target: ${scanTarget}`,
    "  confidence: high",
    "agent_source:",
    `  type: ${source}`,
    "  framework: [any]",
    "  provider: [any]",
    "detection:",
    "  condition: any",
    "  false_positives: []",
    "  conditions:",
    `    - field: ${field}`,
    "      operator: regex",
    `      value: ${pattern}`,
    "      description: probe",
    "response:",
    "  actions: [alert]",
    "test_cases:",
    "  true_positives: []",
    "  true_negatives: []",
    "",
  ].join("\n");
}

/** The legacy shape, verbatim, so its blindness stays pinned as a regression. */
function legacyEvent(content: string): AgentEvent {
  return {
    type: "mcp_exchange",
    timestamp: new Date().toISOString(),
    content,
    fields: {
      tool_name: "corpus-sample",
      tool_input: content,
      tool_response: content,
      user_input: content,
    },
  };
}

/** Load an engine holding exactly one probe rule for `field`. */
async function engineForField(
  field: string,
  pattern = SENTINEL,
  source = "llm_io",
): Promise<ATREngine> {
  const dir = mkdtempSync(join(tmpdir(), "atr-shape-"));
  writeFileSync(join(dir, "probe.yaml"), ruleYaml("ATR-2026-95001", field, pattern, source), "utf-8");
  const engine = new ATREngine({ rulesDir: dir });
  await engine.loadRules();
  return engine;
}

/** Does a condition on `field` fire on `text` through the canonical shapes? */
function firesOnShapes(engine: ATREngine, text: string): boolean {
  return corpusShapes(text).some((s) => engine.evaluate(s.event).length > 0);
}

// ---------------------------------------------------------------------------
// The field list, derived from the engine so it cannot drift
// ---------------------------------------------------------------------------

/**
 * Field names src/engine.ts resolveField() knows: every `case '...'` in its
 * body plus every default field EVENT_TYPE_TO_FIELD maps an event type to.
 * Parsed from source on purpose — a hand-copied list is exactly how the harness
 * fell behind the engine in the first place.
 */
function engineResolvableFields(): readonly string[] {
  const src = readFileSync(join(REPO_ROOT, "src/engine.ts"), "utf-8");

  const start = src.indexOf("private resolveField(");
  expect(start, "resolveField not found in src/engine.ts — update this parser").toBeGreaterThan(0);
  const end = src.indexOf("\n  }", start);
  const body = src.slice(start, end);
  const cases = [...body.matchAll(/case '([a-z_]+)'/g)].map((m) => m[1] as string);

  const mapStart = src.indexOf("const EVENT_TYPE_TO_FIELD");
  expect(mapStart, "EVENT_TYPE_TO_FIELD not found — update this parser").toBeGreaterThan(0);
  const mapBody = src.slice(mapStart, src.indexOf("};", mapStart));
  const defaults = [...mapBody.matchAll(/:\s*'([a-z_]+)'/g)].map((m) => m[1] as string);

  return [...new Set([...cases, ...defaults, "content"])].sort();
}

/** Every `field:` name declared by any rule on disk. */
function ruleDeclaredFields(): readonly string[] {
  const walk = (dir: string): string[] => {
    const out: string[] = [];
    for (const e of readdirSync(dir)) {
      const p = join(dir, e);
      if (statSync(p).isDirectory()) out.push(...walk(p));
      else if (e.endsWith(".yaml") || e.endsWith(".yml")) out.push(p);
    }
    return out;
  };
  const fields = new Set<string>();
  for (const file of walk(join(REPO_ROOT, "rules"))) {
    let doc: unknown;
    try {
      doc = yaml.load(readFileSync(file, "utf-8"));
    } catch {
      continue;
    }
    if (doc === null || typeof doc !== "object") continue;
    for (const f of conditionFields(doc as RuleLike)) fields.add(f);
  }
  return [...fields].sort();
}

// ---------------------------------------------------------------------------

describe("field reachability — no rule may be scored against a field nothing fills", () => {
  it("every field src/engine.ts can resolve is either measured or declared unmeasurable", () => {
    const undeclared = engineResolvableFields().filter(
      (f) => !isMeasurableField(f) && !UNMEASURABLE_FIELDS.has(f),
    );
    expect(
      undeclared,
      "these fields resolve in the engine but no shape fills them and no reason is on " +
        "record — a rule detecting on them would be scored CLEAN without being measured. " +
        "Add them to a shape in scripts/lib/corpus-event.ts, or to UNMEASURABLE_FIELDS " +
        "with the reason they cannot be measured.",
    ).toEqual([]);
  });

  it("every field a rule on disk declares is either measured or declared unmeasurable", () => {
    const undeclared = ruleDeclaredFields().filter(
      (f) =>
        !isMeasurableField(f) &&
        !UNMEASURABLE_FIELDS.has(f) &&
        !f.startsWith("trace.") &&
        !f.startsWith("behavioral."),
    );
    expect(
      undeclared,
      "rules detect on these fields but the FP harness cannot fill them",
    ).toEqual([]);
  });

  it.each([...MEASURED_FIELDS])("resolves %s from the canonical shapes (proved end to end)", async (field) => {
    const engine = await engineForField(field);
    expect(firesOnShapes(engine, `benign preamble ${SENTINEL} trailer`)).toBe(true);
  });

  /**
   * Second axis of the same disease. Resolving the field is not enough: the
   * engine also drops a rule whose agent_source.type does not match the event
   * type, so a shape set that only emits `tool_call` events would never evaluate
   * an llm_io rule at all — every one of them scored clean without being read.
   */
  it("evaluates rules of every agent_source.type declared on disk", async () => {
    const sources = new Set<string>();
    const walk = (dir: string): string[] => {
      const out: string[] = [];
      for (const e of readdirSync(dir)) {
        const p = join(dir, e);
        if (statSync(p).isDirectory()) out.push(...walk(p));
        else if (e.endsWith(".yaml") || e.endsWith(".yml")) out.push(p);
      }
      return out;
    };
    for (const file of walk(join(REPO_ROOT, "rules"))) {
      try {
        const doc = yaml.load(readFileSync(file, "utf-8")) as { agent_source?: { type?: string } };
        const t = doc?.agent_source?.type;
        if (typeof t === "string") sources.add(t);
      } catch {
        continue;
      }
    }
    expect(sources.size).toBeGreaterThan(3);
    for (const source of sources) {
      const engine = await engineForField("content", SENTINEL, source);
      expect(
        firesOnShapes(engine, `benign preamble ${SENTINEL} trailer`),
        `no shape admits a rule with agent_source.type: ${source} — every such rule ` +
          `would be reported FP-clean without ever being evaluated`,
      ).toBe(true);
    }
  });

  it("pins the fields that are deliberately NOT measured, with a stated reason", async () => {
    for (const field of UNMEASURABLE_FIELDS.keys()) {
      const engine = await engineForField(field);
      expect(
        firesOnShapes(engine, `benign preamble ${SENTINEL} trailer`),
        `${field} is now reachable. That may be correct — but decide it deliberately: ` +
          `pouring document text into a field production fills with a short identifier ` +
          `manufactures false positives that cannot happen in production.`,
      ).toBe(false);
      expect(unmeasurableReason(field)).toBeTruthy();
    }
  });

  it("an unknown field name is reported as unmeasurable rather than silently ignored", () => {
    expect(isMeasurableField("no_such_field")).toBe(false);
    expect(unmeasurableReason("no_such_field")).toContain("no shape carries the sample into it");
  });
});

describe("the legacy shape — the blindness these shapes replace", () => {
  it.each(["tool_args", "agent_output", "agent_message", "tool_description"])(
    "%s was unreachable on the old single-event shape",
    async (field) => {
      const engine = await engineForField(field);
      const text = `benign preamble ${SENTINEL} trailer`;
      expect(engine.evaluate(legacyEvent(text))).toHaveLength(0);
      expect(firesOnShapes(engine, text)).toBe(true);
    },
  );

  it("keeps every field the legacy shape did resolve (the change only widens)", async () => {
    for (const field of ["content", "user_input", "tool_response", "tool_input"]) {
      const engine = await engineForField(field);
      const text = `benign preamble ${SENTINEL} trailer`;
      expect(engine.evaluate(legacyEvent(text)).length).toBeGreaterThan(0);
      expect(firesOnShapes(engine, text)).toBe(true);
    }
  });

  it("keeps the legacy tool_name placeholder so old FP counts stay comparable", () => {
    expect(CORPUS_TOOL_NAME).toBe("corpus-sample");
    for (const shape of corpusShapes("x")) {
      expect(shape.event.fields?.["tool_name"]).toBe(CORPUS_TOOL_NAME);
    }
  });
});

describe("JSON encoding — production puts JSON.stringify(toolInput) in tool_args", () => {
  it("carries both the raw and the JSON-encoded form of the sample", () => {
    const shapes = corpusShapes("a\nb");
    const args = shapes.map((s) => s.event.fields?.["tool_args"]);
    expect(args).toContain("a\nb");
    expect(args.some((a) => typeof a === "string" && a.includes("a\\nb"))).toBe(true);
  });

  // `.` does not cross a real newline, but JSON turns U+000A into the two
  // characters \ and n, which `.` happily traverses — so a pattern can join two
  // independent lines. A real critical-severity rule false-positives on a benign
  // Azure pricing document exactly this way, and the old shape could not see it
  // because it never presented the encoded form.
  //
  // Both source types are checked because the engine also filters rules by
  // agent_source.type against the event type: a tool_call event never evaluates
  // an llm_io rule. Covering only tool_call would leave the four llm_io rules
  // that detect on tool_args measured on the raw encoding alone.
  it.each(["tool_call", "llm_io", "mcp_exchange"])(
    "catches a pattern that only matches once newlines are escaped (agent_source: %s)",
    async (source) => {
      const engine = await engineForField("tool_args", "api-version=\\d{4}.*metadata", source);
      const text = "GET /prices?api-version=2023-01-01\nsee the metadata docs";
      expect(engine.evaluate(legacyEvent(text))).toHaveLength(0);
      expect(firesOnShapes(engine, text)).toBe(true);
    },
  );

  it("names its shapes so a harness banner can state what was measured", () => {
    expect(shapeNames()).toEqual([
      "wide-raw",
      "pre-tool-json-arg",
      "pre-tool-json-both",
      "post-tool-json",
    ]);
  });
});

describe("fieldCoverage — 'clean' must never quietly mean 'never looked at'", () => {
  const rule = (id: string, fields: readonly string[], condition = "any", method?: string): RuleLike => ({
    id,
    detection: {
      condition,
      ...(method === undefined ? {} : { method }),
      conditions: fields.map((f) => ({ field: f, operator: "regex", value: "x" })),
    },
  });

  it("says nothing about a fully measurable rule", () => {
    expect(fieldCoverage([rule("A", ["tool_args", "user_input"])])).toEqual([]);
  });

  it("flags an unmeasurable field and keeps ANY-rules as partially measured", () => {
    const [c] = fieldCoverage([rule("B", ["tool_name", "user_input"], "any")]);
    expect(c?.unmeasured).toEqual(["tool_name"]);
    expect(c?.zeroMeasurement).toBe(false);
  });

  it("calls an ALL-rule with one unmeasurable field zero-measurement", () => {
    const [c] = fieldCoverage([rule("C", ["tool_name", "user_input"], "all")]);
    expect(c?.zeroMeasurement).toBe(true);
  });

  it("calls a rule whose every field is unmeasurable zero-measurement", () => {
    const [c] = fieldCoverage([rule("D", ["tool_name"], "any")]);
    expect(c?.zeroMeasurement).toBe(true);
  });

  it("calls trace and behavioral rules zero-measurement whatever their fields say", () => {
    expect(fieldCoverage([rule("E", ["trace.forbid_violation"], "any", "trace")])[0]?.zeroMeasurement).toBe(true);
    expect(fieldCoverage([rule("F", ["content"], "any", "behavioral")])[0]?.zeroMeasurement).toBe(true);
  });

  it("reads both the array and the named-map condition formats", () => {
    const named: RuleLike = {
      id: "G",
      detection: { condition: "a AND b", conditions: { a: { field: "tool_args" }, b: { field: "tool_name" } } },
    };
    expect(conditionFields(named)).toEqual(["tool_args", "tool_name"]);
  });
});

// ---------------------------------------------------------------------------
// End to end through the gate itself
// ---------------------------------------------------------------------------

describe("the gate measures a tool_args rule end to end", () => {
  const TOOL_ARGS_ID = "ATR-2026-95101";
  const CONTROL_ID = "ATR-2026-95102";
  let root: string;
  let deps: GateDeps;

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "atr-shape-gate-"));
    const rulesDir = join(root, "rules");
    const corpusDir = join(root, "corpus");
    mkdirSync(rulesDir, { recursive: true });
    mkdirSync(corpusDir, { recursive: true });

    writeFileSync(
      join(rulesDir, `${TOOL_ARGS_ID}.yaml`),
      ruleYaml(TOOL_ARGS_ID, "tool_args", "169\\.254\\.169\\.254"),
      "utf-8",
    );
    writeFileSync(
      join(rulesDir, `${CONTROL_ID}.yaml`),
      ruleYaml(CONTROL_ID, "tool_args", "zzq-not-in-this-corpus-zzq"),
      "utf-8",
    );
    writeFileSync(
      join(corpusDir, "benign.jsonl"),
      `${JSON.stringify({ text: "curl http://169.254.169.254/latest/meta-data to read instance metadata" })}\n` +
        `${JSON.stringify({ text: "This skill formats CSV files." })}\n`,
      "utf-8",
    );

    deps = {
      repoRoot: root,
      rulesDir,
      corpora: [corpusDir],
      listRuleFiles: () => [`rules/${TOOL_ARGS_ID}.yaml`, `rules/${CONTROL_ID}.yaml`],
    };
  });

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  function idsFile(name: string, ids: readonly string[]): string {
    const p = join(root, name);
    writeFileSync(p, `${ids.join("\n")}\n`, "utf-8");
    return p;
  }

  it("fails a tool_args rule that false-positives — it used to pass unmeasured", async () => {
    const code = await runGate(
      {
        idsFile: idsFile("dirty.txt", [TOOL_ARGS_ID]),
        base: "origin/main",
        emitClean: null,
        emitDirty: null,
        filterMode: false,
      },
      deps,
    );
    expect(code).toBe(EXIT_FAIL);
  });

  it("still passes a tool_args rule that genuinely does not fire", async () => {
    const code = await runGate(
      {
        idsFile: idsFile("clean.txt", [CONTROL_ID]),
        base: "origin/main",
        emitClean: null,
        emitDirty: null,
        filterMode: false,
      },
      deps,
    );
    expect(code).toBe(EXIT_OK);
  });

  it("counts one false positive per sample, not one per shape", async () => {
    const dirty = join(root, "out-dirty.txt");
    await runGate(
      {
        idsFile: idsFile("count.txt", [TOOL_ARGS_ID]),
        base: "origin/main",
        emitClean: null,
        emitDirty: dirty,
        filterMode: true,
      },
      deps,
    );
    // The one triggering sample matches on every shape; the gate must report the
    // rule once, and the corpus has exactly one such document.
    expect(readFileSync(dirty, "utf-8").split("\n").filter(Boolean)).toEqual([TOOL_ARGS_ID]);
  });
});

// ---------------------------------------------------------------------------
// The ratchet: no harness gets to hand-roll its own event shape again
// ---------------------------------------------------------------------------

/**
 * Every FP/coverage harness in this repo once carried its own `asTextEvent()`,
 * copied from whichever sibling was newest at the time. When gate-promotion-fp
 * moved to the canonical shape set the copies stayed behind, and each one kept
 * scoring rules on a presentation narrower than production — reporting rules
 * FP-clean that had simply never been read. On ATR-2026-00091 the narrow copy
 * under-reported its own subject by a factor of ten (372 vs 3,897).
 *
 * A comment saying "keep in sync" did not keep them in sync. This does.
 *
 * src/eval/eval-harness.ts was the one that got away. It is the harness behind
 * `npm run eval` and `npm run eval:pint` — the numbers that end up in README
 * badges and on the website — and it kept its own `sampleToEvent()` until
 * 2026-08-05 because this list only ever looked inside scripts/. Under that
 * private shape every PINT sample was typed llm_input, so the engine's
 * source-type filter dropped 383 of the 773 non-draft rules before matching:
 * the published "precision 100%" was measured over half a rulebase. It is on
 * the list now, and the canonical module moved to src/ so it could be.
 */
describe("harnesses import the canonical shape set — they do not mirror it", () => {
  const HARNESSES = [
    "scripts/gate-promotion-fp.ts",
    "scripts/check-rules-safety.ts",
    "scripts/promote-to-stable.ts",
    "scripts/audit-draft-revival.ts",
    "scripts/validate-rule-testcases.ts",
    "src/eval/eval-harness.ts",
  ] as const;

  for (const rel of HARNESSES) {
    it(`${rel} routes matching through the canonical corpus-event module`, () => {
      const src = readFileSync(join(REPO_ROOT, rel), "utf-8");
      // scripts/ import the shim at scripts/lib/corpus-event.js; anything under
      // src/ imports src/corpus-event.js directly (tsconfig rootDir forbids a
      // src -> scripts import). Both resolve to the same module.
      expect(src).toMatch(/from\s+["'](?:\.\/lib\/|\.\.\/|\.\/)corpus-event\.js["']/);
    });

    it(`${rel} does not build its own AgentEvent literal`, () => {
      const src = readFileSync(join(REPO_ROOT, rel), "utf-8");
      // An event literal is `type:` immediately followed by one of the engine's
      // event-type strings. Comments and doc blocks are stripped first so that
      // describing the old defect does not trip the check.
      const code = src
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/(^|[^:])\/\/.*$/gm, "$1")
        // One documented exception, and only this one: audit-draft-revival's
        // fieldAwareEvent() delivers a test case's payload into the engine field
        // the test case itself names (or parses it as a trace). That is a
        // deliberate second presentation used ONLY to score declared true
        // positives -- a rule reading `tool_args` cannot fire on an event that
        // carries none, and scoring that as a rule failure measures the harness.
        // The benign-corpus path, which is what this ratchet protects, goes
        // through matchedRuleIds like everything else.
        .replace(/function fieldAwareEvent[\s\S]*?\n}\n/, "");
      const literal =
        /type:\s*["'](?:mcp_exchange|llm_input|llm_output|tool_call|tool_response|agent_behavior|multi_agent_message)["']/;
      const offenders = code.split("\n").filter((l) => literal.test(l));
      expect(offenders).toEqual([]);
    });
  }
});
