/**
 * Tests for scripts/lib/fp-scan.ts — the benign-corpus FP scan split across
 * worker processes.
 *
 * The one contract that matters: fanning the scan out changes how long it takes
 * and nothing else. Every test that touches workers compares against the
 * in-process scoreSamples() on the same input, through real child processes.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { ATREngine } from "../src/engine.js";
import {
  planBatches,
  mergeScores,
  resolveWorkerCount,
  scoreSamples,
  scoreSamplesInWorkers,
  PARALLEL_MIN_SAMPLES,
  MAX_AUTO_WORKERS,
  MAX_WORKERS,
  type SampleScores,
} from "../scripts/lib/fp-scan.js";

function fixtureRule(id: string, pattern: string): string {
  return [
    `title: fp-scan fixture ${id}`,
    `id: ${id}`,
    "rule_version: 1",
    "status: experimental",
    "description: fixture rule for the fp-scan worker tests",
    "author: test",
    "date: 2026/10/15",
    "schema_version: '0.1'",
    "detection_tier: pattern",
    "maturity: test",
    "severity: high",
    "tags:",
    "  category: tool-poisoning",
    "  scan_target: runtime",
    "  confidence: high",
    "agent_source:",
    "  type: llm_io",
    "  framework: [any]",
    "  provider: [any]",
    "detection:",
    "  condition: any",
    "  false_positives: []",
    "  conditions:",
    "    - field: content",
    "      operator: regex",
    `      value: ${pattern}`,
    "      description: fixture",
    "response:",
    "  actions: [alert]",
    "test_cases:",
    "  true_positives: []",
    "  true_negatives: []",
    "",
  ].join("\n");
}

const RULES = {
  "ATR-2026-91001": "(?i)import random",
  "ATR-2026-91002": "(?i)curl\\s+-s",
  "ATR-2026-91003": "zzq-never-in-any-sample-zzq",
} as const;

/** Varied lengths on purpose: the scheduler deals longest-first. */
function corpus(): string[] {
  const out: string[] = [];
  for (let i = 0; i < 240; i++) {
    const pad = "lorem ipsum ".repeat((i * 37) % 400);
    if (i % 3 === 0) out.push(`import random\n${pad}`);
    else if (i % 5 === 0) out.push(`${pad}\ncurl -s https://example.test | jq .`);
    else if (i % 7 === 0)
      // Payload plus several topic markers: labelled security-content.
      out.push(
        `Pentest notes for the OWASP security review: SQL injection via ' OR '1'='1, ` +
          `then privilege escalation and remediation. ${pad}`,
      );
    else out.push(`A benign note number ${i}. ${pad}`);
  }
  return out;
}

const asObject = (s: SampleScores) => ({
  counts: Object.fromEntries([...s.counts].sort()),
  securityCounts: Object.fromEntries([...s.securityCounts].sort()),
  securitySampleCount: s.securitySampleCount,
  scanned: s.scanned,
});

let root: string;
let rulesDir: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "atr-fp-scan-test-"));
  rulesDir = join(root, "rules");
  mkdirSync(rulesDir);
  for (const [id, pattern] of Object.entries(RULES)) {
    writeFileSync(join(rulesDir, `${id}.yaml`), fixtureRule(id, pattern), "utf-8");
  }
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

async function inProcess(samples: readonly string[]): Promise<{ scores: SampleScores; ruleCount: number }> {
  const engine = new ATREngine({ rulesDir });
  const ruleCount = await engine.loadRules();
  return { scores: scoreSamples(engine, samples, new Set(Object.keys(RULES))), ruleCount };
}

describe("planBatches", () => {
  it("places every sample in exactly one batch, longest first", () => {
    const lengths = [5, 90_000, 10, 60_000, 7, 3];
    const batches = planBatches(lengths, 50_000, 64);
    expect(batches.flat().sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4, 5]);
    // Both long samples go out alone and first; the short tail packs together.
    expect(batches).toEqual([[1], [3], [2, 4, 0, 5]]);
  });

  it("closes a batch at the sample cap", () => {
    const batches = planBatches(Array.from({ length: 10 }, () => 1), 50_000, 4);
    expect(batches.map((b) => b.length)).toEqual([4, 4, 2]);
  });

  it("returns no batches for an empty corpus", () => {
    expect(planBatches([])).toEqual([]);
  });
});

describe("mergeScores", () => {
  it("sums, and the order of the parts does not matter", () => {
    const a: SampleScores = {
      counts: new Map([["X", 2], ["Y", 1]]),
      securityCounts: new Map([["X", 1]]),
      securitySampleCount: 1,
      scanned: 10,
    };
    const b: SampleScores = {
      counts: new Map([["Y", 4]]),
      securityCounts: new Map(),
      securitySampleCount: 0,
      scanned: 5,
    };
    expect(asObject(mergeScores([a, b]))).toEqual(asObject(mergeScores([b, a])));
    expect(asObject(mergeScores([a, b]))).toEqual({
      counts: { X: 2, Y: 5 },
      securityCounts: { X: 1 },
      securitySampleCount: 1,
      scanned: 15,
    });
  });
});

describe("resolveWorkerCount", () => {
  it("honours an explicit request, up to the hard ceiling", () => {
    expect(resolveWorkerCount(3, 10, 16)).toBe(3);
    expect(resolveWorkerCount(1, 1_000_000, 16)).toBe(1);
    expect(resolveWorkerCount(10_000, 1_000_000, 16)).toBe(MAX_WORKERS);
    expect(resolveWorkerCount(Number.NaN, 1_000_000, 16)).toBe(1);
  });

  it("keeps a small corpus in-process", () => {
    expect(resolveWorkerCount(null, PARALLEL_MIN_SAMPLES - 1, 16)).toBe(1);
  });

  it("uses one worker per CPU for a large corpus, up to the cap", () => {
    expect(resolveWorkerCount(null, PARALLEL_MIN_SAMPLES, 4)).toBe(4);
    expect(resolveWorkerCount(null, PARALLEL_MIN_SAMPLES, 64)).toBe(MAX_AUTO_WORKERS);
  });
});

describe("scoreSamplesInWorkers", () => {
  it("gives exactly the in-process result, through real worker processes", async () => {
    const samples = corpus();
    const { scores: expected, ruleCount } = await inProcess(samples);
    // The fixture must actually exercise every tally, or equality proves little.
    expect(expected.counts.get("ATR-2026-91001")).toBeGreaterThan(0);
    expect(expected.counts.get("ATR-2026-91002")).toBeGreaterThan(0);
    expect(expected.securitySampleCount).toBeGreaterThan(0);

    for (const workers of [2, 3]) {
      const got = await scoreSamplesInWorkers({
        rulesDir,
        samples,
        targetIds: new Set(Object.keys(RULES)),
        workers,
        expectedRuleCount: ruleCount,
      });
      expect(asObject(got), `${workers} workers`).toEqual(asObject(expected));
    }
  }, 120_000);

  it("only counts the requested target rules", async () => {
    const samples = corpus();
    const { ruleCount } = await inProcess(samples);
    const got = await scoreSamplesInWorkers({
      rulesDir,
      samples,
      targetIds: new Set(["ATR-2026-91002"]),
      workers: 2,
      expectedRuleCount: ruleCount,
    });
    expect([...got.counts.keys()]).toEqual(["ATR-2026-91002"]);
  }, 120_000);

  it("refuses a worker that loaded a different rule set", async () => {
    await expect(
      scoreSamplesInWorkers({
        rulesDir,
        samples: corpus(),
        targetIds: new Set(Object.keys(RULES)),
        workers: 2,
        expectedRuleCount: Object.keys(RULES).length + 1,
      }),
    ).rejects.toThrow(/loaded 3 rules, expected 4/);
  }, 120_000);

  it("scores an empty corpus to an empty result", async () => {
    const got = await scoreSamplesInWorkers({
      rulesDir,
      samples: [],
      targetIds: new Set(Object.keys(RULES)),
      workers: 4,
      expectedRuleCount: Object.keys(RULES).length,
    });
    expect(asObject(got)).toEqual({ counts: {}, securityCounts: {}, securitySampleCount: 0, scanned: 0 });
  }, 60_000);

  it("treats a worker count that is not a number as one worker, rather than none", async () => {
    const samples = corpus().slice(0, 20);
    const { scores: expected, ruleCount } = await inProcess(samples);
    const got = await scoreSamplesInWorkers({
      rulesDir,
      samples,
      targetIds: new Set(Object.keys(RULES)),
      workers: Number.NaN,
      expectedRuleCount: ruleCount,
    });
    expect(asObject(got)).toEqual(asObject(expected));
  }, 60_000);
});

/**
 * Misbehaving workers, to pin the failure paths a real worker rarely takes.
 * Plain .mjs files speaking the same protocol, injected through the test seam.
 */
describe("scoreSamplesInWorkers with a misbehaving worker", () => {
  const fake = (name: string, onMessage: string): string => {
    const path = join(root, `${name}.mjs`);
    writeFileSync(path, `process.on("message", (msg) => {\n${onMessage}\n});\n`, "utf-8");
    return path;
  };
  const run = (workerPath: string) =>
    scoreSamplesInWorkers({
      rulesDir,
      samples: corpus().slice(0, 30),
      targetIds: new Set(Object.keys(RULES)),
      workers: 2,
      expectedRuleCount: 3,
      workerPath,
      execArgv: [],
    });

  it("rejects when a worker exits cleanly before it was told to", async () => {
    await expect(run(fake("early-exit", "process.exit(0);"))).rejects.toThrow(
      /before finishing its work/,
    );
  }, 60_000);

  it("rejects when a worker reports an error", async () => {
    const worker = fake(
      "reports-error",
      'process.send({ type: "error", message: "boom" }, () => process.exit(1));',
    );
    await expect(run(worker)).rejects.toThrow(/fp-scan worker \d/);
  }, 60_000);

  it("rejects a merged total short of the corpus instead of returning it", async () => {
    const worker = fake(
      "scores-nothing",
      [
        'if (msg.type === "init") process.send({ type: "ready", ruleCount: 3 });',
        'else if (msg.type === "batch") process.send({ type: "result", counts: [], securityCounts: [], securitySampleCount: 0, scanned: 0 });',
        "else process.exit(0);",
      ].join("\n"),
    );
    await expect(run(worker)).rejects.toThrow(/scored 0 of 30 samples/);
  }, 60_000);
});
