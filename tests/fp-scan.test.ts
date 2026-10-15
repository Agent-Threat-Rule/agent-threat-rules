/**
 * Tests for scripts/lib/fp-scan.ts — the benign-corpus FP scan split across
 * worker processes.
 *
 * The one contract that matters: fanning the scan out changes how long it takes
 * and nothing else. Every test that touches workers compares against the
 * in-process scoreSamples() on the same input, through real child processes.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { fork, spawn, spawnSync, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import {
  closeSync,
  mkdtempSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  writeFileSync,
  rmSync,
} from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { constants as osConstants, tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
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

/**
 * Stopping a scan midway. A worker scoring a batch notices nothing — not a
 * signal listener, not a message, not its parent going away — until the batch
 * is done, and one batch can be minutes of work. Each case below runs a real
 * process tree and waits for every process in it to be gone.
 */
const requireFromTests = createRequire(import.meta.url);
/** How fp-scan.ts starts its workers. */
const TSX_LOADER = pathToFileURL(requireFromTests.resolve("tsx")).href;
const FP_SCAN_URL = new URL("../scripts/lib/fp-scan.ts", import.meta.url).href;
const WORKER_PATH = fileURLToPath(new URL("../scripts/lib/fp-scan-worker.ts", import.meta.url));

/** Poll until `probe` returns something other than null. */
async function waitFor<T>(what: string, timeoutMs: number, probe: () => T | null): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = probe();
    if (value !== null) return value;
    if (Date.now() > deadline) throw new Error(`timed out after ${timeoutMs}ms waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 25));
  }
}

/** Settle with `p`, or reject once `ms` have passed, so a `finally` always gets to run. */
async function within<T>(ms: number, what: string, p: Promise<T>): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out after ${ms}ms waiting for ${what}`)), ms);
  });
  try {
    return await Promise.race([p, timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/** True while `pid` is a live process. A zombie has already exited; it only waits to be reaped. */
function isRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
  const ps = spawnSync("ps", ["-o", "stat=", "-p", String(pid)], { encoding: "utf-8" });
  // Without ps a zombie cannot be told apart, so count it as running.
  if (ps.error !== undefined) return true;
  const stat = ps.stdout.trim();
  return stat !== "" && !stat.startsWith("Z");
}

interface StopRun {
  /** What the test sends the process it started. */
  readonly send: NodeJS.Signals;
  /** Plain node, or the tsx CLI, which is how CI and `npx tsx` run the gate. */
  readonly launcher: "node" | "tsx";
  /** Code the scanning process runs before it starts the scan. */
  readonly preamble?: string;
}

interface StoppedScan {
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
  /** Workers still running 5s after the process was sent `send`. */
  readonly survivors: readonly number[];
  /** What the processes wrote to stderr. */
  readonly stderr: string;
}

/** Where one stop-midway case keeps its scripts, pid records, stop file and stderr. */
interface StopDir {
  readonly dir: string;
  readonly pidDir: string;
  readonly stopFile: string;
  readonly stderrPath: string;
}

function makeStopDir(): StopDir {
  const dir = mkdtempSync(join(root, "stop-"));
  const pidDir = join(dir, "pids");
  mkdirSync(pidDir);
  return { dir, pidDir, stopFile: join(dir, "stop"), stderrPath: join(dir, "stderr.txt") };
}

/** A line of generated JS that records the running process's pid as `kind`. */
function recordPid(d: StopDir, kind: string): string {
  return `writeFileSync(${JSON.stringify(d.pidDir)} + "/${kind}-" + process.pid, "");`;
}

/** The pids recorded so far by processes of `kind`. */
function recordedPids(d: StopDir, kind: string): number[] {
  return readdirSync(d.pidDir)
    .filter((name) => name.startsWith(`${kind}-`))
    .map((name) => Number(name.slice(kind.length + 1)));
}

/**
 * A worker that is busy the way a real one is while it scores a batch: a
 * synchronous loop, so only the operating system can stop it. It gives up after
 * 20s, or at once when the stop file appears.
 */
function writeBusyWorker(d: StopDir): string {
  const path = join(d.dir, "busy-worker.mjs");
  const source = [
    'import { existsSync, writeFileSync } from "node:fs";',
    recordPid(d, "worker"),
    'process.on("message", (msg) => {',
    '  if (msg.type === "init") process.send({ type: "ready", ruleCount: 3 });',
    '  if (msg.type !== "batch") return;',
    `  ${recordPid(d, "busy")}`,
    "  const until = Date.now() + 20_000;",
    `  while (Date.now() < until && !existsSync(${JSON.stringify(d.stopFile)})) {}`,
    "  process.exit(0);",
    "});",
  ];
  writeFileSync(path, source.join("\n"), "utf-8");
  return path;
}

/**
 * A process that runs a two-worker scan of `workerPath`, starting the workers
 * the way real ones are (with the tsx loader). It gives up after 30s, or at once
 * when the stop file appears.
 */
function writeScanner(d: StopDir, workerPath: string, preamble: string): string {
  const path = join(d.dir, "scanner.mjs");
  const source = [
    'import { existsSync, writeFileSync } from "node:fs";',
    `import { scoreSamplesInWorkers } from ${JSON.stringify(FP_SCAN_URL)};`,
    recordPid(d, "scanner"),
    "const until = Date.now() + 30_000;",
    "setInterval(() => {",
    `  if (Date.now() > until || existsSync(${JSON.stringify(d.stopFile)})) process.exit(9);`,
    "}, 50).unref();",
    preamble,
    "scoreSamplesInWorkers({",
    `  rulesDir: ${JSON.stringify(rulesDir)},`,
    // Too long to share a batch: four batches, so both workers get one.
    '  samples: Array.from({ length: 4 }, () => "x".repeat(40_000)),',
    "  targetIds: new Set(),",
    "  workers: 2,",
    "  expectedRuleCount: 3,",
    `  workerPath: ${JSON.stringify(workerPath)},`,
    `  execArgv: ["--import", ${JSON.stringify(TSX_LOADER)}],`,
    "}).then(",
    "  () => process.exit(0),",
    "  (e) => { console.error(String(e)); process.exitCode = 2; },",
    ");",
  ];
  writeFileSync(path, source.join("\n"), "utf-8");
  return path;
}

/** Release whatever a case started and wait for every recorded process to be gone. */
async function releaseAll(d: StopDir, parent: ChildProcess): Promise<void> {
  writeFileSync(d.stopFile, "");
  if (parent.exitCode === null && parent.signalCode === null) parent.kill("SIGKILL");
  const started = (): number[] => [
    ...(parent.pid === undefined ? [] : [parent.pid]),
    ...recordedPids(d, "scanner"),
    ...recordedPids(d, "worker"),
  ];
  await waitFor("every process this test started to stop", 10_000, () =>
    started().some(isRunning) ? null : true,
  );
}

/**
 * Run a two-worker scan in a process of its own, wait until both workers are
 * busy with a batch, send the process the test started `run.send`, and see
 * which workers are still running. Every process records its pid as it starts,
 * and the case waits for each of them to be gone, whatever happened.
 */
async function stopMidScan(run: StopRun): Promise<StoppedScan> {
  const d = makeStopDir();
  const scanner = writeScanner(d, writeBusyWorker(d), run.preamble ?? "");
  const args =
    run.launcher === "node"
      ? ["--import", TSX_LOADER, scanner]
      : [requireFromTests.resolve("tsx/cli"), scanner];
  const stderrFd = openSync(d.stderrPath, "w");
  const parent = spawn(process.execPath, args, { stdio: ["ignore", "ignore", stderrFd] });
  closeSync(stderrFd);
  const exited = once(parent, "exit") as Promise<[number | null, NodeJS.Signals | null]>;
  const stderr = (): string => readFileSync(d.stderrPath, "utf-8");
  const withStderr = (e: Error): never => {
    throw new Error(`${e.message}; stderr: ${stderr().slice(-2_000)}`);
  };
  let failed = true;
  try {
    await waitFor("both workers to hold a batch", 30_000, () =>
      recordedPids(d, "busy").length === 2 ? true : null,
    ).catch(withStderr);
    parent.kill(run.send);
    const [code, signal] = await within(40_000, "the parent to exit", exited).catch(withStderr);
    const workers = recordedPids(d, "worker");
    const survivors = await waitFor("the workers to stop", 5_000, () =>
      workers.some(isRunning) ? null : [],
    ).catch(() => workers.filter(isRunning));
    failed = false;
    return { code, signal, survivors, stderr: stderr() };
  } finally {
    // A cleanup that times out must not hide the failure that came first.
    const released = releaseAll(d, parent);
    await (failed ? released.catch(() => undefined) : released);
  }
}

describe("scoreSamplesInWorkers when the parent is stopped", () => {
  for (const send of ["SIGTERM", "SIGINT"] as const) {
    it(`stops its workers on ${send}, then dies of ${send}`, async () => {
      const stopped = await stopMidScan({ send, launcher: "node" });
      expect(stopped.survivors).toEqual([]);
      expect(stopped.signal).toBe(send);
    }, 120_000);

    it(`stops its workers on ${send} under the tsx CLI, which exits 128 + the signal number`, async () => {
      const stopped = await stopMidScan({ send, launcher: "tsx" });
      expect(stopped.survivors).toEqual([]);
      expect(stopped.code).toBe(128 + osConstants.signals[send]);
    }, 120_000);
  }

  it("leaves the signal to another listener, but still stops its workers and rejects", async () => {
    // once(): such a listener removes itself before it runs, and still counts.
    const stopped = await stopMidScan({
      send: "SIGTERM",
      launcher: "node",
      preamble: 'process.once("SIGTERM", () => console.error("other listener ran"));',
    });
    expect(stopped.survivors).toEqual([]);
    expect(stopped.signal).toBe(null);
    expect(stopped.code).toBe(2);
    expect(stopped.stderr).toMatch(/other listener ran/);
    expect(stopped.stderr).toMatch(/fp-scan interrupted by SIGTERM/);
  }, 120_000);

  it("stops its workers when the parent dies of an uncaught exception", async () => {
    const stopped = await stopMidScan({
      send: "SIGUSR2",
      launcher: "node",
      preamble: 'process.on("SIGUSR2", () => { throw new Error("scanner crashed"); });',
    });
    expect(stopped.survivors).toEqual([]);
    expect(stopped.code).toBe(1);
    expect(stopped.stderr).toMatch(/scanner crashed/);
  }, 120_000);

  it("holds its listeners only while the scan runs", async () => {
    const listeners = () => ["SIGINT", "SIGTERM", "exit"].map((e) => process.listenerCount(e));
    const before = listeners();
    const scan = (expectedRuleCount: number) =>
      scoreSamplesInWorkers({
        rulesDir,
        samples: corpus().slice(0, 30),
        targetIds: new Set(Object.keys(RULES)),
        workers: 2,
        expectedRuleCount,
      });

    const passing = scan(Object.keys(RULES).length);
    expect(listeners()).toEqual(before.map((n) => n + 1));
    await passing;
    expect(listeners()).toEqual(before);

    const failing = scan(Object.keys(RULES).length + 1);
    // Awaited below; this only keeps an earlier failed assertion from leaving
    // the rejection unhandled.
    failing.catch(() => undefined);
    expect(listeners()).toEqual(before.map((n) => n + 1));
    await expect(failing).rejects.toThrow(/expected 4/);
    expect(listeners()).toEqual(before);
  }, 120_000);
});

describe("fp-scan-worker when its parent goes away", () => {
  const startWorker = () =>
    fork(WORKER_PATH, [], {
      execArgv: ["--import", TSX_LOADER],
      env: { ...process.env, ATR_FP_SCAN_WORKER: "1" },
      serialization: "advanced",
    });

  it("exits 1 once the channel to the parent closes", async () => {
    const child = startWorker();
    const exited = once(child, "exit") as Promise<[number | null, NodeJS.Signals | null]>;
    try {
      child.send({ type: "init", rulesDir, targetIds: Object.keys(RULES) });
      const [ready] = await within(30_000, "the worker to load its rules", once(child, "message"));
      expect(ready).toEqual({ type: "ready", ruleCount: 3 });
      // All a worker can see of a parent that died without sending `end`.
      child.disconnect();
      const [code] = await within(10_000, "the worker to exit", exited);
      // Not 0: the work was not done.
      expect(code).toBe(1);
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    }
  }, 60_000);

  it("exits 1 when the channel closed while it was still loading", async () => {
    const child = startWorker();
    const exited = once(child, "exit") as Promise<[number | null, NodeJS.Signals | null]>;
    try {
      child.disconnect();
      const [code] = await within(30_000, "the worker to exit", exited);
      expect(code).toBe(1);
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    }
  }, 60_000);
});
