/**
 * fp-scan.ts — the benign-corpus false-positive scan, in one process or several.
 *
 * WHY THIS EXISTS
 *
 * The scheduled reverify job in .github/workflows/action-eligibility.yml re-runs
 * every rule over every benign sample, and it had never once finished: 67
 * scheduled runs from 2026-08-09 to 2026-10-14, 62 cancelled at their timeout,
 * the other 4 spending 3h08m-3h14m on a single core. Everything it computes is a
 * per-sample verdict summed per rule, so the work splits across processes
 * exactly — the merged counts are the same for any number of workers and any
 * order of samples. Measured 2026-10-15 over the full 13,848-sample corpus:
 * every one of the 793 rules recorded in data/benign-fp-measurement.json came
 * back field for field.
 *
 * SCHEDULING
 *
 * The cost of a sample is nothing like uniform. The slowest 10% of samples were
 * 66% of the work, and one 81,627-character document took 185 seconds by itself.
 * A fixed split hands one worker most of the long documents and leaves the others
 * idle — the first prototype finished 8 of 9 workers while the ninth ran on. So
 * samples are dealt longest-first, in small batches, to whichever worker asks
 * next.
 *
 * The in-process path (scoreSamples) is the original loop, unchanged; small
 * corpora — every test fixture — still take it.
 */
import { fork } from "node:child_process";
import { createRequire } from "node:module";
import * as os from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { classifySecurityContent } from "../../src/corpus/security-content.js";
import { matchedRuleIds, type ScannableEngine } from "./corpus-event.js";

/** Per-rule false-positive tallies over some set of samples. */
export interface SampleScores {
  /** Samples each target rule matched (rules that matched nothing are absent). */
  readonly counts: ReadonlyMap<string, number>;
  /** The part of `counts` that landed on security-content samples. */
  readonly securityCounts: ReadonlyMap<string, number>;
  /** Samples labelled security-content. */
  readonly securitySampleCount: number;
  /** Samples scored. A merge that does not add up to the corpus is an error. */
  readonly scanned: number;
}

/** Below this many samples the cost of starting workers outweighs them. */
export const PARALLEL_MIN_SAMPLES = 1_000;
/** Ceiling for the automatic worker count; --workers can still go higher... */
export const MAX_AUTO_WORKERS = 8;
/** ...up to this hard ceiling, so a typo cannot fork thousands of processes. */
export const MAX_WORKERS = 64;

/** CPUs available to this process; availableParallelism() is Node 18.14+. */
function cpuCount(): number {
  return typeof os.availableParallelism === "function" ? os.availableParallelism() : os.cpus().length;
}
/**
 * Signals that end a parallel scan early. A worker scoring a batch notices
 * nothing until the batch is done, and one batch can be minutes of work, so on
 * either signal the parent stops its workers before it goes rather than leave
 * them running, reparented to PID 1, after it.
 */
export const STOP_SIGNALS: readonly NodeJS.Signals[] = ["SIGINT", "SIGTERM"];
/** How often a parallel scan reports progress. */
export const PROGRESS_EVERY_MS = 60_000;
/** A batch closes once it holds this many characters... */
export const BATCH_MAX_CHARS = 50_000;
/** ...or this many samples, whichever comes first. */
export const BATCH_MAX_SAMPLES = 64;

/**
 * Score samples against the target rules in this process.
 *
 * Counted PER SAMPLE through matchedRuleIds(): a document that trips a rule on
 * several shapes is one false positive, not several.
 */
export function scoreSamples(
  engine: ScannableEngine,
  samples: readonly string[],
  targetIds: ReadonlySet<string>,
): SampleScores {
  const counts = new Map<string, number>();
  const securityCounts = new Map<string, number>();
  let securitySampleCount = 0;
  for (const text of samples) {
    // Labelled BEFORE the rules run and from the sample text alone. The label
    // cannot be a function of which rules fired, or it degenerates into
    // "whatever is inconvenient is not benign".
    const isSecurityContent =
      classifySecurityContent(text).label === "security-content";
    if (isSecurityContent) securitySampleCount += 1;
    for (const id of matchedRuleIds(engine, text)) {
      if (!targetIds.has(id)) continue;
      counts.set(id, (counts.get(id) ?? 0) + 1);
      if (isSecurityContent)
        securityCounts.set(id, (securityCounts.get(id) ?? 0) + 1);
    }
  }
  return { counts, securityCounts, securitySampleCount, scanned: samples.length };
}

/** Sum partial scores. Pure; the result does not depend on the order of `parts`. */
export function mergeScores(parts: readonly SampleScores[]): SampleScores {
  const counts = new Map<string, number>();
  const securityCounts = new Map<string, number>();
  let securitySampleCount = 0;
  let scanned = 0;
  for (const p of parts) {
    for (const [id, n] of p.counts) counts.set(id, (counts.get(id) ?? 0) + n);
    for (const [id, n] of p.securityCounts)
      securityCounts.set(id, (securityCounts.get(id) ?? 0) + n);
    securitySampleCount += p.securitySampleCount;
    scanned += p.scanned;
  }
  return { counts, securityCounts, securitySampleCount, scanned };
}

/**
 * Group sample indices into batches, longest samples first.
 *
 * Every index appears in exactly one batch. A sample longer than the character
 * budget gets a batch of its own, so the most expensive documents are handed out
 * first and individually, and the cheap tail is packed tightly at the end.
 */
export function planBatches(
  lengths: readonly number[],
  maxChars = BATCH_MAX_CHARS,
  maxSamples = BATCH_MAX_SAMPLES,
): readonly (readonly number[])[] {
  const order = lengths
    .map((len, i) => [len, i] as const)
    .sort((a, b) => b[0] - a[0] || a[1] - b[1])
    .map(([, i]) => i);
  const batches: number[][] = [];
  let current: number[] = [];
  let chars = 0;
  for (const i of order) {
    const len = lengths[i] ?? 0;
    if (current.length > 0 && (chars + len > maxChars || current.length >= maxSamples)) {
      batches.push(current);
      current = [];
      chars = 0;
    }
    current.push(i);
    chars += len;
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

/**
 * How many worker processes to use.
 *
 * An explicit request wins. Otherwise a small corpus stays in-process (every
 * unit-test fixture does), and a large one gets one worker per CPU up to
 * MAX_AUTO_WORKERS. The answer never changes WHAT is measured, only how fast.
 */
export function resolveWorkerCount(
  requested: number | null,
  sampleCount: number,
  cpus: number = cpuCount(),
): number {
  if (requested !== null) {
    return Number.isFinite(requested) ? Math.max(1, Math.min(Math.floor(requested), MAX_WORKERS)) : 1;
  }
  if (sampleCount < PARALLEL_MIN_SAMPLES) return 1;
  return Math.max(1, Math.min(cpus, MAX_AUTO_WORKERS));
}

// ---------------------------------------------------------------------------
// Worker processes
// ---------------------------------------------------------------------------

const WORKER_PATH = join(dirname(fileURLToPath(import.meta.url)), "fp-scan-worker.ts");
/**
 * The TypeScript loader each worker is started with. Resolved to an absolute
 * URL so a worker loads the same way however the parent was started (npx tsx,
 * node --import tsx, or a test runner with its own transform).
 */
function tsxLoader(): string {
  return pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;
}

/** What a worker sends back. Maps travel as entry arrays. */
export type WorkerMessage =
  | { readonly type: "ready"; readonly ruleCount: number }
  | {
      readonly type: "result";
      readonly counts: readonly (readonly [string, number])[];
      readonly securityCounts: readonly (readonly [string, number])[];
      readonly securitySampleCount: number;
      readonly scanned: number;
    }
  | { readonly type: "error"; readonly message: string };

/** What the parent sends a worker. */
export type ParentMessage =
  | { readonly type: "init"; readonly rulesDir: string; readonly targetIds: readonly string[] }
  | { readonly type: "batch"; readonly texts: readonly string[] }
  | { readonly type: "end" };

export interface ParallelScanRequest {
  /** Directory holding exactly the rule files to load — the parent's own. */
  readonly rulesDir: string;
  readonly samples: readonly string[];
  readonly targetIds: ReadonlySet<string>;
  readonly workers: number;
  /** Rules the parent loaded from rulesDir. A worker that loads a different number is an error. */
  readonly expectedRuleCount: number;
  /** Progress lines, one every PROGRESS_EVERY_MS. */
  readonly log?: (line: string) => void;
  /** Test seam: the worker script to fork, and the node flags to start it with. */
  readonly workerPath?: string;
  readonly execArgv?: readonly string[];
}

/**
 * Score samples across worker processes and merge the results.
 *
 * Rejects — and kills the remaining workers — on any worker error, on a worker
 * that exits before it was told to, on a worker that loaded a different rule
 * count, and on a merged total that does not equal the corpus. A partial scan
 * must never come back looking like a complete one.
 *
 * The workers also go when the parent goes while the scan runs: on a
 * STOP_SIGNALS signal (the scan rejects, and the signal is delivered again so
 * the parent still ends; see onStopSignal), and on any other exit that still
 * emits 'exit', such as an uncaught exception or process.exit() elsewhere. Only
 * an end that runs no JavaScript (SIGKILL, a native crash) leaves them to stop
 * on their own; see fp-scan-worker.ts.
 */
export function scoreSamplesInWorkers(req: ParallelScanRequest): Promise<SampleScores> {
  const batches = planBatches(req.samples.map((s) => s.length));
  const requested = Number.isFinite(req.workers) ? Math.floor(req.workers) : 1;
  const workers = Math.max(1, Math.min(requested, MAX_WORKERS, batches.length));
  const started = Date.now();
  // Progress is reported against characters, not samples: the longest samples go
  // out first and carry most of the work, so "10% of samples" would arrive late
  // and read as a stall.
  const totalChars = req.samples.reduce((n, s) => n + s.length, 0);
  let lastReport = started;
  let next = 0;
  let scored = 0;
  let scoredChars = 0;
  let exited = 0;
  let failed = false;
  const parts: SampleScores[] = [];

  const workerPath = req.workerPath ?? WORKER_PATH;
  const execArgv = req.execArgv ?? ["--import", tsxLoader()];
  return new Promise<SampleScores>((resolve, reject) => {
    const children: ReturnType<typeof fork>[] = [];
    // kill(2) is synchronous, so this works from an 'exit' listener too.
    const killWorkers = (): void => {
      for (const c of children) if (c.exitCode === null && c.signalCode === null) c.kill();
    };
    // A listener on a signal replaces Node's default for it, which is to exit.
    // So this one stops the workers and then, unless something else in the
    // process is listening and owns the decision, delivers the signal again:
    // with the last listener gone the default is back, and the parent ends on
    // the signal instead of leaving its workers behind. (Under the tsx CLI, as
    // CI runs the gate, the CLI above it still exits 128 + the signal number.)
    const onStopSignal = (signal: NodeJS.Signals): void => {
      fail(new Error(`fp-scan interrupted by ${signal}`));
      if (process.listenerCount(signal) === 0) process.kill(process.pid, signal);
    };
    // Each bound to its own signal, since process.emit("SIGINT") passes none,
    // and prepended, so that the count above still includes every other
    // listener, a process.once() one that would otherwise run first included.
    const signalListeners = STOP_SIGNALS.map((s) => [s, () => onStopSignal(s)] as const);
    // The listeners belong to the scan: added before the first fork, removed
    // as soon as the scan resolves or rejects.
    const listen = (): void => {
      for (const [s, l] of signalListeners) process.prependListener(s, l);
      process.on("exit", killWorkers);
    };
    const unlisten = (): void => {
      for (const [s, l] of signalListeners) process.off(s, l);
      process.off("exit", killWorkers);
    };
    // Once failed, every handler below is a no-op and every child is killed:
    // a rejected scan must not leave workers grinding through the corpus. The
    // kill comes before the listeners go, so a second signal arriving meanwhile
    // is still caught instead of ending the parent partway through the list.
    const fail = (err: Error): void => {
      if (failed) return;
      failed = true;
      killWorkers();
      unlisten();
      reject(err);
    };
    listen();

    const start = (k: number): void => {
      let told = false;
      let inFlightChars = 0;
      const child = fork(workerPath, [], {
        execArgv: [...execArgv],
        env: { ...process.env, ATR_FP_SCAN_WORKER: "1" },
        serialization: "advanced",
      });
      children.push(child);

      const send = (msg: ParentMessage): void => {
        if (failed) return;
        try {
          child.send(msg);
        } catch (e) {
          fail(e instanceof Error ? e : new Error(String(e)));
        }
      };
      const dispatch = (): void => {
        if (failed) return;
        const batch = batches[next];
        if (batch === undefined) {
          told = true;
          send({ type: "end" });
          return;
        }
        next += 1;
        const texts = batch.map((i) => req.samples[i] as string);
        inFlightChars = texts.reduce((n, t) => n + t.length, 0);
        send({ type: "batch", texts });
      };

      child.on("message", (raw: unknown) => {
        if (failed) return;
        const msg = raw as WorkerMessage;
        if (msg.type === "ready") {
          if (msg.ruleCount !== req.expectedRuleCount) {
            fail(
              new Error(
                `fp-scan worker ${k} loaded ${msg.ruleCount} rules, expected ${req.expectedRuleCount}`,
              ),
            );
            return;
          }
          dispatch();
        } else if (msg.type === "result") {
          parts.push({
            counts: new Map(msg.counts),
            securityCounts: new Map(msg.securityCounts),
            securitySampleCount: msg.securitySampleCount,
            scanned: msg.scanned,
          });
          scored += msg.scanned;
          scoredChars += inFlightChars;
          const now = Date.now();
          if (req.log !== undefined && now - lastReport >= PROGRESS_EVERY_MS) {
            lastReport = now;
            const pct = totalChars === 0 ? 100 : Math.floor((100 * scoredChars) / totalChars);
            req.log(
              `scored ${scored}/${req.samples.length} samples (${pct}% of the text) ` +
                `on ${workers} workers, ${Math.round((now - started) / 1000)}s`,
            );
          }
          dispatch();
        } else {
          fail(new Error(`fp-scan worker ${k}: ${msg.message}`));
        }
      });
      child.on("error", (e) => fail(e));
      child.on("exit", (code, signal) => {
        if (failed) return;
        if (!told || code !== 0) {
          fail(
            new Error(
              `fp-scan worker ${k} exited (code ${code}, signal ${signal}) before finishing its work`,
            ),
          );
          return;
        }
        exited += 1;
        if (exited < workers) return;
        const merged = mergeScores(parts);
        if (merged.scanned !== req.samples.length) {
          fail(
            new Error(`fp-scan workers scored ${merged.scanned} of ${req.samples.length} samples`),
          );
          return;
        }
        unlisten();
        resolve(merged);
      });

      send({ type: "init", rulesDir: req.rulesDir, targetIds: [...req.targetIds] });
    };

    // fork() can throw synchronously (ENOMEM, EAGAIN). Whatever was already
    // started is killed by fail(), and nothing more is started.
    try {
      for (let k = 0; k < workers && !failed; k++) start(k);
    } catch (e) {
      fail(e instanceof Error ? e : new Error(String(e)));
    }
  });
}
