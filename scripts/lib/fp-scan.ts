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
import { availableParallelism } from "node:os";
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
/** Ceiling for the automatic worker count; --workers can still go higher. */
export const MAX_AUTO_WORKERS = 8;
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
  cpus: number = availableParallelism(),
): number {
  if (requested !== null) return Math.max(1, Math.floor(requested));
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
}

/**
 * Score samples across worker processes and merge the results.
 *
 * Rejects — and kills the remaining workers — on any worker error, on a worker
 * that exits before it was told to, on a worker that loaded a different rule
 * count, and on a merged total that does not equal the corpus. A partial scan
 * must never come back looking like a complete one.
 */
export function scoreSamplesInWorkers(req: ParallelScanRequest): Promise<SampleScores> {
  const batches = planBatches(req.samples.map((s) => s.length));
  const workers = Math.max(1, Math.min(req.workers, batches.length));
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

  const loader = tsxLoader();
  return new Promise<SampleScores>((resolve, reject) => {
    const children: ReturnType<typeof fork>[] = [];
    const fail = (err: Error): void => {
      if (failed) return;
      failed = true;
      for (const c of children) if (c.exitCode === null) c.kill();
      reject(err);
    };

    for (let k = 0; k < workers; k++) {
      let told = false;
      let inFlightChars = 0;
      const child = fork(WORKER_PATH, [], {
        execArgv: ["--import", loader],
        env: { ...process.env, ATR_FP_SCAN_WORKER: "1" },
        serialization: "advanced",
      });
      children.push(child);

      const send = (msg: ParentMessage): void => {
        try {
          child.send(msg);
        } catch (e) {
          fail(e instanceof Error ? e : new Error(String(e)));
        }
      };
      const dispatch = (): void => {
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
        resolve(merged);
      });

      send({ type: "init", rulesDir: req.rulesDir, targetIds: [...req.targetIds] });
    }
  });
}
