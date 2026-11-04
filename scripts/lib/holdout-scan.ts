/**
 * holdout-scan.ts — run every holdout sample through the engine, in parallel.
 *
 * One pass per sample, two engines: a hunt-lane engine (every rule, so each
 * candidate's own matches can be attributed to it) and an enforce-lane engine
 * (the lane as it actually runs, including its withholding of unconfirmed
 * `confirm: embedding` rules). Lane-level figures come from the second, never
 * from a union of per-rule matches, so they describe the lane a user turns on.
 *
 * Both engines see the sample through matchedRuleIds(): the canonical shape
 * set every FP gate in this repo uses, identical for attacks and benign
 * samples. A rule cannot earn detection credit on a presentation it is not
 * charged false positives on.
 *
 * A sample that throws is recorded as an error and counted, never as "no
 * match" — eval-harness.ts maps exceptions to a clean verdict, and a
 * measurement that does that cannot tell a crash from a true negative.
 */
import { fork } from "node:child_process";
import { createRequire } from "node:module";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { ATREngine } from "../../src/engine.js";
import { matchedRuleIds } from "./corpus-event.js";
import type { HoldoutSample } from "./holdout.js";
import { rulesInLane } from "../../src/measurement/enforce-lane.js";

export interface SampleScan {
  readonly id: string;
  readonly hunt: readonly string[];
  readonly enforce: readonly string[];
  readonly ms: number;
  readonly error: string | null;
}

export interface ScanResult {
  readonly scans: ReadonlyMap<string, SampleScan>;
  readonly huntRules: number;
  readonly enforceRules: number;
}

export async function engines(rulesDir: string): Promise<{ hunt: ATREngine; enforce: ATREngine }> {
  const hunt = new ATREngine({ rulesDir, lane: "hunt" });
  const enforce = new ATREngine({ rulesDir, lane: "enforce" });
  await hunt.loadRules();
  await enforce.loadRules();
  return { hunt, enforce };
}

export function scanOne(hunt: ATREngine, enforce: ATREngine, s: HoldoutSample): SampleScan {
  const start = performance.now();
  try {
    const h = [...matchedRuleIds(hunt, s.text)].sort();
    const e = [...matchedRuleIds(enforce, s.text)].sort();
    return { id: s.id, hunt: h, enforce: e, ms: performance.now() - start, error: null };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { id: s.id, hunt: [], enforce: [], ms: performance.now() - start, error: message.slice(0, 200) };
  }
}

/** Worker entry: scan samples whose index i satisfies i % shards === shard. */
export async function runShard(
  rulesDir: string,
  samples: readonly HoldoutSample[],
  shard: number,
  shards: number,
  outPath: string,
): Promise<void> {
  const { hunt, enforce } = await engines(rulesDir);
  const lines: string[] = [JSON.stringify({
    huntRules: hunt.getRules().length,
    // getRules() lists every rule loaded; the lane decides which may fire.
    enforceRules: rulesInLane(enforce.getRules(), "enforce"),
  })];
  for (let i = shard; i < samples.length; i += shards) lines.push(JSON.stringify(scanOne(hunt, enforce, samples[i]!)));
  writeFileSync(outPath, lines.join("\n") + "\n");
}

function tsxLoader(): string {
  return pathToFileURL(createRequire(import.meta.url).resolve("tsx")).href;
}

function forkShard(script: string, args: readonly string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = fork(script, [...args], { execArgv: ["--import", tsxLoader()], stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code, signal) =>
      code === 0 ? resolve() : reject(new Error(`holdout scan worker ${args.join(" ")} exited ${code ?? signal}`)),
    );
  });
}

/**
 * Scan all samples across `workers` processes. Every sample must come back
 * exactly once and every worker must have loaded the same rule counts; anything
 * else rejects, so a partial scan can never be reported as a complete one.
 */
export async function scanAll(
  script: string,
  samples: readonly HoldoutSample[],
  workers: number,
): Promise<ScanResult> {
  const dir = mkdtempSync(join(tmpdir(), "atr-holdout-"));
  const outs = Array.from({ length: workers }, (_, i) => join(dir, `shard-${i}.jsonl`));
  await Promise.all(outs.map((out, i) => forkShard(script, ["--worker", String(i), String(workers), out])));
  const scans = new Map<string, SampleScan>();
  const counts = new Set<string>();
  let huntRules = 0;
  let enforceRules = 0;
  for (const out of outs) {
    const [head, ...rows] = readFileSync(out, "utf8").trim().split("\n");
    const h = JSON.parse(head!) as { huntRules: number; enforceRules: number };
    counts.add(`${h.huntRules}/${h.enforceRules}`);
    huntRules = h.huntRules;
    enforceRules = h.enforceRules;
    for (const row of rows) {
      const s = JSON.parse(row) as SampleScan;
      if (scans.has(s.id)) throw new Error(`holdout scan: sample ${s.id} scanned twice`);
      scans.set(s.id, s);
    }
  }
  if (counts.size !== 1) throw new Error(`holdout scan: workers loaded different rule counts ${[...counts].join(", ")}`);
  const missing = samples.filter((s) => !scans.has(s.id));
  if (missing.length > 0) throw new Error(`holdout scan: ${missing.length} samples never came back`);
  return { scans, huntRules, enforceRules };
}

export const THIS_DIR = fileURLToPath(new URL(".", import.meta.url));
