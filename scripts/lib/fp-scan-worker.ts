/**
 * fp-scan-worker.ts — one worker process of the benign-corpus FP scan.
 *
 * Started only by scoreSamplesInWorkers() in ./fp-scan.ts, never run by hand.
 * It loads the same rule directory the parent loaded, then scores whatever
 * batches it is handed with the same scoreSamples() the in-process path uses,
 * so a sample is scored identically whichever process scores it.
 *
 * Protocol (all over the IPC channel, in order):
 *   parent -> init {rulesDir, targetIds}   worker -> ready {ruleCount}
 *   parent -> batch {texts}                worker -> result {counts, ...}
 *   ...                                    ...
 *   parent -> end                          worker exits 0
 * Any failure is reported as `error` and the worker exits 1.
 */
import { ATREngine } from "../../src/engine.js";
import {
  scoreSamples,
  type ParentMessage,
  type WorkerMessage,
} from "./fp-scan.js";

function reply(msg: WorkerMessage): Promise<void> {
  return new Promise((resolve, reject) => {
    process.send!(msg, (err: Error | null) => (err ? reject(err) : resolve()));
  });
}

async function serve(): Promise<void> {
  let engine: ATREngine | null = null;
  let targets: ReadonlySet<string> = new Set();
  // Messages are handled strictly one at a time, in arrival order.
  let queue: Promise<void> = Promise.resolve();

  const handle = async (msg: ParentMessage): Promise<void> => {
    if (msg.type === "init") {
      engine = new ATREngine({ rulesDir: msg.rulesDir });
      const ruleCount = await engine.loadRules();
      targets = new Set(msg.targetIds);
      await reply({ type: "ready", ruleCount });
    } else if (msg.type === "batch") {
      if (engine === null) throw new Error("batch received before init");
      const s = scoreSamples(engine, msg.texts, targets);
      await reply({
        type: "result",
        counts: [...s.counts],
        securityCounts: [...s.securityCounts],
        securitySampleCount: s.securitySampleCount,
        scanned: s.scanned,
      });
    } else {
      process.exit(0);
    }
  };

  process.on("message", (raw: unknown) => {
    queue = queue
      .then(() => handle(raw as ParentMessage))
      .catch(async (e: unknown) => {
        const message = e instanceof Error ? (e.stack ?? e.message) : String(e);
        try {
          await reply({ type: "error", message });
        } finally {
          process.exit(1);
        }
      });
  });
}

if (process.send !== undefined && process.env.ATR_FP_SCAN_WORKER === "1") {
  void serve();
}
