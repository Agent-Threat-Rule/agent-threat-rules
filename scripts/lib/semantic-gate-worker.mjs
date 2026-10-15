/**
 * Worker entry for scripts/lib/semantic-gate-runner.ts.
 *
 * Runs the deterministic gate (checkDraft) off the lane's main thread, so a
 * fallback regex that backtracks catastrophically can be stopped by the
 * runner's time budget: worker.terminate() interrupts a V8 regex mid-match,
 * and nothing in the same thread can.
 *
 * Plain .mjs on purpose. The runner starts the worker with no inherited
 * execArgv, so it has neither `npx tsx`'s loader (CI) nor vite-node (vitest);
 * it registers tsx itself before importing the TypeScript gate.
 */
import { parentPort, workerData } from "node:worker_threads";
import { register } from "tsx/esm/api";

register();
const { checkDraft } = await import("./semantic-engine-gate.ts");
parentPort.postMessage(checkDraft(workerData));
