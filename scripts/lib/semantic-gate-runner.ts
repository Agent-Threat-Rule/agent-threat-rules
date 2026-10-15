/**
 * Run one draft's deterministic gate under a wall-clock budget.
 *
 * WHY
 *   The fallback regex is untrusted LLM output. The engine's isReDoSSafe only
 *   refuses one nested-quantifier shape; (?:\w+\s*)+ passes it and backtracks
 *   exponentially on any true_positive it does not match, and the gate is
 *   designed around such judge-only misses. The gate used to run in-process and
 *   synchronously, so one such draft hung the job until GitHub's six-hour limit
 *   killed it, and every rule already authored in that run was lost. Here the
 *   gate runs in a worker; past the budget the worker is terminated (that
 *   interrupts a V8 regex mid-match) and the draft is routed to human review.
 */
import { Worker } from "node:worker_threads";
import type { DraftCheckInput, DraftCheckResult } from "./semantic-engine-gate.js";

/**
 * Wall-clock budget for one draft's whole gate, worker start-up included. A
 * well-behaved draft finishes in seconds on MEASUREMENT_CORPORA; anything near
 * this is a pathological pattern, not a slow machine.
 */
export const GATE_TIME_BUDGET_MS = 120_000;

const WORKER_URL = new URL("./semantic-gate-worker.mjs", import.meta.url);

function overBudget(budgetMs: number): DraftCheckResult {
  return {
    gate: {
      ok: false,
      reason:
        `fallback_regex exceeded the gate time budget (${budgetMs} ms); catastrophic backtracking suspected. ` +
        "The draft was stopped and routed so it cannot hang the run.",
    },
  };
}

/**
 * Resolves with the gate's verdict, or with a routed verdict when the budget
 * runs out. Rejects when the worker fails without a verdict: that is the gate
 * not running, not a draft being judged, and must not read as a rejection.
 */
export function runDraftCheckWithBudget(
  input: DraftCheckInput,
  budgetMs: number = GATE_TIME_BUDGET_MS,
): Promise<DraftCheckResult> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(WORKER_URL, { workerData: input, execArgv: [] });
    let settled = false;
    const settle = (finish: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void worker.terminate().finally(finish);
    };
    const timer = setTimeout(() => settle(() => resolve(overBudget(budgetMs))), budgetMs);
    worker.once("message", (result: DraftCheckResult) => settle(() => resolve(result)));
    worker.once("error", (e: Error) => settle(() => reject(new Error(`gate worker failed: ${e.message}`))));
    worker.once("exit", (code: number) =>
      settle(() => reject(new Error(`gate worker exited with code ${code} before returning a verdict`))),
    );
  });
}
