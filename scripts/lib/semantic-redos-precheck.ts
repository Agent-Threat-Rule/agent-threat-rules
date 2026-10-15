/**
 * Per-draft ReDoS precheck: scripts/gate-redos.py on the one fallback.
 *
 * WHY
 *   A fallback can finish on every cluster sample and every benign sample and
 *   still hang on a string shaped like its own grammar. PR CI catches that with
 *   gate-redos.py (redos-gate.yml), which pumps inputs from the pattern's own
 *   parse tree. The lane did not run it, so such a draft reached the rolling PR
 *   and failed there; with the pre-push backstop it would fail the whole job
 *   instead. Running the same script on the draft alone routes just that draft.
 *
 * The script is run unchanged, against its committed baseline. The candidate
 * id is never in the baseline, so any slow condition is reported as NEW.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";
import { CANDIDATE_RULE_ID } from "./semantic-engine-gate.js";

/** gate-redos.py kills each condition after a few seconds; this only bounds a stuck interpreter. */
export const REDOS_PRECHECK_TIMEOUT_MS = 120_000;

export interface RedosRun {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  readonly error?: Error;
}

export type RedosVerdict =
  | { readonly kind: "ok" }
  | { readonly kind: "backtracks"; readonly detail: string }
  | { readonly kind: "unavailable"; readonly detail: string };

/** Printed by gate-redos.py when a condition outside the baseline is over budget. */
const FAIL_MARKER = "backtrack catastrophically";

const tail = (text: string): string => text.trim().split("\n").slice(-3).join(" | ").slice(0, 300);

/**
 * Exit 1 means two different things from gate-redos.py: a slow pattern, or a
 * Python that could not even import yaml. Only the first is a verdict on the
 * draft; reading the second as one would route every draft and leave the lane
 * quietly producing nothing.
 */
export function classifyRedosRun(run: RedosRun): RedosVerdict {
  if (run.error) return { kind: "unavailable", detail: run.error.message };
  if (run.status === 0) return { kind: "ok" };
  if (run.status === 1 && run.stdout.includes(FAIL_MARKER)) {
    const lines = run.stdout.split("\n").filter((l) => l.includes(CANDIDATE_RULE_ID));
    return { kind: "backtracks", detail: lines.map((l) => l.trim()).join("; ") || tail(run.stdout) };
  }
  return { kind: "unavailable", detail: `gate-redos.py exited ${run.status}: ${tail(run.stderr || run.stdout)}` };
}

/** The smallest rule gate-redos.py reads: one regex condition under the candidate id. */
function probeRule(fallback: string): string {
  return yaml.dump({
    id: CANDIDATE_RULE_ID,
    title: "semantic lane ReDoS precheck",
    detection: { conditions: [{ field: "user_input", operator: "regex", value: fallback }], condition: "any" },
  });
}

export function redosPrecheck(
  fallback: string,
  repoRoot: string,
  timeoutMs: number = REDOS_PRECHECK_TIMEOUT_MS,
): RedosVerdict {
  const dir = mkdtempSync(join(tmpdir(), "semantic-redos-"));
  try {
    writeFileSync(join(dir, "candidate.yaml"), probeRule(fallback), "utf-8");
    const run = spawnSync("python3", ["scripts/gate-redos.py", "--rules", dir], {
      cwd: repoRoot,
      encoding: "utf-8",
      timeout: timeoutMs,
    });
    return classifyRedosRun({ status: run.status, stdout: run.stdout ?? "", stderr: run.stderr ?? "", error: run.error });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
