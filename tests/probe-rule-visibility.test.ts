/**
 * Tests for scripts/probe-rule-visibility.ts.
 *
 * The script exists because "0 false positives" was accepted as evidence for
 * five rules that had never been exercised: the benign corpora contained
 * `torsocks` zero times, so a Tor rule scored a clean 0 by matching nothing. A
 * probe that reports the same PASS for a covered rule and a blind one is
 * decoration, so the contracts pinned here are the two that make it bite:
 *
 *  1. A CONDITION THE CORPUS CANNOT SEE FAILS. The fixture reproduces the
 *     original shape — a `torsocks` condition next to an `.onion` condition
 *     that the corpus does cover. Reporting per rule instead of per condition
 *     would let the covered half hide the blind half, so the blind condition
 *     must be named and the exit code must be non-zero even though the rule's
 *     corpus FP count is 0.
 *
 *  2. NO TRUE_POSITIVES MEANS NO VERDICT. Without a control the script cannot
 *     tell a clean rule from an engine that never compiled a pattern (the
 *     constructor does not compile; only `loadRules()` does). That must exit 3
 *     and print nothing that reads like a pass.
 *
 * A well-covered real rule is also probed, so a change that makes everything
 * fail cannot pass these tests.
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(REPO_ROOT, "scripts/probe-rule-visibility.ts");
const FIXTURES = join(REPO_ROOT, "tests/fixtures/probe-visibility");
const COVERED_RULE = join(
  REPO_ROOT,
  "rules/context-exfiltration/ATR-2026-00075-agent-memory-manipulation.yaml",
);

const EXIT_OK = 0;
const EXIT_FAIL = 1;
const EXIT_NO_CONTROL = 3;

function runProbe(ruleFile: string): { status: number; stdout: string; stderr: string } {
  const r = spawnSync("npx", ["tsx", SCRIPT, ruleFile], {
    cwd: REPO_ROOT,
    encoding: "utf-8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return { status: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

describe("probe-rule-visibility", () => {
  it("fails a rule whose condition the benign corpus never exercises", () => {
    const r = runProbe(join(FIXTURES, "corpus-blind-rule.yaml"));

    // The whole point: the corpus FP count is clean and the verdict is still FAIL.
    expect(r.stdout).toMatch(/corpus\s+0 FP/);
    expect(r.status).toBe(EXIT_FAIL);

    // The blind condition is named, and the word the corpus lacks is printed.
    expect(r.stdout).toContain("BLIND");
    expect(r.stdout).toContain("torsocks");

    // The condition the corpus does cover is not dragged down with it.
    expect(r.stdout).toMatch(/\[seen\s*\].*onion/);
  }, 180_000);

  it("refuses a verdict when the rule declares no true_positives", () => {
    const r = runProbe(join(FIXTURES, "no-control-rule.yaml"));
    expect(r.status).toBe(EXIT_NO_CONTROL);
    expect(r.stderr).toContain("CONTROL IMPOSSIBLE");
    expect(r.stdout).not.toContain("PASS");
  }, 180_000);

  it("passes a rule every condition of which the corpus exercises", () => {
    const r = runProbe(COVERED_RULE);
    expect(r.status).toBe(EXIT_OK);
    expect(r.stdout).toContain("PASS");
    expect(r.stdout).not.toContain("BLIND");
  }, 180_000);
});
