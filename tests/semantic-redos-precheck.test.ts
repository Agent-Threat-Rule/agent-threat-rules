/**
 * Tests for scripts/lib/semantic-redos-precheck.ts
 *
 * A fallback can finish on every cluster sample and every benign sample and
 * still hang on a string shaped like its own grammar. PR CI catches that with
 * scripts/gate-redos.py; the lane used to find out only when that check failed
 * on the PR. The precheck runs the same script on the one draft, so the draft
 * is routed to human review instead.
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { classifyRedosRun, redosPrecheck } from "../scripts/lib/semantic-redos-precheck.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const BACKTRACKING = "(?i)ignore\\s+(?:\\w+\\s*)+following\\s+(?:instructions|rules)\\s+and\\s+(?:just\\s+)?(?:say|print|output)";

const pythonWithYaml = spawnSync("python3", ["-c", "import yaml"], { encoding: "utf-8" }).status === 0;

describe("classifyRedosRun", () => {
  it("is ok when gate-redos.py exits 0", () => {
    expect(classifyRedosRun({ status: 0, stdout: "OK: 0 known, 0 new\n", stderr: "" })).toEqual({ kind: "ok" });
  });

  it("names the hanging condition when gate-redos.py fails the pattern", () => {
    const stdout =
      "scanning 1 regex conditions\n  NEW  ATR-SEMANTIC-CANDIDATE#0 hang\n\n" +
      "FAIL: 1 condition(s) backtrack catastrophically and are not in data/redos-baseline.json\n";
    const verdict = classifyRedosRun({ status: 1, stdout, stderr: "" });
    expect(verdict.kind).toBe("backtracks");
    if (verdict.kind === "backtracks") expect(verdict.detail).toContain("ATR-SEMANTIC-CANDIDATE#0 hang");
  });

  // A missing PyYAML also exits 1. Reading it as "the pattern backtracks" would
  // route every draft and leave the lane quietly producing nothing.
  it("is unavailable, not a verdict on the pattern, when the script could not run", () => {
    const missingYaml = { status: 1, stdout: "", stderr: "ModuleNotFoundError: No module named 'yaml'\n" };
    expect(classifyRedosRun(missingYaml).kind).toBe("unavailable");
    const noPython = { status: null, stdout: "", stderr: "", error: new Error("spawnSync python3 ENOENT") };
    expect(classifyRedosRun(noPython).kind).toBe("unavailable");
    expect(classifyRedosRun({ status: 2, stdout: "", stderr: "no regex conditions" }).kind).toBe("unavailable");
  });
});

describe.skipIf(!pythonWithYaml)("redosPrecheck (runs scripts/gate-redos.py)", () => {
  it("flags a pattern that backtracks on its own pumped input", () => {
    expect(redosPrecheck(BACKTRACKING, REPO_ROOT).kind).toBe("backtracks");
  }, 120_000);

  it("passes a linear pattern", () => {
    expect(redosPrecheck("(?i)\\bsecret\\s+key\\b", REPO_ROOT)).toEqual({ kind: "ok" });
  }, 120_000);
});
