/**
 * Tests for scripts/gate-redos.py input derivation.
 *
 * In October 2026 two consumers packaging the corpus found conditions that
 * hang for seconds to minutes on inputs of 8,000 to 50,000 characters while
 * this gate reported them clean. The gate's inputs were 1,500 to 3,000
 * characters long and only ever pumped the first branch of an alternation.
 * Each fixture below is the shape of one of those misses, run with the long
 * inputs off (the gate as it was) and on (the gate as it is).
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const pythonWithYaml = spawnSync("python3", ["-c", "import yaml"], { encoding: "utf-8" }).status === 0;

/** Rule id -> one regex condition, written as a rules directory gate-redos.py can scan. */
function rulesDir(conditions: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "gate-redos-"));
  for (const [id, value] of Object.entries(conditions)) {
    writeFileSync(
      join(dir, `${id}.yaml`),
      yaml.dump({ id, title: id, detection: { conditions: [{ field: "content", operator: "regex", value }], condition: "any" } }),
      "utf-8",
    );
  }
  return dir;
}

function gate(dir: string, ...extra: string[]) {
  const run = spawnSync("python3", ["scripts/gate-redos.py", "--rules", dir, "--jobs", "2", ...extra], {
    cwd: REPO_ROOT,
    encoding: "utf-8",
    timeout: 170_000,
  });
  return { status: run.status, stdout: run.stdout ?? "" };
}

// Quadratic only past a few thousand characters: "<!--" then \s* then \s*
// split one whitespace run (ATR-2026-01462 condition 0).
const LONG_ONLY = "(?i)(?:<!--\\s*|\\[)\\s*SYSTEM\\s+OVERRIDE\\b";
// Linear in its first branch, quadratic in the second: \s*,?\s+ is \s*\s+
// without the comma (ATR-2026-01006 condition 2).
const LATER_BRANCH = '(?i)interlace\\s+(part\\s*(1|one|2|two)|"[^"]{3,60}"\\s*,?\\s+and\\s+")';
// Variable-width lookbehind: Python re refuses it, pyatr falls back to the
// regex module, JavaScript accepts it. It runs in production either way.
const NOT_PYTHON_RE = "(?<=a+)b";
// Linear from any one "echo", quadratic when every position is an "echo":
// each start rescans to the end of the line. The old inputs never repeat the
// opener, so they never reach it (issue #601).
const OPENER_TILED = "(?i)echo(?:[^\\n|]|\\|(?!\\s*base64))*\\|\\s*base64";

describe.skipIf(!pythonWithYaml)("gate-redos.py input derivation", () => {
  it("misses both shapes with the long inputs off, as the gate used to", () => {
    const dir = rulesDir({ "LONG-ONLY": LONG_ONLY, "LATER-BRANCH": LATER_BRANCH });
    try {
      const run = gate(dir, "--long-chars", "0");
      expect(run.status).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);

  it("fails both shapes with the long inputs on, naming each condition", () => {
    const dir = rulesDir({ "LONG-ONLY": LONG_ONLY, "LATER-BRANCH": LATER_BRANCH });
    try {
      const run = gate(dir);
      expect(run.status).toBe(1);
      expect(run.stdout).toMatch(/NEW\s+LONG-ONLY#0/);
      expect(run.stdout).toMatch(/NEW\s+LATER-BRANCH#0/);
      expect(run.stdout).toContain("backtrack catastrophically");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);

  it("passes the linear rewrites of the same two conditions", () => {
    const dir = rulesDir({
      "LONG-ONLY": "(?i)(?:<!--|\\[)\\s*SYSTEM\\s+OVERRIDE\\b",
      "LATER-BRANCH": '(?i)interlace\\s+(part\\s*(1|one|2|two)|"[^"]{3,60}"(?:\\s*,)?\\s+and\\s+")',
    });
    try {
      const run = gate(dir);
      expect(run.status).toBe(0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);

  it("fails a condition that is quadratic only when its opener repeats", () => {
    const dir = rulesDir({ "OPENER-TILED": OPENER_TILED });
    try {
      expect(gate(dir, "--long-chars", "0").status).toBe(0);
      const run = gate(dir);
      expect(run.status).toBe(1);
      expect(run.stdout).toMatch(/NEW\s+OPENER-TILED#0/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);

  it("makes scripts/verify_rule_redos.py fail what the gate fails", () => {
    const dir = rulesDir({ "LATER-BRANCH": LATER_BRANCH });
    try {
      const run = spawnSync("python3", ["scripts/verify_rule_redos.py", join(dir, "LATER-BRANCH.yaml")], {
        cwd: REPO_ROOT,
        encoding: "utf-8",
        timeout: 170_000,
      });
      expect(run.status).toBe(1);
      expect(run.stdout).toContain("blowup    : FAIL");
      expect(run.stdout).toMatch(/#0 (hang|\d+\.\d+s)/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);

  it("treats an edited pattern as new even when its RULE#index key is baselined", () => {
    const dir = rulesDir({ "LONG-ONLY": LONG_ONLY });
    const baseline = join(dir, "baseline.json");
    try {
      expect(gate(dir, "--baseline", baseline, "--update-baseline").status).toBe(0);
      const known = gate(dir, "--baseline", baseline);
      expect(known.status).toBe(0);
      expect(known.stdout).toMatch(/known\s+LONG-ONLY#0/);
      // Still quadratic, one more alternative: same key, different pattern.
      writeFileSync(
        join(dir, "LONG-ONLY.yaml"),
        yaml.dump({
          id: "LONG-ONLY",
          title: "LONG-ONLY",
          detection: {
            conditions: [{ field: "content", operator: "regex", value: LONG_ONLY.replace("OVERRIDE", "(?:OVERRIDE|BYPASS)") }],
            condition: "any",
          },
        }),
        "utf-8",
      );
      const edited = gate(dir, "--baseline", baseline);
      expect(edited.status).toBe(1);
      expect(edited.stdout).toMatch(/NEW \(pattern changed\)\s+LONG-ONLY#0/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);

  it("lists a condition Python re cannot compile instead of passing it silently", () => {
    const dir = rulesDir({ "NOT-PYTHON-RE": NOT_PYTHON_RE });
    try {
      const run = gate(dir);
      expect(run.status).toBe(0);
      expect(run.stdout).toContain("do not compile under Python re and were not timed: NOT-PYTHON-RE#0");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);
});
