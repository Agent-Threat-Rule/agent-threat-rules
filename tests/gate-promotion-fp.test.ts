/**
 * Tests for scripts/gate-promotion-fp.ts — the enforce-lane FP gate and its
 * new filter mode.
 *
 * Five contracts are pinned here:
 *
 *  1. DEFAULT BEHAVIOUR IS FROZEN. CI (.github/workflows/maturity-fp-gate.yml)
 *     runs this script with no output flags and relies on exit 1 when a
 *     promoted rule false-positives. Adding --emit-clean must NOT relax that.
 *  2. SEPARATION. --emit-clean / --emit-dirty must partition the scanned ids
 *     exactly: every scanned id lands in one list, never both, never neither.
 *  3. FILTER MODE. --filter-mode exits 0 on a dirty finding (so a `set -e`
 *     promoter can consume the clean list), but refuses to run without an emit
 *     target — it must never become a way to silently mute the gate.
 *  4. DISCOVERY SEES UNCOMMITTED RULES. Candidates come from tracked AND
 *     untracked-not-ignored files. Tracked-only discovery made the gate report
 *     "nothing to gate" + exit 0 for rules that exist on disk but have not been
 *     committed — a zero-measurement PASS on exactly the rules nobody had
 *     measured yet (scripts/fn-mine-llm.ts authors into the tree, then gates).
 *  5. AN UNRESOLVABLE ID IS A FAILURE, NOT A WARNING. Exit 3, ids named, and no
 *     list written. Anything softer reads as "scanned it, all fine".
 *
 * The gate scan runs against an injected fixture corpus (GateDeps), so these
 * tests are deterministic and do not depend on the precision of any real rule.
 * Two subprocess smoke tests cover the CLI entry point itself, because a broken
 * "invoked directly" guard would turn the CI gate into a silent no-op.
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import {
  parseCliOptions,
  parsePromotedFiles,
  partitionByFp,
  resolveExitCode,
  formatIdList,
  gitRuleFiles,
  runGate,
  GateUsageError,
  EXIT_OK,
  EXIT_FAIL,
  EXIT_USAGE,
  EXIT_MISSING_IDS,
  type GateDeps,
  type GitRunner,
} from "../scripts/gate-promotion-fp.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(REPO_ROOT, "scripts/gate-promotion-fp.ts");

const DIRTY_ID = "ATR-2026-90001";
const CLEAN_ID = "ATR-2026-90002";

/** A minimal but schema-valid rule whose single regex is `pattern`. */
function fixtureRule(id: string, title: string, pattern: string): string {
  return [
    `title: ${title}`,
    `id: ${id}`,
    "rule_version: 1",
    "status: experimental",
    "description: fixture rule for the promotion FP gate tests",
    "author: test",
    "date: 2026/07/28",
    "schema_version: '0.1'",
    "detection_tier: pattern",
    "maturity: test",
    "severity: high",
    "tags:",
    "  category: tool-poisoning",
    "  scan_target: runtime",
    "  confidence: high",
    "agent_source:",
    "  type: llm_io",
    "  framework: [any]",
    "  provider: [any]",
    "detection:",
    "  condition: any",
    "  false_positives: []",
    "  conditions:",
    "    - field: content",
    "      operator: regex",
    `      value: ${pattern}`,
    "      description: fixture",
    "response:",
    "  actions: [alert]",
    "test_cases:",
    "  true_positives: []",
    "  true_negatives: []",
    "",
  ].join("\n");
}

interface Fixture {
  readonly root: string;
  readonly deps: GateDeps;
  readonly out: string;
}

/**
 * A throwaway repo root: two rules (one that fires on the benign corpus, one
 * that cannot) plus a tiny benign corpus.
 */
function makeFixture(): Fixture {
  const root = mkdtempSync(join(tmpdir(), "atr-gate-test-"));
  const rulesDir = join(root, "rules");
  const corpusDir = join(root, "corpus");
  const out = join(root, "out");
  mkdirSync(rulesDir, { recursive: true });
  mkdirSync(corpusDir, { recursive: true });

  const dirtyFile = `${DIRTY_ID}-fixture-dirty.yaml`;
  const cleanFile = `${CLEAN_ID}-fixture-clean.yaml`;
  writeFileSync(
    join(rulesDir, dirtyFile),
    fixtureRule(DIRTY_ID, "fixture rule that fires on benign code", "(?i)import random"),
    "utf-8",
  );
  writeFileSync(
    join(rulesDir, cleanFile),
    fixtureRule(CLEAN_ID, "fixture rule that never fires", "zzq-never-in-benign-corpus-zzq"),
    "utf-8",
  );

  const samples = [
    { text: "import random\nprint(random.random())" },
    { text: "This skill formats CSV files for the user." },
    { text: "from bs4 import BeautifulSoup" },
  ];
  writeFileSync(
    join(corpusDir, "benign.jsonl"),
    `${samples.map((s) => JSON.stringify(s)).join("\n")}\n`,
    "utf-8",
  );

  return {
    root,
    out,
    deps: {
      repoRoot: root,
      rulesDir,
      corpora: [corpusDir],
      listRuleFiles: () => [`rules/${dirtyFile}`, `rules/${cleanFile}`],
    },
  };
}

function writeIdsFile(fixture: Fixture, name: string, ids: readonly string[]): string {
  const path = join(fixture.root, name);
  writeFileSync(path, formatIdList(ids), "utf-8");
  return path;
}

function readIds(path: string): string[] {
  return readFileSync(path, "utf-8").split("\n").filter(Boolean);
}

const BASE_OPTIONS = {
  base: "origin/main",
  emitClean: null,
  emitDirty: null,
  filterMode: false,
} as const;

describe("parseCliOptions", () => {
  it("defaults to gate semantics with no output flags", () => {
    expect(parseCliOptions([])).toEqual({
      idsFile: null,
      base: "origin/main",
      emitClean: null,
      emitDirty: null,
      emitMeasurement: null,
      filterMode: false,
    });
  });

  it("keeps the existing --ids / --base parsing", () => {
    const opts = parseCliOptions(["--ids", "/tmp/ids.txt", "--base", "origin/release"]);
    expect(opts.idsFile).toBe("/tmp/ids.txt");
    expect(opts.base).toBe("origin/release");
  });

  it("parses the emit paths", () => {
    const opts = parseCliOptions(["--emit-clean", "/tmp/c.txt", "--emit-dirty", "/tmp/d.txt"]);
    expect(opts.emitClean).toBe("/tmp/c.txt");
    expect(opts.emitDirty).toBe("/tmp/d.txt");
    expect(opts.filterMode).toBe(false);
  });

  it("rejects --filter-mode without an emit target (would only mute the gate)", () => {
    expect(() => parseCliOptions(["--filter-mode"])).toThrow(GateUsageError);
    expect(() => parseCliOptions(["--filter-mode", "--emit-clean", "/tmp/c.txt"])).not.toThrow();
    expect(() => parseCliOptions(["--filter-mode", "--emit-dirty", "/tmp/d.txt"])).not.toThrow();
  });

  it("rejects an emit flag with no value or a value that is another flag", () => {
    expect(() => parseCliOptions(["--emit-clean"])).toThrow(GateUsageError);
    expect(() => parseCliOptions(["--emit-clean", "--filter-mode"])).toThrow(GateUsageError);
  });

  it("rejects emitting both lists to the same path", () => {
    expect(() => parseCliOptions(["--emit-clean", "/tmp/x", "--emit-dirty", "/tmp/x"])).toThrow(
      GateUsageError,
    );
  });
});

describe("pure helpers", () => {
  it("partitionByFp separates clean from dirty and orders deterministically", () => {
    const counts = new Map([
      ["ATR-2026-00003", 0],
      ["ATR-2026-00001", 5],
      ["ATR-2026-00002", 0],
      ["ATR-2026-00004", 9],
      ["ATR-2026-00005", 5],
    ]);
    const { clean, dirty } = partitionByFp(counts);
    expect(clean).toEqual(["ATR-2026-00002", "ATR-2026-00003"]);
    expect(dirty).toEqual([
      ["ATR-2026-00004", 9],
      ["ATR-2026-00001", 5],
      ["ATR-2026-00005", 5],
    ]);
  });

  it("resolveExitCode keeps gate semantics by default and relaxes only in filter mode", () => {
    expect(resolveExitCode(0, false)).toBe(EXIT_OK);
    expect(resolveExitCode(0, true)).toBe(EXIT_OK);
    expect(resolveExitCode(3, false)).toBe(EXIT_FAIL);
    expect(resolveExitCode(3, true)).toBe(EXIT_OK);
  });

  it("formatIdList writes one id per line and an empty file for an empty list", () => {
    expect(formatIdList([])).toBe("");
    expect(formatIdList(["A", "B"])).toBe("A\nB\n");
  });

  it("parsePromotedFiles only picks up enforce-lane maturities", () => {
    const diff = [
      "+++ b/rules/tool-poisoning/ATR-2026-00001-a.yaml",
      "+maturity: stable",
      "+++ b/rules/prompt-injection/ATR-2026-00002-b.yaml",
      "+maturity: test",
      "+++ b/rules/prompt-injection/ATR-2026-00003-c.yaml",
      '+maturity: "production"',
    ].join("\n");
    expect(parsePromotedFiles(diff)).toEqual([
      "rules/tool-poisoning/ATR-2026-00001-a.yaml",
      "rules/prompt-injection/ATR-2026-00003-c.yaml",
    ]);
  });
});

describe("runGate against a fixture corpus", () => {
  let fixture: Fixture;
  let mixedIds: string;

  beforeAll(() => {
    fixture = makeFixture();
    mixedIds = writeIdsFile(fixture, "mixed.txt", [DIRTY_ID, CLEAN_ID]);
  });

  afterAll(() => {
    rmSync(fixture.root, { recursive: true, force: true });
  });

  it("default mode still fails on a dirty rule and writes nothing", async () => {
    const code = await runGate({ ...BASE_OPTIONS, idsFile: mixedIds }, fixture.deps);
    expect(code).toBe(EXIT_FAIL);
    expect(existsSync(fixture.out)).toBe(false);
  });

  it("default mode passes when every requested rule is FP-clean", async () => {
    const cleanOnly = writeIdsFile(fixture, "clean-only.txt", [CLEAN_ID]);
    const code = await runGate({ ...BASE_OPTIONS, idsFile: cleanOnly }, fixture.deps);
    expect(code).toBe(EXIT_OK);
  });

  it("--emit-clean partitions the ids exactly and keeps gate semantics", async () => {
    const clean = join(fixture.out, "gate-clean.txt");
    const dirty = join(fixture.out, "gate-dirty.txt");
    const code = await runGate(
      { ...BASE_OPTIONS, idsFile: mixedIds, emitClean: clean, emitDirty: dirty },
      fixture.deps,
    );
    expect(code).toBe(EXIT_FAIL);
    expect(readIds(clean)).toEqual([CLEAN_ID]);
    expect(readIds(dirty)).toEqual([DIRTY_ID]);
  });

  it("--filter-mode emits the same lists but exits 0 so a `set -e` promoter survives", async () => {
    const clean = join(fixture.out, "filter-clean.txt");
    const dirty = join(fixture.out, "filter-dirty.txt");
    const code = await runGate(
      {
        ...BASE_OPTIONS,
        idsFile: mixedIds,
        emitClean: clean,
        emitDirty: dirty,
        filterMode: true,
      },
      fixture.deps,
    );
    expect(code).toBe(EXIT_OK);
    expect(readIds(clean)).toEqual([CLEAN_ID]);
    expect(readIds(dirty)).toEqual([DIRTY_ID]);
  });

  it("emits empty lists (not missing files) when the id list is empty", async () => {
    const empty = writeIdsFile(fixture, "empty.txt", []);
    const clean = join(fixture.out, "empty-clean.txt");
    const dirty = join(fixture.out, "empty-dirty.txt");
    const code = await runGate(
      { ...BASE_OPTIONS, idsFile: empty, emitClean: clean, emitDirty: dirty },
      fixture.deps,
    );
    expect(code).toBe(EXIT_OK);
    expect(readFileSync(clean, "utf-8")).toBe("");
    expect(readFileSync(dirty, "utf-8")).toBe("");
  });

  // Was: "never lets an unresolvable id reach the clean list" — which asserted
  // exit 0. Keeping the ghost id out of the clean list is necessary but not
  // sufficient: exit 0 told the caller the scan happened. It did not.
  it("fails with a distinct code when an id matches no rule on disk", async () => {
    const withGhost = writeIdsFile(fixture, "ghost.txt", [CLEAN_ID, "ATR-2026-99999"]);
    const clean = join(fixture.out, "ghost-clean.txt");
    const code = await runGate(
      { ...BASE_OPTIONS, idsFile: withGhost, emitClean: clean },
      fixture.deps,
    );
    expect(code).toBe(EXIT_MISSING_IDS);
    expect(code).not.toBe(EXIT_OK);
  });

  it("writes no list at all when ids are missing, so a stale file cannot be consumed", async () => {
    const ghostOnly = writeIdsFile(fixture, "ghost-only.txt", ["ATR-2026-99999"]);
    const clean = join(fixture.out, "never-written-clean.txt");
    const dirty = join(fixture.out, "never-written-dirty.txt");
    const code = await runGate(
      { ...BASE_OPTIONS, idsFile: ghostOnly, emitClean: clean, emitDirty: dirty },
      fixture.deps,
    );
    expect(code).toBe(EXIT_MISSING_IDS);
    expect(existsSync(clean)).toBe(false);
    expect(existsSync(dirty)).toBe(false);
  });

  it("missing ids fail even in --filter-mode (filter relaxes the FP verdict, not bad input)", async () => {
    const ghostOnly = writeIdsFile(fixture, "ghost-filter.txt", ["ATR-2026-99999"]);
    const clean = join(fixture.out, "filter-missing-clean.txt");
    const code = await runGate(
      { ...BASE_OPTIONS, idsFile: ghostOnly, emitClean: clean, filterMode: true },
      fixture.deps,
    );
    expect(code).toBe(EXIT_MISSING_IDS);
    expect(existsSync(clean)).toBe(false);
  });

});

describe("gitRuleFiles — candidate discovery", () => {
  let root: string;

  /** Records the argv of every git invocation so the flag contract is pinned. */
  function fakeGit(tracked: string, untracked: string): { run: GitRunner; calls: string[][] } {
    const calls: string[][] = [];
    const run: GitRunner = (args) => {
      calls.push([...args]);
      return args.includes("--others") ? untracked : tracked;
    };
    return { run, calls };
  }

  function touch(rel: string): void {
    const abs = join(root, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, "id: ATR-2026-00000\n", "utf-8");
  }

  beforeAll(() => {
    root = mkdtempSync(join(tmpdir(), "atr-discovery-"));
    touch("rules/a/tracked.yaml");
    touch("rules/b/untracked.yaml");
    touch("rules/b/notes.md");
  });

  afterAll(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it("asks git for untracked files with --exclude-standard (the flag that was missing)", () => {
    const { run, calls } = fakeGit("rules/a/tracked.yaml\n", "");
    gitRuleFiles(root, run);
    const others = calls.find((c) => c.includes("--others"));
    expect(others).toBeDefined();
    expect(others).toContain("--exclude-standard");
    expect(others).toContain("rules/");
  });

  it("includes an uncommitted rule file — the case that produced a zero-measurement PASS", () => {
    const { run } = fakeGit("rules/a/tracked.yaml\n", "rules/b/untracked.yaml\n");
    expect(gitRuleFiles(root, run)).toEqual([
      "rules/a/tracked.yaml",
      "rules/b/untracked.yaml",
    ]);
  });

  it("keeps the previous tracked-only result when nothing is uncommitted", () => {
    const { run } = fakeGit("rules/a/tracked.yaml\n", "");
    expect(gitRuleFiles(root, run)).toEqual(["rules/a/tracked.yaml"]);
  });

  it("de-duplicates, sorts, and ignores non-rule files", () => {
    const { run } = fakeGit(
      "rules/b/untracked.yaml\nrules/a/tracked.yaml\nrules/b/notes.md\n",
      "rules/b/untracked.yaml\n",
    );
    expect(gitRuleFiles(root, run)).toEqual([
      "rules/a/tracked.yaml",
      "rules/b/untracked.yaml",
    ]);
  });

  it("drops a still-tracked file that is gone from the working tree", () => {
    const { run } = fakeGit("rules/a/tracked.yaml\nrules/a/deleted.yaml\n", "");
    expect(gitRuleFiles(root, run)).toEqual(["rules/a/tracked.yaml"]);
  });
});

describe("CLI entry point (guards against a no-op gate)", () => {
  function run(args: readonly string[]): { status: number; stderr: string } {
    const r = spawnSync("npx", ["tsx", SCRIPT, ...args], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      timeout: 120_000,
    });
    return { status: r.status ?? -1, stderr: r.stderr ?? "" };
  }

  it("exits 2 on a usage error instead of silently doing nothing", () => {
    const { status, stderr } = run(["--filter-mode"]);
    expect(status).toBe(EXIT_USAGE);
    expect(stderr).toContain("usage error");
  });

  it("actually executes main when invoked directly (emits the requested file)", () => {
    const dir = mkdtempSync(join(tmpdir(), "atr-gate-cli-"));
    const ids = join(dir, "ids.txt");
    const clean = join(dir, "clean.txt");
    // An EMPTY id list is the only genuinely empty scan: nothing was requested,
    // so nothing is unmeasured. A nonexistent id is a different thing entirely
    // and is asserted below.
    writeFileSync(ids, "", "utf-8");
    const { status } = run(["--ids", ids, "--emit-clean", clean]);
    expect(status).toBe(EXIT_OK);
    expect(existsSync(clean)).toBe(true);
    rmSync(dir, { recursive: true, force: true });
  });

  it("exits 3 and names the id when --ids points at a rule that does not exist", () => {
    const dir = mkdtempSync(join(tmpdir(), "atr-gate-cli-missing-"));
    const ids = join(dir, "ids.txt");
    const clean = join(dir, "clean.txt");
    writeFileSync(ids, "ATR-2026-99999\n", "utf-8");
    const { status, stderr } = run(["--ids", ids, "--emit-clean", clean]);
    expect(status).toBe(EXIT_MISSING_IDS);
    expect(stderr).toContain("ATR-2026-99999");
    expect(existsSync(clean)).toBe(false);
    rmSync(dir, { recursive: true, force: true });
  });
});
