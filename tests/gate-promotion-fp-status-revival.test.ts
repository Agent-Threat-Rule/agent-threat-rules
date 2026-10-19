/**
 * Tests for how scripts/gate-promotion-fp.ts --base finds a rule that enters the
 * enforce lane without an added `maturity: stable|production` line — above all
 * a rule revived by its status alone.
 *
 * A rule fires in the enforce (auto-block) lane when it is live — src/engine.ts
 * skips `status: draft | deprecated` before any lane gate — and its maturity is
 * stable. --base used to find a promotion only by an added maturity line, so a
 * PR that changed nothing but `status: draft` -> `status: experimental` on a rule
 * already at `maturity: stable` moved it into the enforce lane while the gate
 * printed "nothing to gate" and exited 0. That is what #415 did to
 * ATR-2026-00080.
 *
 * These cases drive the path CI takes (maturity-fp-gate.yml): a real
 * `git diff base...HEAD` in a throwaway repository, the real engine, a
 * one-sample benign corpus. Several are spellings that no reading of the diff's
 * lines can see, which is why the gate now loads each changed rule on both sides
 * of the diff (scripts/lib/enforce-lane-entry.ts; unit tests in
 * tests/enforce-lane-entry.test.ts).
 *
 * The gate's own git calls inherit the environment, so the global git config is
 * pinned for the whole file: a developer's settings must not decide what these
 * tests see. One case then turns hostile settings back on, on purpose.
 */

import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { runGate, EXIT_OK, EXIT_FAIL, type GateDeps } from "../scripts/gate-promotion-fp.js";

const ID = "ATR-2026-90021";
const OTHER_ID = "ATR-2026-90022";
const FILE = `rules/a/${ID}-fixture.yaml`;
/** Fires on the one benign sample below. */
const FIRES = "(?i)import random";
/** Fires on nothing. */
const SILENT = "zzq-never-in-benign-corpus-zzq";

const GIT_ENV = {
  ...process.env,
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_AUTHOR_NAME: "fixture",
  GIT_AUTHOR_EMAIL: "fixture@example.invalid",
  GIT_COMMITTER_NAME: "fixture",
  GIT_COMMITTER_EMAIL: "fixture@example.invalid",
};

function git(root: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd: root, env: GIT_ENV, encoding: "utf-8" }).trim();
}

/** Run `fn` with these process.env entries set, then put the old values back. */
async function withEnv<T>(vars: Record<string, string>, fn: () => Promise<T>): Promise<T> {
  const saved = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  Object.assign(process.env, vars);
  try {
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

const PINNED = { GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_NOSYSTEM: "1" };
let unpinned: Record<string, string | undefined> = {};
const dirs: string[] = [];

beforeAll(() => {
  unpinned = Object.fromEntries(Object.keys(PINNED).map((k) => [k, process.env[k]]));
  Object.assign(process.env, PINNED);
});

afterAll(() => {
  for (const [k, v] of Object.entries(unpinned)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

interface RuleSpec {
  /** Raw YAML where the status line goes; may span lines, may be empty. */
  readonly status: string;
  readonly maturity: string;
  readonly pattern: string;
  readonly id?: string;
  /** Raw YAML for the id, replacing `id: <id>`; may span lines, may be empty. */
  readonly idLine?: string;
}

/** A minimal rule the engine loads. */
function rule({ status, maturity, pattern, id = ID, idLine = `id: ${id}` }: RuleSpec): string {
  return [
    "title: fixture rule for the enforce-lane entry tests",
    idLine,
    "rule_version: 1",
    status,
    "description: fixture",
    "author: test",
    "date: 2026/10/16",
    "schema_version: '0.1'",
    "detection_tier: pattern",
    maturity,
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
    `      value: "${pattern}"`,
    "      description: fixture",
    "response:",
    "  actions: [alert]",
    "test_cases:",
    "  true_positives: []",
    "  true_negatives: []",
    "",
  ]
    .filter((line) => line !== "")
    .concat("")
    .join("\n");
}

interface Repo {
  readonly root: string;
  readonly out: string;
  /** The commit the PR branched from: what CI passes as --base. */
  readonly base: string;
  readonly deps: GateDeps;
}

/** A repository whose base commit holds `files` and a one-sample benign corpus. */
function repoWith(files: Record<string, string>): Repo {
  const dir = mkdtempSync(join(tmpdir(), "atr-gate-lane-entry-"));
  dirs.push(dir);
  const root = join(dir, "repo");
  for (const [rel, text] of Object.entries(files)) put(root, rel, text);
  put(root, "corpus/benign.jsonl", `${JSON.stringify({ text: "import random\nprint(random.random())" })}\n`);
  git(root, "init", "--quiet", "-b", "main");
  git(root, "add", "-A");
  git(root, "commit", "--quiet", "-m", "base");
  return {
    root,
    out: join(dir, "out"),
    base: git(root, "rev-parse", "HEAD"),
    deps: {
      repoRoot: root,
      rulesDir: join(root, "rules"),
      corpora: [join(root, "corpus")],
      listRuleFiles: () => [],
    },
  };
}

function put(root: string, rel: string, text: string): void {
  mkdirSync(dirname(join(root, rel)), { recursive: true });
  writeFileSync(join(root, rel), text, "utf-8");
}

/** Replace one exact piece of a file's text; the fixture must contain it. */
function edit(repo: Repo, rel: string, from: string, to: string): void {
  const path = join(repo.root, rel);
  const before = readFileSync(path, "utf-8");
  expect(before, `fixture edit must apply to ${rel}: ${JSON.stringify(from)}`).toContain(from);
  writeFileSync(path, before.replace(from, to), "utf-8");
}

/** The PR: whatever `change` does to the tree, committed on top of the base. */
function commit(repo: Repo, change: () => void): void {
  change();
  git(repo.root, "add", "-A");
  git(repo.root, "commit", "--quiet", "-m", "change");
}

function readIds(path: string): string[] {
  return existsSync(path) ? readFileSync(path, "utf-8").split("\n").filter(Boolean) : [];
}

/** Run the gate exactly as maturity-fp-gate.yml does, plus the two lists. */
async function gate(repo: Repo): Promise<{ code: number; clean: string[]; dirty: string[] }> {
  const clean = join(repo.out, "clean.txt");
  const dirty = join(repo.out, "dirty.txt");
  const code = await runGate(
    { idsFile: null, base: repo.base, emitClean: clean, emitDirty: dirty, filterMode: false },
    repo.deps,
  );
  return { code, clean: readIds(clean), dirty: readIds(dirty) };
}

/** A rule that is inert now, carries maturity stable, and fires on the corpus. */
const INERT_STABLE = rule({ status: "status: draft", maturity: "maturity: stable", pattern: FIRES });

describe("runGate --base: a revival into the enforce lane by status alone", () => {
  it.each([
    ["deprecated -> experimental, maturity stable", "status: deprecated", "status: experimental", "maturity: stable"],
    ["draft -> stable, maturity stable", "status: draft", "status: stable", "maturity: stable"],
    ["quoted values", 'status: "deprecated"', 'status: "experimental"', 'maturity: "stable"'],
    ["draft -> experimental, maturity production", "status: draft", "status: experimental", "maturity: production"],
  ])("fails when the revived rule false-positives (%s)", async (_label, from, to, maturity) => {
    const repo = repoWith({ [FILE]: rule({ status: from, maturity, pattern: FIRES }) });
    commit(repo, () => edit(repo, FILE, from, to));
    const result = await gate(repo);
    expect(result.code).toBe(EXIT_FAIL);
    expect(result.dirty).toEqual([ID]);
  });

  it("measures a revived rule that is FP-clean instead of skipping it", async () => {
    const repo = repoWith({ [FILE]: rule({ status: "status: deprecated", maturity: "maturity: stable", pattern: SILENT }) });
    commit(repo, () => edit(repo, FILE, "status: deprecated", "status: experimental"));
    const result = await gate(repo);
    expect(result.code).toBe(EXIT_OK);
    // On the clean list means it was scanned. Before, both lists came back
    // empty: "nothing to gate".
    expect(result.clean).toEqual([ID]);
  });

  it("fails when the revival deletes the status line (the engine treats no status as live)", async () => {
    const repo = repoWith({ [FILE]: INERT_STABLE });
    commit(repo, () => edit(repo, FILE, "status: draft\n", ""));
    expect((await gate(repo)).code).toBe(EXIT_FAIL);
  });

  it("fails when HEAD is the PR's merge commit and the base branch has moved on, as in CI", async () => {
    // pull_request checks out the merge commit; the workflow then fetches the
    // base branch, which may be newer than the merge commit's first parent. Here
    // main later revives the same rule and adds another: judged against main's
    // tip instead of the merge base, the PR's revival would look like no change.
    const repo = repoWith({ [FILE]: INERT_STABLE });
    const other = "rules/b/ATR-2026-90023-fixture.yaml";
    git(repo.root, "checkout", "--quiet", "-b", "pr");
    commit(repo, () => edit(repo, FILE, "status: draft", "status: experimental"));
    git(repo.root, "checkout", "--quiet", "-b", "merge", repo.base);
    git(repo.root, "merge", "--quiet", "--no-ff", "-m", "merge pr", "pr");
    git(repo.root, "checkout", "--quiet", "main");
    commit(repo, () => {
      edit(repo, FILE, "status: draft", "status: experimental");
      put(repo.root, other, rule({ status: "status: experimental", maturity: "maturity: stable", pattern: FIRES, id: "ATR-2026-90023" }));
    });
    git(repo.root, "checkout", "--quiet", "merge");
    const result = await gate({ ...repo, base: "main" });
    expect(result.code).toBe(EXIT_FAIL);
    // The rule main added after the PR branched is not this PR's to measure.
    expect(result.dirty).toEqual([ID]);
  });
});

describe("runGate --base: revivals no reading of the diff's lines can see", () => {
  it("fails when the status line is left untouched but swallowed into a quoted scalar", async () => {
    // YAML reads `notes` as one multi-line string; the rule has no status, so it
    // is live. The diff adds `notes: "x` and `"` and never mentions status.
    const repo = repoWith({ [FILE]: INERT_STABLE });
    commit(repo, () => edit(repo, FILE, "status: draft\n", 'notes: "x\nstatus: draft\n"\n'));
    const result = await gate(repo);
    expect(result.code).toBe(EXIT_FAIL);
    expect(result.dirty).toEqual([ID]);
  });

  it("fails when a rule line starting with `++ ` precedes the status change", async () => {
    // In a unified diff that line is `+++ note: x`, which looks like a file header.
    const repo = repoWith({ [FILE]: INERT_STABLE });
    commit(repo, () => {
      edit(repo, FILE, "rule_version: 1\n", "rule_version: 1\n++ note: x\n");
      edit(repo, FILE, "status: draft", "status: experimental");
    });
    expect((await gate(repo)).code).toBe(EXIT_FAIL);
  });

  it("fails when the status is a `? status` key and only its value line changes", async () => {
    const repo = repoWith({
      [FILE]: rule({ status: "? status\n: draft", maturity: "maturity: stable", pattern: FIRES }),
    });
    commit(repo, () => edit(repo, FILE, "\n: draft\n", "\n: experimental\n"));
    expect((await gate(repo)).code).toBe(EXIT_FAIL);
  });

  it("fails when the status comes through a merge key and the anchored value changes", async () => {
    const repo = repoWith({
      [FILE]: rule({ status: "x-lane: &lane\n  status: draft\n<<: *lane", maturity: "maturity: stable", pattern: FIRES }),
    });
    commit(repo, () => edit(repo, FILE, "  status: draft", "  status: experimental"));
    expect((await gate(repo)).code).toBe(EXIT_FAIL);
  });

  it("fails for a rule file whose path has a space (git writes that header with a trailing tab)", async () => {
    const spaced = `rules/a/${ID} fixture.yaml`;
    const repo = repoWith({ [spaced]: INERT_STABLE });
    commit(repo, () => edit(repo, spaced, "status: draft", "status: experimental"));
    expect((await gate(repo)).code).toBe(EXIT_FAIL);
  });

  it.each([
    ["on its own line", `id:\n  ${ID}`],
    ["as a block scalar", `id: >-\n  ${ID}`],
    ["with a tag", `id: !!str ${ID}`],
  ])("measures the revived rule under the id the engine reads, written %s", async (_label, idLine) => {
    // Read line by line, these ids came out as nothing (the file was dropped from
    // the scan) or as `>-` / `!!str`, which no loaded rule carries: a clean 0.
    const repo = repoWith({ [FILE]: rule({ status: "status: draft", maturity: "maturity: stable", pattern: FIRES, idLine }) });
    commit(repo, () => edit(repo, FILE, "status: draft", "status: experimental"));
    const result = await gate(repo);
    expect(result.code).toBe(EXIT_FAIL);
    expect(result.dirty).toEqual([ID]);
  });
});

describe("runGate --base: other ways into the enforce lane without a plain maturity line", () => {
  it("fails for a maturity promotion written with a trailing comment", async () => {
    const repo = repoWith({ [FILE]: rule({ status: "status: experimental", maturity: "maturity: test", pattern: FIRES }) });
    commit(repo, () => edit(repo, FILE, "maturity: test", "maturity: stable  # promoted"));
    expect((await gate(repo)).code).toBe(EXIT_FAIL);
  });

  it("fails when a file the engine never loaded is renamed to .yaml", async () => {
    const parked = `${FILE}.off`;
    const repo = repoWith({ [parked]: rule({ status: "status: experimental", maturity: "maturity: stable", pattern: FIRES }) });
    commit(repo, () => renameSync(join(repo.root, parked), join(repo.root, FILE)));
    expect((await gate(repo)).code).toBe(EXIT_FAIL);
  });

  it("fails when another rule takes over an enforce-lane rule's path", async () => {
    const repo = repoWith({ [FILE]: rule({ status: "status: experimental", maturity: "maturity: stable", pattern: SILENT }) });
    commit(repo, () => put(repo.root, FILE, rule({ status: "status: experimental", maturity: "maturity: stable", pattern: FIRES, id: OTHER_ID })));
    const result = await gate(repo);
    expect(result.code).toBe(EXIT_FAIL);
    expect(result.dirty).toEqual([OTHER_ID]);
  });

  it("measures a moved enforce-lane rule again rather than pairing it by similarity", async () => {
    const moved = `rules/b/${ID}-fixture.yaml`;
    const repo = repoWith({ [FILE]: rule({ status: "status: experimental", maturity: "maturity: stable", pattern: FIRES }) });
    commit(repo, () => {
      mkdirSync(join(repo.root, "rules", "b"), { recursive: true });
      renameSync(join(repo.root, FILE), join(repo.root, moved));
    });
    expect((await gate(repo)).code).toBe(EXIT_FAIL);
  });

  it("names an inert rule whose maturity is raised in a spelling the line reader misses", async () => {
    // The engine skips the rule, so the scan cannot measure it, but it is named
    // as promoted: otherwise a separate status-only PR, judged against a base
    // where the maturity was still test, would complete the move unmeasured.
    const repo = repoWith({ [FILE]: rule({ status: "status: draft", maturity: "maturity: test", pattern: FIRES }) });
    commit(repo, () => edit(repo, FILE, "maturity: test", "maturity: stable  # promoted"));
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      await gate(repo);
      expect(log.mock.calls.flat().join("\n")).toContain("gating 1 promoted rule(s)");
    } finally {
      log.mockRestore();
    }
  });

  it("fails when a maturity-stable rule that did not load at the merge base now loads", async () => {
    const broken = rule({ status: "status: experimental", maturity: "maturity: stable", pattern: FIRES }).replace(
      "title: fixture rule for the enforce-lane entry tests\n",
      "",
    );
    const repo = repoWith({ [FILE]: broken });
    commit(repo, () => put(repo.root, FILE, rule({ status: "status: experimental", maturity: "maturity: stable", pattern: FIRES })));
    const result = await gate(repo);
    expect(result.code).toBe(EXIT_FAIL);
    expect(result.dirty).toEqual([ID]);
  });

  it("refuses two promoted files with the same name, which the scan would copy over each other", async () => {
    const twin = `rules/b/${ID}-fixture.yaml`;
    const repo = repoWith({ [FILE]: INERT_STABLE });
    commit(repo, () => {
      edit(repo, FILE, "status: draft", "status: experimental");
      put(repo.root, twin, rule({ status: "status: experimental", maturity: "maturity: stable", pattern: SILENT, id: OTHER_ID }));
    });
    await expect(gate(repo)).rejects.toThrow(/share a file name/);
  });

  it("fails rather than leave out a promoted file whose rule id it cannot read", async () => {
    const repo = repoWith({
      [FILE]: rule({ status: "status: experimental", maturity: "maturity: test", pattern: FIRES, idLine: "" }),
    });
    commit(repo, () => edit(repo, FILE, "maturity: test", "maturity: stable"));
    await expect(gate(repo)).rejects.toThrow(/no readable string rule id/);
  });

  it("fails rather than measure a revived rule under an id the engine loads as a number", async () => {
    // `id: 12345` loads (the loader only needs it truthy) as the number 12345;
    // read as text it is "12345", which the scan's count never matches: a clean 0.
    const repo = repoWith({ [FILE]: rule({ status: "status: draft", maturity: "maturity: stable", pattern: FIRES, idLine: "id: 12345" }) });
    commit(repo, () => edit(repo, FILE, "status: draft", "status: experimental"));
    await expect(gate(repo)).rejects.toThrow(/no readable string rule id/);
  });

  it("still gates a plain maturity promotion", async () => {
    const repo = repoWith({ [FILE]: rule({ status: "status: experimental", maturity: "maturity: test", pattern: FIRES }) });
    commit(repo, () => edit(repo, FILE, "maturity: test", "maturity: stable"));
    const result = await gate(repo);
    expect(result.code).toBe(EXIT_FAIL);
    expect(result.dirty).toEqual([ID]);
  });
});

describe("runGate --base: what must not be gated", () => {
  async function expectNothingGated(repo: Repo): Promise<void> {
    const result = await gate(repo);
    expect(result.code).toBe(EXIT_OK);
    expect(result.clean).toEqual([]);
    expect(result.dirty).toEqual([]);
  }

  it("a revival whose maturity keeps the rule out of the enforce lane", async () => {
    const repo = repoWith({ [FILE]: rule({ status: "status: draft", maturity: "maturity: test", pattern: FIRES }) });
    commit(repo, () => edit(repo, FILE, "status: draft", "status: experimental"));
    await expectNothingGated(repo);
  });

  it("a demotion out of the live set", async () => {
    const repo = repoWith({ [FILE]: rule({ status: "status: experimental", maturity: "maturity: stable", pattern: FIRES }) });
    commit(repo, () => edit(repo, FILE, "status: experimental", "status: deprecated"));
    await expectNothingGated(repo);
  });

  it("a status edit between two live values on a rule already in the enforce lane", async () => {
    const repo = repoWith({ [FILE]: rule({ status: "status: experimental", maturity: "maturity: stable", pattern: FIRES }) });
    commit(repo, () => edit(repo, FILE, "status: experimental", 'status: "stable"'));
    await expectNothingGated(repo);
  });

  it("a change that only deletes a rule, or edits a file under rules/ that is not one", async () => {
    const repo = repoWith({
      [FILE]: rule({ status: "status: experimental", maturity: "maturity: stable", pattern: FIRES }),
      "rules/README.md": "status: draft\n",
    });
    commit(repo, () => {
      rmSync(join(repo.root, FILE));
      edit(repo, "rules/README.md", "status: draft", "status: experimental\nmaturity: stable");
    });
    await expectNothingGated(repo);
  });

  it("an edit that leaves an enforce-lane rule where it was", async () => {
    const repo = repoWith({ [FILE]: rule({ status: "status: experimental", maturity: "maturity: stable", pattern: FIRES }) });
    commit(repo, () => edit(repo, FILE, "description: fixture\n", "description: fixture, reworded\n"));
    await expectNothingGated(repo);
  });

  it("a revived rule file the engine cannot load, with a warning naming it", async () => {
    const repo = repoWith({ [FILE]: INERT_STABLE });
    commit(repo, () => {
      edit(repo, FILE, "status: draft", "status: experimental");
      edit(repo, FILE, "title: fixture rule for the enforce-lane entry tests\n", "");
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    try {
      await expectNothingGated(repo);
      expect(warn.mock.calls.flat().join("\n")).toContain(FILE);
    } finally {
      warn.mockRestore();
    }
  });
});

describe("runGate --base: a developer's git settings", () => {
  it("still reads an added maturity line with no prefixes, colour on, and an external diff driver", async () => {
    // An inert rule promoted by its maturity line enters no lane, so only the
    // maturity-line reader can name it; under these settings it used to read
    // nothing and the gate said "nothing to gate".
    const repo = repoWith({ [FILE]: rule({ status: "status: draft", maturity: "maturity: test", pattern: FIRES }) });
    commit(repo, () => edit(repo, FILE, "maturity: test", "maturity: stable"));
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    try {
      await withEnv(
        {
          GIT_CONFIG_COUNT: "3",
          GIT_CONFIG_KEY_0: "diff.noprefix",
          GIT_CONFIG_VALUE_0: "true",
          GIT_CONFIG_KEY_1: "color.ui",
          GIT_CONFIG_VALUE_1: "always",
          GIT_CONFIG_KEY_2: "diff.external",
          GIT_CONFIG_VALUE_2: "true",
        },
        () => gate(repo),
      );
      expect(log.mock.calls.flat().join("\n")).toContain("gating 1 promoted rule(s)");
    } finally {
      log.mockRestore();
    }
  });
});
