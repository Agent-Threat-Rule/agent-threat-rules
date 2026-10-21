/**
 * Tests for scripts/remeasure-benign-fp.ts — the delta re-measure of the
 * response-action evidence.
 *
 * THE CONTRACT
 *
 * The delta must write evidence IDENTICAL to a full
 * `gate-promotion-fp.ts --ids <every rule> --filter-mode --emit-measurement`
 * run on the same tree, except `generated_at` and `commit`. The decisive test
 * below checks exactly that, with the REAL scripts at the function level: the
 * base evidence is produced by the real full measurement, the delta runs on a
 * harvested tree, and the real full measurement runs again on that tree for
 * comparison. Nothing here stands in for either side.
 *
 * ONE TRAP, ON THE COMPARISON SIDE
 *
 * gate-promotion-fp.ts writes `corpus_digest` from its module constant
 * REPO_ROOT, not from the injected GateDeps — so a full measurement of this
 * fixture carries the digest of the real repository's corpus. The base evidence
 * and the comparison document therefore get the digest a full run IN the
 * fixture would have written (corpusDigest over the fixture). The delta itself
 * must compute it over the head tree it was pointed at, and that is asserted
 * directly.
 *
 * Refusals: every precondition that would make "base count + delta" wrong exits
 * 4 ("full measurement required") and writes nothing. A disagreement between
 * the attribution pass and the canonical count exits 5 and writes nothing.
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { dirname, join, relative } from "node:path";
import { tmpdir } from "node:os";
import { gitRuleFiles, ruleIdOf, runGate } from "../scripts/gate-promotion-fp.js";
import { corpusDigest, MEASUREMENT_CORPORA } from "../src/quality/action-eligibility.js";
import { loadCorpusTexts } from "../scripts/lib/benign-corpus.js";
import {
  DEFAULT_MAX_FULL_RULES,
  EXIT_FAIL,
  EXIT_FULL_MEASUREMENT_REQUIRED,
  EXIT_INCONSISTENT,
  EXIT_OK,
  EXIT_USAGE,
  RemeasureUsageError,
  defaultRemeasureDeps,
  parseRemeasureArgs,
  runRemeasure,
  writeAddedCorpus,
  type RemeasureDeps,
  type RemeasureOptions,
} from "../scripts/remeasure-benign-fp.js";
import { parseAttributionReport, type AttributedRule } from "../scripts/lib/fp-attribution.js";
import { readRules } from "../scripts/gate-action-eligibility.js";

const EVIDENCE = "data/benign-fp-measurement.json";
const ARXIV = "data/benign-corpus-extended/arxiv.jsonl";
const NPM = "data/benign-corpus-extended/npm.jsonl";
const PYPI = "data/benign-corpus-extended/pypi.jsonl";
const SKILL_DIR = "data/skill-benchmark/benign";
const CODE = "data/benign-code/corpus.jsonl";

// R1 fires on "zebracorn" and its detection never changes: measured on the delta.
const R1 = "ATR-2026-91001";
// R2 never fires; its maturity moves test -> stable with the detection untouched,
// so it stays on the delta and its maturity must still come from the head tree.
const R2 = "ATR-2026-91002";
// R3's detection widens between base and head: measured in full.
const R3 = "ATR-2026-91003";
// R4 exists only at head, so the base evidence has no record of it: measured in full.
const R4 = "ATR-2026-91004";
// R6 is deleted at head: a full run would not measure it, so neither may the delta.
const R6 = "ATR-2026-91006";
// R7 fires on "zebracorn" like R1 but is a draft; R8 has maturity deprecated. The
// engine evaluates neither, so a full run records neither, and nor may the delta.
const R7 = "ATR-2026-91007";
const R8 = "ATR-2026-91008";

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

/** A minimal schema-valid rule the real engine loads; `pattern` is its one regex. */
function rule(id: string, pattern: string, maturity = "test"): string {
  return [
    `title: fixture ${id}`,
    `id: ${id}`,
    "rule_version: 1",
    "status: experimental",
    "description: fixture rule for the delta re-measure tests",
    "author: test",
    "date: 2026/10/15",
    "schema_version: '0.1'",
    "detection_tier: pattern",
    `maturity: ${maturity}`,
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
    `      value: '${pattern}'`,
    "      description: fixture",
    "response:",
    "  actions: [alert]",
    "test_cases:",
    "  true_positives: []",
    "  true_negatives: []",
    "",
  ].join("\n");
}

const record = (text: string, source: string, sourceId: string): string =>
  `${JSON.stringify({ text, source, source_id: sourceId, fetched_at: "2026-10-11" })}\n`;

function put(root: string, rel: string, text: string): void {
  mkdirSync(dirname(join(root, rel)), { recursive: true });
  writeFileSync(join(root, rel), text);
}

const digestOf = (root: string): string =>
  corpusDigest(
    root,
    MEASUREMENT_CORPORA,
    { existsSync, readdirSync, statSync, readFileSync },
    { join, relative },
    createHash,
  );

interface Fixture {
  readonly dir: string;
  readonly root: string;
  readonly scratch: string;
  readonly evidence: string;
  readonly report: string;
}

const fixtures: string[] = [];

/**
 * The real full measurement over every rule the tree carries, enumerated the
 * way the measurement itself enumerates them (gitRuleFiles + ruleIdOf).
 * `corpus_digest` is then set to what a full run inside the fixture would have
 * written (see the trap in the header).
 */
async function measureFull(fx: Fixture, out: string): Promise<void> {
  const ids = [...new Set(gitRuleFiles(fx.root).map((f) => ruleIdOf(fx.root, f)))].filter(
    (id): id is string => id !== null,
  );
  const idsFile = join(fx.scratch, `ids-${Date.now()}-${Math.random()}.txt`);
  writeFileSync(idsFile, `${ids.join("\n")}\n`);
  const code = await runGate(
    {
      idsFile,
      base: "origin/main",
      emitClean: null,
      emitDirty: join(fx.scratch, "full-dirty.txt"),
      emitMeasurement: out,
      filterMode: true,
    },
    {
      repoRoot: fx.root,
      rulesDir: join(fx.root, "rules"),
      corpora: MEASUREMENT_CORPORA.map((c) => join(fx.root, c)),
      listRuleFiles: () => gitRuleFiles(fx.root),
    },
  );
  expect(code).toBe(0);
  const doc = JSON.parse(readFileSync(out, "utf-8")) as Record<string, unknown>;
  writeFileSync(out, `${JSON.stringify({ ...doc, corpus_digest: digestOf(fx.root) }, null, 2)}\n`);
}

/** main as it stands before a harvest: rules, corpora, and evidence measured on them. */
async function baseFixture(): Promise<Fixture> {
  const dir = mkdtempSync(join(tmpdir(), "atr-remeasure-test-"));
  fixtures.push(dir);
  const fx: Fixture = {
    dir,
    root: join(dir, "repo"),
    scratch: join(dir, "scratch"),
    evidence: join(dir, "repo", EVIDENCE),
    report: join(dir, "scratch", "attribution.json"),
  };
  mkdirSync(fx.root, { recursive: true });
  mkdirSync(fx.scratch, { recursive: true });
  git(fx.root, "init", "--quiet", "-b", "main");
  put(fx.root, `rules/a/${R1}.yaml`, rule(R1, "zebracorn"));
  put(fx.root, `rules/a/${R2}.yaml`, rule(R2, "qqq-never-in-any-sample-qqq"));
  put(fx.root, `rules/b/${R3}.yaml`, rule(R3, "marmoset"));
  put(fx.root, `rules/b/${R6}.yaml`, rule(R6, "okapi"));
  put(fx.root, `${SKILL_DIR}/a.md`, "# A skill\n\nThis skill mentions zebracorn once.\n");
  put(fx.root, `${SKILL_DIR}/nested/b.md`, "# B skill\n\nFormats CSV files for the user. Okapi.\n");
  put(
    fx.root,
    ARXIV,
    record("An abstract about marmoset vocalisation.", "arxiv", "2401.00001") +
      record("A survey of graph neural networks.", "arxiv", "2401.00002") +
      record("Zebracorn twice, zebracorn.", "arxiv", "2401.00003") +
      "not json at all\n" +
      `${JSON.stringify({ source: "arxiv", source_id: "2401.00004" })}\n`,
  );
  put(fx.root, NPM, record("left-pad pads strings on the left", "npm", "left-pad"));
  put(fx.root, CODE, record("import os\nprint(os.getcwd())", "py-stdlib", "std-00"));
  git(fx.root, "add", "-A");
  git(fx.root, "commit", "--quiet", "-m", "base");
  await measureFull(fx, fx.evidence);
  git(fx.root, "add", EVIDENCE);
  git(fx.root, "commit", "--quiet", "-m", "evidence");
  return fx;
}

/** What a weekly harvest plus a week of rule work leave in the working tree. */
function harvest(fx: Fixture): void {
  appendFileSync(
    join(fx.root, ARXIV),
    record("We study zebracorn detection in the wild.", "arxiv", "2410.11111") +
      record("Pangolin scales as armour.", "arxiv", "2410.22222") +
      record("Nothing to see here.", "arxiv", "2410.33333") +
      // the same text as a base sample: the corpus is a multiset, so it counts again
      record("Zebracorn twice, zebracorn.", "arxiv", "2410.44444") +
      record("Axolotl limb regrowth.", "arxiv", "2410.55555"),
  );
  // one new text in two new records: two added samples, attributed to both
  appendFileSync(join(fx.root, NPM), record("We study zebracorn detection in the wild.", "npm", "zebracorn-study"));
  put(fx.root, PYPI, record("zebracorn utilities for python", "pypi", "zebracorn-utils"));
  put(fx.root, `${SKILL_DIR}/new-skill.md`, "# New skill\n\nIt also mentions zebracorn.\n");
  put(fx.root, `rules/a/${R2}.yaml`, rule(R2, "qqq-never-in-any-sample-qqq", "stable"));
  put(fx.root, `rules/b/${R3}.yaml`, rule(R3, "marmoset|pangolin"));
  put(fx.root, `rules/b/${R4}.yaml`, rule(R4, "axolotl"));
  unlinkSync(join(fx.root, `rules/b/${R6}.yaml`));
}

const options = (fx: Fixture, extra: Partial<RemeasureOptions> = {}): RemeasureOptions => ({
  baseRef: "HEAD",
  emitMeasurement: fx.evidence,
  report: fx.report,
  maxFullRules: DEFAULT_MAX_FULL_RULES,
  ...extra,
});

/** generated_at and commit differ by construction; everything else must not. */
function comparable(raw: string, digest?: string): string {
  const doc = JSON.parse(raw) as Record<string, unknown>;
  return JSON.stringify(
    {
      ...doc,
      generated_at: "<date>",
      commit: "<commit>",
      ...(digest === undefined ? {} : { corpus_digest: digest }),
    },
    null,
    2,
  );
}

afterAll(() => {
  for (const d of fixtures.splice(0)) rmSync(d, { recursive: true, force: true });
});

describe("the delta equals a full re-measurement of the harvested tree", () => {
  let fx: Fixture;
  let code: number;
  let delta: string;
  let full: string;
  let baseEvidence: Record<string, unknown>;

  beforeAll(async () => {
    fx = await baseFixture();
    baseEvidence = JSON.parse(readFileSync(fx.evidence, "utf-8")) as Record<string, unknown>;
    harvest(fx);
    code = await runRemeasure(options(fx), defaultRemeasureDeps(fx.root));
    delta = readFileSync(fx.evidence, "utf-8");
    const fullOut = join(fx.scratch, "full.json");
    await measureFull(fx, fullOut);
    full = readFileSync(fullOut, "utf-8");
  });

  it("succeeds", () => {
    expect(code).toBe(EXIT_OK);
  });

  it("writes the same document as the full measurement, byte for byte, except generated_at and commit", () => {
    expect(comparable(delta)).toBe(comparable(full, digestOf(fx.root)));
    expect(delta).toBe(`${JSON.stringify(JSON.parse(delta), null, 2)}\n`);
  });

  it("binds the evidence to the head corpus it describes", () => {
    const doc = JSON.parse(delta) as { corpus_digest: string; sample_count: number };
    expect(doc.corpus_digest).toBe(digestOf(fx.root));
    expect(doc.corpus_digest).not.toBe(baseEvidence.corpus_digest);
    const head = MEASUREMENT_CORPORA.flatMap((c) => loadCorpusTexts(join(fx.root, c)));
    expect(doc.sample_count).toBe(head.length);
    expect(doc.sample_count).toBe((baseEvidence.sample_count as number) + 8);
  });

  it("counts a duplicated text again, as the full measurement does", () => {
    const rules = (JSON.parse(delta) as { rules: Record<string, { fp_count: number }> }).rules;
    const before = (baseEvidence.rules as Record<string, { fp_count: number }>)[R1];
    expect(before?.fp_count).toBe(2);
    expect(rules[R1]?.fp_count).toBe(7);
  });

  it("takes static fields from the head rules and drops a rule deleted at head", () => {
    const rules = (JSON.parse(delta) as { rules: Record<string, { maturity: string }> }).rules;
    expect(Object.keys(rules)).toEqual([R1, R2, R3, R4]);
    expect(rules[R2]?.maturity).toBe("stable");
    expect(Object.keys(baseEvidence.rules as object)).toContain(R6);
  });

  it("measures unchanged rules on the new samples only and the rest in full", () => {
    const report = parseAttributionReport(readFileSync(fx.report, "utf-8"));
    expect(report.rules_total).toBe(4);
    expect(report.measured_on_added_only).toBe(2);
    expect(report.measured_in_full).toEqual([
      { id: R3, reason: "detection-changed" },
      { id: R4, reason: "absent-from-base-evidence" },
    ]);
    expect(report.added_sample_count).toBe(8);
    expect(report.base_sample_count).toBe(baseEvidence.sample_count);
    expect(report.head_sample_count).toBe(report.base_sample_count + 8);
  });

  it("attributes every count a new sample added to the sample, with its provenance", () => {
    const report = parseAttributionReport(readFileSync(fx.report, "utf-8"));
    const byId = new Map<string, AttributedRule>(report.rules.map((r) => [r.id, r]));
    expect([...byId.keys()]).toEqual([R1, R3, R4]);

    const r1 = byId.get(R1);
    expect(r1).toMatchObject({ measured: "delta", fp_count_before: 2, fp_count_after: 7, added_matches: 5 });
    const where = (r1?.samples ?? []).map((s) => s.locations.map((l) => `${l.source}:${l.source_id}`));
    expect(where).toContainEqual(["arxiv:2410.11111", "npm:zebracorn-study"]);
    expect(r1?.samples.find((s) => s.locations.length === 2)?.occurrences).toBe(2);
    expect(where).toContainEqual(["arxiv:2410.44444"]);
    expect(where).toContainEqual(["pypi:zebracorn-utils"]);
    const skill = r1?.samples.find((s) => s.locations[0]?.file === `${SKILL_DIR}/new-skill.md`);
    expect(skill?.locations[0]).toEqual({
      file: `${SKILL_DIR}/new-skill.md`,
      line: null,
      source: null,
      source_id: null,
    });
    const dup = r1?.samples.find((s) => s.locations[0]?.source_id === "2410.44444");
    expect(dup?.excerpt).toBe("Zebracorn twice, zebracorn.");
    expect(dup?.locations[0]?.file).toBe(ARXIV);
    expect(dup?.locations[0]?.line).toBe(9);

    expect(byId.get(R3)).toMatchObject({ measured: "full", fp_count_before: 1, fp_count_after: 2, added_matches: 1 });
    expect(byId.get(R3)?.samples[0]?.locations[0]?.source_id).toBe("2410.22222");
    expect(byId.get(R4)).toMatchObject({ measured: "full", fp_count_before: null, fp_count_after: 1, added_matches: 1 });
  });
});

describe("refusals write nothing", () => {
  async function expectRefusal(
    fx: Fixture,
    expected: number,
    opts: Partial<RemeasureOptions> = {},
    deps: RemeasureDeps = defaultRemeasureDeps(fx.root),
  ): Promise<void> {
    const before = readFileSync(fx.evidence, "utf-8");
    const code = await runRemeasure(options(fx, opts), deps);
    expect(code).toBe(expected);
    expect(readFileSync(fx.evidence, "utf-8")).toBe(before);
    expect(existsSync(fx.report)).toBe(false);
  }

  /** Commit an edited base evidence file, the way a stale or hand-edited one would land on main. */
  function commitEvidence(fx: Fixture, edit: (doc: Record<string, unknown>) => Record<string, unknown>): void {
    const doc = JSON.parse(readFileSync(fx.evidence, "utf-8")) as Record<string, unknown>;
    writeFileSync(fx.evidence, `${JSON.stringify(edit(doc), null, 2)}\n`);
    git(fx.root, "commit", "--quiet", "-am", "edit evidence");
  }

  it("when the base evidence was not measured on the base corpus", async () => {
    const fx = await baseFixture();
    commitEvidence(fx, (d) => ({ ...d, corpus_digest: "0".repeat(32) }));
    harvest(fx);
    await expectRefusal(fx, EXIT_FULL_MEASUREMENT_REQUIRED);
  });

  it("when a base sample was removed", async () => {
    const fx = await baseFixture();
    harvest(fx);
    const arxiv = readFileSync(join(fx.root, ARXIV), "utf-8");
    writeFileSync(join(fx.root, ARXIV), arxiv.replace(/^.*2401\.00002.*\n/m, ""));
    await expectRefusal(fx, EXIT_FULL_MEASUREMENT_REQUIRED);
  });

  it("when a base sample was modified", async () => {
    const fx = await baseFixture();
    harvest(fx);
    const arxiv = readFileSync(join(fx.root, ARXIV), "utf-8");
    writeFileSync(join(fx.root, ARXIV), arxiv.replace("graph neural networks", "graph neural nets"));
    await expectRefusal(fx, EXIT_FULL_MEASUREMENT_REQUIRED);
  });

  it("when the base evidence was taken on a different shape set", async () => {
    const fx = await baseFixture();
    commitEvidence(fx, (d) => ({ ...d, shapes: (d.shapes as string[]).filter((s) => s !== "skill") }));
    harvest(fx);
    await expectRefusal(fx, EXIT_FULL_MEASUREMENT_REQUIRED);
  });

  it("when the base evidence's sample count does not match the base corpus", async () => {
    const fx = await baseFixture();
    commitEvidence(fx, (d) => ({ ...d, sample_count: (d.sample_count as number) + 1 }));
    harvest(fx);
    await expectRefusal(fx, EXIT_FULL_MEASUREMENT_REQUIRED);
  });

  it("when the base evidence names other corpora", async () => {
    const fx = await baseFixture();
    commitEvidence(fx, (d) => ({ ...d, corpora: ["data/skill-benchmark/benign"] }));
    harvest(fx);
    await expectRefusal(fx, EXIT_FULL_MEASUREMENT_REQUIRED);
  });

  it("when the base ref carries no evidence at all", async () => {
    const fx = await baseFixture();
    git(fx.root, "rm", "--quiet", EVIDENCE);
    git(fx.root, "commit", "--quiet", "-m", "drop evidence");
    put(fx.root, EVIDENCE, "{}\n");
    harvest(fx);
    await expectRefusal(fx, EXIT_FULL_MEASUREMENT_REQUIRED);
  });

  it("when more rules need a full measurement than allowed, instead of running for hours", async () => {
    const fx = await baseFixture();
    harvest(fx);
    await expectRefusal(fx, EXIT_FULL_MEASUREMENT_REQUIRED, { maxFullRules: 1 });
  });

  it("when the tree carries no rules at all, rather than writing evidence for none", async () => {
    const fx = await baseFixture();
    rmSync(join(fx.root, "rules"), { recursive: true, force: true });
    await expectRefusal(fx, EXIT_FAIL);
  });

  it("when the base ref does not resolve", async () => {
    const fx = await baseFixture();
    harvest(fx);
    await expectRefusal(fx, EXIT_USAGE, { baseRef: "no-such-branch" });
  });

  it("when the attribution pass disagrees with the canonical count", async () => {
    const fx = await baseFixture();
    harvest(fx);
    const real = defaultRemeasureDeps(fx.root);
    const blind: RemeasureDeps = {
      ...real,
      matchedRuleIds: (engine, text) =>
        new Set([...real.matchedRuleIds(engine, text)].filter((id) => id !== R1)),
    };
    await expectRefusal(fx, EXIT_INCONSISTENT, {}, blind);
  });
});

describe("an unchanged corpus re-measures only what is stale", () => {
  it("leaves unchanged rules at their committed counts and measures the rest in full", async () => {
    const fx = await baseFixture();
    put(fx.root, `rules/b/${R4}.yaml`, rule(R4, "zebracorn|marmoset"));
    const code = await runRemeasure(options(fx), defaultRemeasureDeps(fx.root));
    expect(code).toBe(EXIT_OK);
    const fullOut = join(fx.scratch, "full.json");
    await measureFull(fx, fullOut);
    expect(comparable(readFileSync(fx.evidence, "utf-8"))).toBe(
      comparable(readFileSync(fullOut, "utf-8"), digestOf(fx.root)),
    );
    const report = parseAttributionReport(readFileSync(fx.report, "utf-8"));
    expect(report.added_sample_count).toBe(0);
    expect(report.rules).toEqual([]);
  });
});

describe("a rule the engine does not evaluate", () => {
  const draft = (id: string, pattern: string): string =>
    rule(id, pattern).replace("status: experimental", "status: draft");

  it("gets no record on either path, and the delta still equals the full measurement", async () => {
    const fx = await baseFixture();
    put(fx.root, `rules/c/${R7}.yaml`, draft(R7, "zebracorn"));
    put(fx.root, `rules/c/${R8}.yaml`, rule(R8, "zebracorn", "deprecated"));
    harvest(fx);
    expect(await runRemeasure(options(fx), defaultRemeasureDeps(fx.root))).toBe(EXIT_OK);
    const fullOut = join(fx.scratch, "full.json");
    await measureFull(fx, fullOut);
    const delta = readFileSync(fx.evidence, "utf-8");
    expect(comparable(delta)).toBe(comparable(readFileSync(fullOut, "utf-8"), digestOf(fx.root)));
    expect(Object.keys((JSON.parse(delta) as { rules: object }).rules)).toEqual([R1, R2, R3, R4]);
  });

  it("is measured in full once revived, not credited with the 0 an older measurement wrote for it", async () => {
    const fx = await baseFixture();
    put(fx.root, `rules/c/${R7}.yaml`, draft(R7, "zebracorn"));
    put(fx.root, `rules/c/${R8}.yaml`, rule(R8, "zebracorn", "deprecated"));
    git(fx.root, "add", "-A");
    git(fx.root, "commit", "--quiet", "-m", "two inert rules");
    // What gate-promotion-fp.ts wrote for such rules before it asked the engine:
    // a 0, under the fingerprint the action gate compares against.
    const prints = new Map(readRules(join(fx.root, "rules")).map((r) => [r.id, r.fingerprint]));
    const zero = (id: string, maturity: string): Record<string, unknown> => ({
      fp_count: 0,
      maturity,
      detection_fingerprint: prints.get(id),
      partial_measurement: false,
      skill_path_unmeasured: false,
    });
    const doc = JSON.parse(readFileSync(fx.evidence, "utf-8")) as { rules: Record<string, unknown> };
    const rules = Object.fromEntries(
      Object.entries({ ...doc.rules, [R7]: zero(R7, "test"), [R8]: zero(R8, "deprecated") }).sort(([a], [b]) =>
        a.localeCompare(b),
      ),
    );
    writeFileSync(fx.evidence, `${JSON.stringify({ ...doc, rules }, null, 2)}\n`);
    git(fx.root, "commit", "--quiet", "-am", "evidence as the older measurement wrote it");
    // Revived in one line: same detection, so the same fingerprint as the 0 above.
    put(fx.root, `rules/c/${R7}.yaml`, rule(R7, "zebracorn"));
    harvest(fx);

    expect(await runRemeasure(options(fx), defaultRemeasureDeps(fx.root))).toBe(EXIT_OK);
    const fullOut = join(fx.scratch, "full.json");
    await measureFull(fx, fullOut);
    const delta = readFileSync(fx.evidence, "utf-8");
    expect(comparable(delta)).toBe(comparable(readFileSync(fullOut, "utf-8"), digestOf(fx.root)));
    const out = (JSON.parse(delta) as { rules: Record<string, { fp_count: number }> }).rules;
    // R1's count: 2 on the base corpus, 5 on the added samples. Not the carried 0 plus 5.
    expect(out[R7]?.fp_count).toBe(7);
    expect(out[R8]).toBeUndefined();
    const report = parseAttributionReport(readFileSync(fx.report, "utf-8"));
    expect(report.measured_in_full).toContainEqual({ id: R7, reason: "not-evaluated-at-base" });
    // The 0 was never a count, so the report does not show it as the one before.
    expect(report.rules.find((r) => r.id === R7)).toMatchObject({ measured: "full", fp_count_before: null });
  });

  it("drops the record of a rule retired at head, as the full measurement does", async () => {
    const fx = await baseFixture();
    const before = JSON.parse(readFileSync(fx.evidence, "utf-8")) as { rules: Record<string, unknown> };
    expect(Object.keys(before.rules)).toContain(R1);
    put(fx.root, `rules/a/${R1}.yaml`, draft(R1, "zebracorn"));
    harvest(fx);
    expect(await runRemeasure(options(fx), defaultRemeasureDeps(fx.root))).toBe(EXIT_OK);
    const fullOut = join(fx.scratch, "full.json");
    await measureFull(fx, fullOut);
    const delta = readFileSync(fx.evidence, "utf-8");
    expect(comparable(delta)).toBe(comparable(readFileSync(fullOut, "utf-8"), digestOf(fx.root)));
    expect(Object.keys((JSON.parse(delta) as { rules: object }).rules)).toEqual([R2, R3, R4]);
  });
});

describe("writeAddedCorpus", () => {
  it("round-trips every text the corpus loader can produce, duplicates included", () => {
    const dir = mkdtempSync(join(tmpdir(), "atr-added-corpus-"));
    fixtures.push(dir);
    const texts = [
      "plain",
      "",
      "multi\nline\r\nwith CRLF",
      "  padded on both sides  ",
      "lone surrogate \ud800 inside",
      "emoji 🦎 and 中文",
      '{"text":"a JSON document as text"}',
      "duplicate",
      "duplicate",
      "",
    ];
    writeAddedCorpus(join(dir, "added"), texts);
    expect([...loadCorpusTexts(join(dir, "added"))].sort()).toEqual([...texts].sort());
  });
});

describe("parseRemeasureArgs", () => {
  it("reads every flag", () => {
    expect(
      parseRemeasureArgs([
        "--base-ref",
        "origin/main",
        "--emit-measurement",
        "data/benign-fp-measurement.json",
        "--report",
        "/tmp/r.json",
        "--max-full-rules",
        "12",
      ]),
    ).toEqual({
      baseRef: "origin/main",
      emitMeasurement: "data/benign-fp-measurement.json",
      report: "/tmp/r.json",
      maxFullRules: 12,
    });
  });

  it("defaults the base to HEAD, the report to none and the limit to 200", () => {
    expect(parseRemeasureArgs(["--emit-measurement", "out.json"])).toEqual({
      baseRef: "HEAD",
      emitMeasurement: "out.json",
      report: null,
      maxFullRules: 200,
    });
  });

  it.each([
    [[], "--emit-measurement is required"],
    [["--emit-measurement"], "requires a value"],
    [["--emit-measurement", "--report", "r.json"], "requires a value"],
    [["--emit-measurment", "out.json"], "unknown argument"],
    [["--emit-measurement", "out.json", "stray"], "unknown argument"],
    [["--emit-measurement", "a.json", "--emit-measurement", "b.json"], "more than once"],
    [["--emit-measurement", "out.json", "--base-ref", "-c"], "--base-ref"],
    [["--emit-measurement", "out.json", "--max-full-rules", "ten"], "--max-full-rules"],
    [["--emit-measurement", "out.json", "--max-full-rules", "-1"], "--max-full-rules"],
    [["--emit-measurement", "out.json", "--report", "out.json"], "different"],
  ])("rejects %j", (argv, message) => {
    expect(() => parseRemeasureArgs(argv)).toThrow(RemeasureUsageError);
    expect(() => parseRemeasureArgs(argv)).toThrow(message);
  });
});
