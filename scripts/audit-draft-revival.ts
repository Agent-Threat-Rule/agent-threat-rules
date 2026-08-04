#!/usr/bin/env node
/**
 * audit-draft-revival.ts — measure, for every `status: draft` rule, whether it
 * could be revived (status flipped to `experimental`) without regressing quality.
 *
 * WHY: engine.ts skips `status: deprecated | draft` on BOTH evaluation paths
 * (evaluateRaw and evaluateAsync), before the lane gate. A draft rule therefore
 * never fires in any lane — not even `hunt` — no matter how good it is. Reviving
 * one is a one-line status edit, so the only question worth measuring is:
 * "if this rule were allowed to fire, would it behave?"
 *
 * This script answers that for all draft rules at once, by measurement, not by
 * eyeballing YAML:
 *   1. discover every rule whose normalised status is `draft`
 *   2. flip a COPY of it to `experimental` (in memory — no rule file is written)
 *   3. run its own declared test_cases through the live engine
 *   4. count its false positives on the benign corpora
 *   5. classify: REVIVE / TESTCASE-FAIL / FP-DIRTY / NO-TESTCASES
 *
 * Measurement fidelity notes (both are places this repo has been burned before):
 *   - The benign event shape comes from scripts/lib/corpus-event.ts (`matchedRuleIds`
 *     + the same three corpora), the single module every FP harness shares. It used
 *     to be a verbatim COPY of gate-promotion-fp.ts's builder, and copying is how the
 *     defect spread: when that gate moved to the canonical shape set, this copy did
 *     not, and kept scoring rules on a narrower presentation than production. The
 *     same corpus scored with a different event shape yields wildly different FP
 *     counts, so import the shared module — never mirror it.
 *   - Measuring a draft rule WITHOUT flipping it returns 0 FP and 0 test-case hits
 *     for every rule — the engine skipped it. That zero is an artefact, not a
 *     result. The flip is what makes the numbers real; `--no-flip` exists only to
 *     demonstrate that artefact.
 *   - Test cases are scored against the generic text shape FIRST (as
 *     validate-rule-testcases.ts does) and, only if that does not fire, against a
 *     shape that puts the payload where the test case says it lives: the named
 *     engine field (`tool_args`, `tool_name`, …) or, for method=trace rules, a
 *     parsed `event.trace`. A rule whose condition reads `tool_args` cannot fire
 *     on an event that carries no `tool_args`; scoring that as a rule failure
 *     measures the harness, not the rule. Both shapes are applied to true
 *     NEGATIVES too, so the extra shape can never manufacture a clean pass.
 *
 * Scope: tracked rule files by default, so the population matches what CI and
 * gate-promotion-fp see. Untracked draft rules are never silently dropped — they
 * are listed by id and can be included with --include-untracked.
 *
 * This script never writes to rules/. It is a measurement pass only.
 *
 * Usage:
 *   npx tsx scripts/audit-draft-revival.ts [--json] [--out <path>]
 *                                          [--only <ATR-id,ATR-id>]
 *                                          [--include-untracked] [--no-flip]
 */
import { readFileSync, readdirSync, statSync, existsSync, writeFileSync, mkdtempSync, mkdirSync } from "node:fs";
import { join, resolve, dirname, relative } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { ATREngine } from "../src/engine.js";
import type { ATRRule, AgentEvent } from "../src/types.js";
import { matchedRuleIds } from "./lib/corpus-event.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(REPO_ROOT, "rules");

/** Same three benign corpora the promotion FP gate uses. Keep in sync. */
const CORPORA: readonly string[] = [
  join(REPO_ROOT, "data/skill-benchmark/benign"),
  join(REPO_ROOT, "data/benign-corpus-extended"),
  join(REPO_ROOT, "data/benign-code"),
];

/**
 * Test-case text extraction. The first four keys are exactly the chain used by
 * scripts/validate-rule-testcases.ts; `tool_args` is appended because 25 draft
 * test cases carry their payload there and the shorter chain would score them as
 * empty strings — i.e. as rule failures that are really harness failures.
 */
const TEXT_KEYS = ["tool_response", "input", "content", "tool_description", "tool_args"] as const;

/**
 * Engine field names a test case may name explicitly. When an entry uses one,
 * the payload is ALSO delivered in that field (see fieldAwareEvent) — a rule
 * whose condition reads `tool_args` cannot fire on an event that has no
 * `tool_args`, and scoring that as a rule failure would be a harness artefact.
 */
const ENGINE_FIELD_KEYS = [
  "tool_name",
  "tool_args",
  "tool_input",
  "tool_response",
  "tool_description",
  "user_input",
  "agent_output",
  "agent_message",
] as const;

/** agent_source.type -> an event type that maps back to it (EVENT_TYPE_TO_SOURCE). */
const SOURCE_TO_EVENT_TYPE: Record<string, AgentEvent["type"]> = {
  tool_call: "tool_call",
  mcp_exchange: "tool_response",
  llm_io: "llm_input",
  agent_behavior: "agent_behavior",
  multi_agent_comm: "multi_agent_message",
};

type Verdict = "REVIVE" | "TESTCASE-FAIL" | "FP-DIRTY" | "NO-TESTCASES";

interface DraftRule {
  readonly id: string;
  readonly file: string;
  readonly tracked: boolean;
  readonly severity: string;
  readonly maturity: string;
  readonly rule: ATRRule;
}

interface TestCaseResult {
  readonly tpPass: number;
  readonly tpFail: number;
  readonly tnPass: number;
  readonly tnFail: number;
  readonly unextractable: number;
  /** True positives that only fired once the payload was delivered in its declared field / as a trace. */
  readonly shapeDependentTp: number;
  readonly failures: readonly string[];
}

interface RuleResult extends TestCaseResult {
  readonly id: string;
  readonly file: string;
  readonly tracked: boolean;
  readonly severity: string;
  readonly maturity: string;
  readonly fpCount: number;
  readonly verdict: Verdict;
}

// ---------------------------------------------------------------------------
// CLI (pure)
// ---------------------------------------------------------------------------

interface Options {
  readonly json: boolean;
  readonly out: string | null;
  readonly only: ReadonlySet<string> | null;
  readonly includeUntracked: boolean;
  readonly flip: boolean;
}

function parseOptions(argv: readonly string[]): Options {
  const valueOf = (name: string): string | null => {
    const i = argv.indexOf(name);
    return i >= 0 ? (argv[i + 1] ?? null) : null;
  };
  const only = valueOf("--only");
  return {
    json: argv.includes("--json"),
    out: valueOf("--out"),
    only: only === null ? null : new Set(only.split(",").map((s) => s.trim()).filter(Boolean)),
    includeUntracked: argv.includes("--include-untracked"),
    flip: !argv.includes("--no-flip"),
  };
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

function walkYamlFiles(dir: string): readonly string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) found.push(...walkYamlFiles(full));
    else if (entry.endsWith(".yaml") || entry.endsWith(".yml")) found.push(full);
  }
  return found;
}

function trackedRuleFiles(): ReadonlySet<string> {
  const out = execFileSync("git", ["ls-files", "rules/"], {
    cwd: REPO_ROOT,
    encoding: "utf-8",
    maxBuffer: 64 * 1024 * 1024,
  });
  return new Set(out.split("\n").filter((f) => f.endsWith(".yaml") || f.endsWith(".yml")));
}

/** Handles both `status: draft` and `status: "draft"` (and any casing/padding). */
function normalised(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function discoverDrafts(): readonly DraftRule[] {
  const tracked = trackedRuleFiles();
  const drafts: DraftRule[] = [];
  for (const file of walkYamlFiles(RULES_DIR)) {
    let parsed: unknown;
    try {
      parsed = yaml.load(readFileSync(file, "utf-8"));
    } catch {
      continue;
    }
    if (parsed === null || typeof parsed !== "object") continue;
    const rule = parsed as ATRRule & { maturity?: string };
    if (normalised(rule.status) !== "draft") continue;
    const rel = relative(REPO_ROOT, file);
    drafts.push({
      id: rule.id,
      file: rel,
      tracked: tracked.has(rel),
      severity: String(rule.severity ?? "unknown"),
      maturity: String(rule.maturity ?? "unset"),
      rule,
    });
  }
  return [...drafts].sort((a, b) => a.id.localeCompare(b.id));
}

// ---------------------------------------------------------------------------
// Engine (loads ONLY the audited rules — never the whole rules/ tree)
// ---------------------------------------------------------------------------

/** Immutable flip: the on-disk rule file is never touched. */
function flipToExperimental(rule: ATRRule): ATRRule {
  return { ...rule, status: "experimental" };
}

async function buildEngine(rules: readonly ATRRule[]): Promise<ATREngine> {
  // An empty rulesDir is mandatory: with rulesDir undefined the engine falls back
  // to the bundled rules/ directory and would silently load all ~780 rules.
  const emptyDir = mkdtempSync(join(tmpdir(), "atr-draft-audit-empty-"));
  const engine = new ATREngine({ rules: [...rules], rulesDir: emptyDir });
  const loaded = await engine.loadRules();
  if (loaded !== rules.length) {
    throw new Error(`engine loaded ${loaded} rules but ${rules.length} were supplied — scope leak`);
  }
  return engine;
}

/**
 * Every rule id a sample matches, via the canonical shape set.
 *
 * This used to be a copy of gate-promotion-fp.ts's event builder. Copying is how
 * the defect spread: when that gate moved to the canonical shapes, the copies did
 * not, and each one silently kept scoring rules on a presentation narrower than
 * production. Import the shared module rather than mirroring it.
 */
function matchedIds(engine: ATREngine, content: string): ReadonlySet<string> {
  return matchedRuleIds(engine, content);
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------

function extractText(entry: unknown): string | null {
  if (typeof entry === "string") return entry;
  if (entry === null || typeof entry !== "object") return null;
  const rec = entry as Record<string, unknown>;
  for (const key of TEXT_KEYS) {
    const v = rec[key];
    if (typeof v === "string" && v.length > 0) return v;
    if (v !== undefined && v !== null && typeof v === "object") return JSON.stringify(v);
  }
  return null;
}

function entriesOf(rule: ATRRule, bucket: "true_positives" | "true_negatives"): readonly unknown[] {
  const tc = (rule as { test_cases?: Record<string, unknown> }).test_cases;
  const arr = tc?.[bucket];
  return Array.isArray(arr) ? arr : [];
}

/**
 * Secondary event shape: deliver the payload in the field the test case names,
 * and as a parsed trace for method=trace rules. Used ONLY for test cases (the
 * benign FP scan keeps the gate's shape verbatim). Without this, a rule reading
 * `tool_args` or `event.trace` can never fire on its own declared TP — a harness
 * artefact that reads exactly like a broken rule.
 */
function fieldAwareEvent(entry: unknown, text: string, rule: ATRRule): AgentEvent | null {
  const method = (rule.detection as { method?: string } | undefined)?.method;
  if (method === "trace") {
    try {
      const parsed = JSON.parse(text) as { spans?: unknown };
      if (Array.isArray(parsed.spans)) {
        return {
          type: "tool_call",
          timestamp: new Date().toISOString(),
          content: text,
          trace: parsed as AgentEvent["trace"],
        };
      }
    } catch {
      return null;
    }
    return null;
  }
  if (entry === null || typeof entry !== "object") return null;
  const rec = entry as Record<string, unknown>;
  const fields: Record<string, string> = {};
  for (const key of ENGINE_FIELD_KEYS) {
    const v = rec[key];
    if (typeof v === "string" && v.length > 0) fields[key] = v;
  }
  if (Object.keys(fields).length === 0) return null;
  const sourceType = String(rule.agent_source?.type ?? "");
  return {
    type: SOURCE_TO_EVENT_TYPE[sourceType] ?? "tool_call",
    timestamp: new Date().toISOString(),
    content: text,
    fields,
  };
}

interface Firing {
  readonly fired: boolean;
  /** The generic text shape alone did not fire it; a declared-field/trace shape did. */
  readonly shapeDependent: boolean;
}

function fires(engine: ATREngine, entry: unknown, text: string, draft: DraftRule): Firing {
  if (matchedIds(engine, text).has(draft.id)) return { fired: true, shapeDependent: false };
  const extra = fieldAwareEvent(entry, text, draft.rule);
  if (extra === null) return { fired: false, shapeDependent: false };
  const hit = engine.evaluate(extra).some((m) => m.rule.id === draft.id);
  return { fired: hit, shapeDependent: hit };
}

function runTestCases(engine: ATREngine, draft: DraftRule): TestCaseResult {
  let tpPass = 0;
  let tpFail = 0;
  let tnPass = 0;
  let tnFail = 0;
  let unextractable = 0;
  let shapeDependentTp = 0;
  const failures: string[] = [];

  for (const entry of entriesOf(draft.rule, "true_positives")) {
    const text = extractText(entry);
    if (text === null) {
      unextractable++;
      failures.push("TP has no extractable text field (harness blind spot, not a rule failure)");
      continue;
    }
    const { fired, shapeDependent } = fires(engine, entry, text, draft);
    if (fired) {
      tpPass++;
      if (shapeDependent) shapeDependentTp++;
    } else {
      tpFail++;
      failures.push(`TP NOT triggered: ${JSON.stringify(text).slice(0, 90)}`);
    }
  }
  for (const entry of entriesOf(draft.rule, "true_negatives")) {
    const text = extractText(entry);
    if (text === null) {
      unextractable++;
      failures.push("TN has no extractable text field (harness blind spot, not a rule failure)");
      continue;
    }
    if (fires(engine, entry, text, draft).fired) {
      tnFail++;
      failures.push(`TN triggered (should not): ${JSON.stringify(text).slice(0, 90)}`);
    } else tnPass++;
  }
  return { tpPass, tpFail, tnPass, tnFail, unextractable, shapeDependentTp, failures };
}

// ---------------------------------------------------------------------------
// Benign FP scan (single corpus pass, all audited rules tallied at once)
// ---------------------------------------------------------------------------

function loadCorpusTexts(pathStr: string): readonly string[] {
  const texts: string[] = [];
  if (!existsSync(pathStr)) return texts;
  const files: string[] = [];
  if (statSync(pathStr).isDirectory()) {
    for (const e of readdirSync(pathStr))
      if (e.endsWith(".jsonl") || e.endsWith(".md")) files.push(join(pathStr, e));
  } else files.push(pathStr);
  for (const f of files) {
    let raw: string;
    try {
      raw = readFileSync(f, "utf-8");
    } catch {
      continue;
    }
    if (f.endsWith(".md")) {
      texts.push(raw);
      continue;
    }
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        const obj = JSON.parse(t) as { text?: string };
        if (typeof obj.text === "string" && obj.text.length > 0) texts.push(obj.text);
      } catch {
        continue;
      }
    }
  }
  return texts;
}

interface FpScan {
  readonly counts: ReadonlyMap<string, number>;
  readonly sampleCount: number;
}

function scanBenign(engine: ATREngine, ids: ReadonlySet<string>): FpScan {
  const samples: string[] = [];
  for (const c of CORPORA) samples.push(...loadCorpusTexts(c));
  const counts = new Map<string, number>();
  for (const id of ids) counts.set(id, 0);
  let done = 0;
  for (const text of samples) {
    for (const id of matchedIds(engine, text)) {
      if (ids.has(id)) counts.set(id, (counts.get(id) ?? 0) + 1);
    }
    done++;
    if (done % 500 === 0) process.stderr.write(`[draft-audit] benign scan ${done}/${samples.length}\n`);
  }
  return { counts, sampleCount: samples.length };
}

// ---------------------------------------------------------------------------
// Verdict + reporting
// ---------------------------------------------------------------------------

function verdictOf(tc: TestCaseResult, fpCount: number, hasTestCases: boolean): Verdict {
  if (!hasTestCases) return "NO-TESTCASES";
  if (tc.tpFail > 0 || tc.tnFail > 0 || tc.unextractable > 0) return "TESTCASE-FAIL";
  return fpCount === 0 ? "REVIVE" : "FP-DIRTY";
}

function printHuman(
  results: readonly RuleResult[],
  sampleCount: number,
  flipped: boolean,
  log: (s: string) => void,
): void {
  const byVerdict = (v: Verdict): readonly RuleResult[] => results.filter((r) => r.verdict === v);
  log("");
  log(`[draft-audit] audited ${results.length} draft rule(s) against ${sampleCount} benign samples`);
  log(
    flipped
      ? `[draft-audit] lane = hunt (engine default) · status flipped draft -> experimental in memory only`
      : `[draft-audit] lane = hunt (engine default) · NO FLIP — every number below is an engine-skip artefact`,
  );
  log("");
  for (const v of ["REVIVE", "FP-DIRTY", "TESTCASE-FAIL", "NO-TESTCASES"] as const) {
    const group = byVerdict(v);
    log(`=== ${v} — ${group.length} rule(s)`);
    for (const r of group) {
      const tc = `TP ${r.tpPass}/${r.tpPass + r.tpFail} · TN ${r.tnPass}/${r.tnPass + r.tnFail}`;
      const extra =
        (r.unextractable > 0 ? ` · ${r.unextractable} unextractable` : "") +
        (r.shapeDependentTp > 0 ? ` · ${r.shapeDependentTp} TP need declared-field/trace shape` : "");
      log(`  ${r.id}  ${r.severity.padEnd(8)} maturity=${r.maturity.padEnd(6)} FP=${r.fpCount}  ${tc}${extra}`);
      if (v !== "REVIVE") for (const f of r.failures.slice(0, 3)) log(`      - ${f}`);
    }
    log("");
  }
  const sev = (v: Verdict, s: string): number =>
    results.filter((r) => r.verdict === v && r.severity === s).length;
  log(`[draft-audit] REVIVE by severity: critical=${sev("REVIVE", "critical")} high=${sev("REVIVE", "high")} medium=${sev("REVIVE", "medium")}`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(argv: readonly string[]): Promise<number> {
  const options = parseOptions(argv);
  const all = discoverDrafts();
  const untracked = all.filter((d) => !d.tracked);
  if (untracked.length > 0) {
    process.stderr.write(
      `[draft-audit] ${untracked.length} draft rule(s) are UNTRACKED and ` +
        `${options.includeUntracked ? "INCLUDED (--include-untracked)" : "EXCLUDED (pass --include-untracked to audit them)"}: ` +
        `${untracked.map((d) => d.id).join(", ")}\n`,
    );
  }
  const scoped = all
    .filter((d) => options.includeUntracked || d.tracked)
    .filter((d) => options.only === null || options.only.has(d.id));

  if (scoped.length === 0) {
    process.stderr.write("[draft-audit] no draft rules in scope — nothing measured.\n");
    return 1;
  }
  process.stderr.write(
    `[draft-audit] scope: ${scoped.length} draft rule(s) of ${all.length} on disk ` +
      `(flip=${options.flip ? "on" : "OFF — expect artefact zeros"})\n`,
  );

  const audited = options.flip ? scoped.map((d) => flipToExperimental(d.rule)) : scoped.map((d) => d.rule);
  const engine = await buildEngine(audited);
  const ids = new Set(scoped.map((d) => d.id));

  const tcResults = new Map<string, TestCaseResult>();
  for (const draft of scoped) tcResults.set(draft.id, runTestCases(engine, draft));

  const { counts, sampleCount } = scanBenign(engine, ids);

  const results: readonly RuleResult[] = scoped.map((d) => {
    const tc = tcResults.get(d.id) as TestCaseResult;
    const hasTestCases =
      entriesOf(d.rule, "true_positives").length + entriesOf(d.rule, "true_negatives").length > 0;
    const fpCount = counts.get(d.id) ?? 0;
    return {
      id: d.id,
      file: d.file,
      tracked: d.tracked,
      severity: d.severity,
      maturity: d.maturity,
      fpCount,
      verdict: verdictOf(tc, fpCount, hasTestCases),
      ...tc,
    };
  });

  const payload = {
    generated: new Date().toISOString(),
    repoRoot: REPO_ROOT,
    head: execFileSync("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT, encoding: "utf-8" }).trim(),
    lane: "hunt",
    flipped: options.flip,
    benignSamples: sampleCount,
    corpora: CORPORA.map((c) => relative(REPO_ROOT, c)),
    draftsOnDisk: all.length,
    untrackedDraftIds: untracked.map((d) => d.id),
    audited: results.length,
    summary: {
      REVIVE: results.filter((r) => r.verdict === "REVIVE").length,
      "FP-DIRTY": results.filter((r) => r.verdict === "FP-DIRTY").length,
      "TESTCASE-FAIL": results.filter((r) => r.verdict === "TESTCASE-FAIL").length,
      "NO-TESTCASES": results.filter((r) => r.verdict === "NO-TESTCASES").length,
    },
    results,
  };

  if (options.out !== null) {
    const target = resolve(options.out);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, `${JSON.stringify(payload, null, 2)}\n`, "utf-8");
    process.stderr.write(`[draft-audit] wrote JSON -> ${options.out}\n`);
  }
  if (options.json) {
    process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
    printHuman(results, sampleCount, options.flip, (s) => process.stderr.write(`${s}\n`));
  } else {
    printHuman(results, sampleCount, options.flip, (s) => process.stdout.write(`${s}\n`));
  }
  return 0;
}

const INVOKED_DIRECTLY =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exitCode = code;
    })
    .catch((e: unknown) => {
      console.error(e instanceof Error ? e.stack : String(e));
      process.exitCode = 1;
    });
}

export { parseOptions, discoverDrafts, flipToExperimental, verdictOf, extractText };
