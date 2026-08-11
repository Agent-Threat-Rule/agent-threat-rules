#!/usr/bin/env node
/**
 * probe-rule-visibility.ts — answer "is this rule's 0 FP evidence, or is it
 * just untested?" before the rule is proposed.
 *
 * WHY THIS EXISTS
 *
 * A batch of five rules was authored, each measured at 0 FP over the 5.3K
 * in-repo benign corpus, and each was then broken at 20-57% FP by benign
 * samples a reviewer wrote by hand in a few minutes. The measurement was not
 * wrong — it was empty. The corpora contained `torsocks` zero times and
 * `.onion` zero times, so a Tor rule scored 0 FP by never being exercised.
 *
 * Zero false positives on a corpus that cannot see your rule is not a clean
 * result. It is an unrun test that reports success. This script refuses to let
 * that state go unnoticed, by checking three things a plain FP count does not:
 *
 *   1. CONTROL. The engine only matches after `loadRules()` — the constructor
 *      does not compile patterns, so a harness that skips the await returns
 *      zero matches for every input. Every run here re-fires the rule's own
 *      declared true_positives first and ABORTS if any of them misses. A zero
 *      that follows a failed control is reported as "not run", never "clean".
 *
 *   2. VISIBILITY. For each condition, the distinctive literal words inside the
 *      regex are counted across the benign corpora. A condition whose literals
 *      never appear was never exercised, and its 0 FP carries no information.
 *      This is reported per condition, not as one number for the rule, because
 *      one well-covered condition otherwise hides five blind ones.
 *
 *   3. TWINS. An optional file of hand-written benign samples aimed at this
 *      rule's family. The in-repo corpora are agent-tooling READMEs; they are
 *      not a sample of all legitimate English. A twin file is how a reviewer's
 *      counter-examples become a repeatable check instead of a one-off.
 *
 * WHAT IT IS NOT
 *
 * Not a CI gate and not a promotion gate — `gate-promotion-fp.ts` owns the
 * enforce-lane decision. This runs earlier, while the regex is still being
 * written, and its verdict is advisory except for the control failure.
 *
 * The literal extraction is a heuristic: it strips regex syntax and keeps
 * alphabetic runs of four or more characters. It can undercount a condition
 * built entirely from short words or character classes. It is a smoke alarm for
 * the blind-corpus failure, not a coverage proof.
 *
 * USAGE
 *   npx tsx scripts/probe-rule-visibility.ts rules/<cat>/<rule>.yaml
 *   npx tsx scripts/probe-rule-visibility.ts <rule.yaml> --twins <twins.json>
 *   npx tsx scripts/probe-rule-visibility.ts <rule.yaml> --json
 *
 * EXIT CODES
 *   0  control passed, every condition is visible, no twin false-positived
 *   1  a condition is blind, or a twin false-positived
 *   2  bad usage, unreadable rule, or unreadable corpus
 *   3  CONTROL FAILED — the engine is not matching; no result is meaningful
 */
import { readFileSync, readdirSync, existsSync, statSync, mkdtempSync, copyFileSync } from "node:fs";
import { join, resolve, dirname, basename } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { load as parseYaml } from "js-yaml";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent } from "../src/types.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Same three corpora the FP gate and the action-eligibility evidence use. */
const CORPORA: readonly string[] = Object.freeze([
  "data/skill-benchmark/benign",
  "data/benign-corpus-extended",
  "data/benign-code",
]);

/** A literal shorter than this is too common to say anything about coverage. */
const MIN_LITERAL_LEN = 4;

/** Regex keywords and flag names that survive syntax stripping but are not content. */
const REGEX_NOISE: ReadonlySet<string> = new Set(["true", "false", "null"]);

interface Sample {
  readonly label: string;
  readonly text: string;
}

/**
 * A condition is judged on how much of its own vocabulary the corpus contains,
 * not on its most common word. Reporting the maximum would rate a Tor rule
 * (`torsocks|\.onion|tor2web`) as covered on the strength of an incidental
 * `from`, which is the exact mistake this script exists to catch. Coverage is
 * the fraction of distinct literals that appear at least once.
 */
interface ConditionReport {
  readonly index: number;
  readonly description: string;
  readonly literals: readonly string[];
  readonly literalsSeen: number;
  /** literalsSeen / literals.length, or 1 when no literal could be extracted. */
  readonly coverage: number;
  /** The rarest literal that does appear — the closest thing to a real anchor. */
  readonly rarestSeen: string | null;
  readonly rarestSeenHits: number;
  /** Literals the corpus has never contained, most informative first. */
  readonly unseen: readonly string[];
  /** No literal appears at all: the condition was never exercised. */
  readonly blind: boolean;
  /** Most of the vocabulary is missing: the 0 FP is thin, not clean. */
  readonly thin: boolean;
}

/** Below this share of its own vocabulary, a condition's 0 FP is not evidence. */
const THIN_COVERAGE = 0.34;

function fail(msg: string, code: number): never {
  console.error(msg);
  process.exit(code);
}

function flag(name: string): string | null {
  const i = process.argv.indexOf(name);
  return i >= 0 ? (process.argv[i + 1] ?? null) : null;
}

function asTextEvent(content: string): AgentEvent {
  return {
    type: "mcp_exchange",
    timestamp: new Date().toISOString(),
    content,
    fields: {
      tool_name: "corpus-sample",
      tool_input: content,
      tool_response: content,
      user_input: content,
    },
  } as AgentEvent;
}

/** Mirrors gate-promotion-fp.ts loadCorpusTexts so counts stay comparable. */
function loadCorpusTexts(pathStr: string): string[] {
  const texts: string[] = [];
  if (!existsSync(pathStr)) return texts;
  const files: string[] = [];
  if (statSync(pathStr).isDirectory()) {
    for (const e of readdirSync(pathStr)) {
      if (e.endsWith(".jsonl") || e.endsWith(".md")) files.push(join(pathStr, e));
    }
  } else {
    files.push(pathStr);
  }
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

/**
 * Pull the content words out of a regex: drop escapes, classes, groups and
 * quantifiers, then keep alphabetic runs long enough to be distinctive.
 */
function literalsOf(pattern: string): string[] {
  const stripped = pattern
    .replace(/\(\?[imsux]*\)/g, " ")
    .replace(/\\[dDwWsSbBAZznrtfv]/g, " ")
    .replace(/\\[pP]\{[^}]*\}/g, " ")
    .replace(/\\u\{[^}]*\}/g, " ")
    .replace(/\[[^\]]*\]/g, " ")
    .replace(/\{\d*,?\d*\}/g, " ")
    .replace(/[()|?*+^$.\\/<>{}]/g, " ");
  const out = new Set<string>();
  for (const m of stripped.matchAll(/[A-Za-z]{2,}/g)) {
    const w = m[0].toLowerCase();
    if (w.length >= MIN_LITERAL_LEN && !REGEX_NOISE.has(w)) out.add(w);
  }
  return [...out];
}

function regexConditions(rule: unknown): { value: string; description: string }[] {
  const detection = (rule as { detection?: { conditions?: unknown } }).detection;
  const conds = detection?.conditions;
  if (!Array.isArray(conds)) return [];
  const out: { value: string; description: string }[] = [];
  for (const c of conds) {
    const cond = c as Record<string, unknown>;
    if (cond["operator"] === "regex" && typeof cond["value"] === "string") {
      out.push({
        value: cond["value"],
        description: typeof cond["description"] === "string" ? cond["description"] : "",
      });
    }
  }
  return out;
}

function readTwins(path: string): Sample[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf-8"));
  } catch (e) {
    fail(`cannot read twins file ${path}: ${e instanceof Error ? e.message : String(e)}`, 2);
  }
  const rows = Array.isArray(parsed)
    ? parsed
    : ((parsed as { benign_twins?: unknown }).benign_twins ?? null);
  if (!Array.isArray(rows)) {
    fail(`twins file ${path} must be an array, or an object with a benign_twins array`, 2);
  }
  return rows.map((r, i) => {
    const row = r as { label?: unknown; text?: unknown };
    if (typeof row.text !== "string" || row.text.length === 0) {
      fail(`twins file ${path}: entry ${i} has no text`, 2);
    }
    return { label: typeof row.label === "string" ? row.label : `twin#${i}`, text: row.text };
  });
}

async function main(): Promise<void> {
  const rulePath = process.argv[2];
  if (!rulePath || rulePath.startsWith("--")) {
    fail("usage: probe-rule-visibility.ts <rule.yaml> [--twins <file.json>] [--json]", 2);
  }
  const asJson = process.argv.includes("--json");
  const twinsPath = flag("--twins");
  const abs = resolve(rulePath);
  if (!existsSync(abs)) fail(`no such rule file: ${abs}`, 2);

  let rule: unknown;
  try {
    rule = parseYaml(readFileSync(abs, "utf-8"));
  } catch (e) {
    fail(`cannot parse ${abs}: ${e instanceof Error ? e.message : String(e)}`, 2);
  }
  const ruleId = (rule as { id?: string }).id;
  if (!ruleId) fail(`${abs} has no id`, 2);

  const conditions = regexConditions(rule);
  if (conditions.length === 0) {
    fail(`${ruleId} declares no array-format regex conditions — nothing to probe`, 2);
  }

  // Scope the engine to this one rule so hits cannot be attributed to a neighbour.
  const scoped = mkdtempSync(join(tmpdir(), "atr-probe-"));
  copyFileSync(abs, join(scoped, basename(abs)));
  const engine = new ATREngine({ rulesDir: scoped });
  const loaded = await engine.loadRules();
  if (loaded < 1) fail(`engine loaded ${loaded} rules from ${abs} — cannot probe`, 3);

  const hits = (text: string): boolean => {
    for (const m of engine.evaluate(asTextEvent(text))) if (m.rule.id === ruleId) return true;
    for (const m of engine.scanSkill(text)) if (m.rule.id === ruleId) return true;
    return false;
  };

  // ---- 1. CONTROL -------------------------------------------------------
  const tps = ((rule as { test_cases?: { true_positives?: { input?: string }[] } }).test_cases
    ?.true_positives ?? []) as { input?: string }[];
  const controlInputs = tps.map((t) => t.input).filter((s): s is string => typeof s === "string");
  if (controlInputs.length === 0) {
    fail(`CONTROL IMPOSSIBLE: ${ruleId} declares no true_positives. Without them a zero here cannot be distinguished from an engine that is not matching at all.`, 3);
  }
  const controlMisses = controlInputs.filter((s) => !hits(s));
  if (controlMisses.length > 0) {
    console.error(`CONTROL FAILED for ${ruleId}: ${controlMisses.length}/${controlInputs.length} declared true_positives did not fire.`);
    for (const m of controlMisses) console.error(`  miss: ${m.slice(0, 120)}`);
    fail("The engine is not matching this rule. Every count below would be 'not run', not 'clean'. Refusing to report.", 3);
  }

  // ---- 2. VISIBILITY ----------------------------------------------------
  const corpusTexts: string[] = [];
  for (const c of CORPORA) corpusTexts.push(...loadCorpusTexts(join(REPO_ROOT, c)));
  if (corpusTexts.length === 0) fail(`no benign corpus samples found under ${CORPORA.join(", ")}`, 2);
  const haystack = corpusTexts.join("\n").toLowerCase();

  const occurrences = (needle: string): number => {
    let n = 0;
    let from = 0;
    for (;;) {
      const at = haystack.indexOf(needle, from);
      if (at === -1) break;
      n++;
      from = at + needle.length;
    }
    return n;
  };

  const reports: ConditionReport[] = conditions.map((c, index) => {
    const literals = literalsOf(c.value);
    const counted = literals
      .map((lit) => ({ lit, n: occurrences(lit) }))
      .sort((a, b) => a.n - b.n);
    const seen = counted.filter((x) => x.n > 0);
    const unseen = counted.filter((x) => x.n === 0).map((x) => x.lit);
    const coverage = literals.length === 0 ? 1 : seen.length / literals.length;
    return {
      index,
      description: c.description,
      literals,
      literalsSeen: seen.length,
      coverage,
      rarestSeen: seen[0]?.lit ?? null,
      rarestSeenHits: seen[0]?.n ?? 0,
      unseen,
      blind: literals.length > 0 && seen.length === 0,
      thin: literals.length > 0 && seen.length > 0 && coverage < THIN_COVERAGE,
    };
  });

  // ---- 3. CORPUS FP + TWINS --------------------------------------------
  const corpusFp = corpusTexts.filter((t) => hits(t)).length;
  const twins = twinsPath ? readTwins(resolve(twinsPath)) : [];
  const twinFp = twins.filter((t) => hits(t.text));

  const blind = reports.filter((r) => r.blind);
  const thin = reports.filter((r) => r.thin);
  const ok = blind.length === 0 && thin.length === 0 && twinFp.length === 0;

  if (asJson) {
    console.log(JSON.stringify({ rule: ruleId, control: controlInputs.length, corpusSamples: corpusTexts.length, corpusFp, conditions: reports, twinSamples: twins.length, twinFp: twinFp.map((t) => t.label), ok }, null, 2));
    process.exit(ok ? 0 : 1);
  }

  console.log(`rule      ${ruleId}`);
  console.log(`control   OK — ${controlInputs.length}/${controlInputs.length} declared true_positives fire`);
  console.log(`corpus    ${corpusFp} FP / ${corpusTexts.length} benign samples`);
  console.log("");
  console.log("condition visibility (share of each condition's own vocabulary the corpus contains)");
  for (const r of reports) {
    const tag = r.blind ? "BLIND" : r.thin ? "THIN " : "seen ";
    const pct = r.literals.length === 0 ? "n/a" : `${r.literalsSeen}/${r.literals.length}`;
    const anchor = r.rarestSeen ? `rarest seen "${r.rarestSeen}" x${r.rarestSeenHits}` : "nothing seen";
    console.log(`  [${tag}] #${r.index} ${pct} literals · ${anchor}${r.description ? ` — ${r.description}` : ""}`);
    if (r.unseen.length > 0) {
      console.log(`          never in corpus: ${r.unseen.slice(0, 8).join(", ")}${r.unseen.length > 8 ? ` (+${r.unseen.length - 8})` : ""}`);
    }
  }
  if (blind.length > 0 || thin.length > 0) {
    console.log("");
    console.log(`BLIND means the corpus contains none of that condition's distinctive words;`);
    console.log(`THIN means under ${Math.round(THIN_COVERAGE * 100)}% of them appear. Either way the 0 FP is an unrun`);
    console.log(`test, not a clean result. Write benign samples containing those words and`);
    console.log(`re-run with --twins before proposing this rule.`);
  }
  if (twinsPath) {
    console.log("");
    console.log(`twins     ${twinFp.length} FP / ${twins.length} hand-written benign samples`);
    for (const t of twinFp) console.log(`  FP: ${t.label}`);
  }
  console.log("");
  console.log(ok ? "PASS — every condition is exercised by the corpus and no twin false-positived." : "FAIL — see above.");
  process.exit(ok ? 0 : 1);
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.stack : String(e));
  process.exit(2);
});
