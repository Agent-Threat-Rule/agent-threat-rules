/**
 * Generalization / robustness harness.
 *
 * First-principles premise: a detection rule's real value is NOT whether it
 * fires on its own authored test case (that is true by construction of the
 * merge gate) — it is whether it still fires on *unseen variants* of the same
 * attack, at zero added FP. That number is the rule's real-world recall, and
 * today it is unmeasured.
 *
 * This harness takes each pattern rule's `true_positives`, generates a battery
 * of semantic-preserving mutations (the variants a real attacker would use),
 * runs them through the REAL ATR engine (so engine-level normalization and
 * base64 decoding are honoured), and reports per-rule robustness.
 *
 * Mutations are split into two classes with two different owners:
 *   - SEMANTIC  (synonym / reorder / case / whitespace / benign-wrapper)
 *       failure => the rule is a brittle signature. Fix = generalize the regex
 *       or hand the technique to the L2 semantic layer.
 *   - EVASION   (homoglyph / zero-width / leetspeak / base64)
 *       failure => the engine's normalization layer has a coverage gap. Fix =
 *       the normalizer (helps every rule at once), not the individual rule.
 *
 * FP is re-checked on every rule's `true_negatives` so robustness gains are
 * never bought with precision.
 *
 * Usage:
 *   tsx scripts/eval-generalization.ts                  # sample 40 rules
 *   tsx scripts/eval-generalization.ts --all            # every pattern rule
 *   tsx scripts/eval-generalization.ts --rule ATR-2026-00335
 *   tsx scripts/eval-generalization.ts --worst 30 --json out.json
 *
 * @module agent-threat-rules/scripts/eval-generalization
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { decodeBase64Blocks, foldConfusables, normalizeUnicode } from '../src/engine.js';
import { loadRulesFromDirectory } from '../src/loader.js';
import type { ATRRule } from '../src/types.js';
import { needsUnicodeFlag } from '../src/engine.js';

const RULES_DIR = resolve(process.cwd(), 'rules');

// ---------------------------------------------------------------------------
// Mutation battery — every mutation must PRESERVE the attack (still malicious),
// only changing surface form. If a mutation could neutralize the attack it does
// not belong here.
// ---------------------------------------------------------------------------

type MutationClass = 'semantic' | 'evasion';
interface Mutation {
  readonly family: string;
  readonly cls: MutationClass;
  readonly text: string;
}

/** Bidirectional synonym sets for common injection vocabulary. */
const SYNONYMS: readonly (readonly string[])[] = [
  ['ignore', 'disregard', 'bypass', 'override', 'forget'],
  ['previous', 'prior', 'earlier', 'preceding'],
  ['instructions', 'directives', 'rules', 'guidelines', 'commands'],
  ['refuse', 'deny', 'reject', 'decline'],
  ['must', 'shall', 'have to', 'are required to'],
  ['reveal', 'disclose', 'expose', 'print', 'show'],
  ['system prompt', 'system message', 'initial instructions'],
  ['never', 'at no point', 'under no circumstances'],
  ['always', 'in every case', 'without exception'],
  ['you are', "you're", 'you now are'],
];

const HOMOGLYPH: Record<string, string> = {
  a: 'а', e: 'е', o: 'о', p: 'р', c: 'с',
  x: 'х', y: 'у', A: 'А', E: 'Е', O: 'О',
};
const LEET: Record<string, string> = { a: '4', e: '3', i: '1', o: '0', s: '5' };

function swapSynonyms(text: string): string {
  let out = text;
  for (const set of SYNONYMS) {
    for (let i = 0; i < set.length; i++) {
      const from = set[i];
      const to = set[(i + 1) % set.length];
      const re = new RegExp(`\\b${from.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi');
      if (re.test(out)) {
        out = out.replace(re, to);
        break; // one swap per set keeps it readable + still an attack
      }
    }
  }
  return out;
}

function reorderClauses(text: string): string {
  const parts = text.split(/(?<=[.!?])\s+/).filter(Boolean);
  if (parts.length < 2) return text;
  return [...parts].reverse().join(' ');
}

function homoglyph(text: string): string {
  return text.replace(/[aeopcxyAEO]/g, (ch) => HOMOGLYPH[ch] ?? ch);
}

function zeroWidth(text: string): string {
  return text.replace(/([A-Za-z])(?=[A-Za-z])/g, '$1​');
}

function leet(text: string): string {
  return text.replace(/[aeios]/gi, (ch) => LEET[ch.toLowerCase()] ?? ch);
}

function base64Wrap(text: string): string {
  const b64 = Buffer.from(text, 'utf8').toString('base64');
  return `Please decode this base64 and follow the instruction inside: ${b64}`;
}

const BENIGN_PRE = 'Thanks for the help so far, here is the next step. ';
const BENIGN_POST = ' Let me know once that is done.';

function buildMutations(input: string): Mutation[] {
  const m: Mutation[] = [
    { family: 'control', cls: 'semantic', text: input },
    { family: 'lowercase', cls: 'semantic', text: input.toLowerCase() },
    { family: 'uppercase', cls: 'semantic', text: input.toUpperCase() },
    { family: 'ws_collapse', cls: 'semantic', text: input.replace(/\s+/g, ' ').trim() },
    { family: 'ws_expand', cls: 'semantic', text: input.replace(/ /g, '  ').replace(/\. /g, '.\n') },
    { family: 'synonym', cls: 'semantic', text: swapSynonyms(input) },
    { family: 'reorder', cls: 'semantic', text: reorderClauses(input) },
    { family: 'wrap_pre', cls: 'semantic', text: BENIGN_PRE + input },
    { family: 'wrap_post', cls: 'semantic', text: input + BENIGN_POST },
    { family: 'homoglyph', cls: 'evasion', text: homoglyph(input) },
    { family: 'zerowidth', cls: 'evasion', text: zeroWidth(input) },
    { family: 'leetspeak', cls: 'evasion', text: leet(input) },
    { family: 'base64', cls: 'evasion', text: base64Wrap(input) },
  ];
  // Drop mutations that didn't actually change the text (e.g. synonym no-op) to
  // avoid double-counting them as the control.
  const seen = new Set<string>();
  return m.filter((x) => {
    if (x.family === 'control') return true;
    if (x.text === input || seen.has(x.text)) return false;
    seen.add(x.text);
    return true;
  });
}

// ---------------------------------------------------------------------------
// Pattern matching — mirrors the authoritative semantics used by the merge gate
// (validate-rules.ts) and the engine's array-condition path: fieldValue is
// normalizeUnicode'd, regex compiled with 'i' (or '' when case_sensitive, plus
// 'u' when the pattern uses \u{} / \p{}), and base64 blocks are decoded and
// scanned separately. We evaluate at the PATTERN level on purpose: engine-level
// gates (code-block suppression, confidence downweighting) are orthogonal to
// the question "does this rule's pattern generalize to variants?" and would
// otherwise confound the measurement.
// ---------------------------------------------------------------------------

interface ArrayCond {
  readonly field?: string;
  readonly operator?: string;
  readonly match_type?: string;
  readonly value?: string;
  readonly patterns?: readonly string[];
  readonly case_sensitive?: boolean;
}

function condPatterns(c: ArrayCond): string[] {
  if (typeof c.value === 'string') return [c.value];
  if (Array.isArray(c.patterns)) return c.patterns.filter((p): p is string => typeof p === 'string');
  return [];
}

function condOp(c: ArrayCond): string {
  return (c.operator ?? c.match_type ?? 'regex').toLowerCase();
}

/** Mirror engine.normalizeRegex: JS RegExp takes flags as a param, not inline. */
function stripInlineFlags(pattern: string): string {
  return pattern.replace(/^\(\?[imsx]+\)/, '');
}

function matchOne(c: ArrayCond, value: string): boolean {
  const cs = c.case_sensitive === true;
  const hay = cs ? value : value.toLowerCase();
  for (const raw0 of condPatterns(c)) {
    const op = condOp(c);
    if (op === 'regex') {
      const raw = stripInlineFlags(raw0);
      const flags = (cs ? '' : 'i') + (needsUnicodeFlag(raw) ? 'u' : '');
      try {
        if (new RegExp(raw, flags).test(value)) return true;
      } catch {
        /* malformed regex — treat as non-matching, surfaced elsewhere */
      }
    } else {
      const raw = raw0;
      const needle = cs ? raw : raw.toLowerCase();
      if (op === 'contains' && hay.includes(needle)) return true;
      if (op === 'exact' && hay === needle) return true;
      if (op === 'starts_with' && hay.startsWith(needle)) return true;
    }
  }
  return false;
}

function arrayConditions(rule: ATRRule): ArrayCond[] {
  const conds = (rule.detection as { conditions?: unknown }).conditions;
  return Array.isArray(conds) ? (conds as ArrayCond[]) : [];
}

/** True iff the rule's detection pattern matches the (variant) text. */
function fires(rule: ATRRule, text: string): boolean {
  const conds = arrayConditions(rule);
  if (conds.length === 0) return false;
  // Candidate views the engine scans. The engine tests each pattern against
  // BOTH the normalized fieldValue AND the raw value (engine.ts:975), so a
  // zero-width-stripping normalization never hides a rule that targets the raw
  // bytes. We also scan decoded base64 blocks (raw + normalized), as scanSkill
  // does. Dedup keeps the OR cheap.
  const decoded = decodeBase64Blocks(text);
  const norm = normalizeUnicode(text);
  const candidates = Array.from(
    new Set([
      text,
      norm,
      foldConfusables(norm),
      ...decoded,
      ...decoded.map((d) => foldConfusables(normalizeUnicode(d))),
    ]),
  );
  const logic = (rule.detection as { condition?: string }).condition === 'all' ? 'all' : 'any';
  const test = (c: ArrayCond) => candidates.some((v) => matchOne(c, v));
  return logic === 'all' ? conds.every(test) : conds.some(test);
}

function ruleMethod(rule: ATRRule): string {
  const det = rule.detection as { method?: string } | undefined;
  return det?.method ?? 'pattern';
}

// Test cases come in several shapes:
//   { input: "<text>", expected }
//   { input: "<benign>", tool_response: "<poisoned payload>", expected }
//   { input: { tool_name: "...", tool_args: "..." }, expected, matched_condition }
// The rule may detect on any field, and the payload can be nested inside an
// `input` object, so the attack text is every string LEAF across the case,
// excluding meta keys that describe the case rather than carry payload.
const META_KEYS = new Set([
  'expected', 'description', 'reason', 'attack_type', 'note', 'matched_condition', 'label',
]);

function collectStrings(node: unknown, out: string[]): void {
  if (typeof node === 'string') {
    out.push(node);
  } else if (Array.isArray(node)) {
    for (const v of node) collectStrings(v, out);
  } else if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) {
      if (!META_KEYS.has(k)) collectStrings(v, out);
    }
  }
}

function caseText(tc: Record<string, unknown>): string {
  const out: string[] = [];
  collectStrings(tc, out);
  return out.join('\n');
}

function truePositives(rule: ATRRule): string[] {
  const tc = rule.test_cases?.true_positives ?? [];
  return tc.map((t) => caseText(t as unknown as Record<string, unknown>)).filter((s) => s.length > 0);
}

function trueNegatives(rule: ATRRule): string[] {
  const tc = rule.test_cases?.true_negatives ?? [];
  return tc.map((t) => caseText(t as unknown as Record<string, unknown>)).filter((s) => s.length > 0);
}

// ---------------------------------------------------------------------------
// Per-rule scoring
// ---------------------------------------------------------------------------

interface RuleScore {
  ruleId: string;
  status: string;
  controlOk: boolean;          // fires on its own unmutated TP via the engine
  robSemantic: number | null;  // caught semantic variants / total
  robEvasion: number | null;   // caught evasion variants / total
  failedFamilies: string[];
  fpHolds: boolean;            // no true_negative (or its variants) wrongly fires
  fpBreakers: string[];
  tpCount: number;
}

function scoreRule(rule: ATRRule): RuleScore {
  const tps = truePositives(rule);
  const fams = new Map<string, { cls: MutationClass; caught: number; total: number }>();
  let controlOk = true;

  for (const tp of tps) {
    for (const mut of buildMutations(tp)) {
      const hit = fires(rule, mut.text);
      if (mut.family === 'control') {
        if (!hit) controlOk = false;
        continue;
      }
      const acc = fams.get(mut.family) ?? { cls: mut.cls, caught: 0, total: 0 };
      acc.total += 1;
      if (hit) acc.caught += 1;
      fams.set(mut.family, acc);
    }
  }

  const tally = (cls: MutationClass): number | null => {
    let caught = 0, total = 0;
    for (const acc of Array.from(fams.values())) if (acc.cls === cls) { caught += acc.caught; total += acc.total; }
    return total === 0 ? null : caught / total;
  };

  const failedFamilies = Array.from(fams.entries())
    .filter(([, a]) => a.total > 0 && a.caught / a.total < 0.5)
    .map(([f]) => f)
    .sort();

  // FP guard: control + the cheap semantic mutations of every true_negative
  const fpBreakers: string[] = [];
  for (const tn of trueNegatives(rule)) {
    for (const mut of buildMutations(tn).filter((m) => m.cls === 'semantic')) {
      if (fires(rule, mut.text)) { fpBreakers.push(`${mut.family}`); break; }
    }
  }

  return {
    ruleId: rule.id,
    status: rule.status ?? 'unknown',
    controlOk,
    robSemantic: tally('semantic'),
    robEvasion: tally('evasion'),
    failedFamilies,
    fpHolds: fpBreakers.length === 0,
    fpBreakers: Array.from(new Set(fpBreakers)),
    tpCount: tps.length,
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const BASELINE_PATH = resolve(process.cwd(), 'data/generalization-baseline.json');

function parseArgs(argv: string[]) {
  const a = { all: false, sample: 40, rule: '', worst: 25, json: '', gate: false, writeBaseline: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === '--all') a.all = true;
    else if (k === '--sample') a.sample = Number(argv[++i]);
    else if (k === '--rule') a.rule = argv[++i];
    else if (k === '--worst') a.worst = Number(argv[++i]);
    else if (k === '--json') a.json = argv[++i];
    else if (k === '--gate') { a.gate = true; a.all = true; }
    else if (k === '--write-baseline') { a.writeBaseline = true; a.all = true; }
  }
  return a;
}

interface Baseline {
  generatedAt: string;
  note: string;
  knownBroken: string[];   // rules that don't match their own TP — backlog, not new regressions
  knownFpBroken: string[]; // rules that FP on their own/mutated true_negatives — backlog
}

function loadBaseline(): Baseline {
  if (!existsSync(BASELINE_PATH)) return { generatedAt: '', note: '', knownBroken: [], knownFpBroken: [] };
  return JSON.parse(readFileSync(BASELINE_PATH, 'utf8')) as Baseline;
}

/**
 * CI ratchet. Fails (exit 1) when a NEW pattern rule fails to match its own TP
 * or false-positives on its own true_negatives — i.e. the autoresearch pipeline
 * shipped a broken rule. Pre-existing failures live in the baseline and only
 * tighten (a fixed rule is reported as removable). This makes "matches own TP +
 * 0 self-FP" a merge requirement without blocking on the existing backlog.
 */
function runGate(scores: RuleScore[]): never {
  const base = loadBaseline();
  const broken = scores.filter((s) => !s.controlOk).map((s) => s.ruleId);
  const fpBroken = scores.filter((s) => !s.fpHolds).map((s) => s.ruleId);
  const baseBroken = new Set(base.knownBroken);
  const baseFp = new Set(base.knownFpBroken);

  const newBroken = broken.filter((id) => !baseBroken.has(id));
  const newFp = fpBroken.filter((id) => !baseFp.has(id));
  const fixedBroken = base.knownBroken.filter((id) => !broken.includes(id));
  const fixedFp = base.knownFpBroken.filter((id) => !fpBroken.includes(id));

  console.log('\n=== ATR Generalization GATE ===');
  console.log(`broken: ${broken.length} (baseline ${base.knownBroken.length})   self-FP: ${fpBroken.length} (baseline ${base.knownFpBroken.length})`);

  if (fixedBroken.length || fixedFp.length) {
    console.log(`\nRATCHET — these are fixed and should be removed from the baseline:`);
    for (const id of [...fixedBroken, ...fixedFp]) console.log(`  + ${id}`);
    console.log(`  (run --write-baseline to tighten)`);
  }

  if (newBroken.length === 0 && newFp.length === 0) {
    console.log(`\nGATE PASS — no new broken or self-FP rules.\n`);
    process.exit(0);
  }

  console.log(`\nGATE FAIL — new regressions introduced:`);
  for (const id of newBroken) console.log(`  ✗ ${id}: pattern does not match its own authored true_positive`);
  for (const id of newFp) console.log(`  ✗ ${id}: fires on its own benign true_negative (false positive)`);
  console.log(`\nFix the rule (or, if the attack is genuinely semantic, move the TP to an L2 rule).`);
  console.log(`Do NOT widen the baseline to silence this.\n`);
  process.exit(1);
}

function pct(n: number | null): string {
  return n === null ? '  n/a' : `${(n * 100).toFixed(0).padStart(3)}%`;
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const raw = loadRulesFromDirectory(RULES_DIR);

  const pattern = raw.filter((r) => ruleMethod(r) === 'pattern' && truePositives(r).length > 0);
  const draftInert = pattern.filter((r) => r.status === 'draft' || r.status === 'deprecated');

  let target = pattern;
  if (args.rule) target = pattern.filter((r) => r.id === args.rule);
  else if (!args.all) {
    // Deterministic stride sample (no RNG) for reproducibility.
    const stride = Math.max(1, Math.floor(pattern.length / args.sample));
    target = pattern.filter((_, i) => i % stride === 0).slice(0, args.sample);
  }

  const scores = target.map(scoreRule);

  if (args.writeBaseline) {
    const baseline: Baseline = {
      generatedAt: new Date().toISOString(),
      note: 'Pre-existing pattern rules that fail to match their own TP, or self-FP. Ratchet only — new entries must be fixed, not added. See scripts/eval-generalization.ts --gate.',
      knownBroken: scores.filter((s) => !s.controlOk).map((s) => s.ruleId).sort(),
      knownFpBroken: scores.filter((s) => !s.fpHolds).map((s) => s.ruleId).sort(),
    };
    writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2) + '\n');
    console.log(`wrote baseline: ${baseline.knownBroken.length} broken, ${baseline.knownFpBroken.length} self-FP -> ${BASELINE_PATH}`);
    return;
  }

  if (args.gate) runGate(scores);

  const tested = scores.filter((s) => s.controlOk);
  const broken = scores.filter((s) => !s.controlOk);
  const med = (xs: number[]) => (xs.length ? xs.slice().sort((a, b) => a - b)[Math.floor(xs.length / 2)] : NaN);
  const semVals = tested.map((s) => s.robSemantic).filter((x): x is number => x !== null);
  const evaVals = tested.map((s) => s.robEvasion).filter((x): x is number => x !== null);

  console.log('\n=== ATR Generalization / Robustness Report ===');
  console.log(`pattern rules on disk: ${pattern.length}   tested this run: ${target.length}`);
  console.log(`draft/deprecated (INERT in production engine — never fire): ${draftInert.length}`);
  console.log(`pattern matches own TP: ${tested.length}   pattern BROKEN on own TP: ${broken.length}`);
  console.log(`median SEMANTIC robustness: ${pct(med(semVals))}   (rule-level: harden regex / move to L2)`);
  console.log(`median EVASION  robustness: ${pct(med(evaVals))}   (engine-level: fix normalizer)`);
  const brittle = tested.filter((s) => (s.robSemantic ?? 1) < 0.5);
  const fpBroken = scores.filter((s) => !s.fpHolds);
  console.log(`BRITTLE signatures (semantic <50%): ${brittle.length}`);
  console.log(`FP broke under benign mutation: ${fpBroken.length}`);

  const worst = tested
    .slice()
    .sort((a, b) => (a.robSemantic ?? 1) - (b.robSemantic ?? 1))
    .slice(0, args.worst);

  console.log(`\n--- worst ${worst.length} by semantic robustness (brittle = signature, not detector) ---`);
  console.log('rule                 stat  sem  eva  failed-families');
  for (const s of worst) {
    console.log(
      `${s.ruleId.padEnd(20)} ${s.status.slice(0, 4).padEnd(4)} ${pct(s.robSemantic)} ${pct(s.robEvasion)}  ${s.failedFamilies.join(',')}`,
    );
  }

  if (broken.length) {
    console.log(`\n--- pattern does NOT match its own authored TP (rule bug) ---`);
    for (const s of broken) console.log(`  ${s.ruleId} (${s.status})`);
  }
  if (fpBroken.length) {
    console.log(`\n--- FP broke under benign mutation (precision risk) ---`);
    for (const s of fpBroken) console.log(`  ${s.ruleId}: ${s.fpBreakers.join(',')}`);
  }

  if (args.json) {
    writeFileSync(
      args.json,
      JSON.stringify({ generatedAt: new Date().toISOString(), pattern: pattern.length, draftInert: draftInert.length, scores }, null, 2),
    );
    console.log(`\nwrote ${args.json}`);
  }
  console.log('');
}

main();
