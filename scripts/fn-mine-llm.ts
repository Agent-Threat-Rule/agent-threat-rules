#!/usr/bin/env node
/**
 * scripts/fn-mine-llm.ts
 *
 * Unattended false-negative mining: regenerates fresh FN reports against the
 * CURRENT rule set for the corpora ATR has committed fixtures for
 * (HackAPrompt, PINT), clusters the misses via Claude into generalizable
 * regex candidates, gates every candidate against the FULL FN set + FULL
 * benign corpus using the exact engine regex-compile semantics, authors
 * survivors as draft ATR rules, self-tests each on the real engine, and
 * re-verifies the whole batch against the repo's own safety gate before
 * handing off to the calling workflow to open a draft PR.
 *
 * This is the scheduled/unattended counterpart to the interactive /fn-mine
 * Claude Code workflow — same methodology (full-set clustering, engine-
 * accurate gate, one residual round), reimplemented as direct
 * @anthropic-ai/sdk calls (matching scripts/quality-upgrade.ts's pattern)
 * so it can run headless in GitHub Actions without a Claude Code session.
 *
 * Never merges anything. Drops (does not force-fix) any candidate that
 * fails self-test or the safety gate — an empty result is a valid, honest
 * outcome, not an error. A safety-gate failure it cannot attribute to its own
 * batch, a duplicate rule id on the branch, or an open-PR listing it cannot
 * read fails the run instead: those are not empty weeks.
 *
 * Usage:
 *   npx tsx scripts/fn-mine-llm.ts [--dry-run] [--cap 5] [--min-recovers 8]
 *
 * Environment:
 *   CLAUDE_CODE_OAUTH_TOKEN (preferred) or ANTHROPIC_API_KEY — see scripts/lib/claude-client.ts
 *   ATR_FNMINE_MODEL optional (default: claude-sonnet-5)
 *   FN_MINE_OPEN_PR_FILES optional: a file listing the paths open PRs touch, one
 *     per line (the workflow writes it, so this step needs no GitHub token).
 *     Unset, the miner asks `gh pr list` itself.
 */

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync, execSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import Anthropic from '@anthropic-ai/sdk';
import { needsUnicodeFlag } from '../src/engine.js';
import { callClaude as sharedCallClaude, describeBackend, backendAvailable } from './lib/claude-client.js';
import { coverageOf, successfulHackapromptMisses, describeNullResult, authoringRoom } from './lib/fn-mine-input.js';
import { gateAuthoredBatch } from './lib/fn-mine-gate.js';
import { assertSomeChunkRead, mineChunkReply, type ChunkResult, type MineCandidate } from './lib/fn-mine-reply.js';
import { finalizeAuthoredRule, isRuleCategory, re2Problem, visibilityProblem, withoutHackapromptGoal } from './lib/fn-mine-quality.js';
import { loadOwaspAllowlists, type OwaspAllowlists } from './lib/normalize-references.js';
import { prepareGateCorpus, type GateCorpus } from './lib/semantic-gate.js';
import { loadBenignSamples } from './lib/benign-corpus.js';
import { RULE_YAML_OPTIONS } from './lib/semantic-rule-builder.js';
import yaml from 'js-yaml';
import type { ATRCategory } from '../src/types.js';
import {
  readRuleFileIds,
  duplicateRuleIds,
  describeDuplicateRuleIds,
  usedRuleSeqs,
  nextRuleSeq,
  formatRuleId,
  type RuleFileId,
} from './lib/rule-ids.js';

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const REPO_ROOT = process.cwd();
const DEFAULT_MODEL = process.env['ATR_FNMINE_MODEL'] ?? 'claude-sonnet-5';
const MAX_TOKENS = 8192;
const CHUNK_SIZE = 300;
const RESIDUAL_THRESHOLD = 20; // below this many uncovered FN, skip round 2
const REFERENCE_RULE = 'rules/prompt-injection/ATR-2026-00003-jailbreak-attempt.yaml';
const REPORT_PATH = 'output/fn-mine-report.json';
const RULE_ID_YEAR = '2026';

interface CorpusSpec {
  readonly name: string;
  readonly corpusPath: string;
  readonly reportPath: string;
  readonly regenerate: readonly string[]; // shell commands to (re)build corpus + report
}

const CORPORA: readonly CorpusSpec[] = [
  {
    name: 'hackaprompt',
    corpusPath: 'data/hackaprompt/hackaprompt-corpus.json',
    reportPath: 'data/hackaprompt/hackaprompt-eval-report.json',
    regenerate: [
      'python3 scripts/hackaprompt-to-corpus.py --sample 5000',
      'npx tsx src/eval/run-hackaprompt-benchmark.ts',
    ],
  },
  {
    name: 'pint',
    corpusPath: 'data/pint-benchmark/pint-corpus.json',
    reportPath: 'data/pint-benchmark/pint-eval-report.json',
    regenerate: ['npx tsx src/eval/run-pint-benchmark.ts'],
  },
];

// ---------------------------------------------------------------------------
// Anthropic call plumbing (same pattern as scripts/quality-upgrade.ts)
// ---------------------------------------------------------------------------

/**
 * Route through the shared client so this lane spends subscription credit via
 * the local `claude` CLI when a CLAUDE_CODE_OAUTH_TOKEN is present, and only
 * falls back to the metered API key when it is not. See scripts/lib/claude-client.ts
 * for why: a metered balance running out is what killed this lane silently.
 */
async function callClaude(systemPrompt: string, userPrompt: string, model: string): Promise<string> {
  return sharedCallClaude(systemPrompt, userPrompt, model, MAX_TOKENS);
}

// ---------------------------------------------------------------------------
// Engine-accurate regex gate (mirrors src/engine.ts's normalizeRegex + the
// auto 'iu' flag rule EXACTLY — see compilePatterns() in src/engine.ts).
// ---------------------------------------------------------------------------

function normalizeRegex(pattern: string): string {
  return pattern.replace(/^\(\?[imsx]+\)/, '');
}

function compileEngineAccurate(value: string): RegExp | null {
  const pattern = normalizeRegex(value);
  const flags = needsUnicodeFlag(pattern) ? 'iu' : 'i';
  try {
    return new RegExp(pattern, flags);
  } catch {
    return null;
  }
}

function loadBenignTexts(): readonly string[] {
  const dir = path.join(REPO_ROOT, 'data/benign-corpus-extended');
  const out: string[] = [];
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith('.jsonl')) continue;
    for (const line of fs.readFileSync(path.join(dir, f), 'utf8').split('\n')) {
      if (!line.trim()) continue;
      try {
        const rec = JSON.parse(line);
        out.push(typeof rec === 'string' ? rec : (rec.text ?? rec.content ?? ''));
      } catch {
        // skip malformed line
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// FN loading
// ---------------------------------------------------------------------------

interface FnCorpus {
  readonly name: string;
  readonly texts: readonly string[];
}

function loadHackapromptFn(spec: CorpusSpec): readonly string[] {
  const corpus = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, spec.corpusPath), 'utf8'));
  const report = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, spec.reportPath), 'utf8'));
  const { texts, missed, droppedUnsuccessful } = successfulHackapromptMisses(corpus, report);
  console.log(
    `[fn-mine] hackaprompt: ${missed} missed, ${droppedUnsuccessful} of them failed in the competition ` +
      `(correct=false) and are not mined, ${texts.length} successful submissions remain`,
  );
  return texts;
}

function loadPintFn(spec: CorpusSpec): readonly string[] {
  const corpus = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, spec.corpusPath), 'utf8')) as Array<{ text: string }>;
  const report = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, spec.reportPath), 'utf8'));
  const missed = (report.report?.missedAttacks ?? report.missedAttacks ?? []) as Array<{ id: string }>;
  return missed
    .map((m) => {
      const idx = parseInt(m.id.split('-')[1] ?? '', 10) - 1;
      return corpus[idx]?.text;
    })
    .filter((t): t is string => Boolean(t));
}

function loadFnCorpus(spec: CorpusSpec): FnCorpus {
  const texts = spec.name === 'hackaprompt' ? loadHackapromptFn(spec) : loadPintFn(spec);
  return { name: spec.name, texts };
}

// ---------------------------------------------------------------------------
// Mining (Claude clusters a chunk of FN texts into candidate regexes)
// ---------------------------------------------------------------------------

const MINE_SYSTEM_PROMPT = `You are a senior detection engineer mining false negatives (real attacks an existing detection engine MISSED) into generalizable regex rules for ATR (Agent Threat Rules), an open detection standard.

RIGOR — reject your own candidate if it violates these:
- The regex must capture the attack CLASS (the injection technique/structure), NOT a literal payload. It must plausibly match unseen variants, not just the exact strings you were shown.
- Encode the actual injection signal — never a bare benign verb alone.
- Use (?i) as a leading inline flag for case-insensitivity (the engine strips this prefix and reapplies it as a real regex flag — this is the house convention).
- For emoji/astral codepoints write the LITERAL character, not an escape. \\u{XXXX} is JavaScript-only and does not compile in the Python or Go channels; \\UXXXXXXXX is Python-only and a no-op in JS. The literal is the one spelling all three accept, and the engine adds the 'u' flag when it sees one.
- NEVER an unbounded .* — use bounded [\\s\\S]{0,N} spans instead.
- Add \\b word boundaries around bare keyword tokens.
- HackAPrompt submissions all try to make the model say "I have been PWNED". That sentence is the competition's goal, not an attack technique: real attackers never send it. Never anchor a regex on "I have been", "PWNED" or its spellings; capture how the text gets the model to comply. The gate counts recoveries with that sentence removed.
- You are NOT given the benign corpus or the full FN set — you cannot know true recovers/benignFP. Propose your honest best candidates; an independent script will gate them empirically and only survivors move forward. Over-proposing plausible-looking candidates that get rejected is fine; under-proposing is not.

OUTPUT FORMAT: pure JSON, no markdown fences, no prose before or after. First character must be {. Schema:
{
  "candidates": [
    {
      "cluster": "short-kebab-technique-name",
      "regex": "the exact regex source (JS re syntax, with leading (?i) if case-insensitive)",
      "category": "one of: agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning",
      "rationale": "one sentence: what technique this captures and why it generalizes"
    }
  ]
}
If nothing in this slice yields a generalizable candidate, use an empty array — that is an honest, valid result.`;

function buildMinePrompt(chunkLabel: string, texts: readonly string[]): string {
  const numbered = texts.map((t, i) => `[${i}] ${t.slice(0, 300).replace(/\n/g, '\\n')}`).join('\n');
  return `CORPUS SLICE: ${chunkLabel} (${texts.length} false-negative attack texts — the detection engine currently misses ALL of these)

Cluster these by shared attack STRUCTURE (the injection mechanism/technique), not surface topic. For each sizable cluster, propose ONE generalizable regex per the rules in your system prompt.

FALSE-NEGATIVE TEXTS:
${numbered}`;
}

/** One chunk's candidates. An unreadable reply is asked for once more, then the chunk is skipped (see fn-mine-reply.ts). */
async function mineChunk(chunkLabel: string, texts: readonly string[], model: string): Promise<ChunkResult> {
  return mineChunkReply(
    chunkLabel,
    () => callClaude(MINE_SYSTEM_PROMPT, buildMinePrompt(chunkLabel, texts), model),
    (line) => console.log(`::warning::[fn-mine] ${line}`),
  );
}

// ---------------------------------------------------------------------------
// Gate — engine-accurate recovers/benignFP over the FULL sets
// ---------------------------------------------------------------------------

interface GatedCandidate extends MineCandidate {
  recovers: number;
  benignFP: number;
  exampleFNs: string[];
}

interface GateContext {
  /** The texts recoveries are counted on: the FN texts, HackAPrompt's with its goal sentence removed. */
  readonly measureOn: readonly string[];
  /** MEASUREMENT_CORPORA, for the corpus visibility gate's arithmetic. */
  readonly corpus: GateCorpus;
}

function gateCandidates(
  candidates: readonly MineCandidate[],
  fullFn: readonly string[],
  benignTexts: readonly string[],
  minRecovers: number,
  gate: GateContext,
): GatedCandidate[] {
  const survivors: GatedCandidate[] = [];
  const drop = (c: MineCandidate, why: string) => console.log(`[fn-mine]   drop ${c.cluster}: ${why}`);
  for (const c of candidates) {
    if (!isRuleCategory(c.category)) { drop(c, `unknown category ${JSON.stringify(c.category)}`); continue; }
    const re = compileEngineAccurate(c.regex);
    if (!re) continue; // invalid-after-engine-normalize — drop silently, logged by caller if desired
    // The PR's RE2 portability gate compiles every regex with Go's regexp.
    const re2 = re2Problem(c.regex);
    if (re2) { drop(c, re2); continue; }
    // Counted on measureOn, so a regex that only recovers HackAPrompt's goal
    // sentence recovers nothing. Examples stay the real, unmodified texts.
    let recovers = 0;
    const examples: string[] = [];
    gate.measureOn.forEach((m, i) => {
      if (!re.test(m)) return;
      recovers++;
      const original = fullFn[i] ?? m;
      if (examples.length < 5 && re.test(original)) examples.push(original);
    });
    if (recovers < minRecovers) {
      if (gate.measureOn !== fullFn && fullFn.filter((t) => re.test(t)).length >= minRecovers) {
        drop(c, `recovers ${recovers} < ${minRecovers} without HackAPrompt's goal sentence: it keys on "I have been PWNED"`);
      }
      continue;
    }
    if (examples.length === 0) continue;
    const visibility = visibilityProblem(c.regex, gate.corpus);
    if (visibility) { drop(c, visibility); continue; }
    let benignFP = 0;
    for (const t of benignTexts) {
      if (t && re.test(t)) { benignFP++; if (benignFP > 0) break; } // any hit is disqualifying
    }
    if (benignFP > 0) continue;
    survivors.push({ ...c, recovers, benignFP: 0, exampleFNs: examples });
  }
  return survivors;
}

function computeResidual(fullFn: readonly string[], survivors: readonly GatedCandidate[]): string[] {
  const compiled = survivors.map((s) => compileEngineAccurate(s.regex)).filter((r): r is RegExp => r !== null);
  return fullFn.filter((t) => !compiled.some((re) => re.test(t)));
}

// ---------------------------------------------------------------------------
// Authoring (Claude writes the full ATR rule YAML for a gated survivor)
// ---------------------------------------------------------------------------

function buildAuthorSystemPrompt(referenceYaml: string): string {
  return `You are authoring ONE payload-grounded ATR detection rule YAML file. NEVER mention PanGuard anywhere in the output.

Copy this reference rule's structure EXACTLY (field order; references block with owasp_llm/owasp_agentic/mitre_atlas/mitre_attack; compliance block with ALL THREE of eu_ai_act/nist_ai_rmf/iso_42001; metadata_provenance; tags; agent_source; detection; response; confidence; test_cases), except wild_fp_rate (see below):

--- REFERENCE RULE ---
${referenceYaml}
--- END REFERENCE ---

Requirements:
- detection.conditions must include EXACTLY the given gated regex verbatim (field: content, operator: regex) — do not alter it.
- test_cases.true_positives: 2-3 of the given real FN attack texts (truncate to ~180 chars, escape for YAML double-quoted strings).
- test_cases.true_negatives: 3-4 benign texts you write that do NOT match the given regex (verify mentally before including).
- references use REAL valid ids: owasp_llm and owasp_agentic as BARE ids, no title (e.g. "LLM01:2025", "ASI01:2026"; pick ones fitting the technique); mitre_atlas e.g. "AML.T0051 - LLM Prompt Injection" or "AML.T0054 - LLM Jailbreak".
- compliance: use this exact gate-passing shape, parameterized to the technique:
  eu_ai_act: article 15 (primary) + article 9 (secondary)
  nist_ai_rmf: subcategory MP.5.1 (primary) + MG.3.2 (secondary)
  iso_42001: clause 8.1 (primary) + clause 8.3 (secondary)
- status: experimental, maturity: test, author: "ATR Community", severity: high. (draft rules are never evaluated by the engine.)
- Do NOT include wild_fp_rate, even though the reference rule has one: it records a measurement in the wild, and this rule has had none.

OUTPUT FORMAT: pure YAML, no markdown fences, no prose before or after. The output must be a single complete, valid YAML document.`;
}

function buildAuthorUserPrompt(id: string, c: GatedCandidate): string {
  return `id: ${id}
category: ${c.category}
technique/cluster: ${c.cluster}
rationale: ${c.rationale}
GATED REGEX (engine-verified recovers=${c.recovers}, benignFP=0 — use EXACTLY as given): ${JSON.stringify(c.regex)}

Real false-negative attack texts this rule must fire on (use 2-3 as true_positives):
${c.exampleFNs.map((t, i) => `${i + 1}. ${t.slice(0, 200)}`).join('\n')}`;
}

async function authorRule(id: string, c: GatedCandidate, referenceYaml: string, model: string, correctionNote?: string): Promise<string> {
  const system = buildAuthorSystemPrompt(referenceYaml);
  const user = buildAuthorUserPrompt(id, c) + (correctionNote ? `\n\nPREVIOUS ATTEMPT FAILED: ${correctionNote}\nFix this specific issue and output the complete corrected YAML.` : '');
  const raw = await callClaude(system, user, model);
  return raw.trim().replace(/^```(?:yaml)?\s*\n?/i, '').replace(/\n?```\s*$/i, '');
}

function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48);
}

/**
 * Write the model's rule as the PR's checks require it (finalizeAuthoredRule:
 * status, wild_fp_rate, OWASP ids). Returns why it could not, for the
 * corrective retry, or null once written.
 */
function writeAuthoredRule(fullPath: string, text: string, category: ATRCategory, allowlists: OwaspAllowlists): string | null {
  let doc: unknown;
  try {
    doc = yaml.load(text);
  } catch (e) {
    return `the output is not valid YAML: ${e instanceof Error ? e.message : String(e)}`;
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return 'the output is not a single YAML mapping';
  fs.writeFileSync(fullPath, yaml.dump(finalizeAuthoredRule(doc as Record<string, unknown>, category, allowlists), RULE_YAML_OPTIONS));
  return null;
}

/** Runs `node dist/cli.js test <file>`; returns null on success, failure text otherwise. */
function selfTest(filePath: string): string | null {
  try {
    const out = execSync(`node dist/cli.js test ${JSON.stringify(filePath)}`, { cwd: REPO_ROOT, encoding: 'utf8' });
    if (/All tests passed/.test(out)) return null;
    return out.slice(-1500);
  } catch (e) {
    const out = e instanceof Error && 'stdout' in e ? String((e as { stdout?: unknown }).stdout ?? '') : '';
    return (out || String(e)).slice(-1500);
  }
}

// ---------------------------------------------------------------------------
// Safety-gate integration (repo's own 65K-benign / cross-rule-conflict gate)
// ---------------------------------------------------------------------------

interface SafetyGateResult {
  pass: boolean;
  failedFiles: string[];
  raw: string;
}

function runSafetyGate(): SafetyGateResult {
  let raw = '';
  let pass = false;
  try {
    raw = execSync('npx tsx scripts/check-rules-safety.ts --base origin/main', { cwd: REPO_ROOT, encoding: 'utf8' });
    pass = /PASS —/.test(raw);
  } catch (e) {
    raw = e instanceof Error && 'stdout' in e ? String((e as { stdout?: unknown }).stdout ?? '') : String(e);
    pass = false;
  }
  const failedFiles: string[] = [];
  const re = /✗\s+(rules\/\S+\.yaml)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(raw)) !== null) failedFiles.push(m[1]);
  return { pass, failedFiles, raw };
}

/**
 * Gate this run's authored rules, dropping the ones a failure blames — including
 * a rule whose TN a waiting rule in the rolling PR matches, which the gate files
 * under the waiting rule. Throws when a failure names nothing this run authored.
 */
function gateAuthored(authored: readonly AuthoredRule[]): readonly AuthoredRule[] {
  return gateAuthoredBatch(authored, runSafetyGate, (rule, blamedBy) => {
    console.log(`[fn-mine]   safety-gate rejected ${rule.id} — dropping: ${blamedBy.join(' | ')}`);
    fs.rmSync(path.join(REPO_ROOT, rule.file), { force: true });
  });
}

// ---------------------------------------------------------------------------
// Rule ids
// ---------------------------------------------------------------------------

/** A branch holding a duplicate id can never pass validate-rules; adding to it wastes the run. */
function assertNoDuplicateRuleIds(onDisk: readonly RuleFileId[]): void {
  const dups = duplicateRuleIds(onDisk);
  if (dups.size > 0) throw new Error(`${describeDuplicateRuleIds(dups)} Nothing was mined.`);
}

/**
 * Paths open PRs touch. Another lane's rolling PR allocates from its own branch
 * and holds ids main lacks; allocating without them collides when either merges.
 * Unreadable is an error, not an empty list: an empty list is how they collided.
 */
function openPrRuleFiles(): readonly string[] {
  const listed = process.env['FN_MINE_OPEN_PR_FILES'];
  const read = (): string =>
    listed
      ? fs.readFileSync(listed, 'utf8')
      : execFileSync('gh', ['pr', 'list', '--state', 'open', '--limit', '1000', '--json', 'files', '--jq', '.[].files[].path'], {
          cwd: REPO_ROOT,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
        });
  try {
    return read().split('\n').map((l) => l.trim()).filter(Boolean);
  } catch (e) {
    const source = listed ? `FN_MINE_OPEN_PR_FILES (${listed})` : '`gh pr list`';
    throw new Error(
      `could not read the rule files open PRs hold from ${source}: ${e instanceof Error ? e.message : String(e)}. ` +
        'Ids allocated without them collide with other lanes; nothing was mined.',
    );
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

/** Rule files this branch adds over origin/main — the rolling PR's waiting rules. */
function pendingNewRuleFiles(): number {
  const out = execSync('git diff --name-only --diff-filter=A origin/main -- rules/', { cwd: REPO_ROOT, encoding: 'utf8' });
  return out.split('\n').filter((f) => /\.ya?ml$/.test(f)).length;
}

function writeNullReport(note: string): void {
  fs.mkdirSync(path.dirname(path.join(REPO_ROOT, REPORT_PATH)), { recursive: true });
  fs.writeFileSync(path.join(REPO_ROOT, REPORT_PATH), JSON.stringify({ authored: [], note }, null, 2));
}

interface AuthoredRule {
  id: string;
  file: string;
  cluster: string;
  recovers: number;
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      'dry-run': { type: 'boolean', default: false },
      cap: { type: 'string', default: '5' },
      'min-recovers': { type: 'string', default: '8' },
      model: { type: 'string', default: DEFAULT_MODEL },
    },
  });
  const cap = parseInt(values.cap as string, 10);
  const minRecovers = parseInt(values['min-recovers'] as string, 10);
  const model = values.model as string;
  const isDryRun = values['dry-run'] as boolean;

  console.log(`[fn-mine] model=${model} cap=${cap} minRecovers=${minRecovers} dryRun=${isDryRun}`);

  // After the resume merged main in: a waiting rule whose id main took since
  // (another lane merged first) makes the rolling PR unmergeable. Say so here,
  // by file, rather than keep stacking rules onto it.
  assertNoDuplicateRuleIds(readRuleFileIds(REPO_ROOT, 'rules'));

  const perPrLimit = Number(process.env['MAX_NEW_PER_PR'] ?? '10');
  const pending = pendingNewRuleFiles();
  const room = authoringRoom(cap, pending, perPrLimit);
  if (room === 0) {
    const note =
      `NULL RESULT — this branch already adds ${pending} rule file(s) over main and the per-PR limit is ${perPrLimit}. ` +
      'Merge the rolling PR, or close it (the next run then starts fresh from main); nothing is mined until there is room.';
    console.log(`[fn-mine] ${note}`);
    writeNullReport(note);
    console.log('::authored-files::');
    return;
  }
  if (room < cap) console.log(`[fn-mine] ${pending} rule(s) already wait in this branch; authoring at most ${room} this run.`);

  // Read before spending model credit; a dry run allocates no ids.
  const openPrFiles = isDryRun ? [] : openPrRuleFiles();

  // The safety gate below re-checks every rule this branch adds over main, so a
  // waiting rule that now fails it (a stricter gate, a grown benign corpus, an
  // edit in review) would make the gate reject this run's batch without naming
  // any of it. Stop before spending model credit, and name the file.
  if (pending > 0) {
    const pre = runSafetyGate();
    if (!pre.pass) {
      const named = pre.failedFiles.length > 0 ? pre.failedFiles.join(', ') : '(the gate named no file; see its output)';
      throw new Error(
        `rule(s) already waiting in this branch fail check-rules-safety against current main: ${named}. ` +
          `Fix or remove them in the rolling PR; nothing was mined.\n${pre.raw.slice(-2000)}`,
      );
    }
  }

  console.log('[fn-mine] regenerating FN reports against the current rule set...');
  // Per-corpus fault tolerance: an external dependency failing for ONE corpus
  // (e.g. HackAPrompt's upstream HuggingFace dataset requiring auth) must not
  // crash the whole run — the OTHER corpora should still get mined. A corpus
  // that fails to regenerate is skipped for this run and logged loudly, not
  // silently — this is exactly the kind of failure `set -o pipefail` in the
  // calling workflow is there to make visible if left unhandled.
  const availableCorpora: CorpusSpec[] = [];
  for (const spec of CORPORA) {
    try {
      for (const cmd of spec.regenerate) {
        console.log(`[fn-mine]   $ ${cmd}`);
        execSync(cmd, { cwd: REPO_ROOT, stdio: 'inherit' });
      }
      availableCorpora.push(spec);
    } catch (e) {
      console.log(`[fn-mine] WARNING: ${spec.name} corpus regeneration failed — skipping this corpus for this run.`);
      console.log(`[fn-mine]   ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  if (availableCorpora.length === 0) {
    throw new Error('Every corpus failed to regenerate — nothing to mine. See warnings above for per-corpus failure reasons.');
  }

  const benignTexts = loadBenignTexts();
  console.log(`[fn-mine] benign gate corpus: ${benignTexts.length} records`);
  const gateCorpus = prepareGateCorpus(loadBenignSamples(REPO_ROOT));
  if (gateCorpus.samples.length === 0) throw new Error('MEASUREMENT_CORPORA is empty: the visibility check would pass every candidate');

  const stages = { fnTotal: 0, uncovered: 0, proposed: 0, survived: 0 };
  const replies = { asked: 0, unread: 0 };
  let allSurvivors: Array<GatedCandidate & { corpus: string }> = [];
  for (const spec of availableCorpora) {
    const fnRaw = loadFnCorpus(spec);
    // Coverage is judged by the eval harness over every rule on disk, drafts
    // included, with canaries; a broken judgement throws and fails the run.
    const cov = await coverageOf(fnRaw.texts, path.join(REPO_ROOT, 'rules'));
    const fn = { name: fnRaw.name, texts: [...cov.uncovered] };
    stages.fnTotal += fnRaw.texts.length;
    stages.uncovered += fn.texts.length;
    console.log(
      `[fn-mine] ${spec.name}: ${fnRaw.texts.length} false negatives against the LIVE engine, ` +
      `${cov.coveredCount} already covered by a rule on disk (${cov.draftsEvaluated} drafts evaluated), ` +
      `${fn.texts.length} genuinely un-mined`,
    );
    if (fn.texts.length === 0) continue;

    // Round 1: chunked mining over the FULL FN set.
    const chunks: string[][] = [];
    for (let start = 0; start < fn.texts.length; start += CHUNK_SIZE) {
      chunks.push(fn.texts.slice(start, start + CHUNK_SIZE));
    }
    let round1Candidates: MineCandidate[] = [];
    for (let i = 0; i < chunks.length; i++) {
      const label = `${spec.name}[${i * CHUNK_SIZE}:${i * CHUNK_SIZE + chunks[i].length}]`;
      console.log(`[fn-mine]   mining ${label}...`);
      const chunk = await mineChunk(label, chunks[i], model);
      replies.asked += 1;
      if (!chunk.read) replies.unread += 1;
      round1Candidates.push(...chunk.candidates);
    }
    const gate: GateContext = {
      measureOn: spec.name === 'hackaprompt' ? fn.texts.map(withoutHackapromptGoal) : fn.texts,
      corpus: gateCorpus,
    };
    const round1Survivors = gateCandidates(round1Candidates, fn.texts, benignTexts, minRecovers, gate);
    stages.proposed += round1Candidates.length;
    console.log(`[fn-mine] ${spec.name} round 1: ${round1Candidates.length} proposed -> ${round1Survivors.length} survive the gate`);

    // Round 2: residual (only what round 1 left uncovered).
    const residual = computeResidual(fn.texts, round1Survivors);
    let round2Survivors: GatedCandidate[] = [];
    if (residual.length >= RESIDUAL_THRESHOLD) {
      console.log(`[fn-mine] ${spec.name}: ${residual.length} FN still uncovered -> mining residual`);
      const rChunks: string[][] = [];
      for (let start = 0; start < residual.length; start += CHUNK_SIZE) {
        rChunks.push(residual.slice(start, start + CHUNK_SIZE));
      }
      let round2Candidates: MineCandidate[] = [];
      for (let i = 0; i < rChunks.length; i++) {
        const label = `${spec.name}-residual[${i * CHUNK_SIZE}:${i * CHUNK_SIZE + rChunks[i].length}]`;
        console.log(`[fn-mine]   mining ${label}...`);
        const chunk = await mineChunk(label, rChunks[i], model);
        replies.asked += 1;
        if (!chunk.read) replies.unread += 1;
        round2Candidates.push(...chunk.candidates);
      }
      round2Survivors = gateCandidates(round2Candidates, fn.texts, benignTexts, minRecovers, gate);
      stages.proposed += round2Candidates.length;
      console.log(`[fn-mine] ${spec.name} round 2 (residual): ${round2Candidates.length} proposed -> ${round2Survivors.length} survive`);
    } else {
      console.log(`[fn-mine] ${spec.name}: only ${residual.length} FN uncovered — below residual threshold (${RESIDUAL_THRESHOLD}), skipping round 2`);
    }

    for (const s of [...round1Survivors, ...round2Survivors]) allSurvivors.push({ ...s, corpus: spec.name });
  }

  // Every reply unreadable is a lane that could not run, not an empty week.
  assertSomeChunkRead(replies.asked, replies.unread);
  if (replies.unread > 0) {
    console.log(`::warning::[fn-mine] ${replies.unread} of ${replies.asked} chunk(s) skipped: their replies could not be read as JSON.`);
  }

  // Dedup by exact regex, rank by recovers, cap.
  const seen = new Set<string>();
  allSurvivors = allSurvivors
    .filter((s) => { const k = s.regex.trim(); if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => b.recovers - a.recovers);
  const picked = allSurvivors.slice(0, room);
  const deferred = allSurvivors.length - picked.length;
  console.log(`[fn-mine] total survivors: ${allSurvivors.length}. Authoring top ${picked.length}${deferred > 0 ? ` (deferring ${deferred} to next run)` : ''}.`);

  if (picked.length === 0) {
    const note = describeNullResult({ ...stages, survived: allSurvivors.length });
    console.log(`[fn-mine] ${note} Not an error.`);
    writeNullReport(note);
    console.log('::authored-files::');
    return;
  }

  if (isDryRun) {
    console.log('[fn-mine] --dry-run: stopping before authoring. Survivors:');
    console.log(JSON.stringify(picked, null, 2));
    console.log(`[fn-mine] NULL RESULT — --dry-run: ${picked.length} survivor(s) found, authoring skipped.`);
    console.log('::authored-files::');
    return;
  }

  // Next free id past everything on disk (main + the rolling PR) AND every rule
  // file an open PR touches — the other rolling lane allocates from its own branch.
  let nextId = nextRuleSeq(usedRuleSeqs(readRuleFileIds(REPO_ROOT, 'rules'), openPrFiles, RULE_ID_YEAR));

  const referenceYaml = fs.readFileSync(path.join(REPO_ROOT, REFERENCE_RULE), 'utf8');
  const allowlists = loadOwaspAllowlists(REPO_ROOT);
  const authored: AuthoredRule[] = [];

  for (const c of picked) {
    const id = formatRuleId(RULE_ID_YEAR, nextId);
    nextId++;
    const slug = slugify(c.cluster);
    const file = `rules/${c.category}/${id}-${slug}.yaml`;
    const fullPath = path.join(REPO_ROOT, file);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });

    console.log(`[fn-mine] authoring ${id} (${c.cluster}, recovers=${c.recovers})...`);
    const category = c.category as ATRCategory; // checked by isRuleCategory in the gate
    let failure =
      writeAuthoredRule(fullPath, await authorRule(id, c, referenceYaml, model), category, allowlists) ?? selfTest(file);
    if (failure) {
      console.log(`[fn-mine]   self-test failed, one corrective retry for ${id}...`);
      failure =
        writeAuthoredRule(fullPath, await authorRule(id, c, referenceYaml, model, failure), category, allowlists) ??
        selfTest(file);
    }
    if (failure) {
      console.log(`[fn-mine]   DROPPING ${id} — self-test still failing after retry:\n${failure}`);
      fs.rmSync(fullPath, { force: true });
      continue;
    }
    authored.push({ id, file, cluster: c.cluster, recovers: c.recovers });
  }

  if (authored.length === 0) {
    console.log('[fn-mine] NULL RESULT — every candidate failed self-test even after retry. Not an error.');
    console.log('::authored-files::');
    return;
  }

  // Repo-standard gates. Regenerate crosswalk docs first (a rule change always
  // makes them stale), then the safety gate. Anything the gate rejects is
  // DROPPED (not force-fixed) and the gate re-run on the remainder until it
  // passes — matches the "quality over volume" norm. A failure that names
  // nothing this run authored fails the run (see scripts/lib/fn-mine-gate.ts).
  execSync('npm run build', { cwd: REPO_ROOT, stdio: 'inherit' });
  execSync('python3 scripts/generate-attack-crosswalk.py', { cwd: REPO_ROOT, stdio: 'inherit' });
  execSync('python3 scripts/generate-ast-crosswalk.py', { cwd: REPO_ROOT, stdio: 'inherit' });

  const kept = gateAuthored(authored);

  if (kept.length === 0) {
    console.log('[fn-mine] NULL RESULT after safety-gate — the gate rejected every authored rule (reasons above). Not an error.');
    console.log('::authored-files::');
    return;
  }
  if (kept.length < authored.length) {
    execSync('python3 scripts/generate-attack-crosswalk.py', { cwd: REPO_ROOT, stdio: 'inherit' });
    execSync('python3 scripts/generate-ast-crosswalk.py', { cwd: REPO_ROOT, stdio: 'inherit' });
  }

  fs.mkdirSync(path.dirname(path.join(REPO_ROOT, REPORT_PATH)), { recursive: true });
  fs.writeFileSync(path.join(REPO_ROOT, REPORT_PATH), JSON.stringify({ authored: kept, deferred }, null, 2));
  console.log(`[fn-mine] DONE — ${kept.length} rule(s) authored and gate-clean: ${kept.map((a) => a.id).join(', ')}`);
  console.log(`::authored-files::${kept.map((a) => a.file).join(',')}`);
  console.log(`::report-file::${REPORT_PATH}`);
}

main().catch((e) => {
  console.error('[fn-mine] FATAL:', e);
  process.exit(1);
});
