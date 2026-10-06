#!/usr/bin/env node
/**
 * scripts/fn-mine-llm.ts
 *
 * Unattended false-negative mining: regenerates fresh FN reports against the
 * CURRENT rule set for the corpora in scripts/lib/fn-mine-corpora.ts
 * (HackAPrompt, PINT, LLMail-Inject, BrowseSafe-Bench), clusters the misses
 * via Claude into generalizable regex candidates, gates every candidate
 * against the FULL FN set + FULL benign corpus using the exact engine
 * regex-compile semantics, authors survivors as draft ATR rules, self-tests
 * each on the real engine, and re-verifies the whole batch against the repo's
 * own safety gate before handing off to the calling workflow to open a draft PR.
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
import { coverageOf, describeNullResultByCorpus, authoringRoom, type CorpusStageCounts } from './lib/fn-mine-input.js';
import {
  MINED_CORPORA,
  channelNote,
  falseNegatives,
  planChunks,
  unseenFirst,
  vendoredProblem,
  type Chunk,
  type MinedCorpusSpec,
} from './lib/fn-mine-corpora.js';
import { gateAuthoredBatch } from './lib/fn-mine-gate.js';
import { countRecoveries } from './lib/fn-mine-recoveries.js';
import { assertSomeChunkRead, mineChunkReply, type ChunkResult, type MineCandidate } from './lib/fn-mine-reply.js';
import {
  finalizeAuthoredRule,
  hasBenchmarkArtifacts,
  isRuleCategory,
  re2Problem,
  visibilityProblem,
  withoutBenchmarkArtifacts,
} from './lib/fn-mine-quality.js';
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
const RESIDUAL_THRESHOLD = 20; // below this many uncovered FN, skip round 2
const REFERENCE_RULE = 'rules/prompt-injection/ATR-2026-00003-jailbreak-attempt.yaml';
const REPORT_PATH = 'output/fn-mine-report.json';
const RULE_ID_YEAR = '2026';

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
- Some slices name their benchmark's own scoring strings (a fixed recipient, a required reply, placeholder addresses). The same applies to them: never anchor on them; the gate removes them before counting.
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

function buildMinePrompt(chunk: Chunk, spec: MinedCorpusSpec): string {
  const numbered = chunk.texts
    .map((t, i) => `[${i}] ${t.slice(0, spec.budget.promptChars).replace(/\n/g, '\\n')}`)
    .join('\n');
  const goal = spec.goalNote ? `\nBENCHMARK SCORING STRINGS: ${spec.goalNote}\n` : '';
  return `CORPUS SLICE: ${chunk.label} (${chunk.texts.length} false-negative attack texts — the detection engine currently misses ALL of these)
${channelNote(spec.shape)}${goal}

Cluster these by shared attack STRUCTURE (the injection mechanism/technique), not surface topic. For each sizable cluster, propose ONE generalizable regex per the rules in your system prompt.

FALSE-NEGATIVE TEXTS:
${numbered}`;
}

/** One chunk's candidates. An unreadable reply is asked for once more, then the chunk is skipped (see fn-mine-reply.ts). */
async function mineChunk(chunk: Chunk, spec: MinedCorpusSpec, model: string): Promise<ChunkResult> {
  return mineChunkReply(
    chunk.label,
    () => callClaude(MINE_SYSTEM_PROMPT, buildMinePrompt(chunk, spec), model),
    (line) => console.log(`::warning::[fn-mine] ${line}`),
  );
}

// ---------------------------------------------------------------------------
// Gate — engine-accurate recovers/benignFP over the FULL sets
// ---------------------------------------------------------------------------

interface GatedCandidate extends MineCandidate {
  recovers: number;
  benignFP: number;
  /** Excerpts around the match, verbatim (countRecoveries): what the true positives are cut from. */
  exampleFNs: readonly string[];
}

interface GateContext {
  readonly corpusName: string;
  /** The texts recoveries are counted on: the FN texts with the corpus's benchmark artifacts removed. */
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
    // Counted on measureOn, so a regex that only recovers a benchmark's scoring
    // strings recovers nothing, and as distinct attacks, so copies of one
    // template sentence count once. Examples are excerpts of the real texts.
    const { recovers, copies, examples } = countRecoveries(re, gate.measureOn, fullFn);
    if (recovers < minRecovers) {
      if (copies >= minRecovers) {
        drop(c, `recovers ${copies} texts but only ${recovers} distinct line(s) < ${minRecovers}: copies of one template`);
      } else if (gate.measureOn !== fullFn && fullFn.filter((t) => re.test(t)).length >= minRecovers) {
        drop(c, `recovers ${recovers} < ${minRecovers} without ${gate.corpusName}'s benchmark artifacts: it keys on the benchmark's scoring strings`);
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
- test_cases.true_positives: 2-3 of the given real FN attack excerpts, copied VERBATIM. Each is a JSON string that the gated regex matches; a JSON string is a valid YAML double-quoted scalar, so write it as given. Do not shorten or reword it: the regex must still match it.
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

Excerpts of real false-negative attack texts this rule must fire on, each containing the regex's match (use 2-3 as true_positives):
${c.exampleFNs.map((t, i) => `${i + 1}. ${JSON.stringify(t)}`).join('\n')}`;
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

/**
 * The corpora this run can mine. A report corpus whose regeneration fails, or a
 * vendored corpus missing from disk, is skipped and logged loudly: one corpus's
 * external dependency (HackAPrompt's upstream dataset requiring auth, say) must
 * not stop the others. Every corpus unavailable fails the run.
 */
function prepareCorpora(): readonly MinedCorpusSpec[] {
  console.log('[fn-mine] regenerating FN reports against the current rule set...');
  const available: MinedCorpusSpec[] = [];
  for (const spec of MINED_CORPORA) {
    try {
      if (spec.kind === 'vendored') {
        const problem = vendoredProblem(spec, REPO_ROOT);
        if (problem) throw new Error(problem);
      } else {
        for (const cmd of spec.regenerate) {
          console.log(`[fn-mine]   $ ${cmd}`);
          execSync(cmd, { cwd: REPO_ROOT, stdio: 'inherit' });
        }
      }
      available.push(spec);
    } catch (e) {
      console.log(`[fn-mine] WARNING: ${spec.name} corpus is unavailable — skipping this corpus for this run.`);
      console.log(`[fn-mine]   ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  if (available.length === 0) {
    throw new Error('Every corpus failed to regenerate — nothing to mine. See warnings above for per-corpus failure reasons.');
  }
  return available;
}

interface MineSettings {
  readonly model: string;
  readonly minRecovers: number;
  readonly benignTexts: readonly string[];
  readonly gateCorpus: GateCorpus;
}

interface RoundResult {
  readonly proposed: number;
  readonly survivors: readonly GatedCandidate[];
  readonly asked: number;
  readonly unread: number;
  /** The texts the round's chunks showed the model. */
  readonly shown: readonly string[];
}

/** One round: each chunk the budget allows to the model, every candidate through the gate. */
async function mineRound(
  label: string,
  texts: readonly string[],
  fn: readonly string[],
  spec: MinedCorpusSpec,
  gate: GateContext,
  s: MineSettings,
): Promise<RoundResult> {
  const candidates: MineCandidate[] = [];
  let unread = 0;
  const chunks = planChunks(label, texts, spec.budget);
  for (const chunk of chunks) {
    console.log(`[fn-mine]   mining ${chunk.label}...`);
    const reply = await mineChunk(chunk, spec, s.model);
    if (!reply.read) unread += 1;
    candidates.push(...reply.candidates);
  }
  const shown = chunks.flatMap((c) => c.texts);
  if (texts.length > shown.length) {
    console.log(`[fn-mine]   ${label}: chunk cap ${spec.budget.maxChunksPerRound} reached; ${texts.length - shown.length} FN not shown this round`);
  }
  const survivors = gateCandidates(candidates, fn, s.benignTexts, s.minRecovers, gate);
  return { proposed: candidates.length, survivors, asked: chunks.length, unread, shown };
}

interface CorpusRun {
  readonly stages: CorpusStageCounts;
  readonly survivors: readonly GatedCandidate[];
  readonly asked: number;
  readonly unread: number;
}

/** Mine one corpus: its uncovered FNs, round 1, then the residual round. */
async function mineCorpus(spec: MinedCorpusSpec, s: MineSettings): Promise<CorpusRun> {
  const fnRaw = await falseNegatives(spec, REPO_ROOT, (line) => console.log(`[fn-mine] ${line}`));
  // Coverage is judged by the eval harness over every rule on disk, drafts
  // included, with canaries, on the shape the corpus reaches an agent as; a
  // broken judgement throws and fails the run.
  const cov = await coverageOf(fnRaw, path.join(REPO_ROOT, 'rules'), spec.shape);
  const fn = [...cov.uncovered];
  console.log(
    `[fn-mine] ${spec.name}: ${fnRaw.length} false negatives against the LIVE engine (${spec.shape}), ` +
      `${cov.coveredCount} already covered by a rule on disk (${cov.draftsEvaluated} drafts evaluated), ` +
      `${fn.length} genuinely un-mined`,
  );
  const empty = { corpus: spec.name, fnTotal: fnRaw.length, uncovered: fn.length, proposed: 0, survived: 0 };
  if (fn.length === 0) return { stages: empty, survivors: [], asked: 0, unread: 0 };

  const gate: GateContext = {
    corpusName: spec.name,
    measureOn: hasBenchmarkArtifacts(spec.name) ? fn.map((t) => withoutBenchmarkArtifacts(spec.name, t)) : fn,
    corpus: s.gateCorpus,
  };
  const r1 = await mineRound(spec.name, fn, fn, spec, gate, s);
  console.log(`[fn-mine] ${spec.name} round 1: ${r1.proposed} proposed -> ${r1.survivors.length} survive the gate`);

  const residual = computeResidual(fn, r1.survivors);
  let r2: RoundResult = { proposed: 0, survivors: [], asked: 0, unread: 0, shown: [] };
  if (residual.length >= RESIDUAL_THRESHOLD) {
    console.log(`[fn-mine] ${spec.name}: ${residual.length} FN still uncovered -> mining residual`);
    // What round 1's cap kept from the model goes first; re-planning from index
    // 0 re-sent round 1's chunks whenever nothing survived.
    r2 = await mineRound(`${spec.name}-residual`, unseenFirst(residual, r1.shown), fn, spec, gate, s);
    console.log(`[fn-mine] ${spec.name} round 2 (residual): ${r2.proposed} proposed -> ${r2.survivors.length} survive`);
  } else {
    console.log(`[fn-mine] ${spec.name}: only ${residual.length} FN uncovered — below residual threshold (${RESIDUAL_THRESHOLD}), skipping round 2`);
  }
  const survivors = [...r1.survivors, ...r2.survivors];
  return {
    stages: { ...empty, proposed: r1.proposed + r2.proposed, survived: survivors.length },
    survivors,
    asked: r1.asked + r2.asked,
    unread: r1.unread + r2.unread,
  };
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

  const availableCorpora = prepareCorpora();
  const benignTexts = loadBenignTexts();
  console.log(`[fn-mine] benign gate corpus: ${benignTexts.length} records`);
  const gateCorpus = prepareGateCorpus(loadBenignSamples(REPO_ROOT));
  if (gateCorpus.samples.length === 0) throw new Error('MEASUREMENT_CORPORA is empty: the visibility check would pass every candidate');

  const perCorpus: CorpusStageCounts[] = [];
  const replies = { asked: 0, unread: 0 };
  let allSurvivors: Array<GatedCandidate & { corpus: string }> = [];
  for (const spec of availableCorpora) {
    const run = await mineCorpus(spec, { model, minRecovers, benignTexts, gateCorpus });
    perCorpus.push(run.stages);
    replies.asked += run.asked;
    replies.unread += run.unread;
    for (const s of run.survivors) allSurvivors.push({ ...s, corpus: spec.name });
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
    const note = describeNullResultByCorpus(perCorpus);
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
