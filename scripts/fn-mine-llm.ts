#!/usr/bin/env node
/**
 * scripts/fn-mine-llm.ts
 *
 * Unattended false-negative mining: regenerates fresh FN reports against the
 * CURRENT rule set for the corpora in scripts/lib/fn-mine-corpora.ts
 * (HackAPrompt, PINT, LLMail-Inject, BrowseSafe-Bench), clusters the misses
 * via Claude into generalizable regex candidates, gates every candidate
 * against the FN set + FULL benign corpus using the exact engine
 * regex-compile semantics, authors survivors as draft ATR rules, self-tests
 * each on the real engine, and re-verifies the whole batch against the repo's
 * own safety gate before handing off to the calling workflow to open a draft PR.
 *
 * Each corpus's uncovered misses are split by content hash (scripts/lib/
 * fn-mine-heldout.ts): 70% are shown to the model and count toward
 * --min-recovers, 30% are never shown and a candidate must recover some of
 * them too. Every candidate must also fire on no benign email or web page
 * presented to the engine as tool output (scripts/lib/fn-mine-tool-benign.ts);
 * without those corpora the run fails before mining anything.
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
 *   npx tsx scripts/fn-mine-llm.ts [--dry-run] [--cap 5] [--min-recovers 8] [--corpus a,b]
 *
 *   --corpus mines only the named MINED_CORPORA (comma-separated), for a
 *   backfill on a newly vendored corpus without re-spending model calls on
 *   the exhausted ones. An unknown name, or a value naming none, fails the run
 *   before anything else (selectCorpora). The report's `corpora` lists what
 *   this run was asked to mine, so a filtered null result is not read as the
 *   whole lane's.
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
import { callClaude as sharedCallClaude, describeBackend, backendAvailable } from './lib/claude-client.js';
import {
  coverageOf,
  describeNullResultByCorpus,
  assertNullResultComplete,
  authoringRoom,
  type CorpusStageCounts,
} from './lib/fn-mine-input.js';
import {
  channelNote,
  minedCorpusShape,
  selectCorpora,
  falseNegatives,
  planChunks,
  unseenFirst,
  minedCorpusProblem,
  type Chunk,
  type MinedCorpusSpec,
} from './lib/fn-mine-corpora.js';
import { gateAuthoredBatch } from './lib/fn-mine-gate.js';
import { schemaProblem } from './lib/fn-mine-schema.js';
import { redosPrecheck } from './lib/semantic-redos-precheck.js';
import {
  compileEngineAccurate,
  computeResidual,
  dropBacktracking,
  gateCandidates,
  pickDistinct,
  type GateContext,
  type GatedCandidate,
} from './lib/fn-mine-candidate-gate.js';
import { HELD_OUT_PERCENT, MIN_HELD_OUT_RECOVERS, seenLines, splitHeldOut, unmineableReason } from './lib/fn-mine-heldout.js';
import { dropToolOutputHits, requireToolOutputBenign, type ToolOutputBenign } from './lib/fn-mine-tool-benign.js';
import {
  generalizationVerdict,
  MIN_SIGNAL_SHARE,
  readOutOfSample,
  readUserInputBenign,
  type OutOfSampleCorpus,
} from './lib/fn-mine-generalization.js';
import { assertSomeChunkRead, mineChunkReply, type ChunkResult, type MineCandidate } from './lib/fn-mine-reply.js';
import { finalizeAuthoredRule, hasBenchmarkArtifacts, withoutBenchmarkArtifacts } from './lib/fn-mine-quality.js';
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
// Benign text corpus (the regex-only check; see fn-mine-candidate-gate.ts)
// ---------------------------------------------------------------------------

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
  out.push(...loadHardNegatives(), ...readUserInputBenign(REPO_ROOT));
  return out;
}

/**
 * The benign hard negatives the attack datasets ship (a security question, the
 * same request without the injection, a clean tool description), vendored by
 * scripts/sync-attack-sources.py. Read here only: this gate is the one place a
 * regex keyed on a request rather than an injection should be stopped by them,
 * and no rule-wide measurement counts them.
 */
function loadHardNegatives(): readonly string[] {
  const dir = path.join(REPO_ROOT, 'data/fn-mine-benign/hard-negatives');
  if (!fs.existsSync(dir)) return [];
  const out: string[] = [];
  for (const id of fs.readdirSync(dir).sort()) {
    const file = path.join(dir, id, 'corpus.json');
    if (!fs.existsSync(file)) continue;
    const doc = JSON.parse(fs.readFileSync(file, 'utf8')) as { samples?: { text?: unknown }[] };
    for (const s of doc.samples ?? []) if (typeof s.text === 'string') out.push(s.text);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Mining (Claude clusters a chunk of FN texts into candidate regexes)
// ---------------------------------------------------------------------------

const MINE_SYSTEM_PROMPT = `You are a senior detection engineer mining false negatives (real attacks an existing detection engine MISSED) into generalizable regex rules for ATR (Agent Threat Rules), an open detection standard.

RIGOR — reject your own candidate if it violates these:
- The regex must capture the attack CLASS (the injection technique/structure), NOT a literal payload. It must plausibly match unseen variants, not just the exact strings you were shown.
- Encode the actual injection signal — never a bare benign verb alone. For text a tool returns, the request itself is NOT the signal: business systems return "submit the grade", "cancel appointment APT-2041", "send the offer letter" every day. The regex must key on how the text addresses the agent: an override of its instructions, words addressed to the AI/assistant, a demand to hide it from the user, a forged [SYSTEM]/<INFORMATION> tag, a claim to come before the user's task. A gate rejects a candidate whose own matches lack such a signal, or that still fires on the same words with the signal removed.
- The same holds for text a user types. People ask colleagues to "take over as interim lead", "step in for me", "decode the config and follow it", "convert the file and run it". A user-input regex must key on how the text works on the model itself: an override of its instructions, reassigning its persona ("you are now", "pretend you are", "stay in character"), asking for its own system prompt or instructions, or demanding it stop refusing or drop its filters. The same gate applies, with those signals added, and its twins are the matched words in an ordinary message or meeting note.
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
// Authoring (Claude writes the full ATR rule YAML for a gated survivor)
// ---------------------------------------------------------------------------

function buildAuthorSystemPrompt(referenceYaml: string): string {
  return `You are authoring ONE payload-grounded ATR detection rule YAML file. NEVER mention PanGuard anywhere in the output.

Copy this reference rule's structure EXACTLY (field order; references block with owasp_llm/owasp_agentic/mitre_atlas/mitre_attack; compliance block with ALL THREE of eu_ai_act/nist_ai_rmf/iso_42001; metadata_provenance; tags; agent_source; detection; response; confidence; test_cases), except wild_fp_rate (see below):

--- REFERENCE RULE ---
${referenceYaml}
--- END REFERENCE ---

Requirements:
- detection.conditions must be EXACTLY ONE condition: the given gated regex verbatim (field: content, operator: regex), condition: any. Do not copy the reference rule's conditions and do not alter the regex; the file is rewritten to exactly that condition anyway.
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
GATED REGEX (engine-verified recovers=${c.recovers}; no match on the lane's benign gate corpora — a finite set, not a deployment false-positive rate; use EXACTLY as given): ${JSON.stringify(c.regex)}

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
 * status, wild_fp_rate, OWASP ids, today's UTC date in place of the one the
 * model copied) and with detection set to exactly the gated regex, whatever
 * conditions the model copied or altered. Returns why it could not, for the
 * corrective retry, or null once written.
 */
function writeAuthoredRule(
  fullPath: string,
  text: string,
  c: GatedCandidate & { readonly corpus: string },
  allowlists: OwaspAllowlists,
): string | null {
  let doc: unknown;
  try {
    doc = yaml.load(text);
  } catch (e) {
    return `the output is not valid YAML: ${e instanceof Error ? e.message : String(e)}`;
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return 'the output is not a single YAML mapping';
  const category = c.category as ATRCategory; // checked by isRuleCategory in the gate
  // A rule mined from a corpus that reaches the agent as tool output looks at tool output only.
  const shape = minedCorpusShape(c.corpus);
  const rule = finalizeAuthoredRule(doc as Record<string, unknown>, category, allowlists, c.regex, new Date(), shape);
  fs.writeFileSync(fullPath, yaml.dump(rule, RULE_YAML_OPTIONS));
  return null;
}

function runValidator(): string {
  try {
    return execSync('npx tsx tests/validate-rules.ts', { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    return e instanceof Error && 'stdout' in e ? String((e as { stdout?: unknown }).stdout ?? '') : String(e);
  }
}

/** The schema validator, then `node dist/cli.js test <file>`; returns null on success, failure text otherwise. */
function selfTest(filePath: string): string | null {
  const schema = schemaProblem(filePath, runValidator());
  if (schema) return schema;
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

function writeNullReport(note: string, corpora: readonly MinedCorpusSpec[]): void {
  fs.mkdirSync(path.dirname(path.join(REPO_ROOT, REPORT_PATH)), { recursive: true });
  const report = { corpora: corpora.map((c) => c.name), authored: [], note };
  fs.writeFileSync(path.join(REPO_ROOT, REPORT_PATH), JSON.stringify(report, null, 2));
}

/**
 * The corpora this run can mine, and the ones it could not. A report corpus
 * whose regeneration fails, or a vendored corpus missing from disk, is skipped
 * and logged loudly: one corpus's external dependency (HackAPrompt's upstream
 * dataset requiring auth, say) must not stop the others. A skipped corpus
 * makes a null result partial (assertNullResultComplete), not exhausted. Every
 * corpus unavailable fails the run.
 */
function prepareCorpora(selected: readonly MinedCorpusSpec[]): {
  readonly available: readonly MinedCorpusSpec[];
  readonly skipped: readonly string[];
} {
  console.log('[fn-mine] regenerating FN reports against the current rule set...');
  const available: MinedCorpusSpec[] = [];
  const skipped: string[] = [];
  for (const spec of selected) {
    try {
      if (spec.kind === 'vendored' || spec.kind === 'oos') {
        const problem = minedCorpusProblem(spec, REPO_ROOT);
        if (problem) throw new Error(problem);
      } else {
        for (const cmd of spec.regenerate) {
          console.log(`[fn-mine]   $ ${cmd}`);
          execSync(cmd, { cwd: REPO_ROOT, stdio: 'inherit' });
        }
      }
      available.push(spec);
    } catch (e) {
      skipped.push(spec.name);
      console.log(`::warning::[fn-mine] ${spec.name} corpus is unavailable — skipping this corpus for this run.`);
      console.log(`[fn-mine]   ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  if (available.length === 0) {
    throw new Error('Every corpus failed to regenerate — nothing to mine. See warnings above for per-corpus failure reasons.');
  }
  return { available, skipped };
}

/**
 * The benign sides of the gate, each logged: the regex-only text corpus, the
 * measurement corpora the visibility check counts on, and the tool-output
 * corpora (read by the caller, which fails the run without them).
 */
function readBenignGate(toolBenign: ToolOutputBenign): { benignTexts: readonly string[]; gateCorpus: GateCorpus } {
  const benignTexts = loadBenignTexts();
  console.log(`[fn-mine] benign gate corpus: ${benignTexts.length} records`);
  console.log(
    `[fn-mine] benign tool-output corpus: ${toolBenign.emails.length} emails, ${toolBenign.pages.length} pages, ` +
      `${toolBenign.records.length} records, ${toolBenign.tasks.length} tasks, ` +
      `${toolBenign.enterprise.length} business-system outputs (every candidate, as tool_response)`,
  );
  const gateCorpus = prepareGateCorpus(loadBenignSamples(REPO_ROOT));
  if (gateCorpus.samples.length === 0) throw new Error('MEASUREMENT_CORPORA is empty: the visibility check would pass every candidate');
  return { benignTexts, gateCorpus };
}

/** What the per-rule report records about the gate, so a reviewer reads the held-out counts against it. */
function gateReportNote(toolBenign: ToolOutputBenign, oos: readonly OutOfSampleCorpus[]): Record<string, unknown> {
  return {
    heldOut: {
      percent: HELD_OUT_PERCENT,
      minRecovers: MIN_HELD_OUT_RECOVERS,
      note: 'held out from the same corpus, so the same generator: it shows the regex is not a list of shown lines, not that it generalizes',
    },
    outOfSample: {
      corpora: oos.map((c) => ({ id: c.id, attacks: c.texts.length })),
      minRecovers: 1,
      note: 'attacks in corpora the rule was not mined from; per-rule counts are in authored[].outOfSample',
    },
    injectionSignal: {
      appliesTo: 'every rule; INJECTION_SIGNALS for tool output, USER_INPUT_SIGNALS for user input',
      minShareOfMatches: MIN_SIGNAL_SHARE,
      list: 'scripts/lib/fn-mine-generalization.ts INJECTION_SIGNALS',
    },
    benignTwins:
      'each rule must not fire on its own recoveries with the injection signals removed: ticket, to-do and record frames for tool output; message, meeting-note and reply-draft frames for user input',
    toolOutputBenign: {
      emails: toolBenign.emails.length,
      pages: toolBenign.pages.length,
      records: toolBenign.records.length,
      tasks: toolBenign.tasks.length,
      businessSystemOutputs: toolBenign.enterprise.length,
      eventShape: 'tool_response',
    },
    whatZeroMeans:
      'A rule that passed fired on none of the benign texts counted here, in the event shape stated. ' +
      'That is not a false-positive rate in deployment: these corpora do not cover every business system an agent reads.',
  };
}

interface MineSettings {
  readonly model: string;
  readonly minRecovers: number;
  readonly benignTexts: readonly string[];
  readonly gateCorpus: GateCorpus;
  /** Benign emails, pages, records, tasks and business outputs every candidate is run against as tool output. */
  readonly toolBenign: ToolOutputBenign;
  /** Attack corpora for the out-of-sample gate; the mined corpus is skipped per candidate. */
  readonly oos: readonly OutOfSampleCorpus[];
}

interface RoundResult {
  readonly proposed: number;
  readonly survivors: readonly GatedCandidate[];
  readonly asked: number;
  readonly unread: number;
  /** The texts the round's chunks showed the model. */
  readonly shown: readonly string[];
}

/**
 * `survivors` that pass the generalization gates (fn-mine-generalization.ts):
 * an attack outside the mined corpus, and for a tool-output corpus an
 * injection signal in its own matches and no hit on its benign twins. Each
 * drop is logged with every failed gate's reason.
 */
function dropUngeneralized<T extends GatedCandidate>(
  survivors: readonly T[],
  fn: readonly string[],
  spec: MinedCorpusSpec,
  oos: readonly OutOfSampleCorpus[],
): T[] {
  const kept: T[] = [];
  for (const s of survivors) {
    const re = compileEngineAccurate(s.regex);
    const recovered = re ? fn.filter((t) => re.test(t)) : [];
    const v = generalizationVerdict(
      { regex: s.regex, recovered, minedFrom: spec.name, shape: spec.shape },
      oos,
    );
    if (!v.pass) {
      for (const [gate, why] of Object.entries(v.failures)) console.log(`[fn-mine]   drop ${s.cluster} (${gate}): ${why}`);
      continue;
    }
    kept.push({ ...s, outOfSample: v.outOfSample });
  }
  return kept;
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
  const gated = gateCandidates(candidates, fn, s.benignTexts, s.minRecovers, gate);
  const benignClean = await dropToolOutputHits(gated, s.toolBenign);
  const survivors = dropUngeneralized(benignClean, fn, spec, s.oos);
  for (const c of survivors) {
    console.log(
      `[fn-mine]   keep ${c.cluster}: recovers ${c.recovers} shown FN, ${c.heldOutRecovers} of ${gate.heldOut.length} held out, ` +
        `out of sample ${JSON.stringify(c.outOfSample ?? {})}`,
    );
  }
  return { proposed: candidates.length, survivors, asked: chunks.length, unread, shown };
}

interface CorpusRun {
  readonly stages: CorpusStageCounts;
  readonly survivors: readonly GatedCandidate[];
  readonly asked: number;
  readonly unread: number;
}

interface UncoveredSplit {
  readonly fnTotal: number;
  readonly uncovered: number;
  /** The minable side: the only FN texts the model, the residual and the chunk plan see. */
  readonly fn: readonly string[];
  readonly heldOut: readonly string[];
}

/** A corpus's false negatives no rule on disk covers, split into minable and held out, logged. */
async function uncoveredSplit(spec: MinedCorpusSpec): Promise<UncoveredSplit> {
  const fnRaw = await falseNegatives(spec, REPO_ROOT, (line) => console.log(`[fn-mine] ${line}`));
  // Coverage is judged by the eval harness over every rule on disk, drafts
  // included, with canaries, on the shape the corpus reaches an agent as; a
  // broken judgement throws, and main() skips this corpus with a warning and
  // records it in the report.
  const cov = await coverageOf(fnRaw, path.join(REPO_ROOT, 'rules'), spec.shape);
  // Each text's coverage is judged on its own, so splitting the uncovered set
  // is the same as judging each side separately. The held-out side is only
  // ever counted.
  const { minable: fn, heldOut } = splitHeldOut(cov.uncovered);
  console.log(
    `[fn-mine] ${spec.name}: ${fnRaw.length} false negatives against the LIVE engine (${spec.shape}), ` +
      `${cov.coveredCount} already covered by a rule on disk (${cov.draftsEvaluated} drafts evaluated), ` +
      `${cov.uncovered.length} genuinely un-mined: ${fn.length} minable, ${heldOut.length} held out (${HELD_OUT_PERCENT}%, never shown)`,
  );
  return { fnTotal: fnRaw.length, uncovered: cov.uncovered.length, fn, heldOut };
}

/** Mine one corpus: its uncovered FNs, round 1, then the residual round. */
async function mineCorpus(spec: MinedCorpusSpec, s: MineSettings): Promise<CorpusRun> {
  const { fnTotal, uncovered, fn, heldOut } = await uncoveredSplit(spec);
  const empty = { corpus: spec.name, fnTotal, uncovered, proposed: 0, survived: 0 };
  if (uncovered === 0) return { stages: empty, survivors: [], asked: 0, unread: 0 };
  const notMinedBecause = unmineableReason(fn.length, heldOut.length, s.minRecovers);
  if (notMinedBecause) {
    console.log(`[fn-mine] ${spec.name}: not mined, ${notMinedBecause}`);
    return { stages: { ...empty, notMinedBecause }, survivors: [], asked: 0, unread: 0 };
  }

  const gate: GateContext = {
    corpusName: spec.name,
    measureOn: hasBenchmarkArtifacts(spec.name) ? fn.map((t) => withoutBenchmarkArtifacts(spec.name, t)) : fn,
    heldOut,
    seenLines: seenLines(fn, spec.name),
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
  /** Distinct held-out FN texts the rule's regex recovers: texts the model never saw, from the same corpus. */
  heldOutRecovers: number;
  /** Attacks it recovers in corpora it was not mined from, by corpus. */
  outOfSample: Readonly<Record<string, number>>;
}

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      'dry-run': { type: 'boolean', default: false },
      cap: { type: 'string', default: '5' },
      'min-recovers': { type: 'string', default: '8' },
      model: { type: 'string', default: DEFAULT_MODEL },
      corpus: { type: 'string', default: '' },
    },
  });
  // Before anything else runs: an early return further down must not turn a typo green.
  const selectedCorpora = selectCorpora(values.corpus as string);
  const cap = parseInt(values.cap as string, 10);
  const minRecovers = parseInt(values['min-recovers'] as string, 10);
  const model = values.model as string;
  const isDryRun = values['dry-run'] as boolean;

  console.log(
    `[fn-mine] model=${model} cap=${cap} minRecovers=${minRecovers} dryRun=${isDryRun}` +
      (values.corpus ? ` corpora=${selectedCorpora.map((c) => c.name).join(',')}` : ''),
  );

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
    writeNullReport(note, selectedCorpora);
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

  // Before any corpus is regenerated or any model credit spent: without these
  // no candidate can be gated, whichever corpus it comes from.
  const toolBenign = requireToolOutputBenign(REPO_ROOT);
  const oos = readOutOfSample(REPO_ROOT);
  console.log(`[fn-mine] out-of-sample corpora: ${oos.map((c) => `${c.id} ${c.texts.length}`).join(', ')}`);
  const { available: availableCorpora, skipped: skippedCorpora } = prepareCorpora(selectedCorpora);
  const { benignTexts, gateCorpus } = readBenignGate(toolBenign);

  const perCorpus: CorpusStageCounts[] = [];
  const replies = { asked: 0, unread: 0 };
  let allSurvivors: Array<GatedCandidate & { corpus: string }> = [];
  // One corpus failing mid-mining (a sample the model call cannot carry, a
  // coverage error) used to end the run and discard every other corpus's
  // survivors. It is skipped like a corpus that failed to regenerate: its
  // survivors are lost, the others are authored, and a null result with a
  // failed corpus still fails the run. If every corpus fails, so does the run.
  const failedCorpora: string[] = [];
  for (const spec of availableCorpora) {
    let run: CorpusRun;
    try {
      run = await mineCorpus(spec, { model, minRecovers, benignTexts, gateCorpus, toolBenign, oos });
    } catch (e) {
      failedCorpora.push(spec.name);
      console.log(`::warning::[fn-mine] ${spec.name}: mining failed — skipping this corpus for this run.`);
      console.log(`[fn-mine]   ${e instanceof Error ? e.message.slice(0, 500) : String(e)}`);
      continue;
    }
    perCorpus.push(run.stages);
    replies.asked += run.asked;
    replies.unread += run.unread;
    for (const s of run.survivors) allSurvivors.push({ ...s, corpus: spec.name });
  }
  if (failedCorpora.length === availableCorpora.length) {
    throw new Error(`mining failed for every corpus (${failedCorpora.join(', ')}); see the warnings above`);
  }

  // Every reply unreadable is a lane that could not run, not an empty week.
  assertSomeChunkRead(replies.asked, replies.unread);
  if (replies.unread > 0) {
    console.log(`::warning::[fn-mine] ${replies.unread} of ${replies.asked} chunk(s) skipped: their replies could not be read as JSON.`);
  }

  // The workflow's ReDoS gate, on each regex alone; then rank by recovers, keep
  // each only for attacks no survivor above it recovers, cap.
  const fast = dropBacktracking(allSurvivors, (regex) => redosPrecheck(regex, REPO_ROOT));
  const distinct = pickDistinct(fast.kept, minRecovers);
  for (const d of distinct.dropped) console.log(`[fn-mine]   overlap: drop ${d.candidate.cluster}: ${d.why}`);
  allSurvivors = [...distinct.kept];
  const picked = allSurvivors.slice(0, room);
  const deferred = allSurvivors.length - picked.length;
  console.log(`[fn-mine] total survivors: ${allSurvivors.length}. Authoring top ${picked.length}${deferred > 0 ? ` (deferring ${deferred} to next run)` : ''}.`);

  if (picked.length === 0) {
    // A skipped corpus makes this a partial run, not an exhausted one.
    assertNullResultComplete([...skippedCorpora, ...failedCorpora]);
    // Survivors the ReDoS precheck took all of are a null result too, and must
    // say so: the per-corpus counts alone read as rules that survived.
    const note =
      fast.dropped > 0
        ? `NULL RESULT — the ReDoS precheck dropped all ${fast.dropped} survivor(s) of the gate. ${describeNullResultByCorpus(perCorpus)}`
        : describeNullResultByCorpus(perCorpus);
    console.log(`[fn-mine] ${note} Not an error.`);
    writeNullReport(note, selectedCorpora);
    console.log('::authored-files::');
    return;
  }

  if (isDryRun) {
    console.log('[fn-mine] --dry-run: stopping before authoring. Survivors:');
    console.log(JSON.stringify(picked.map(({ recoveryKeys: _keys, ...rest }) => rest), null, 2));
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

    console.log(`[fn-mine] authoring ${id} (${c.cluster}, recovers=${c.recovers}, heldOut=${c.heldOutRecovers})...`);
    let failure = writeAuthoredRule(fullPath, await authorRule(id, c, referenceYaml, model), c, allowlists) ?? selfTest(file);
    if (failure) {
      console.log(`[fn-mine]   self-test failed, one corrective retry for ${id}...`);
      failure =
        writeAuthoredRule(fullPath, await authorRule(id, c, referenceYaml, model, failure), c, allowlists) ??
        selfTest(file);
    }
    if (failure) {
      console.log(`[fn-mine]   DROPPING ${id} — self-test still failing after retry:\n${failure}`);
      fs.rmSync(fullPath, { force: true });
      continue;
    }
    authored.push({
      id,
      file,
      cluster: c.cluster,
      recovers: c.recovers,
      heldOutRecovers: c.heldOutRecovers,
      outOfSample: c.outOfSample ?? {},
    });
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
  const report = {
    corpora: selectedCorpora.map((c) => c.name),
    authored: kept,
    deferred,
    notMined: [...skippedCorpora, ...failedCorpora],
    gate: gateReportNote(toolBenign, oos),
  };
  fs.writeFileSync(path.join(REPO_ROOT, REPORT_PATH), JSON.stringify(report, null, 2));
  console.log(`[fn-mine] DONE — ${kept.length} rule(s) authored and gate-clean: ${kept.map((a) => a.id).join(', ')}`);
  console.log(`::authored-files::${kept.map((a) => a.file).join(',')}`);
  console.log(`::report-file::${REPORT_PATH}`);
}

main().catch((e) => {
  console.error('[fn-mine] FATAL:', e);
  process.exit(1);
});
