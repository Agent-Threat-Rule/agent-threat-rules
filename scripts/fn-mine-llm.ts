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
 * outcome, not an error.
 *
 * Usage:
 *   npx tsx scripts/fn-mine-llm.ts [--dry-run] [--cap 5] [--min-recovers 8]
 *
 * Environment:
 *   ANTHROPIC_API_KEY required
 *   ATR_FNMINE_MODEL optional (default: claude-sonnet-5)
 */

import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';
import { parseArgs } from 'node:util';
import Anthropic from '@anthropic-ai/sdk';
import { needsUnicodeFlag } from '../src/engine.js';

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

async function callClaude(systemPrompt: string, userPrompt: string, model: string): Promise<string> {
  const client = new Anthropic({ apiKey: process.env['ANTHROPIC_API_KEY'] });
  const response = await client.messages.create({
    model,
    max_tokens: MAX_TOKENS,
    system: systemPrompt,
    messages: [{ role: 'user', content: userPrompt }],
  });
  const textBlock = response.content.find((b) => b.type === 'text');
  if (!textBlock || textBlock.type !== 'text') throw new Error('No text block in LLM response');
  return textBlock.text;
}

function extractBalancedJson(text: string): string {
  let cleaned = text.trim();
  cleaned = cleaned.replace(/^```(?:json)?\s*\n?/i, '').replace(/\n?```\s*$/i, '');
  const firstBrace = cleaned.indexOf('{');
  if (firstBrace === -1) throw new Error('No JSON object opening brace found in LLM output');
  let depth = 0;
  let inString = false;
  let escape = false;
  let lastBrace = -1;
  for (let i = firstBrace; i < cleaned.length; i++) {
    const ch = cleaned[i];
    if (escape) { escape = false; continue; }
    if (inString) {
      if (ch === '\\') escape = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') { inString = true; continue; }
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) { lastBrace = i; break; } }
  }
  if (lastBrace === -1) throw new Error('Unbalanced braces — no top-level JSON object closed');
  return cleaned.slice(firstBrace, lastBrace + 1);
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
  const corpus = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, spec.corpusPath), 'utf8')) as Array<{ id: string; text: string }>;
  const byId = new Map(corpus.map((c) => [c.id, c.text]));
  const report = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, spec.reportPath), 'utf8'));
  const missed = (report.report?.missedAttacks ?? report.missedAttacks ?? []) as Array<{ id: string }>;
  return missed.map((m) => byId.get(m.id)).filter((t): t is string => Boolean(t));
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

/**
 * Load every regex condition from every rule currently on disk, REGARDLESS of
 * maturity/status. The live engine skips status:draft rules (so they don't
 * suppress the benchmark's measured FN count), but a rule authored by a PRIOR
 * fn-mine run for the same attack cluster still exists on disk — mining that
 * cluster again next week would just produce a near-duplicate PR forever,
 * since draft rules stay invisible to the benchmark until a human promotes
 * them. Filtering FN texts against ALL existing regexes (draft included)
 * before mining prevents this — it treats "already authored, awaiting
 * promotion" the same as "already covered" for mining-input purposes.
 */
function loadAllExistingRegexes(): RegExp[] {
  const out: RegExp[] = [];
  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, entry.name);
      if (entry.isDirectory()) { walk(p); continue; }
      if (!entry.name.endsWith('.yaml')) continue;
      const text = fs.readFileSync(p, 'utf8');
      // Cheap line-based extraction (avoids a full YAML parse for every rule):
      // matches `value: "..."` or `value: '...'` lines under a regex condition.
      for (const m of text.matchAll(/^\s*value:\s*["'](.+)["']\s*$/gm)) {
        const re = compileEngineAccurate(m[1].replace(/\\(["'])/g, '$1'));
        if (re) out.push(re);
      }
    }
  };
  walk(path.join(REPO_ROOT, 'rules'));
  return out;
}

function filterAlreadyCovered(texts: readonly string[], existing: readonly RegExp[]): string[] {
  return texts.filter((t) => !existing.some((re) => re.test(t)));
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
- You are NOT given the benign corpus or the full FN set — you cannot know true recovers/benignFP. Propose your honest best candidates; an independent script will gate them empirically and only survivors move forward. Over-proposing plausible-looking candidates that get rejected is fine; under-proposing is not.

OUTPUT FORMAT: pure JSON, no markdown fences, no prose before or after. First character must be {. Schema:
{
  "candidates": [
    {
      "cluster": "short-kebab-technique-name",
      "regex": "the exact regex source (JS re syntax, with leading (?i) if case-insensitive)",
      "category": "one of: agent-manipulation, context-exfiltration, data-poisoning, excessive-autonomy, model-abuse, model-security, privilege-escalation, prompt-injection, skill-compromise, tool-poisoning",
      "rationale": "one sentence: what technique this captures and why it generalizes"
    }
  ]
}
If nothing in this slice yields a generalizable candidate, use an empty array — that is an honest, valid result.`;

interface MineCandidate {
  cluster: string;
  regex: string;
  category: string;
  rationale: string;
}

function buildMinePrompt(chunkLabel: string, texts: readonly string[]): string {
  const numbered = texts.map((t, i) => `[${i}] ${t.slice(0, 300).replace(/\n/g, '\\n')}`).join('\n');
  return `CORPUS SLICE: ${chunkLabel} (${texts.length} false-negative attack texts — the detection engine currently misses ALL of these)

Cluster these by shared attack STRUCTURE (the injection mechanism/technique), not surface topic. For each sizable cluster, propose ONE generalizable regex per the rules in your system prompt.

FALSE-NEGATIVE TEXTS:
${numbered}`;
}

async function mineChunk(chunkLabel: string, texts: readonly string[], model: string): Promise<MineCandidate[]> {
  const raw = await callClaude(MINE_SYSTEM_PROMPT, buildMinePrompt(chunkLabel, texts), model);
  const parsed = JSON.parse(extractBalancedJson(raw)) as { candidates?: MineCandidate[] };
  return parsed.candidates ?? [];
}

// ---------------------------------------------------------------------------
// Gate — engine-accurate recovers/benignFP over the FULL sets
// ---------------------------------------------------------------------------

interface GatedCandidate extends MineCandidate {
  recovers: number;
  benignFP: number;
  exampleFNs: string[];
}

function gateCandidates(
  candidates: readonly MineCandidate[],
  fullFn: readonly string[],
  benignTexts: readonly string[],
  minRecovers: number,
): GatedCandidate[] {
  const survivors: GatedCandidate[] = [];
  for (const c of candidates) {
    const re = compileEngineAccurate(c.regex);
    if (!re) continue; // invalid-after-engine-normalize — drop silently, logged by caller if desired
    let recovers = 0;
    const examples: string[] = [];
    for (const t of fullFn) {
      if (re.test(t)) {
        recovers++;
        if (examples.length < 5) examples.push(t);
      }
    }
    if (recovers < minRecovers) continue;
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

Copy this reference rule's structure EXACTLY (field order; references block with owasp_llm/owasp_agentic/mitre_atlas/mitre_attack; compliance block with ALL THREE of eu_ai_act/nist_ai_rmf/iso_42001; metadata_provenance; tags; agent_source; detection; response; confidence; wild_fp_rate; test_cases):

--- REFERENCE RULE ---
${referenceYaml}
--- END REFERENCE ---

Requirements:
- detection.conditions must include EXACTLY the given gated regex verbatim (field: content, operator: regex) — do not alter it.
- test_cases.true_positives: 2-3 of the given real FN attack texts (truncate to ~180 chars, escape for YAML double-quoted strings).
- test_cases.true_negatives: 3-4 benign texts you write that do NOT match the given regex (verify mentally before including).
- references use REAL valid ids: owasp_llm e.g. "LLM01:2025"; owasp_agentic e.g. "ASI01:2026 - ..." (pick one fitting the technique); mitre_atlas e.g. "AML.T0051 - LLM Prompt Injection" or "AML.T0054 - LLM Jailbreak".
- compliance: use this exact gate-passing shape, parameterized to the technique:
  eu_ai_act: article 15 (primary) + article 9 (secondary)
  nist_ai_rmf: subcategory MP.5.1 (primary) + MG.3.2 (secondary)
  iso_42001: clause 8.1 (primary) + clause 8.3 (secondary)
- status: draft, maturity: test, author: "ATR Community", severity: high.

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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

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

  const existingRegexes = loadAllExistingRegexes();
  console.log(`[fn-mine] existing rule regexes on disk (any status, incl. draft): ${existingRegexes.length}`);

  let allSurvivors: Array<GatedCandidate & { corpus: string }> = [];
  for (const spec of availableCorpora) {
    const fnRaw = loadFnCorpus(spec);
    const fnFiltered = filterAlreadyCovered(fnRaw.texts, existingRegexes);
    const fn = { name: fnRaw.name, texts: fnFiltered };
    console.log(
      `[fn-mine] ${spec.name}: ${fnRaw.texts.length} false negatives against the LIVE engine, ` +
      `${fnRaw.texts.length - fn.texts.length} already covered by an existing (possibly draft) rule, ` +
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
      const cands = await mineChunk(label, chunks[i], model);
      round1Candidates.push(...cands);
    }
    const round1Survivors = gateCandidates(round1Candidates, fn.texts, benignTexts, minRecovers);
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
        const cands = await mineChunk(label, rChunks[i], model);
        round2Candidates.push(...cands);
      }
      round2Survivors = gateCandidates(round2Candidates, fn.texts, benignTexts, minRecovers);
      console.log(`[fn-mine] ${spec.name} round 2 (residual): ${round2Candidates.length} proposed -> ${round2Survivors.length} survive`);
    } else {
      console.log(`[fn-mine] ${spec.name}: only ${residual.length} FN uncovered — below residual threshold (${RESIDUAL_THRESHOLD}), skipping round 2`);
    }

    for (const s of [...round1Survivors, ...round2Survivors]) allSurvivors.push({ ...s, corpus: spec.name });
  }

  // Dedup by exact regex, rank by recovers, cap.
  const seen = new Set<string>();
  allSurvivors = allSurvivors
    .filter((s) => { const k = s.regex.trim(); if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => b.recovers - a.recovers);
  const picked = allSurvivors.slice(0, cap);
  const deferred = allSurvivors.length - picked.length;
  console.log(`[fn-mine] total survivors: ${allSurvivors.length}. Authoring top ${picked.length}${deferred > 0 ? ` (deferring ${deferred} to next run)` : ''}.`);

  if (picked.length === 0) {
    console.log('[fn-mine] NULL RESULT — nothing survived the gate this run. Not an error.');
    fs.mkdirSync(path.dirname(path.join(REPO_ROOT, REPORT_PATH)), { recursive: true });
    fs.writeFileSync(path.join(REPO_ROOT, REPORT_PATH), JSON.stringify({ authored: [], note: 'null result' }, null, 2));
    console.log('::authored-files::');
    return;
  }

  if (isDryRun) {
    console.log('[fn-mine] --dry-run: stopping before authoring. Survivors:');
    console.log(JSON.stringify(picked, null, 2));
    return;
  }

  // Compute next free ATR id: max across origin/main + all open PR branches (best-effort — just origin/main here;
  // the calling workflow's checkout is fresh so origin/main is authoritative at trigger time).
  const existingIds = execSync("find rules -name '*.yaml' -exec grep -h '^id: ATR-' {} \\;", { cwd: REPO_ROOT, encoding: 'utf8' })
    .split('\n')
    .map((l) => parseInt(l.match(/ATR-2026-(\d+)/)?.[1] ?? '0', 10))
    .filter((n) => n > 0);
  let nextId = Math.max(0, ...existingIds) + 1;

  const referenceYaml = fs.readFileSync(path.join(REPO_ROOT, REFERENCE_RULE), 'utf8');
  const authored: AuthoredRule[] = [];

  for (const c of picked) {
    const id = `ATR-2026-${String(nextId).padStart(5, '0')}`;
    nextId++;
    const slug = slugify(c.cluster);
    const file = `rules/${c.category}/${id}-${slug}.yaml`;
    const fullPath = path.join(REPO_ROOT, file);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });

    console.log(`[fn-mine] authoring ${id} (${c.cluster}, recovers=${c.recovers})...`);
    let yaml = await authorRule(id, c, referenceYaml, model);
    fs.writeFileSync(fullPath, yaml.endsWith('\n') ? yaml : yaml + '\n');

    let failure = selfTest(file);
    if (failure) {
      console.log(`[fn-mine]   self-test failed, one corrective retry for ${id}...`);
      yaml = await authorRule(id, c, referenceYaml, model, failure);
      fs.writeFileSync(fullPath, yaml.endsWith('\n') ? yaml : yaml + '\n');
      failure = selfTest(file);
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
  // makes them stale), then validate/compliance/mappings, then the safety gate.
  // Anything the safety gate rejects is DROPPED (not force-fixed) and the gate
  // re-run once on the remainder — matches the "quality over volume" norm.
  execSync('npm run build', { cwd: REPO_ROOT, stdio: 'inherit' });
  execSync('python3 scripts/generate-attack-crosswalk.py', { cwd: REPO_ROOT, stdio: 'inherit' });
  execSync('python3 scripts/generate-ast-crosswalk.py', { cwd: REPO_ROOT, stdio: 'inherit' });

  for (let attempt = 0; attempt < 2 && authored.length > 0; attempt++) {
    const gate = runSafetyGate();
    if (gate.pass) break;
    const dropIds = new Set(gate.failedFiles);
    const before = authored.length;
    for (let i = authored.length - 1; i >= 0; i--) {
      if (dropIds.has(authored[i].file)) {
        console.log(`[fn-mine]   safety-gate rejected ${authored[i].id} — dropping: ${gate.raw.match(new RegExp(`✗\\s+${authored[i].file}.*`))?.[0] ?? ''}`);
        fs.rmSync(path.join(REPO_ROOT, authored[i].file), { force: true });
        authored.splice(i, 1);
      }
    }
    if (authored.length === before) {
      // Gate failed but didn't name a specific file we recognize — bail safely rather than guess.
      console.log('[fn-mine] safety gate failed without attributable per-file rejections — dropping entire batch to be safe.');
      for (const a of authored) fs.rmSync(path.join(REPO_ROOT, a.file), { force: true });
      authored.length = 0;
    }
  }

  if (authored.length > 0) {
    execSync('python3 scripts/generate-attack-crosswalk.py', { cwd: REPO_ROOT, stdio: 'inherit' });
    execSync('python3 scripts/generate-ast-crosswalk.py', { cwd: REPO_ROOT, stdio: 'inherit' });
  }

  if (authored.length === 0) {
    console.log('[fn-mine] NULL RESULT after safety-gate — nothing survived. Not an error.');
    console.log('::authored-files::');
    return;
  }

  fs.mkdirSync(path.dirname(path.join(REPO_ROOT, REPORT_PATH)), { recursive: true });
  fs.writeFileSync(path.join(REPO_ROOT, REPORT_PATH), JSON.stringify({ authored, deferred }, null, 2));
  console.log(`[fn-mine] DONE — ${authored.length} rule(s) authored and gate-clean: ${authored.map((a) => a.id).join(', ')}`);
  console.log(`::authored-files::${authored.map((a) => a.file).join(',')}`);
  console.log(`::report-file::${REPORT_PATH}`);
}

main().catch((e) => {
  console.error('[fn-mine] FATAL:', e);
  process.exit(1);
});
