/**
 * scripts/lib/fn-mine-corpora.ts
 *
 * The corpora the scheduled FN-mine lane (scripts/fn-mine-llm.ts) mines, where
 * each one's false negatives come from, and how much model time each may cost.
 *
 * HackAPrompt (2023) and the self-built PINT set were the lane's only input
 * until 2026-10, and its last run on them (actions run 37459737398) proposed
 * 40 candidates of which none recovered 8 misses: those corpora are exhausted.
 * LLMail-Inject and BrowseSafe-Bench attack an agent that holds tools, through
 * that tool's output (scripts/sync-agent-attack-corpora.ts vendors them).
 *
 * Two kinds of spec:
 *   - `report`   — a benchmark under src/eval regenerates a miss report, and the
 *                  misses are read from it (HackAPrompt, PINT).
 *   - `vendored` — a corpus registered in scripts/lib/fn-corpora.ts; the misses
 *                  are what the live rules miss on the corpus's delivery shape
 *                  (liveMisses), because no benchmark script runs it.
 */
import fs from 'node:fs';
import path from 'node:path';
import { corpusById, type DeliveryShape } from './fn-corpora.js';
import { liveMisses, successfulHackapromptMisses } from './fn-mine-input.js';

/**
 * How much of a corpus one run shows the model. Every chunk is one model call,
 * so maxChunksPerRound bounds the calls: at most 2 x maxChunksPerRound per
 * corpus (round 1 and the residual round). The residual round shows the texts
 * round 1 could not first (unseenFirst), so one run reaches up to
 * 2 x maxChunksPerRound x chunkSize misses. Texts past that wait until merged
 * rules cover earlier ones; the gate still counts recoveries over the corpus's
 * full FN set.
 */
export interface MineBudget {
  /** Texts per model call. */
  readonly chunkSize: number;
  /** Characters of each text the model is shown. */
  readonly promptChars: number;
  readonly maxChunksPerRound: number;
}

interface SpecBase {
  readonly name: string;
  readonly shape: DeliveryShape;
  readonly budget: MineBudget;
  /**
   * The benchmark's scoring strings, for the mining prompt (they are removed
   * before recoveries are counted: BENCHMARK_ARTIFACTS in fn-mine-quality.ts).
   */
  readonly goalNote?: string;
}

export interface ReportCorpusSpec extends SpecBase {
  readonly kind: 'report';
  readonly corpusPath: string;
  readonly reportPath: string;
  /** Shell commands that (re)build the corpus and its miss report. */
  readonly regenerate: readonly string[];
}

export interface VendoredCorpusSpec extends SpecBase {
  readonly kind: 'vendored';
  /** Id in scripts/lib/fn-corpora.ts CORPORA. */
  readonly registryId: string;
}

export type MinedCorpusSpec = ReportCorpusSpec | VendoredCorpusSpec;

/** Short prompt texts: 300 of them, 300 characters each — the lane's original slice. */
const PROMPT_BUDGET: MineBudget = Object.freeze({ chunkSize: 300, promptChars: 300, maxChunksPerRound: 3 });

/**
 * Emails (median ~950 characters) and page projections (median ~2.2 KB) put
 * the injection anywhere in the text, so each is shown longer and fewer go in
 * a call: about the same prompt size as a prompt chunk.
 */
const EMAIL_BUDGET: MineBudget = Object.freeze({ chunkSize: 75, promptChars: 1200, maxChunksPerRound: 3 });
const PAGE_BUDGET: MineBudget = Object.freeze({ chunkSize: 60, promptChars: 1500, maxChunksPerRound: 3 });

export const MINED_CORPORA: readonly MinedCorpusSpec[] = Object.freeze([
  {
    kind: 'report',
    name: 'hackaprompt',
    shape: 'llm_input',
    budget: PROMPT_BUDGET,
    corpusPath: 'data/hackaprompt/hackaprompt-corpus.json',
    reportPath: 'data/hackaprompt/hackaprompt-eval-report.json',
    regenerate: ['python3 scripts/hackaprompt-to-corpus.py --sample 5000', 'npx tsx src/eval/run-hackaprompt-benchmark.ts'],
  },
  {
    kind: 'report',
    name: 'pint',
    shape: 'llm_input',
    budget: PROMPT_BUDGET,
    corpusPath: 'data/pint-benchmark/pint-corpus.json',
    reportPath: 'data/pint-benchmark/pint-eval-report.json',
    regenerate: ['npx tsx src/eval/run-pint-benchmark.ts'],
  },
  {
    kind: 'vendored',
    name: 'llmail-inject',
    registryId: 'llmail-inject',
    shape: 'tool_response',
    budget: EMAIL_BUDGET,
    goalNote:
      'Every LLMail email had to make the agent send an email to contact@contact.com (often obfuscated: ' +
      'contact[at]contact[dot]com) with body "confirmation" or "$NUM million", and the retrieval levels had to ' +
      'mention "Project Zenith" or "Q2 Budget" to be retrieved. Those are the challenge\'s scoring strings, not ' +
      'techniques: never anchor a regex on them.',
  },
  {
    kind: 'vendored',
    name: 'browsesafe-bench',
    registryId: 'browsesafe-bench',
    shape: 'tool_response',
    budget: PAGE_BUDGET,
    goalNote:
      'Each text is the part of a web page no benign page shares: the hidden injection plus the page\'s own ' +
      'content and look-alike phishing banners the benchmark also plants on benign pages. Eleven fixed template ' +
      'payloads exfiltrate to placeholder addresses (attacker@evil.com, test@example-collector.com, ' +
      'leak@badsite.com, ...): never anchor a regex on those addresses.',
  },
]);

/** What a vendored corpus file says it holds, or why it cannot be read. */
function declaredCount(file: string): { readonly count: number | null } | { readonly problem: string } {
  try {
    const doc = JSON.parse(fs.readFileSync(file, 'utf8')) as { count?: unknown };
    return { count: typeof doc.count === 'number' ? doc.count : null };
  } catch (e) {
    return { problem: `is not valid JSON (${e instanceof Error ? e.message : String(e)})` };
  }
}

/**
 * Why a vendored corpus cannot be mined this run, or null. Report corpora
 * regenerate instead. The registry loader reads an unreadable file as no
 * samples, which would mine nothing and report 0 FN as an exhausted corpus;
 * so the file must parse, hold attacks, and hold as many as it declares.
 */
export function vendoredProblem(spec: VendoredCorpusSpec, root: string): string | null {
  const def = corpusById(spec.registryId);
  if (!def) return `${spec.registryId} is not in scripts/lib/fn-corpora.ts CORPORA`;
  const file = path.join(root, def.path);
  if (!fs.existsSync(file)) return `${def.path} is missing (run scripts/sync-agent-attack-corpora.ts --write)`;
  const declared = declaredCount(file);
  if ('problem' in declared) return `${def.path} ${declared.problem}`;
  const attacks = def.load(root).filter((s) => s.label === 'attack').length;
  if (attacks === 0) return `${def.path} holds no attack samples`;
  if (declared.count !== null && declared.count !== attacks) {
    return `${def.path} declares ${declared.count} rows but ${attacks} attack samples load`;
  }
  return null;
}

const readJson = (root: string, rel: string): unknown => JSON.parse(fs.readFileSync(path.join(root, rel), 'utf8'));

function hackapromptMisses(spec: ReportCorpusSpec, root: string, log: (line: string) => void): readonly string[] {
  const corpus = readJson(root, spec.corpusPath) as Parameters<typeof successfulHackapromptMisses>[0];
  const report = readJson(root, spec.reportPath) as Parameters<typeof successfulHackapromptMisses>[1];
  const { texts, missed, droppedUnsuccessful } = successfulHackapromptMisses(corpus, report);
  log(
    `hackaprompt: ${missed} missed, ${droppedUnsuccessful} of them failed in the competition ` +
      `(correct=false) and are not mined, ${texts.length} successful submissions remain`,
  );
  return texts;
}

interface MissReport {
  readonly report?: { readonly missedAttacks?: readonly { id: string }[] };
  readonly missedAttacks?: readonly { id: string }[];
}

function pintMisses(spec: ReportCorpusSpec, root: string): readonly string[] {
  const corpus = readJson(root, spec.corpusPath) as readonly { text: string }[];
  const report = readJson(root, spec.reportPath) as MissReport;
  const missed = report.report?.missedAttacks ?? report.missedAttacks ?? [];
  return missed
    .map((m) => corpus[parseInt(m.id.split('-')[1] ?? '', 10) - 1]?.text)
    .filter((t): t is string => Boolean(t));
}

async function vendoredMisses(spec: VendoredCorpusSpec, root: string, log: (line: string) => void): Promise<readonly string[]> {
  const def = corpusById(spec.registryId);
  const attacks = (def?.load(root) ?? []).filter((s) => s.label === 'attack').map((s) => s.text);
  const missed = await liveMisses(attacks, path.join(root, 'rules'), spec.shape);
  log(`${spec.name}: ${attacks.length} attacks presented as ${spec.shape}, ${missed.length} missed by the live rules`);
  return missed;
}

/** The corpus's false negatives against the current rules, before draft coverage. */
export async function falseNegatives(spec: MinedCorpusSpec, root: string, log: (line: string) => void): Promise<readonly string[]> {
  if (spec.kind === 'vendored') return vendoredMisses(spec, root, log);
  return spec.name === 'hackaprompt' ? hackapromptMisses(spec, root, log) : pintMisses(spec, root);
}

export interface Chunk {
  readonly label: string;
  readonly texts: readonly string[];
}

/** At most budget.maxChunksPerRound chunks of `texts`, in order, labelled for the log. */
export function planChunks(name: string, texts: readonly string[], budget: MineBudget): readonly Chunk[] {
  const chunks: Chunk[] = [];
  for (let start = 0; start < texts.length && chunks.length < budget.maxChunksPerRound; start += budget.chunkSize) {
    const slice = texts.slice(start, start + budget.chunkSize);
    chunks.push({ label: `${name}[${start}:${start + slice.length}]`, texts: slice });
  }
  return chunks;
}

/**
 * `texts` with those not in `shown` first, each group in its own order. The
 * residual round plans its chunks from this, so the FNs past round 1's cap
 * reach the model before round 1's are shown again.
 */
export function unseenFirst(texts: readonly string[], shown: readonly string[]): readonly string[] {
  const seen = new Set(shown);
  return [...texts.filter((t) => !seen.has(t)), ...texts.filter((t) => seen.has(t))];
}

/** The channel line the mining prompt opens with, so the model knows who wrote the text. */
export function channelNote(shape: DeliveryShape): string {
  return shape === 'tool_response'
    ? "CHANNEL: these texts reach the agent as a TOOL's OUTPUT (an email the mail tool returned, a page the browser fetched), not as the user's prompt. A rule for them must read the text the tool returned."
    : 'CHANNEL: these texts reach the agent as the user\'s prompt.';
}
