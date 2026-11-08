/**
 * scripts/lib/fn-mine-generalization.ts
 *
 * Three FN-mine gates (scripts/fn-mine-llm.ts) that ask whether a candidate
 * detects an injection or only the request the injection makes.
 *
 * Why (2026-11-08, PR #819): ten rules mined from the Nemotron agentic
 * indirect-injection set passed every gate the lane had, recovered 103 of 215
 * held-out Nemotron rows, and fired on none of ~66,000 benign samples. Six
 * hand-written business tool outputs ("Submit interview feedback for candidate
 * ... include an overall rating", "Add new items to inventory. SKU ...
 * Quantity ...", "To cancel your appointment APT-2041 ...") each tripped one of
 * them. The rules keyed on what the injection asks the agent to do, and HR,
 * ERP, LMS and calendar systems return that same wording when nobody is
 * attacking. Three things let that through, and each gate here closes one:
 *
 * 1. Held-out was the same generator. A regex that memorised Nemotron's
 *    templates recovered its held-out rows as easily as its shown ones.
 *    outOfSampleProblem: a candidate must also recover at least one attack in
 *    a corpus it was not mined from (data/fn-mine-oos, AgentDojo and
 *    InjecAgent, plus every other usable attack corpus in fn-corpora.ts).
 *
 * 2. Nothing required an injection signal. The goal note even told the miner
 *    to "key on what the injected instruction asks the agent to do", because
 *    the generator's wrappers had been removed as benchmark artifacts.
 *    injectionSignalProblem: on the attacks it recovers, the regex's own match
 *    must contain an injection signal (INJECTION_SIGNALS: text addressed to
 *    the agent, an override of its instructions, a demand for secrecy, a
 *    forged authority tag, a precedence demand) in at least
 *    MIN_SIGNAL_SHARE of matches. Deterministic, so a reviewer can rerun it
 *    and read the list it is judged against.
 *
 * 3. The benign twins came from the same dataset. twinProblem: each candidate
 *    is run on twins of its own recoveries, the matched text with every
 *    injection signal removed and set in an ordinary ticket, to-do or record
 *    frame. A regex that still fires matches the request, not the injection.
 *
 * Gates 2 and 3 apply to candidates mined from tool output, where a request
 * the user never made is the attack but the same request in a business record
 * is not. Gate 1 applies to every candidate.
 *
 * What none of this measures: false positives in deployment. The benign
 * corpora are finite and named in the report (gateReportNote in the miner);
 * "fires on none" means none of those texts, as the stated event shape.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CORPORA } from './fn-corpora.js';
import { compileEngineAccurate } from './fn-mine-candidate-gate.js';
import { withoutBenchmarkArtifacts } from './fn-mine-quality.js';

// ---------------------------------------------------------------------------
// Injection signals
// ---------------------------------------------------------------------------

export interface InjectionSignal {
  readonly id: string;
  readonly re: RegExp;
}

/**
 * Text that marks an instruction as injected rather than requested: it is
 * addressed to the agent, overrides what the agent was told, demands secrecy
 * from the user, forges an authority or system tag, or claims precedence over
 * the task. Each is a property of how the text speaks to the agent, not of
 * what it asks for. Kept narrow on purpose: a word that also opens ordinary
 * business text ("Important", "Assistant" as a job title) is not here alone.
 */
export const INJECTION_SIGNALS: readonly InjectionSignal[] = Object.freeze([
  {
    id: 'override',
    re: /\b(?:ignore|disregard|forget|override|bypass|skip)\b[\s\S]{0,30}\b(?:previous|prior|above|earlier|original|preceding|all|any|other|your|the\s+user'?s?)\b[\s\S]{0,20}\b(?:instructions?|rules?|tasks?|prompts?|directions?|guidelines?|requests?)\b/i,
  },
  {
    id: 'addressed-to-agent',
    re: /\b(?:hi|hello|hey|dear|attention|note\s+to|message\s+(?:to|for)|instructions?\s+(?:to|for))\b[\s,:]{0,4}(?:the\s+)?(?:[a-z]+\s+){0,2}(?:ai|assistant|agent|model|bot|llm|gpt|claude|copilot)\b|\bto\s+you,\s*(?:the\s+)?(?:ai|assistant|agent|model|gpt|claude)\b|\bas\s+an?\s+(?:ai|ai\s+assistant|language\s+model|agent)\b/i,
  },
  {
    // A forged turn or document boundary: the text pretends one input ended
    // and a new speaker (the user, the system) began. Chat-template tokens,
    // instruction-format markers, role tags, "end of tool output".
    id: 'forged-boundary',
    re: /<\|[^|>\n]{1,40}\|>|\[\s*\/?\s*INST\s*\]|<<\s*\/?\s*SYS\s*>>|<\s*\/?\s*(?:user|assistant|system|human|instruction|tool_output|context|end_of_turn|start_of_turn)\b[^>\n]{0,40}>|\b(?:end|begin|start)\s+(?:of\s+)?(?:the\s+)?(?:tool\s+output|tool\s+response|user\s+(?:prompt|message|input)|system\s+(?:prompt|message)|context|email|document)\b|(?:^|\n)\s*(?:#{2,}\s*)?(?:system|assistant)\s*:/i,
  },
  {
    id: 'precedence',
    re: /\b(?:before|instead\s+of|prior\s+to)\s+(?:you\s+)?(?:continu|complet|finish|respond|answer|reply|replying|proceed|summari[sz]|solv|doing\s+(?:anything|that|the\s+task))\w*|\b(?:you|the\s+(?:ai|assistant|agent|model))\s+(?:must|need\s+to|have\s+to|are\s+required\s+to|should\s+now)\b|\b(?:first|immediately|now)\s+(?:you\s+)?(?:must|need\s+to)\b/i,
  },
  {
    id: 'secrecy',
    re: /\b(?:do\s+not|don'?t|never|without)\s+(?:tell|telling|inform|informing|notify|notifying|mention|mentioning|alert|alerting|ask|asking|let|confirm|confirming)\b[\s\S]{0,12}\b(?:the\s+)?(?:user|them|anyone|customer|human|requester|owner)\b|\b(?:secretly|silently|quietly|covertly)\b|\bkeep\s+(?:this|it)\s+(?:secret|hidden|confidential)\b/i,
  },
  {
    id: 'forged-authority',
    re: /\[\s*\/?\s*(?:system|admin|administrator|instructions?|priority|important|assistant)\b[^\]\n]{0,30}\]|<\s*\/?\s*(?:system|instructions?|information|important|admin|im_start|im_end)\b[^>\n]{0,20}>|\b(?:system|admin|developer)\s+(?:prompt|message|override|instruction|update|notice)\b|\b(?:new|updated|additional|real|actual|hidden)\s+(?:instructions?|task|goal|objective)\b|\b(?:IMPORTANT|URGENT|ATTENTION)\s*(?:!{2,}|:)/i,
  },
]);

/** The signal ids found in `text`, in INJECTION_SIGNALS order. */
export function signalsIn(text: string): readonly string[] {
  return INJECTION_SIGNALS.filter((s) => s.re.test(text)).map((s) => s.id);
}

/** `text` with every injection signal removed: what is left is the request alone. */
export function withoutSignals(text: string): string {
  let out = text;
  for (const s of INJECTION_SIGNALS) {
    const global = new RegExp(s.re.source, s.re.flags.includes('g') ? s.re.flags : `${s.re.flags}g`);
    out = out.replace(global, ' ');
  }
  return out.replace(/[ \t]{2,}/g, ' ').trim();
}

/**
 * Share of a candidate's matches that must carry a signal. Not 1: a corpus
 * holds a few injections phrased as a bare request, and one of them should not
 * sink a regex that otherwise keys on the injection. Not lower: at half, a
 * regex on the request alone passes whenever the corpus wraps most requests in
 * a signal, which is how #819 passed.
 */
export const MIN_SIGNAL_SHARE = 0.8;

/** The match of `re` in each of `texts` that it matches. */
function matches(re: RegExp, texts: readonly string[]): string[] {
  const out: string[] = [];
  for (const t of texts) {
    const m = re.exec(t);
    if (m) out.push(m[0]);
  }
  return out;
}

/**
 * Why `regex` fails the injection-signal gate on `recovered` (attack texts it
 * should match), or null. Judged on the regex's own match, not the whole text:
 * a signal elsewhere in the attack does not make the regex depend on it.
 */
export function injectionSignalProblem(regex: string, recovered: readonly string[]): string | null {
  const re = compileEngineAccurate(regex);
  if (!re) return 'does not compile';
  const spans = matches(re, recovered);
  if (spans.length === 0) return 'matches none of the attacks it is said to recover';
  const withSignal = spans.filter((s) => signalsIn(s).length > 0).length;
  const share = withSignal / spans.length;
  return share >= MIN_SIGNAL_SHARE
    ? null
    : `injection signal in ${withSignal} of ${spans.length} of its matches (< ${Math.round(MIN_SIGNAL_SHARE * 100)}%): ` +
        'it matches the request an injection makes, which business systems also send, not the injection';
}

// ---------------------------------------------------------------------------
// Benign twins
// ---------------------------------------------------------------------------

/** Ordinary places a request sits in a business system's tool output. */
const TWIN_FRAMES: readonly ((request: string) => string)[] = Object.freeze([
  (r: string) => r,
  (r: string) => `Ticket #4821 (status: open)\nRequested action: ${r}\nRequester: operations team`,
  (r: string) => `To-do list for this week:\n- ${r}\n- Review the quarterly numbers`,
  (r: string) => JSON.stringify({ id: 'TASK-2207', status: 'pending', assignee: 'me', notes: r }),
]);

/**
 * Twins of `texts`: each with `corpus`'s generator wrappers and every injection
 * signal removed, in each frame. The wrappers go first: they are a generator's
 * fixed way of addressing the agent ("Hi Assistant, I forgot to mention
 * earlier ..."), so a twin that kept half of one would not be benign.
 */
export function benignTwins(texts: readonly string[], corpus = ''): readonly string[] {
  const out: string[] = [];
  for (const t of texts) {
    const request = withoutSignals(withoutBenchmarkArtifacts(corpus, t));
    if (!request) continue;
    for (const frame of TWIN_FRAMES) out.push(frame(request));
  }
  return out;
}

/**
 * Why `regex` fails its twin gate, or null: it fires on a twin of one of
 * `recovered` (attacks from `corpus`), the same words with nothing addressed
 * to the agent.
 */
export function twinProblem(regex: string, recovered: readonly string[], corpus = ''): string | null {
  const re = compileEngineAccurate(regex);
  if (!re) return 'does not compile';
  const twins = benignTwins(recovered, corpus);
  const hit = twins.find((t) => re.test(t));
  return hit === undefined
    ? null
    : `fires on a benign twin of its own recovery (signals removed): ${JSON.stringify(hit.replace(/\s+/g, ' ').slice(0, 140))}`;
}

// ---------------------------------------------------------------------------
// Out of sample
// ---------------------------------------------------------------------------

/** Attack corpora vendored for this gate only (scripts/sync-generalization-corpora.py). */
export const OOS_CORPORA: readonly { readonly id: string; readonly path: string }[] = Object.freeze([
  { id: 'agentdojo', path: 'data/fn-mine-oos/agentdojo/corpus.json' },
  { id: 'injecagent', path: 'data/fn-mine-oos/injecagent/corpus.json' },
]);

/**
 * Registry corpora never counted as out of sample: rules the repo's own
 * pipelines generated, so a hit there can be the lane meeting itself.
 */
const NOT_OUT_OF_SAMPLE = new Set(['autoresearch-adversarial', 'autoresearch-missed']);

export interface OutOfSampleCorpus {
  readonly id: string;
  readonly texts: readonly string[];
}

/** The vendored OOS corpora, or the first problem reading one. */
function readVendoredOos(root: string): { corpora: readonly OutOfSampleCorpus[] } | { problem: string } {
  const corpora: OutOfSampleCorpus[] = [];
  for (const c of OOS_CORPORA) {
    const file = join(root, c.path);
    if (!existsSync(file)) return { problem: `${c.path} is missing (run scripts/sync-generalization-corpora.py --write)` };
    const doc = JSON.parse(readFileSync(file, 'utf8')) as { count?: unknown; samples?: { text?: unknown }[] };
    const texts = (doc.samples ?? []).map((s) => s.text).filter((t): t is string => typeof t === 'string' && t.length > 0);
    if (texts.length === 0 || doc.count !== texts.length) return { problem: `${c.path} declares ${String(doc.count)} samples but holds ${texts.length}` };
    corpora.push({ id: c.id, texts });
  }
  return { corpora };
}

/**
 * Every attack corpus the gate can count out-of-sample hits on: the vendored
 * OOS corpora, which must be present, and each usable attack corpus in the
 * fn-corpora registry that loads on this machine (HackAPrompt is gitignored).
 * Which corpus a candidate was mined from is excluded per candidate.
 */
export function readOutOfSample(root: string): readonly OutOfSampleCorpus[] {
  const vendored = readVendoredOos(root);
  if ('problem' in vendored) {
    throw new Error(`the out-of-sample corpora cannot be read: ${vendored.problem}. Every candidate is gated on them; nothing was mined.`);
  }
  const registry: OutOfSampleCorpus[] = [];
  for (const def of CORPORA) {
    if (!def.usable || NOT_OUT_OF_SAMPLE.has(def.id) || !existsSync(join(root, def.path))) continue;
    const texts = def.load(root).filter((s) => s.label === 'attack').map((s) => s.text);
    if (texts.length > 0) registry.push({ id: def.id, texts });
  }
  return [...vendored.corpora, ...registry];
}

/** Out-of-sample attacks `regex` recovers, by corpus, skipping `minedFrom`. */
export function outOfSampleRecoveries(
  regex: string,
  corpora: readonly OutOfSampleCorpus[],
  minedFrom: string,
): Readonly<Record<string, number>> {
  const re = compileEngineAccurate(regex);
  if (!re) return {};
  const out: Record<string, number> = {};
  for (const c of corpora) {
    if (c.id === minedFrom) continue;
    const n = c.texts.filter((t) => re.test(t)).length;
    if (n > 0) out[c.id] = n;
  }
  return out;
}

/** At least this many out-of-sample attacks, in any corpus but the mined one. */
export const MIN_OUT_OF_SAMPLE = 1;

/** Why `regex` fails the out-of-sample gate, or null. */
export function outOfSampleProblem(regex: string, corpora: readonly OutOfSampleCorpus[], minedFrom: string): string | null {
  const hits = outOfSampleRecoveries(regex, corpora, minedFrom);
  const total = Object.values(hits).reduce((a, b) => a + b, 0);
  if (total >= MIN_OUT_OF_SAMPLE) return null;
  const names = corpora.filter((c) => c.id !== minedFrom).map((c) => c.id).join(', ');
  return `recovers no attack outside ${minedFrom} (checked: ${names}): its held-out recoveries share the mined corpus's generator`;
}

// ---------------------------------------------------------------------------
// The three gates together
// ---------------------------------------------------------------------------

export interface GeneralizationVerdict {
  readonly pass: boolean;
  /** Each failed gate's reason, keyed by gate. */
  readonly failures: Readonly<Record<string, string>>;
  /** Out-of-sample recoveries by corpus, for the report. */
  readonly outOfSample: Readonly<Record<string, number>>;
}

export interface GeneralizationInput {
  readonly regex: string;
  /** The attacks in the mined corpus the candidate matches, as the corpus holds them (signals intact). */
  readonly recovered: readonly string[];
  readonly minedFrom: string;
  /** True for a candidate mined from tool output: gates 2 and 3 apply. */
  readonly toolOutput: boolean;
}

/** Every gate's verdict on one candidate, all run so a reviewer sees each reason. */
export function generalizationVerdict(input: GeneralizationInput, oos: readonly OutOfSampleCorpus[]): GeneralizationVerdict {
  const failures: Record<string, string> = {};
  const oosProblem = outOfSampleProblem(input.regex, oos, input.minedFrom);
  if (oosProblem) failures['out-of-sample'] = oosProblem;
  if (input.toolOutput) {
    const signal = injectionSignalProblem(input.regex, input.recovered);
    if (signal) failures['injection-signal'] = signal;
    const twin = twinProblem(input.regex, input.recovered, input.minedFrom);
    if (twin) failures['benign-twin'] = twin;
  }
  return {
    pass: Object.keys(failures).length === 0,
    failures,
    outOfSample: outOfSampleRecoveries(input.regex, oos, input.minedFrom),
  };
}
