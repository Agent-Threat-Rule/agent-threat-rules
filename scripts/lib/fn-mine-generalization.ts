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
 *    a corpus it was not mined from (every corpus under data/fn-mine-oos,
 *    listed in fn-mine-oos.ts, plus every other usable attack corpus in
 *    fn-corpora.ts).
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
 * All three gates apply to every candidate. Until 2026-11-09 gates 2 and 3
 * ran on tool-output candidates only, and two rules mined from user-input
 * corpora (PR #828) keyed on phrasing a colleague uses ("taking over as",
 * "decode ... then follow it") passed. A user-input candidate is judged
 * against USER_INPUT_SIGNALS (persona reassignment, a request for the
 * model's own configuration, refusal suppression, plus every tool-output
 * signal) and its twins sit in message and meeting-note frames.
 *
 * What none of this measures: false positives in deployment. The benign
 * corpora are finite and named in the report (gateReportNote in the miner);
 * "fires on none" means none of those texts, as the stated event shape.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CORPORA } from './fn-corpora.js';
import { compileEngineAccurate } from './fn-mine-candidate-gate.js';
import { OOS_SOURCES, readOosTexts } from './fn-mine-oos.js';
import { withoutBenchmarkArtifacts, withoutScoringStrings } from './fn-mine-quality.js';

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

/**
 * What marks a user turn, rather than a tool output, as an attack on the
 * model: on top of INJECTION_SIGNALS, the text reassigns the model's persona,
 * asks for its own configuration, or demands it drop its refusals. Each is
 * about the model's own behaviour; a request a colleague could make of a
 * person ("take over as interim CFO", "decode the config and follow it") is
 * not here. Added 2026-11-09 after PR #828: two rules mined from user-input
 * corpora passed every gate and fired on 3 of 7 ordinary business sentences,
 * because gates 2 and 3 ran on tool-output candidates only.
 */
export const USER_INPUT_SIGNALS: readonly InjectionSignal[] = Object.freeze([
  ...INJECTION_SIGNALS,
  {
    id: 'persona-reassignment',
    re: /\byou\s+are\s+(?:now|no\s+longer)\b|\bfrom\s+now\s+on,?\s+(?:you|act|respond|answer)\b|\bpretend\s+(?:to\s+be|that\s+you|you(?:'re|\s+are))\b|\b(?:act|behave|respond|answer)\s+as\s+(?:if\s+you\s+(?:were|are|had)|an?\s+(?:unrestricted|unfiltered|uncensored|jailbroken|evil|rogue))\b|\b(?:role-?play)\s+as\b|\byou\s+will\s+(?:now\s+)?(?:act|respond|answer|reply)\s+as\b|\bstay\s+in\s+character\b/i,
  },
  {
    id: 'model-config-request',
    re: /\b(?:your|the)\s+(?:system\s+(?:prompt|message|instructions?)|initial\s+(?:prompt|instructions?)|hidden\s+(?:prompt|instructions?|rules)|original\s+(?:prompt|instructions?)|pre-?prompt)\b|\b(?:repeat|print|reveal|output|recite)\s+(?:all\s+)?(?:of\s+)?(?:your\s+(?:instructions|prompt|rules)|the\s+(?:text|words)\s+above)\b|\byour\s+(?:own\s+)?(?:instructions|guidelines|programming)\b/i,
  },
  {
    id: 'refusal-suppression',
    re: /\b(?:never|don'?t|do\s+not|without)\s+(?:refus|apologi[sz]|add(?:ing)?\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?))\w*|\b(?:no|without\s+any)\s+(?:restrictions|filters|censorship|ethical\s+(?:guidelines|constraints))\b|\b(?:unrestricted|unfiltered|uncensored|jailbr(?:oken|eak)|developer\s+mode)\b|\bdo\s+anything\s+now\b/i,
  },
]);

/** The signals that mark an attack in `shape`'s input. */
export function signalsFor(shape: 'tool_response' | 'llm_input'): readonly InjectionSignal[] {
  return shape === 'tool_response' ? INJECTION_SIGNALS : USER_INPUT_SIGNALS;
}

/** The signal ids found in `text`, in list order. */
export function signalsIn(text: string, signals: readonly InjectionSignal[] = INJECTION_SIGNALS): readonly string[] {
  return signals.filter((s) => s.re.test(text)).map((s) => s.id);
}

/** `text` with every injection signal removed: what is left is the request alone. */
export function withoutSignals(text: string, signals: readonly InjectionSignal[] = INJECTION_SIGNALS): string {
  let out = text;
  for (const s of signals) {
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
export function injectionSignalProblem(
  regex: string,
  recovered: readonly string[],
  signals: readonly InjectionSignal[] = INJECTION_SIGNALS,
): string | null {
  const re = compileEngineAccurate(regex);
  if (!re) return 'does not compile';
  const spans = matches(re, recovered);
  if (spans.length === 0) return 'matches none of the attacks it is said to recover';
  const withSignal = spans.filter((s) => signalsIn(s, signals).length > 0).length;
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

/** Ordinary places the same words sit in a message one person sends another. */
const USER_TWIN_FRAMES: readonly ((request: string) => string)[] = Object.freeze([
  (r: string) => r,
  (r: string) => `Hi team, quick one before Friday: ${r} Thanks!`,
  (r: string) => `Meeting notes, ops sync\n- ${r}\n- Next sync on Tuesday`,
  (r: string) => `Can you help me write a reply to my manager? Context: ${r}`,
]);

/**
 * Twins of `texts`: each with `corpus`'s generator wrappers and every injection
 * signal removed, in each frame of `shape`. The wrappers go first: they are a
 * generator's fixed way of addressing the agent ("Hi Assistant, I forgot to
 * mention earlier ..."), so a twin that kept half of one would not be benign.
 */
export function benignTwins(
  texts: readonly string[],
  corpus = '',
  shape: 'tool_response' | 'llm_input' = 'tool_response',
): readonly string[] {
  const frames = shape === 'tool_response' ? TWIN_FRAMES : USER_TWIN_FRAMES;
  const out: string[] = [];
  for (const t of texts) {
    const request = withoutSignals(withoutBenchmarkArtifacts(corpus, t), signalsFor(shape));
    if (!request) continue;
    for (const frame of frames) out.push(frame(request));
  }
  return out;
}

/**
 * Why `regex` fails its twin gate, or null: it fires on a twin of one of
 * `recovered` (attacks from `corpus`), the same words with nothing addressed
 * to the agent.
 */
export function twinProblem(
  regex: string,
  recovered: readonly string[],
  corpus = '',
  shape: 'tool_response' | 'llm_input' = 'tool_response',
): string | null {
  const re = compileEngineAccurate(regex);
  if (!re) return 'does not compile';
  const twins = benignTwins(recovered, corpus, shape);
  const hit = twins.find((t) => re.test(t));
  return hit === undefined
    ? null
    : `fires on a benign twin of its own recovery (signals removed): ${JSON.stringify(hit.replace(/\s+/g, ' ').slice(0, 140))}`;
}

// ---------------------------------------------------------------------------
// Out of sample
// ---------------------------------------------------------------------------

/**
 * The vendored attack corpora under data/fn-mine-oos (scripts/lib/fn-mine-oos.ts
 * lists them and which sync script writes each). They began as this gate's
 * evidence only; since every one is also mined, a corpus counts here for every
 * rule except those mined from itself (outOfSampleRecoveries skips minedFrom).
 * Each SOURCE.md names the pinned upstream and license.
 */
export const OOS_CORPORA: readonly { readonly id: string; readonly path: string }[] = Object.freeze(
  OOS_SOURCES.map((s) => Object.freeze({ id: s.id, path: s.path })),
);

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
  for (const source of OOS_SOURCES) {
    const read = readOosTexts(root, source);
    if ('problem' in read) return { problem: read.problem };
    corpora.push({ id: source.id, texts: read.texts.map((t) => withoutScoringStrings(source.id, t)) });
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
  const vendoredIds = new Set(vendored.corpora.map((c) => c.id));
  for (const def of CORPORA) {
    if (!def.usable || NOT_OUT_OF_SAMPLE.has(def.id) || vendoredIds.has(def.id) || !existsSync(join(root, def.path))) continue;
    const texts = def
      .load(root)
      .filter((s) => s.label === 'attack')
      .map((s) => withoutScoringStrings(def.id, s.text));
    if (texts.length > 0) registry.push({ id: def.id, texts });
  }
  return [...vendored.corpora, ...registry];
}

/**
 * Characters of a sample, case- and whitespace-folded, that identify it across
 * corpora. Public jailbreak and injection sets republish each other (93% of
 * jailbreak-cls is in in-the-wild-jailbreak; half of deepset is in
 * multilingual-pi), and a republished template often differs only in the
 * question at its end. A sample whose opening matches one in the mined corpus
 * is the mined sample again, not out-of-sample evidence.
 */
const SAMPLE_KEY_CHARS = 200;
function sampleKey(text: string): string {
  return text.toLowerCase().replace(/\s+/g, ' ').trim().slice(0, SAMPLE_KEY_CHARS);
}

/**
 * Corpora built from another corpus's attacks, so neither is out of sample for
 * the other. sampleKey catches a republished text; these hold the same payload
 * inside different text. k8s-resource-pi plants neuralchemy-pi's injections in
 * Kubernetes manifests (its builder says so); garak-full's dan and inthewild
 * probes are the TrustAIRLab jailbreak collection and its promptinject probe is
 * PromptInject; deepset is half of multilingual-pi.
 */
const DERIVED_FROM: readonly (readonly string[])[] = Object.freeze([
  ['k8s-resource-pi', 'neuralchemy-pi'],
  ['garak-full', 'in-the-wild-jailbreak', 'jailbreak-cls', 'promptinject'],
  ['deepset', 'multilingual-pi'],
]);

/** `minedFrom` and every corpus that shares its attacks by construction. */
export function sameFamily(minedFrom: string): ReadonlySet<string> {
  const out = new Set([minedFrom]);
  for (const group of DERIVED_FROM) if (group.includes(minedFrom)) for (const id of group) out.add(id);
  return out;
}

/**
 * Out-of-sample attacks `regex` recovers, by corpus, skipping `minedFrom`, the
 * corpora derived from it or it from them (sameFamily), and any sample
 * elsewhere that `minedFrom` also holds (sampleKey).
 */
export function outOfSampleRecoveries(
  regex: string,
  corpora: readonly OutOfSampleCorpus[],
  minedFrom: string,
): Readonly<Record<string, number>> {
  const re = compileEngineAccurate(regex);
  if (!re) return {};
  const mined = new Set(corpora.find((c) => c.id === minedFrom)?.texts.map(sampleKey) ?? []);
  const family = sameFamily(minedFrom);
  const out: Record<string, number> = {};
  for (const c of corpora) {
    if (family.has(c.id)) continue;
    const n = c.texts.filter((t) => !mined.has(sampleKey(t)) && re.test(t)).length;
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
  const family = sameFamily(minedFrom);
  const names = corpora.filter((c) => !family.has(c.id)).map((c) => c.id).join(', ');
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
  /** The event shape the candidate was mined from; it picks the signal list and the twin frames. */
  readonly shape: 'tool_response' | 'llm_input';
}

/** Every gate's verdict on one candidate, all run so a reviewer sees each reason. */
export function generalizationVerdict(input: GeneralizationInput, oos: readonly OutOfSampleCorpus[]): GeneralizationVerdict {
  const failures: Record<string, string> = {};
  const oosProblem = outOfSampleProblem(input.regex, oos, input.minedFrom);
  if (oosProblem) failures['out-of-sample'] = oosProblem;
  const signal = injectionSignalProblem(input.regex, input.recovered, signalsFor(input.shape));
  if (signal) failures['injection-signal'] = signal;
  const twin = twinProblem(input.regex, input.recovered, input.minedFrom, input.shape);
  if (twin) failures['benign-twin'] = twin;
  return {
    pass: Object.keys(failures).length === 0,
    failures,
    outOfSample: outOfSampleRecoveries(input.regex, oos, input.minedFrom),
  };
}

// ---------------------------------------------------------------------------
// Benign user input
// ---------------------------------------------------------------------------

/** Hand-written work requests (role handovers, decode-then-follow, ...); see its SOURCE.md. */
export const USER_INPUT_BENIGN = 'data/fn-mine-benign/user-input-business/corpus.json';

/**
 * The benign user-input texts every candidate must not fire on. A missing or
 * short file throws: the gate would otherwise pass a regex on a colleague's
 * request again.
 */
export function readUserInputBenign(root: string): readonly string[] {
  const file = join(root, USER_INPUT_BENIGN);
  if (!existsSync(file)) throw new Error(`${USER_INPUT_BENIGN} is missing: the user-input benign check cannot run`);
  const doc = JSON.parse(readFileSync(file, 'utf8')) as { count?: number; samples?: { text?: unknown }[] };
  const texts = (doc.samples ?? []).map((s) => s.text).filter((t): t is string => typeof t === 'string');
  if (texts.length === 0 || texts.length !== doc.count) {
    throw new Error(`${USER_INPUT_BENIGN} declares ${doc.count} samples but ${texts.length} read`);
  }
  return texts;
}
