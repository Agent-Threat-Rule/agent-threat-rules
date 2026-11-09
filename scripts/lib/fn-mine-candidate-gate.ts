/**
 * scripts/lib/fn-mine-candidate-gate.ts
 *
 * The synchronous half of the FN-mine gate (scripts/fn-mine-llm.ts): what a
 * proposed regex must do on the corpus's false negatives and on the benign
 * text corpus before it is authored. Moved out of the miner, whose main() runs
 * on import, so the gate can be tested on its own.
 *
 * The tool-output benign check, which needs the engine, runs after this one
 * (scripts/lib/fn-mine-tool-benign.ts).
 */
import type { RedosVerdict } from './semantic-redos-precheck.js';
import { needsUnicodeFlag } from '../../src/engine.js';
import { heldOutRecoveries, MIN_HELD_OUT_RECOVERS, type SeenText } from './fn-mine-heldout.js';
import { countRecoveries } from './fn-mine-recoveries.js';
import { isRuleCategory, re2Problem, visibilityProblem } from './fn-mine-quality.js';
import type { MineCandidate } from './fn-mine-reply.js';
import type { GateCorpus } from './semantic-gate.js';

// ---------------------------------------------------------------------------
// Engine-accurate regex compile (mirrors src/engine.ts's normalizeRegex + the
// auto 'iu' flag rule EXACTLY — see compilePatterns() in src/engine.ts).
// ---------------------------------------------------------------------------

function normalizeRegex(pattern: string): string {
  return pattern.replace(/^\(\?[imsx]+\)/, '');
}

export function compileEngineAccurate(value: string): RegExp | null {
  const pattern = normalizeRegex(value);
  const flags = needsUnicodeFlag(pattern) ? 'iu' : 'i';
  try {
    return new RegExp(pattern, flags);
  } catch {
    return null;
  }
}

export interface GatedCandidate extends MineCandidate {
  recovers: number;
  /** Distinct held-out texts recovered: texts the model was never shown. */
  heldOutRecovers: number;
  benignFP: number;
  /** Excerpts around the match, verbatim (countRecoveries): what the true positives are cut from. Minable texts only. */
  exampleFNs: readonly string[];
  /** The distinct minable attacks it recovers (countRecoveries keys), for pickDistinct. */
  recoveryKeys?: readonly string[];
  /** Attacks it recovers in corpora it was not mined from, by corpus (fn-mine-generalization.ts). */
  outOfSample?: Readonly<Record<string, number>>;
}

export interface GateContext {
  readonly corpusName: string;
  /** The texts recoveries are counted on: the minable FN texts with the corpus's benchmark artifacts removed. */
  readonly measureOn: readonly string[];
  /** The held-out FN texts, as the corpus holds them. Never shown to the model. */
  readonly heldOut: readonly string[];
  /** The minable side's lines (seenLines): a held-out hit on text the model was shown is not counted. */
  readonly seenLines: SeenText;
  /** MEASUREMENT_CORPORA, for the corpus visibility gate's arithmetic. */
  readonly corpus: GateCorpus;
}

type Drop = (c: MineCandidate, why: string) => void;

/** The candidate's minable recoveries, or null (with the reason logged) when it has too few. */
function minableRecoveries(
  c: MineCandidate,
  re: RegExp,
  fullFn: readonly string[],
  minRecovers: number,
  gate: GateContext,
  drop: Drop,
): { recovers: number; examples: readonly string[]; keys: readonly string[] } | null {
  // Counted on measureOn, so a regex that only recovers a benchmark's scoring
  // strings recovers nothing, and as distinct attacks, so copies of one
  // template sentence count once. Examples are excerpts of the real texts.
  const { recovers, copies, examples, keys } = countRecoveries(re, gate.measureOn, fullFn);
  if (recovers >= minRecovers) return examples.length > 0 ? { recovers, examples, keys } : null;
  if (copies >= minRecovers) {
    drop(c, `recovers ${copies} texts but only ${recovers} distinct line(s) < ${minRecovers}: copies of one template`);
  } else if (gate.measureOn !== fullFn && fullFn.filter((t) => re.test(t)).length >= minRecovers) {
    drop(c, `recovers ${recovers} < ${minRecovers} without ${gate.corpusName}'s benchmark artifacts: it keys on the benchmark's scoring strings`);
  }
  return null;
}

/** True when any benign text matches: one hit is disqualifying. */
function hitsBenign(re: RegExp, benignTexts: readonly string[]): boolean {
  return benignTexts.some((t) => Boolean(t) && re.test(t));
}

/**
 * The candidates that recover at least `minRecovers` distinct minable FN texts
 * and MIN_HELD_OUT_RECOVERS distinct held-out ones, are RE2 portable, visible
 * to the measurement corpora, and match no benign text. `fullFn` is the
 * minable FN texts as the corpus holds them.
 */
export function gateCandidates(
  candidates: readonly MineCandidate[],
  fullFn: readonly string[],
  benignTexts: readonly string[],
  minRecovers: number,
  gate: GateContext,
): GatedCandidate[] {
  const survivors: GatedCandidate[] = [];
  const drop: Drop = (c, why) => console.log(`[fn-mine]   drop ${c.cluster}: ${why}`);
  for (const c of candidates) {
    if (!isRuleCategory(c.category)) { drop(c, `unknown category ${JSON.stringify(c.category)}`); continue; }
    const re = compileEngineAccurate(c.regex);
    if (!re) continue; // invalid-after-engine-normalize — drop silently, logged by caller if desired
    // The PR's RE2 portability gate compiles every regex with Go's regexp.
    const re2 = re2Problem(c.regex);
    if (re2) { drop(c, re2); continue; }
    const minable = minableRecoveries(c, re, fullFn, minRecovers, gate, drop);
    if (!minable) continue;
    const heldOutRecovers = heldOutRecoveries(re, gate.heldOut, gate.corpusName, gate.seenLines);
    if (heldOutRecovers < MIN_HELD_OUT_RECOVERS) {
      drop(c, `recovers ${minable.recovers} shown texts but ${heldOutRecovers} held-out (< ${MIN_HELD_OUT_RECOVERS} of ${gate.heldOut.length}): it does not reach texts the model never saw`);
      continue;
    }
    const visibility = visibilityProblem(c.regex, gate.corpus);
    if (visibility) { drop(c, visibility); continue; }
    if (hitsBenign(re, benignTexts)) continue;
    survivors.push({
      ...c,
      recovers: minable.recovers,
      heldOutRecovers,
      benignFP: 0,
      exampleFNs: minable.examples,
      recoveryKeys: minable.keys,
    });
  }
  return survivors;
}

/**
 * `survivors` whose regex passes scripts/gate-redos.py on its own
 * (`precheck`, semantic-redos-precheck.ts in the lane). The authored rule's
 * one condition is the candidate's regex (gatedDetection), so this is the
 * verdict the workflow's ReDoS gate will give. Before 2026-11-08 the lane did
 * not run it: one slow regex (actions run 42447405455, ATR-2026-02880) failed
 * that gate for the whole batch of ten. Checked before pickDistinct, so a
 * dropped regex frees its place and does not displace an overlapping one.
 *
 * A precheck that runs out of time drops that one regex: the script kills a
 * single slow search in seconds, so a whole run out of time is the pattern,
 * not the machine. A precheck that cannot run at all (no yaml, no python)
 * throws: authoring blind would sink the batch again, for every regex alike.
 */
export function dropBacktracking<T extends GatedCandidate>(
  survivors: readonly T[],
  precheck: (regex: string) => RedosVerdict,
): { readonly kept: T[]; readonly dropped: number } {
  let dropped = 0;
  const kept = survivors.filter((s) => {
    const v = precheck(s.regex);
    const timedOut = v.kind === 'unavailable' && /ETIMEDOUT/.test(v.detail);
    if (v.kind === 'unavailable' && !timedOut) throw new Error(`ReDoS precheck could not run on ${s.cluster}: ${v.detail}`);
    if (v.kind === 'backtracks' || timedOut) {
      console.log(
        `[fn-mine]   drop ${s.cluster}: ${timedOut ? 'the ReDoS precheck ran out of time on it' : 'backtracks catastrophically under scripts/gate-redos.py'}`,
      );
      dropped += 1;
      return false;
    }
    return true;
  });
  return { kept, dropped };
}

/**
 * Survivors worth authoring, best first: ranked by recoveries, each kept only
 * when it recovers at least `minRecovers` attacks of its corpus that no
 * survivor kept before it does. Round 1 and the residual round both propose
 * for the same clusters, so two regexes worded differently can recover the
 * same attacks; authoring both doubles a reviewer's work for no recall (the
 * 2026-11-08 run wrote two job-offer, two appointment-cancellation and two
 * referral rules). A survivor without keys falls back to the exact-regex
 * check. `dropped` says why each one went.
 */
export function pickDistinct<T extends GatedCandidate & { readonly corpus: string }>(
  survivors: readonly T[],
  minRecovers: number,
): { readonly kept: readonly T[]; readonly dropped: readonly { readonly candidate: T; readonly why: string }[] } {
  const covered = new Map<string, Set<string>>();
  const regexes = new Set<string>();
  const kept: T[] = [];
  const dropped: { candidate: T; why: string }[] = [];
  for (const s of [...survivors].sort((a, b) => b.recovers - a.recovers)) {
    const regex = s.regex.trim();
    if (regexes.has(regex)) {
      dropped.push({ candidate: s, why: 'same regex as a survivor ranked above it' });
      continue;
    }
    const seen = covered.get(s.corpus) ?? new Set<string>();
    const fresh = (s.recoveryKeys ?? []).filter((k) => !seen.has(k));
    if (s.recoveryKeys && fresh.length < minRecovers) {
      dropped.push({ candidate: s, why: `only ${fresh.length} of its ${s.recovers} recoveries are new beyond the survivors ranked above it (< ${minRecovers})` });
      continue;
    }
    regexes.add(regex);
    covered.set(s.corpus, new Set([...seen, ...fresh]));
    kept.push(s);
  }
  return { kept, dropped };
}

/** The FN texts no survivor matches: what the residual round mines. */
export function computeResidual(fullFn: readonly string[], survivors: readonly GatedCandidate[]): string[] {
  const compiled = survivors.map((s) => compileEngineAccurate(s.regex)).filter((r): r is RegExp => r !== null);
  return fullFn.filter((t) => !compiled.some((re) => re.test(t)));
}
