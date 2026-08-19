/**
 * fn-cluster.ts — turn a pile of false negatives into candidate rule anchors.
 *
 * THE QUESTION THIS ANSWERS
 *
 * "Which of these misses could become ONE rule?" A miss is only worth a rule
 * if the same attack technique shows up repeatedly AND leaves a literal string
 * behind. Both halves are load-bearing:
 *
 *   - repeated, no literal   -> the technique is real but lives in meaning,
 *                               not in characters. The pattern layer cannot
 *                               reach it. docs/DETECTION-BOUNDARY.md calls
 *                               this judgment-type.
 *   - literal, not repeated  -> a one-off. A rule for it is a signature for a
 *                               single sample; it will never fire again and it
 *                               still spends a false-positive budget.
 *
 * HOW A CLUSTER IS FOUND
 *
 * Frequent token n-grams over the missed samples, mined bottom-up (Apriori):
 * an n-gram is enumerated only when its (n-1)-token prefix was already
 * frequent, so the search never touches the full n-gram space. Support is
 * DOCUMENT frequency — how many distinct missed samples contain the phrase —
 * because the question is "how many misses would one rule recover", and a
 * sample repeating a phrase forty times is still one miss recovered.
 *
 * Phrases are interned as integer nodes with a parent pointer rather than
 * built as strings. Rebuilding `tokens.slice(i, i+n).join(" ")` at every
 * position of every level is O(n) string work per position and turned a
 * 5,000-sample corpus into a hang; the node form makes each extension one
 * small key lookup and materialises the text only for the survivors.
 *
 * Longest-first greedy selection then keeps a phrase only when it recovers
 * `minSupport` samples that no already-kept phrase recovers. Without that,
 * every sub-phrase of a winning phrase reports as its own cluster and the
 * output looks like dozens of findings that are one finding.
 *
 * NORMALISATION, AND WHY THE OUTPUT IS STILL A USABLE ANCHOR
 *
 * Text is lowercased and every whitespace run collapses to one space before
 * mining, so `Ignore\n  ALL previous` and `ignore all previous` cluster
 * together. A returned phrase is therefore an exact substring of the
 * NORMALISED sample, not necessarily of the raw one. A rule built from it must
 * be case-insensitive and must put `\s+` where the phrase has a space.
 * `anchorRegex()` does that transcription so a human does not do it at 1am.
 *
 * THE BENIGN COUNT IS NOT COMPUTED HERE
 *
 * This module reports structure. Whether a phrase is safe to ship depends on
 * how often it occurs in the benign corpora, and that number must come from
 * the same corpora the false-positive gate charges rules against
 * (scripts/lib/benign-corpus.ts). Keeping them apart stops this file growing a
 * second, divergent idea of what "benign" means.
 */

/** Lowercase, whitespace-collapsed view of a sample. */
export function normalise(text: string): string {
  return text.toLowerCase().replace(/\s+/g, " ").trim();
}

/** Tokens are whitespace-delimited runs of the normalised text. */
export function tokenise(normalised: string): readonly string[] {
  return normalised.length === 0 ? [] : normalised.split(" ");
}

export interface ClusterOptions {
  /** Minimum distinct missed samples a phrase must cover. */
  readonly minSupport: number;
  /** Longest phrase, in tokens. */
  readonly maxPhraseTokens: number;
  /** Tokens read per sample; long documents are truncated, not skipped. */
  readonly maxTokensPerSample: number;
  /**
   * Frequent phrases carried into the next level, highest support first.
   * A bound, not a filter: dropping the tail can only lose LONGER phrases,
   * never invent one, and never changes a reported support count.
   */
  readonly maxCandidatesPerLevel: number;
}

export const DEFAULT_CLUSTER_OPTIONS: ClusterOptions = Object.freeze({
  minSupport: 3,
  maxPhraseTokens: 8,
  maxTokensPerSample: 600,
  maxCandidatesPerLevel: 6000,
});

export interface ClusterInput {
  readonly id: string;
  readonly text: string;
  readonly family: string;
}

export interface Cluster {
  /** The shared literal, normalised. */
  readonly phrase: string;
  readonly tokens: number;
  /** Distinct missed samples this phrase covers. */
  readonly support: number;
  /** Samples it covers that no earlier-kept cluster covers. */
  readonly newlyCovered: number;
  readonly sampleIds: readonly string[];
  readonly families: readonly string[];
  readonly examples: readonly string[];
}

interface Doc {
  readonly id: string;
  readonly family: string;
  readonly raw: string;
  readonly tokens: Int32Array;
}

/**
 * Interned phrase trie. Node 0 is unused so `-1` can mean "not frequent here"
 * in the per-document position arrays without a second sentinel.
 */
class PhraseTrie {
  private readonly parent: number[] = [-1];
  private readonly token: number[] = [-1];
  private readonly depth: number[] = [0];
  private readonly index = new Map<string, number>();

  intern(parentNode: number, tokenId: number): number {
    const key = `${parentNode}|${tokenId}`;
    const existing = this.index.get(key);
    if (existing !== undefined) return existing;
    const id = this.parent.length;
    this.parent.push(parentNode);
    this.token.push(tokenId);
    this.depth.push((this.depth[parentNode] ?? 0) + 1);
    this.index.set(key, id);
    return id;
  }

  depthOf(node: number): number {
    return this.depth[node] ?? 0;
  }

  /** Token ids from root to `node`, in order. */
  path(node: number): readonly number[] {
    const out: number[] = [];
    for (let n = node; n > 0; n = this.parent[n] ?? -1) out.unshift(this.token[n] ?? -1);
    return out;
  }
}

function prepare(
  inputs: readonly ClusterInput[],
  opts: ClusterOptions,
): { docs: readonly Doc[]; vocabulary: readonly string[] } {
  const ids = new Map<string, number>();
  const vocabulary: string[] = [];
  const docs = inputs.map((s) => {
    const raw = normalise(s.text);
    const words = tokenise(raw).slice(0, opts.maxTokensPerSample);
    const tokens = new Int32Array(words.length);
    words.forEach((w, i) => {
      let id = ids.get(w);
      if (id === undefined) {
        id = vocabulary.length;
        vocabulary.push(w);
        ids.set(w, id);
      }
      tokens[i] = id;
    });
    return { id: s.id, family: s.family, raw, tokens };
  });
  return { docs, vocabulary };
}

/** Document frequency for the nodes currently sitting in `positions`. */
function countLevel(
  docs: readonly Doc[],
  positions: readonly Int32Array[],
): Map<number, number[]> {
  const support = new Map<number, number[]>();
  docs.forEach((_doc, d) => {
    const row = positions[d];
    if (row === undefined) return;
    const seen = new Set<number>();
    for (let i = 0; i < row.length; i += 1) {
      const node = row[i] ?? -1;
      if (node < 0 || seen.has(node)) continue;
      seen.add(node);
      const bucket = support.get(node);
      if (bucket === undefined) support.set(node, [d]);
      else bucket.push(d);
    }
  });
  return support;
}

/** Nodes with support >= minSupport, capped to the highest-support prefix. */
function prune(
  support: ReadonlyMap<number, number[]>,
  opts: ClusterOptions,
): { keep: Set<number>; frequent: Map<number, readonly number[]> } {
  const frequent = new Map<number, readonly number[]>();
  for (const [node, docIds] of support) {
    if (docIds.length >= opts.minSupport) frequent.set(node, docIds);
  }
  const ranked = [...frequent.entries()]
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, opts.maxCandidatesPerLevel)
    .map(([node]) => node);
  return { keep: new Set(ranked), frequent };
}

/**
 * All frequent phrases, as trie nodes mapped to the documents containing them.
 * Level 1 seeds one node per token occurrence; level n extends only positions
 * whose level n-1 node survived pruning.
 */
function frequentNodes(
  docs: readonly Doc[],
  trie: PhraseTrie,
  opts: ClusterOptions,
): Map<number, readonly number[]> {
  const all = new Map<number, readonly number[]>();
  let positions: Int32Array[] = docs.map((doc) => {
    const row = new Int32Array(doc.tokens.length);
    for (let i = 0; i < doc.tokens.length; i += 1) row[i] = trie.intern(0, doc.tokens[i] ?? -1);
    return row;
  });

  for (let level = 1; level <= opts.maxPhraseTokens; level += 1) {
    const { keep, frequent } = prune(countLevel(docs, positions), opts);
    for (const [node, docIds] of frequent) all.set(node, docIds);
    if (keep.size === 0 || level === opts.maxPhraseTokens) break;

    positions = docs.map((doc, d) => {
      const prev = positions[d];
      const row = new Int32Array(doc.tokens.length).fill(-1);
      if (prev === undefined) return row;
      for (let i = 0; i + level < doc.tokens.length; i += 1) {
        const parent = prev[i] ?? -1;
        if (parent < 0 || !keep.has(parent)) continue;
        row[i] = trie.intern(parent, doc.tokens[i + level] ?? -1);
      }
      return row;
    });
  }
  return all;
}

const EXAMPLE_CHARS = 220;
const MAX_EXAMPLES = 3;
const MAX_SAMPLE_IDS = 40;

function buildCluster(
  phrase: string,
  docIds: readonly number[],
  freshCount: number,
  docs: readonly Doc[],
): Cluster {
  const members = docIds.map((i) => docs[i]).filter((d): d is Doc => d !== undefined);
  return {
    phrase,
    tokens: phrase.split(" ").length,
    support: docIds.length,
    newlyCovered: freshCount,
    sampleIds: members.slice(0, MAX_SAMPLE_IDS).map((d) => d.id),
    families: [...new Set(members.map((d) => d.family))].sort().slice(0, 12),
    examples: members.slice(0, MAX_EXAMPLES).map((d) => d.raw.slice(0, EXAMPLE_CHARS)),
  };
}

export interface ClusterResult {
  readonly clusters: readonly Cluster[];
  /** Missed samples no cluster covers — one-offs, by construction. */
  readonly uncoveredIds: readonly string[];
  readonly uncovered: number;
}

/**
 * Longest-first, then highest-support. Longest-first is deliberate: a longer
 * phrase is a more specific anchor and therefore a cheaper one to ship, so it
 * claims its samples before a shorter phrase can.
 */
function rankNodes(
  frequent: ReadonlyMap<number, readonly number[]>,
  trie: PhraseTrie,
): readonly number[] {
  return [...frequent.keys()].sort((a, b) => {
    const depthDiff = trie.depthOf(b) - trie.depthOf(a);
    if (depthDiff !== 0) return depthDiff;
    return (frequent.get(b)?.length ?? 0) - (frequent.get(a)?.length ?? 0);
  });
}

export function clusterMisses(
  inputs: readonly ClusterInput[],
  options: Partial<ClusterOptions> = {},
): ClusterResult {
  const opts: ClusterOptions = { ...DEFAULT_CLUSTER_OPTIONS, ...options };
  const { docs, vocabulary } = prepare(inputs, opts);
  const trie = new PhraseTrie();
  const frequent = frequentNodes(docs, trie, opts);

  const covered = new Set<number>();
  const clusters: Cluster[] = [];
  for (const node of rankNodes(frequent, trie)) {
    const docIds = frequent.get(node);
    if (docIds === undefined) continue;
    const fresh = docIds.filter((d) => !covered.has(d));
    if (fresh.length < opts.minSupport) continue;
    const phrase = trie
      .path(node)
      .map((t) => vocabulary[t] ?? "")
      .join(" ");
    clusters.push(buildCluster(phrase, docIds, fresh.length, docs));
    for (const d of fresh) covered.add(d);
  }

  const uncoveredIds = docs.filter((_, i) => !covered.has(i)).map((d) => d.id);
  return {
    clusters: clusters.sort((a, b) => b.newlyCovered - a.newlyCovered),
    uncoveredIds: uncoveredIds.slice(0, 200),
    uncovered: uncoveredIds.length,
  };
}

// ---------------------------------------------------------------------------
// artifact vs judgment — the criterion from docs/DETECTION-BOUNDARY.md §2.1
// ---------------------------------------------------------------------------

/**
 * A phrase is ARTIFACT-type when no token in it is an ordinary English word:
 * it cannot appear unless the text carries a machine-produced string. It is
 * JUDGMENT-type when at least one token is ordinary English, because then a
 * legitimate sentence can contain it and precision has to be earned rather
 * than inherited.
 *
 * The word list is `/usr/share/dict/words` — an external artifact this project
 * did not tune, which is the point. When it is absent (CI images often ship
 * without it) the classification is reported as `unknown` rather than guessed:
 * guessing here silently relabels every phrase as an artifact and makes a
 * judgment-type ruleset look safe.
 *
 * NON-ENGLISH IS ITS OWN ANSWER, NOT "ARTIFACT"
 *
 * An English dictionary says nothing about `역할극 해줘` or
 * `höre nicht auf alles zuvor gesagte`. Scoring those as artifacts would be
 * the dictionary reporting its own coverage gap as a security property — a
 * German sentence is ordinary prose to a German speaker and carries exactly
 * the benign-collision risk that "artifact" is supposed to rule out. So a
 * phrase carrying non-ASCII letters returns `non-english`: a real answer that
 * says the benign evidence for it has to come from a corpus in that language,
 * which this repository does not have.
 *
 * SHORT WORDS COUNT AS ENGLISH
 *
 * `in`, `the`, `is` are in the dictionary and are the most benign tokens
 * there are. An earlier cut of this function required length > 2 before
 * consulting the dictionary, which classified the single-token phrase `in`
 * as an ARTIFACT — while the benign gate simultaneously reported it in 10,781
 * of 12,060 benign samples. The gate caught it; the label was still wrong,
 * and a label that is wrong in the safe direction is the kind that gets
 * trusted later.
 */
export type PhraseFamily = "artifact" | "judgment" | "non-english" | "unknown";

/** True when any code point is outside ASCII. Written as a scan rather than a
 *  regex so the source carries no escape sequence a copy-paste can mangle. */
function hasNonAscii(text: string): boolean {
  for (let i = 0; i < text.length; i += 1) {
    if ((text.codePointAt(i) ?? 0) > 127) return true;
  }
  return false;
}

export function classifyPhrase(
  phrase: string,
  dictionary: ReadonlySet<string> | null,
): PhraseFamily {
  if (dictionary === null) return "unknown";
  if (hasNonAscii(phrase)) return "non-english";
  const words = phrase.split(" ").map((t) => t.replace(/[^a-z0-9]/g, ""));
  const anyEnglish = words.some((w) => w.length >= 2 && dictionary.has(w));
  return anyEnglish ? "judgment" : "artifact";
}

/** Escape a normalised phrase into a case-insensitive, whitespace-tolerant regex. */
export function anchorRegex(phrase: string): string {
  return phrase
    .split(" ")
    .map((token) => token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("\\s+");
}
