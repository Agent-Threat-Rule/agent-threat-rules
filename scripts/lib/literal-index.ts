/**
 * Multi-literal document-frequency counter (Aho-Corasick).
 *
 * WHY NOT `corpus.includes(literal)` IN A LOOP
 *   The visibility gate asks one question of ~12k distinct literals against
 *   ~32M characters of benign corpus. Naive containment is ~380 GB of scanning
 *   per run, which turns a gate into something people delete. Aho-Corasick
 *   answers all literals in a single pass over each document.
 *
 * WHAT IT REPORTS
 *   DOCUMENT frequency -- how many corpus samples contain the literal at least
 *   once -- not total occurrences. The gate's question is "how many benign
 *   samples could this rule have fired on", and one sample repeating a token
 *   forty times is still one sample it could have fired on.
 *
 * CASE
 *   Callers lowercase both the literals and the documents. This structure does
 *   no folding of its own, so it stays honest for any caller that wants exact
 *   matching later.
 */

/** Built automaton. Opaque to callers; only `patterns` is meaningful outside. */
export interface LiteralIndex {
  readonly patterns: readonly string[];
  readonly next: readonly Map<number, number>[];
  readonly fail: Int32Array;
  /** Pattern id terminating at this node, or -1. Patterns are deduplicated. */
  readonly out: Int32Array;
  /** Nearest suffix node carrying an output, or -1. */
  readonly outLink: Int32Array;
}

/** An empty literal matches everything and would poison the counts. */
function usable(p: string): boolean {
  return p.length > 0;
}

export function buildLiteralIndex(literals: readonly string[]): LiteralIndex {
  const patterns = [...new Set(literals.filter(usable))];
  const next: Map<number, number>[] = [new Map()];
  const outList: number[] = [-1];

  patterns.forEach((pattern, id) => {
    let node = 0;
    for (let i = 0; i < pattern.length; i += 1) {
      const code = pattern.charCodeAt(i);
      let child = next[node]?.get(code);
      if (child === undefined) {
        child = next.length;
        next.push(new Map());
        outList.push(-1);
        next[node]?.set(code, child);
      }
      node = child;
    }
    if (outList[node] === -1) outList[node] = id;
  });

  const size = next.length;
  const fail = new Int32Array(size);
  const out = Int32Array.from(outList);
  const outLink = new Int32Array(size).fill(-1);

  // BFS over the trie: standard goto/fail construction.
  const queue: number[] = [];
  for (const child of next[0]?.values() ?? []) {
    fail[child] = 0;
    queue.push(child);
  }
  for (let head = 0; head < queue.length; head += 1) {
    const node = queue[head] as number;
    const failNode = fail[node] as number;
    outLink[node] = out[failNode] !== -1 ? failNode : (outLink[failNode] as number);
    for (const [code, child] of next[node] ?? []) {
      let f = failNode;
      let candidate = next[f]?.get(code);
      while (candidate === undefined && f !== 0) {
        f = fail[f] as number;
        candidate = next[f]?.get(code);
      }
      fail[child] = candidate === undefined || candidate === child ? 0 : candidate;
      queue.push(child);
    }
  }

  return { patterns, next, fail, out, outLink };
}

/**
 * How many documents contain each pattern, indexed like `index.patterns`.
 *
 * A pattern seen twice in one document counts once: `seenIn` records the last
 * document id that credited a pattern, which is cheaper and less error-prone
 * than allocating a Set per document.
 */
export function documentFrequencies(
  index: LiteralIndex,
  documents: Iterable<string>,
): readonly number[] {
  const counts = new Int32Array(index.patterns.length);
  const seenIn = new Int32Array(index.patterns.length).fill(-1);
  // Hoisted: this inner loop runs once per corpus character (~32M on the ATR
  // benign corpora), so a property lookup per character is not free.
  const { next, fail, out, outLink } = index;
  let docId = 0;
  for (const doc of documents) {
    let node = 0;
    for (let i = 0; i < doc.length; i += 1) {
      const code = doc.charCodeAt(i);
      let candidate = (next[node] as Map<number, number>).get(code);
      while (candidate === undefined && node !== 0) {
        node = fail[node] as number;
        candidate = (next[node] as Map<number, number>).get(code);
      }
      node = candidate ?? 0;
      for (let hit = node; hit !== -1; hit = outLink[hit] as number) {
        const id = out[hit] as number;
        if (id === -1) continue;
        if (seenIn[id] === docId) continue;
        seenIn[id] = docId;
        counts[id] = (counts[id] as number) + 1;
      }
    }
    docId += 1;
  }
  return [...counts];
}

/** Convenience view: literal -> document frequency. */
export function frequencyMap(
  index: LiteralIndex,
  frequencies: readonly number[],
): ReadonlyMap<string, number> {
  const map = new Map<string, number>();
  index.patterns.forEach((p, i) => map.set(p, frequencies[i] ?? 0));
  return map;
}
