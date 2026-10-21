/**
 * The base side of a delta re-measure (scripts/remeasure-benign-fp.ts): the
 * committed evidence at a base commit, the corpus that evidence describes, and
 * how the head corpus differs from it.
 *
 * Everything here exists to answer one question before a single rule runs: is
 * "the committed count plus what the new samples add" the same number a full
 * measurement would produce? It is only when the evidence describes exactly
 * the base corpus (digest, corpora, shapes, sample count) and the head corpus
 * holds every base sample. Anything else is FullMeasurementRequired, and the
 * caller writes nothing.
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { join, relative } from "node:path";
import { corpusDigest, MEASUREMENT_CORPORA } from "../../src/quality/action-eligibility.js";
import { shapeNames } from "./corpus-event.js";
import { loadCorpusRecords, loadCorpusTexts, type CorpusRecord } from "./benign-corpus.js";
import { sanitizeInline } from "./fp-attribution.js";
import { load as parseYaml } from "js-yaml";
import { isInert } from "../gate-action-eligibility.js";

export const EVIDENCE_PATH = "data/benign-fp-measurement.json";

export class RemeasureUsageError extends Error {}
/** The base evidence cannot be extended; only a full measurement can produce evidence. */
export class FullMeasurementRequired extends Error {}
/** Two independent counts of the same thing disagree. */
export class Inconsistent extends Error {}

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

export const isObj = (v: unknown): v is Readonly<Record<string, unknown>> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
export const isCount = (v: unknown): v is number => Number.isInteger(v) && (v as number) >= 0;
export const sameList = (a: readonly unknown[], b: readonly unknown[]): boolean =>
  a.length === b.length && a.every((x, i) => x === b[i]);
export const currentShapes = (): readonly string[] => [...shapeNames(), "skill"];

export function countTexts(texts: readonly string[]): ReadonlyMap<string, number> {
  const counts = new Map<string, number>();
  for (const t of texts) counts.set(t, (counts.get(t) ?? 0) + 1);
  return counts;
}

export function sameMultiset(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const counts = new Map(countTexts(a));
  for (const t of b) {
    const n = counts.get(t) ?? 0;
    if (n === 0) return false;
    counts.set(t, n - 1);
  }
  return true;
}

/** head minus base, as multisets: which head samples the base does not account for. */
export function subtractSamples(
  head: readonly string[],
  base: readonly string[],
): { readonly added: readonly string[]; readonly missing: readonly string[] } {
  const unclaimed = new Map(countTexts(base));
  const added: string[] = [];
  for (const t of head) {
    const n = unclaimed.get(t) ?? 0;
    if (n > 0) unclaimed.set(t, n - 1);
    else added.push(t);
  }
  const missing = [...unclaimed].flatMap(([t, n]) => Array.from({ length: n }, () => t));
  return { added, missing };
}

export const digestOf = (root: string): string =>
  corpusDigest(root, MEASUREMENT_CORPORA, { existsSync, readdirSync, statSync, readFileSync }, { join, relative }, createHash);

// ---------------------------------------------------------------------------
// Git
// ---------------------------------------------------------------------------

/** Runs git; `input` goes to its stdin, and `encoding` decodes its stdout (default utf-8). */
export type Git = (args: readonly string[], input?: string, encoding?: BufferEncoding) => string;

export function gitIn(root: string): Git {
  return (args, input, encoding = "utf-8") =>
    execFileSync("git", [...args], {
      cwd: root,
      encoding,
      input,
      maxBuffer: 256 * 1024 * 1024,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
}

function resolveBase(git: Git, ref: string): string {
  try {
    return git(["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]).trim();
  } catch {
    throw new RemeasureUsageError(`--base-ref ${ref} does not resolve to a commit`);
  }
}

/** The base corpora exactly as committed, under `dir`, at the paths the digest names. */
function materializeBase(git: Git, commit: string, dir: string): void {
  mkdirSync(dir, { recursive: true });
  const present = MEASUREMENT_CORPORA.filter((c) => {
    try {
      git(["cat-file", "-e", `${commit}:${c}`]);
      return true;
    } catch {
      return false;
    }
  });
  if (present.length === 0) return;
  const tar = `${dir}.tar`;
  git(["archive", "--format=tar", "-o", tar, commit, "--", ...present]);
  execFileSync("tar", ["-xf", tar, "-C", dir], { stdio: ["ignore", "pipe", "pipe"] });
}

/**
 * Rule ids that, at `commit`, only draft, deprecated or deprecated-maturity
 * rule files carry: rules the engine skipped there, decided as the action gate
 * decides it (isInert). An older gate-promotion-fp.ts still wrote each of them
 * a 0 it never measured, so a base record for one of these ids is not a count
 * the delta may extend.
 *
 * Read from the raw blobs (ls-tree, cat-file), as the base evidence is, so no
 * export-ignore or other attribute can hide a rule file. What cannot be read
 * that way is an error, never a rule that was not there.
 */
export function inertRuleIdsAt(git: Git, commit: string): ReadonlySet<string> {
  const entries = git(["ls-tree", "-r", "-z", commit, "--", "rules"])
    .split("\0")
    .filter((e) => e.length > 0)
    .map((e) => {
      const m = /^(\d{6}) (\w+) ([0-9a-f]+)\t(.*)$/s.exec(e);
      if (m === null) throw new Error(`unexpected git ls-tree entry: ${JSON.stringify(e.slice(0, 120))}`);
      return { mode: m[1] ?? "", type: m[2] ?? "", sha: m[3] ?? "", path: m[4] ?? "" };
    })
    .filter((e) => /\.ya?ml$/.test(e.path));
  const unreadable = entries.find((e) => e.type !== "blob" || e.mode === "120000");
  if (unreadable !== undefined) {
    throw new FullMeasurementRequired(
      `${unreadable.path} at ${commit.slice(0, 12)} is a ${unreadable.mode === "120000" ? "symlink" : unreadable.type}; ` +
        `the delta reads base rules as plain files only`,
    );
  }
  if (entries.length === 0) return new Set();
  // latin1 keeps one char per byte, so the sizes cat-file reports are offsets.
  const out = git(["cat-file", "--batch"], `${entries.map((e) => e.sha).join("\n")}\n`, "latin1");
  const all = new Set<string>();
  const live = new Set<string>();
  let at = 0;
  for (const e of entries) {
    const eol = out.indexOf("\n", at);
    const header = /^([0-9a-f]+) blob (\d+)$/.exec(out.slice(at, eol));
    if (eol < 0 || header === null || header[1] !== e.sha) {
      throw new Error(`git cat-file could not read ${e.path} at ${commit.slice(0, 12)}`);
    }
    const size = Number(header[2]);
    const text = Buffer.from(out.slice(eol + 1, eol + 1 + size), "latin1").toString("utf-8");
    at = eol + 1 + size + 1;
    let doc: unknown;
    try {
      doc = parseYaml(text);
    } catch {
      continue; // as readRules: a file that does not parse is not a rule the gate reads
    }
    const r = doc as { id?: unknown; status?: unknown; maturity?: unknown } | null;
    if (typeof r?.id !== "string") continue;
    all.add(r.id);
    if (!isInert(r.status, r.maturity)) live.add(r.id);
  }
  return new Set([...all].filter((id) => !live.has(id)));
}

// ---------------------------------------------------------------------------
// Base and head
// ---------------------------------------------------------------------------

export interface BaseRecord {
  readonly fp_count: unknown;
  readonly detection_fingerprint: unknown;
}

export interface BaseEvidence {
  readonly digest: string;
  readonly corpora: readonly unknown[];
  readonly shapes: readonly unknown[];
  readonly sampleCount: number;
  readonly rules: ReadonlyMap<string, BaseRecord>;
}

function readBaseEvidence(git: Git, commit: string): BaseEvidence {
  let doc: unknown;
  try {
    // cat-file, not show: the raw blob, with no textconv or other filter between it and the parse.
    doc = JSON.parse(git(["cat-file", "blob", `${commit}:${EVIDENCE_PATH}`]));
  } catch {
    throw new FullMeasurementRequired(`the base has no readable ${EVIDENCE_PATH}`);
  }
  if (
    !isObj(doc) ||
    typeof doc.corpus_digest !== "string" ||
    !Array.isArray(doc.corpora) ||
    !Array.isArray(doc.shapes) ||
    !isCount(doc.sample_count) ||
    !isObj(doc.rules)
  ) {
    throw new FullMeasurementRequired(`the base ${EVIDENCE_PATH} is not in the format a measurement writes`);
  }
  const rules = new Map(
    Object.entries(doc.rules).map(([id, r]): [string, BaseRecord] => [
      id,
      isObj(r) ? { fp_count: r.fp_count, detection_fingerprint: r.detection_fingerprint } : { fp_count: null, detection_fingerprint: null },
    ]),
  );
  return { digest: doc.corpus_digest, corpora: doc.corpora, shapes: doc.shapes, sampleCount: doc.sample_count, rules };
}

export interface Corpus {
  readonly records: readonly CorpusRecord[];
  readonly texts: readonly string[];
}

/** Records for provenance, texts for counting; the two loaders must agree text for text. */
export function readCorpus(root: string, label: string): Corpus {
  const records = MEASUREMENT_CORPORA.flatMap((c) => loadCorpusRecords(root, c));
  const texts = MEASUREMENT_CORPORA.flatMap((c) => loadCorpusTexts(join(root, c)));
  if (!sameList(records.map((r) => r.text), texts)) {
    throw new Inconsistent(`the ${label} corpus reads differently through loadCorpusRecords and loadCorpusTexts`);
  }
  return { records, texts };
}

export interface Base {
  readonly commit: string;
  readonly evidence: BaseEvidence;
  readonly corpus: Corpus;
  /** Ids the engine skipped at the base commit (inertRuleIdsAt). */
  readonly inertRuleIds: ReadonlySet<string>;
}

export function loadBase(git: Git, ref: string, dir: string): Base {
  const commit = resolveBase(git, ref);
  const evidence = readBaseEvidence(git, commit);
  if (!sameList(evidence.corpora, MEASUREMENT_CORPORA)) {
    throw new FullMeasurementRequired(
      `the base evidence was measured on ${JSON.stringify(evidence.corpora)}, not ${JSON.stringify(MEASUREMENT_CORPORA)}`,
    );
  }
  if (!sameList(evidence.shapes, currentShapes())) {
    throw new FullMeasurementRequired(
      `the base evidence was measured on shapes ${JSON.stringify(evidence.shapes)}, not ${JSON.stringify(currentShapes())}`,
    );
  }
  materializeBase(git, commit, dir);
  const digest = digestOf(dir);
  if (digest !== evidence.digest) {
    throw new FullMeasurementRequired(
      `the base evidence does not describe the base corpus (it records digest ${evidence.digest}; ` +
        `the corpus at ${commit.slice(0, 12)} hashes to ${digest})`,
    );
  }
  const corpus = readCorpus(dir, "base");
  if (corpus.texts.length !== evidence.sampleCount) {
    throw new FullMeasurementRequired(
      `the base evidence counts ${evidence.sampleCount} samples; the base corpus holds ${corpus.texts.length}`,
    );
  }
  return { commit, evidence, corpus, inertRuleIds: inertRuleIdsAt(git, commit) };
}

export function addedSamples(head: Corpus, base: Corpus): readonly string[] {
  const { added, missing } = subtractSamples(head.texts, base.texts);
  if (missing.length > 0) {
    const example = sanitizeInline(missing[0] ?? "", 80);
    throw new FullMeasurementRequired(
      `${missing.length} base sample(s) are no longer in the corpus, removed or edited ` +
        `(for example "${example}"); a count cannot be reduced by a delta`,
    );
  }
  return added;
}

/**
 * Head records that are new relative to the base, by text. A head record is
 * old when the base has the same file with the same line in it, counted as a
 * multiset, so a duplicated text points at the copy the harvest added.
 */
export function newRecordsByText(head: Corpus, base: Corpus): ReadonlyMap<string, readonly CorpusRecord[]> {
  const key = (r: CorpusRecord): string => `${r.file}\u0000${r.raw}`;
  const old = new Map(countTexts(base.records.map(key)));
  const out = new Map<string, CorpusRecord[]>();
  for (const r of head.records) {
    const n = old.get(key(r)) ?? 0;
    if (n > 0) {
      old.set(key(r), n - 1);
      continue;
    }
    const list = out.get(r.text) ?? [];
    list.push(r);
    out.set(r.text, list);
  }
  return out;
}
