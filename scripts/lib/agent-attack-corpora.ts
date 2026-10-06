/**
 * scripts/lib/agent-attack-corpora.ts
 *
 * The pure half of scripts/sync-agent-attack-corpora.ts: which upstream rows
 * become a vendored corpus row, in what order, and what the corpus file and its
 * SOURCE.md say. No network here, so every decision below is unit-tested on real
 * rows (tests/agent-attack-corpora.test.ts).
 *
 * Both corpora reach an agent as TOOL OUTPUT, not as user input: an LLMail
 * email is what the mail tool returns when the user asks for a summary, and a
 * BrowseSafe page is what the browser tool returns. scripts/lib/fn-corpora.ts
 * records that shape; the FN-mine lane judges coverage on it.
 */
import { createHash } from 'node:crypto';

// ---------------------------------------------------------------------------
// Pinned upstream sources
// ---------------------------------------------------------------------------

export interface UpstreamDataset {
  /** Corpus id, and the directory under data/test-corpora/. */
  readonly id: string;
  /** Hugging Face dataset repo. */
  readonly repo: string;
  /** The commit every file is read at. */
  readonly revision: string;
  /** The SPDX id the dataset card must declare, or the sync refuses to vendor. */
  readonly license: string;
}

export const LLMAIL: UpstreamDataset = Object.freeze({
  id: 'llmail-inject',
  repo: 'microsoft/llmail-inject-challenge',
  revision: '1063bdf01ec8762b812d5e06ee768a06faa5a6f7',
  license: 'mit',
});

export const BROWSESAFE: UpstreamDataset = Object.freeze({
  id: 'browsesafe-bench',
  repo: 'perplexity-ai/browsesafe-bench',
  revision: 'b506fb5bc7fd4472c8738055a67a0ef6406afdc9',
  license: 'mit',
});

/**
 * Evaluated and NOT vendored. The card's front matter says `license: other`;
 * its README says "License: MIT"; the LICENSE file it ships restricts use to
 * non-commercial research and forbids redistribution for other purposes. ATR is
 * MIT and redistributes its corpora, so the restrictive file governs.
 */
export const NOT_VENDORED: readonly { readonly repo: string; readonly revision: string; readonly reason: string }[] =
  Object.freeze([
    {
      repo: 'Lakera/b3-agent-security-benchmark-weak',
      revision: '063fc4ab3eb697a7961df6ef37cf521e1bf6b649',
      reason:
        'card front matter `license: other`; LICENSE file: research purposes only, non-commercial, ' +
        'no redistribution for non-research purposes',
    },
  ]);

/** Upper bound on rows per corpus; the file-size budget can stop a corpus earlier. */
export const MAX_ROWS = 3000;
/** Each corpus.json stays under 5 MB; this leaves room for JSON escaping. */
export const MAX_CORPUS_BYTES = 4_500_000;

/** The front-matter `license:` line of a dataset card, or null. */
export function cardLicenseLine(readme: string): string | null {
  const front = /^---\n([\s\S]*?)\n---/.exec(readme);
  const line = front?.[1].split('\n').find((l) => /^license:/.test(l.trim()));
  return line?.trim() ?? null;
}

/** Why the card's license does not permit vendoring, or null when it does. */
export function licenseProblem(readme: string, expected: string): string | null {
  const line = cardLicenseLine(readme);
  if (line === null) return 'the dataset card declares no license';
  return line === `license: ${expected}` ? null : `the dataset card declares "${line}", not "license: ${expected}"`;
}

// ---------------------------------------------------------------------------
// Shared row handling
// ---------------------------------------------------------------------------

export interface CorpusRow {
  readonly text: string;
  /** The upstream taxonomy, verbatim (LLMail: phase/level). */
  readonly family: string;
}

const sha256 = (s: string): string => createHash('sha256').update(s).digest('hex');

/**
 * At most `max` rows, spread across families: each family in content-hash
 * order, then one row from each family in turn. Deterministic for a given input
 * set whatever order the upstream file lists it in.
 */
export function stratifiedSample(rows: readonly CorpusRow[], max: number): readonly CorpusRow[] {
  const byFamily = new Map<string, CorpusRow[]>();
  for (const r of rows) byFamily.set(r.family, [...(byFamily.get(r.family) ?? []), r]);
  const queues = [...byFamily.keys()]
    .sort()
    .map((f) => [...(byFamily.get(f) ?? [])].sort((a, b) => (sha256(a.text) < sha256(b.text) ? -1 : 1)));
  const out: CorpusRow[] = [];
  for (let i = 0; out.length < max && queues.some((q) => i < q.length); i++) {
    for (const q of queues) if (i < q.length && out.length < max) out.push(q[i]);
  }
  return out;
}

/** The rows, in order, that fit `maxBytes` of serialized corpus. */
export function withinBudget(rows: readonly CorpusRow[], maxBytes: number): readonly CorpusRow[] {
  let used = 0;
  const out: CorpusRow[] = [];
  for (const r of rows) {
    const bytes = Buffer.byteLength(JSON.stringify(r), 'utf8') + 64;
    if (used + bytes > maxBytes) break;
    used += bytes;
    out.push(r);
  }
  return out;
}

// ---------------------------------------------------------------------------
// LLMail-Inject
// ---------------------------------------------------------------------------

/** All five must be true for a submission to have succeeded (see the card). */
export const LLMAIL_OBJECTIVES: readonly string[] = Object.freeze([
  'email.retrieved',
  'defense.undetected',
  'exfil.sent',
  'exfil.destination',
  'exfil.content',
]);

export interface LlmailRawRow {
  readonly subject?: string | null;
  readonly body?: string | null;
  readonly scenario?: string | null;
  readonly objectives?: string | Record<string, unknown> | null;
}

function objectivesOf(row: LlmailRawRow): Record<string, unknown> {
  if (row.objectives && typeof row.objectives === 'object') return row.objectives;
  if (typeof row.objectives !== 'string') return {};
  try {
    return JSON.parse(row.objectives) as Record<string, unknown>;
  } catch {
    return {};
  }
}

/** True when the submission met every objective: the agent sent the attacker's email. */
export function llmailSucceeded(row: LlmailRawRow): boolean {
  const o = objectivesOf(row);
  return LLMAIL_OBJECTIVES.every((k) => o[k] === true);
}

/**
 * The email as the mail tool hands it to the agent: subject line, then body.
 * The challenge's own "Subject of the email: ... Body:" framing is left out on
 * purpose — every row would carry it, and a regex on it would recover them all.
 */
export function llmailRow(row: LlmailRawRow, phase: string): CorpusRow | null {
  const subject = (row.subject ?? '').trim();
  const body = (row.body ?? '').trim();
  const text = subject ? `${subject}\n\n${body}` : body;
  if (!body || !llmailSucceeded(row)) return null;
  return { text, family: `${phase}/${row.scenario ?? 'unknown'}` };
}

/** Successful submissions, one row per distinct email text. */
export function llmailRows(raw: Iterable<{ readonly row: LlmailRawRow; readonly phase: string }>): readonly CorpusRow[] {
  const seen = new Map<string, CorpusRow>();
  for (const { row, phase } of raw) {
    const r = llmailRow(row, phase);
    if (r && !seen.has(r.text)) seen.set(r.text, r);
  }
  return [...seen.values()];
}

// ---------------------------------------------------------------------------
// BrowseSafe-Bench
// ---------------------------------------------------------------------------

/** Attributes that only carry layout; an injection hidden in a page never lives there. */
const LAYOUT_ATTRIBUTES = new Set([
  'style', 'class', 'id', 'type', 'lang', 'charset', 'rel', 'target', 'width', 'height',
  'viewbox', 'xmlns', 'd', 'fill', 'stroke', 'role', 'tabindex', 'colspan', 'rowspan',
]);

/** Shorter units are labels and navigation; no injection in the benchmark is this short. */
const MIN_UNIT_CHARS = 20;

const ENTITIES: Readonly<Record<string, string>> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };

function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === '#') {
      const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

const UNIT = /<!--([\s\S]*?)-->|\s([\w:-]+)\s*=\s*"([^"]*)"|>([^<]+)</g;

/**
 * The page's text units, in document order and deduplicated: comment bodies,
 * non-layout attribute values (data-*, aria-*, alt, title, href, content, form
 * values — where hidden injections live) and text nodes.
 */
export function pageUnits(html: string): readonly string[] {
  const out: string[] = [];
  for (const m of html.matchAll(UNIT)) {
    if (m[2] !== undefined && LAYOUT_ATTRIBUTES.has(m[2].toLowerCase())) continue;
    const raw = m[1] ?? m[3] ?? m[4] ?? '';
    const unit = decodeEntities(raw).replace(/\s+/g, ' ').trim();
    if (unit.length >= MIN_UNIT_CHARS) out.push(unit);
  }
  return [...new Set(out)];
}

/**
 * What an attack page holds that no benign page of the benchmark holds. Pages
 * average ~53 KB of HTML, so 3000 of them would be ~160 MB; the template
 * chrome, navigation and the benign "distractor" elements the benchmark plants
 * on every page are shared with its benign pages and add nothing to mine. The
 * injection never appears on a benign page, so it is always kept.
 */
export function attackProjection(html: string, benignUnits: ReadonlySet<string>): string {
  return pageUnits(html).filter((u) => !benignUnits.has(u)).join('\n');
}

export interface BrowsesafeRawRow {
  readonly content?: string | null;
  readonly label?: string | null;
}

/** Projections longer than this are skipped: the miner reads one per prompt line. */
export const MAX_PROJECTION_CHARS = 6000;

/** Attack rows of one BrowseSafe split, projected against its benign rows. */
export function browsesafeRows(rows: readonly BrowsesafeRawRow[], split: string): readonly CorpusRow[] {
  const benign = new Set(rows.filter((r) => r.label === 'no').flatMap((r) => pageUnits(r.content ?? '')));
  const out: CorpusRow[] = [];
  for (const r of rows) {
    if (r.label !== 'yes' || !r.content) continue;
    const text = attackProjection(r.content, benign);
    if (text.length >= MIN_UNIT_CHARS && text.length <= MAX_PROJECTION_CHARS) out.push({ text, family: split });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Output documents
// ---------------------------------------------------------------------------

export interface CorpusDocMeta {
  readonly dataset: UpstreamDataset;
  readonly retrieved: string;
  readonly filter: string;
}

/** corpus.json in the schema scripts/lib/fn-corpora.ts loadAttackFixtures reads. */
export function corpusDocument(rows: readonly CorpusRow[], meta: CorpusDocMeta): Record<string, unknown> {
  return {
    source: meta.dataset.id,
    source_url: `https://huggingface.co/datasets/${meta.dataset.repo}`,
    revision: meta.dataset.revision,
    license: meta.dataset.license.toUpperCase(),
    extraction_date: meta.retrieved,
    row_filter: meta.filter,
    count: rows.length,
    attacks: rows.map((r) => ({ text: r.text, label: 'attack', attack_family: r.family })),
  };
}

/** SOURCE.md: where the rows came from, under what license, and which rows. */
export function sourceMarkdown(meta: CorpusDocMeta, licenseLine: string, files: readonly string[], count: number): string {
  const { dataset } = meta;
  return [
    `# ${dataset.id}`,
    '',
    `- Upstream: https://huggingface.co/datasets/${dataset.repo}`,
    `- Revision: \`${dataset.revision}\``,
    `- Files: ${files.map((f) => `\`${f}\``).join(', ')}`,
    `- License (dataset card front matter, quoted): \`${licenseLine}\``,
    `- Retrieved: ${meta.retrieved}`,
    `- Row filter: ${meta.filter}`,
    `- Rows kept: ${count}`,
    '',
    'Regenerate with `npx tsx scripts/sync-agent-attack-corpora.ts --write`.',
    '',
  ].join('\n');
}
