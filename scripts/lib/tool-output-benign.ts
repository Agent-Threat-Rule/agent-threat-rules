/**
 * scripts/lib/tool-output-benign.ts
 *
 * The pure half of the benign TOOL-OUTPUT corpora that scripts/sync-agent-
 * attack-corpora.ts vendors for the FN-mine gate (scripts/fn-mine-llm.ts):
 * ordinary emails and ordinary web pages, the text a mail tool and a browser
 * tool return to an agent when nobody is attacking it.
 *
 * Why they exist: the lane mines LLMail-Inject (attack emails) and
 * BrowseSafe-Bench (attack pages), both delivered as tool_response, and
 * certified every candidate "0 benign FP" on data/benign-corpus-extended:
 * prompts, skill docs, code, conversations and arXiv text, and not one email or
 * web page. Zero hits there say nothing about mail or pages. The rules on main
 * show the size of that blind spot: they pass the repo's benign gates, and
 * scripts/report-tool-output-benign-fp.ts measured 34 of them firing on 465 of
 * these 694 benign pages (ATR-2026-00011 alone on 439, mostly the benchmark's
 * planted warning banners).
 *
 * Scope: these corpora are read by the FN-mine gate only. They are NOT in
 * MEASUREMENT_CORPORA (scripts/lib/benign-corpus.ts) or any repo-wide quality
 * gate, baseline or threshold; whether they belong there is a separate
 * decision. scripts/report-tool-output-benign-fp.ts measures what the rules
 * already on main fire on them, for that decision.
 *
 * Sources (licenses read from each dataset card at the pinned revision):
 *
 *   ISTA-DASLab/Panza-emails (Apache-2.0). Emails three people wrote and
 *     donated for research on personalised writing; names and places in them
 *     were replaced by the publishers. Every row is kept. Narrow: 526 short
 *     messages from three senders (EMAIL_SET_LIMITS).
 *
 *   perplexity-ai/browsesafe-bench (MIT), the benign (label 'no') pages of the
 *     test split the attack corpus is cut from, at the same revision, through
 *     the same text-unit extraction (pageUnits) and identifier masking.
 *
 * Evaluated and not vendored: see NOT_VENDORED_EMAIL below.
 */
import {
  BROWSESAFE,
  MIT_PERMISSION_NOTICE,
  pageUnits,
  scrubIdentifiers,
  type BrowsesafeRawRow,
  type CorpusRow,
} from './agent-attack-corpora.js';

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

export interface BenignSource {
  /** Directory name under data/fn-mine-benign/. */
  readonly id: string;
  /** Hugging Face dataset repo. */
  readonly repo: string;
  /** The commit every row is read at. */
  readonly revision: string;
  /** The front-matter license id the dataset card must declare, or the sync refuses to vendor. */
  readonly license: 'apache-2.0' | 'mit';
  /** The vendored file, relative to the repo root. */
  readonly path: string;
  /** Who the rows are attributed to, as the upstream states it. */
  readonly attribution: string;
  /** Where the upstream license is stated. */
  readonly licenseUrl: string;
}

export const BENIGN_EMAILS: BenignSource = Object.freeze({
  id: 'panza-emails',
  repo: 'ISTA-DASLab/Panza-emails',
  revision: '3c972a7d1e8f747eedb5351003f4adb0cf35ffe7',
  license: 'apache-2.0',
  path: 'data/fn-mine-benign/panza-emails/corpus.json',
  attribution: 'The Panza Emails dataset, ISTA DASLab (IST Austria); emails donated by their three authors',
  // The dataset repo ships no LICENSE file; its card's front matter declares the license.
  licenseUrl: 'https://huggingface.co/datasets/ISTA-DASLab/Panza-emails/blob/3c972a7d1e8f747eedb5351003f4adb0cf35ffe7/README.md',
});

export const BENIGN_PAGES: BenignSource = Object.freeze({
  id: 'browsesafe-benign',
  repo: BROWSESAFE.repo,
  revision: BROWSESAFE.revision,
  license: 'mit',
  path: 'data/fn-mine-benign/browsesafe-benign/corpus.json',
  attribution: BROWSESAFE.copyright,
  licenseUrl: BROWSESAFE.licenseUrl,
});

/** The Apache-2.0 text, vendored beside the emails (Apache-2.0 section 4(a)), and its sha256. */
export const APACHE_2_0_URL = 'https://www.apache.org/licenses/LICENSE-2.0.txt';
export const APACHE_2_0_SHA256 = 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30';
export const APACHE_2_0_FILE = 'LICENSE-APACHE-2.0.txt';

/**
 * Real benign email sets checked and not vendored, with the reason. A license a
 * re-uploader declares on a dataset card does not cover mail other people
 * wrote: the Enron mail was released by FERC as a public record, and CMU's
 * distribution carries no license at all.
 */
export const NOT_VENDORED_EMAIL: readonly { readonly source: string; readonly reason: string }[] = Object.freeze([
  {
    source: 'Yale-LILY/aeslc (Enron subject lines)',
    reason: 'card front matter `license: unknown`',
  },
  {
    source: 'SetFit/enron_spam, corbt/enron-emails, snoop2head/enron_aeslc_emails, jacquelinehe/enron-emails',
    reason: 'card declares no license; the underlying Enron mail (CMU distribution) carries none',
  },
  {
    source: 'LLM-PBE/enron-email, ridalefdali/enron_email, salokr/MailEx (Enron-derived)',
    reason:
      'the card declares apache-2.0 / cc-by-4.0, but the mail was written by Enron employees and their ' +
      'correspondents; a re-uploader cannot license it, so the declaration is not a clean grant',
  },
  {
    source: 'Apache SpamAssassin public corpus (easy_ham / hard_ham)',
    reason: 'its readme: "Copyright for the text in the messages remains with the original senders"; no license',
  },
]);

/**
 * What the email set does not cover, stated in its SOURCE.md. A candidate that
 * passes it has been tested on personal and work mail three people sent, not
 * on the bulk of a real inbox.
 */
export const EMAIL_SET_LIMITS =
  'Narrow set: 526 emails written by three people (david, isabel, marcus), almost all short messages they ' +
  'sent themselves: scheduling, replies, requests to colleagues. It holds no quoted replies or forwarded ' +
  'message bodies, newsletters, marketing mail, receipts, automated notifications or calendar invites. A rule ' +
  'that fires on those is not caught here; a clean result on this set is evidence about ordinary ' +
  'correspondence only.';

// ---------------------------------------------------------------------------
// Row handling
// ---------------------------------------------------------------------------

/** `text` without NUL bytes: a model CLI receives the prompt as argv, which cannot carry one. */
export function withoutNul(text: string): string {
  return text.replace(/\u0000/g, '');
}

const EMAIL_ADDRESS = /[\w.%+-]+@[\w-]+(?:\.[\w-]+)+/g;
/**
 * A phone number: optional country code and area code, then two or three digit
 * groups. It may end a sentence or a clause ("... 974-9986."), but not run on
 * into a word, a path or another number ("1.2.3", "10:30", "4567.89").
 */
const PHONE = /(?<![\w.,:/-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{3,4}[ .-]\d{3,7}(?:[ .-]\d{2,4})?(?![\w:/-]|[.,]\w)/g;
/** A Zoom meeting id (zoom.us/j/<id>) and its passcode parameter. */
const ZOOM_ID = /(zoom\.us\/(?:j|w|my)\/)(\d+)/gi;
const ZOOM_PWD = /([?&]pwd=)[^&\s"'#<>]+/gi;
const YEAR_RANGE = /^(?:19|20)\d\d[ .-](?:19|20)\d\d$/;
const MIN_PHONE_DIGITS = 7;

function maskPhone(m: string): string {
  const digits = m.replace(/\D/g, '').length;
  return digits < MIN_PHONE_DIGITS || YEAR_RANGE.test(m) ? m : m.replace(/\d/g, '0');
}

/**
 * `text` with email addresses replaced whole, phone numbers and Zoom meeting
 * ids masked digit by digit and Zoom passcodes masked. The publishers already replaced names and places; addresses and
 * numbers are what is left that could reach a person. The shapes stay, so a
 * rule that keys on "an address" or "a number" is still tested.
 */
export function scrubContactDetails(text: string): string {
  return text
    .replace(EMAIL_ADDRESS, 'redacted@example.com')
    .replace(ZOOM_ID, (_m, prefix: string, id: string) => `${prefix}${id.replace(/\d/g, '0')}`)
    .replace(ZOOM_PWD, '$1REDACTED')
    .replace(PHONE, maskPhone);
}

/**
 * The JSON objects on one line of a .jsonl file. One line of the pinned Panza
 * files holds two objects back to back; a line that is not JSON throws, so the
 * sync fails instead of vendoring half a row.
 */
export function jsonObjects(line: string): unknown[] {
  const out: unknown[] = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inString) {
      if (ch === '\\') i++;
      else if (ch === '"') inString = false;
    } else if (depth === 0 && ch !== '{' && !/\s/.test(ch)) {
      throw new Error(`text outside a JSON object at ${i}: ${line.slice(0, 80)}`);
    } else if (ch === '"') inString = true;
    else if (ch === '{' && depth++ === 0) start = i;
    else if (ch === '}' && --depth === 0) out.push(JSON.parse(line.slice(start, i + 1)));
  }
  if (depth !== 0 || out.length === 0) throw new Error(`not a JSON object line: ${line.slice(0, 80)}`);
  return out;
}

export interface PanzaRawRow {
  readonly email?: string | null;
  readonly subject?: string | null;
}

const lf = (s: string): string => s.replace(/\r\n?/g, '\n').trim();

/** The email as a mail tool hands it to the agent, as llmailRow builds it: subject line, blank line, body. */
export function panzaRow(row: PanzaRawRow, family: string): CorpusRow | null {
  const subject = lf(row.subject ?? '');
  const body = lf(row.email ?? '');
  if (!body) return null;
  const text = subject ? `${subject}\n\n${body}` : body;
  return { text: withoutNul(scrubContactDetails(scrubIdentifiers(text))), family };
}

/** Every email, one row per distinct text. */
export function panzaRows(raw: Iterable<{ readonly row: PanzaRawRow; readonly family: string }>): readonly CorpusRow[] {
  const seen = new Map<string, CorpusRow>();
  for (const { row, family } of raw) {
    const r = panzaRow(row, family);
    if (r && !seen.has(r.text)) seen.set(r.text, r);
  }
  return [...seen.values()];
}

/** Shorter text is a label or a stub page; the attack projection keeps nothing shorter either. */
const MIN_PAGE_CHARS = 20;

/**
 * Benign pages longer than this are skipped (about the longest 15% of the test
 * split). A whole page is kept, not its unique part, so this is larger than the
 * attack projection's MAX_PROJECTION_CHARS.
 */
export const MAX_BENIGN_PAGE_CHARS = 20_000;

/**
 * The benign pages of one BrowseSafe split, each as the text units of the
 * whole page (pageUnits: comments, non-layout attributes, text nodes), the
 * same extraction the attack corpus is cut with, identifiers masked
 * (scrubIdentifiers) and NUL bytes removed. Nothing is subtracted: in
 * production the agent reads the whole page, template chrome and the
 * look-alike warning banners the benchmark plants on benign pages included.
 */
export function benignPageRows(rows: readonly BrowsesafeRawRow[], split: string): readonly CorpusRow[] {
  const out: CorpusRow[] = [];
  for (const r of rows) {
    if (r.label !== 'no' || !r.content) continue;
    const text = pageUnits(r.content).join('\n');
    if (text.length >= MIN_PAGE_CHARS && text.length <= MAX_BENIGN_PAGE_CHARS) {
      out.push({ text: withoutNul(scrubIdentifiers(text)), family: split });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Output documents
// ---------------------------------------------------------------------------

export interface BenignDocMeta {
  readonly source: BenignSource;
  readonly retrieved: string;
  readonly filter: string;
  readonly notes?: readonly string[];
}

const PURPOSE =
  'Benign tool output for the FN-mine gate (scripts/fn-mine-llm.ts) only: a candidate rule must fire on none of ' +
  'these, presented as tool_response. Not part of MEASUREMENT_CORPORA or any repo-wide gate, baseline or threshold.';

/** corpus.json: provenance, then the rows under `samples`, each labelled benign. */
export function benignDocument(rows: readonly CorpusRow[], meta: BenignDocMeta): Record<string, unknown> {
  const { source } = meta;
  return {
    source: source.id,
    source_url: `https://huggingface.co/datasets/${source.repo}`,
    revision: source.revision,
    license: source.license === 'mit' ? 'MIT' : 'Apache-2.0',
    attribution: source.attribution,
    extraction_date: meta.retrieved,
    row_filter: meta.filter,
    purpose: PURPOSE,
    count: rows.length,
    samples: rows.map((r) => ({ text: r.text, label: 'benign', family: r.family })),
  };
}

function licenseSection(source: BenignSource): readonly string[] {
  if (source.license === 'mit') {
    return [
      `The rows in corpus.json are a portion of the upstream dataset, redistributed under its MIT license (${source.licenseUrl}):`,
      '',
      '```',
      'MIT License',
      '',
      source.attribution,
      '',
      MIT_PERMISSION_NOTICE,
      '```',
    ];
  }
  return [
    `The rows in corpus.json are a portion of the upstream dataset (${source.attribution}), redistributed under the`,
    `Apache License, Version 2.0, which its dataset card declares (${source.licenseUrl}). A copy of the license is in`,
    `\`${APACHE_2_0_FILE}\` beside this file (${APACHE_2_0_URL}). The upstream ships no NOTICE file.`,
    '',
    'Changes made to the upstream rows (Apache-2.0 section 4(b)): subject and body joined as "subject, blank line,',
    'body"; CRLF line ends converted to LF; leading and trailing whitespace trimmed; email addresses replaced by',
    '`redacted@example.com`; phone numbers and Zoom meeting ids masked digit by digit, Zoom passcodes masked;',
    'signed-URL parameters and tokens masked as in the attack corpora; NUL bytes removed; duplicate texts dropped.',
  ];
}

/** SOURCE.md: what the rows are for, where they came from, which rows, and the license they travel under. */
export function benignSourceMarkdown(meta: BenignDocMeta, licenseLine: string, files: readonly string[], count: number): string {
  const { source } = meta;
  return [
    `# ${source.id}`,
    '',
    PURPOSE,
    '',
    `- Upstream: https://huggingface.co/datasets/${source.repo}`,
    `- Revision: \`${source.revision}\``,
    `- Files: ${files.map((f) => `\`${f}\``).join(', ')}`,
    `- License (dataset card front matter, quoted): \`${licenseLine}\``,
    `- Retrieved: ${meta.retrieved}`,
    `- Row filter: ${meta.filter}`,
    `- Rows kept: ${count}`,
    '',
    'Regenerate with `npx tsx scripts/sync-agent-attack-corpora.ts --source ' + source.id + ' --write`.',
    ...(meta.notes ?? []).flatMap((n) => ['', n]),
    '',
    '## License',
    '',
    ...licenseSection(source),
    '',
  ].join('\n');
}
