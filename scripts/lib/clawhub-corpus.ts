/**
 * The ClawHub registry as a benign corpus.
 *
 * WHAT THIS CORPUS IS
 *
 * `data/clawhub-scan/clawhub-registry.json` is a full crawl of the ClawHub
 * skill registry taken 2026-03-26: 36,394 published skills, each with the
 * metadata the registry itself serves — author, name, summary, downloads,
 * stars, versions, updatedAt. Every one of them is a real artifact that real
 * users installed; the sum of the `downloads` column is 24,574,190.
 *
 * WHAT THIS CORPUS IS NOT — READ BEFORE QUOTING ANY NUMBER FROM IT
 *
 * It is NOT a corpus of SKILL.md bodies. The crawl stored no skill content.
 * `summary` is the registry's own description field and it is TRUNCATED:
 * 13,693 of the 36,394 summaries are exactly 160 characters and 15,603 (42.9%)
 * end in a literal "...". Median length is 159 characters. A real SKILL.md is
 * orders of magnitude longer and carries the parts a scanner most wants to see
 * — bash blocks, tool declarations, frontmatter, URLs.
 *
 * So a rule that is clean here is clean ON REGISTRY DESCRIPTION TEXT. That is a
 * real production surface (marketplace listing pages, `search` results, install
 * prompts) and it is worth measuring on its own terms. It is not a licence to
 * say "0 FP on 36,394 real skills".
 *
 * It is also NOT a curated benign set. It is the registry in full, which is
 * where malware lives too — the 2026-04 wild scan found confirmed droppers on
 * this very platform. Anything flagged has to be triaged by hand before being
 * called a false positive; see docs/research/.
 */

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

/** A row exactly as the registry crawl stored it. */
export interface ClawhubEntry {
  readonly author: string;
  readonly name: string;
  readonly summary: string;
  readonly downloads: number;
  readonly stars: number;
  readonly versions: number;
  readonly updatedAt: string;
}

/**
 * Which text of a registry row gets poured into the event.
 *
 * `summary` — the description field verbatim. The primary measurement: it is
 *   the only free text the publisher wrote, so it is the only place a pattern
 *   can honestly fire.
 * `card` — "name\n\nsummary", i.e. what a listing page renders. A sensitivity
 *   check: skill NAMES are attacker-controlled too (typosquats, `safe-exec`),
 *   and several ATR rules key on names. Reported separately, never merged into
 *   the primary number.
 */
export type TextVariant = 'summary' | 'card';

export const TEXT_VARIANTS: readonly TextVariant[] = Object.freeze(['summary', 'card']);

/** A corpus sample: the registry row plus a stable id. */
export interface ClawhubSample {
  readonly id: string;
  readonly author: string;
  readonly name: string;
  readonly summary: string;
  readonly downloads: number;
  readonly stars: number;
  readonly versions: number;
  readonly updatedAt: string;
  /** True when `summary` ends in "..." — the registry cut the text off. */
  readonly truncated: boolean;
}

/** Stable id for a row. author/name is unique across all 36,394 rows. */
export function sampleId(entry: ClawhubEntry): string {
  return `${entry.author}/${entry.name}`;
}

/** The text a given variant presents to the engine. */
export function sampleText(sample: ClawhubSample, variant: TextVariant): string {
  return variant === 'card' ? `${sample.name}\n\n${sample.summary}` : sample.summary;
}

function isEntry(value: unknown): value is ClawhubEntry {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.author === 'string' &&
    typeof v.name === 'string' &&
    typeof v.summary === 'string' &&
    typeof v.downloads === 'number' &&
    typeof v.stars === 'number' &&
    typeof v.versions === 'number' &&
    typeof v.updatedAt === 'string'
  );
}

/** Reject the whole file rather than silently scanning a subset. */
export function toSample(entry: ClawhubEntry): ClawhubSample {
  return Object.freeze({
    id: sampleId(entry),
    author: entry.author,
    name: entry.name,
    summary: entry.summary,
    downloads: entry.downloads,
    stars: entry.stars,
    versions: entry.versions,
    updatedAt: entry.updatedAt,
    truncated: entry.summary.trimEnd().endsWith('...'),
  });
}

export interface RegistryRead {
  readonly samples: readonly ClawhubSample[];
  readonly sourceSha256: string;
}

/**
 * Parse the registry. Throws on any row that is not the expected shape — a
 * corpus builder that skips malformed rows reports a denominator it did not
 * scan, and every rate computed from it is wrong by an unknown amount.
 */
export function readRegistry(path: string): RegistryRead {
  const raw = readFileSync(path);
  const parsed: unknown = JSON.parse(raw.toString('utf8'));
  if (!Array.isArray(parsed)) {
    throw new Error(`registry is not an array: ${path}`);
  }
  const samples = parsed.map((row, i) => {
    if (!isEntry(row)) {
      throw new Error(`registry row ${i} is not a ClawhubEntry: ${JSON.stringify(row).slice(0, 200)}`);
    }
    return toSample(row);
  });
  const ids = new Set(samples.map((s) => s.id));
  if (ids.size !== samples.length) {
    throw new Error(`registry has duplicate author/name ids: ${samples.length - ids.size} collisions`);
  }
  return Object.freeze({
    samples: Object.freeze(samples),
    sourceSha256: createHash('sha256').update(raw).digest('hex'),
  });
}

/**
 * Download strata.
 *
 * A false positive on a skill nobody installed costs nobody anything. A false
 * positive on the #3 skill on the platform breaks thousands of installs and
 * gets the scanner uninstalled. Rates are therefore reported per stratum, top
 * ranks first, never as one pooled number.
 *
 * Strata are RANK-based (top N by downloads), not threshold-based, so they stay
 * comparable if the registry is re-crawled and absolute download counts move.
 */
export const DOWNLOAD_TIERS: readonly number[] = Object.freeze([100, 1_000, 10_000]);

/** Samples sorted by downloads descending; ties broken by id for determinism. */
export function byDownloadsDesc(samples: readonly ClawhubSample[]): readonly ClawhubSample[] {
  return Object.freeze(
    [...samples].sort((a, b) => (b.downloads - a.downloads) || a.id.localeCompare(b.id)),
  );
}
