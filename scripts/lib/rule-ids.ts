/**
 * scripts/lib/rule-ids.ts
 *
 * Rule-id bookkeeping for lanes that allocate ids without a human picking them.
 *
 * "Highest id on disk + 1" sees main and the lane's own branch only. Another
 * lane's open PR holds ids main does not have yet (auto-semantic/rolling held
 * 02846–02853 while main stopped at 02845), so the next batch reused them, and
 * whichever PR merged second failed "Duplicate rule ID" in tests/validate-rules.ts.
 * scripts/check-rules-safety.ts compares ids only among the files a PR adds, so
 * nothing upstream of that noticed. Allocation therefore also counts the rule
 * files open PRs touch, and duplicates already on disk are reported by name.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

export interface RuleFileId {
  /** Path relative to the repository root, e.g. rules/prompt-injection/ATR-2026-00003-x.yaml. */
  readonly file: string;
  /** The top-level `id:` value, or null when the file has none. */
  readonly id: string | null;
}

const TOP_LEVEL_ID = /^id:[ \t]*(["']?)(ATR-\d{4}-\d+)\1[ \t]*(?:#.*)?$/m;

export function topLevelRuleId(yamlText: string): string | null {
  return TOP_LEVEL_ID.exec(yamlText)?.[2] ?? null;
}

function isRuleFile(name: string): boolean {
  return name.endsWith('.yaml') || name.endsWith('.yml');
}

function walkRuleFiles(dir: string): readonly string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) return walkRuleFiles(full);
    return isRuleFile(entry) ? [full] : [];
  });
}

/** Every rule file under `root/dir`, with its top-level id. */
export function readRuleFileIds(root: string, dir: string): readonly RuleFileId[] {
  return walkRuleFiles(join(root, dir)).map((full) => ({
    file: relative(root, full).split('\\').join('/'),
    id: topLevelRuleId(readFileSync(full, 'utf8')),
  }));
}

/** id → every file declaring it, for ids declared by more than one file. */
export function duplicateRuleIds(entries: readonly RuleFileId[]): ReadonlyMap<string, readonly string[]> {
  const sorted = entries.flatMap((e) => (e.id ? [e.id] : [])).sort();
  const repeated = [...new Set(sorted.filter((id, i) => i > 0 && sorted[i - 1] === id))];
  return new Map(repeated.map((id) => [id, entries.filter((e) => e.id === id).map((e) => e.file)] as const));
}

export function describeDuplicateRuleIds(dups: ReadonlyMap<string, readonly string[]>): string {
  const detail = [...dups].map(([id, files]) => `${id} in ${files.join(', ')}`).join('; ');
  return `duplicate rule id(s): ${detail}. Renumber them (scripts/next-rule-id.ts --include-open-prs) before adding more rules.`;
}

function seqsIn(text: string, year: string): readonly number[] {
  return [...text.matchAll(new RegExp(`ATR-${year}-(\\d+)`, 'g'))].map((m) => Number(m[1]));
}

function fileName(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1);
}

/**
 * Sequence numbers under `year` that are taken: ids declared on disk, ids in
 * rule file names on disk, and ids in the names of rule files open PRs touch.
 */
export function usedRuleSeqs(onDisk: readonly RuleFileId[], openPrFiles: readonly string[], year: string): readonly number[] {
  const declared = onDisk.flatMap((e) => (e.id ? seqsIn(e.id, year) : []));
  const named = onDisk.flatMap((e) => seqsIn(fileName(e.file), year));
  const inFlight = openPrFiles.filter((p) => p.startsWith('rules/')).flatMap((p) => seqsIn(fileName(p), year));
  return [...declared, ...named, ...inFlight];
}

export function nextRuleSeq(used: readonly number[]): number {
  return used.reduce((max, n) => Math.max(max, n), 0) + 1;
}

export function formatRuleId(year: string, seq: number): string {
  return `ATR-${year}-${String(seq).padStart(5, '0')}`;
}
