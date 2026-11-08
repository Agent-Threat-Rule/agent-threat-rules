/**
 * scripts/vendor-suites/in-sample.ts
 *
 * How far the vendor guardrail test suites are from out-of-sample for ATR's
 * rules, measured three ways:
 *
 *   1. Ablation. Rules whose YAML names a vendor (promptfoo, llm-guard, NeMo /
 *      NeMo Guardrails) or the `(vendor-corpus-import)` author tag were
 *      written from these suites; rulesDirWithout() gives a copy of rules/
 *      without them, so the runner can re-measure the same samples.
 *   2. Rule-text overlap. A rule that does not name a vendor can still carry a
 *      vendor sample's text in its YAML (a test case, a pattern literal).
 *      ruleTextOverlaps() finds every rule whose parsed YAML strings share a
 *      run of SHINGLE_CHARS characters with a sample (whitespace folded,
 *      typographic quotes folded to ASCII, lower-cased).
 *   3. Corpus overlap. vendorSamplesInCorpus() finds vendor samples that occur
 *      verbatim inside another committed corpus (garak-full), whose rules may
 *      have been mined from the same text.
 *
 * The same pattern decides what (1) removes in the runner and in the tests.
 */

import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import yaml from 'js-yaml';

/** A rule YAML naming one of the three vendors or the vendor-import author tag. */
export const VENDOR_NAMING_PATTERN = /promptfoo|\bllm[-_ ]?guard\b|\bnemo\b|vendor-corpus-import/i;

/** Length of the shared character run that counts as rule-text overlap. */
export const SHINGLE_CHARS = 40;

export function listRuleFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return listRuleFiles(p);
    return /\.ya?ml$/.test(name) ? [p] : [];
  });
}

export function ruleIdOf(text: string): string | null {
  const m = /^id:\s*["']?([A-Z0-9-]+)["']?\s*$/m.exec(text);
  return m ? m[1]! : null;
}

/** Rule ids whose YAML text matches `pattern`, sorted. */
export function rulesNaming(rulesDir: string, pattern: RegExp = VENDOR_NAMING_PATTERN): string[] {
  return listRuleFiles(rulesDir)
    .map((p) => readFileSync(p, 'utf-8'))
    .filter((t) => pattern.test(t))
    .map(ruleIdOf)
    .filter((id): id is string => id !== null)
    .sort();
}

/** A temporary copy of `rulesDir` without `excludeIds`; throws when an id has no file. */
export function rulesDirWithout(
  rulesDir: string,
  excludeIds: readonly string[],
): { readonly dir: string; readonly removed: readonly string[] } {
  const exclude = new Set(excludeIds);
  const removed: string[] = [];
  const dir = join(mkdtempSync(join(tmpdir(), 'atr-vendor-ablation-')), 'rules');
  cpSync(rulesDir, dir, {
    recursive: true,
    filter: (src) => {
      if (!/\.ya?ml$/.test(src) || statSync(src).isDirectory()) return true;
      const id = ruleIdOf(readFileSync(src, 'utf-8'));
      if (id !== null && exclude.has(id)) {
        removed.push(id);
        return false;
      }
      return true;
    },
  });
  const missing = excludeIds.filter((id) => !removed.includes(id));
  if (missing.length > 0) throw new Error(`rulesDirWithout: no rule file for ${missing.join(', ')}`);
  return { dir, removed: [...removed].sort() };
}

/** Whitespace folded, typographic quotes folded to ASCII, lower-cased. */
export function foldText(s: string): string {
  return s
    .replace(/[“”„]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

/** Every string value in a parsed YAML document. */
export function yamlStrings(node: unknown): string[] {
  if (typeof node === 'string') return [node];
  if (Array.isArray(node)) return node.flatMap(yamlStrings);
  if (node !== null && typeof node === 'object') return Object.values(node).flatMap(yamlStrings);
  return [];
}

export interface TextItem {
  readonly id: string;
  readonly text: string;
}

/**
 * Rules whose parsed YAML strings share a run of `n` folded characters with a
 * sample: rule id -> sample ids, both sorted. Rules with no overlap are absent.
 */
export function ruleTextOverlaps(
  rules: readonly TextItem[],
  samples: readonly TextItem[],
  n: number = SHINGLE_CHARS,
): Map<string, string[]> {
  const owners = new Map<string, Set<string>>();
  for (const s of samples) {
    const t = foldText(s.text);
    for (let i = 0; i + n <= t.length; i++) {
      const sh = t.slice(i, i + n);
      const set = owners.get(sh) ?? new Set<string>();
      set.add(s.id);
      owners.set(sh, set);
    }
  }
  const out = new Map<string, string[]>();
  for (const r of [...rules].sort((a, b) => a.id.localeCompare(b.id))) {
    const hit = new Set<string>();
    for (const str of r.text.split('\u0000')) {
      const t = foldText(str);
      for (let i = 0; i + n <= t.length; i++) {
        const ids = owners.get(t.slice(i, i + n));
        if (ids) for (const id of ids) hit.add(id);
      }
    }
    if (hit.size > 0) out.set(r.id, [...hit].sort());
  }
  return out;
}

/** Each rule's parsed YAML strings, NUL-joined so no run crosses two strings. */
export function loadRuleTexts(rulesDir: string): TextItem[] {
  return listRuleFiles(rulesDir).flatMap((p) => {
    const raw = readFileSync(p, 'utf-8');
    const id = ruleIdOf(raw);
    if (id === null) return [];
    return [{ id, text: yamlStrings(yaml.load(raw)).join('\u0000') }];
  });
}

export interface CorpusOccurrence {
  readonly sample_id: string;
  readonly vendor: string;
  /** A corpus file holding a prompt that shares at least minFraction of the sample's text. */
  readonly file: string;
  /** Index, in the file's `prompts` array, of the prompt sharing the most. */
  readonly prompt_index: number;
  /** Share of the sample's distinct `n`-character runs that occur in that prompt (1 = the whole sample is in it). */
  readonly shared_run_fraction: number;
  /** `contained`: the whole folded sample occurs in the prompt; `shared-template`: most of it does. */
  readonly relation: 'contained' | 'shared-template';
}

/** Prompts of a garak-full family file (`{ family, count, prompts: string[] }`). */
function garakPrompts(path: string): string[] {
  const d = JSON.parse(readFileSync(path, 'utf-8')) as { prompts?: unknown };
  return Array.isArray(d.prompts) ? d.prompts.filter((p): p is string => typeof p === 'string') : [];
}

function runsOf(t: string, n: number): Set<string> {
  const out = new Set<string>();
  for (let i = 0; i + n <= t.length; i++) out.add(t.slice(i, i + n));
  return out;
}

/**
 * Vendor samples that share most of their text with a prompt of a directory
 * of garak-full family files: for each sample and file, the prompt holding the
 * largest share of the sample's distinct `n`-character folded runs. Listed when
 * that share is at least `minFraction` (`contained` when the whole folded
 * sample occurs in the prompt), once per file. Jailbreak templates recur across corpora with the payload slot
 * filled differently, so a shared template is reported, not only exact copies.
 * Samples shorter than `n` folded characters have no runs and are not tested.
 */
export function vendorSamplesInCorpus(
  samples: readonly (TextItem & { vendor: string })[],
  corpusDir: string,
  n = SHINGLE_CHARS,
  minFraction = 0.5,
): CorpusOccurrence[] {
  if (!existsSync(corpusDir)) return [];
  const owners = new Map<string, string[]>();
  const runCount = new Map<string, number>();
  for (const s of samples) {
    const runs = runsOf(foldText(s.text), n);
    runCount.set(s.id, runs.size);
    for (const r of runs) owners.set(r, [...(owners.get(r) ?? []), s.id]);
  }
  const files = readdirSync(corpusDir).filter((x) => x.endsWith('.json')).sort();
  const best = new Map<string, { index: number; shared: number; text: string }>(); // key: sample id + NUL + file
  for (const f of files) {
    garakPrompts(join(corpusDir, f)).forEach((prompt, index) => {
      const folded = foldText(prompt);
      const shared = new Map<string, number>();
      for (const r of runsOf(folded, n)) for (const id of owners.get(r) ?? []) shared.set(id, (shared.get(id) ?? 0) + 1);
      for (const [id, k] of shared) {
        const key = `${id}\u0000${f}`;
        const cur = best.get(key);
        if (cur === undefined || k > cur.shared) best.set(key, { index, shared: k, text: folded });
      }
    });
  }
  const out: CorpusOccurrence[] = [];
  for (const s of samples) for (const f of files) {
    const b = best.get(`${s.id}\u0000${f}`);
    const total = runCount.get(s.id) ?? 0;
    if (b === undefined || total === 0) continue;
    const fraction = b.shared / total;
    if (fraction < minFraction) continue;
    out.push({
      sample_id: s.id,
      vendor: s.vendor,
      file: basename(f),
      prompt_index: b.index,
      shared_run_fraction: Number(fraction.toFixed(4)),
      relation: b.text.includes(foldText(s.text)) ? 'contained' : 'shared-template',
    });
  }
  return out;
}
