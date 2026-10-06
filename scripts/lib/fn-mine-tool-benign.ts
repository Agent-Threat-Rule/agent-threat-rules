/**
 * scripts/lib/fn-mine-tool-benign.ts
 *
 * The FN-mine gate's tool-output check (scripts/fn-mine-llm.ts): a candidate
 * must fire on no benign email and no benign web page (the corpora in
 * scripts/lib/tool-output-benign.ts), presented to the real engine as the text
 * a tool returned, the way coverageOf and liveMisses present LLMail and
 * BrowseSafe (tool_response, fn-mine-input.ts PRESENTATIONS).
 *
 * The regex-only benign check (fn-mine-candidate-gate.ts) tests raw strings.
 * This one runs each candidate as a rule through src/eval/eval-harness.ts, so
 * the engine's own normalization (NFKC, zero-width stripping, confusable
 * folding), field resolution and source admission decide, as they will in
 * production. A candidate that does not fire on its own recoveries there is
 * dropped too: its zero benign hits would have measured nothing.
 *
 * Applied to every candidate, not only those mined from tool_response corpora:
 * the lane authors llm_io rules, and the engine runs llm_io rules on
 * tool_response events (src/engine.ts llmIoOverToolResponse), so a rule mined
 * from HackAPrompt scans the same emails and pages.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import yaml from 'js-yaml';
import { detectionsByRule } from './fn-mine-input.js';
import { BENIGN_EMAILS, BENIGN_PAGES, type BenignSource } from './tool-output-benign.js';
import { compileEngineAccurate, type GatedCandidate } from './fn-mine-candidate-gate.js';
import { matchExcerpt } from './fn-mine-recoveries.js';

export interface ToolOutputBenign {
  readonly emails: readonly string[];
  readonly pages: readonly string[];
}

/** The benign texts of one vendored corpus, or why they cannot be trusted. */
function readBenignFile(root: string, source: BenignSource): { texts: readonly string[] } | { problem: string } {
  const file = join(root, source.path);
  if (!existsSync(file)) return { problem: `${source.path} is missing (run scripts/sync-agent-attack-corpora.ts --source ${source.id} --write)` };
  let doc: { count?: unknown; samples?: unknown };
  try {
    doc = JSON.parse(readFileSync(file, 'utf8')) as typeof doc;
  } catch (e) {
    return { problem: `${source.path} is not valid JSON (${e instanceof Error ? e.message : String(e)})` };
  }
  const samples = Array.isArray(doc.samples) ? (doc.samples as { text?: unknown }[]) : [];
  const texts = samples.map((s) => s.text).filter((t): t is string => typeof t === 'string' && t.length > 0);
  if (texts.length === 0) return { problem: `${source.path} holds no benign samples` };
  if (doc.count !== texts.length) return { problem: `${source.path} declares ${String(doc.count)} samples but holds ${texts.length}` };
  return { texts };
}

/**
 * Both vendored corpora, or the first problem. The miner fails closed on a
 * problem: the tool_response corpora are not mined without these.
 */
export function readToolOutputBenign(root: string): { corpus: ToolOutputBenign } | { problem: string } {
  const emails = readBenignFile(root, BENIGN_EMAILS);
  if ('problem' in emails) return emails;
  const pages = readBenignFile(root, BENIGN_PAGES);
  if ('problem' in pages) return pages;
  return { corpus: { emails: emails.texts, pages: pages.texts } };
}

/**
 * A candidate as the engine loads it: one regex on the content field, with the
 * agent_source and tags the authored rule copies from the reference rule
 * (llm_io; scan_target mcp, confidence high). Without tags the engine throws
 * inside evaluate, and the eval harness reads the throw as "no detection".
 */
function candidateRule(index: number, regex: string): string {
  return yaml.dump({
    id: `ATR-2099-${String(index + 1).padStart(5, '0')}`,
    title: `fn-mine candidate ${index + 1}`,
    status: 'experimental',
    maturity: 'test',
    severity: 'high',
    tags: { category: 'prompt-injection', scan_target: 'mcp', confidence: 'high' },
    agent_source: { type: 'llm_io' },
    detection: { conditions: [{ field: 'content', operator: 'regex', value: regex }], condition: 'any' },
  });
}

export interface ToolOutputVerdict {
  /** Benign emails plus pages the candidate fires on. */
  readonly benignHits: number;
  /** Whether it fires on at least one of its own recoveries: if not, benignHits measured nothing. */
  readonly firesOnOwn: boolean;
  /** Where in the first benign text it fires on, labelled (email/page) and cut around the match, for the log. */
  readonly firstHit?: string;
}

const SNIPPET_CHARS = 120;

/** `kind: ` and about SNIPPET_CHARS of `text` around the regex's match (its start if only the engine's normalization matches). */
function hitSnippet(kind: string, text: string, regex: string): string {
  const re = compileEngineAccurate(regex);
  const excerpt = re ? matchExcerpt(text, re, SNIPPET_CHARS) : text.slice(0, SNIPPET_CHARS);
  return `${kind}: ${excerpt.replace(/\s+/g, ' ').trim()}`;
}

/** Each candidate's verdict, in order, from one engine run over every benign text and every candidate's own texts. */
export async function toolOutputVerdicts(
  candidates: readonly { readonly regex: string; readonly own: readonly string[] }[],
  benign: ToolOutputBenign,
): Promise<readonly ToolOutputVerdict[]> {
  if (candidates.length === 0) return [];
  const benignTexts = [...benign.emails, ...benign.pages];
  // Candidate i's own texts sit at [ownStart[i], ownStart[i] + own.length) after the benign texts.
  const ownStart: number[] = [];
  let next = benignTexts.length;
  for (const c of candidates) {
    ownStart.push(next);
    next += c.own.length;
  }
  const texts = [...benignTexts, ...candidates.flatMap((c) => c.own)];
  const root = mkdtempSync(join(tmpdir(), 'fn-mine-tool-benign-'));
  try {
    candidates.forEach((c, i) => writeFileSync(join(root, `candidate-${i}.yaml`), candidateRule(i, c.regex)));
    const hits = await detectionsByRule(root, texts, 'tool_response');
    return candidates.map((c, i) => {
      const fired = hits.get(`ATR-2099-${String(i + 1).padStart(5, '0')}`) ?? [];
      const onBenign = fired.filter((j) => j < benignTexts.length);
      const own = fired.some((j) => j >= ownStart[i] && j < ownStart[i] + c.own.length);
      const first = onBenign[0];
      return {
        benignHits: onBenign.length,
        firesOnOwn: own,
        ...(first === undefined
          ? {}
          : { firstHit: hitSnippet(first < benign.emails.length ? 'email' : 'page', benignTexts[first], c.regex) }),
      };
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

/**
 * `survivors` that fire on no benign tool output and do fire on their own
 * recoveries (their exampleFNs, minable texts only), each drop logged.
 */
export async function dropToolOutputHits<T extends GatedCandidate>(
  survivors: readonly T[],
  benign: ToolOutputBenign,
): Promise<T[]> {
  const verdicts = await toolOutputVerdicts(survivors.map((s) => ({ regex: s.regex, own: s.exampleFNs })), benign);
  const drop = (c: T, why: string) => console.log(`[fn-mine]   drop ${c.cluster}: ${why}`);
  return survivors.filter((s, i) => {
    const v = verdicts[i];
    if (!v?.firesOnOwn) {
      drop(s, 'the engine does not fire it on its own recoveries presented as tool_response: zero benign hits there would measure nothing');
      return false;
    }
    if (v.benignHits > 0) {
      drop(s, `fires on ${v.benignHits} benign tool output(s) (emails ${benign.emails.length}, pages ${benign.pages.length}), first: ${JSON.stringify(v.firstHit)}`);
      return false;
    }
    return true;
  });
}
