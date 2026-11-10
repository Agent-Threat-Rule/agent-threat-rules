/**
 * scripts/lib/fn-mine-refusal.ts
 *
 * What the miner does when the model declines a chunk.
 *
 * Why (2026-11-08, run 42526623466): the model refused the first chunk of
 * cyberseceval-pi and of k8s-resource-pi ("API Error: ... can't help with
 * this"), the miner treated it like any failed call, and each corpus was
 * skipped whole. A refusal is usually about a few samples in the chunk (an
 * attack whose goal is itself harmful), not the corpus. So a refused chunk is
 * asked of the next model in the list, then split in half and each half asked
 * again, down to MIN_SPLIT texts; only a piece still refused at that size is
 * dropped, and the drop is counted and logged. Any other error is rethrown.
 */
import type { ChunkResult, MineCandidate } from './fn-mine-reply.js';

/** How an API or CLI refusal reads; distinct from a timeout or a bad reply. */
const REFUSAL = /can'?t help with (?:this|that)|cannot help with (?:this|that)|unable to help with|violat\w* (?:our )?usage polic|content (?:filter|policy)/i;

export function isRefusal(e: unknown): boolean {
  return REFUSAL.test(e instanceof Error ? e.message : String(e));
}

/** A call that ran out of time; run 42545372643 lost english-pi-3k whole to one. */
export function isTimeout(e: unknown): boolean {
  return /timed out after \d+ms/i.test(e instanceof Error ? e.message : String(e));
}

/** A refused piece no larger than this is dropped instead of split again. */
export const MIN_SPLIT = 8;

export interface RefusalSafeResult extends ChunkResult {
  /** Texts no model would take, even split down to MIN_SPLIT. */
  readonly dropped: number;
  /** Model calls that came back refused. */
  readonly refusals: number;
}

/**
 * Candidates for `texts`, asking `models` in order on a refusal and splitting
 * the texts when every model refuses. `ask` makes one call; `warn` gets one
 * line per refusal handled.
 */
export async function mineRefusalSafe(
  texts: readonly string[],
  ask: (texts: readonly string[], model: string) => Promise<ChunkResult>,
  models: readonly string[],
  warn: (line: string) => void,
  minSplit = MIN_SPLIT,
): Promise<RefusalSafeResult> {
  if (models.length === 0) throw new Error('mineRefusalSafe needs at least one model');
  let refusals = 0;
  let timeouts = 0;
  for (const model of models) {
    try {
      const r = await ask(texts, model);
      return { ...r, dropped: 0, refusals };
    } catch (e) {
      if (isTimeout(e)) {
        // A slow call is the chunk, not the corpus: try the next model, and
        // if every model times out, return the chunk unread (assertSomeChunkRead
        // still fails a run that read nothing).
        timeouts += 1;
        warn(`${model} timed out on ${texts.length} text(s)`);
        continue;
      }
      if (!isRefusal(e)) throw e;
      refusals += 1;
      warn(`${model} declined ${texts.length} text(s)`);
    }
  }
  if (timeouts > 0 && refusals === 0) return { candidates: [], read: false, dropped: 0, refusals };
  if (texts.length <= minSplit) {
    warn(`dropping ${texts.length} text(s) every model declined`);
    return { candidates: [], read: true, dropped: texts.length, refusals };
  }
  const half = Math.ceil(texts.length / 2);
  const a = await mineRefusalSafe(texts.slice(0, half), ask, models, warn, minSplit);
  const b = await mineRefusalSafe(texts.slice(half), ask, models, warn, minSplit);
  const candidates: MineCandidate[] = [...a.candidates, ...b.candidates];
  return { candidates, read: a.read || b.read, dropped: a.dropped + b.dropped, refusals: refusals + a.refusals + b.refusals };
}

/** The models to ask, in order: the run's model, then ATR_FNMINE_FALLBACK_MODELS (comma-separated). */
export function refusalModels(primary: string, env: Readonly<Record<string, string | undefined>> = process.env): readonly string[] {
  const fallbacks = (env['ATR_FNMINE_FALLBACK_MODELS'] ?? 'claude-opus-5-5')
    .split(',')
    .map((m) => m.trim())
    .filter((m) => m && m !== primary);
  return [primary, ...fallbacks];
}
