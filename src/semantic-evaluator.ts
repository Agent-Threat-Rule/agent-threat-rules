/**
 * Semantic-method rule evaluator (LLM-as-judge).
 *
 * Implements atr-method-v1.1.md §6.4 evaluation semantics. The judge
 * itself is passed in via dependency injection — the reference engine
 * does NOT bundle a vendor SDK. Operators wire in OpenAI, Anthropic,
 * or a local model at deployment time.
 *
 * Capability: atr/method/semantic (per atr-method-v1.1.md §9).
 *
 * Fallback behavior per spec §6.4:
 *   - If judge is unavailable AND rule.semantic.fallback_method === 'pattern',
 *     the engine falls back to pattern evaluation on the same input.
 *   - If fallback_method === 'none' or absent, the engine returns a
 *     graceful_error (matched: false, error: <reason>).
 */

import type {
  ATRRule,
  ATRSemanticDetection,
  ATRSemanticJudge,
  ATRSemanticJudgeResult,
} from "./types.js";

export interface SemanticEvaluationResult {
  matched: boolean;
  /** Judge response confidence (0.0-1.0) if judge was called */
  confidence?: number;
  /** Judge response category if returned */
  category?: string;
  /** Judge response evidence if returned */
  evidence?: string;
  /** Why the rule did not evaluate via judge (cache hit / fallback / error) */
  reason?: string;
  /** Set when judge unavailable AND fallback_method !== 'pattern' */
  error?: string;
}

interface JudgeCache {
  get(key: string): { confidence: number; category: string; evidence?: string } | undefined;
  set(key: string, value: { confidence: number; category: string; evidence?: string; expires_at: number }): void;
}

class InMemoryJudgeCache implements JudgeCache {
  private store = new Map<string, { confidence: number; category: string; evidence?: string; expires_at: number }>();
  get(key: string) {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (entry.expires_at < Date.now()) {
      this.store.delete(key);
      return undefined;
    }
    return { confidence: entry.confidence, category: entry.category, evidence: entry.evidence };
  }
  set(key: string, value: { confidence: number; category: string; evidence?: string; expires_at: number }): void {
    this.store.set(key, value);
  }
}

const DEFAULT_CACHE: JudgeCache = new InMemoryJudgeCache();

/** Render a prompt template by substituting `{{input}}` with the actual input. */
function renderPrompt(template: string, input: string): string {
  return template.replace(/\{\{\s*input\s*\}\}/g, input);
}

/** Compute a stable cache key from (judge prompt hash, input). */
function cacheKey(promptHash: string | undefined, input: string): string {
  // Caller should hash; we just concatenate. For reference, prefer pre-hashed input.
  return `${promptHash ?? "no-hash"}:${input}`;
}

export interface SemanticEvaluatorOptions {
  /** Caller-supplied judge function. If absent, fallback path is taken. */
  judge?: ATRSemanticJudge;
  /** Caller-supplied cache. Defaults to an in-process Map cache. */
  cache?: JudgeCache;
}

export async function evaluateSemanticRule(
  rule: ATRRule,
  input: string,
  options: SemanticEvaluatorOptions = {},
): Promise<SemanticEvaluationResult> {
  const sem: ATRSemanticDetection | undefined = rule.detection.semantic;
  if (!sem) {
    return { matched: false, error: "rule has method=semantic but no detection.semantic block" };
  }

  // Cache check
  const cache = options.cache ?? DEFAULT_CACHE;
  const key = cacheKey(sem.judge_prompt_hash, input);
  const cached = cache.get(key);
  if (cached) {
    return {
      matched: cached.confidence >= sem.threshold,
      confidence: cached.confidence,
      category: cached.category,
      evidence: cached.evidence,
      reason: "cache_hit",
    };
  }

  // Judge unavailable → fallback path
  if (!options.judge) {
    if (sem.fallback_method === "pattern") {
      return {
        matched: false,
        reason: "judge_unavailable_fallback_pattern",
      };
    }
    return {
      matched: false,
      error: "judge_unavailable_no_fallback",
    };
  }

  // Call judge
  const prompt = renderPrompt(sem.prompt_template, input);
  let response: ATRSemanticJudgeResult;
  try {
    response = await options.judge({
      prompt,
      input,
      judge_model_class: sem.judge_model_class,
    });
  } catch (err) {
    if (sem.fallback_method === "pattern") {
      return {
        matched: false,
        reason: `judge_error_fallback_pattern: ${(err as Error).message}`,
      };
    }
    return { matched: false, error: `judge_error: ${(err as Error).message}` };
  }

  // Cache the response if cache_ttl set
  if (sem.cache_ttl && sem.cache_ttl > 0) {
    cache.set(key, {
      confidence: response.confidence,
      category: response.category,
      evidence: response.evidence,
      expires_at: Date.now() + sem.cache_ttl * 1000,
    });
  }

  return {
    matched: response.confidence >= sem.threshold,
    confidence: response.confidence,
    category: response.category,
    evidence: response.evidence,
    reason: "judge_evaluated",
  };
}
