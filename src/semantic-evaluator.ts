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

import { createHash } from "node:crypto";

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

/**
 * Upper bound on characters sent to the judge. Bounds token cost and protects
 * the endpoint from a multi-megabyte input. Note: padding past the cap is a
 * known evasion tradeoff (a payload buried after the cap is not seen) — the cap
 * exists to bound cost/DoS, not as a security boundary on its own.
 */
const DEFAULT_MAX_INPUT_CHARS = 20_000;

/** Render a prompt template by substituting `{{input}}` with the actual input. */
function renderPrompt(template: string, input: string): string {
  return template.replace(/\{\{\s*input\s*\}\}/g, input);
}

/**
 * Compute a stable cache key from (judge prompt template, input).
 *
 * Hashes the prompt template together with the input so two semantic rules with
 * different prompts can never collide on the same input — which would serve
 * rule A's verdict to rule B through the shared module-level cache. Both fields
 * are length-prefixed before hashing so a ':' inside the input cannot forge
 * another (template, input) pair's key.
 */
function cacheKey(promptTemplate: string, input: string): string {
  return createHash("sha256")
    .update(`${promptTemplate.length}:${promptTemplate}|${input.length}:${input}`)
    .digest("hex");
}

export interface SemanticEvaluatorOptions {
  /** Caller-supplied judge function. If absent, fallback path is taken. */
  judge?: ATRSemanticJudge;
  /** Caller-supplied cache. Defaults to an in-process Map cache. */
  cache?: JudgeCache;
  /** Max input chars sent to the judge (default 20000). Bounds token cost. */
  maxInputChars?: number;
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

  // Bound input size before hashing/judging to cap token cost and protect the
  // judge endpoint from a multi-megabyte input. The judge only sees boundedInput.
  const maxInputChars = options.maxInputChars ?? DEFAULT_MAX_INPUT_CHARS;
  const boundedInput =
    input.length > maxInputChars ? input.slice(0, maxInputChars) : input;

  // Cache check
  const cache = options.cache ?? DEFAULT_CACHE;
  const key = cacheKey(sem.prompt_template, boundedInput);
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
  const prompt = renderPrompt(sem.prompt_template, boundedInput);
  let response: ATRSemanticJudgeResult;
  try {
    response = await options.judge({
      prompt,
      input: boundedInput,
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
