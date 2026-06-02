/**
 * OpenAI-compatible semantic judge adapter.
 *
 * Converts any chat-completions-compatible endpoint into an ATRSemanticJudge.
 * This keeps ATR vendor-neutral while giving operators a ready-to-use bridge
 * for OpenAI, LiteLLM, vLLM, LM Studio, and similar gateways.
 *
 * @module agent-threat-rules/judges/openai-compatible
 */

import type { ATRSemanticJudge, ATRSemanticJudgeResult } from "../types.js";

export interface OpenAICompatibleJudgeConfig {
  /** API key sent as Bearer token. */
  readonly apiKey: string;
  /** API base URL, /v1 URL, or full /chat/completions URL. */
  readonly baseUrl?: string;
  /** Chat model name. */
  readonly model?: string;
  /** Sampling temperature. Defaults to 0 for deterministic judging. */
  readonly temperature?: number;
  /** Maximum output tokens. */
  readonly maxTokens?: number;
  /** Request timeout in milliseconds. */
  readonly timeoutMs?: number;
  /** Extra headers such as organization or project IDs. */
  readonly additionalHeaders?: Record<string, string>;
  /** Include OpenAI JSON mode response_format. Defaults to true. */
  readonly jsonMode?: boolean;
}

interface OpenAIChatCompletionResponse {
  readonly choices?: Array<{
    readonly message?: {
      readonly content?: string;
    };
  }>;
}

const DEFAULT_BASE_URL = "https://api.openai.com/v1";
const DEFAULT_MODEL = "gpt-4o-mini";
const DEFAULT_TEMPERATURE = 0;
const DEFAULT_MAX_TOKENS = 256;
const DEFAULT_TIMEOUT_MS = 10_000;

function resolveEndpoint(baseUrl: string | undefined): string {
  const base = (baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
  if (base.endsWith("/chat/completions")) return base;
  if (base.endsWith("/v1")) return `${base}/chat/completions`;
  return `${base}/v1/chat/completions`;
}

function stripJsonFence(content: string): string {
  return content
    .replace(/^```(?:json)?\s*\n?/i, "")
    .replace(/\n?```\s*$/i, "")
    .trim();
}

function clampConfidence(value: number): number {
  return Math.max(0, Math.min(1, value));
}

function normalizeJudgeResult(raw: unknown): ATRSemanticJudgeResult {
  if (raw === null || typeof raw !== "object") {
    throw new Error("Judge result must be a JSON object");
  }

  const obj = raw as Record<string, unknown>;
  const category = obj["category"];
  if (typeof category !== "string" || category.trim().length === 0) {
    throw new Error("Judge result missing category");
  }

  const confidence = Number(obj["confidence"]);
  if (!Number.isFinite(confidence)) {
    throw new Error("Judge result missing numeric confidence");
  }

  const evidence = obj["evidence"];
  return {
    category: category.trim(),
    confidence: clampConfidence(confidence),
    evidence:
      typeof evidence === "string" && evidence.trim().length > 0
        ? evidence.trim()
        : undefined,
  };
}

function parseJudgeContent(content: string): ATRSemanticJudgeResult {
  const cleaned = stripJsonFence(content);
  let parsed: unknown;
  try {
    parsed = JSON.parse(cleaned);
  } catch {
    throw new Error("Judge response was not valid JSON");
  }
  return normalizeJudgeResult(parsed);
}

function sanitizeFetchError(error: unknown): Error {
  if (error instanceof Error && error.name === "AbortError") {
    return new Error("Judge request timed out");
  }
  if (error instanceof Error) {
    return new Error(`Judge request failed: ${error.message}`);
  }
  return new Error("Judge request failed");
}

/**
 * Create an ATR semantic judge backed by an OpenAI-compatible chat endpoint.
 */
export function createOpenAICompatibleJudge(
  config: OpenAICompatibleJudgeConfig,
): ATRSemanticJudge {
  if (config.apiKey.trim().length === 0) {
    throw new Error("OpenAI-compatible judge requires apiKey");
  }

  const endpoint = resolveEndpoint(config.baseUrl);
  const model = config.model ?? DEFAULT_MODEL;
  const temperature = config.temperature ?? DEFAULT_TEMPERATURE;
  const maxTokens = config.maxTokens ?? DEFAULT_MAX_TOKENS;
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const jsonMode = config.jsonMode ?? true;

  return async ({ prompt }) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    const body: Record<string, unknown> = {
      model,
      messages: [{ role: "user", content: prompt }],
      temperature,
      max_tokens: maxTokens,
    };

    if (jsonMode) {
      body["response_format"] = { type: "json_object" };
    }

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          ...config.additionalHeaders,
          "Content-Type": "application/json",
          "Authorization": `Bearer ${config.apiKey}`,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const data = (await response.json()) as OpenAIChatCompletionResponse;
      const content = data.choices?.[0]?.message?.content;
      if (typeof content !== "string" || content.trim().length === 0) {
        throw new Error("Judge response missing message content");
      }

      return parseJudgeContent(content);
    } catch (error) {
      throw sanitizeFetchError(error);
    } finally {
      clearTimeout(timeout);
    }
  };
}
