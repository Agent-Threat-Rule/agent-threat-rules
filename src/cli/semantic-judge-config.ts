import { createOpenAICompatibleJudge } from '../judges/openai-compatible.js';
import type { ATRSemanticJudge } from '../types.js';

export interface SemanticJudgeConfigResult {
  readonly enabled: boolean;
  readonly judge?: ATRSemanticJudge;
}

function envEnabled(value: string | undefined): boolean {
  if (!value) return false;
  return ['1', 'true', 'yes', 'on'].includes(value.toLowerCase());
}

function parsePositiveInt(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

export function createSemanticJudgeFromConfig(
  options: Record<string, string> = {},
): SemanticJudgeConfigResult {
  const enabled =
    options['semantic'] === 'true' ||
    envEnabled(process.env['ATR_SEMANTIC']);

  if (!enabled) {
    return { enabled: false };
  }

  const apiKey =
    options['semantic-api-key'] ??
    process.env['ATR_SEMANTIC_API_KEY'] ??
    process.env['LLM_API_KEY'];

  if (!apiKey) {
    throw new Error(
      'Semantic judge enabled but no API key configured. Set --semantic-api-key, ATR_SEMANTIC_API_KEY, or LLM_API_KEY.',
    );
  }

  const baseUrl =
    options['semantic-base-url'] ??
    process.env['ATR_SEMANTIC_BASE_URL'] ??
    process.env['LLM_BASE_URL'];

  const model =
    options['semantic-model'] ??
    process.env['ATR_SEMANTIC_MODEL'] ??
    process.env['LLM_MODEL'];

  const timeoutMs = parsePositiveInt(
    options['semantic-timeout'] ?? process.env['ATR_SEMANTIC_TIMEOUT_MS'],
  );

  const jsonMode = options['semantic-no-json-mode'] === 'true' ? false : undefined;

  return {
    enabled: true,
    judge: createOpenAICompatibleJudge({
      apiKey,
      baseUrl,
      model,
      timeoutMs,
      jsonMode,
    }),
  };
}
