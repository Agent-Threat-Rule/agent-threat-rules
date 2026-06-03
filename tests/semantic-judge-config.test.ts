import { afterEach, describe, expect, it } from 'vitest';
import { createSemanticJudgeFromConfig } from '../src/cli/semantic-judge-config.js';

const ENV_KEYS = [
  'ATR_SEMANTIC',
  'ATR_SEMANTIC_API_KEY',
  'ATR_SEMANTIC_BASE_URL',
  'ATR_SEMANTIC_MODEL',
  'ATR_SEMANTIC_TIMEOUT_MS',
  'LLM_API_KEY',
  'LLM_BASE_URL',
  'LLM_MODEL',
] as const;

const ORIGINAL_ENV = Object.fromEntries(
  ENV_KEYS.map((key) => [key, process.env[key]]),
) as Record<typeof ENV_KEYS[number], string | undefined>;

function clearSemanticEnv(): void {
  for (const key of ENV_KEYS) {
    delete process.env[key];
  }
}

describe('createSemanticJudgeFromConfig', () => {
  afterEach(() => {
    clearSemanticEnv();
    for (const key of ENV_KEYS) {
      const value = ORIGINAL_ENV[key];
      if (value !== undefined) {
        process.env[key] = value;
      }
    }
  });

  it('is disabled by default', () => {
    clearSemanticEnv();
    const result = createSemanticJudgeFromConfig();
    expect(result.enabled).toBe(false);
    expect(result.judge).toBeUndefined();
  });

  it('requires an API key when explicitly enabled', () => {
    clearSemanticEnv();
    expect(() => createSemanticJudgeFromConfig({ semantic: 'true' })).toThrow(
      /no API key configured/,
    );
  });

  it('creates a judge from CLI-style options', () => {
    clearSemanticEnv();
    const result = createSemanticJudgeFromConfig({
      semantic: 'true',
      'semantic-api-key': 'test-key',
      'semantic-base-url': 'http://localhost:11434/v1',
      'semantic-model': 'local-judge',
      'semantic-timeout': '1234',
      'semantic-no-json-mode': 'true',
    });

    expect(result.enabled).toBe(true);
    expect(result.judge).toBeTypeOf('function');
  });

  it('creates a judge from environment opt-in', () => {
    clearSemanticEnv();
    process.env.ATR_SEMANTIC = '1';
    process.env.ATR_SEMANTIC_API_KEY = 'env-key';

    const result = createSemanticJudgeFromConfig();

    expect(result.enabled).toBe(true);
    expect(result.judge).toBeTypeOf('function');
  });
});
