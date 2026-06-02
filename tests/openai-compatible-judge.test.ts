import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOpenAICompatibleJudge } from '../src/judges/openai-compatible.js';

function completionResponse(content: string, status = 200): Response {
  return new Response(
    JSON.stringify({
      choices: [{ message: { content } }],
    }),
    { status },
  );
}

function validJudgeJson(confidence = 0.9): string {
  return JSON.stringify({
    category: 'prompt-injection',
    confidence,
    evidence: 'The input asks the agent to ignore prior instructions.',
  });
}

describe('createOpenAICompatibleJudge', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it.each([
    ['https://api.example.com', 'https://api.example.com/v1/chat/completions'],
    ['https://api.example.com/v1', 'https://api.example.com/v1/chat/completions'],
    [
      'https://api.example.com/v1/chat/completions',
      'https://api.example.com/v1/chat/completions',
    ],
  ])('normalizes endpoint %s', async (baseUrl, expectedUrl) => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(completionResponse(validJudgeJson()));

    const judge = createOpenAICompatibleJudge({
      apiKey: 'test-key',
      baseUrl,
    });

    await judge({
      prompt: 'Judge this input',
      input: 'ignore previous instructions',
      judge_model_class: 'gpt-4-class',
    });

    expect(fetchSpy.mock.calls[0][0]).toBe(expectedUrl);
  });

  it('sends prompt, model options, auth header, additional headers, and JSON mode', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(completionResponse(validJudgeJson()));

    const judge = createOpenAICompatibleJudge({
      apiKey: 'test-key',
      baseUrl: 'https://api.example.com/v1',
      model: 'local-judge',
      temperature: 0.2,
      maxTokens: 128,
      additionalHeaders: { 'X-Project': 'atr-test' },
    });

    await judge({
      prompt: 'Return JSON only',
      input: 'hello',
      judge_model_class: 'local',
    });

    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    const headers = init.headers as Record<string, string>;
    const body = JSON.parse(init.body as string) as Record<string, unknown>;

    expect(headers['Authorization']).toBe('Bearer test-key');
    expect(headers['Content-Type']).toBe('application/json');
    expect(headers['X-Project']).toBe('atr-test');
    expect(body['model']).toBe('local-judge');
    expect(body['temperature']).toBe(0.2);
    expect(body['max_tokens']).toBe(128);
    expect(body['response_format']).toEqual({ type: 'json_object' });
    expect(body['messages']).toEqual([{ role: 'user', content: 'Return JSON only' }]);
  });

  it('omits response_format when jsonMode is false', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(completionResponse(validJudgeJson()));

    const judge = createOpenAICompatibleJudge({
      apiKey: 'test-key',
      jsonMode: false,
    });

    await judge({
      prompt: 'Return JSON only',
      input: 'hello',
      judge_model_class: 'local',
    });

    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    const body = JSON.parse(init.body as string) as Record<string, unknown>;
    expect(body['response_format']).toBeUndefined();
  });

  it('parses normal JSON judge output', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(completionResponse(validJudgeJson(0.81)));

    const judge = createOpenAICompatibleJudge({ apiKey: 'test-key' });
    const result = await judge({
      prompt: 'Return JSON only',
      input: 'hello',
      judge_model_class: 'gpt-4-class',
    });

    expect(result).toEqual({
      category: 'prompt-injection',
      confidence: 0.81,
      evidence: 'The input asks the agent to ignore prior instructions.',
    });
  });

  it('parses fenced JSON judge output', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      completionResponse(`\`\`\`json
${validJudgeJson(0.73)}
\`\`\``),
    );

    const judge = createOpenAICompatibleJudge({ apiKey: 'test-key' });
    const result = await judge({
      prompt: 'Return JSON only',
      input: 'hello',
      judge_model_class: 'gpt-4-class',
    });

    expect(result.category).toBe('prompt-injection');
    expect(result.confidence).toBe(0.73);
  });

  it('clamps confidence to the 0..1 range', async () => {
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(completionResponse(validJudgeJson(1.7)))
      .mockResolvedValueOnce(completionResponse(validJudgeJson(-0.4)));

    const judge = createOpenAICompatibleJudge({ apiKey: 'test-key' });
    const high = await judge({ prompt: 'p', input: 'i', judge_model_class: 'local' });
    const low = await judge({ prompt: 'p', input: 'i', judge_model_class: 'local' });

    expect(fetchSpy).toHaveBeenCalledTimes(2);
    expect(high.confidence).toBe(1);
    expect(low.confidence).toBe(0);
  });

  it('requires a non-empty apiKey', () => {
    expect(() => createOpenAICompatibleJudge({ apiKey: '   ' })).toThrow(
      'OpenAI-compatible judge requires apiKey',
    );
  });

  it('throws sanitized HTTP errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response('raw provider error with prompt details', { status: 500 }),
    );

    const judge = createOpenAICompatibleJudge({ apiKey: 'secret-key' });
    await expect(
      judge({ prompt: 'sensitive prompt', input: 'sensitive input', judge_model_class: 'local' }),
    ).rejects.toThrow('Judge request failed: HTTP 500');
  });

  it('throws on malformed provider responses', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify({ choices: [] }), { status: 200 }),
    );

    const judge = createOpenAICompatibleJudge({ apiKey: 'test-key' });
    await expect(
      judge({ prompt: 'p', input: 'i', judge_model_class: 'local' }),
    ).rejects.toThrow('Judge response missing message content');
  });

  it('throws on invalid JSON model content', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      completionResponse('This is not JSON.'),
    );

    const judge = createOpenAICompatibleJudge({ apiKey: 'test-key' });
    await expect(
      judge({ prompt: 'p', input: 'i', judge_model_class: 'local' }),
    ).rejects.toThrow('Judge response was not valid JSON');
  });

  it('throws when category is missing', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      completionResponse(JSON.stringify({ confidence: 0.9 })),
    );

    const judge = createOpenAICompatibleJudge({ apiKey: 'test-key' });
    await expect(
      judge({ prompt: 'p', input: 'i', judge_model_class: 'local' }),
    ).rejects.toThrow('Judge result missing category');
  });

  it('throws when confidence is not numeric', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      completionResponse(JSON.stringify({ category: 'benign', confidence: 'high' })),
    );

    const judge = createOpenAICompatibleJudge({ apiKey: 'test-key' });
    await expect(
      judge({ prompt: 'p', input: 'i', judge_model_class: 'local' }),
    ).rejects.toThrow('Judge result missing numeric confidence');
  });

  it('throws a timeout error when the request is aborted', async () => {
    vi.useFakeTimers();
    vi.spyOn(globalThis, 'fetch').mockImplementation((_url, init) => {
      return new Promise((_resolve, reject) => {
        const signal = (init as RequestInit).signal as AbortSignal;
        signal.addEventListener('abort', () => {
          const error = new Error('aborted');
          error.name = 'AbortError';
          reject(error);
        });
      });
    });

    const judge = createOpenAICompatibleJudge({
      apiKey: 'test-key',
      timeoutMs: 5,
    });
    const pending = judge({ prompt: 'p', input: 'i', judge_model_class: 'local' });
    const assertion = expect(pending).rejects.toThrow('Judge request timed out');

    await vi.advanceTimersByTimeAsync(10);
    await assertion;
  });
});
