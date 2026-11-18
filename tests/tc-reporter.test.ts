import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createTCReporter } from '../src/tc-reporter.js';
import type { ATRDetectionReport, ATRCleanReport } from '../src/engine.js';

const DETECTION: ATRDetectionReport = {
  ruleId: 'ATR-001',
  severity: 'HIGH',
  scanTarget: 'test-skill',
  category: 'prompt-injection',
  confidence: 0.95,
  timestamp: '2026-04-08T00:00:00Z',
  contentHash: 'sha256-abc123',
};

const CLEAN: ATRCleanReport = {
  rulesEvaluated: 100,
  scanTarget: 'clean-skill',
  timestamp: '2026-04-08T00:00:00Z',
  contentHash: 'sha256-def456',
};

function mockFetchOk() {
  return vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    new Response(JSON.stringify({ ok: true }), { status: 200 }),
  );
}

describe('createTCReporter', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // ── HTTPS Enforcement ──────────────────────────────────────────

  it('requires HTTPS for non-localhost', () => {
    expect(() => createTCReporter({ tcUrl: 'http://evil.com' })).toThrow('HTTPS required');
  });

  it('allows HTTP for localhost', async () => {
    const reporter = createTCReporter({ tcUrl: 'http://localhost:3000' });
    await reporter.destroy();
    expect(reporter).toBeDefined();
  });

  it('allows HTTP for 127.0.0.1', async () => {
    const reporter = createTCReporter({ tcUrl: 'http://127.0.0.1:3000' });
    await reporter.destroy();
    expect(reporter).toBeDefined();
  });

  it('allows HTTP for IPv6 loopback [::1]', async () => {
    const reporter = createTCReporter({ tcUrl: 'http://[::1]:3000' });
    await reporter.destroy();
    expect(reporter).toBeDefined();
  });

  // ── Batching ───────────────────────────────────────────────────

  it('buffers events and flushes at batchSize', async () => {
    const fetchSpy = mockFetchOk();

    const reporter = createTCReporter({
      tcUrl: 'http://localhost:3000',
      batchSize: 2,
      flushIntervalMs: 999_999_999,
    });

    reporter.onDetection(DETECTION);
    expect(fetchSpy).not.toHaveBeenCalled();

    reporter.onDetection({ ...DETECTION, ruleId: 'ATR-002' });
    await vi.advanceTimersByTimeAsync(50);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const body = JSON.parse(fetchSpy.mock.calls[0][1]!.body as string);
    expect(body.events).toHaveLength(2);
    expect(body.events[0].sigmaRuleMatched).toBe('ATR-001');
    expect(body.events[1].sigmaRuleMatched).toBe('ATR-002');

    await reporter.destroy();
  });

  it('periodic flush sends buffered events', async () => {
    const fetchSpy = mockFetchOk();

    const reporter = createTCReporter({
      tcUrl: 'http://localhost:3000',
      batchSize: 100,
      flushIntervalMs: 5000,
    });

    reporter.onDetection(DETECTION);
    expect(fetchSpy).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(5100);

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    await reporter.destroy();
  });

  it('flush() sends remaining events', async () => {
    const fetchSpy = mockFetchOk();

    const reporter = createTCReporter({
      tcUrl: 'http://localhost:3000',
      batchSize: 100,
      flushIntervalMs: 999_999_999,
    });

    reporter.onDetection(DETECTION);
    await reporter.flush();

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    await reporter.destroy();
  });

  // ── Headers ────────────────────────────────────────────────────

  it('sends correct headers with API key', async () => {
    const fetchSpy = mockFetchOk();

    const reporter = createTCReporter({
      tcUrl: 'http://localhost:3000',
      apiKey: 'test-key-123',
      batchSize: 1,
      flushIntervalMs: 999_999_999,
    });

    reporter.onDetection(DETECTION);
    await vi.advanceTimersByTimeAsync(50);

    const headers = fetchSpy.mock.calls[0][1]!.headers as Record<string, string>;
    expect(headers['Authorization']).toBe('Bearer test-key-123');
    // One client-id header, vendor-neutral. The legacy alias was dropped.
    expect(Object.keys(headers).filter((h) => /client-id/i.test(h))).toEqual(['X-ATR-Client-Id']);
    expect(headers['Content-Type']).toBe('application/json');

    await reporter.destroy();
  });

  it('omits Authorization header when no API key', async () => {
    const fetchSpy = mockFetchOk();

    const reporter = createTCReporter({
      tcUrl: 'http://localhost:3000',
      batchSize: 1,
      flushIntervalMs: 999_999_999,
    });

    reporter.onDetection(DETECTION);
    await vi.advanceTimersByTimeAsync(50);

    const headers = fetchSpy.mock.calls[0][1]!.headers as Record<string, string>;
    expect(headers['Authorization']).toBeUndefined();

    await reporter.destroy();
  });

  // ── Clean Events ───────────────────────────────────────────────

  it('handles onClean events', async () => {
    const fetchSpy = mockFetchOk();

    const reporter = createTCReporter({
      tcUrl: 'http://localhost:3000',
      batchSize: 1,
      flushIntervalMs: 999_999_999,
    });

    reporter.onClean!(CLEAN);
    await vi.advanceTimersByTimeAsync(50);

    const body = JSON.parse(fetchSpy.mock.calls[0][1]!.body as string);
    expect(body.events[0].sigmaRuleMatched).toBe('__clean__');
    expect(body.events[0].scanTarget).toBe('clean-skill');

    await reporter.destroy();
  });

  // ── Error Handling ─────────────────────────────────────────────

  it('retains events on HTTP error', async () => {
    const errors: string[] = [];
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(new Response('Server Error', { status: 500 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const reporter = createTCReporter({
      tcUrl: 'http://localhost:3000',
      batchSize: 1,
      flushIntervalMs: 999_999_999,
      onError: (err) => { errors.push(err.message); },
    });

    reporter.onDetection(DETECTION);
    await vi.advanceTimersByTimeAsync(50);

    expect(errors[0]).toContain('HTTP 500');
    await reporter.flush();
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    const body = JSON.parse(fetchSpy.mock.calls[1][1]!.body as string);
    expect(body.events[0].sigmaRuleMatched).toBe('ATR-001');

    await reporter.destroy();
  });

  it('retains events on network error', async () => {
    vi.useRealTimers();

    const errors: string[] = [];
    vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('ECONNREFUSED'));

    const reporter = createTCReporter({
      tcUrl: 'http://localhost:3000',
      batchSize: 1,
      flushIntervalMs: 999_999_999,
      onError: (err) => { errors.push(err.message); },
    });

    reporter.onDetection(DETECTION);
    await new Promise((r) => setTimeout(r, 50));

    expect(errors[0]).toBe('ECONNREFUSED');
    await reporter.destroy();
  });

  // ── Concurrent Flush Guard ─────────────────────────────────────

  it('prevents concurrent flushes', async () => {
    let resolveFirst!: (v: Response) => void;
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockImplementationOnce(() => new Promise((resolve) => { resolveFirst = resolve; }))
      .mockResolvedValue(new Response(JSON.stringify({ ok: true }), { status: 200 }));

    const reporter = createTCReporter({
      tcUrl: 'http://localhost:3000',
      batchSize: 100,
      flushIntervalMs: 999_999_999,
    });

    reporter.onDetection(DETECTION);
    const firstFlush = reporter.flush();
    // Second flush while first is in-flight — should be skipped
    const secondFlush = reporter.flush();

    resolveFirst(new Response(JSON.stringify({ ok: true }), { status: 200 }));
    await firstFlush;
    await secondFlush;

    // Only one fetch call — second was skipped because flushing=true
    expect(fetchSpy).toHaveBeenCalledTimes(1);

    await reporter.destroy();
  });

  // ── Buffer Cap ─────────────────────────────────────────────────

  it('caps buffer at 1000 events', async () => {
    const fetchSpy = mockFetchOk();

    const reporter = createTCReporter({
      tcUrl: 'http://localhost:3000',
      batchSize: 9999,
      flushIntervalMs: 999_999_999,
    });

    for (let i = 0; i < 1100; i++) {
      reporter.onDetection({ ...DETECTION, ruleId: `ATR-${i}` });
    }

    await reporter.flush();
    const body = JSON.parse(fetchSpy.mock.calls[0][1]!.body as string);
    expect(body.events.length).toBeLessThanOrEqual(1000);

    await reporter.destroy();
  });

  // ── Privacy / PII ──────────────────────────────────────────────

  it('does not send PII — only anonymized fields', async () => {
    const fetchSpy = mockFetchOk();

    const reporter = createTCReporter({
      tcUrl: 'http://localhost:3000',
      batchSize: 1,
      flushIntervalMs: 999_999_999,
    });

    reporter.onDetection(DETECTION);
    await vi.advanceTimersByTimeAsync(50);

    const body = JSON.parse(fetchSpy.mock.calls[0][1]!.body as string);
    const event = body.events[0];
    // TC ThreatDataSchema format: mapped from internal ATR fields
    expect(event.sigmaRuleMatched).toBe('ATR-001');
    expect(event.attackType).toBe('prompt-injection');
    expect(event.mitreTechnique).toBe('ATR-001');
    expect(event.region).toBe('unknown');
    expect(event.timestamp).toBeDefined();
    // Extra fields for richer data
    expect(event.severity).toBe('HIGH');
    expect(event.confidence).toBe(0.95);
    expect(event.contentHash).toBe('sha256-abc123');

    await reporter.destroy();
  });

  it('sanitizes scanTarget — strips paths and truncates', async () => {
    const fetchSpy = mockFetchOk();

    const reporter = createTCReporter({
      tcUrl: 'http://localhost:3000',
      batchSize: 1,
      flushIntervalMs: 999_999_999,
    });

    reporter.onDetection({
      ...DETECTION,
      scanTarget: '/Users/secret/path/to/../../etc/passwd',
    });
    await vi.advanceTimersByTimeAsync(50);

    const body = JSON.parse(fetchSpy.mock.calls[0][1]!.body as string);
    const target = body.events[0].scanTarget;
    expect(target).not.toContain('/');
    expect(target).not.toContain('\\');
    expect(target).not.toContain('..');
    expect(target.length).toBeLessThanOrEqual(64);

    await reporter.destroy();
  });

  // ── destroy() awaits flush ─────────────────────────────────────

  it('destroy() awaits flush before returning', async () => {
    const fetchSpy = mockFetchOk();

    const reporter = createTCReporter({
      tcUrl: 'http://localhost:3000',
      batchSize: 100,
      flushIntervalMs: 999_999_999,
    });

    reporter.onDetection(DETECTION);
    await reporter.destroy();

    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  // ── Export ─────────────────────────────────────────────────────

  it('exports from index', async () => {
    const mod = await import('../src/index.js');
    expect(mod.createTCReporter).toBeDefined();
    expect(typeof mod.createTCReporter).toBe('function');
  });
});
