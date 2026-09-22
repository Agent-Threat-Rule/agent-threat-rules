/**
 * Threat Cloud Reporter — turns any ATR integration into a global sensor endpoint.
 *
 * Usage:
 *   import { ATREngine, createTCReporter } from 'agent-threat-rules';
 *
 *   const engine = new ATREngine({
 *     reporter: createTCReporter(),          // anonymous, no API key needed
 *   });
 *
 *   // or with explicit config:
 *   const engine = new ATREngine({
 *     reporter: createTCReporter({
 *       tcUrl: 'https://tc.panguard.ai',
 *       apiKey: process.env.TC_API_KEY,
 *       batchSize: 50,
 *       flushIntervalMs: 60_000,
 *     }),
 *   });
 *
 * Privacy: only ruleId, severity, category, confidence, contentHash, and timestamp
 * are sent. scanTarget is sanitized to a short label (max 64 chars, no path separators).
 * No raw content, no PII, no file paths.
 *
 * @module tc-reporter
 */

import { randomUUID } from 'node:crypto';
import type { ATRReporter, ATRDetectionReport, ATRCleanReport } from './engine.js';

const MAX_BUFFER = 1000;

/**
 * The endpoint used when reporting is switched on. Reporting itself is opt-in:
 * the CLI sends nothing unless --report-to-cloud is passed.
 *
 * Resolution order: explicit argument, then the ATR_TC_URL environment variable,
 * then the built-in default. The environment variable exists so that a deployment
 * can point the sensor at its own collector without patching this package.
 */
export const DEFAULT_TC_URL = 'https://tc.panguard.ai';

export function resolveTcUrl(explicit?: string): string {
  const raw = explicit ?? process.env.ATR_TC_URL ?? DEFAULT_TC_URL;
  return raw.replace(/\/+$/, '');
}

export interface TCReporterConfig {
  /** Threat Cloud endpoint. Default: ATR_TC_URL, else https://tc.panguard.ai */
  readonly tcUrl?: string;
  /** Optional API key for authenticated reporting. Default: env TC_API_KEY */
  readonly apiKey?: string;
  /** Flush buffer when it reaches this size. Default: 50 */
  readonly batchSize?: number;
  /** Periodic flush interval in ms. Default: 60000 (60s) */
  readonly flushIntervalMs?: number;
  /** Unique client ID. Default: random UUID per process */
  readonly clientId?: string;
  /** Called on flush errors. Default: no-op (silent). Provide your own logger. */
  readonly onError?: (error: Error) => void;
}

interface ThreatEvent {
  readonly ruleId: string;
  readonly severity: string;
  readonly category: string;
  readonly confidence: number;
  readonly contentHash: string;
  readonly timestamp: string;
  readonly scanTarget: string;
}

/**
 * Create an ATRReporter that buffers detection events and POSTs them
 * to ATR Threat Cloud in batches. Each reporter instance = one sensor endpoint.
 */
export function createTCReporter(config?: TCReporterConfig): ATRReporter & {
  flush(): Promise<void>;
  destroy(): Promise<void>;
} {
  const tcUrl = resolveTcUrl(config?.tcUrl);
  const apiKey = config?.apiKey ?? process.env.TC_API_KEY ?? '';
  const batchSize = config?.batchSize ?? 50;
  const flushIntervalMs = config?.flushIntervalMs ?? 60_000;
  const clientId = config?.clientId ?? randomUUID();
  const onError = config?.onError ?? (() => { /* silent by default — pass onError to log */ });

  // Enforce HTTPS for non-localhost
  if (tcUrl.startsWith('http://') && !isLocalhost(tcUrl)) {
    throw new Error('HTTPS required for Threat Cloud endpoint (use https://)');
  }

  let buffer: ThreatEvent[] = [];
  let flushing = false;
  let flushTimer: ReturnType<typeof setInterval> | null = null;

  // Start periodic flush
  flushTimer = setInterval(() => { void flushBuffer(); }, flushIntervalMs);
  // Don't keep the process alive just for flushing
  if (flushTimer && typeof flushTimer === 'object' && 'unref' in flushTimer) {
    flushTimer.unref();
  }

  async function flushBuffer(): Promise<void> {
    if (flushing || buffer.length === 0) return;
    flushing = true;

    const batch = [...buffer];
    buffer = [];

    // Map ATR events to TC ThreatDataSchema format.
    // Field name `sigmaRuleMatched` is legacy on the TC side (now stores ATR
    // rule ID) — reporter must match the API contract or requests get 400.
    const tcEvents = batch.map((e) => ({
      attackSourceIP: clientId,
      attackType: e.category,
      mitreTechnique: e.ruleId,
      sigmaRuleMatched: e.ruleId,
      timestamp: e.timestamp,
      region: 'unknown',
      // Extra fields for richer data (TC ignores unknown fields via Zod passthrough)
      severity: e.severity,
      confidence: e.confidence,
      contentHash: e.contentHash,
      scanTarget: e.scanTarget,
    }));

    try {
      const res = await fetch(`${tcUrl}/api/threats`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Panguard-Client-Id': clientId,
          ...(apiKey ? { 'Authorization': `Bearer ${apiKey}` } : {}),
        },
        body: JSON.stringify({ events: tcEvents }),
        signal: AbortSignal.timeout(10_000),
      });

      if (!res.ok) {
        buffer = [...batch, ...buffer].slice(0, MAX_BUFFER);
        onError(new Error(`TC upload failed: HTTP ${res.status}`));
      }
    } catch (err) {
      buffer = [...batch, ...buffer].slice(0, MAX_BUFFER);
      onError(err instanceof Error ? err : new Error(String(err)));
    } finally {
      flushing = false;
    }
  }

  function enqueue(event: ThreatEvent): void {
    buffer = [...buffer, event];
    // Cap buffer to prevent memory leak
    if (buffer.length >= MAX_BUFFER) {
      buffer = buffer.slice(-MAX_BUFFER);
    }
    // Auto-flush when batch size reached
    if (buffer.length >= batchSize) {
      void flushBuffer();
    }
  }

  const reporter: ATRReporter & {
    flush(): Promise<void>;
    destroy(): Promise<void>;
  } = {
    onDetection: (report: ATRDetectionReport) => {
      enqueue({
        ruleId: report.ruleId,
        severity: report.severity,
        category: report.category,
        confidence: report.confidence,
        contentHash: report.contentHash,
        timestamp: report.timestamp,
        scanTarget: sanitizeScanTarget(report.scanTarget),
      });
    },

    onClean: (report: ATRCleanReport) => {
      enqueue({
        ruleId: '__clean__',
        severity: 'none',
        category: 'clean',
        confidence: 1,
        contentHash: report.contentHash,
        timestamp: report.timestamp,
        scanTarget: sanitizeScanTarget(report.scanTarget),
      });
    },

    /** Manually flush all buffered events to TC. Call before process exit. */
    flush: flushBuffer,

    /** Stop periodic flush timer and flush remaining events. Await to ensure delivery. */
    async destroy() {
      if (flushTimer) {
        clearInterval(flushTimer);
        flushTimer = null;
      }
      await flushBuffer();
    },
  };

  return reporter;
}

/** Strip path separators and truncate to prevent PII leakage via scanTarget. */
function sanitizeScanTarget(target: string): string {
  return target
    .replace(/[/\\]/g, '-')
    .replace(/\.\./g, '')
    .slice(0, 64);
}

function isLocalhost(url: string): boolean {
  try {
    const parsed = new URL(url);
    const h = parsed.hostname;
    return h === 'localhost'
      || h === '127.0.0.1'
      || h === '::1'
      || h === '[::1]';
  } catch {
    return false;
  }
}
