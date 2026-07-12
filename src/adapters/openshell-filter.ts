/**
 * OpenShell content-inspection filter — ATR reference binding for NVIDIA OpenShell.
 *
 * Implements the external content-filter contract proposed in
 * NVIDIA/OpenShell#1272 ("L7 content inspection hooks — scriptable
 * request/response filtering"): the OpenShell *supervisor* (outside the agent
 * sandbox) runs this as a script against L7 request/response bodies. The body
 * arrives on stdin; the script signals the verdict via exit code:
 *
 *   exit 0  -> allow  (no rule at/above the deny threshold matched)
 *   exit 1  -> deny   (the verdict JSON, with reasons, is written to stdout)
 *   exit 2  -> internal error (supervisor applies its on_timeout/on_error policy)
 *
 * Two run modes:
 *   one-shot (default): read the whole body from stdin, evaluate, exit.
 *       Matches the #1272 contract literally. Cold-starts the engine per call.
 *   serve (--serve):    read NDJSON requests line-by-line from stdin and write
 *       one NDJSON verdict per line. Loads the rule set ONCE, so per-request
 *       latency is just regex evaluation (sub-ms). Production path for a
 *       persistent guard service (cf. NVIDIA/OpenShell#1733 RFC 0005). A bad
 *       line (or an engine error) yields a per-line error verdict and the
 *       stream continues — one malformed body cannot take the inspector offline.
 *
 * Output is the canonical ATR detection event (atr.* fields per the engine
 * INTERFACE-CONTRACT). Matched raw values are redacted by default
 * (ATR_FORENSIC_MODE=1 to retain), satisfying the "audit evidence without
 * storing raw sensitive values" requirement of the egress-middleware RFC (#1733).
 *
 * Environment (aligned with engines/{go,typescript}/INTERFACE-CONTRACT.md):
 *   ATR_RULES_DIR | ATR_CORPUS_PATH  rule directory (default: bundled rules)
 *   ATR_MIN_SEVERITY                 deny at or above this severity (default high)
 *   ATR_FORENSIC_MODE                "1"/"true" to retain raw matched values
 *   ATR_MAX_BODY_BYTES               stdin hard cap (default 524288)
 *
 * Adds NO new dependency: reuses the canonical ATREngine. It does not decide
 * routing (that is OpenShell's Privacy Router, #1043) — it only inspects content
 * and returns allow/deny, per the #1272 separation of concerns.
 *
 * @module agent-threat-rules/openshell-filter
 */

import { createInterface } from 'node:readline';
import { ATREngine } from '../engine.js';
import type { AgentEvent, ATRMatch } from '../types.js';

/** L7 traffic direction, mirroring OpenShell #1272 `content_filters[].direction`. */
export type Direction = 'request' | 'response';

/** Verdict decision returned to the supervisor. */
export type Decision = 'allow' | 'deny';

/** Severity ordering for the deny threshold (ATR_MIN_SEVERITY). */
const SEVERITY_RANK: Readonly<Record<string, number>> = Object.freeze({
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
});

const DEFAULT_MIN_SEVERITY = 'high';
const DEFAULT_MAX_BODY_BYTES = 512 * 1024;
const REDACTED = '[REDACTED]';

function severityRank(severity: string): number {
  return SEVERITY_RANK[severity.toLowerCase()] ?? 0;
}

export interface FilterOptions {
  /** Inbound response (agent will consume) vs outbound request (agent is sending). */
  readonly direction: Direction;
  /** Deny when a matched rule's severity is at or above this (default "high"). */
  readonly minSeverity: string;
  /** Directory of ATR rule YAML files. Omit to use the rules bundled with the package. */
  readonly rulesDir?: string;
  /** When true, include the raw matched value instead of redacting it. */
  readonly forensic: boolean;
}

/**
 * A single finding, shaped after the canonical ATR detection event
 * (engines/go/INTERFACE-CONTRACT.md). Only the subset an inline content filter
 * can populate is emitted; the supervisor enriches agent/session/service fields.
 */
export interface Finding {
  readonly 'atr.rule_id': string;
  readonly 'atr.severity': string;
  readonly 'atr.category': string;
  readonly 'atr.confidence': number;
  readonly 'atr.matched_field': string;
  readonly 'atr.matched_value_redacted': string;
}

export interface FilterVerdict {
  readonly decision: Decision;
  readonly findings: readonly Finding[];
}

/**
 * Map an OpenShell traffic direction to the ATR event channel.
 *
 * - response: content flowing INTO the agent (model reply, tool/web response).
 *   Scanned as `llm_input` so indirect-prompt-injection rules fire — the danger
 *   is the agent acting on injected instructions it just received.
 * - request: content flowing OUT of the agent (the prompt/tool args it is
 *   sending). Scanned as `llm_output` so data-exfiltration / secret-leak rules
 *   fire before the body leaves the sandbox boundary.
 */
function directionToEventType(direction: Direction): AgentEvent['type'] {
  return direction === 'response' ? 'llm_input' : 'llm_output';
}

/**
 * Convert an engine match into a redaction-safe canonical finding. `channel` is
 * the ATR event channel that was scanned (llm_input for an inbound response,
 * llm_output for an outbound request) — the honest value for atr.matched_field
 * when the whole body is inspected as a single field. In forensic mode the
 * field carries the matched rule pattern (not redacted); otherwise [REDACTED].
 */
function toFinding(match: ATRMatch, channel: string, forensic: boolean): Finding {
  const matchedPattern = match.matchedPatterns?.[0];
  return {
    'atr.rule_id': match.rule.id,
    'atr.severity': match.rule.severity,
    'atr.category': match.rule.tags?.category ?? 'unknown',
    'atr.confidence': match.confidence,
    'atr.matched_field': channel,
    'atr.matched_value_redacted': forensic && matchedPattern ? matchedPattern : REDACTED,
  };
}

/**
 * The ATR content inspector. Construct once, reuse across many bodies (the
 * `serve` path does exactly this so the rule set loads a single time).
 */
export class OpenShellFilter {
  private readonly engine: ATREngine;
  private readonly denyRank: number;
  private loadPromise: Promise<number> | null = null;

  constructor(private readonly options: FilterOptions) {
    this.engine = new ATREngine(options.rulesDir ? { rulesDir: options.rulesDir } : {});
    this.denyRank = severityRank(options.minSeverity);
  }

  /** Load rules exactly once, even under concurrent first calls. */
  private ensureLoaded(): Promise<number> {
    if (this.loadPromise === null) this.loadPromise = this.engine.loadRules();
    return this.loadPromise;
  }

  /**
   * Inspect one body. Returns a deny verdict when any rule at or above the
   * configured deny threshold matches; otherwise allow. Never throws on
   * benign/empty input.
   */
  async inspect(body: string): Promise<FilterVerdict> {
    await this.ensureLoaded();
    if (!body.trim()) return { decision: 'allow', findings: [] };

    const channel = directionToEventType(this.options.direction);
    const event: AgentEvent = {
      type: channel,
      timestamp: new Date().toISOString(),
      content: body,
    };

    const matches = this.engine.evaluate(event);
    const blocking = matches.filter((m) => severityRank(m.rule.severity) >= this.denyRank);

    return {
      decision: blocking.length > 0 ? 'deny' : 'allow',
      findings: blocking.map((m) => toFinding(m, channel, this.options.forensic)),
    };
  }
}

// ── CLI wiring (the script the OpenShell supervisor execs) ───────────────────

/** Parse the required --direction flag. Throws (fail-closed) on missing/invalid. */
export function parseDirection(arg: string | undefined): Direction {
  if (arg === 'request' || arg === 'response') return arg;
  throw new Error(`unknown --direction "${arg ?? '(missing)'}"; expected "request" or "response"`);
}

function argValue(argv: readonly string[], flag: string): string | undefined {
  const i = argv.indexOf(flag);
  return i >= 0 && i + 1 < argv.length ? argv[i + 1] : undefined;
}

/** Build FilterOptions from argv + the ATR_* environment contract. */
export function optionsFromEnv(argv: readonly string[]): FilterOptions {
  const minRaw = (process.env['ATR_MIN_SEVERITY'] ?? DEFAULT_MIN_SEVERITY).toLowerCase();
  const minSeverity = SEVERITY_RANK[minRaw] !== undefined ? minRaw : DEFAULT_MIN_SEVERITY;
  const forensicRaw = process.env['ATR_FORENSIC_MODE'];
  return {
    direction: parseDirection(argValue(argv, '--direction')),
    minSeverity,
    rulesDir: process.env['ATR_RULES_DIR'] ?? process.env['ATR_CORPUS_PATH'] ?? undefined,
    forensic: forensicRaw === '1' || forensicRaw === 'true',
  };
}

function maxBodyBytes(): number {
  const n = Number.parseInt(process.env['ATR_MAX_BODY_BYTES'] ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : DEFAULT_MAX_BODY_BYTES;
}

async function readStdin(limitBytes: number): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    total += (chunk as Buffer).length;
    if (total > limitBytes) {
      throw new Error(`stdin exceeds ATR_MAX_BODY_BYTES (${limitBytes})`);
    }
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** One-shot: whole body on stdin, verdict via exit code. Implements #1272. */
async function runOneShot(filter: OpenShellFilter, limitBytes: number): Promise<number> {
  const body = await readStdin(limitBytes);
  const verdict = await filter.inspect(body);
  // Verdict (with reasons) on stdout so the supervisor can surface it in the 403.
  process.stdout.write(JSON.stringify(verdict) + '\n');
  return verdict.decision === 'deny' ? 1 : 0;
}

/**
 * Serve: NDJSON request per line ({"id":"..","body":".."}), NDJSON verdict per
 * line. Rules load once. A malformed line or an engine error yields a per-line
 * error verdict and the loop continues — a single bad body cannot DoS the
 * inspector (which would otherwise fail open under the supervisor's on_timeout).
 */
async function runServe(filter: OpenShellFilter): Promise<number> {
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let id: string | undefined;
    let body = '';
    try {
      const req = JSON.parse(line) as { id?: string; body?: string };
      id = req.id;
      body = typeof req.body === 'string' ? req.body : '';
    } catch {
      process.stdout.write(JSON.stringify({ id, error: 'invalid_json' }) + '\n');
      continue;
    }
    // Enforce the same hard cap as one-shot mode (ATR_MAX_BODY_BYTES); without
    // it a single oversized NDJSON line would pass an uncapped body to the engine.
    if (Buffer.byteLength(body, 'utf8') > maxBodyBytes()) {
      process.stdout.write(JSON.stringify({ id, error: 'body_too_large' }) + '\n');
      continue;
    }
    let verdict: FilterVerdict;
    try {
      verdict = await filter.inspect(body);
    } catch {
      process.stdout.write(JSON.stringify({ id, error: 'engine_error' }) + '\n');
      continue;
    }
    process.stdout.write(JSON.stringify({ id, ...verdict }) + '\n');
  }
  return 0;
}

async function main(argv: readonly string[]): Promise<number> {
  const filter = new OpenShellFilter(optionsFromEnv(argv));
  return argv.includes('--serve') ? runServe(filter) : runOneShot(filter, maxBodyBytes());
}

const isDirectInvocation = Boolean(process.argv[1]) && import.meta.url === `file://${process.argv[1]}`;
if (isDirectInvocation) {
  main(process.argv.slice(2))
    .then((code) => process.exit(code))
    .catch((err) => {
      process.stderr.write(`openshell-filter: ${err instanceof Error ? err.message : String(err)}\n`);
      process.exit(2);
    });
}
