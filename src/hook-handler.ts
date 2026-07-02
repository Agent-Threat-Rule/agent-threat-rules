/**
 * Hook Handler - Bridges Claude Code hooks to the ATR engine.
 *
 * Converts HookInput (PreToolUse/PostToolUse) into AgentEvents,
 * evaluates them, and returns HookOutput for the agent host.
 *
 * Supports a stdio JSON-lines loop for use as a Claude Code hook process.
 *
 * CRITICAL: Fail-open on all errors -- default to "allow" so a
 * bug in the guard never blocks legitimate agent operations.
 *
 * @module agent-threat-rules/hook-handler
 */

import { createInterface } from 'node:readline';
import type {
  AgentEvent,
  HookInput,
  HookOutput,
  VerdictOutcome,
} from './types.js';
import type { ATREngine } from './engine.js';
import type { ActionExecutor } from './action-executor.js';

/** Default evaluation timeout in milliseconds */
const DEFAULT_TIMEOUT_MS = 5_000;

export interface HookHandlerConfig {
  readonly engine: ATREngine;
  readonly executor: ActionExecutor;
  readonly timeoutMs?: number;
  readonly failOpen?: boolean;
}

/**
 * Create an "allow" hook output, used as the safe default.
 */
function allowOutput(reason?: string): HookOutput {
  return Object.freeze({
    decision: 'allow' as VerdictOutcome,
    reason: reason ?? 'No threat detected.',
  });
}

/**
 * Convert a HookInput into an AgentEvent for engine evaluation.
 */
function hookInputToEvent(input: HookInput): AgentEvent {
  const isPreTool = input.hook === 'PreToolUse';
  const type = isPreTool ? 'tool_call' : 'tool_response';

  const toolInput = input.tool_input ?? {};
  const content = typeof toolInput['content'] === 'string'
    ? toolInput['content']
    : JSON.stringify(toolInput);

  const fields: Record<string, string> = {
    tool_name: input.tool_name ?? '',
    tool_args: JSON.stringify(toolInput),
    content,
  };

  // For PostToolUse, include output/response if present
  if (!isPreTool) {
    const output = toolInput['output'] ?? toolInput['response'];
    if (typeof output === 'string') {
      fields['tool_response'] = output;
    }
  }

  return Object.freeze({
    type,
    timestamp: input.timestamp ?? new Date().toISOString(),
    content,
    fields: Object.freeze(fields),
    sessionId: input.session_id,
  });
}

/**
 * Run a promise with a timeout. Resolves to the promise result
 * or rejects with a timeout error.
 *
 * NOTE (ReDoS): this timeout is a race on the microtask/timer queue, so it can
 * only abort work that yields to the event loop (async layers — semantic judge,
 * embeddings, network). It CANNOT interrupt a synchronous RegExp: a
 * catastrophic-backtracking match monopolizes the single thread and the timer
 * callback is queued behind the very work it is meant to cancel. The real
 * defense against a pathological rule is compile-time rejection — see
 * isReDoSSafe / safeCompile in engine.ts — plus the MAX_EVAL_LENGTH input cap.
 */
function withTimeout<T>(
  promise: Promise<T>,
  ms: number
): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`Evaluation timed out after ${ms}ms`));
    }, ms);

    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (err) => { clearTimeout(timer); reject(err); }
    );
  });
}

export class HookHandler {
  private readonly engine: ATREngine;
  private readonly executor: ActionExecutor;
  private readonly timeoutMs: number;
  private readonly failOpen: boolean;

  constructor(config: HookHandlerConfig) {
    this.engine = config.engine;
    this.executor = config.executor;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.failOpen = config.failOpen ?? true;
  }

  /**
   * Handle a PreToolUse hook event.
   * Converts input to an AgentEvent, evaluates, and returns a HookOutput.
   */
  async handlePreToolUse(input: HookInput): Promise<HookOutput> {
    try {
      const event = hookInputToEvent(input);
      return await this.evaluateAndRespond(event);
    } catch (err) {
      return this.handleError(err);
    }
  }

  /**
   * Handle a PostToolUse hook event.
   * Scans the tool output for threats.
   */
  async handlePostToolUse(input: HookInput): Promise<HookOutput> {
    try {
      const event = hookInputToEvent(input);
      return await this.evaluateAndRespond(event);
    } catch (err) {
      return this.handleError(err);
    }
  }

  /**
   * Start a stdio JSON-lines loop.
   *
   * Reads one JSON object per line from stdin, dispatches to the
   * appropriate handler, and writes one JSON line to stdout.
   *
   * Exits cleanly when stdin closes.
   */
  async startStdioLoop(): Promise<void> {
    const rl = createInterface({
      input: process.stdin,
      crlfDelay: Infinity,
    });

    for await (const line of rl) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      let output: HookOutput;

      try {
        const input = JSON.parse(trimmed) as HookInput;
        output = await this.dispatch(input);
      } catch (err) {
        output = this.handleError(err);
      }

      process.stdout.write(JSON.stringify(output) + '\n');
    }
  }

  /**
   * Dispatch a HookInput to the appropriate handler.
   */
  private async dispatch(input: HookInput): Promise<HookOutput> {
    switch (input.hook) {
      case 'PreToolUse':
        return this.handlePreToolUse(input);
      case 'PostToolUse':
        return this.handlePostToolUse(input);
      default:
        return allowOutput(`Unknown hook type: ${String((input as unknown as Record<string, unknown>).hook)}`);
    }
  }

  /**
   * Evaluate an event with timeout and convert the verdict to HookOutput.
   */
  private async evaluateAndRespond(event: AgentEvent): Promise<HookOutput> {
    const { verdict } = await withTimeout(
      this.engine.evaluateWithVerdict(event, this.executor),
      this.timeoutMs
    );

    const matchedRules = verdict.matches.map((m) => m.rule.id);

    return Object.freeze({
      decision: verdict.outcome,
      reason: verdict.reason,
      message: verdict.outcome === 'deny'
        ? `Blocked: ${verdict.reason}`
        : undefined,
      matched_rules: matchedRules.length > 0
        ? Object.freeze(matchedRules)
        : undefined,
    });
  }

  /**
   * Handle errors with fail-open or fail-closed behavior.
   */
  private handleError(err: unknown): HookOutput {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`[atr-guard] Error: ${message}\n`);

    if (this.failOpen) {
      return allowOutput(`Guard error (fail-open): ${message}`);
    }

    return Object.freeze({
      decision: 'deny' as VerdictOutcome,
      reason: `Guard error (fail-closed): ${message}`,
    });
  }
}
