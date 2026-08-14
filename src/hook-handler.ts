/**
 * Hook Handler - Bridges Claude Code hooks to the ATR engine.
 *
 * Converts HookInput (PreToolUse/PostToolUse) into AgentEvents,
 * evaluates them, and returns HookOutput for the agent host.
 *
 * Supports a stdio JSON-lines loop for use as a Claude Code hook process.
 *
 * CRITICAL: Fail-open on all errors -- default to "allow" so a
 * bug in the guard never blocks legitimate agent operations. `failOpen: false`
 * flips the internal verdict to deny, but note that a deny only reaches the host
 * when blocking is enabled (below); in advisory mode a fail-closed guard error
 * is still reported without a permissionDecision, because advisory mode's
 * contract is "ATR never votes on permission".
 *
 * BLOCKING IS OPT-IN. By default this handler emits detection facts and no
 * permission decision at all: the PreToolUse payload omits
 * hookSpecificOutput.permissionDecision and the PostToolUse payload omits
 * `decision: 'block'`, so Claude Code applies exactly the flow it would use with
 * no hook installed. Turning blocking on restores the historical severity +
 * confidence matrix verbatim. See src/enforcement.ts.
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
import { resolveBlocking } from './enforcement.js';

/** Default evaluation timeout in milliseconds */
const DEFAULT_TIMEOUT_MS = 5_000;

/** Options for the Claude Code contract mappers. */
export interface HookContractOptions {
  /**
   * Emit a real permission decision. Defaults to FALSE (advisory): the payload
   * carries ATR's findings but no permissionDecision / no `decision: 'block'`,
   * leaving the host's own permission flow untouched.
   */
  readonly blocking?: boolean;
}

export interface HookHandlerConfig {
  readonly engine: ATREngine;
  readonly executor: ActionExecutor;
  readonly timeoutMs?: number;
  readonly failOpen?: boolean;
  /**
   * Operator directive permitting ATR to emit a blocking permission decision.
   * OFF BY DEFAULT. Resolution order: this field > ATR_BLOCKING > false.
   * Enabling it reproduces the pre-existing severity+confidence matrix exactly.
   */
  readonly blocking?: boolean;
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
 * Map a verdict to the Claude Code PreToolUse hook contract.
 *
 * CRITICAL (finding #8 — silent non-enforcement): `atr init` wires this guard
 * into Claude Code's PreToolUse hook, but Claude Code ONLY honors a block when
 * it reads hookSpecificOutput.permissionDecision === 'deny' (or exit code 2).
 * The generic { decision } shape ATR emits internally is an unknown field to
 * Claude Code — it silently ignores it and runs the tool anyway. That is fake
 * protection: the hook looks installed and never blocks. VerdictOutcome
 * (allow|ask|deny) maps 1:1 onto permissionDecision, so we emit the exact
 * contract. ATR fields are carried alongside under non-colliding keys for logs
 * and non-Claude-Code consumers; we deliberately do NOT emit a top-level
 * `decision` here, so Claude Code cannot misread a stray field.
 *
 * ADVISORY MODE (the default — `blocking` unset or false): permissionDecision is
 * OMITTED, not downgraded. `permissionDecision: "allow"` is an affirmative
 * approval in this contract: it suppresses the host's own permission prompt, so
 * emitting it for a verdict ATR is not enforcing would make a tool the host
 * would have asked about run silently instead. Omitting the field leaves the
 * host on its own default path. permissionDecisionReason goes with it — a reason
 * without a decision is not part of the contract — so the findings travel in the
 * atr_* keys and, for `atr guard`, on stderr via the adapter's alert action.
 */
export function toClaudeCodePreToolUse(
  output: HookOutput,
  options: HookContractOptions = {}
): Record<string, unknown> {
  const advisory = !(options.blocking ?? false);

  if (advisory) {
    return {
      hookSpecificOutput: { hookEventName: 'PreToolUse' },
      atr_advisory: true,
      atr_decision: output.decision,
      atr_reason: output.reason ?? output.message ?? '',
      ...(output.matched_rules ? { matched_rules: output.matched_rules } : {}),
    };
  }

  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: output.decision,
      permissionDecisionReason: output.reason ?? output.message ?? '',
    },
    atr_decision: output.decision,
    ...(output.matched_rules ? { matched_rules: output.matched_rules } : {}),
  };
}

/**
 * Map a verdict to the Claude Code PostToolUse hook contract. The tool has
 * already run, so PostToolUse cannot un-run it — Claude Code blocks by feeding
 * `decision: 'block'` + reason back to the model (stops it trusting poisoned
 * tool output). A deny OR ask verdict blocks; allow passes. The generic ATR
 * decision is preserved under atr_decision to avoid colliding with Claude
 * Code's 'block' sentinel on the shared `decision` key.
 *
 * ADVISORY MODE (the default): `decision: 'block'` is omitted. There is no
 * "allow" sentinel to downgrade to on this path — the absence of the key IS the
 * pass-through — so advisory mode simply never sets it, and the findings still
 * travel in atr_decision / atr_reason / matched_rules.
 */
export function toClaudeCodePostToolUse(
  output: HookOutput,
  options: HookContractOptions = {}
): Record<string, unknown> {
  const blocking = options.blocking ?? false;
  const block = blocking && (output.decision === 'deny' || output.decision === 'ask');
  return {
    hookSpecificOutput: { hookEventName: 'PostToolUse' },
    ...(blocking ? {} : { atr_advisory: true }),
    atr_decision: output.decision,
    ...(blocking ? {} : { atr_reason: output.reason ?? output.message ?? '' }),
    ...(output.matched_rules ? { matched_rules: output.matched_rules } : {}),
    ...(block ? { decision: 'block', reason: output.reason ?? output.message ?? '' } : {}),
  };
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
  private readonly blocking: boolean;

  constructor(config: HookHandlerConfig) {
    this.engine = config.engine;
    this.executor = config.executor;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.failOpen = config.failOpen ?? true;
    this.blocking = resolveBlocking(config.blocking);
  }

  /** Is this handler permitted to emit a blocking permission decision? */
  isBlocking(): boolean {
    return this.blocking;
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
  async startStdioLoop(format: 'claude-code' | 'generic' = 'claude-code'): Promise<void> {
    const rl = createInterface({
      input: process.stdin,
      crlfDelay: Infinity,
    });

    for await (const line of rl) {
      const trimmed = line.trim();
      if (!trimmed) continue;

      let output: HookOutput;
      // Default to PreToolUse framing: an unparseable line has no hook type, and
      // PreToolUse is the only framing that can still influence the host before
      // the tool runs. (The error path itself fail-OPENS to allow unless
      // failOpen: false — see handleError; the header comment on this module is
      // the accurate one.)
      let hookType: HookInput['hook'] = 'PreToolUse';

      try {
        const input = JSON.parse(trimmed) as HookInput;
        if (input.hook === 'PostToolUse') hookType = 'PostToolUse';
        output = await this.dispatch(input);
      } catch (err) {
        output = this.handleError(err);
      }

      // Emit the host's exact hook contract. Generic { decision } is silently
      // ignored by Claude Code (fake protection) — see toClaudeCodePreToolUse.
      const contractOptions = { blocking: this.blocking };
      const payload =
        format === 'generic'
          ? (output as unknown as Record<string, unknown>)
          : hookType === 'PostToolUse'
            ? toClaudeCodePostToolUse(output, contractOptions)
            : toClaudeCodePreToolUse(output, contractOptions);

      process.stdout.write(JSON.stringify(payload) + '\n');
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
