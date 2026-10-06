/**
 * Action Executor - Executes ATR response actions via platform adapters.
 *
 * Deduplicates actions, sorts by priority, and delegates execution
 * to a PlatformAdapter. Handles per-action errors so one failure
 * does not block the rest.
 *
 * ENFORCEMENT GATE: actions above the OBSERVE blast-radius tier are dispatched
 * only when the operator has enabled blocking (`blocking: true` here; the CLI
 * maps ATR_BLOCKING / `atr guard --blocking` onto it). Without it they are
 * recorded as suppressed and the adapter is never called. See
 * src/enforcement.ts for why this is opt-in and
 * src/quality/action-eligibility.ts for the tier ladder this gate reads.
 *
 * @module agent-threat-rules/action-executor
 */

import type {
  ATRAction,
  ActionResult,
  ExecutionContext,
  PlatformAdapter,
} from "./types.js";
import { isEnforcementAction, blockingFromConfig } from "./enforcement.js";
import { TIER_NAMES, actionTier } from "./quality/action-eligibility.js";

/** Priority order: lower number = higher priority (executed first) */
const ACTION_PRIORITY: Readonly<Record<ATRAction, number>> = {
  kill_agent: 0,
  block_input: 1,
  block_output: 2,
  block_tool: 3,
  quarantine_session: 4,
  reduce_permissions: 5,
  reset_context: 6,
  alert: 7,
  escalate: 8,
  snapshot: 9,
  shadow: 10,
};

/**
 * Map action names to PlatformAdapter method names.
 *
 * Exported because it is the authoritative list of actions this engine can
 * actually dispatch. Rule files also carry SPEC Appendix A vocabulary
 * (`revoke_credential`, `quarantine_artifact`, ...) that has no entry here and
 * therefore never reaches an adapter — see executeOne's "Unknown action" branch.
 * src/quality/action-eligibility.ts ranks exactly these keys by blast radius, and
 * tests/action-eligibility.test.ts pins the two sets equal, so implementing a new
 * adapter method forces an explicit decision about how destructive it is.
 */
export const ACTION_METHOD_MAP: Readonly<Record<ATRAction, keyof PlatformAdapter>> = {
  block_input: "blockInput",
  block_output: "blockOutput",
  block_tool: "blockTool",
  quarantine_session: "quarantineSession",
  reset_context: "resetContext",
  alert: "alert",
  shadow: "shadow",
  snapshot: "snapshot",
  escalate: "escalate",
  reduce_permissions: "reducePermissions",
  kill_agent: "killAgent",
};

export interface ActionExecutorConfig {
  readonly adapter: PlatformAdapter;
  readonly dryRun?: boolean;
  /**
   * Operator directive permitting enforcement actions. OFF BY DEFAULT.
   *
   * When false, any action above the OBSERVE blast-radius tier
   * (block_input / block_output / block_tool / reduce_permissions /
   * reset_context / quarantine_session / kill_agent) is refused before the
   * adapter is touched; OBSERVE actions (alert / snapshot / shadow / escalate)
   * run exactly as before.
   *
   * This field is the only input — the executor does not read `ATR_BLOCKING`.
   * A non-boolean throws rather than being coerced: `blocking: "false"` is
   * truthy in JavaScript and would otherwise enable enforcement. `atr guard`
   * resolves the environment itself and passes the result here.
   *
   * This is the runtime half of SPEC.md §5.5 ("Engines MUST NOT execute
   * response actions automatically without an explicit configuration directive
   * from the operator"). Until it existed, `atr guard` built an executor
   * unconditionally and dispatched every declared action, including on a verdict
   * of `allow`.
   */
  readonly blocking?: boolean;
  readonly onActionComplete?: (result: ActionResult) => void;
}

export class ActionExecutor {
  private readonly adapter: PlatformAdapter;
  private readonly dryRun: boolean;
  private readonly blocking: boolean;
  private readonly onActionComplete?: (result: ActionResult) => void;

  constructor(config: ActionExecutorConfig) {
    this.adapter = config.adapter;
    this.dryRun = config.dryRun ?? false;
    this.blocking = blockingFromConfig(config.blocking);
    this.onActionComplete = config.onActionComplete;
  }

  /**
   * Execute all actions from the verdict context.
   *
   * Actions are deduplicated, sorted by priority, and executed
   * sequentially. Each action is wrapped in try/catch so a single
   * failure does not prevent subsequent actions from running.
   *
   * Returns a frozen array of ActionResult.
   */
  async execute(context: ExecutionContext): Promise<readonly ActionResult[]> {
    const actions = this.deduplicateAndSort(context.verdict.actions);
    const results: ActionResult[] = [];

    for (const action of actions) {
      const result = await this.executeOne(action, context);
      results.push(result);

      if (this.onActionComplete) {
        this.onActionComplete(result);
      }
    }

    return Object.freeze(results);
  }

  /**
   * Deduplicate actions and sort by priority (highest priority first).
   */
  private deduplicateAndSort(
    actions: readonly ATRAction[],
  ): readonly ATRAction[] {
    const unique = [...new Set(actions)];
    return unique.sort((a, b) => {
      const pa = ACTION_PRIORITY[a] ?? 99;
      const pb = ACTION_PRIORITY[b] ?? 99;
      return pa - pb;
    });
  }

  /**
   * Execute a single action, returning a result even on failure.
   */
  private async executeOne(
    action: ATRAction,
    context: ExecutionContext,
  ): Promise<ActionResult> {
    const timestamp = new Date().toISOString();

    // Enforcement gate — checked BEFORE dry-run, because "would execute" is
    // false for an action that enforcement policy forbids. The adapter is never
    // reached, so a downstream adapter that really blocks cannot act while the
    // hook channel is telling the host nothing.
    if (!this.blocking && isEnforcementAction(action)) {
      return Object.freeze({
        action,
        success: true,
        message:
          `[advisory] Suppressed ${action} (tier ${TIER_NAMES[actionTier(action)]}): ` +
          `blocking is disabled. Enable it with blocking: true (atr guard: ` +
          `--blocking or ATR_BLOCKING=1).`,
        timestamp,
      });
    }

    if (this.dryRun) {
      return Object.freeze({
        action,
        success: true,
        message: `[dry-run] Would execute: ${action}`,
        timestamp,
      });
    }

    try {
      const methodName = ACTION_METHOD_MAP[action];
      if (!methodName) {
        return Object.freeze({
          action,
          success: false,
          message: `Unknown action: ${action}`,
          timestamp,
        });
      }

      const method = this.adapter[methodName] as
        | ((ctx: ExecutionContext) => Promise<ActionResult>)
        | undefined;

      if (typeof method !== "function") {
        return Object.freeze({
          action,
          success: false,
          message: `Adapter "${this.adapter.name}" does not implement: ${methodName}`,
          timestamp,
        });
      }

      return await method.call(this.adapter, context);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return Object.freeze({
        action,
        success: false,
        message: `Action "${action}" failed: ${message}`,
        timestamp,
      });
    }
  }

  /** Get the adapter name for diagnostics */
  getAdapterName(): string {
    return this.adapter.name;
  }

  /** Check if dry-run mode is enabled */
  isDryRun(): boolean {
    return this.dryRun;
  }

  /** Is this executor permitted to dispatch enforcement actions? */
  isBlocking(): boolean {
    return this.blocking;
  }
}
