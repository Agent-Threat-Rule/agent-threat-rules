/**
 * ActionExecutor tests.
 *
 * Validates action deduplication, priority ordering, adapter delegation,
 * error handling, dry-run mode, and the onActionComplete callback.
 *
 * Cases whose subject is an action above the OBSERVE blast-radius tier pass
 * `blocking: true`: dispatching those is opt-in and off by default. The default
 * (suppressed, adapter untouched) is pinned in tests/enforcement.test.ts.
 */

import { describe, it, expect, vi } from "vitest";
import { ActionExecutor } from "../src/action-executor.js";
import type {
  ATRAction,
  ATRVerdict,
  ActionResult,
  AgentEvent,
  ExecutionContext,
  PlatformAdapter,
} from "../src/types.js";

/** Create a mock adapter where every method is a vi.fn() returning success */
function createMockAdapter(
  overrides: Partial<Record<keyof PlatformAdapter, unknown>> = {},
): PlatformAdapter {
  const defaultImpl = (action: ATRAction) =>
    vi.fn(
      async (): Promise<ActionResult> =>
        Object.freeze({
          action,
          success: true,
          message: `mock: ${action}`,
          timestamp: new Date().toISOString(),
        }),
    );

  return {
    name: "mock",
    blockInput: defaultImpl("block_input"),
    blockOutput: defaultImpl("block_output"),
    blockTool: defaultImpl("block_tool"),
    quarantineSession: defaultImpl("quarantine_session"),
    resetContext: defaultImpl("reset_context"),
    alert: defaultImpl("alert"),
    shadow: defaultImpl("shadow"),
    snapshot: defaultImpl("snapshot"),
    escalate: defaultImpl("escalate"),
    reducePermissions: defaultImpl("reduce_permissions"),
    killAgent: defaultImpl("kill_agent"),
    ...overrides,
  } as unknown as PlatformAdapter;
}

/** Build a minimal ExecutionContext with the given actions */
function makeContext(actions: readonly ATRAction[]): ExecutionContext {
  const verdict: ATRVerdict = {
    outcome: "deny",
    reason: "test verdict",
    matchCount: 1,
    highestSeverity: "critical",
    highestConfidence: 0.95,
    actions: Object.freeze([...actions]),
    matches: Object.freeze([]),
    timestamp: new Date().toISOString(),
  };

  const event: AgentEvent = {
    type: "tool_call",
    timestamp: new Date().toISOString(),
    content: "test_tool",
  };

  return Object.freeze({
    event,
    matches: Object.freeze([]),
    verdict,
  });
}

describe("ActionExecutor", () => {
  it("executes actions in priority order (kill_agent first, snapshot last)", async () => {
    const callOrder: string[] = [];

    const adapter = createMockAdapter({
      killAgent: vi.fn(async (): Promise<ActionResult> => {
        callOrder.push("kill_agent");
        return Object.freeze({
          action: "kill_agent" as ATRAction,
          success: true,
          message: "killed",
          timestamp: new Date().toISOString(),
        });
      }),
      alert: vi.fn(async (): Promise<ActionResult> => {
        callOrder.push("alert");
        return Object.freeze({
          action: "alert" as ATRAction,
          success: true,
          message: "alerted",
          timestamp: new Date().toISOString(),
        });
      }),
      snapshot: vi.fn(async (): Promise<ActionResult> => {
        callOrder.push("snapshot");
        return Object.freeze({
          action: "snapshot" as ATRAction,
          success: true,
          message: "snapshotted",
          timestamp: new Date().toISOString(),
        });
      }),
    });

    const executor = new ActionExecutor({ adapter, blocking: true });
    // Provide actions in non-priority order
    const ctx = makeContext(["snapshot", "kill_agent", "alert"]);

    await executor.execute(ctx);

    expect(callOrder).toEqual(["kill_agent", "alert", "snapshot"]);
  });

  it("deduplicates actions", async () => {
    const adapter = createMockAdapter();
    const executor = new ActionExecutor({ adapter });

    const ctx = makeContext(["alert", "alert", "snapshot", "alert"]);
    const results = await executor.execute(ctx);

    // Only 2 unique actions: alert and snapshot
    expect(results).toHaveLength(2);
    const actionNames = results.map((r) => r.action);
    expect(actionNames).toContain("alert");
    expect(actionNames).toContain("snapshot");
  });

  it("calls the correct adapter method for each action type", async () => {
    const adapter = createMockAdapter();
    const executor = new ActionExecutor({ adapter, blocking: true });

    const ctx = makeContext(["block_input", "escalate"]);
    await executor.execute(ctx);

    expect(adapter.blockInput).toHaveBeenCalledTimes(1);
    expect(adapter.escalate).toHaveBeenCalledTimes(1);
    // Others should not be called
    expect(adapter.killAgent).not.toHaveBeenCalled();
    expect(adapter.snapshot).not.toHaveBeenCalled();
  });

  it("continues with other actions when adapter method throws", async () => {
    const adapter = createMockAdapter({
      alert: vi.fn(async () => {
        throw new Error("adapter alert failed");
      }),
    });

    const executor = new ActionExecutor({ adapter });
    const ctx = makeContext(["alert", "snapshot"]);

    const results = await executor.execute(ctx);

    expect(results).toHaveLength(2);

    const alertResult = results.find((r) => r.action === "alert");
    expect(alertResult).toBeDefined();
    expect(alertResult!.success).toBe(false);
    expect(alertResult!.message).toContain("adapter alert failed");

    const snapshotResult = results.find((r) => r.action === "snapshot");
    expect(snapshotResult).toBeDefined();
    expect(snapshotResult!.success).toBe(true);
  });

  it("dry-run mode returns success without calling adapter", async () => {
    const adapter = createMockAdapter();
    const executor = new ActionExecutor({ adapter, dryRun: true, blocking: true });

    const ctx = makeContext(["kill_agent", "alert"]);
    const results = await executor.execute(ctx);

    expect(results).toHaveLength(2);
    for (const result of results) {
      expect(result.success).toBe(true);
      expect(result.message).toContain("[dry-run]");
    }

    // Adapter methods should NOT be called in dry-run mode
    expect(adapter.killAgent).not.toHaveBeenCalled();
    expect(adapter.alert).not.toHaveBeenCalled();
  });

  it("onActionComplete callback is called for each result", async () => {
    const adapter = createMockAdapter();
    const completedResults: ActionResult[] = [];
    const onComplete = vi.fn((result: ActionResult) => {
      completedResults.push(result);
    });

    const executor = new ActionExecutor({
      adapter,
      onActionComplete: onComplete,
    });

    const ctx = makeContext(["alert", "snapshot"]);
    await executor.execute(ctx);

    expect(onComplete).toHaveBeenCalledTimes(2);
    expect(completedResults).toHaveLength(2);
  });

  it("returns a frozen array of ActionResult", async () => {
    const adapter = createMockAdapter();
    const executor = new ActionExecutor({ adapter });

    const ctx = makeContext(["alert"]);
    const results = await executor.execute(ctx);

    expect(Object.isFrozen(results)).toBe(true);
  });

  it("returns empty results for empty actions array", async () => {
    const adapter = createMockAdapter();
    const executor = new ActionExecutor({ adapter });

    const ctx = makeContext([]);
    const results = await executor.execute(ctx);

    expect(results).toHaveLength(0);
    expect(Object.isFrozen(results)).toBe(true);
  });

  it("getAdapterName returns the adapter name", () => {
    const adapter = createMockAdapter();
    const executor = new ActionExecutor({ adapter });
    expect(executor.getAdapterName()).toBe("mock");
  });

  it("isDryRun reflects constructor config", () => {
    const adapter = createMockAdapter();

    const normalExec = new ActionExecutor({ adapter });
    expect(normalExec.isDryRun()).toBe(false);

    const dryExec = new ActionExecutor({ adapter, dryRun: true });
    expect(dryExec.isDryRun()).toBe(true);
  });
});
