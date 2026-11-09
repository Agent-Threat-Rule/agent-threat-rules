import { afterEach, describe, expect, it, vi } from "vitest";
import { StdioAdapter } from "../src/adapters/stdio-adapter.js";
import type { ATRAction, ATRMatch, ATRVerdict, ExecutionContext } from "../src/types.js";

const originalShadowLog = process.env.ATR_SHADOW_LOG;

function makeContext(): ExecutionContext {
  const matches = ["ATR-2026-00001", "ATR-2026-00002"].map(
    (id) => ({ rule: { id } }) as unknown as ATRMatch,
  );
  const verdict: ATRVerdict = {
    outcome: "deny", reason: "test verdict", matchCount: 2,
    highestSeverity: "critical", highestConfidence: 0.95,
    actions: Object.freeze(["alert"]), matches: Object.freeze(matches),
    timestamp: new Date().toISOString(),
  };
  return Object.freeze({
    event: { type: "tool_call", timestamp: new Date().toISOString(),
      content: "x".repeat(250), fields: { tool_name: "shell" } },
    matches: Object.freeze(matches), verdict, sessionId: "session-1",
  });
}

function captureStderr() {
  return vi.spyOn(process.stderr, "write").mockReturnValue(true);
}

function writtenJson(spy: ReturnType<typeof captureStderr>): Record<string, unknown> {
  expect(spy).toHaveBeenCalledTimes(1);
  const line = String(spy.mock.calls[0]![0]);
  expect(line.endsWith("\n")).toBe(true);
  expect(line.trim().split("\n")).toHaveLength(1);
  return JSON.parse(line) as Record<string, unknown>;
}

afterEach(() => {
  vi.restoreAllMocks();
  if (originalShadowLog === undefined) delete process.env.ATR_SHADOW_LOG;
  else process.env.ATR_SHADOW_LOG = originalShadowLog;
});

describe("StdioAdapter", () => {
  it('has name "stdio"', () => expect(new StdioAdapter().name).toBe("stdio"));

  const methods: Array<[keyof StdioAdapter, ATRAction]> = [
    ["blockInput", "block_input"], ["blockOutput", "block_output"],
    ["blockTool", "block_tool"], ["quarantineSession", "quarantine_session"],
    ["resetContext", "reset_context"], ["alert", "alert"], ["shadow", "shadow"],
    ["snapshot", "snapshot"], ["escalate", "escalate"],
    ["reducePermissions", "reduce_permissions"], ["killAgent", "kill_agent"],
  ];

  it.each(methods)("%s returns a frozen successful result", async (method, action) => {
    captureStderr();
    delete process.env.ATR_SHADOW_LOG;
    const adapter = new StdioAdapter();
    const call = adapter[method] as (ctx: ExecutionContext) => Promise<{
      action: ATRAction; success: boolean; timestamp: string;
    }>;
    const result = await call.call(adapter, makeContext());
    expect(result).toMatchObject({ action, success: true });
    expect(new Date(result.timestamp).toISOString()).toBe(result.timestamp);
    expect(Object.isFrozen(result)).toBe(true);
  });

  it("buffers each block response with documented fields and flushes correctly", async () => {
    const adapter = new StdioAdapter();
    const ctx = makeContext();
    const cases: Array<[keyof StdioAdapter, Record<string, unknown>]> = [
      ["blockInput", { action: "block_input", verdict: "deny", reason: "test verdict" }],
      ["blockOutput", { action: "block_output", verdict: "deny", reason: "test verdict" }],
      ["blockTool", { action: "block_tool", verdict: "deny", reason: "test verdict", tool: "shell" }],
      ["quarantineSession", { action: "quarantine_session", verdict: "deny", sessionId: "session-1" }],
      ["resetContext", { action: "reset_context", verdict: "deny" }],
      ["reducePermissions", { action: "reduce_permissions", verdict: "deny", reason: "test verdict" }],
      ["killAgent", { action: "kill_agent", verdict: "deny", reason: "test verdict" }],
    ];
    for (const [method, expected] of cases) {
      await (adapter[method] as (ctx: ExecutionContext) => Promise<unknown>).call(adapter, ctx);
      const response = adapter.flushResponses();
      expect(response).toEqual([expected]);
      expect(Object.isFrozen(response)).toBe(true);
      expect(adapter.flushResponses()).toEqual([]);
    }
    await adapter.blockTool({ ...ctx, event: { ...ctx.event, fields: undefined } });
    await adapter.quarantineSession({ ...ctx, sessionId: undefined });
    expect(adapter.flushResponses()).toEqual([
      { action: "block_tool", verdict: "deny", reason: "test verdict", tool: "unknown" },
      { action: "quarantine_session", verdict: "deny", sessionId: "unknown" },
    ]);
  });

  it("preserves response order", async () => {
    const adapter = new StdioAdapter();
    await adapter.blockInput(makeContext());
    await adapter.resetContext(makeContext());
    expect(adapter.flushResponses()).toMatchObject([
      { action: "block_input" }, { action: "reset_context" },
    ]);
  });

  it("writes alert, escalation, and a truncated snapshot only to stderr", async () => {
    const expected = ["alert", "escalation", "snapshot"];
    for (const method of ["alert", "escalate", "snapshot"] as const) {
      const spy = captureStderr();
      const adapter = new StdioAdapter();
      await adapter[method](makeContext());
      const json = writtenJson(spy);
      expect(json.type).toBe(expected.shift());
      if (method === "snapshot") {
        expect(json).toMatchObject({ event: { contentPreview: "x".repeat(200) } });
      }
      expect(adapter.flushResponses()).toEqual([]);
      spy.mockRestore();
    }
  });

  it.each([["medium", "medium"], [undefined, null]] as const)(
    "alert falls back from missing highest severity to %s",
    async (advisory, expected) => {
      const spy = captureStderr();
      const ctx = makeContext();
      const verdict = { ...ctx.verdict, highestSeverity: undefined,
        advisorySeverity: advisory } as unknown as ATRVerdict;
      await new StdioAdapter().alert({ ...ctx, verdict });
      expect(writtenJson(spy).severity).toBe(expected);
    },
  );

  it("writes shadow rule ids only when ATR_SHADOW_LOG is set", async () => {
    const spy = captureStderr();
    const adapter = new StdioAdapter();
    delete process.env.ATR_SHADOW_LOG;
    await adapter.shadow(makeContext());
    expect(spy).not.toHaveBeenCalled();
    expect(adapter.flushResponses()).toEqual([]);
    process.env.ATR_SHADOW_LOG = "1";
    await adapter.shadow(makeContext());
    expect(writtenJson(spy)).toMatchObject({
      type: "shadow", ruleIds: ["ATR-2026-00001", "ATR-2026-00002"],
    });
  });
});
