/**
 * Stdio Platform Adapter - Adapter for Claude Code hook integration.
 *
 * Block actions write JSON responses to an internal buffer that can
 * be flushed to stdout. Alert and snapshot actions log to stderr
 * to avoid interfering with the JSON protocol on stdout.
 *
 * @module agent-threat-rules/adapters/stdio-adapter
 */

import type {
  ActionResult,
  ExecutionContext,
  PlatformAdapter,
} from "../types.js";

function makeResult(
  action: ActionResult["action"],
  message: string,
): ActionResult {
  return Object.freeze({
    action,
    success: true,
    message,
    timestamp: new Date().toISOString(),
  });
}

export class StdioAdapter implements PlatformAdapter {
  readonly name = "stdio";
  private readonly responseBuffer: unknown[] = [];

  /**
   * Get buffered responses and clear the buffer.
   * Returns a frozen copy.
   */
  flushResponses(): readonly unknown[] {
    const copy = Object.freeze([...this.responseBuffer]);
    this.responseBuffer.length = 0;
    return copy;
  }

  async blockInput(ctx: ExecutionContext): Promise<ActionResult> {
    const entry = {
      action: "block_input",
      verdict: ctx.verdict.outcome,
      reason: ctx.verdict.reason,
    };
    this.responseBuffer.push(entry);
    return makeResult("block_input", "Input blocked via stdio protocol");
  }

  async blockOutput(ctx: ExecutionContext): Promise<ActionResult> {
    const entry = {
      action: "block_output",
      verdict: ctx.verdict.outcome,
      reason: ctx.verdict.reason,
    };
    this.responseBuffer.push(entry);
    return makeResult("block_output", "Output blocked via stdio protocol");
  }

  async blockTool(ctx: ExecutionContext): Promise<ActionResult> {
    const entry = {
      action: "block_tool",
      verdict: ctx.verdict.outcome,
      reason: ctx.verdict.reason,
      tool: ctx.event.fields?.["tool_name"] ?? "unknown",
    };
    this.responseBuffer.push(entry);
    return makeResult("block_tool", "Tool blocked via stdio protocol");
  }

  async quarantineSession(ctx: ExecutionContext): Promise<ActionResult> {
    const entry = {
      action: "quarantine_session",
      verdict: ctx.verdict.outcome,
      sessionId: ctx.sessionId ?? "unknown",
    };
    this.responseBuffer.push(entry);
    return makeResult(
      "quarantine_session",
      "Session quarantined via stdio protocol",
    );
  }

  async resetContext(ctx: ExecutionContext): Promise<ActionResult> {
    const entry = {
      action: "reset_context",
      verdict: ctx.verdict.outcome,
    };
    this.responseBuffer.push(entry);
    return makeResult("reset_context", "Context reset via stdio protocol");
  }

  async alert(ctx: ExecutionContext): Promise<ActionResult> {
    const alertMsg = {
      type: "alert",
      severity: ctx.verdict.highestSeverity ?? ctx.verdict.advisorySeverity ?? null,
      reason: ctx.verdict.reason,
      matchCount: ctx.verdict.matchCount,
    };
    process.stderr.write(JSON.stringify(alertMsg) + "\n");
    return makeResult("alert", "Alert written to stderr");
  }

  async shadow(ctx: ExecutionContext): Promise<ActionResult> {
    // Shadow mode: record the match for audit but never surface it to
    // the user or the agent runtime. Output is gated behind an env var
    // so production consumers can opt-in to the audit stream.
    if (process.env.ATR_SHADOW_LOG) {
      const shadowMsg = {
        type: "shadow",
        severity: ctx.verdict.highestSeverity ?? ctx.verdict.advisorySeverity ?? null,
        reason: ctx.verdict.reason,
        matchCount: ctx.verdict.matchCount,
        ruleIds: ctx.matches.map((m) => m.rule.id),
        timestamp: new Date().toISOString(),
      };
      process.stderr.write(JSON.stringify(shadowMsg) + "\n");
    }
    return makeResult(
      "shadow",
      "Shadow match recorded (no user-facing output)",
    );
  }

  async snapshot(ctx: ExecutionContext): Promise<ActionResult> {
    const snapshotData = {
      type: "snapshot",
      event: {
        type: ctx.event.type,
        contentPreview: ctx.event.content.slice(0, 200),
      },
      verdict: ctx.verdict.outcome,
      matchCount: ctx.verdict.matchCount,
      timestamp: new Date().toISOString(),
    };
    process.stderr.write(JSON.stringify(snapshotData) + "\n");
    return makeResult("snapshot", "Snapshot written to stderr");
  }

  async escalate(ctx: ExecutionContext): Promise<ActionResult> {
    const escalation = {
      type: "escalation",
      severity: ctx.verdict.highestSeverity ?? ctx.verdict.advisorySeverity ?? null,
      reason: ctx.verdict.reason,
      matchCount: ctx.verdict.matchCount,
    };
    process.stderr.write(JSON.stringify(escalation) + "\n");
    return makeResult("escalate", "Escalation written to stderr");
  }

  async reducePermissions(ctx: ExecutionContext): Promise<ActionResult> {
    const entry = {
      action: "reduce_permissions",
      verdict: ctx.verdict.outcome,
      reason: ctx.verdict.reason,
    };
    this.responseBuffer.push(entry);
    return makeResult(
      "reduce_permissions",
      "Permissions reduced via stdio protocol",
    );
  }

  async killAgent(ctx: ExecutionContext): Promise<ActionResult> {
    const entry = {
      action: "kill_agent",
      verdict: ctx.verdict.outcome,
      reason: ctx.verdict.reason,
    };
    this.responseBuffer.push(entry);
    return makeResult("kill_agent", "Agent kill requested via stdio protocol");
  }
}
