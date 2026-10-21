/**
 * A failed tool call's output is scanned too.
 *
 * When a tool call fails, a Bash command whose exit code Claude Code counts as a
 * failure among them, Claude Code does not send PostToolUse: it sends
 * PostToolUseFailure, { tool_name, tool_input, tool_use_id, error, is_interrupt,
 * duration_ms }, with no tool_response (checked against the shipped 2.1.280
 * binary). For a shell command, error is Claude Code's `Exit code N` line, its
 * abort note when it aborted the command, then the command's stderr and stdout,
 * trimmed. The guard answered that event "Unknown hook type" and allowed it, so
 * ending a command with `; exit 1` kept its output from every rule. The guard
 * now builds the event from error, without Claude Code's lines, and answers in
 * the PostToolUse contract under the PostToolUseFailure name.
 */
import { describe, it, expect } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";
import { HookHandler, toClaudeCodePostToolUse } from "../src/hook-handler.js";
import { ATREngine } from "../src/engine.js";
import { ActionExecutor } from "../src/action-executor.js";
import { DefaultAdapter } from "../src/adapters/default-adapter.js";
import type { ATRRule, HookInput } from "../src/types.js";

const CLI = new URL("../src/cli.ts", import.meta.url).pathname;
const ATTACK = "a zebracorn attack";

function rule(id: string, source: string, field: string, value: string): ATRRule {
  return {
    id,
    title: "PostToolUseFailure probe",
    status: "experimental",
    maturity: "test",
    severity: "high",
    description: "fixture rule for the PostToolUseFailure event",
    author: "test",
    date: "2026/10/20",
    tags: { category: "prompt-injection", scan_target: "runtime", confidence: "high" },
    agent_source: { type: source, framework: ["any"], provider: ["any"] },
    detection: { condition: "any", conditions: [{ field, operator: "regex", value, description: "probe" }] },
    response: { actions: ["alert"] },
  } as unknown as ATRRule;
}

const READS_USER_INPUT = rule("ATR-2026-97401", "llm_io", "user_input", "zebracorn");
const READS_TOOL_RESPONSE = rule("ATR-2026-97402", "mcp_exchange", "tool_response", "zebracorn");
const ANCHORED = rule("ATR-2026-97403", "mcp_exchange", "content", "^a zebracorn");

/** A PostToolUseFailure hook input in the shape Claude Code sends. */
function failure(toolName: string, toolInput: Record<string, unknown>, error: unknown): HookInput {
  return {
    session_id: "s1",
    hook_event_name: "PostToolUseFailure",
    tool_name: toolName,
    tool_input: toolInput,
    tool_use_id: "toolu_test",
    error,
    is_interrupt: false,
    duration_ms: 12,
  } as unknown as HookInput;
}

const failedCommand = failure("Bash", { command: "cat notes.md; exit 1" }, `Exit code 1\n${ATTACK}`);

describe("atr guard on a PostToolUseFailure event", () => {
  it("scans the failed command's output and answers under that event's name", () => {
    const dir = mkdtempSync(join(tmpdir(), "atr-posttoolusefailure-"));
    try {
      const rulesDir = join(dir, "rules", "prompt-injection");
      mkdirSync(rulesDir, { recursive: true });
      for (const r of [READS_USER_INPUT, READS_TOOL_RESPONSE, ANCHORED]) {
        writeFileSync(join(rulesDir, `${r.id}.yaml`), yaml.dump(r));
      }
      const r = spawnSync("npx", ["tsx", CLI, "guard", "--rules", join(dir, "rules")], {
        input: `${JSON.stringify(failedCommand)}\n`,
        encoding: "utf8",
        timeout: 120_000,
      });
      const stdout = r.stdout ?? "";
      const start = stdout.indexOf("{");
      expect(start, `no JSON in stdout: ${stdout}${r.stderr}`).toBeGreaterThanOrEqual(0);
      const payload = JSON.parse(stdout.slice(start)) as Record<string, unknown>;
      expect(payload["hookSpecificOutput"]).toEqual({ hookEventName: "PostToolUseFailure" });
      expect(payload["matched_rules"]).toEqual(expect.arrayContaining([READS_USER_INPUT.id, READS_TOOL_RESPONSE.id, ANCHORED.id]));
      expect(payload).not.toHaveProperty("decision");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("HookHandler.handlePostToolUseFailure", () => {
  const engine = new ATREngine();
  for (const r of [READS_USER_INPUT, READS_TOOL_RESPONSE, ANCHORED]) engine.addRule(r);
  const handler = new HookHandler({ engine, executor: new ActionExecutor({ adapter: new DefaultAdapter() }) });

  it("reads the error without Claude Code's Exit code line, so a pattern anchored at the start reads the output", async () => {
    const ids = (await handler.handlePostToolUseFailure(failedCommand)).matched_rules ?? [];
    expect(ids).toEqual(expect.arrayContaining([READS_USER_INPUT.id, READS_TOOL_RESPONSE.id, ANCHORED.id]));
  });

  it("reads an error that is not a string as a tool output", async () => {
    const structured = failure("mcp__docs__fetch", { url: "https://x.test" }, { message: "fetch failed", details: ATTACK });
    expect((await handler.handlePostToolUseFailure(structured)).matched_rules ?? []).toContain(READS_TOOL_RESPONSE.id);
  });

  it("scans the tool's input in its place when the command printed nothing", async () => {
    // A silent failure (false, test -f, grep -q) arrives as the Exit code line alone.
    const silent = failure("Bash", { command: `test -f ${ATTACK}` }, "Exit code 1");
    expect((await handler.handlePostToolUseFailure(silent)).matched_rules ?? []).toContain(READS_USER_INPUT.id);
    const quiet = failure("Bash", { command: "false" }, "Exit code 1");
    expect((await handler.handlePostToolUseFailure(quiet)).matched_rules ?? []).toEqual([]);
  });

  it("reads past the note Claude Code adds when it aborts a command, and a CRLF after the Exit code line", async () => {
    const note = "<error>Command was aborted before completion</error>";
    for (const error of [`Exit code 143\n${note}\n${ATTACK}`, `Exit code 1\r\n${ATTACK}`]) {
      const ids = (await handler.handlePostToolUseFailure(failure("Bash", { command: "sleep 600" }, error))).matched_rules ?? [];
      expect(ids, JSON.stringify(error)).toContain(ANCHORED.id);
    }
  });
});

describe("the PostToolUseFailure contract", () => {
  it("blocks a restraining verdict only with blocking on, under the PostToolUseFailure name", () => {
    const deny = { decision: "deny" as const, reason: "poisoned output", matched_rules: ["ATR-2026-97401"] };
    const blocking = toClaudeCodePostToolUse(deny, { blocking: true }, "PostToolUseFailure");
    expect(blocking).toMatchObject({ hookSpecificOutput: { hookEventName: "PostToolUseFailure" }, decision: "block", reason: "poisoned output" });
    const advisory = toClaudeCodePostToolUse(deny, {}, "PostToolUseFailure");
    expect(advisory).toMatchObject({ hookSpecificOutput: { hookEventName: "PostToolUseFailure" }, atr_advisory: true });
    expect(advisory).not.toHaveProperty("decision");
    expect(toClaudeCodePostToolUse(deny, { blocking: true })["hookSpecificOutput"]).toEqual({ hookEventName: "PostToolUse" });
  });
});
