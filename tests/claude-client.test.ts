/**
 * Tests for scripts/lib/claude-client.ts — which meter does a run spend?
 *
 * This matters because of what happened without it. Every rule-authoring lane
 * built its own Anthropic client against ANTHROPIC_API_KEY, which bills a
 * metered balance. When that balance ran out the lanes did not stop: they
 * failed per call, counted the failures, and exited 0. The daily pipeline was
 * dead for days behind a green check, and nothing in a run's output said which
 * credential it had used or whether it had used one at all.
 *
 * So the selection rule is pinned here, including the direction of the
 * preference. Getting it backwards would silently put the daily pipeline back
 * on the meter that runs out.
 *
 * No network is touched: only backend SELECTION is under test.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { selectBackend, backendAvailable, describeBackend, NoBackendError } from "../scripts/lib/claude-client.js";

const TOUCHED = ["ATR_LLM_BACKEND", "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"] as const;
let saved: Record<string, string | undefined> = {};

beforeEach(() => {
  saved = Object.fromEntries(TOUCHED.map((k) => [k, process.env[k]]));
  for (const k of TOUCHED) delete process.env[k];
});

afterEach(() => {
  for (const k of TOUCHED) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k] as string;
  }
});

describe("backend selection", () => {
  it("prefers the CLI when an OAuth token is present, even if an API key also is", () => {
    // The direction matters. Both credentials are routinely present at once on
    // a developer machine, and defaulting to the API key is what puts a daily
    // pipeline back on a balance that runs out mid-month.
    process.env.CLAUDE_CODE_OAUTH_TOKEN = "sk-ant-oat-test";
    process.env.ANTHROPIC_API_KEY = "sk-ant-api-test";
    expect(selectBackend().backend).toBe("cli");
  });

  it("falls back to the API key when there is no OAuth token", () => {
    process.env.ANTHROPIC_API_KEY = "sk-ant-api-test";
    expect(selectBackend().backend).toBe("api");
  });

  it("throws NoBackendError when neither credential is present", () => {
    expect(() => selectBackend()).toThrow(NoBackendError);
    expect(backendAvailable()).toBe(false);
  });

  it("names both credentials in the no-backend message, so the fix is in the error", () => {
    // A script that dies here should tell the operator what to set, not leave
    // them reading source. This was the difference between a five-minute fix
    // and a lane that stayed dead.
    let msg = "";
    try {
      selectBackend();
    } catch (e) {
      msg = e instanceof Error ? e.message : String(e);
    }
    expect(msg).toContain("CLAUDE_CODE_OAUTH_TOKEN");
    expect(msg).toContain("ANTHROPIC_API_KEY");
    expect(msg).toContain("claude setup-token");
  });

  it("honours an explicit ATR_LLM_BACKEND=api override", () => {
    process.env.CLAUDE_CODE_OAUTH_TOKEN = "sk-ant-oat-test";
    process.env.ATR_LLM_BACKEND = "api";
    expect(selectBackend().backend).toBe("api");
  });

  it("honours an explicit ATR_LLM_BACKEND=cli override with no token set", () => {
    process.env.ATR_LLM_BACKEND = "cli";
    expect(selectBackend().backend).toBe("cli");
  });

  it("rejects an unrecognised ATR_LLM_BACKEND rather than guessing", () => {
    // Silently falling back on a typo is how a run ends up on the wrong meter
    // with nothing in the log to say so.
    process.env.ATR_LLM_BACKEND = "clii";
    process.env.CLAUDE_CODE_OAUTH_TOKEN = "sk-ant-oat-test";
    expect(() => selectBackend()).toThrow(NoBackendError);
  });
});

describe("describeBackend", () => {
  it("names the meter, not just the backend", () => {
    // "cli" alone does not answer the question an operator is actually asking.
    process.env.CLAUDE_CODE_OAUTH_TOKEN = "sk-ant-oat-test";
    expect(describeBackend()).toContain("subscription");

    delete process.env.CLAUDE_CODE_OAUTH_TOKEN;
    process.env.ANTHROPIC_API_KEY = "sk-ant-api-test";
    expect(describeBackend()).toContain("metered");
  });

  it("does not throw when no backend is available", () => {
    // It is called from logging paths; throwing there would turn a diagnostic
    // into the failure.
    expect(() => describeBackend()).not.toThrow();
    expect(describeBackend()).toContain("none");
  });

  it("never echoes the credential value", () => {
    process.env.CLAUDE_CODE_OAUTH_TOKEN = "sk-ant-oat-SECRETVALUE";
    process.env.ANTHROPIC_API_KEY = "sk-ant-api-SECRETVALUE";
    const out = describeBackend();
    expect(out).not.toContain("SECRETVALUE");
  });
});
