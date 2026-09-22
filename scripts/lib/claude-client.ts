/**
 * One place where this repository talks to Claude.
 *
 * WHY THIS EXISTS
 *
 * Every rule-authoring lane here (semantic authoring, ATD drafting, FN mining,
 * quality upgrade) constructed its own `new Anthropic({ apiKey })` against
 * ANTHROPIC_API_KEY. That key bills a metered credit balance, and when the
 * balance ran out the lanes did not stop — they failed per-call, counted the
 * failures, and exited 0. The daily rule pipeline was dead for days behind a
 * green check.
 *
 * The local `claude` CLI authenticates with a long-lived OAuth token
 * (`claude setup-token` -> CLAUDE_CODE_OAUTH_TOKEN, prefix `sk-ant-oat`) and
 * draws on the subscription rather than metered credit. That is the right
 * meter for a daily pipeline: it does not silently run out mid-month, and it
 * is the same credential the operations harness already runs headless on.
 *
 * So: prefer the CLI, fall back to the API, and never guess which one ran.
 *
 * BACKENDS
 *
 *   cli  — spawn `claude -p`. Subscription credit. Needs the `claude` binary
 *          plus either CLAUDE_CODE_OAUTH_TOKEN or an existing interactive
 *          login. Preferred.
 *   api  — @anthropic-ai/sdk against ANTHROPIC_API_KEY. Metered credit.
 *          Kept as a fallback, and for anyone running this without the CLI.
 *
 * Selection is automatic; ATR_LLM_BACKEND=cli|api forces one. The chosen
 * backend is logged on first use, because "which meter did this run spend"
 * is exactly the question that was unanswerable before.
 */
import { spawn } from "node:child_process";
import Anthropic from "@anthropic-ai/sdk";

export type Backend = "cli" | "api";

/** Thrown when no backend is usable. Distinct from a call that ran and failed. */
export class NoBackendError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NoBackendError";
  }
}

// `claude -p` starts a full agent session, so it is meaningfully slower than a
// raw API call on the same prompt — 180s was not enough for the semantic-authoring
// prompt in testing. Overridable with ATR_LLM_TIMEOUT_MS.
const CLI_TIMEOUT_MS = Number(process.env.ATR_LLM_TIMEOUT_MS || 600_000);

let announced = false;

function announce(backend: Backend, reason: string): void {
  if (announced) return;
  announced = true;
  const meter = backend === "cli" ? "subscription" : "metered API credit";
  console.log(`[claude-client] backend=${backend} (${meter}) — ${reason}`);
}

function hasCli(): boolean {
  // `claude` is resolved by the shell at spawn time; probing PATH here would
  // duplicate that and get it wrong for shims. Presence of a credential or an
  // explicit request is what we gate on, and a missing binary surfaces as a
  // spawn ENOENT with a clear message.
  return Boolean(process.env.CLAUDE_CODE_OAUTH_TOKEN) || process.env.ATR_LLM_BACKEND === "cli";
}

export function selectBackend(): { backend: Backend; reason: string } {
  const forced = process.env.ATR_LLM_BACKEND;
  if (forced === "cli") return { backend: "cli", reason: "ATR_LLM_BACKEND=cli" };
  if (forced === "api") return { backend: "api", reason: "ATR_LLM_BACKEND=api" };
  if (forced && forced !== "cli" && forced !== "api") {
    throw new NoBackendError(`ATR_LLM_BACKEND must be "cli" or "api", got "${forced}"`);
  }
  if (hasCli()) return { backend: "cli", reason: "CLAUDE_CODE_OAUTH_TOKEN present" };
  if (process.env.ANTHROPIC_API_KEY) {
    return { backend: "api", reason: "no CLAUDE_CODE_OAUTH_TOKEN; falling back to ANTHROPIC_API_KEY" };
  }
  throw new NoBackendError(
    "No Claude backend available. Set CLAUDE_CODE_OAUTH_TOKEN (preferred — run `claude setup-token`, " +
      "subscription credit) or ANTHROPIC_API_KEY (metered credit).",
  );
}

async function callViaCli(system: string, user: string, model: string): Promise<string> {
  const args = ["-p", user, "--model", model, "--output-format", "text", "--allowed-tools", ""];
  if (system) args.push("--system-prompt", system);

  return new Promise<string>((resolve, reject) => {
    // ANTHROPIC_API_KEY is stripped so a stale key in the environment cannot
    // silently redirect this call onto the metered meter — the whole point of
    // choosing the CLI backend is knowing which meter was spent.
    const env = { ...process.env };
    delete env.ANTHROPIC_API_KEY;

    const child = spawn("claude", args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`claude CLI timed out after ${CLI_TIMEOUT_MS}ms`));
    }, CLI_TIMEOUT_MS);

    child.stdout.on("data", (d) => (out += String(d)));
    child.stderr.on("data", (d) => (err += String(d)));
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(
        new Error(
          `claude CLI could not be spawned (${e.message}). Install it, or set ATR_LLM_BACKEND=api ` +
            `with ANTHROPIC_API_KEY.`,
        ),
      );
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code === 0) return resolve(out.trim());
      // Pass the CLI's own words through. The callers classify failures by
      // matching on the reason string, so paraphrasing here would break the
      // infrastructure-vs-content split that keeps dead lanes from going green.
      reject(new Error(`claude CLI exited ${code}: ${(err || out).trim().slice(0, 600)}`));
    });
  });
}

async function callViaApi(system: string, user: string, model: string, maxTokens: number): Promise<string> {
  const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  const resp = await client.messages.create({
    model,
    max_tokens: maxTokens,
    ...(system ? { system } : {}),
    messages: [{ role: "user", content: user }],
  });
  return resp.content
    .filter((b): b is Anthropic.TextBlock => b.type === "text")
    .map((b) => b.text)
    .join("\n")
    .trim();
}

/**
 * Send one prompt, get the text back.
 *
 * Drop-in for the `callClaude(systemPrompt, userPrompt, model)` shape the
 * scripts already use. `maxTokens` applies to the API backend only; the CLI
 * manages its own budget.
 */
export async function callClaude(
  system: string,
  user: string,
  model: string,
  maxTokens = 4096,
): Promise<string> {
  const { backend, reason } = selectBackend();
  announce(backend, reason);
  return backend === "cli" ? callViaCli(system, user, model) : callViaApi(system, user, model, maxTokens);
}

/** True when some backend is usable. Lets a script exit cleanly instead of throwing. */
export function backendAvailable(): boolean {
  try {
    selectBackend();
    return true;
  } catch {
    return false;
  }
}

/** For logging and run summaries: which meter is this run about to spend? */
export function describeBackend(): string {
  try {
    const { backend, reason } = selectBackend();
    return `${backend} (${backend === "cli" ? "subscription" : "metered API credit"}) — ${reason}`;
  } catch (e) {
    return `none — ${e instanceof Error ? e.message : String(e)}`;
  }
}
