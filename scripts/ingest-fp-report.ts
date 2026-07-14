#!/usr/bin/env npx tsx
/**
 * ingest-fp-report.ts — closes the false-positive feedback loop.
 *
 * A confirmed false positive (a benign input a rule wrongly matched) is the most
 * valuable benign sample we can get: it is real-world, and it names exactly which
 * rule is too loose. This script turns one confirmed FP into a PERMANENT benign
 * regression sample by appending it to data/benign-corpus-extended/wild-fp-confirmed.jsonl
 * — the same corpus that check-rules-safety.ts, gate-promotion-fp.ts, and
 * promote-to-stable.ts already scan. From that moment on:
 *
 *   - every NEW rule must stay 0-FP on this sample (safety gate), and
 *   - the offending rule can never be PROMOTED to a blocking lane until it stops
 *     matching it (promotion gate), and
 *   - the offending rule is reported here so it can be tightened or demoted.
 *
 * The loop is: rule alerts in hunt lane -> real benign input trips it -> that input
 * is reported (false-positive.yml issue) or captured (dogfooding) -> ingested here
 * -> the corpus grows toward the real world and the rule is forced to converge.
 * A new attack is NEVER rejected for having FPs — it enters at maturity:test in the
 * hunt/alert lane and simply cannot reach the enforce lane until it is FP-clean on
 * this ever-growing corpus.
 *
 * Usage:
 *   npx tsx scripts/ingest-fp-report.ts --text "<benign input>" --id dogfood-2026-07-14-1
 *   npx tsx scripts/ingest-fp-report.ts --issue 123        # parse a false-positive.yml issue via gh
 *   npx tsx scripts/ingest-fp-report.ts --text "..." --write   # actually append (default: dry-run)
 *
 * Exit 0 = ran cleanly. Exit 1 = bad args / rule-id given but nothing matched.
 */

import { readFileSync, appendFileSync, existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent } from "../src/types.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS = join(REPO_ROOT, "data/benign-corpus-extended/wild-fp-confirmed.jsonl");
const RULES_DIR = join(REPO_ROOT, "rules");

// Evaluate against every native event surface: a benign input can arrive as a
// user message, a tool response, or a tool call. A rule that fires on ANY of them
// against benign text is a false positive on that surface.
const EVENT_TYPES: AgentEvent["type"][] = ["llm_input", "tool_response", "tool_call"];

interface Args {
  text: string | null;
  issue: number | null;
  id: string | null;
  source: string;
  write: boolean;
}

function parseArgs(argv: string[]): Args {
  const a: Args = { text: null, issue: null, id: null, source: "field-fp-confirmed", write: false };
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (k === "--text") a.text = argv[++i] ?? null;
    else if (k === "--issue") a.issue = Number(argv[++i]);
    else if (k === "--id") a.id = argv[++i] ?? null;
    else if (k === "--source") a.source = argv[++i] ?? a.source;
    else if (k === "--write") a.write = true;
  }
  return a;
}

/** Pull the "Input that triggered the false positive" field out of a false-positive.yml issue body. */
function loadFromIssue(issue: number): { text: string; id: string; ruleHint: string | null } {
  const raw = execFileSync("gh", ["issue", "view", String(issue), "--json", "body,title"], {
    encoding: "utf-8",
  });
  const { body, title } = JSON.parse(raw) as { body: string; title: string };
  // GitHub form issues render as "### <label>\n\n<value>\n\n" blocks.
  const section = (label: string): string | null => {
    const re = new RegExp(`###\\s*${label}\\s*\\n+([\\s\\S]*?)(?:\\n###\\s|$)`, "i");
    const m = body.match(re);
    const v = m?.[1]?.trim();
    return v && v !== "_No response_" ? v : null;
  };
  const input = section("Input that triggered the false positive");
  if (!input) {
    throw new Error(`issue #${issue} has no "Input that triggered the false positive" field`);
  }
  return { text: input, id: `issue-${issue}`, ruleHint: section("Rule ID") ?? title };
}

function alreadyPresent(text: string): boolean {
  if (!existsSync(CORPUS)) return false;
  const norm = text.trim();
  for (const line of readFileSync(CORPUS, "utf-8").split("\n")) {
    if (!line.trim()) continue;
    try {
      if ((JSON.parse(line).text ?? "").trim() === norm) return true;
    } catch {
      /* skip malformed */
    }
  }
  return false;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  let text = args.text;
  let id = args.id;
  if (args.issue != null && !Number.isNaN(args.issue)) {
    const fromIssue = loadFromIssue(args.issue);
    text = text ?? fromIssue.text;
    id = id ?? fromIssue.id;
  }
  if (!text) {
    console.error("ingest-fp-report: need --text or --issue <n>");
    process.exit(1);
  }
  if (!id) id = `fp-${Date.now().toString(36)}`;

  const engine = new ATREngine({ rulesDir: RULES_DIR });
  await engine.loadRules();

  const offenders = new Set<string>();
  for (const type of EVENT_TYPES) {
    const evt: AgentEvent = { type, content: text, timestamp: "2026-01-01T00:00:00Z" };
    for (const m of engine.evaluate(evt)) offenders.add(m.rule.id);
  }

  console.log(`[fp-ingest] sample id=${id} (${text.length} chars)`);
  if (offenders.size === 0) {
    console.log(
      "[fp-ingest] no rule currently matches this input — either it was already " +
        "tightened, or the report predates a fix. Still safe to add as a benign " +
        "regression sample (prevents future regressions).",
    );
  } else {
    console.log(
      `[fp-ingest] ${offenders.size} rule(s) FALSELY match this benign input (must be ` +
        `tightened or kept out of the enforce lane):\n  ${[...offenders].sort().join(", ")}`,
    );
  }

  if (alreadyPresent(text)) {
    console.log("[fp-ingest] already in wild-fp-confirmed.jsonl — nothing to add.");
    return;
  }

  const record = JSON.stringify({ source: args.source, source_id: id, text });
  if (args.write) {
    appendFileSync(CORPUS, record + "\n", "utf-8");
    console.log(`[fp-ingest] appended to ${CORPUS.replace(REPO_ROOT + "/", "")}`);
    if (offenders.size > 0) {
      console.log(
        "[fp-ingest] the offending rule(s) above will now FAIL the safety/promotion " +
          "gate until tightened — that is the loop working as intended.",
      );
    }
  } else {
    console.log("[fp-ingest] dry-run (no --write). Would append:");
    console.log("  " + record.slice(0, 160) + (record.length > 160 ? "…" : ""));
  }
}

main().catch((e) => {
  console.error("[fp-ingest] error:", e instanceof Error ? e.message : e);
  process.exit(1);
});
