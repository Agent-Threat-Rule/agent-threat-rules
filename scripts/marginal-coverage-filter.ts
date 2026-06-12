#!/usr/bin/env node
/**
 * marginal-coverage-filter.ts — Wave-2 marginal scan coverage filter
 *
 * Reads an attack corpus (JSONL, one {"source": "...", "attack": "..."} per
 * line), runs every attack through the full ATR engine (event evaluation +
 * skill scanning, mirroring check-rules-safety.ts's matchAllRuleIds), and
 * writes the UNCOVERED lines (no rule matched) verbatim to the misses file.
 *
 * Usage:
 *   npx tsx scripts/marginal-coverage-filter.ts \
 *     --corpus /tmp/wave2/corpus.jsonl \
 *     --out /tmp/wave2/misses.jsonl
 *
 * Final line on stdout is a single JSON summary:
 *   {"total":N,"covered":N,"missed":N}
 * All progress / warning output goes to stderr so stdout stays parseable.
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent } from "../src/types.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(REPO_ROOT, "rules");

interface CliArgs {
  corpus: string;
  out: string;
}

interface CorpusLine {
  source?: string;
  attack?: string;
}

function parseArgs(): CliArgs {
  const argv = process.argv.slice(2);
  const corpusIdx = argv.indexOf("--corpus");
  const outIdx = argv.indexOf("--out");
  const corpus = corpusIdx >= 0 ? (argv[corpusIdx + 1] ?? "") : "";
  const out = outIdx >= 0 ? (argv[outIdx + 1] ?? "") : "";
  if (!corpus || !out) {
    console.error(
      "Usage: npx tsx scripts/marginal-coverage-filter.ts --corpus <corpus.jsonl> --out <misses.jsonl>",
    );
    process.exit(1);
  }
  return { corpus, out };
}

/** Build a single AgentEvent from arbitrary text content. */
function asTextEvent(content: string): AgentEvent {
  return {
    type: "mcp_exchange",
    timestamp: new Date().toISOString(),
    content,
    fields: {
      tool_name: "corpus-sample",
      tool_input: content,
      tool_response: content,
      user_input: content,
    },
  };
}

/**
 * Run the ATR engine over a sample and return the set of rule IDs that
 * matched (across both event evaluation and skill scanning, to mirror
 * the production engine's two paths).
 */
function matchAllRuleIds(engine: ATREngine, content: string): Set<string> {
  const matched = new Set<string>();
  for (const m of engine.evaluate(asTextEvent(content))) matched.add(m.rule.id);
  for (const m of engine.scanSkill(content)) matched.add(m.rule.id);
  return matched;
}

async function main(): Promise<void> {
  const { corpus, out } = parseArgs();

  if (!existsSync(corpus)) {
    console.error(`[coverage-filter] corpus not found: ${corpus}`);
    process.exit(1);
  }

  const engine = new ATREngine({ rulesDir: RULES_DIR });
  await engine.loadRules();

  const raw = readFileSync(corpus, "utf-8");
  const missedLines: string[] = [];
  let total = 0;
  let covered = 0;

  for (const line of raw.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    let parsed: CorpusLine;
    try {
      parsed = JSON.parse(trimmed) as CorpusLine;
    } catch {
      console.error(
        `[coverage-filter] skipping unparseable line: ${trimmed.slice(0, 80)}`,
      );
      continue;
    }

    const attack = parsed.attack;
    if (typeof attack !== "string" || attack.length === 0) {
      console.error(
        `[coverage-filter] skipping line without attack field: ${trimmed.slice(0, 80)}`,
      );
      continue;
    }

    total += 1;
    const matchedIds = matchAllRuleIds(engine, attack);
    if (matchedIds.size > 0) {
      covered += 1;
    } else {
      missedLines.push(trimmed);
    }
  }

  writeFileSync(out, missedLines.join("\n") + (missedLines.length > 0 ? "\n" : ""), "utf-8");

  const missed = total - covered;
  console.error(
    `[coverage-filter] corpus=${corpus} rules=${RULES_DIR} misses written to ${out}`,
  );
  console.log(JSON.stringify({ total, covered, missed }));
}

void main();
