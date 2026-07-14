#!/usr/bin/env npx tsx
/**
 * demote-fp-rules.ts — the enforcement half of the FP feedback loop.
 *
 * The enforce lane (maturity: stable) auto-BLOCKS. A rule there must be 0-FP on
 * the benign corpus, because blocking a legitimate action is real harm. But the
 * corpus GROWS (ingest-fp-report.ts feeds real-world false positives into
 * wild-fp-confirmed.jsonl), so a rule that was clean when promoted can start
 * false-positiving as the corpus catches up to the real world.
 *
 * This script re-runs EVERY maturity:stable rule against the FULL current benign
 * corpus and DEMOTES any that now match a benign sample (stable -> test). The rule
 * is not deleted and keeps alerting in the hunt/alert lane — it just drops out of
 * the auto-block lane until it is tightened and re-promoted through
 * promote-to-stable.ts. This is how rules self-sediment: coverage stays (nothing
 * is removed), but only rules that survive the ever-growing corpus keep the power
 * to block.
 *
 * Usage:
 *   npx tsx scripts/demote-fp-rules.ts            # dry-run report
 *   npx tsx scripts/demote-fp-rules.ts --write    # apply demotions to the rule files
 *
 * Exit 0 always (a report/no-op is not a failure).
 */

import { readFileSync, writeFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent } from "../src/types.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(REPO_ROOT, "rules");
const ENFORCE_MATURITY = "stable"; // the auto-block lane
const DEMOTE_TO = "test"; // still alerts in the alert/hunt lane

const BENIGN_SOURCES = [
  join(REPO_ROOT, "data/skill-benchmark/benign"), // *.md
  join(REPO_ROOT, "data/benign-corpus-extended"), // *.jsonl {text}
  join(REPO_ROOT, "data/benign-code"), // *.jsonl {text}
  join(REPO_ROOT, "data/research-mentions"), // corpus.jsonl {text}
];
const EVENT_TYPES: AgentEvent["type"][] = ["llm_input", "tool_response", "tool_call"];

const write = process.argv.includes("--write");

function loadBenign(): string[] {
  const out: string[] = [];
  for (const src of BENIGN_SOURCES) {
    if (!existsSync(src)) continue;
    const entries = statSync(src).isDirectory() ? readdirSync(src).map((f) => join(src, f)) : [src];
    for (const p of entries) {
      if (p.endsWith(".md")) {
        out.push(readFileSync(p, "utf-8"));
      } else if (p.endsWith(".jsonl")) {
        for (const line of readFileSync(p, "utf-8").split("\n")) {
          if (!line.trim()) continue;
          try {
            const o = JSON.parse(line);
            const t = o.text ?? o.content ?? o.code;
            if (typeof t === "string") out.push(t);
          } catch {
            /* skip */
          }
        }
      }
    }
  }
  return out;
}

/**
 * Flip the top-level `maturity:` field in a rule YAML, preserving everything else.
 * Handles both bare (`maturity: stable`) and quoted (`maturity: "stable"`) values —
 * the quoted form is common and was silently skipped by an earlier bare-only regex,
 * leaving the worst offenders (which happen to be quoted, e.g. 00020/00021/00001)
 * un-demoted.
 */
function setMaturity(path: string, to: string): boolean {
  const src = readFileSync(path, "utf-8");
  const re = /^(maturity:[ \t]*)(["']?)(\w+)\2([ \t]*)$/m;
  if (!re.test(src)) return false;
  writeFileSync(path, src.replace(re, `$1$2${to}$2$4`), "utf-8");
  return true;
}

async function main(): Promise<void> {
  const engine = new ATREngine({ rulesDir: RULES_DIR });
  await engine.loadRules();

  // Map rule id -> file path (walk the rules tree).
  const idToPath = new Map<string, string>();
  const walk = (dir: string): void => {
    for (const e of readdirSync(dir)) {
      const p = join(dir, e);
      if (statSync(p).isDirectory()) walk(p);
      else if (e.endsWith(".yaml")) {
        const m = readFileSync(p, "utf-8").match(/^id:\s*(ATR-\d{4}-\d{5})/m);
        if (m) idToPath.set(m[1], p);
      }
    }
  };
  walk(RULES_DIR);

  const stableIds = new Set<string>();
  for (const r of engine.getRules?.() ?? []) {
    if ((r as { maturity?: string }).maturity === ENFORCE_MATURITY) stableIds.add(r.id);
  }
  // Fallback if getRules() is unavailable: read maturity from files.
  if (stableIds.size === 0) {
    for (const [id, p] of idToPath) {
      if (/^maturity:\s*stable\s*$/m.test(readFileSync(p, "utf-8"))) stableIds.add(id);
    }
  }

  const benign = loadBenign();
  console.log(
    `[demote] scanning ${stableIds.size} enforce-lane (stable) rule(s) against ${benign.length} benign samples`,
  );

  // rule id -> {count, example}
  const fp = new Map<string, { count: number; example: string }>();
  for (const text of benign) {
    const hit = new Set<string>();
    for (const type of EVENT_TYPES) {
      for (const m of engine.evaluate({ type, content: text, timestamp: "2026-01-01T00:00:00Z" })) {
        if (stableIds.has(m.rule.id)) hit.add(m.rule.id);
      }
    }
    for (const id of hit) {
      const cur = fp.get(id) ?? { count: 0, example: text.slice(0, 100).replace(/\s+/g, " ") };
      cur.count++;
      fp.set(id, cur);
    }
  }

  if (fp.size === 0) {
    console.log("[demote] all enforce-lane rules are 0-FP on the current corpus — nothing to demote.");
    return;
  }

  const demoted: string[] = [];
  for (const [id, info] of [...fp.entries()].sort((a, b) => b[1].count - a[1].count)) {
    const path = idToPath.get(id);
    console.log(`  ${id} — ${info.count} FP  e.g. "${info.example}…"  ${path ? "" : "(file not found)"}`);
    if (write && path && setMaturity(path, DEMOTE_TO)) demoted.push(id);
  }

  if (write) {
    console.log(
      `\n[demote] demoted ${demoted.length} rule(s) ${ENFORCE_MATURITY} -> ${DEMOTE_TO} ` +
        `(they keep alerting in the alert/hunt lane; re-promote via promote-to-stable.ts once tightened).`,
    );
  } else {
    console.log(
      `\n[demote] dry-run: ${fp.size} enforce-lane rule(s) FP on the corpus and would be demoted. ` +
        `Re-run with --write to apply.`,
    );
  }
}

main().catch((e) => {
  console.error("[demote] error:", e instanceof Error ? e.message : e);
  process.exit(1);
});
