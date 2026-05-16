#!/usr/bin/env npx tsx
/**
 * promote-detection-ready.ts
 *
 * Walks proposals/ for drafts with _triage.detection_ready=true,
 * runs scripts/generate-detection-from-poc.ts against each, and moves
 * successfully-generated rules into rules/<category>/ATR-2026-NNNNN-
 * <slug>.yaml. Failed generations stay as proposals.
 *
 * After this script runs, scripts/check-rules-safety.ts is the next
 * gate -- it can be invoked per-rule (--file) or batch (--base origin/
 * main). Rules that clear safety are eligible for auto-merge via the
 * existing tc-pr-back.yml flow.
 *
 * Usage:
 *   npx tsx scripts/promote-detection-ready.ts                # dry-run
 *   npx tsx scripts/promote-detection-ready.ts --write        # commit changes
 *   npx tsx scripts/promote-detection-ready.ts --max 5        # cap to 5 promotions
 *   npx tsx scripts/promote-detection-ready.ts --source ghsa  # only this source
 *
 * Exit codes:
 *   0 success (may have promoted 0 or more)
 *   1 fatal IO / parse error
 */

import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const PROPOSALS_BASE = resolve(REPO_ROOT, "proposals");
const RULES_BASE = resolve(REPO_ROOT, "rules");
const GENERATOR = resolve(__dirname, "generate-detection-from-poc.ts");
const DEFAULT_MAX = 10;

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const SOURCE_FILTER = opt("--source");
const MAX_PROMOTE = opt("--max") ? parseInt(opt("--max")!, 10) : DEFAULT_MAX;

const VALID_CATEGORIES = new Set([
  "agent-manipulation",
  "context-exfiltration",
  "data-poisoning",
  "excessive-autonomy",
  "model-abuse",
  "privilege-escalation",
  "prompt-injection",
  "skill-compromise",
  "tool-poisoning",
]);

interface Candidate {
  proposalPath: string;
  proposalAbs: string;
  source: string;
  category: string;
  draftId: string;
}

function walkYaml(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const f = join(dir, entry);
    let s;
    try {
      s = statSync(f);
    } catch {
      continue;
    }
    if (s.isDirectory()) out.push(...walkYaml(f));
    else if (s.isFile() && (entry.endsWith(".yaml") || entry.endsWith(".yml")))
      out.push(f);
  }
  return out;
}

function loadProposal(path: string): Record<string, unknown> | null {
  try {
    return yaml.load(readFileSync(path, "utf-8")) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function findCandidates(): Candidate[] {
  const out: Candidate[] = [];
  for (const f of walkYaml(PROPOSALS_BASE)) {
    if (!f.includes(".proposal.")) continue;
    const rel = f.slice(REPO_ROOT.length + 1);
    const source = rel.split("/")[1] ?? "unknown";
    if (SOURCE_FILTER && source !== SOURCE_FILTER) continue;
    const doc = loadProposal(f);
    if (!doc) continue;
    const triage = doc._triage as
      | { detection_ready?: boolean }
      | undefined;
    if (triage?.detection_ready !== true) continue;
    const tags = doc.tags as { category?: string } | undefined;
    const category = tags?.category ?? "";
    if (!VALID_CATEGORIES.has(category)) continue;
    const draftId =
      typeof doc.id === "string" ? doc.id : "";
    if (!draftId.startsWith("ATR-DRAFT-")) continue;
    out.push({
      proposalPath: rel,
      proposalAbs: f,
      source,
      category,
      draftId,
    });
  }
  return out;
}

function nextAtrId(): () => string {
  const seen = new Set<number>();
  const idRe = /^id:\s*ATR-2026-(\d{5})\b/m;
  for (const f of walkYaml(RULES_BASE)) {
    try {
      const m = idRe.exec(readFileSync(f, "utf-8"));
      if (m) seen.add(parseInt(m[1], 10));
    } catch {
      /* skip */
    }
  }
  let next = (Math.max(0, ...Array.from(seen)) + 1) || 1;
  return () => {
    while (seen.has(next)) next += 1;
    seen.add(next);
    return `ATR-2026-${String(next).padStart(5, "0")}`;
  };
}

function slugify(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);
}

interface PromotionResult {
  candidate: Candidate;
  status: "promoted" | "no-patterns" | "error";
  reason?: string;
  newRulePath?: string;
  newRuleId?: string;
}

function tryGenerate(c: Candidate, idGen: () => string, write: boolean): PromotionResult {
  // Use a generator-scoped tmp path that does not need the final ID,
  // so we only allocate an ATR ID after a successful generation. This
  // keeps the ATR-2026-NNNNN sequence dense; failures don't burn IDs.
  const tmpOut = `/tmp/atr-promote-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}.yaml`;
  let genOk = false;
  try {
    execFileSync(
      "npx",
      ["tsx", GENERATOR, c.proposalAbs, "--output", tmpOut],
      { stdio: "pipe", encoding: "utf-8" },
    );
    genOk = true;
  } catch (err: unknown) {
    const e = err as { status?: number; stderr?: string };
    if (e.status === 2) {
      return { candidate: c, status: "no-patterns", reason: "no extractable patterns" };
    }
    return {
      candidate: c,
      status: "error",
      reason: `generator failed: ${e.stderr ?? String(err)}`,
    };
  }
  if (!genOk || !existsSync(tmpOut)) {
    return { candidate: c, status: "error", reason: "generator produced no output" };
  }

  let rule: Record<string, unknown>;
  try {
    rule = yaml.load(readFileSync(tmpOut, "utf-8")) as Record<string, unknown>;
  } catch (err) {
    unlinkSync(tmpOut);
    return { candidate: c, status: "error", reason: `parse: ${String(err)}` };
  }

  const newId = idGen();
  rule.id = newId;
  rule.status = "experimental";
  if (rule.maturity === undefined) rule.maturity = "experimental";

  const title =
    typeof rule.title === "string"
      ? rule.title
      : c.draftId.replace("ATR-DRAFT-", "");
  const slug = slugify(title) || newId.toLowerCase();
  const outFileName = `${newId}-${slug}.yaml`;
  const outDir = join(RULES_BASE, c.category);
  const outAbs = join(outDir, outFileName);
  const outRel = outAbs.slice(REPO_ROOT.length + 1);

  if (write) {
    if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
    writeFileSync(outAbs, yaml.dump(rule, { lineWidth: 120, noRefs: true }), "utf-8");
    if (existsSync(c.proposalAbs)) unlinkSync(c.proposalAbs);
  }

  unlinkSync(tmpOut);
  return {
    candidate: c,
    status: "promoted",
    newRulePath: outRel,
    newRuleId: newId,
  };
}

function main(): void {
  if (!existsSync(GENERATOR)) {
    console.error(`generator not found at ${GENERATOR}`);
    process.exit(1);
  }

  const candidates = findCandidates();
  const limited = candidates.slice(0, MAX_PROMOTE);
  const idGen = nextAtrId();

  const summary = {
    run_date: new Date().toISOString(),
    write: WRITE,
    candidates_total: candidates.length,
    candidates_attempted: limited.length,
    source_filter: SOURCE_FILTER ?? null,
    max: MAX_PROMOTE,
    promoted: 0,
    no_patterns: 0,
    errors: 0,
    results: [] as Array<{
      proposal: string;
      status: string;
      new_rule?: string;
      new_id?: string;
      reason?: string;
    }>,
  };

  for (const c of limited) {
    const r = tryGenerate(c, idGen, WRITE);
    if (r.status === "promoted") summary.promoted += 1;
    else if (r.status === "no-patterns") summary.no_patterns += 1;
    else summary.errors += 1;
    summary.results.push({
      proposal: c.proposalPath,
      status: r.status,
      new_rule: r.newRulePath,
      new_id: r.newRuleId,
      reason: r.reason,
    });
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::promote-summary::${JSON.stringify({
      candidates: summary.candidates_total,
      attempted: summary.candidates_attempted,
      promoted: summary.promoted,
      no_patterns: summary.no_patterns,
      errors: summary.errors,
    })}`,
  );
}

main();
