#!/usr/bin/env node
/**
 * gate-promotion-fp.ts — block a maturity promotion that would put an
 * FP-producing rule into the enforce (auto-block) lane.
 *
 * WHY: maturity:stable is the enforce lane (see engine.ts — "enforce = only
 * maturity=stable rules, auto-block, lowest FP"). A promoter that keys on time
 * ("≥60 days in test + 0 FP *reports*") can promote a rule that has never been
 * scanned against a benign corpus. This gate re-runs the rules a PR promotes to
 * stable/production against the local benign corpora and FAILS if any of them
 * false-positive — so a bad promotion turns the PR red instead of shipping.
 *
 * Modes:
 *   gate-promotion-fp.ts --base origin/main   # auto-detect rules this branch
 *                                             # sets to stable/production, gate them
 *   gate-promotion-fp.ts --ids <file>         # gate an explicit ATR-id list
 *
 * Exit 0 = no promoted rule false-positives (or nothing promoted).
 * Exit 1 = at least one promoted rule FPs on the benign corpus.
 */
import {
  readFileSync,
  readdirSync,
  existsSync,
  statSync,
  mkdtempSync,
  copyFileSync,
} from "node:fs";
import { join, resolve, dirname, basename } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent } from "../src/types.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(REPO_ROOT, "rules");
const CORPORA = [
  join(REPO_ROOT, "data/skill-benchmark/benign"),
  join(REPO_ROOT, "data/benign-corpus-extended"),
  join(REPO_ROOT, "data/benign-code"),
];
const ENFORCE_MATURITIES = new Set(["stable", "production"]);

function arg(name: string): string | null {
  const i = process.argv.indexOf(name);
  return i >= 0 ? (process.argv[i + 1] ?? null) : null;
}

/** Rule files this branch sets to an enforce-lane maturity, vs the base ref. */
function promotedFilesFromDiff(base: string): string[] {
  const diff = execFileSync(
    "git",
    ["diff", `${base}...HEAD`, "--unified=0", "--", "rules/"],
    { cwd: REPO_ROOT, encoding: "utf-8", maxBuffer: 64 * 1024 * 1024 },
  );
  const files = new Set<string>();
  let current: string | null = null;
  for (const line of diff.split("\n")) {
    const m = /^\+\+\+ b\/(rules\/.*\.ya?ml)$/.exec(line);
    if (m) {
      current = m[1] ?? null;
      continue;
    }
    const mm = /^\+\s*maturity:\s*["']?(\w+)["']?\s*$/.exec(line);
    if (mm && current && ENFORCE_MATURITIES.has(mm[1] ?? "")) files.add(current);
  }
  return [...files];
}

function ruleIdOf(file: string): string | null {
  for (const line of readFileSync(join(REPO_ROOT, file), "utf-8").split("\n")) {
    const m = /^id:\s*(\S+)/.exec(line);
    if (m) return m[1] ?? null;
  }
  return null;
}

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

function loadCorpusTexts(pathStr: string): string[] {
  const texts: string[] = [];
  if (!existsSync(pathStr)) return texts;
  const files: string[] = [];
  if (statSync(pathStr).isDirectory()) {
    for (const e of readdirSync(pathStr))
      if (e.endsWith(".jsonl") || e.endsWith(".md")) files.push(join(pathStr, e));
  } else files.push(pathStr);
  for (const f of files) {
    let raw: string;
    try {
      raw = readFileSync(f, "utf-8");
    } catch {
      continue;
    }
    if (f.endsWith(".md")) {
      texts.push(raw);
      continue;
    }
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        const obj = JSON.parse(t) as { text?: string };
        if (typeof obj.text === "string" && obj.text.length > 0) texts.push(obj.text);
      } catch {
        continue;
      }
    }
  }
  return texts;
}

/** Copy just the target rule files into a temp dir so the engine loads only them. */
function scopedRulesDir(files: string[]): string {
  const dir = mkdtempSync(join(tmpdir(), "atr-gate-"));
  for (const f of files) copyFileSync(join(REPO_ROOT, f), join(dir, basename(f)));
  return dir;
}

async function main(): Promise<void> {
  const idsFile = arg("--ids");
  const base = arg("--base") ?? "origin/main";

  let targetFiles: string[];
  let targetIds: Set<string>;

  if (idsFile) {
    targetIds = new Set(
      readFileSync(idsFile, "utf-8").split("\n").map((s) => s.trim()).filter(Boolean),
    );
    targetFiles = [];
    for (const f of execFileSync("git", ["ls-files", "rules/"], {
      cwd: REPO_ROOT,
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    }).split("\n")) {
      if (!f.endsWith(".yaml") && !f.endsWith(".yml")) continue;
      const id = ruleIdOf(f);
      if (id && targetIds.has(id)) targetFiles.push(f);
    }
  } else {
    targetFiles = promotedFilesFromDiff(base);
    targetIds = new Set(targetFiles.map(ruleIdOf).filter((x): x is string => !!x));
  }

  if (targetFiles.length === 0) {
    console.log(`[fp-gate] no rules promoted to enforce lane vs ${base} — nothing to gate.`);
    return;
  }
  console.log(`[fp-gate] gating ${targetFiles.length} promoted rule(s) against the benign corpus`);

  const engine = new ATREngine({ rulesDir: scopedRulesDir(targetFiles) });
  await engine.loadRules();

  const samples: string[] = [];
  for (const c of CORPORA) samples.push(...loadCorpusTexts(c));

  const fp = new Map<string, number>();
  for (const id of targetIds) fp.set(id, 0);
  for (const text of samples) {
    const matched = new Set<string>();
    for (const m of engine.evaluate(asTextEvent(text))) matched.add(m.rule.id);
    for (const m of engine.scanSkill(text)) matched.add(m.rule.id);
    for (const id of matched) if (targetIds.has(id)) fp.set(id, (fp.get(id) ?? 0) + 1);
  }

  const dirty = [...fp.entries()].filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]);
  console.log(`[fp-gate] corpus = ${samples.length} benign samples`);
  console.log(`[fp-gate] clean = ${targetIds.size - dirty.length} · dirty = ${dirty.length}`);
  if (dirty.length > 0) {
    console.error(`\n[fp-gate] FAIL — these promoted rules false-positive on benign content and`);
    console.error(`must not enter the enforce (auto-block) lane:`);
    for (const [id, n] of dirty) console.error(`  ${id} — ${n} FP`);
    process.exit(1);
  }
  console.log(`[fp-gate] PASS — all promoted rules are FP-clean on the benign corpus.`);
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.stack : String(e));
  process.exit(1);
});
