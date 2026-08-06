#!/usr/bin/env npx tsx
/**
 * measure-rule-recall-ab.ts — 規則收緊前後的 A/B attack recall。
 *
 * 「規則變聰明」的 recall 不能只用它自己的 5 條 test_cases 量。這裡用一個
 * 寬得多的攻擊集:
 *   1. 全 repo 所有規則的 test_cases.true_positives(4,038 條真攻擊樣本)
 *   2. data/test-corpora/ 底下的標準攻擊語料(garak inthewild / llm-guard /
 *      promptinject / promptfoo / nemo-guardrails / mitre-atlas)
 *
 * 判準:BASE 規則會 fire 的攻擊樣本裡,VARIANT 還 fire 幾條。
 */
import {
  readFileSync,
  readdirSync,
  statSync,
  existsSync,
  mkdtempSync,
  copyFileSync,
} from "node:fs";
import { join, resolve, dirname, basename } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { load } from "js-yaml";
import { ATREngine } from "../src/engine.js";
import { corpusShapes } from "../src/corpus-event.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function attackSamples(): string[] {
  const out: string[] = [];
  for (const f of execFileSync("git", ["ls-files", "rules/"], {
    encoding: "utf-8",
    maxBuffer: 64 * 1024 * 1024,
  })
    .split("\n")
    .filter((f) => f.endsWith(".yaml") || f.endsWith(".yml"))) {
    let d: any;
    try {
      d = load(readFileSync(join(REPO_ROOT, f), "utf-8"));
    } catch {
      continue;
    }
    const tps =
      d?.test_cases?.true_positives ??
      d?.detection?.test_cases?.true_positives ??
      [];
    for (const t of tps) {
      const txt = typeof t === "string" ? t : (t?.input ?? "");
      if (typeof txt === "string" && txt.length > 0) out.push(txt);
    }
  }
  const push = (v: unknown): void => {
    if (typeof v === "string" && v.length > 0) out.push(v);
  };
  const gk = join(REPO_ROOT, "data/test-corpora/garak-full/inthewild.json");
  if (existsSync(gk))
    (JSON.parse(readFileSync(gk, "utf-8")).prompts as string[]).forEach(push);
  for (const rel of [
    "data/test-corpora/llm-guard/corpus.json",
    "data/test-corpora/promptfoo/corpus.json",
    "data/test-corpora/nemo-guardrails/corpus.json",
  ]) {
    const p = join(REPO_ROOT, rel);
    if (!existsSync(p)) continue;
    const j = JSON.parse(readFileSync(p, "utf-8")) as any;
    for (const a of j.attacks ?? j.samples ?? [])
      push(a?.text ?? a?.prompt ?? a);
  }
  const pi = join(REPO_ROOT, "data/test-corpora/promptinject");
  if (existsSync(pi))
    for (const f of readdirSync(pi).filter((x) => x.endsWith(".json"))) {
      try {
        const j = JSON.parse(readFileSync(join(pi, f), "utf-8")) as any[];
        if (Array.isArray(j))
          for (const r of j) push(r?.full_prompt ?? r?.attack_instruction);
      } catch {
        /* ignore */
      }
    }
  return out;
}

function ruleFileFor(dir: string, id: string): string | null {
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) {
      const r = ruleFileFor(full, id);
      if (r) return r;
    } else if (e.endsWith(".yaml") || e.endsWith(".yml")) {
      const s = readFileSync(full, "utf-8");
      if (s.includes(`\nid: ${id}\n`) || s.startsWith(`id: ${id}\n`))
        return full;
    }
  }
  return null;
}

async function engineFor(dir: string, ids: string[]): Promise<ATREngine> {
  const scoped = mkdtempSync(join(tmpdir(), "atr-ab-"));
  for (const id of ids) {
    const f = ruleFileFor(resolve(dir), id);
    if (!f) throw new Error(`not found ${id} in ${dir}`);
    copyFileSync(f, join(scoped, basename(f)));
  }
  const e = new ATREngine({ rulesDir: scoped });
  await e.loadRules();
  return e;
}

function fires(e: ATREngine, text: string, id: string): boolean {
  for (const shape of corpusShapes(text))
    for (const m of e.evaluate(shape.event)) if (m.rule.id === id) return true;
  for (const m of e.scanSkill(text)) if (m.rule.id === id) return true;
  return false;
}

async function main(): Promise<void> {
  const [baseDir, varDir, ...ids] = process.argv.slice(2);
  if (!baseDir || !varDir || ids.length === 0)
    throw new Error(
      "usage: measure-rule-recall-ab.ts <baseRulesDir> <variantRulesDir> <id...>",
    );
  const attacks = attackSamples();
  console.log(`attack corpus = ${attacks.length} samples`);
  const base = await engineFor(baseDir, ids);
  const vari = await engineFor(varDir, ids);
  for (const id of ids) {
    let b = 0;
    let kept = 0;
    let newHits = 0;
    for (const a of attacks) {
      const fb = fires(base, a, id);
      const fv = fires(vari, a, id);
      if (fb) {
        b += 1;
        if (fv) kept += 1;
      } else if (fv) newHits += 1;
    }
    console.log(
      `${id}  base_attack_hits=${b}  variant_kept=${kept} (${b ? ((100 * kept) / b).toFixed(1) : "n/a"}%)  variant_new=${newHits}`,
    );
  }
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.stack : String(e));
  process.exit(1);
});
