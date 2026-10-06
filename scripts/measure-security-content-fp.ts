#!/usr/bin/env npx tsx
/**
 * measure-security-content-fp.ts — 重現 docs/research/benign-gate-security-education-2026-08-07.md 的頭條數字。
 *
 * 問題:14,561 個 FP 裡,有多少落在被標為「資安內容」的樣本上?
 *
 * 不需要重跑全語料。被標記的樣本只有 37 條,所以把**全部規則**跑在**那 37 條**上,
 * 得到的 match 總數就是資安內容貢獻的 FP 精確值(gate 的計數方式是 per-sample
 * per-rule,與這裡一致)。
 */
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { ATREngine } from "../src/engine.js";
import { corpusShapes } from "../src/corpus-event.js";
import { classifySecurityContent } from "../src/corpus/security-content.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CORPORA = [
  join(REPO_ROOT, "data/skill-benchmark/benign"),
  join(REPO_ROOT, "data/benign-corpus-extended"),
  join(REPO_ROOT, "data/benign-code"),
];

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (e.endsWith(".jsonl") || e.endsWith(".md")) out.push(full);
  }
  return out;
}

async function main(): Promise<void> {
  const secSamples: { source: string; text: string }[] = [];
  let total = 0;
  for (const c of CORPORA) {
    if (!existsSync(c)) continue;
    for (const f of statSync(c).isDirectory() ? walk(c) : [c]) {
      const raw = readFileSync(f, "utf-8");
      const rel = relative(REPO_ROOT, f);
      const consider = (t: string): void => {
        total += 1;
        if (classifySecurityContent(t).label === "security-content")
          secSamples.push({ source: rel, text: t });
      };
      if (f.endsWith(".md")) {
        consider(raw);
        continue;
      }
      for (const line of raw.split("\n")) {
        const t = line.trim();
        if (!t) continue;
        try {
          const o = JSON.parse(t) as { text?: string };
          if (typeof o.text === "string" && o.text.length > 0) consider(o.text);
        } catch {
          /* ignore */
        }
      }
    }
  }
  console.log(`corpus = ${total} · security-content = ${secSamples.length}`);

  const engine = new ATREngine({ rulesDir: join(REPO_ROOT, "rules") });
  await engine.loadRules();
  console.log(`rules loaded = ${engine.getRules().length}`);

  let fp = 0;
  const perRule = new Map<string, number>();
  const perSource = new Map<string, number>();
  for (const s of secSamples) {
    const matched = new Set<string>();
    for (const shape of corpusShapes(s.text))
      for (const m of engine.evaluate(shape.event)) matched.add(m.rule.id);
    for (const m of engine.scanSkill(s.text)) matched.add(m.rule.id);
    fp += matched.size;
    perSource.set(s.source, (perSource.get(s.source) ?? 0) + matched.size);
    for (const id of matched) perRule.set(id, (perRule.get(id) ?? 0) + 1);
  }
  console.log(`FP landing on security-content samples = ${fp}`);
  console.log(`distinct rules firing on them = ${perRule.size}`);
  console.log("\ntop rules on security content:");
  for (const [id, n] of [...perRule].sort((a, b) => b[1] - a[1]).slice(0, 15))
    console.log(`  ${id} — ${n}`);
  console.log("\nsource distribution of the labelled samples:");
  const cnt = new Map<string, number>();
  for (const s of secSamples) cnt.set(s.source, (cnt.get(s.source) ?? 0) + 1);
  for (const [src, n] of [...cnt].sort((a, b) => b[1] - a[1]))
    console.log(`  ${src}: ${n} sample(s), ${perSource.get(src) ?? 0} FP`);
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.stack : String(e));
  process.exit(1);
});
