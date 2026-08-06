#!/usr/bin/env npx tsx
/**
 * measure-rule-fp-segmented.ts — 對一小組規則同時量:
 *   FP  = data/skill-benchmark/benign + benign-corpus-extended + benign-code(與 gate 同一組語料 / 同一組事件形狀)
 *   TP  = 規則自己的 test_cases.true_positives(每條各自算)
 *   + 依 src/corpus/security-content.ts 把 FP 拆成「一般 benign」與「資安內容」
 *
 * 用法:npx tsx scripts/measure-rule-fp-segmented.ts <rulesDir> <ATR-id> [<ATR-id>...]
 */
import {
  readFileSync,
  readdirSync,
  existsSync,
  statSync,
  mkdtempSync,
  copyFileSync,
} from "node:fs";
import { join, resolve, dirname, basename, relative } from "node:path";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { load } from "js-yaml";
import { ATREngine } from "../src/engine.js";
import { corpusShapes } from "../src/corpus-event.js";
import { classifySecurityContent } from "../src/corpus/security-content.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CORPORA = [
  join(REPO_ROOT, "data/skill-benchmark/benign"),
  join(REPO_ROOT, "data/benign-corpus-extended"),
  join(REPO_ROOT, "data/benign-code"),
];

interface Sample {
  readonly source: string;
  readonly text: string;
}

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (e.endsWith(".jsonl") || e.endsWith(".md")) out.push(full);
  }
  return out;
}

function loadCorpus(p: string): Sample[] {
  const out: Sample[] = [];
  if (!existsSync(p)) return out;
  for (const f of statSync(p).isDirectory() ? walk(p) : [p]) {
    let raw: string;
    try {
      raw = readFileSync(f, "utf-8");
    } catch {
      continue;
    }
    const rel = relative(REPO_ROOT, f);
    if (f.endsWith(".md")) {
      out.push({ source: rel, text: raw });
      continue;
    }
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        const o = JSON.parse(t) as { text?: string };
        if (o.text) out.push({ source: rel, text: o.text });
      } catch {
        /* ignore */
      }
    }
  }
  return out;
}

function ruleFileFor(rulesDir: string, id: string): string | null {
  const search = (d: string): string | null => {
    for (const e of readdirSync(d)) {
      const full = join(d, e);
      if (statSync(full).isDirectory()) {
        const r = search(full);
        if (r) return r;
      } else if (e.endsWith(".yaml") || e.endsWith(".yml")) {
        if (
          readFileSync(full, "utf-8").includes(`\nid: ${id}\n`) ||
          readFileSync(full, "utf-8").startsWith(`id: ${id}\n`)
        )
          return full;
      }
    }
    return null;
  };
  return search(rulesDir);
}

async function main(): Promise<void> {
  const [rulesDirArg, ...ids] = process.argv.slice(2);
  if (!rulesDirArg || ids.length === 0)
    throw new Error("usage: measure-rule-fp-segmented.ts <rulesDir> <id...>");
  const rulesDir = resolve(rulesDirArg);

  const files = ids.map((id) => {
    const f = ruleFileFor(rulesDir, id);
    if (!f) throw new Error(`rule not found: ${id} under ${rulesDir}`);
    return f;
  });

  const scoped = mkdtempSync(join(tmpdir(), "atr-exp-"));
  files.forEach((f) => copyFileSync(f, join(scoped, basename(f))));
  const engine = new ATREngine({ rulesDir: scoped });
  await engine.loadRules();

  const samples: Sample[] = [];
  for (const c of CORPORA) samples.push(...loadCorpus(c));

  const fpGeneral = new Map<string, number>();
  const fpSecurity = new Map<string, number>();
  const bySource = new Map<string, Map<string, number>>();
  for (const id of ids) {
    fpGeneral.set(id, 0);
    fpSecurity.set(id, 0);
    bySource.set(id, new Map());
  }

  let nSecurity = 0;
  for (const s of samples) {
    const isSec = classifySecurityContent(s.text).label === "security-content";
    if (isSec) nSecurity += 1;
    const matched = new Set<string>();
    for (const shape of corpusShapes(s.text))
      for (const m of engine.evaluate(shape.event)) matched.add(m.rule.id);
    for (const m of engine.scanSkill(s.text)) matched.add(m.rule.id);
    for (const id of matched) {
      if (!fpGeneral.has(id)) continue;
      if (isSec) fpSecurity.set(id, (fpSecurity.get(id) ?? 0) + 1);
      else fpGeneral.set(id, (fpGeneral.get(id) ?? 0) + 1);
      const bs = bySource.get(id)!;
      bs.set(s.source, (bs.get(s.source) ?? 0) + 1);
    }
  }

  // recall on each rule's own declared true positives
  const tpHit = new Map<string, [number, number]>();
  for (let i = 0; i < ids.length; i++) {
    const id = ids[i]!;
    const d = load(readFileSync(files[i]!, "utf-8")) as any;
    const tps =
      d?.test_cases?.true_positives ??
      d?.detection?.test_cases?.true_positives ??
      [];
    let hit = 0;
    for (const t of tps) {
      const text = typeof t === "string" ? t : (t?.input ?? JSON.stringify(t));
      const matched = new Set<string>();
      for (const shape of corpusShapes(String(text)))
        for (const m of engine.evaluate(shape.event)) matched.add(m.rule.id);
      for (const m of engine.scanSkill(String(text))) matched.add(m.rule.id);
      if (matched.has(id)) hit += 1;
    }
    tpHit.set(id, [hit, tps.length]);
  }

  console.log(
    `corpus = ${samples.length} samples (security-content labeled = ${nSecurity})`,
  );
  console.log(`rulesDir = ${rulesDir}`);
  for (const id of ids) {
    const g = fpGeneral.get(id) ?? 0;
    const s = fpSecurity.get(id) ?? 0;
    const [h, n] = tpHit.get(id) ?? [0, 0];
    console.log(
      `${id}  FP_total=${g + s}  FP_general=${g}  FP_security=${s}  own_TP=${h}/${n}`,
    );
    const top = [...(bySource.get(id) ?? new Map())]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 4);
    for (const [src, n2] of top) console.log(`      ${src}: ${n2}`);
  }
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.stack : String(e));
  process.exit(1);
});
