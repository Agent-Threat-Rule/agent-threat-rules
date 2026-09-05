/**
 * Authoring tool: for one rule YAML, print each condition's required literals,
 * then run every condition against the measured benign corpora and report hits.
 * Usage: npx tsx _ruletool.ts <rule.yaml> [--corpus]
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import yaml from "js-yaml";
import { requirementOf, literalsOf } from "../scripts/lib/regex-literals.js";

const ruleFile = process.argv[2];
const doCorpus = process.argv.includes("--corpus");
const doc: any = yaml.load(readFileSync(ruleFile, "utf8"));
const conds: any[] = doc?.detection?.conditions ?? [];

console.log(`RULE ${doc.id} — ${conds.length} conditions\n`);
for (const [i, c] of conds.entries()) {
  const r = requirementOf(String(c.value));
  console.log(`[${i + 1}] field=${c.field}`);
  console.log(`    constrained=${r.constrained}  literals=${JSON.stringify(literalsOf(r))}`);
}

if (!doCorpus) process.exit(0);

// ---- corpus sweep ----
const CORPORA = ["data/skill-benchmark/benign", "data/benign-corpus-extended", "data/benign-code"];
type Sample = { text: string; src: string };
const samples: Sample[] = [];
function walk(p: string) {
  let st; try { st = statSync(p); } catch { return; }
  if (st.isDirectory()) { for (const f of readdirSync(p)) walk(join(p, f)); return; }
  const txt = readFileSync(p, "utf8");
  if (p.endsWith(".jsonl")) {
    for (const line of txt.split("\n")) {
      const t = line.trim(); if (!t) continue;
      try { const o = JSON.parse(t); const s = o.text ?? o.content ?? o.input ?? ""; if (s) samples.push({ text: String(s), src: `${p}` }); } catch {}
    }
  } else if (p.endsWith(".json")) {
    try {
      const o = JSON.parse(txt);
      const arr = Array.isArray(o) ? o : (o.samples ?? o.items ?? []);
      for (const it of arr) { const s = typeof it === "string" ? it : (it.text ?? it.content ?? it.input ?? ""); if (s) samples.push({ text: String(s), src: p }); }
    } catch {}
  } else {
    samples.push({ text: txt, src: p });
  }
}
for (const c of CORPORA) walk(resolve(process.cwd(), c));
console.log(`\ncorpus: ${samples.length} benign samples`);

const compiled = conds.map((c, i) => {
  const v = String(c.value);
  const nv = v.replace(/^\(\?[imsx]+\)/, "");
  const flags = /\\u\{|\\p\{/.test(nv) ? "iu" : "i";
  try { return { i, re: new RegExp(nv, flags) }; } catch (e) { console.log(`  !! condition ${i + 1} will not compile: ${e}`); return null; }
}).filter(Boolean) as { i: number; re: RegExp }[];

const isAll = (doc?.detection?.condition ?? "any") === "all";
let total = 0;
const perSample = samples.map((s) => compiled.filter(({ re }) => re.test(s.text)).length);
if (isAll) {
  const conj = samples.filter((_, k) => perSample[k] === compiled.length);
  console.log(`condition: all -> conjunction benign hits: ${conj.length}`);
  for (const h of conj.slice(0, 6)) console.log(`    ${h.src.split("/").slice(-1)[0]} :: ${h.text.slice(0, 200).replace(/\n/g, "\\n")}`);
}
for (const { i, re } of compiled) {
  const hits = samples.filter((s) => re.test(s.text));
  console.log(`[${i + 1}] benign hits: ${hits.length}`);
  for (const h of hits.slice(0, 6)) {
    const m = h.text.match(re);
    console.log(`    ${h.src.split("/").slice(-1)[0]} :: ...${(m ? m[0] : "").slice(0, 160).replace(/\n/g, "\\n")}...`);
  }
  total += hits.length;
}
console.log(`TOTAL benign hits across conditions: ${total}`);
