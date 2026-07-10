#!/usr/bin/env tsx
/**
 * promote-to-stable.ts — Gap B of the detection flywheel.
 *
 * Auto-graduates PROVEN `maturity: test` (also experimental/draft) rules to
 * `maturity: stable`, which is the gate into the ENFORCE lane — i.e. the point
 * at which a rule stops merely ADVISING and can actually BLOCK an attack.
 * Without this step the flywheel keeps producing hundreds of `test` rules that
 * DETECT but never PROTECT, so a fresh attack is seen and logged but not stopped.
 *
 * A rule is promoted ONLY when EVERY gate passes. The gate IS the safety — this
 * is deliberately conservative (cf. the past "auto-merged 11 FP rules" incident):
 *
 *   1. SOAK     the rule's `date` is at least SOAK_DAYS old — proven over time,
 *               not brand-new and unobserved.
 *   2. RECALL   every declared true_positive triggers the rule AND every declared
 *               true_negative does not (100% self-test), with at least MIN_TP
 *               true_positives on record. A rule that cannot catch its own
 *               declared attacks is not ready to enforce.
 *   3. ZERO-FP  the rule fires on ZERO of the committed benign corpus
 *               (data/skill-benchmark/benign) — no false positive on known-good.
 *
 * Promotions are capped at MAX per run. Dry-run by default; pass --apply to
 * rewrite the `maturity:` line (and only that line — detection logic is never
 * touched). The resulting change is opened as a PR that STILL passes the full
 * rule-quality / safety CI before anything merges — a second independent gate.
 *
 * Usage:  npx tsx scripts/promote-to-stable.ts [--apply]
 * Env:    PROMOTE_SOAK_DAYS (14) · PROMOTE_MIN_TP (2) · PROMOTE_MAX (25)
 */
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';
import { ATREngine } from '../src/engine.js';
import type { AgentEvent } from '../src/types.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const RULES_DIR = join(REPO_ROOT, 'rules');
// The committed 432-sample benign corpus is the FLOOR gate. The production FP
// bar is the ~65K corpus (enforce lane ~0.24% FP) — point PROMOTE_BENIGN_DIR at
// a larger pre-built corpus (e.g. via scripts/build-benign-corpus.ts) for the
// stronger gate. 0-FP here is necessary but the human review on the PR is the
// backstop for the difference between this floor and the full bar.
const BENIGN_DIR = process.env.PROMOTE_BENIGN_DIR
  ? resolve(process.env.PROMOTE_BENIGN_DIR)
  : join(REPO_ROOT, 'data/skill-benchmark/benign');

const SOAK_DAYS = Number(process.env.PROMOTE_SOAK_DAYS ?? 14);
const MIN_TP = Number(process.env.PROMOTE_MIN_TP ?? 2);
const MAX = Number(process.env.PROMOTE_MAX ?? 25);
const APPLY = process.argv.includes('--apply');

const PROMOTABLE_FROM = new Set(['test', 'experimental', 'draft']);

/** Mirror scripts/validate-rule-testcases.ts so test-case field typing is identical. */
function asTextEvent(content: string): AgentEvent {
  return {
    type: 'mcp_exchange',
    timestamp: new Date().toISOString(),
    content,
    fields: {
      tool_name: 'corpus-sample',
      tool_input: content,
      tool_response: content,
      user_input: content,
    },
  };
}

function matched(engine: ATREngine, content: string): Set<string> {
  const s = new Set<string>();
  for (const m of engine.evaluate(asTextEvent(content))) s.add(m.rule.id);
  for (const m of engine.scanSkill(content)) s.add(m.rule.id);
  return s;
}

function listRuleFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...listRuleFiles(p));
    else if (e.name.endsWith('.yaml') || e.name.endsWith('.yml')) out.push(p);
  }
  return out;
}

function parseDate(d: unknown): number | null {
  if (typeof d !== 'string') return null;
  const m = d.match(/(\d{4})[/-](\d{1,2})[/-](\d{1,2})/);
  return m ? Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])) : null;
}

function tcText(t: Record<string, unknown>): string {
  const v = t.tool_response ?? t.input ?? t.content ?? t.tool_description ?? '';
  if (typeof v === 'string') return v;
  return v == null ? '' : JSON.stringify(v);
}

interface Candidate {
  id: string;
  file: string;
  raw: string;
  reasons: string[];
  eligible: boolean;
}

async function main(): Promise<void> {
  const engine = new ATREngine({ rulesDir: RULES_DIR });
  await engine.loadRules();

  // Single pass over the benign corpus → which rule IDs false-positive on it.
  // (Optional local smoke cap via PROMOTE_BENIGN_SAMPLE; CI runs the full set.)
  let benignFiles = readdirSync(BENIGN_DIR).filter((f) => f.endsWith('.md'));
  const benignSample = Number(process.env.PROMOTE_BENIGN_SAMPLE ?? 0);
  if (benignSample > 0) benignFiles = benignFiles.slice(0, benignSample);
  const benignFp = new Map<string, number>();
  let bi = 0;
  for (const f of benignFiles) {
    const text = readFileSync(join(BENIGN_DIR, f), 'utf8');
    for (const id of matched(engine, text)) benignFp.set(id, (benignFp.get(id) ?? 0) + 1);
    if (++bi % 100 === 0) console.error(`  [benign] ${bi}/${benignFiles.length}`);
  }
  console.error(`  [benign] scanned ${benignFiles.length}, ${benignFp.size} rules FP at least once`);

  const now = Date.now();

  // Parse all promotable-maturity rules and apply the CHEAP gates first (soak,
  // TP count, benign-FP from the precomputed map). Only survivors pay for the
  // expensive per-input self-test below — keeps the run tractable.
  interface Raw {
    id: string;
    file: string;
    raw: string;
    tps: Record<string, unknown>[];
    tns: Record<string, unknown>[];
    reasons: string[];
  }
  const parsed: Raw[] = [];
  for (const file of listRuleFiles(RULES_DIR)) {
    const raw = readFileSync(file, 'utf8');
    let doc: Record<string, unknown>;
    try {
      doc = (yaml.load(raw) ?? {}) as Record<string, unknown>;
    } catch {
      continue;
    }
    const id = String(doc.id ?? '');
    const maturity = String(doc.maturity ?? '').replace(/"/g, '');
    if (!id || !PROMOTABLE_FROM.has(maturity)) continue;

    const reasons: string[] = [];
    const dt = parseDate(doc.date);
    const ageDays = dt === null ? -1 : Math.floor((now - dt) / 86_400_000);
    if (ageDays < SOAK_DAYS) reasons.push(`soak ${ageDays}d<${SOAK_DAYS}d`);
    const tc = (doc.test_cases ?? {}) as Record<string, unknown[]>;
    const tps = (tc.true_positives ?? []) as Record<string, unknown>[];
    const tns = (tc.true_negatives ?? []) as Record<string, unknown>[];
    if (tps.length < MIN_TP) reasons.push(`TP ${tps.length}<${MIN_TP}`);
    const fp = benignFp.get(id) ?? 0;
    if (fp > 0) reasons.push(`${fp} benign FP`);

    parsed.push({ id, file, raw, tps, tns, reasons });
  }

  const cheapPass = parsed.filter((p) => p.reasons.length === 0);
  console.error(
    `  [gates] ${parsed.length} candidates · ${cheapPass.length} passed soak+TP-count+0-FP → running self-test`
  );

  // Expensive RECALL self-test only on cheap-gate survivors.
  const candidates: Candidate[] = parsed.map((p) => {
    const reasons = [...p.reasons];
    if (reasons.length === 0) {
      let tpMiss = 0;
      let tnTrip = 0;
      for (const t of p.tps) if (!matched(engine, tcText(t)).has(p.id)) tpMiss++;
      for (const t of p.tns) if (matched(engine, tcText(t)).has(p.id)) tnTrip++;
      if (tpMiss) reasons.push(`${tpMiss} TP miss`);
      if (tnTrip) reasons.push(`${tnTrip} TN trip`);
    }
    return { id: p.id, file: p.file, raw: p.raw, reasons, eligible: reasons.length === 0 };
  });

  const eligible = candidates.filter((c) => c.eligible);
  const promoting = eligible.slice(0, MAX);

  console.log(
    `\n=== promote-to-stable (soak>=${SOAK_DAYS}d · minTP=${MIN_TP} · max=${MAX} · apply=${APPLY}) ===`
  );
  console.log(
    `promotable-maturity candidates: ${candidates.length} · eligible: ${eligible.length} · promoting this run: ${promoting.length}`
  );
  for (const c of promoting) console.log(`  ✅ promote ${c.id}`);
  for (const c of candidates.filter((c) => !c.eligible).slice(0, 12)) {
    console.log(`  ⏳ hold ${c.id}: ${c.reasons.join('; ')}`);
  }

  if (APPLY) {
    let written = 0;
    for (const c of promoting) {
      const stamp = new Date().toISOString().slice(0, 10);
      const next = c.raw.replace(
        /^(maturity:\s*)"?(?:test|experimental|draft)"?[ \t]*$/m,
        `$1stable  # auto-promoted ${stamp}: soak>=${SOAK_DAYS}d + self-test 100% + 0-FP on benign gate`
      );
      if (next !== c.raw) {
        writeFileSync(c.file, next);
        written++;
      }
    }
    console.log(`\napplied: bumped ${written} rule(s) to maturity: stable`);
  } else {
    console.log(`\n(dry-run — pass --apply to write; nothing changed)`);
  }

  // Machine-readable summary for the workflow (GITHUB_OUTPUT).
  console.log(`PROMOTE_COUNT=${promoting.length}`);
  console.log(`PROMOTE_IDS=${promoting.map((c) => c.id).join(',')}`);
}

void main();
