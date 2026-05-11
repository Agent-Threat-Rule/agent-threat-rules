#!/usr/bin/env npx tsx
/**
 * Local safety check: run the 6 new rules ATR-2026-00442..00447 against the
 * 432-file benign skill corpus to ensure zero false positives before commit.
 *
 * Mirrors the FP-on-benign portion of scripts/check-rules-safety.ts but works
 * on untracked files (the auto-merge gate uses git diff which only sees
 * committed adds).
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ATREngine } from '../src/engine.js';
import type { AgentEvent } from '../src/types.js';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BENIGN_DIR = join(REPO_ROOT, 'data/skill-benchmark/benign');
const RULES_DIR = join(REPO_ROOT, 'rules');

const NEW_RULE_IDS = new Set([
  'ATR-2026-00442',
  'ATR-2026-00443',
  'ATR-2026-00444',
  'ATR-2026-00445',
  'ATR-2026-00446',
  'ATR-2026-00447',
]);

async function main(): Promise<void> {
  const engine = new ATREngine({ rulesDir: RULES_DIR });
  const loaded = await engine.loadRules();
  console.log(`[check] loaded ${loaded} rules`);

  const files = readdirSync(BENIGN_DIR).filter((f) => f.endsWith('.md'));
  console.log(`[check] scanning ${files.length} benign samples`);

  const fps: Map<string, string[]> = new Map();
  let scanned = 0;

  for (const file of files) {
    const text = readFileSync(join(BENIGN_DIR, file), 'utf-8');
    const event: AgentEvent = {
      type: 'user_input',
      user_input: text,
      content: text,
      text,
      fields: { text, user_input: text, content: text },
    } as AgentEvent;

    const matches = engine.evaluate(event);
    scanned++;

    for (const m of matches ?? []) {
      const ruleId = (m as any).ruleId ?? (m as any).rule?.id;
      if (ruleId && NEW_RULE_IDS.has(ruleId)) {
        const list = fps.get(ruleId) ?? [];
        list.push(file);
        fps.set(ruleId, list);
      }
    }
  }

  console.log(`[check] scanned ${scanned}/${files.length}`);
  let totalFps = 0;
  if (fps.size === 0) {
    console.log('\n[check] PASS — 0 false positives across all 6 new rules');
    console.log('  ATR-2026-00442 ✓');
    console.log('  ATR-2026-00443 ✓');
    console.log('  ATR-2026-00444 ✓');
    console.log('  ATR-2026-00445 ✓');
    console.log('  ATR-2026-00446 ✓');
    console.log('  ATR-2026-00447 ✓');
  } else {
    console.log('\n[check] FAIL — false positives detected:');
    for (const [ruleId, samples] of fps.entries()) {
      console.log(`  ${ruleId}: ${samples.length} FP(s)`);
      for (const s of samples.slice(0, 5)) {
        console.log(`    - ${s}`);
      }
      if (samples.length > 5) console.log(`    ... and ${samples.length - 5} more`);
      totalFps += samples.length;
    }
    console.log(`\nTotal FPs: ${totalFps}`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
