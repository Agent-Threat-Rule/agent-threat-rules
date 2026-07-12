#!/usr/bin/env node
/**
 * scan-wild-corpus.mjs — flywheel scan phase for the wild-scan pipeline.
 *
 * Reads data/wild-scan/dedup-manifest.json (produced by
 * scripts/dedup-wild-scan-corpus.ts) and runs the current rule engine once
 * per UNIQUE entity (using each group's primary member so a server listed
 * in multiple sources is only scanned once).
 *
 * Extracts scannable text per source type:
 *   - github-topic:       readme.content (+ descriptor_file / entrypoint_file if present)
 *   - official-registry:  server description + packages[].description/
 *                          environmentVariables descriptions + remotes[] headers
 *   - package-deps:       readme
 *   - clawhub:            content (the skill's SKILL.md body)
 *
 * Output: data/wild-scan/scan-report.json (flagged entities + rule-hit
 * histogram + severity breakdown). Clean samples are appended to
 * data/wild-benign/clean-corpus.jsonl (gitignored) to feed the existing
 * promote-to-stable --wild-corpus need.
 */
import { readFileSync, writeFileSync, appendFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { ATREngine } from '../dist/engine.js';

const MANIFEST_PATH = 'data/wild-scan/dedup-manifest.json';
const REPORT_PATH = 'data/wild-scan/scan-report.json';
const WILD_BENIGN_DIR = 'data/wild-benign';
const WILD_BENIGN_OUT = join(WILD_BENIGN_DIR, 'clean-corpus.jsonl');

function extractText(source, data) {
  switch (source) {
    case 'github-topic': {
      const parts = [data.description ?? ''];
      if (data.readme?.content) parts.push(data.readme.content);
      if (data.descriptor_file?.content) parts.push(data.descriptor_file.content);
      if (data.entrypoint_file?.content) parts.push(data.entrypoint_file.content);
      return parts.join('\n\n');
    }
    case 'official-registry': {
      const entry = data.latest_registry_entry ?? data;
      const srv = entry?.server ?? entry;
      const parts = [srv?.description ?? ''];
      for (const p of srv?.packages ?? []) {
        if (p.description) parts.push(p.description);
        for (const ev of p.environmentVariables ?? []) {
          if (ev.description) parts.push(ev.description);
        }
        for (const a of [...(p.runtimeArguments ?? []), ...(p.packageArguments ?? [])]) {
          if (a.description) parts.push(a.description);
          if (a.default) parts.push(String(a.default));
        }
      }
      for (const r of srv?.remotes ?? []) {
        for (const h of r.headers ?? []) {
          if (h.description) parts.push(h.description);
        }
      }
      return parts.join('\n\n');
    }
    case 'package-deps':
      return [data.description ?? '', data.readme ?? ''].join('\n\n');
    case 'clawhub':
      return [data.summary ?? '', data.description ?? '', data.content ?? ''].join('\n\n');
    default:
      return '';
  }
}

async function main() {
  if (!existsSync(MANIFEST_PATH)) {
    console.error(`Missing ${MANIFEST_PATH} -- run dedup-wild-scan-corpus.ts first.`);
    process.exit(1);
  }
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'));

  console.error('Loading rule engine...');
  const engine = new ATREngine({ rulesDir: 'rules' });
  const ruleCount = await engine.loadRules();
  console.error(`Engine loaded: ${ruleCount} rules`);
  console.error(`Scanning ${manifest.groups.length} unique entities...`);

  mkdirSync(WILD_BENIGN_DIR, { recursive: true });
  writeFileSync(WILD_BENIGN_OUT, '');

  let scanned = 0;
  let skipped = 0;
  let clean = 0;
  let flagged = 0;
  const severityCount = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  const ruleHits = {};
  const flaggedEntities = [];
  const startTime = Date.now();

  for (const group of manifest.groups) {
    const { source, file } = group.primary;
    const dir = `data/wild-scan/${source}`;
    let data;
    try {
      data = JSON.parse(readFileSync(join(dir, file), 'utf8'));
    } catch {
      skipped++;
      continue;
    }
    const text = extractText(source, data).trim();
    if (text.length < 10) {
      skipped++;
      continue;
    }
    let matches;
    try {
      matches = engine.scanSkill(text);
    } catch {
      skipped++;
      continue;
    }
    scanned++;

    if (matches.length > 0) {
      flagged++;
      const order = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };
      const topSeverity = matches.reduce(
        (max, m) => (order[m.rule.severity] > order[max] ? m.rule.severity : max),
        'informational'
      );
      severityCount[topSeverity]++;
      for (const m of matches) ruleHits[m.rule.id] = (ruleHits[m.rule.id] || 0) + 1;
      flaggedEntities.push({
        group_id: group.id,
        source,
        file,
        severity: topSeverity,
        rules: matches.map((m) => ({ id: m.rule.id, title: m.rule.title, severity: m.rule.severity })),
      });
    } else {
      clean++;
      appendFileSync(
        WILD_BENIGN_OUT,
        JSON.stringify({
          source: `wild-scan/${source}`,
          source_id: file,
          text,
        }) + '\n'
      );
    }

    if (scanned % 2000 === 0) {
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      process.stderr.write(`  ${scanned}/${manifest.groups.length} (${elapsed}s, flagged=${flagged})\r`);
    }
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  const report = {
    scanned_at_engine_rule_count: ruleCount,
    total_unique_entities: manifest.groups.length,
    scanned,
    skipped,
    clean,
    flagged,
    flagged_pct: scanned ? +((flagged / scanned) * 100).toFixed(2) : 0,
    severity_breakdown: severityCount,
    top_rule_hits: Object.entries(ruleHits)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 50)
      .map(([id, count]) => ({ id, count })),
    flagged_entities: flaggedEntities,
    elapsed_seconds: +elapsed,
  };
  writeFileSync(REPORT_PATH, JSON.stringify(report, null, 2) + '\n');

  console.error(`\n\nDone in ${elapsed}s: ${scanned} scanned, ${flagged} flagged (${report.flagged_pct}%), ${skipped} skipped.`);
  console.error(`Severity: ${JSON.stringify(severityCount)}`);
  console.error(`Wrote ${REPORT_PATH} and ${WILD_BENIGN_OUT} (${clean} clean samples).`);
}

main();
