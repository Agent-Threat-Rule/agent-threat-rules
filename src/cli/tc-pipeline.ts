/**
 * Standardized Threat Cloud pipeline commands.
 *
 *   atr tc sync        Push repo rules → TC (updates metrics + website)
 *   atr tc pull        Pull confirmed TC rules → repo (validate + write)
 *   atr tc crystallize Send missed attacks → TC LLM → new proposals
 *   atr tc status      Show TC state (rules, proposals, threats)
 *
 * All commands are idempotent and safe to run repeatedly.
 * CI workflows call these same commands — no ad-hoc scripts.
 *
 * @module agent-threat-rules/cli/tc-pipeline
 */

import { readFileSync, writeFileSync, existsSync, readdirSync, statSync, mkdirSync, unlinkSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { execSync } from 'node:child_process';

const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

interface TCConfig {
  readonly tcUrl: string;
  readonly adminKey: string;
  readonly rulesDir: string;
  readonly dryRun: boolean;
}

function getConfig(options: Record<string, string | undefined>): TCConfig {
  // No built-in endpoint, for the same reason the reporter has none: this
  // package must not name a collector. These are operator commands, so failing
  // here costs one flag; the alternative is a hostname nobody chose.
  const tcUrl = options['tc-url'] ?? process.env['TC_URL'];
  if (!tcUrl || !tcUrl.trim()) {
    console.error(
      `${RED}Error: no Threat Cloud endpoint. Pass --tc-url <url> or set TC_URL. ` +
        `ATR ships no default endpoint.${RESET}`,
    );
    process.exit(1);
  }
  return {
    tcUrl: tcUrl.trim().replace(/\/+$/, ''),
    adminKey: options['tc-key'] ?? process.env['TC_ADMIN_API_KEY'] ?? process.env['TC_API_KEY'] ?? '',
    rulesDir: resolve(options['rules'] ?? 'rules'),
    dryRun: options['dry-run'] === 'true',
  };
}

function authHeaders(adminKey: string): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (adminKey) h['Authorization'] = `Bearer ${adminKey}`;
  return h;
}

// ── atr tc sync ───────────────────────────────────────────────

export async function cmdTCSync(options: Record<string, string | undefined>): Promise<void> {
  const cfg = getConfig(options);
  console.log(`\n${BOLD}ATR TC Sync${RESET}`);
  console.log(`${DIM}Push repo rules → Threat Cloud${RESET}\n`);

  const rules: Array<{ ruleId: string; ruleContent: string; source: string }> = [];
  for (const cat of readdirSync(cfg.rulesDir)) {
    const catDir = join(cfg.rulesDir, cat);
    if (!statSync(catDir).isDirectory()) continue;
    for (const f of readdirSync(catDir).filter(f => f.endsWith('.yaml'))) {
      const content = readFileSync(join(catDir, f), 'utf-8');
      const id = content.match(/^id:\s*(\S+)/m)?.[1] ?? f;
      rules.push({ ruleId: id, ruleContent: content, source: 'atr' });
    }
  }

  console.log(`  Rules found: ${rules.length}`);

  if (cfg.dryRun) {
    console.log(`  ${DIM}[DRY RUN] Would sync ${rules.length} rules to ${cfg.tcUrl}${RESET}`);
    return;
  }

  if (!cfg.adminKey) {
    console.error(`  ${RED}Error: TC admin key required. Set TC_ADMIN_API_KEY or --tc-key${RESET}`);
    process.exit(1);
  }

  const resp = await fetch(`${cfg.tcUrl}/api/rules/sync`, {
    method: 'POST',
    headers: authHeaders(cfg.adminKey),
    body: JSON.stringify({ rules }),
    signal: AbortSignal.timeout(30_000),
  });
  const data = await resp.json() as { ok: boolean; data?: { count: number } };

  if (data.ok) {
    console.log(`  ${GREEN}Synced: ${data.data?.count ?? rules.length} rules → ${cfg.tcUrl}${RESET}`);
  } else {
    console.error(`  ${RED}Failed: ${JSON.stringify(data)}${RESET}`);
    process.exit(1);
  }

  // Verify metrics
  const metrics = await fetch(`${cfg.tcUrl}/api/metrics`, { signal: AbortSignal.timeout(5000) })
    .then(r => r.json()) as { data?: { totalAtrRules: number } };
  console.log(`  TC metrics: ${metrics.data?.totalAtrRules ?? '?'} rules`);
}

// ── atr tc pull ───────────────────────────────────────────────

export async function cmdTCPull(options: Record<string, string | undefined>): Promise<void> {
  const cfg = getConfig(options);
  const SYNC_FILE = resolve('data/.tc-last-sync');

  console.log(`\n${BOLD}ATR TC Pull${RESET}`);
  console.log(`${DIM}Pull confirmed TC rules → repo${RESET}\n`);

  // Determine since timestamp
  const since = options['since']
    ?? (existsSync(SYNC_FILE) ? readFileSync(SYNC_FILE, 'utf-8').trim() : '');
  const sinceParam = since || new Date(Date.now() - 7 * 86400000).toISOString();

  if (!cfg.adminKey) {
    console.error(`  ${RED}Error: TC admin key required. Set TC_ADMIN_API_KEY or --tc-key${RESET}`);
    process.exit(1);
  }

  const resp = await fetch(`${cfg.tcUrl}/api/atr-rules?since=${encodeURIComponent(sinceParam)}`, {
    headers: authHeaders(cfg.adminKey),
    signal: AbortSignal.timeout(15_000),
  });
  const raw = await resp.json() as { ok: boolean; error?: string; data: Array<{ ruleId: string; ruleContent: string; source: string }> };
  if (!raw.ok) { console.error(`  ${RED}TC API error: ${raw.error ?? resp.status}${RESET}`); process.exit(1); }

  // Find existing rule IDs in repo
  const existingIds = new Set<string>();
  for (const cat of readdirSync(cfg.rulesDir)) {
    const catDir = join(cfg.rulesDir, cat);
    if (!statSync(catDir).isDirectory()) continue;
    for (const f of readdirSync(catDir).filter(f => f.endsWith('.yaml'))) {
      const id = readFileSync(join(catDir, f), 'utf-8').match(/^id:\s*(\S+)/m)?.[1];
      if (id) existingIds.add(id);
    }
  }

  const newRules = raw.data.filter(r => {
    const id = r.ruleContent.match(/^id:\s*(\S+)/m)?.[1] ?? '';
    return !existingIds.has(id) && r.source !== 'atr';
  });

  console.log(`  TC rules: ${raw.data.length} | Already in repo: ${raw.data.length - newRules.length} | New: ${newRules.length}`);

  if (newRules.length === 0) {
    console.log(`  ${GREEN}Up to date.${RESET}`);
    if (!cfg.dryRun) writeFileSync(SYNC_FILE, new Date().toISOString());
    return;
  }

  // Find next rule ID
  let maxId = 0;
  for (const cat of readdirSync(cfg.rulesDir)) {
    const catDir = join(cfg.rulesDir, cat);
    if (!statSync(catDir).isDirectory()) continue;
    for (const f of readdirSync(catDir)) {
      const m = f.match(/ATR-2026-(\d{5})/);
      if (m) maxId = Math.max(maxId, parseInt(m[1]!, 10));
    }
  }
  let nextId = maxId + 1;

  const written: string[] = [];
  for (const rule of newRules) {
    let content = rule.ruleContent;

    // Replace draft IDs
    if (content.includes('DRAFT')) {
      const realId = `ATR-2026-${String(nextId).padStart(5, '0')}`;
      content = content.replace(/ATR-2026-DRAFT-[A-Za-z0-9]+|ATR-2026-DRAFT|ATR-DRAFT/g, realId);
      nextId++;
    }

    // Auto-fix LLM YAML: double-quoted regex → single-quoted
    content = content.replace(
      /^(\s+value:\s*)"((?:[^"\\]|\\.)*)"\s*$/gm,
      (_, prefix, regex) => `${prefix}'${regex.replace(/'/g, "''")}'`,
    );

    const id = content.match(/^id:\s*(\S+)/m)?.[1] ?? 'unknown';
    const category = content.match(/category:\s*(\S+)/m)?.[1] ?? 'prompt-injection';
    const sub = content.match(/subcategory:\s*(\S+)/m)?.[1] ?? id.toLowerCase();
    const slug = sub.replace(/[^a-z0-9-]/g, '-').slice(0, 40);

    const catDir = join(cfg.rulesDir, category);
    if (!existsSync(catDir)) mkdirSync(catDir, { recursive: true });
    const filePath = join(catDir, `${id}-${slug}.yaml`);

    if (cfg.dryRun) {
      console.log(`  ${DIM}[DRY RUN] ${filePath}${RESET}`);
      continue;
    }

    writeFileSync(filePath, content);

    // Validate
    try {
      execSync(`node dist/cli.js validate "${filePath}"`, { encoding: 'utf-8', stdio: 'pipe' });
      written.push(filePath);
      console.log(`  ${GREEN}+${RESET} ${id} (${category}/${slug})`);
    } catch {
      console.log(`  ${RED}x${RESET} ${id} — invalid, removed`);
      unlinkSync(filePath);
    }
  }

  if (!cfg.dryRun) writeFileSync(SYNC_FILE, new Date().toISOString());
  console.log(`\n  ${BOLD}${written.length} rules pulled.${RESET}`);
}

// ── atr tc crystallize ────────────────────────────────────────

export async function cmdTCCrystallize(options: Record<string, string | undefined>): Promise<void> {
  const cfg = getConfig(options);

  console.log(`\n${BOLD}ATR TC Crystallize${RESET}`);
  console.log(`${DIM}Send missed attacks → TC LLM → proposals${RESET}\n`);

  // Load engine + adversarial samples
  const { ATREngine } = await import('../engine.js');
  const engine = new ATREngine({ rulesDir: cfg.rulesDir });
  await engine.loadRules();

  const samplesPath = resolve('data/autoresearch/adversarial-samples.json');
  if (!existsSync(samplesPath)) {
    console.error(`  ${RED}No adversarial samples at ${samplesPath}${RESET}`);
    process.exit(1);
  }
  const samples = JSON.parse(readFileSync(samplesPath, 'utf-8'));

  // Find missed attacks
  const missed = new Map<string, Array<{ payload: string }>>();
  for (const s of samples) {
    const m = engine.evaluate({
      type: 'tool_response', timestamp: new Date().toISOString(),
      content: s.payload, fields: { content: s.payload },
    });
    if (m.length === 0) {
      const list = missed.get(s.technique) ?? [];
      list.push(s);
      missed.set(s.technique, list);
    }
  }

  const techniques = [...missed.entries()].filter(([, items]) => items.length >= 5);
  const totalMissed = techniques.reduce((s, [, i]) => s + i.length, 0);
  console.log(`  Samples: ${samples.length} | Missed: ${totalMissed} | Techniques: ${techniques.length}`);

  if (techniques.length === 0) {
    console.log(`  ${GREEN}All samples covered. Nothing to crystallize.${RESET}`);
    return;
  }

  if (cfg.dryRun) {
    for (const [tech, items] of techniques) {
      console.log(`  ${DIM}[DRY RUN] ${tech}: ${items.length} samples${RESET}`);
    }
    return;
  }

  let created = 0;
  let errors = 0;
  for (const [tech, items] of techniques) {
    const tools = items.slice(0, 8).map((s, i) => ({
      name: `${tech}_${i}`,
      description: s.payload,
    }));

    try {
      const resp = await fetch(`${cfg.tcUrl}/api/analyze-skills`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ skills: [{ package: `crystallize-${tech}-${Date.now()}`, tools }] }),
        signal: AbortSignal.timeout(60_000),
      });

      if (!resp.ok) {
        const text = await resp.text();
        // Skip HTML errors (TC overloaded)
        if (text.startsWith('<!')) { errors++; continue; }
      }

      const data = await resp.json() as { data?: { results?: Array<{ status: string; proposalCount: number; cached: boolean }> } };
      const r = data.data?.results?.[0];
      const p = r?.proposalCount ?? 0;
      created += p;
      const tag = r?.cached ? `${DIM}cached${RESET}` : (p > 0 ? `${GREEN}+${p}${RESET}` : `${DIM}0${RESET}`);
      console.log(`  ${tech} (${items.length}) → ${tag}`);

      await new Promise(r => setTimeout(r, 5000));
    } catch {
      errors++;
      console.log(`  ${tech} → ${RED}error${RESET}`);
    }
  }

  console.log(`\n  ${BOLD}Proposals: ${created} | Errors: ${errors}${RESET}`);
}

// ── atr tc status ─────────────────────────────────────────────

export async function cmdTCStatus(options: Record<string, string | undefined>): Promise<void> {
  const cfg = getConfig(options);

  console.log(`\n${BOLD}ATR Threat Cloud Status${RESET}`);
  console.log(`${DIM}${cfg.tcUrl}${RESET}\n`);

  const [stats, metrics] = await Promise.all([
    fetch(`${cfg.tcUrl}/api/stats`, { signal: AbortSignal.timeout(5000) }).then(r => r.json()).catch(() => null),
    fetch(`${cfg.tcUrl}/api/metrics`, { signal: AbortSignal.timeout(5000) }).then(r => r.json()).catch(() => null),
  ]) as [{ data: Record<string, unknown> } | null, { data: Record<string, unknown> } | null];

  if (!stats?.data) {
    console.error(`  ${RED}Cannot reach TC at ${cfg.tcUrl}${RESET}`);
    process.exit(1);
  }

  const s = stats.data as Record<string, unknown>;
  const p = s['proposalStats'] as Record<string, number>;
  const m = metrics?.data as Record<string, unknown> | undefined;

  // Count local rules
  let localRules = 0;
  for (const cat of readdirSync(cfg.rulesDir)) {
    const catDir = join(cfg.rulesDir, cat);
    if (!statSync(catDir).isDirectory()) continue;
    localRules += readdirSync(catDir).filter(f => f.endsWith('.yaml')).length;
  }

  const tcRules = (s['totalRules'] as number) ?? 0;
  const synced = localRules === tcRules;

  console.log(`  ${BOLD}Rules${RESET}`);
  console.log(`    Local repo:  ${localRules}`);
  console.log(`    TC:          ${tcRules} ${synced ? GREEN + '(synced)' + RESET : RED + '(out of sync — run: atr tc sync)' + RESET}`);
  console.log(`    Metrics API: ${(m?.['totalAtrRules'] as number) ?? '?'}`);

  console.log(`\n  ${BOLD}Proposals${RESET}`);
  console.log(`    Pending:     ${p?.['pending'] ?? 0}`);
  console.log(`    Canary:      ${p?.['canary'] ?? 0}`);
  console.log(`    Confirmed:   ${p?.['confirmed'] ?? 0}`);
  console.log(`    Rejected:    ${p?.['rejected'] ?? 0}`);
  console.log(`    Total:       ${p?.['total'] ?? 0}`);

  console.log(`\n  ${BOLD}Data${RESET}`);
  console.log(`    Threats:     ${s['totalThreats'] ?? 0} (24h: ${s['last24hThreats'] ?? 0})`);
  console.log(`    Skill scans: ${s['skillThreatsTotal'] ?? 0}`);
  console.log(`    Blacklist:   ${s['skillBlacklistTotal'] ?? 0}`);
  console.log(`    Protected:   ${(m?.['totalAgentsProtected'] as number) ?? 0} devices`);
  console.log('');
}
