/**
 * wild-scan-diff.ts — turn one-shot wild scans into a continuous feed.
 *
 * The wild scan (96K agent skills -> 1,302 flagged -> 552 confirmed malware)
 * is ATR's unique discovery asset, but the published blacklist is a frozen
 * snapshot. A snapshot is not a feed. This script diffs a fresh scan against
 * the published baseline and emits what is NEW / GONE / CHANGED since last
 * time, clustered to CAMPAIGN level (one signal per threat actor — never one
 * id per skill hash; a single actor shipping 354 variants is one campaign,
 * not 354 findings).
 *
 * Output is a review artifact, not an auto-publish: new malware attributions
 * are accusations against named third-party authors and must clear human
 * review before they reach the public blacklist.
 *
 * Usage:
 *   npx tsx scripts/wild-scan-diff.ts \
 *     --baseline data/public-blacklist.json \
 *     --current  <fresh-scan-blacklist>.json \
 *     [--out data/wild-scan] [--confirmed-only]
 *
 * Both inputs accept the public-blacklist shape ({ entries: [...] }) or a bare
 * array of entries. An entry needs at least { skill, source }; severity,
 * threat_actor, confirmed_malware and rules are used when present.
 *
 * ANCHOR CAVEAT: entries are keyed on `source::skill` (author/name), which is
 * MUTABLE — an actor can rename a skill and evade the diff. The structural fix
 * is to anchor on an immutable content hash (skill_sha256). Until the scan
 * records that, this diff keys on identity and flags renamed-looking pairs.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join } from "node:path";

interface BlacklistEntry {
  skill: string;
  source: string;
  severity?: string;
  threat_actor?: string;
  confirmed_malware?: boolean;
  primary_rule?: string;
  rules?: string[];
  link?: string;
  sha256?: string;
}

interface ChangedEntry {
  key: string;
  skill: string;
  source: string;
  changes: string[];
  from: Partial<BlacklistEntry>;
  to: Partial<BlacklistEntry>;
}

interface Campaign {
  threat_actor: string;
  newCount: number;
  changedCount: number;
  sources: Record<string, number>;
  severities: Record<string, number>;
  sampleSkills: string[];
}

interface DiffReport {
  generated: string;
  baseline: { path: string; date: string; entries: number };
  current: { path: string; date: string; entries: number };
  confirmedOnly: boolean;
  summary: { added: number; removed: number; changed: number; campaigns: number };
  campaigns: Campaign[];
  added: BlacklistEntry[];
  removed: BlacklistEntry[];
  changed: ChangedEntry[];
}

function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const k = a.slice(2);
    const next = argv[i + 1];
    if (next && !next.startsWith("--")) {
      out[k] = next;
      i++;
    } else {
      out[k] = true;
    }
  }
  return out;
}

interface ScanResult {
  author?: string;
  name?: string;
  riskLevel?: string;
  findings?: Array<{ id?: string }>;
  source?: string;
}

/** Normalize a raw scan-cumulative result ({author,name,riskLevel,findings})
 *  into a blacklist entry. Only flagged (CRITICAL/HIGH) results become entries —
 *  a clean skill is not a blacklist member. */
function fromScanResult(r: ScanResult, defaultSource: string): BlacklistEntry | null {
  const level = (r.riskLevel ?? "").toUpperCase();
  if (level !== "CRITICAL" && level !== "HIGH") return null;
  if (!r.author || !r.name) return null;
  return {
    skill: `${r.author}/${r.name}`,
    source: r.source ?? defaultSource,
    severity: level.toLowerCase(),
    confirmed_malware: level === "CRITICAL",
    rules: (r.findings ?? [])
      .map((f) => (f.id ?? "").replace(/^atr-/i, ""))
      .filter(Boolean),
    threat_actor: r.author,
  };
}

/** Accepts three shapes: a bare entry array, { entries: [...] } (published
 *  blacklist), or { results: [...] } (scan-cumulative — flagged rows only). */
function loadEntries(path: string): BlacklistEntry[] {
  const raw = JSON.parse(readFileSync(path, "utf-8"));
  if (!Array.isArray(raw) && Array.isArray(raw.results)) {
    const src = typeof raw.source === "string" ? raw.source : "ClawHub";
    return (raw.results as ScanResult[])
      .map((r) => fromScanResult(r, src))
      .filter((e): e is BlacklistEntry => e !== null);
  }
  const list: unknown = Array.isArray(raw) ? raw : raw.entries;
  if (!Array.isArray(list)) {
    throw new Error(`${path}: expected an array, { entries: [...] }, or { results: [...] }`);
  }
  return list.filter(
    (e): e is BlacklistEntry =>
      !!e && typeof e.skill === "string" && typeof e.source === "string",
  );
}

const keyOf = (e: BlacklistEntry): string => `${e.source}::${e.skill}`;
const actorOf = (e: BlacklistEntry): string =>
  e.threat_actor && e.threat_actor.trim() ? e.threat_actor : "unattributed";

/** Stable, order-independent fingerprint of an entry's material fields. */
function materialOf(e: BlacklistEntry): string {
  return JSON.stringify({
    severity: e.severity ?? null,
    confirmed: e.confirmed_malware ?? null,
    actor: actorOf(e),
    rules: [...(e.rules ?? (e.primary_rule ? [e.primary_rule] : []))].sort(),
  });
}

function bump(rec: Record<string, number>, k: string): Record<string, number> {
  return { ...rec, [k]: (rec[k] ?? 0) + 1 };
}

function clusterCampaigns(
  added: BlacklistEntry[],
  changed: ChangedEntry[],
  byKey: Map<string, BlacklistEntry>,
): Campaign[] {
  const acc = new Map<string, Campaign>();
  const touch = (actor: string): Campaign =>
    acc.get(actor) ?? {
      threat_actor: actor,
      newCount: 0,
      changedCount: 0,
      sources: {},
      severities: {},
      sampleSkills: [],
    };

  for (const e of added) {
    const actor = actorOf(e);
    const c = touch(actor);
    acc.set(actor, {
      ...c,
      newCount: c.newCount + 1,
      sources: bump(c.sources, e.source),
      severities: bump(c.severities, e.severity ?? "unknown"),
      sampleSkills:
        c.sampleSkills.length < 5 ? [...c.sampleSkills, e.skill] : c.sampleSkills,
    });
  }
  for (const ch of changed) {
    const e = byKey.get(ch.key);
    const actor = e ? actorOf(e) : "unattributed";
    const c = touch(actor);
    acc.set(actor, { ...c, changedCount: c.changedCount + 1 });
  }
  // Campaigns sorted by total activity, largest first.
  return Array.from(acc.values()).sort(
    (a, b) => b.newCount + b.changedCount - (a.newCount + a.changedCount),
  );
}

function isoDate(meta: unknown, fallback: string): string {
  if (meta && typeof meta === "object") {
    const g = (meta as { generated?: string; scan_date?: string });
    const d = g.generated ?? g.scan_date;
    if (typeof d === "string") return d.slice(0, 10);
  }
  return fallback;
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const baselinePath = (args.baseline as string) ?? "data/public-blacklist.json";
  const currentPath = args.current as string;
  const outDir = (args.out as string) ?? "data/wild-scan";
  const confirmedOnly = !!args["confirmed-only"];

  if (!currentPath) {
    console.error(
      "usage: wild-scan-diff.ts --current <new-scan>.json [--baseline <published>.json] [--out <dir>] [--confirmed-only]",
    );
    process.exit(2);
  }

  const keep = (e: BlacklistEntry): boolean =>
    !confirmedOnly || e.confirmed_malware === true;

  const current = loadEntries(currentPath).filter(keep);
  // Scope the baseline to the sources the current scan actually covered, so a
  // partial re-scan (e.g. ClawHub only) does not report every other source's
  // entries as "removed". --no-scope compares the full baseline (use only when
  // current is a full multi-registry re-scan).
  const currentSources = new Set(current.map((e) => e.source));
  const scopeBaseline = !args["no-scope"] && currentSources.size > 0;
  const baseline = loadEntries(baselinePath)
    .filter(keep)
    .filter((e) => !scopeBaseline || currentSources.has(e.source));

  const baseByKey = new Map(baseline.map((e) => [keyOf(e), e] as const));
  const curByKey = new Map(current.map((e) => [keyOf(e), e] as const));

  const added = current.filter((e) => !baseByKey.has(keyOf(e)));
  const removed = baseline.filter((e) => !curByKey.has(keyOf(e)));

  const changed: ChangedEntry[] = [];
  for (const e of current) {
    const k = keyOf(e);
    const prev = baseByKey.get(k);
    if (!prev) continue;
    if (materialOf(prev) === materialOf(e)) continue;
    const changes: string[] = [];
    if ((prev.severity ?? null) !== (e.severity ?? null)) changes.push("severity");
    if ((prev.confirmed_malware ?? null) !== (e.confirmed_malware ?? null))
      changes.push("confirmed_malware");
    if (actorOf(prev) !== actorOf(e)) changes.push("threat_actor");
    if (
      JSON.stringify([...(prev.rules ?? [])].sort()) !==
      JSON.stringify([...(e.rules ?? [])].sort())
    )
      changes.push("rules");
    changed.push({
      key: k,
      skill: e.skill,
      source: e.source,
      changes,
      from: { severity: prev.severity, confirmed_malware: prev.confirmed_malware, threat_actor: prev.threat_actor },
      to: { severity: e.severity, confirmed_malware: e.confirmed_malware, threat_actor: e.threat_actor },
    });
  }

  const campaigns = clusterCampaigns(added, changed, curByKey);
  const stampNow = new Date().toISOString();
  const today = stampNow.slice(0, 10);
  const baselineMeta = JSON.parse(readFileSync(baselinePath, "utf-8"));
  const currentMeta = JSON.parse(readFileSync(currentPath, "utf-8"));

  const report: DiffReport = {
    generated: stampNow,
    baseline: { path: baselinePath, date: isoDate(baselineMeta, "unknown"), entries: baseline.length },
    current: { path: currentPath, date: isoDate(currentMeta, today), entries: current.length },
    confirmedOnly,
    summary: { added: added.length, removed: removed.length, changed: changed.length, campaigns: campaigns.length },
    campaigns,
    added,
    removed,
    changed,
  };

  if (!existsSync(outDir)) mkdirSync(outDir, { recursive: true });
  const jsonPath = join(outDir, `diff-${today}.json`);
  writeFileSync(jsonPath, JSON.stringify(report, null, 2));

  const md = renderMarkdown(report);
  const mdPath = join(outDir, `diff-${today}.md`);
  writeFileSync(mdPath, md);

  // Machine-readable summary line for CI to gate the PR step on.
  console.log(
    `::wild-scan-diff::${JSON.stringify({ added: added.length, removed: removed.length, changed: changed.length, campaigns: campaigns.length, json: jsonPath, md: mdPath })}`,
  );
  console.log(md);
}

function renderMarkdown(r: DiffReport): string {
  const lines: string[] = [];
  lines.push(`# Wild-scan diff — ${r.current.date}`);
  lines.push("");
  lines.push(
    `Baseline ${r.baseline.date} (${r.baseline.entries}) vs current ${r.current.date} (${r.current.entries})${r.confirmedOnly ? " — confirmed-malware only" : ""}.`,
  );
  lines.push("");
  lines.push(
    `New ${r.summary.added} · gone ${r.summary.removed} · changed ${r.summary.changed} · across ${r.summary.campaigns} campaign(s).`,
  );
  lines.push("");
  if (r.campaigns.length) {
    lines.push("## Campaigns (clustered by threat actor — one signal per actor)");
    lines.push("");
    for (const c of r.campaigns) {
      const src = Object.entries(c.sources).map(([k, v]) => `${k} ${v}`).join(", ");
      lines.push(
        `- ${c.threat_actor}: ${c.newCount} new${c.changedCount ? `, ${c.changedCount} changed` : ""}${src ? ` (${src})` : ""}`,
      );
      if (c.sampleSkills.length) lines.push(`  e.g. ${c.sampleSkills.join(", ")}`);
    }
    lines.push("");
  }
  if (!r.summary.added && !r.summary.removed && !r.summary.changed) {
    lines.push("No change since baseline.");
  }
  lines.push("");
  lines.push(
    "_Review artifact. New attributions are accusations against named authors — confirm before publishing to the blacklist._",
  );
  return lines.join("\n");
}

main();
