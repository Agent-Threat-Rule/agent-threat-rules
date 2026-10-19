import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { loadAllRules } from "./rules";
import { loadAdopters, adopterLogoUrl, type Adopter, type AdopterTier } from "./adopters";

const DATA_DIR = join(process.cwd(), "..", "data");
const MEASUREMENTS_DIR = join(DATA_DIR, "measurements");

function readJson<T>(path: string): T | null {
  try {
    return JSON.parse(readFileSync(path, "utf-8")) as T;
  } catch {
    return null;
  }
}

// --- ClawHub Scan ---
interface ClawHubStats {
  scanDate: string;
  atrRules: number;
  totalCrawled: number;
  totalScanned: number;
  summary: { CRITICAL: number; HIGH: number; MEDIUM: number; LOW: number };
  flaggedCount: number;
}

// --- Mega Scan (per-registry crawl counts for the wild scan) ---
// NOTE: this report's `totals` and `malware_campaign` are NOT citable. Its
// totals describe the analysed subset of the wild scan, and its
// confirmed_malware count is publisher-level attribution applied account-wide,
// not per-file adjudication. Only the per-registry crawl counts are read from
// here; the citable headline figures come from WildScanReport below.
interface MegaScanReport {
  scan_date: string;
  engine_version?: string;
  rules_loaded?: number;
  sources: Record<string, number>;
  totals: { scanned: number; flagged: number; flagged_rate?: string };
  severity: { critical: number; high: number; medium: number };
}

// --- Wild Scan (the citable artifact) ---
// data/full-scan-v2-2026-04-14.json is the only wild-scan artifact this repo
// owns that preserved paths and rule ids. Per the standing freeze on wild-scan
// figures, ONLY `total_scanned` / `total_flagged` / `engine.version` from this
// file are citable externally. Confirmed-malware counts derived from it are
// publisher attribution, not per-file analysis, and are not published here.
// See docs/research/wild-scan-drift.md.
interface WildScanReport {
  timestamp: string;
  engine: { version: string; rules: number };
  total_scanned: number;
  total_flagged: number;
  severity: { critical: number; high: number; medium: number };
}

// --- Skill Scan ---
interface SkillScanReport {
  scan_metadata: {
    total_skills_scanned: number;
    total_publishers: number;
    avg_latency_ms: number;
  };
  summary: {
    flagged: number;
    flagged_rate: string;
    severity_breakdown: { critical: number; high: number; medium: number };
  };
}

export interface SiteStats {
  // Rules
  ruleCount: number;
  categoryCount: number;

  // Standard heartbeat — YYYY-MM-DD the canonical stats.json was last
  // regenerated. Drives the "living standard" cadence signal on the home
  // page; empty string if stats.json is absent or lacks a timestamp.
  lastRegenerated: string;

  // ClawHub scan
  clawHubCrawled: number;
  clawHubScanned: number;
  clawHubCritical: number;
  clawHubHigh: number;
  clawHubScanDate: string;

  // Mega scan (latest, larger)
  megaScanTotal: number;
  megaScanFlagged: number;
  megaScanCritical: number;
  megaScanHigh: number;
  megaScanSources: { openclaw: number; skillsSh: number };
  megaScanDate: string;

  // Skill scan
  skillsScanned: number;
  skillPublishers: number;
  skillFlagged: number;
  skillAvgLatency: number;

  // CVEs
  cveCount: number;

  // Ecosystem integrations
  ecosystemIntegrations: EcosystemIntegration[];

  // Coverage
  owaspAgentic: string;
  safeMcp: string;
  owaspAst10: string;

  // Version-pinned benchmark measurements: the only source for a recall,
  // precision or false-positive figure on this site. Read from the file each
  // data/measurements/<source>/latest.json points at; lib/recall.ts formats
  // them with their lane. Empty array if no measurements present yet.
  benchmarks: BenchmarkMeasurement[];
}

export interface EcosystemIntegration {
  name: string;
  type: "merged" | "open" | "using";
  detail: string;
  url?: string;
  logo?: string; // path to logo in public/ecosystem/ or external URL
  /** ADOPTERS.md tier the entry came from (S/1/2/3/4). */
  tier: AdopterTier;
}

/**
 * `breakdown.enforce_lane` of a measurement: the same attack samples through the
 * same detection loop, on an engine that loads only `maturity: stable` rules
 * (the lane to run with blocking on). It counts detections, so it is an upper
 * bound on what blocking stops.
 */
export interface EnforceLaneFigure {
  recall: number;
  detected: number;
  attacks: number;
  rulesInLane: number;
}

/**
 * One benchmark measurement, version-pinned and reproducible: the file
 * data/measurements/<source>/latest.json points at. The full historical series
 * lives alongside as data/measurements/<source>/<date>_*.json.
 *
 * `recall`, `precision`, `f1`, `fp_rate` and the counts are the hunt lane (the
 * engine default, every rule maturity); `enforce` is the enforce lane. Never
 * show `recall` without `enforce` where the measurement records it.
 */
export interface BenchmarkMeasurement {
  /** Stable lowercase source identifier (e.g. "garak", "pint"). */
  source: string;
  /** Upstream version pinned at measurement time. */
  source_version: string;
  /** ATR version under test. */
  atr_version: string;
  /** ISO 8601 timestamp the measurement was taken. */
  measured_at: string;
  /** YYYY-MM-DD slice for display. */
  measured_date: string;
  /** Corpus size in samples. */
  samples: number;
  /** Recall as a fraction in [0,1]. */
  recall: number;
  /** Precision as a fraction in [0,1]. */
  precision: number;
  /** F1 as a fraction in [0,1]. */
  f1: number;
  /** False-positive rate as a fraction in [0,1]. */
  fp_rate: number;
  /** Attack samples detected (confusion.tp); null when the file records no confusion matrix. */
  detected: number | null;
  /** Attack samples evaluated (confusion.tp + confusion.fn). */
  attacks: number | null;
  /** Benign samples (confusion.tn + confusion.fp) and the false positives among them. */
  benign: number | null;
  falsePositives: number | null;
  /** The enforce lane; null when the measurement predates that record. */
  enforce: EnforceLaneFigure | null;
  /** breakdown.layers (the SKILL.md benchmark's attack layers), hunt lane. */
  layers: Record<string, { total: number; detected: number }> | null;
  /** Repo-relative path of the immutable measurement file. */
  measurement_file: string;
}

/** The slice of a measurement file the site reads (src/measurement/schema.ts). */
interface MeasurementFile {
  source: string;
  source_version: string;
  atr_version: string;
  measured_at: string;
  samples: number;
  metrics: { recall: number; precision: number; f1: number; fp_rate: number };
  confusion?: { tp: number; fp: number; tn: number; fn: number };
  breakdown?: { enforce_lane?: unknown; layers?: unknown };
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);
const isCount = (v: unknown): v is number => typeof v === "number" && Number.isInteger(v) && v >= 0;

/**
 * `breakdown.enforce_lane`, or null when the measurement predates it. A record
 * that is present but malformed throws: showing the hunt figure alone would
 * drop exactly the number the record exists to put beside it.
 */
function enforceLaneOf(raw: unknown): EnforceLaneFigure | null {
  if (raw === undefined) return null;
  if (!isRecord(raw) || raw.lane !== "enforce" || !isCount(raw.detected) || !isCount(raw.attacks)
    || raw.attacks === 0 || !isCount(raw.rules_in_lane) || typeof raw.recall !== "number") {
    throw new Error("breakdown.enforce_lane is malformed");
  }
  return { recall: raw.recall, detected: raw.detected, attacks: raw.attacks, rulesInLane: raw.rules_in_lane };
}

function layersOf(raw: unknown): BenchmarkMeasurement["layers"] {
  if (!isRecord(raw)) return null;
  const entries = Object.entries(raw).flatMap(([k, v]) =>
    isRecord(v) && isCount(v.total) && isCount(v.detected) ? [[k, { total: v.total, detected: v.detected }] as const] : [],
  );
  return Object.fromEntries(entries);
}

/**
 * Read the measurement file `latest.json` names. Every figure comes from that
 * file, the same one README's table and the citation checks read.
 */
function readMeasurement(entry: string, dir: string): BenchmarkMeasurement {
  const pointer = JSON.parse(readFileSync(join(dir, "latest.json"), "utf-8")) as { file?: unknown };
  if (typeof pointer.file !== "string" || pointer.file.includes("/") || pointer.file.includes("\\")) {
    throw new Error("latest.json does not name a file in its own directory");
  }
  const m = JSON.parse(readFileSync(join(dir, pointer.file), "utf-8")) as MeasurementFile;
  const c = m.confusion;
  return {
    source: m.source,
    source_version: m.source_version,
    atr_version: m.atr_version,
    measured_at: m.measured_at,
    measured_date: m.measured_at.slice(0, 10),
    samples: m.samples,
    recall: m.metrics.recall,
    precision: m.metrics.precision,
    f1: m.metrics.f1,
    fp_rate: m.metrics.fp_rate,
    detected: c ? c.tp : null,
    attacks: c ? c.tp + c.fn : null,
    benign: c ? c.tn + c.fp : null,
    falsePositives: c ? c.fp : null,
    enforce: enforceLaneOf(m.breakdown?.enforce_lane),
    layers: layersOf(m.breakdown?.layers),
    measurement_file: `data/measurements/${entry}/${pointer.file}`,
  };
}

/**
 * Load every source's current measurement. Returns an empty array if the
 * directory is absent. A source whose files fail to read is skipped with a
 * warning (not thrown, so one bad source does not break the build), and every
 * page that cites it then shows no figure for it rather than a stale one.
 */
function loadBenchmarkMeasurements(): BenchmarkMeasurement[] {
  if (!existsSync(MEASUREMENTS_DIR)) return [];
  const out: BenchmarkMeasurement[] = [];
  for (const entry of readdirSync(MEASUREMENTS_DIR)) {
    const dir = join(MEASUREMENTS_DIR, entry);
    if (!statSync(dir).isDirectory() || !existsSync(join(dir, "latest.json"))) continue;
    try {
      out.push(readMeasurement(entry, dir));
    } catch (err) {
      console.warn(`benchmark measurement ${entry} could not be read:`, err);
    }
  }
  return out.sort((a, b) => a.source.localeCompare(b.source));
}

function isSafeUrl(url: string | undefined): boolean {
  if (!url) return true;
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Ecosystem integrations derived from ADOPTERS.md — the single source of
 * truth for adoption (see lib/adopters.ts header). Tier order preserved
 * (S -> 1 -> 2 -> 3 -> 4); "planning" entries are excluded because they
 * carry no verifiable evidence yet. Status maps shipped -> "merged",
 * in-review -> "open", matching the display vocabulary the pages use.
 */
function ecosystemFromAdopters(): EcosystemIntegration[] {
  const adopters = loadAdopters();
  const ordered: Adopter[] = [
    ...adopters.tierS,
    ...adopters.tier1,
    ...adopters.tier2,
    ...adopters.tier3,
    ...adopters.tier4,
  ];
  return ordered
    .filter((a) => a.status === "shipped" || a.status === "in-review")
    .map((a) => ({
      name: a.name,
      type: a.status === "shipped" ? ("merged" as const) : ("open" as const),
      detail: a.org,
      url: isSafeUrl(a.evidence) ? a.evidence : undefined,
      logo: adopterLogoUrl(a),
      tier: a.tier,
    }));
}

export function loadSiteStats(): SiteStats {
  const clawhub = readJson<ClawHubStats>(
    join(DATA_DIR, "clawhub-scan", "ecosystem-stats.json"),
  );
  const mega = readJson<MegaScanReport>(
    join(DATA_DIR, "mega-scan-report.json"),
  );
  const wild = readJson<WildScanReport>(
    join(DATA_DIR, "full-scan-v2-2026-04-14.json"),
  );
  const skillScan = readJson<SkillScanReport>(
    join(DATA_DIR, "skill-scan-report-full.json"),
  );
  const statsJson = readJson<{ generatedAt?: string }>(
    join(DATA_DIR, "stats.json"),
  );
  // Root stats.json is rewritten by CI on every rules-merge release, so its
  // lastUpdated is the freshest honest "standard heartbeat". data/stats.json
  // generatedAt only moves when the measurement pipeline reruns — keep it as
  // the fallback.
  const rootStatsJson = readJson<{ lastUpdated?: string }>(
    join(process.cwd(), "..", "stats.json"),
  );

  const rules = loadAllRules();

  // The engine skips status: draft | deprecated before the lane gate, so those
  // rules fire in no lane at all; the raw file count overstates what runs. Cite
  // the effective count on user-facing surfaces (same rule as sync-stats.ts).
  const effectiveRuleCount = rules.filter(
    (r: { status?: string }) =>
      r.status !== "draft" && r.status !== "deprecated",
  ).length;

  const categories = new Set(
    rules.map((r: { category: string }) => r.category),
  );

  // Count unique CVEs across all rules
  const cves = new Set<string>();
  for (const rule of rules) {
    const ruleCves = (rule as { cves?: string[] }).cves ?? [];
    for (const cve of ruleCves) {
      if (cve.startsWith("CVE-")) cves.add(cve);
    }
  }

  return {
    ruleCount: effectiveRuleCount,
    categoryCount: categories.size,
    lastRegenerated:
      rootStatsJson?.lastUpdated ?? statsJson?.generatedAt?.slice(0, 10) ?? "",

    clawHubCrawled: clawhub?.totalCrawled ?? 36394,
    clawHubScanned: clawhub?.totalScanned ?? 9676,
    clawHubCritical: clawhub?.summary?.CRITICAL ?? 182,
    clawHubHigh: clawhub?.summary?.HIGH ?? 1124,
    clawHubScanDate: clawhub?.scanDate ?? "2026-03-26",

    // Frozen artifact — these four come from full-scan-v2-2026-04-14.json,
    // the only wild-scan figures cleared for external citation
    // (101,280 scanned / 1,434 flagged, engine v2.0.0, as of 2026-04-13).
    megaScanTotal: wild?.total_scanned ?? 101280,
    megaScanFlagged: wild?.total_flagged ?? 1434,
    megaScanCritical: wild?.severity?.critical ?? 1210,
    megaScanHigh: wild?.severity?.high ?? 282,
    megaScanSources: {
      openclaw: mega?.sources?.openclaw ?? 56480,
      skillsSh: mega?.sources?.skills_sh ?? 3115,
    },
    megaScanDate: wild?.timestamp?.slice(0, 10) ?? "2026-04-13",

    // PINT-format, self-test and SKILL.md figures used to be read here from
    // the eval report files, with hand-written fallbacks (among them a
    // self-test recall of 99.4% that no measurement file records) and no lane.
    // They now come only from `benchmarks`, with the lane; see lib/recall.ts.

    skillsScanned: skillScan?.scan_metadata?.total_skills_scanned ?? 3115,
    skillPublishers: skillScan?.scan_metadata?.total_publishers ?? 104,
    skillFlagged: skillScan?.summary?.flagged ?? 26,
    skillAvgLatency: skillScan?.scan_metadata?.avg_latency_ms ?? 5.39,

    cveCount: cves.size || 16,

    ecosystemIntegrations: ecosystemFromAdopters(),

    owaspAgentic: "10/10",
    safeMcp: "55/78",
    owaspAst10: "7/10",

    benchmarks: loadBenchmarkMeasurements(),
  };
}
