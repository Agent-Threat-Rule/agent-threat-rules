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

// --- Mega Scan (96K ecosystem scan across 6 registries) ---
interface MegaScanReport {
  scan_date: string;
  engine_version?: string;
  rules_loaded?: number;
  sources: Record<string, number>;
  totals: { scanned: number; flagged: number; flagged_rate?: string };
  severity: { critical: number; high: number; medium: number };
  malware_campaign?: {
    confirmed_malware: number;
    threat_actors: Array<{
      name: string;
      skills: number;
      malicious_rate: number;
    }>;
  };
}

// --- PINT Benchmark ---
interface PintReport {
  report: {
    corpusSize: number;
    overall: {
      precision: number;
      recall: number;
      f1: number;
      confusion: { tp: number; fp: number; tn: number; fn: number };
    };
  };
}

// --- Self-Test Eval ---
interface EvalReport {
  report: {
    corpusSize: number;
    overall: {
      precision: number;
      recall: number;
      f1: number;
    };
  };
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

// --- Skill Benchmark ---
interface SkillBenchmarkReport {
  corpus_size: number;
  malicious_count: number;
  benign_count: number;
  overall_recall: number;
  overall_precision: number;
  overall_f1: number;
  fp_rate: number;
  avg_latency_ms: number;
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

  // PINT benchmark
  pintSamples: number;
  pintPrecision: number;
  pintRecall: number;
  pintF1: number;

  // Self-test
  selfTestSamples: number;
  selfTestPrecision: number;
  selfTestRecall: number;

  // Skill scan
  skillsScanned: number;
  skillPublishers: number;
  skillFlagged: number;
  skillAvgLatency: number;

  // Skill benchmark
  skillBenchSamples: number;
  skillBenchRecall: number;
  skillBenchPrecision: number;
  skillBenchF1: number;
  skillBenchFpRate: number;
  skillBenchLatency: number;

  // CVEs
  cveCount: number;

  // Ecosystem integrations
  ecosystemIntegrations: EcosystemIntegration[];

  // Coverage
  owaspAgentic: string;
  safeMcp: string;
  owaspAst10: string;

  // Version-pinned benchmark measurements (canonical source for any
  // public-facing recall claim). Reads from data/measurements/<source>/latest.json.
  // Empty array if no measurements present yet.
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
 * One benchmark measurement, version-pinned and reproducible.
 * Loaded from data/measurements/<source>/latest.json. The full historical
 * series lives alongside as data/measurements/<source>/<date>_*.json.
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
  /** Repo-relative path of the immutable measurement file. */
  measurement_file: string;
}

/**
 * Load every latest measurement from data/measurements/<source>/latest.json.
 * Returns an empty array if the directory is absent. Skips sources whose
 * latest.json fails to parse (logs to console — not thrown — so a bad source
 * does not break site rendering).
 */
function loadBenchmarkMeasurements(): BenchmarkMeasurement[] {
  if (!existsSync(MEASUREMENTS_DIR)) return [];
  const out: BenchmarkMeasurement[] = [];
  for (const entry of readdirSync(MEASUREMENTS_DIR)) {
    const dir = join(MEASUREMENTS_DIR, entry);
    if (!statSync(dir).isDirectory()) continue;
    const latest = join(dir, "latest.json");
    if (!existsSync(latest)) continue;
    try {
      const raw = JSON.parse(readFileSync(latest, "utf-8")) as {
        source: string;
        source_version: string;
        atr_version: string;
        measured_at: string;
        samples: number;
        file: string;
        metrics: { recall: number; precision: number; f1: number; fp_rate: number };
      };
      out.push({
        source: raw.source,
        source_version: raw.source_version,
        atr_version: raw.atr_version,
        measured_at: raw.measured_at,
        measured_date: raw.measured_at.slice(0, 10),
        samples: raw.samples,
        recall: raw.metrics.recall,
        precision: raw.metrics.precision,
        f1: raw.metrics.f1,
        fp_rate: raw.metrics.fp_rate,
        measurement_file: `data/measurements/${entry}/${raw.file}`,
      });
    } catch (err) {
      console.warn(`benchmark measurement ${entry}/latest.json failed to parse:`, err);
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
  const pint = readJson<PintReport>(
    join(DATA_DIR, "pint-benchmark", "pint-eval-report.json"),
  );
  const eval_ = readJson<EvalReport>(join(DATA_DIR, "eval-report.json"));
  const skillScan = readJson<SkillScanReport>(
    join(DATA_DIR, "skill-scan-report-full.json"),
  );
  const skillBench = readJson<SkillBenchmarkReport>(
    join(DATA_DIR, "skill-benchmark", "benchmark-report.json"),
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

    megaScanTotal: mega?.totals?.scanned ?? 96096,
    megaScanFlagged: mega?.totals?.flagged ?? 1302,
    megaScanCritical: mega?.severity?.critical ?? 989,
    megaScanHigh: mega?.severity?.high ?? 353,
    megaScanSources: {
      openclaw: mega?.sources?.openclaw ?? 56480,
      skillsSh: mega?.sources?.skills_sh ?? 3115,
    },
    megaScanDate: mega?.scan_date ?? "2026-04-14",

    pintSamples: pint?.report?.corpusSize ?? 850,
    pintPrecision:
      Math.round((pint?.report?.overall?.precision ?? 0.9965) * 1000) / 10, // 99.7%
    pintRecall:
      Math.round((pint?.report?.overall?.recall ?? 0.6319) * 1000) / 10, // 63.2%
    pintF1: Math.round((pint?.report?.overall?.f1 ?? 0.7599) * 1000) / 10, // 76.0%

    selfTestSamples: eval_?.report?.corpusSize ?? 341,
    selfTestPrecision:
      Math.round((eval_?.report?.overall?.precision ?? 0.997) * 1000) / 10,
    selfTestRecall:
      Math.round((eval_?.report?.overall?.recall ?? 0.994) * 1000) / 10,

    skillsScanned: skillScan?.scan_metadata?.total_skills_scanned ?? 3115,
    skillPublishers: skillScan?.scan_metadata?.total_publishers ?? 104,
    skillFlagged: skillScan?.summary?.flagged ?? 26,
    skillAvgLatency: skillScan?.scan_metadata?.avg_latency_ms ?? 5.39,

    skillBenchSamples: skillBench?.corpus_size ?? 498,
    skillBenchRecall:
      Math.round((skillBench?.overall_recall ?? 1.0) * 1000) / 10,
    skillBenchPrecision:
      Math.round((skillBench?.overall_precision ?? 0.97) * 1000) / 10,
    skillBenchF1: Math.round((skillBench?.overall_f1 ?? 0.984) * 1000) / 10,
    skillBenchFpRate: Math.round((skillBench?.fp_rate ?? 0) * 1000) / 10,
    skillBenchLatency:
      Math.round((skillBench?.avg_latency_ms ?? 3.52) * 10) / 10,

    cveCount: cves.size || 16,

    ecosystemIntegrations: ecosystemFromAdopters(),

    owaspAgentic: "10/10",
    safeMcp: "78/85 (91.8%)",
    owaspAst10: "7/10",

    benchmarks: loadBenchmarkMeasurements(),
  };
}
