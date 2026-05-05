import { readFileSync } from "node:fs";
import { join } from "node:path";
import { loadAllRules } from "./rules";

const DATA_DIR = join(process.cwd(), "..", "data");

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
    threat_actors: Array<{ name: string; skills: number; malicious_rate: number }>;
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
}

export interface EcosystemIntegration {
  name: string;
  type: "merged" | "open" | "using";
  detail: string;
  url?: string;
  logo?: string; // path to logo in public/ecosystem/ or external URL
}

function isSafeUrl(url: string | undefined): boolean {
  if (!url) return true;
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}

export function loadSiteStats(): SiteStats {
  const clawhub = readJson<ClawHubStats>(join(DATA_DIR, "clawhub-scan", "ecosystem-stats.json"));
  const mega = readJson<MegaScanReport>(join(DATA_DIR, "mega-scan-report.json"));
  const pint = readJson<PintReport>(join(DATA_DIR, "pint-benchmark", "pint-eval-report.json"));
  const eval_ = readJson<EvalReport>(join(DATA_DIR, "eval-report.json"));
  const skillScan = readJson<SkillScanReport>(join(DATA_DIR, "skill-scan-report-full.json"));
  const skillBench = readJson<SkillBenchmarkReport>(join(DATA_DIR, "skill-benchmark", "benchmark-report.json"));

  const rules = loadAllRules();

  const categories = new Set(rules.map((r: { category: string }) => r.category));

  // Count unique CVEs across all rules
  const cves = new Set<string>();
  for (const rule of rules) {
    const ruleCves = (rule as { cves?: string[] }).cves ?? [];
    for (const cve of ruleCves) {
      if (cve.startsWith("CVE-")) cves.add(cve);
    }
  }

  return {
    ruleCount: rules.length,
    categoryCount: categories.size,

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
    pintPrecision: Math.round((pint?.report?.overall?.precision ?? 0.9964) * 1000) / 10, // 99.6%
    pintRecall: Math.round((pint?.report?.overall?.recall ?? 0.6142) * 1000) / 10, // 61.4%
    pintF1: Math.round((pint?.report?.overall?.f1 ?? 0.7599) * 1000) / 10, // 76.0%

    selfTestSamples: eval_?.report?.corpusSize ?? 341,
    selfTestPrecision: Math.round((eval_?.report?.overall?.precision ?? 0.997) * 1000) / 10,
    selfTestRecall: Math.round((eval_?.report?.overall?.recall ?? 0.994) * 1000) / 10,

    skillsScanned: skillScan?.scan_metadata?.total_skills_scanned ?? 3115,
    skillPublishers: skillScan?.scan_metadata?.total_publishers ?? 104,
    skillFlagged: skillScan?.summary?.flagged ?? 26,
    skillAvgLatency: skillScan?.scan_metadata?.avg_latency_ms ?? 5.39,

    skillBenchSamples: skillBench?.corpus_size ?? 498,
    skillBenchRecall: Math.round((skillBench?.overall_recall ?? 1.0) * 1000) / 10,
    skillBenchPrecision: Math.round((skillBench?.overall_precision ?? 0.97) * 1000) / 10,
    skillBenchF1: Math.round((skillBench?.overall_f1 ?? 0.984) * 1000) / 10,
    skillBenchFpRate: Math.round((skillBench?.fp_rate ?? 0) * 1000) / 10,
    skillBenchLatency: Math.round((skillBench?.avg_latency_ms ?? 3.52) * 10) / 10,

    cveCount: cves.size || 16,

    ecosystemIntegrations: [
      {
        name: "Cisco AI Defense",
        type: "merged",
        detail: "PR #79 + #99 merged. Full 314-rule pack in skill-scanner production. Upstream maintained.",
        url: "https://github.com/cisco-ai-defense/skill-scanner/pull/99",
      },
      {
        name: "Awesome LM-SSP",
        type: "merged",
        detail: "PR #108 merged into LLM safety/security list.",
        url: "https://github.com/ThuCCSLab/Awesome-LM-SSP/pull/108",
        logo: "https://github.com/CryptoAILab.png?size=128",
      },
      {
        name: "Agentic AI Top 10 Vulnerability",
        type: "merged",
        detail: "PR #14 merged. ATR detection mapping for 12 vulnerability categories.",
        url: "https://github.com/precize/Agentic-AI-Top10-Vulnerability/pull/14",
        logo: "https://github.com/precize.png?size=128",
      },
      {
        name: "OWASP LLM Top 10",
        type: "open",
        detail: "PR #814 submitted. Detection mapping for ASI01-ASI10.",
        url: "https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/pull/814",
      },
      {
        name: "SAFE-MCP",
        type: "open",
        detail: "PR #187 to safe-agentic-framework/safe-mcp. Coverage mapping submitted.",
        url: "https://github.com/safe-agentic-framework/safe-mcp/pull/187",
      },
      {
        name: "Awesome LLM Security",
        type: "open",
        detail: "PR #117 submitted to curated security tools list.",
        url: "https://github.com/corca-ai/awesome-llm-security/pull/117",
      },
      // removed 2026-04-18: target repos returned 404
      // - nicobailon/awesome-mcp-security
      // - nicobailon/safe-mcp
      {
        name: "Awesome LLM agent Security",
        type: "merged",
        detail: "PR #6 merged into LLM agent security tools list.",
        url: "https://github.com/wearetyomsmnv/Awesome-LLM-agent-Security/pull/6",
      },
      {
        name: "Awesome Agentic Patterns",
        type: "merged",
        detail: "PR #58 merged. Deterministic Threat Rule Scanning pattern accepted.",
        url: "https://github.com/nibzard/awesome-agentic-patterns/pull/58",
      },
      {
        name: "Microsoft AGT",
        type: "merged",
        detail: "PR #908 + #1277 merged. 287 ATR rules + weekly auto-sync workflow into Agent Governance Toolkit production.",
        url: "https://github.com/microsoft/agent-governance-toolkit/pull/1277",
      },
      {
        name: "NVIDIA Garak",
        type: "open",
        detail: "PR #1676. 314 ATR detectors. Two review rounds passed; final maintainer review in progress.",
        url: "https://github.com/NVIDIA/garak/pull/1676",
      },
      {
        name: "Promptfoo",
        type: "open",
        detail: "PR #8529 submitted. MCP red team example with ATR deterministic defense.",
        url: "https://github.com/promptfoo/promptfoo/pull/8529",
      },
      {
        name: "Cisco MCP Scanner",
        type: "open",
        detail: "PR #151 submitted. ATR regex analyzer with 20 community rules.",
        url: "https://github.com/cisco-ai-defense/mcp-scanner/pull/151",
      },
      {
        name: "Damn Vulnerable MCP Server",
        type: "open",
        detail: "PR #29 submitted. Blue team detection guide for all 10 challenges.",
        url: "https://github.com/harishsg993010/damn-vulnerable-MCP-server/pull/29",
      },
      {
        name: "Meta LlamaFirewall",
        type: "open",
        detail: "Issue #204. RegexScanner expansion with ATR rules.",
        url: "https://github.com/meta-llama/PurpleLlama/issues/204",
      },
      {
        name: "Portkey Gateway",
        type: "open",
        detail: "Issue #1594. ATR guardrail plugin proposal.",
        url: "https://github.com/Portkey-AI/gateway/issues/1594",
      },
      {
        name: "Sage (Gen Digital)",
        type: "open",
        detail: "PR #33. 27 patterns. Maintainer-invited (vaclavbelak, Norton/Avast parent security team).",
        url: "https://github.com/gendigitalinc/sage/pull/33",
      },
      {
        name: "IBM mcp-context-forge",
        type: "open",
        detail: "PR #4109. ATR threat detection plugin for IBM MCP runtime. 18 tests, follows secrets_detection template.",
        url: "https://github.com/IBM/mcp-context-forge/pull/4109",
      },
      {
        name: "PanGuard Migrator (community)",
        type: "using",
        detail: "@panguard-ai/migrator-community v0.1.0 on npm (MIT). Sigma / YARA → ATR YAML converter — open-core complement to ATR ruleset.",
        url: "https://www.npmjs.com/package/@panguard-ai/migrator-community",
      },
      {
        name: "Awesome AI Security",
        type: "merged",
        detail: "Merged into Agentic Systems section.",
        url: "https://github.com/TalEliyahu/Awesome-AI-Security/pull/53",
      },
      {
        name: "Awesome Cybersecurity Agentic AI",
        type: "open",
        detail: "PR #24 submitted to Tools section.",
        url: "https://github.com/raphabot/awesome-cybersecurity-agentic-ai/pull/24",
      },
      {
        name: "Awesome AI Agents Security",
        type: "open",
        detail: "PR #17 submitted to Static Analysis & Linters.",
        url: "https://github.com/ProjectRecon/awesome-ai-agents-security/pull/17",
      },
      {
        name: "Awesome AI Security (ottosulin)",
        type: "open",
        detail: "PR #192 submitted to MCP Security section.",
        url: "https://github.com/ottosulin/awesome-ai-security/pull/192",
      },
    ],

    owaspAgentic: "10/10",
    safeMcp: "78/85 (91.8%)",
    owaspAst10: "7/10",
  };
}
