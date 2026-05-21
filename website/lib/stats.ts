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

  const rules = loadAllRules();

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
    pintPrecision:
      Math.round((pint?.report?.overall?.precision ?? 0.9964) * 1000) / 10, // 99.6%
    pintRecall:
      Math.round((pint?.report?.overall?.recall ?? 0.6386) * 1000) / 10, // 63.9%
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

    ecosystemIntegrations: [
      // === Tier-1 standards bodies (merged by external maintainer) ===
      {
        name: "MISP Taxonomies",
        type: "merged",
        detail:
          "PR #323 merged 2026-05-10 by adulau (MISP project lead). 10 ATR predicates + 330 rule IDs as MISP machine tags. CIRCL adoption.",
        url: "https://github.com/MISP/misp-taxonomies/pull/323",
        logo: "https://github.com/MISP.png?size=128",
      },
      {
        name: "MISP Galaxy",
        type: "merged",
        detail:
          "PR #1207 merged 2026-05-10 by adulau. 336 cluster values with kill-chain, severity, CVE / OWASP LLM / MITRE ATLAS cross-refs. 10,408 lines.",
        url: "https://github.com/MISP/misp-galaxy/pull/1207",
        logo: "https://github.com/MISP.png?size=128",
      },
      {
        name: "Gen Digital Sage",
        type: "merged",
        detail:
          "PR #33 merged 2026-05-11 by vaclavbelak (Norton / Avast / AVG parent security team). 7 privilege-escalation rules + ATR upstream bridge.",
        url: "https://github.com/gendigitalinc/sage/pull/33",
        logo: "https://github.com/gendigitalinc.png?size=128",
      },
      {
        name: "Microsoft Agent Governance Toolkit",
        type: "merged",
        detail:
          "PR #908 + #1277 merged. Weekly auto-sync workflow runs against ATR main. AGT #1981 (Copilot SWE Agent) generated regression fixtures presuming ATR coverage — closed loop 2026-05-11 in 2h 16m.",
        url: "https://github.com/microsoft/agent-governance-toolkit/pull/1277",
        logo: "https://github.com/microsoft.png?size=128",
      },
      {
        name: "Cisco AI Defense",
        type: "merged",
        detail:
          "PR #79 + #99 merged. Full 314-rule pack in skill-scanner production. Upstream maintained.",
        url: "https://github.com/cisco-ai-defense/skill-scanner/pull/99",
        logo: "https://github.com/cisco-ai-defense.png?size=128",
      },
      // === Curated awesome-list merges ===
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
        detail:
          "PR #14 merged. ATR detection mapping for 12 vulnerability categories.",
        url: "https://github.com/precize/Agentic-AI-Top10-Vulnerability/pull/14",
        logo: "https://github.com/precize.png?size=128",
      },
      {
        name: "Awesome LLM agent Security",
        type: "merged",
        detail: "PR #6 merged into LLM agent security tools list.",
        url: "https://github.com/wearetyomsmnv/Awesome-LLM-agent-Security/pull/6",
      },
      {
        name: "Awesome Agentic Patterns",
        type: "merged",
        detail:
          "PR #58 merged. Deterministic Threat Rule Scanning pattern accepted.",
        url: "https://github.com/nibzard/awesome-agentic-patterns/pull/58",
      },
      {
        name: "Awesome AI Security",
        type: "merged",
        detail: "Merged into Agentic Systems section.",
        url: "https://github.com/TalEliyahu/Awesome-AI-Security/pull/53",
      },
      // === Open PRs / draft conversations (standards + frameworks) ===
      {
        name: "FINOS Common Cloud Controls",
        type: "open",
        detail:
          "PR #986 draft open. ATR guideline-mappings for CN01/CN02/CN04/CN06 + Gemara MappingReference. CI green, CLA signed. Linux Foundation project.",
        url: "https://github.com/finos/common-cloud-controls/pull/986",
        logo: "https://github.com/finos.png?size=128",
      },
      {
        name: "NIST OSCAL",
        type: "open",
        detail:
          "PR #2234 conversation. iMichaela invited Path 1 community contribution; Adam reply 2026-05-11 with 4 technical questions, awaiting NIST reviewer.",
        url: "https://github.com/usnistgov/OSCAL/pull/2234",
        logo: "https://github.com/usnistgov.png?size=128",
      },
      {
        name: "rulezet (CIRCL)",
        type: "open",
        detail:
          "Issue #49 + PR #50 draft. atr_format.py converter mirroring sigma_format with 24 unit tests. CIRCL maintainer Théo GEFFE.",
        url: "https://github.com/rulezet/rulezet-core/pull/50",
      },
      {
        name: "OWASP LLM Top 10",
        type: "open",
        detail:
          "PR #814 open. Detection mapping for ASI01-ASI10; engaged by reviewer desiorac with substantive feedback rounds.",
        url: "https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/pull/814",
        logo: "https://github.com/OWASP.png?size=128",
      },
      {
        name: "SAFE-MCP",
        type: "open",
        detail:
          "Issue #207 open at safe-agentic-framework/safe-mcp. Structured proposal for a detections/ registry to support cross-project rule-ID linkage.",
        url: "https://github.com/safe-agentic-framework/safe-mcp/issues/207",
      },
      {
        name: "Awesome LLM Security",
        type: "open",
        detail: "PR #117 submitted to curated security tools list.",
        url: "https://github.com/corca-ai/awesome-llm-security/pull/117",
      },
      // === Red team tooling (open) ===
      {
        name: "NVIDIA Garak",
        type: "open",
        detail:
          "PR #1676. 330 ATR detectors. Two review rounds passed; final maintainer review in progress.",
        url: "https://github.com/NVIDIA/garak/pull/1676",
        logo: "https://github.com/NVIDIA.png?size=128",
      },
      {
        name: "Microsoft PyRIT",
        type: "open",
        detail:
          "PR #1715 draft. ATR dataset loader for PyRIT red-team orchestrators. Roman Lutz reviewed in 2 min; iterating on doc shape.",
        url: "https://github.com/microsoft/PyRIT/pull/1715",
        logo: "https://github.com/microsoft.png?size=128",
      },
      {
        name: "NVIDIA NeMo Guardrails",
        type: "open",
        detail:
          "PR #1869 open. ATR-inspired threat detection example library config; coderabbitai automated review clean.",
        url: "https://github.com/NVIDIA-NeMo/Guardrails/pull/1869",
        logo: "https://github.com/NVIDIA.png?size=128",
      },
      {
        name: "Protect AI llm-guard",
        type: "open",
        detail:
          "Issue #340. ATRScanner input/output scanner proposal following existing scanner pattern.",
        url: "https://github.com/protectai/llm-guard/issues/340",
      },
      {
        name: "PromptInject (NeurIPS 2022)",
        type: "open",
        detail:
          "Issue #9. Attack-source integration — turn PromptInject's adversarial corpus into ATR detection coverage.",
        url: "https://github.com/agencyenterprise/PromptInject/issues/9",
      },
      {
        name: "Promptfoo",
        type: "open",
        detail:
          "PR #8529 submitted. MCP red team example with ATR deterministic defense.",
        url: "https://github.com/promptfoo/promptfoo/pull/8529",
      },
      {
        name: "Cisco MCP Scanner",
        type: "open",
        detail:
          "PR #151 submitted. ATR regex analyzer with 20 community rules.",
        url: "https://github.com/cisco-ai-defense/mcp-scanner/pull/151",
      },
      {
        name: "Damn Vulnerable MCP Server",
        type: "open",
        detail:
          "PR #29 submitted. Blue team detection guide for all 10 challenges.",
        url: "https://github.com/harishsg993010/damn-vulnerable-MCP-server/pull/29",
      },
      {
        name: "Meta PurpleLlama",
        type: "open",
        detail:
          "PR #206 open. RegexScanner expansion with 20 ATR-derived agent threat patterns. Multi-round maintainer follow-up; awaiting Meta internal CI gate.",
        url: "https://github.com/meta-llama/PurpleLlama/pull/206",
      },
      {
        name: "Portkey Gateway",
        type: "open",
        detail: "PR #1652 open. ATR (Agent Threat Rules) detection plugin.",
        url: "https://github.com/Portkey-AI/gateway/pull/1652",
      },
      {
        name: "IBM mcp-context-forge",
        type: "open",
        detail:
          "PR #4109. ATR threat detection plugin for IBM MCP runtime. 18 tests, follows secrets_detection template.",
        url: "https://github.com/IBM/mcp-context-forge/pull/4109",
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
        type: "merged",
        detail: "PR #192 merged 2026-05-18 into MCP Security section.",
        url: "https://github.com/ottosulin/awesome-ai-security/pull/192",
      },
    ],

    owaspAgentic: "10/10",
    safeMcp: "78/85 (91.8%)",
    owaspAst10: "7/10",
  };
}
