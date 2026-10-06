#!/usr/bin/env npx tsx
/**
 * sync-avid-db.ts
 *
 * Pulls AVID (AI Vulnerability Database) reports from avidml/avid-db and
 * emits ATR rule proposals (proposals/avid/AVID-YYYY-RNNNN.proposal.yaml)
 * for entries we don't already cover.
 *
 * AVID is already 100% AI-scoped, so unlike sync-cisa-kev.ts we don't run
 * an "AI relevance" filter -- every entry in /reports/{year}/ is a report
 * about an AI system or model. We DO filter on:
 *   - problemtype.classof must be in CLASSOF_ALLOW (CVE Entry / Undesirable
 *     Behavior / Issue) -- skip pure Survey / Discussion entries
 *   - impact.avid.sep_view must intersect SEP_INCLUDE (Security / E0100
 *     Discrimination is dropped because it's a fairness issue not a runtime
 *     detection target)
 *
 * Each proposal embeds the AVID report id under references.external so
 * users can verify provenance.
 *
 * Usage:
 *   npx tsx scripts/sync-avid-db.ts                    # dry-run all years
 *   npx tsx scripts/sync-avid-db.ts --year 2026         # one year only
 *   npx tsx scripts/sync-avid-db.ts --year 2026 --limit 25 --write
 *   npx tsx scripts/sync-avid-db.ts --report AVID-2026-R0005 --write
 */

import { readFileSync, writeFileSync, readdirSync, statSync, existsSync, mkdirSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, '..');
const RULES_DIR = resolve(REPO_ROOT, 'rules');
const PROPOSALS_DIR = resolve(REPO_ROOT, 'proposals/avid');

const AVID_OWNER = 'avidml';
const AVID_REPO = 'avid-db';

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag('--write');
const FORCE = flag('--force');
const YEAR = opt('--year');
const LIMIT = parseInt(opt('--limit') ?? '0', 10);
const REPORT = opt('--report');
const VERBOSE = flag('--verbose');

const CLASSOF_ALLOW = new Set(['CVE Entry', 'Undesirable Behavior', 'Issue']);

// AVID's SEP taxonomy: S* = Security, E* = Ethics, P* = Performance.
// For runtime detection rules we keep Security (S*) only by default. Ethics
// problems like discrimination and fairness need a different rule shape
// (statistical fairness checks, not regex detection) so they're skipped.
const SEP_INCLUDE_PREFIX = ['S'];

// --- AVID report shape -----------------------------------------------------

interface AvidReport {
  data_type?: string;
  data_version?: string;
  metadata?: { report_id?: string };
  affects?: {
    developer?: string[];
    deployer?: string[];
    artifacts?: { type?: string; name?: string }[];
  };
  problemtype?: {
    classof?: string;
    type?: string;
    description?: { lang?: string; value?: string };
  };
  references?: { type?: string; label?: string; url?: string }[];
  description?: { lang?: string; value?: string };
  impact?: {
    avid?: {
      risk_domain?: string[];
      sep_view?: string[];
      lifecycle_view?: string[];
      taxonomy_version?: string;
    };
    cvss?: {
      version?: string;
      vectorString?: string;
      baseScore?: number;
      baseSeverity?: string;
    };
    cwe?: { cweId?: string; description?: string }[];
  };
}

// --- existing rule CVE index ----------------------------------------------

function walkYaml(dir: string): string[] {
  const out: string[] = [];
  if (!existsSync(dir)) return out;
  for (const e of readdirSync(dir)) {
    const f = join(dir, e);
    const st = statSync(f);
    if (st.isDirectory()) out.push(...walkYaml(f));
    else if (st.isFile() && e.endsWith('.yaml')) out.push(f);
  }
  return out;
}

function buildCveIndex(): Set<string> {
  const ix = new Set<string>();
  for (const f of walkYaml(RULES_DIR)) {
    let doc: any;
    try {
      doc = yaml.load(readFileSync(f, 'utf-8'));
    } catch {
      continue;
    }
    const cves = doc?.references?.cve;
    if (Array.isArray(cves)) for (const c of cves) ix.add(c);
  }
  return ix;
}

// --- AVID -> ATR mapping helpers ------------------------------------------

function extractCveFromAvid(r: AvidReport): string | null {
  // AVID encodes CVE in problemtype.description.value as e.g. "Vulnerability CVE-2024-0132"
  const v = r.problemtype?.description?.value || '';
  const m = v.match(/\bCVE-\d{4}-\d{4,7}\b/);
  if (m) return m[0];
  // Sometimes encoded in references[].label/url
  for (const ref of r.references || []) {
    const t = `${ref.label ?? ''} ${ref.url ?? ''}`;
    const m2 = t.match(/\bCVE-\d{4}-\d{4,7}\b/);
    if (m2) return m2[0];
  }
  return null;
}

function severityFromCvss(r: AvidReport): string {
  const s = r.impact?.cvss?.baseSeverity?.toLowerCase();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  // No CVSS -- guess from CWE
  const cwes = (r.impact?.cwe ?? []).map((c) => c.cweId).filter((s): s is string => !!s);
  if (cwes.some((c) => ['CWE-78', 'CWE-94', 'CWE-95'].includes(c))) return 'critical';
  if (cwes.some((c) => ['CWE-22', 'CWE-89', 'CWE-918', 'CWE-502'].includes(c))) return 'high';
  return 'medium';
}

function categoryFromAvid(r: AvidReport): string {
  // Use AVID's SEP / Lifecycle hint plus CWE family
  const cwes = (r.impact?.cwe ?? []).map((c) => c.cweId);
  if (cwes.includes('CWE-94') || cwes.includes('CWE-95')) return 'agent-manipulation';
  if (cwes.includes('CWE-78') || cwes.includes('CWE-77')) return 'tool-poisoning';
  if (cwes.includes('CWE-22') || cwes.includes('CWE-918') || cwes.includes('CWE-200'))
    return 'context-exfiltration';
  if (cwes.includes('CWE-269') || cwes.includes('CWE-287') || cwes.includes('CWE-863'))
    return 'privilege-escalation';
  if (cwes.includes('CWE-502') || cwes.includes('CWE-89')) return 'data-poisoning';
  if (cwes.includes('CWE-79')) return 'prompt-injection';
  // Fall back to AVID risk_domain
  const risk = r.impact?.avid?.risk_domain ?? [];
  if (risk.includes('Security')) return 'model-abuse';
  return 'model-abuse';
}

function isInScope(r: AvidReport): boolean {
  const classof = r.problemtype?.classof || '';
  if (!CLASSOF_ALLOW.has(classof)) return false;
  const sep = r.impact?.avid?.sep_view ?? [];
  // sep_view entries are like "S0100: Software Vulnerability"
  return sep.some((s) => SEP_INCLUDE_PREFIX.some((p) => s.startsWith(p)));
}

// --- proposal renderer ----------------------------------------------------

function renderProposal(r: AvidReport): string {
  const reportId = r.metadata?.report_id || 'AVID-UNKNOWN';
  const cve = extractCveFromAvid(r);
  const desc = (r.description?.value || '').replace(/\n+/g, ' ').trim();
  const titleStem = desc.split(/[.;]/)[0].trim().substring(0, 80) || reportId;
  const artifacts = (r.affects?.artifacts ?? [])
    .map((a) => `${a.type}=${a.name}`)
    .join(', ');
  const developer = (r.affects?.developer ?? []).join(', ');
  const cwes = (r.impact?.cwe ?? [])
    .map((c) => `    - "${c.cweId}"`)
    .filter((s) => !!s)
    .join('\n');
  const refs = (r.references ?? [])
    .map((rf) => rf.url)
    .filter((u): u is string => !!u && u.startsWith('http'))
    .map((u) => `    - "${u}"`)
    .join('\n');

  return `# ATR rule proposal -- generated by scripts/sync-avid-db.ts
# Source: AVID report ${reportId}
# Imported on: ${new Date().toISOString().slice(0, 10)}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge.
title: "${titleStem.replace(/"/g, '\\"')} (${reportId})"
id: ATR-DRAFT-${reportId}
rule_version: 1
status: draft
description: >
  ${desc.substring(0, 800)}
author: "ATR Community (AVID sync)"
date: "${new Date().toISOString().slice(0, 10).replace(/-/g, '/')}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${severityFromCvss(r)}

references:
${cve ? `  cve:\n    - "${cve}"` : ''}
${cwes ? `  cwe:\n${cwes}` : ''}
  external:
    - "https://avidml.org/database/?report=${reportId}"
${refs}

metadata_provenance:
  ${cve ? 'cve: avid-sync' : ''}
  ${cwes ? 'cwe: avid-sync' : ''}

tags:
  category: ${categoryFromAvid(r)}
  scan_target: runtime
  confidence: medium

agent_source:
  type: llm_io
  framework:
    - any
  provider:
    - any

detection:
  condition: any
  false_positives: []
  conditions:
    # TODO(human): fill in regex / pattern conditions derived from the
    # AVID report description and any linked PoC. AVID's description is
    # narrative, not a payload, so a regex over the raw text alone will
    # not reliably detect the attack at runtime.
    []

response:
  actions:
    - alert
  notify:
    - security_team

remediation: >
  See AVID report at https://avidml.org/database/?report=${reportId} and any
  linked vendor advisory under references.external.

test_cases:
  true_positives: []
  true_negatives: []

# === sync-avid-db.ts provenance ===
_avid_sync:
  report_id: "${reportId}"
  developer: "${developer.replace(/"/g, '\\"')}"
  artifacts: "${artifacts.replace(/"/g, '\\"')}"
  classof: "${r.problemtype?.classof || ''}"
  sep_view: ${JSON.stringify(r.impact?.avid?.sep_view ?? [])}
  lifecycle_view: ${JSON.stringify(r.impact?.avid?.lifecycle_view ?? [])}
  cvss_base_score: ${r.impact?.cvss?.baseScore ?? 'null'}
`;
}

// --- main -----------------------------------------------------------------

interface GitTreeResponse {
  truncated: boolean;
  tree: Array<{ path: string; type: string }>;
}

export function reportNamesForYear(response: GitTreeResponse, year: string): string[] {
  if (response.truncated) {
    throw new Error('AVID Git tree response was truncated');
  }
  const prefix = `reports/${year}/`;
  return response.tree
    .filter((entry) => entry.type === 'blob' && entry.path.startsWith(prefix))
    .map((entry) => entry.path.slice(prefix.length))
    .filter((name) => name.endsWith('.json') && !name.includes('/'))
    .sort();
}

let reportTreePromise: Promise<GitTreeResponse> | undefined;

async function loadReportTree(): Promise<GitTreeResponse> {
  if (reportTreePromise) return reportTreePromise;
  const url = `https://api.github.com/repos/${AVID_OWNER}/${AVID_REPO}/git/trees/main?recursive=1`;
  const ghToken = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  const headers: Record<string, string> = {
    Accept: 'application/vnd.github+json',
  };
  if (ghToken) headers.Authorization = `Bearer ${ghToken}`;
  reportTreePromise = fetch(url, { headers }).then(async (res) => {
    if (!res.ok) throw new Error(`AVID tree listing failed: ${res.status}`);
    return (await res.json()) as GitTreeResponse;
  });
  return reportTreePromise;
}

async function listReports(year: string): Promise<string[]> {
  return reportNamesForYear(await loadReportTree(), year);
}

async function fetchReport(year: string, name: string): Promise<AvidReport> {
  const url = `https://raw.githubusercontent.com/${AVID_OWNER}/${AVID_REPO}/main/reports/${year}/${name}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`AVID report fetch failed: ${url} -- ${res.status}`);
  return (await res.json()) as AvidReport;
}

async function main() {
  console.log('=== sync-avid-db.ts ===');
  console.log(`mode: ${WRITE ? 'WRITE' : 'dry-run'}`);

  const cveIndex = buildCveIndex();
  console.log(`existing ATR rules cover ${cveIndex.size} unique CVEs`);

  if (WRITE && !existsSync(PROPOSALS_DIR)) mkdirSync(PROPOSALS_DIR, { recursive: true });

  // Decide which years to scan.
  let years: string[];
  if (YEAR) {
    years = [YEAR];
  } else {
    years = ['2026', '2025', '2023', '2022'];
  }

  let scanned = 0;
  let outOfScope = 0;
  let alreadyHaveRule = 0;
  let alreadyHaveProposal = 0;
  let written = 0;

  for (const year of years) {
    console.log(`\n-- year ${year} --`);
    let names: string[];
    try {
      names = await listReports(year);
    } catch (err) {
      console.error(`  listing failed: ${(err as Error).message}`);
      continue;
    }
    console.log(`  ${names.length} reports`);

    for (const name of names) {
      if (REPORT && !name.startsWith(REPORT)) continue;
      if (LIMIT > 0 && scanned >= LIMIT) {
        console.log(`  reached --limit ${LIMIT}, stopping`);
        break;
      }
      scanned++;
      let report: AvidReport;
      try {
        report = await fetchReport(year, name);
      } catch (err) {
        console.error(`  ${name}: fetch failed: ${(err as Error).message}`);
        continue;
      }
      if (!isInScope(report)) {
        outOfScope++;
        if (VERBOSE)
          console.log(
            `  skip ${name}: classof=${report.problemtype?.classof} sep=${(report.impact?.avid?.sep_view ?? []).join(',')}`,
          );
        continue;
      }
      const cve = extractCveFromAvid(report);
      if (cve && cveIndex.has(cve) && !FORCE) {
        alreadyHaveRule++;
        if (VERBOSE) console.log(`  have-rule ${name}: covered (${cve})`);
        continue;
      }
      const target = join(PROPOSALS_DIR, `${report.metadata?.report_id || name.replace(/\.json$/, '')}.proposal.yaml`);
      if (existsSync(target) && !FORCE) {
        alreadyHaveProposal++;
        if (VERBOSE) console.log(`  have-proposal ${name}`);
        continue;
      }
      const body = renderProposal(report);
      if (WRITE) writeFileSync(target, body, 'utf-8');
      written++;
      console.log(
        `  ${WRITE ? 'wrote' : 'would write'} ${report.metadata?.report_id} -> ${target.replace(REPO_ROOT + '/', '')}`,
      );
    }
    if (LIMIT > 0 && scanned >= LIMIT) break;
  }

  console.log('');
  console.log('=== summary ===');
  console.log(`scanned:              ${scanned}`);
  console.log(`out-of-scope:         ${outOfScope}`);
  console.log(`already in ATR:       ${alreadyHaveRule}`);
  console.log(`already in proposals: ${alreadyHaveProposal}`);
  console.log(`${WRITE ? 'written' : 'would-write'}: ${written}`);
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
