#!/usr/bin/env npx tsx
/**
 * sync-ossf-malicious.ts
 *
 * Pulls the OpenSSF Malicious Packages database (a curated, OSV-schema feed of
 * CONFIRMED-malicious npm / PyPI / crates / go / maven / nuget / packagist /
 * rubygems / vscode packages) and emits ATR rule proposals under
 * proposals/ossf-malicious/<MAL-id>.proposal.yaml.
 *
 * Repo:   https://github.com/ossf/malicious-packages
 * Layout (verified live 2026-06-12):
 *   osv/malicious/<ecosystem>/<package>/MAL-YYYY-NNNN.json
 *   ecosystems: crates.io, git, go, maven, npm, nuget, packagist, pypi,
 *               rubygems, vscode, vscode:open-vsx.org
 *   Each record is OSV format:
 *     id (MAL-YYYY-NNNN), summary, details (advisory body / behaviour),
 *     aliases[] (CVE/GHSA when assigned), affected[].package.{ecosystem,name},
 *     references[].url, database_specific.iocs.{domains,urls,ips,hashes,...},
 *     database_specific.malicious-packages-origins[].
 *
 * WHY A FILTER IS MANDATORY
 *   The DB is the entire npm/PyPI malware firehose — tens of thousands of
 *   typosquats. Verified counts on 2026-06-12: npm ~37,687 (git-trees API
 *   TRUNCATES this one), pypi 11,330, rubygems 970, nuget 773, the rest < 20.
 *   Ingesting all of it would bury ATR in noise that has nothing to do with the
 *   agent supply chain. We therefore keep ONLY packages whose name looks like
 *   it belongs in the AGENT supply chain:
 *     (a) exact match against the sync-ghsa AI_PACKAGES allowlist, OR
 *     (b) bounded-token fuzzy match (AGENT_PACKAGE_RX, same shape as the
 *         sync-ghsa firehose regex) against agent/mcp/llm package-name tokens.
 *   Bounded tokens (^|[-_/@.] ... [-_/@.]|$) are required so "mcp" does not
 *   match "esqmcpaypal" and "agent" does not match "change-user-agent".
 *   On 2026-06-12 this filter keeps 51 of ~50,811 records.
 *
 * THESE ARE MALWARE, NOT CVEs
 *   The record describes malicious BEHAVIOUR ("downloads and executes a remote
 *   executable", "exfiltrates host info on install"), not an injection payload.
 *   So:
 *     - category is "tool-poisoning" (the closest ATR category to a poisoned
 *       package entering the agent tool/dependency supply chain), unless the
 *       behaviour text clearly reads as data exfiltration -> "context-
 *       exfiltration". (ATR has no "supply-chain" category; verified via
 *       `ls rules/`.)
 *     - detection_ready is normally FALSE (behaviour described, no inline
 *       payload regex) UNLESS the record carries concrete IoCs
 *       (database_specific.iocs domains / urls / ips / hashes) — those ARE
 *       payload-like content a generator can crystallise into matchers.
 *     - the FULL OSV details body + IoCs are embedded in
 *       _ossf_malicious_sync.advisory_body (the only payload source for the
 *       downstream promote-detection-ready.ts).
 *
 * TRUNCATION
 *   git-trees recursive caps at 100k entries and truncates large subtrees. All
 *   ecosystems EXCEPT npm fit and are listed in full. npm truncates; we list it
 *   best-effort and report `truncated_ecosystems` honestly in the summary so no
 *   one mistakes a partial npm scan for full coverage.
 *
 * Idempotency: dedup by MAL id AND by any alias (CVE/GHSA) against rules/ and
 *   proposals/, unless --force. (CVE id stays the cross-source primary key.)
 *
 * Auth: GITHUB_TOKEN / GH_TOKEN read from env only (never a CLI arg, never
 *   echoed). Without it the run uses the 60-req/hour unauthenticated limit and
 *   exits 2 (recoverable) on rate-limit.
 *
 * Usage:
 *   npx tsx scripts/sync-ossf-malicious.ts                 # dry-run
 *   npx tsx scripts/sync-ossf-malicious.ts --write         # write proposals
 *   npx tsx scripts/sync-ossf-malicious.ts --force         # overwrite existing
 *   npx tsx scripts/sync-ossf-malicious.ts --limit 5 --verbose
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network, schema mismatch)
 *   2 no data path / rate limited (recoverable — daily cron retries)
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const RULES_DIR = resolve(REPO_ROOT, "rules");
const PROPOSALS_BASE = resolve(REPO_ROOT, "proposals");
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "ossf-malicious");

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const FORCE = flag("--force");
const VERBOSE = flag("--verbose");
const LIMIT = opt("--limit") ? parseInt(opt("--limit")!, 10) : Infinity;

const OWNER = "ossf";
const REPO = "malicious-packages";
const REF = "main";
const MAL_ROOT = "osv/malicious";

const POLITE_UA =
  "ATR-Sync/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";
const TOKEN = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;

const RATE_LIMIT_MS = 250;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Agent-supply-chain name filter.
// ---------------------------------------------------------------------------

// Exact-name allowlist (mirrors sync-ghsa.ts AI_PACKAGES — agent frameworks,
// agent infra/protocol, runtime guardrails, LLM IO SDKs). Lowercased, flat.
// In practice the legit names rarely appear in a *malware* DB (the DB holds
// typosquats of them), so AGENT_PACKAGE_RX below does most of the matching,
// but the exact list guarantees a true positive is never missed.
const AI_PACKAGES_FLAT: Set<string> = new Set(
  [
    // pip
    "langchain",
    "langchain-core",
    "langchain-community",
    "langchain-experimental",
    "langgraph",
    "langsmith",
    "llama-index",
    "llama-index-core",
    "openai",
    "anthropic",
    "dspy",
    "dspy-ai",
    "autogen-agentchat",
    "pyautogen",
    "crewai",
    "litellm",
    "semantic-kernel",
    "pyrit",
    "garak",
    "promptfoo",
    "llm-guard",
    "nemoguardrails",
    "guardrails-ai",
    "pydantic-ai",
    "haystack-ai",
    "instructor",
    "ollama",
    "embedchain",
    "mcp",
    "fastmcp",
    // npm
    "@langchain/core",
    "@langchain/community",
    "@langchain/openai",
    "@langchain/anthropic",
    "@anthropic-ai/sdk",
    "@modelcontextprotocol/sdk",
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/inspector",
    "ai",
    "@vercel/ai",
    "@ai-sdk/openai",
    "@ai-sdk/anthropic",
    "llamaindex",
    "@google/genai",
    // others
    "langchain4j",
    "langchainrb",
    "langchaingo",
    "ruby-openai",
    "go-openai",
  ].map((s) => s.toLowerCase()),
);

// Bounded-token fuzzy match. Same construction as sync-ghsa.ts AGENT_PACKAGE_RX:
// the leading/trailing [-_/@.] (or string boundary) stops "mcp" matching inside
// "esqmcpaypal" and "agent" matching "change-user-agent". This is the gate that
// catches typosquats like "ant-mcp-proxy-for-test" or "auth0-ai-ms-agent".
const AGENT_PACKAGE_RX =
  /(?:^|[-_/@.])(?:langchain|langgraph|llama[-_]?index|llamaindex|mcp|fastmcp|modelcontextprotocol|crew[-_]?ai|autogen|pyautogen|semantic[-_]kernel|pydantic[-_]ai|haystack|dspy|embedchain|litellm|guardrails?|llm[-_]?guard|nemoguardrails|agentscope|smolagents|agno|llm|ai[-_]agent|genai|openai|anthropic|ollama)(?:[-_/@.]|$)/i;

function isAgentPackageName(name: string): { match: boolean; reason: string } {
  const lower = name.toLowerCase();
  if (AI_PACKAGES_FLAT.has(lower))
    return { match: true, reason: `allowlist exact: ${lower}` };
  if (AGENT_PACKAGE_RX.test(name)) {
    const m = name.match(AGENT_PACKAGE_RX);
    return { match: true, reason: `agent token ${m ? m[0] : ""}` };
  }
  return { match: false, reason: "no agent token in package name" };
}

// ---------------------------------------------------------------------------
// GitHub git-trees listing (recursive per ecosystem, with truncation honesty).
// ---------------------------------------------------------------------------

interface GhTreeEntry {
  path: string;
  mode: string;
  type: "blob" | "tree";
  sha: string;
}
interface GhTreeResponse {
  sha: string;
  url: string;
  tree: GhTreeEntry[];
  truncated: boolean;
}

function ghHeaders(): Record<string, string> {
  const h: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": POLITE_UA,
  };
  if (TOKEN) h.Authorization = `Bearer ${TOKEN}`;
  return h;
}

async function ghGetTree(sha: string, recursive: boolean): Promise<GhTreeResponse> {
  const u =
    `https://api.github.com/repos/${OWNER}/${REPO}/git/trees/${sha}` +
    (recursive ? "?recursive=1" : "");
  const res = await fetch(u, { headers: ghHeaders() });
  if (res.status === 403 || res.status === 429) {
    const remaining = res.headers.get("x-ratelimit-remaining");
    const reset = res.headers.get("x-ratelimit-reset");
    console.error(
      `rate limited on git-trees ${sha}: remaining=${remaining}, reset=${reset}` +
        (TOKEN ? "" : " (set GITHUB_TOKEN to raise the limit)"),
    );
    process.exit(2);
  }
  if (!res.ok)
    throw new Error(`git-trees fetch failed for ${sha}: ${res.status} ${res.statusText}`);
  return (await res.json()) as GhTreeResponse;
}

// Resolve the SHA of a path one level at a time from the root tree, so we get a
// real tree SHA to recurse into per ecosystem (the recursive cap is per-call).
async function resolvePathSha(segments: string[]): Promise<string> {
  let sha = REF;
  let cur = await ghGetTree(sha, false);
  for (const seg of segments) {
    const entry = cur.tree.find((t) => t.path === seg && t.type === "tree");
    if (!entry) throw new Error(`path segment not found: ${seg}`);
    sha = entry.sha;
    cur = await ghGetTree(sha, false);
    await sleep(RATE_LIMIT_MS);
  }
  return sha;
}

interface MalBlobRef {
  ecosystem: string; // dir name under osv/malicious
  packageDir: string; // first path segment under the ecosystem subtree
  malId: string; // MAL-YYYY-NNNN (from filename)
  fullPath: string; // osv/malicious/<eco>/<pkg>/<MAL>.json
}

// List every MAL-*.json blob per ecosystem, applying the agent name filter
// during listing (so we never fetch the firehose). Returns matched refs plus
// honest scan/truncation accounting.
async function listAgentMalBlobs(): Promise<{
  matched: MalBlobRef[];
  totalScanned: number;
  truncatedEcosystems: string[];
  ecosystemStats: Record<string, { scanned: number; matched: number; truncated: boolean }>;
}> {
  const malRootSha = await resolvePathSha(MAL_ROOT.split("/"));
  const ecoTree = await ghGetTree(malRootSha, false);
  const ecosystems = ecoTree.tree.filter((t) => t.type === "tree");

  const matched: MalBlobRef[] = [];
  const truncatedEcosystems: string[] = [];
  const ecosystemStats: Record<
    string,
    { scanned: number; matched: number; truncated: boolean }
  > = {};
  let totalScanned = 0;

  for (const eco of ecosystems) {
    const tree = await ghGetTree(eco.sha, true);
    await sleep(RATE_LIMIT_MS);
    const blobs = tree.tree.filter(
      (t) => t.type === "blob" && /\/MAL-\d{4}-\d+\.json$/i.test("/" + t.path),
    );
    let ecoMatched = 0;
    for (const b of blobs) {
      const parts = b.path.split("/");
      const packageDir = parts.slice(0, parts.length - 1).join("/") || parts[0];
      const file = parts[parts.length - 1];
      const malId = file.replace(/\.json$/i, "");
      // The package NAME is the package directory (may itself contain slashes
      // for scoped npm packages like @scope/name). Filter on it.
      const verdict = isAgentPackageName(packageDir);
      if (!verdict.match) continue;
      ecoMatched += 1;
      matched.push({
        ecosystem: eco.path,
        packageDir,
        malId,
        fullPath: `${MAL_ROOT}/${eco.path}/${b.path}`,
      });
    }
    totalScanned += blobs.length;
    ecosystemStats[eco.path] = {
      scanned: blobs.length,
      matched: ecoMatched,
      truncated: tree.truncated,
    };
    if (tree.truncated) truncatedEcosystems.push(eco.path);
    if (VERBOSE)
      console.error(
        `  ${eco.path}: scanned=${blobs.length} matched=${ecoMatched}` +
          (tree.truncated ? " (TRUNCATED — partial scan)" : ""),
      );
  }

  return { matched, totalScanned, truncatedEcosystems, ecosystemStats };
}

// ---------------------------------------------------------------------------
// OSV record fetch + parse.
// ---------------------------------------------------------------------------

interface OsvAffected {
  package?: { ecosystem?: string; name?: string };
  versions?: string[];
}
interface OsvReference {
  type?: string;
  url?: string;
}
interface OsvRecord {
  id?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  affected?: OsvAffected[];
  references?: OsvReference[];
  database_specific?: {
    iocs?: Record<string, unknown>;
    "malicious-packages-origins"?: Array<Record<string, unknown>>;
    [k: string]: unknown;
  };
}

async function fetchRaw(path: string): Promise<string> {
  const u = `https://raw.githubusercontent.com/${OWNER}/${REPO}/${REF}/${path}`;
  const res = await fetch(u, { headers: { "User-Agent": POLITE_UA } });
  if (!res.ok)
    throw new Error(`raw fetch failed for ${path}: ${res.status} ${res.statusText}`);
  return await res.text();
}

interface MalSummary {
  malId: string;
  cveAliases: string[]; // CVE-* aliases
  ghsaAliases: string[]; // GHSA-* aliases
  otherAliases: string[];
  title: string;
  summaryText: string;
  detailsText: string;
  packages: string[]; // ecosystem:name
  references: string[];
  iocs: Record<string, unknown> | null;
  iocCount: number;
  published: string | null;
  blobUrl: string;
  rawJson: string;
}

function htmlBlobUrl(fullPath: string): string {
  return `https://github.com/${OWNER}/${REPO}/blob/${REF}/${fullPath}`;
}

function countIocs(iocs: Record<string, unknown> | null | undefined): number {
  if (!iocs || typeof iocs !== "object") return 0;
  let n = 0;
  for (const v of Object.values(iocs)) {
    if (Array.isArray(v)) n += v.length;
    else if (v != null) n += 1;
  }
  return n;
}

function parseRecord(
  ref: MalBlobRef,
  raw: string,
): MalSummary | { error: string } {
  let doc: OsvRecord;
  try {
    doc = JSON.parse(raw) as OsvRecord;
  } catch (e) {
    return { error: `JSON parse failed for ${ref.fullPath}: ${(e as Error).message}` };
  }
  const malId = (doc.id || ref.malId || "").trim();
  if (!/^MAL-\d{4}-\d+$/i.test(malId))
    return { error: `unexpected id "${malId}" in ${ref.fullPath}` };

  const aliases = Array.isArray(doc.aliases) ? doc.aliases.filter((a) => typeof a === "string") : [];
  const cveAliases = aliases.filter((a) => /^CVE-\d{4}-\d+$/i.test(a));
  const ghsaAliases = aliases.filter((a) => /^GHSA-/i.test(a));
  const otherAliases = aliases.filter(
    (a) => !/^CVE-\d{4}-\d+$/i.test(a) && !/^GHSA-/i.test(a),
  );

  const packages = (doc.affected ?? [])
    .map((a) => {
      const eco = a.package?.ecosystem ?? "";
      const name = a.package?.name ?? "";
      return eco || name ? `${eco}:${name}` : "";
    })
    .filter(Boolean);

  const references = (doc.references ?? [])
    .map((r) => r.url)
    .filter((u): u is string => typeof u === "string" && u.length > 0);

  const iocs = doc.database_specific?.iocs ?? null;

  return {
    malId,
    cveAliases,
    ghsaAliases,
    otherAliases,
    title: (doc.summary || malId).trim(),
    summaryText: (doc.summary || "").trim(),
    detailsText: (doc.details || "").trim(),
    packages: packages.length > 0 ? packages : [`${ref.ecosystem}:${ref.packageDir}`],
    references,
    iocs,
    iocCount: countIocs(iocs),
    published: doc.published ?? null,
    blobUrl: htmlBlobUrl(ref.fullPath),
    rawJson: raw,
  };
}

// ---------------------------------------------------------------------------
// Category selection. ATR has no "supply-chain" category (verified via
// `ls rules/`); tool-poisoning is the closest fit for a poisoned package
// entering the agent tool/dependency supply chain. Exfil-flavoured behaviour
// maps to context-exfiltration.
// ---------------------------------------------------------------------------

function categoryFor(m: MalSummary): string {
  const hay = `${m.summaryText} ${m.detailsText}`.toLowerCase();
  if (/exfiltrat|steal(s|ing)?\b|infostealer|leak(s|ing)?\b|sends? .*(host|env|token|credential|cookie|secret)|collects? .*(data|info)/.test(hay))
    return "context-exfiltration";
  return "tool-poisoning";
}

// ---------------------------------------------------------------------------
// Detection-readiness triage. Malware records describe behaviour, not a payload
// regex — so default FALSE. Concrete IoCs (domains/urls/ips/hashes) ARE
// payload-like content a generator can crystallise, so those flip it to TRUE.
// ---------------------------------------------------------------------------

function triageFor(m: MalSummary): { ready: boolean; reason: string } {
  if (m.iocCount > 0)
    return {
      ready: true,
      reason: `concrete IoCs present (${m.iocCount} indicator(s) in database_specific.iocs)`,
    };
  return {
    ready: false,
    reason: "malware behaviour described in prose, no inline payload / IoC",
  };
}

// ---------------------------------------------------------------------------
// Idempotency index.
// ---------------------------------------------------------------------------

function walkYaml(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const f = join(dir, e);
    let st;
    try {
      st = statSync(f);
    } catch {
      continue;
    }
    if (st.isDirectory()) out.push(...walkYaml(f));
    else if (st.isFile() && (e.endsWith(".yaml") || e.endsWith(".yml")))
      out.push(f);
  }
  return out;
}

interface KnownIndex {
  cves: Set<string>;
  mals: Set<string>;
  ghsas: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const mals = new Set<string>();
  const ghsas = new Set<string>();
  for (const dir of [RULES_DIR, PROPOSALS_BASE]) {
    for (const f of walkYaml(dir)) {
      let raw: string;
      try {
        raw = readFileSync(f, "utf-8");
      } catch {
        continue;
      }
      let doc: unknown;
      try {
        doc = yaml.load(raw);
      } catch {
        continue;
      }
      const refs = (
        doc as {
          references?: {
            cve?: string[];
            ghsa?: string[];
            mal?: string[];
            ossf_malicious?: string[];
          };
        }
      )?.references;
      if (refs?.cve)
        for (const c of refs.cve) if (typeof c === "string") cves.add(c);
      if (refs?.ghsa)
        for (const g of refs.ghsa) if (typeof g === "string") ghsas.add(g);
      if (refs?.mal)
        for (const m of refs.mal) if (typeof m === "string") mals.add(m);
      if (refs?.ossf_malicious)
        for (const m of refs.ossf_malicious)
          if (typeof m === "string") mals.add(m);
      // Also pick up MAL ids from filename pattern MAL-YYYY-NNNN.proposal.yaml
      const fm = f.match(/MAL-\d{4}-\d+/i);
      if (fm) mals.add(fm[0]);
    }
  }
  return { cves, mals, ghsas };
}

// ---------------------------------------------------------------------------
// Proposal renderer (field-for-field aligned with sync-huntr / sync-ghsa).
// ---------------------------------------------------------------------------

const ADVISORY_BODY_MAX_CHARS = 8000;

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars; see blob_url for full record)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function renderProposal(m: MalSummary): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  // Primary id is the MAL id; if CVE-aliased, the CVE is the cross-source key
  // for the draft id suffix (still dedup on both).
  const draftIdSuffix =
    m.cveAliases.length > 0 ? m.cveAliases[0] : m.malId;
  const category = categoryFor(m);
  const triage = triageFor(m);

  // Malware in the agent supply chain: treat as high severity (confirmed
  // malicious, executes / exfiltrates on install or use). OSSF DB carries no
  // CVSS, so we do not invent a numeric score.
  const severity = "high";
  const responseActions = ["block_input", "alert"];

  const cveBlock =
    m.cveAliases.length > 0
      ? `  cve:\n${m.cveAliases.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const ghsaBlock =
    m.ghsaAliases.length > 0
      ? `  ghsa:\n${m.ghsaAliases.map((g) => `    - "${g}"`).join("\n")}\n`
      : "";
  const malBlock = `  mal:\n    - "${m.malId}"\n`;

  // references.external = OSV references[] + the GitHub blob URL.
  const externalUrls = Array.from(new Set([...m.references, m.blobUrl]));
  const externalBlock = `  external:\n${externalUrls
    .map((u) => `    - "${u.replace(/"/g, '\\"')}"`)
    .join("\n")}\n`;

  const title = `Malicious package: ${m.title}`.replace(/"/g, '\\"').slice(0, 120);
  const desc = `${m.summaryText || m.title}`.replace(/\n+/g, " ").trim();
  const pkgNote = m.packages.join(", ");

  // The "advisory body" for downstream crystallisation = OSV details prose +
  // any concrete IoCs rendered as text. This is the ONLY payload source for
  // promote-detection-ready.ts.
  const iocsText =
    m.iocs && m.iocCount > 0
      ? "\n\n## Indicators of Compromise (database_specific.iocs)\n" +
        yaml.dump(m.iocs, { lineWidth: 120 })
      : "";
  const advisoryBody = `${m.detailsText || "(no details body provided by OSSF record)"}${iocsText}`;

  return `# ATR rule proposal -- generated by scripts/sync-ossf-malicious.ts
# Source: OpenSSF Malicious Packages DB (${m.malId})
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. This is a CONFIRMED-
#         malicious package in the AGENT supply chain; the OSSF record describes
#         malicious behaviour (and any IoCs) rather than an injection payload,
#         so most records are tracking-only until IoCs are converted to matchers.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${draftIdSuffix}
rule_version: 1
status: draft
description: >
  OpenSSF Malicious Packages confirmed-malicious package ${m.malId}${m.cveAliases.length ? ` (${m.cveAliases[0]})` : ""}.
  Affected: ${pkgNote}.
  ${desc.slice(0, 600)}
author: "ATR Community (OSSF Malicious Packages sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${severity}

references:
${cveBlock}${ghsaBlock}${malBlock}${externalBlock}
metadata_provenance:
  ossf_malicious: ossf-malicious-sync
${m.cveAliases.length ? "  cve: ossf-malicious-sync\n" : ""}${m.ghsaAliases.length ? "  ghsa: ossf-malicious-sync\n" : ""}
tags:
  category: ${category}
  subcategory: malicious-package
  scan_target: supply-chain
  confidence: ${triage.ready ? "high" : "low"}

agent_source:
  type: tool_invocation
  framework:
    - any
  provider:
    - any

detection:
  condition: any
  false_positives: []
  conditions:
    # TODO(human): convert the OSSF malware record below into precision-safe
    # detection.conditions. For a malicious package the practical matchers are
    # the package name(s) above and any IoCs (domains / urls / ips / hashes)
    # embedded in the advisory body under _ossf_malicious_sync. Empty until
    # promoted to rules/.
    []

response:
  actions:
${responseActions.map((a) => `    - ${a}`).join("\n")}
  notify:
    - security_team

confidence: ${triage.ready ? 70 : 50}

test_cases:
  true_positives: []
  true_negatives:
    # TODO(human): add benign package names / inputs that look similar to the
    # malicious package but are legitimate -- required before promoting.
    []

# === sync-ossf-malicious.ts provenance ===
_ossf_malicious_sync:
  mal_id: "${m.malId}"
  cve_aliases: ${JSON.stringify(m.cveAliases)}
  ghsa_aliases: ${JSON.stringify(m.ghsaAliases)}
  other_aliases: ${JSON.stringify(m.otherAliases)}
  affected_packages:
${m.packages.map((p) => `    - "${p.replace(/"/g, '\\"')}"`).join("\n")}
  ioc_count: ${m.iocCount}
  published: ${m.published ? `"${m.published}"` : "null"}
  blob_url: "${m.blobUrl}"
  source_db: "https://github.com/ossf/malicious-packages"
  imported_at: "${new Date().toISOString()}"
  advisory_body: |
${indentForLiteralBlock(advisoryBody, "    ")}

# Triage flag read by promote-detection-ready.ts. OSSF records describe malware
# behaviour; only records carrying concrete IoCs (domains/urls/ips/hashes) are
# detection-ready (the generator lifts matchers from those IoCs, never from
# behaviour prose).
_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason.replace(/"/g, '\\"')}"
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  total_scanned: number;
  agent_matched: number;
  truncated_ecosystems: string[];
  ecosystem_stats: Record<
    string,
    { scanned: number; matched: number; truncated: boolean }
  >;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  skipped_existing: number;
  parse_failures: number;
  errors: string[];
  written_files: string[];
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    total_scanned: 0,
    agent_matched: 0,
    truncated_ecosystems: [],
    ecosystem_stats: {},
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    skipped_existing: 0,
    parse_failures: 0,
    errors: [],
    written_files: [],
  };

  console.error("=== sync-ossf-malicious.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);
  if (!TOKEN)
    console.error(
      "note: no GITHUB_TOKEN/GH_TOKEN in env — running at 60 req/hour " +
        "unauthenticated limit (set a token to raise it).",
    );

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  // --- list + filter ---
  let listing;
  try {
    listing = await listAgentMalBlobs();
  } catch (e) {
    summary.errors.push(`listing failed: ${(e as Error).message}`);
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::ossf-malicious-summary::${JSON.stringify({
        new_proposals: 0,
        total_scanned: 0,
        agent_matched: 0,
        error: (e as Error).message,
      })}`,
    );
    process.exit(2);
  }

  summary.total_scanned = listing.totalScanned;
  summary.agent_matched = listing.matched.length;
  summary.truncated_ecosystems = listing.truncatedEcosystems;
  summary.ecosystem_stats = listing.ecosystemStats;

  console.error(
    `scanned ${listing.totalScanned} MAL records; ${listing.matched.length} ` +
      `matched the agent supply-chain filter` +
      (listing.truncatedEcosystems.length
        ? ` (PARTIAL — truncated ecosystems: ${listing.truncatedEcosystems.join(", ")})`
        : ""),
  );

  if (listing.matched.length === 0) {
    summary.errors.push("no agent-relevant malicious packages matched");
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::ossf-malicious-summary::${JSON.stringify({
        new_proposals: 0,
        total_scanned: summary.total_scanned,
        agent_matched: 0,
      })}`,
    );
    process.exit(0);
  }

  const known = buildKnownIndex();
  let writtenCount = 0;

  for (const ref of listing.matched) {
    if (writtenCount >= LIMIT) break;

    // Dedup by MAL id (cheap, before fetch).
    if (!FORCE && known.mals.has(ref.malId)) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have ${ref.malId}: already covered`);
      continue;
    }
    const outPath = join(PROPOSALS_DIR, `${ref.malId}.proposal.yaml`);
    if (existsSync(outPath) && !FORCE) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-proposal ${outPath}`);
      continue;
    }

    let raw: string;
    try {
      raw = await fetchRaw(ref.fullPath);
      await sleep(RATE_LIMIT_MS);
    } catch (e) {
      summary.parse_failures += 1;
      summary.errors.push(`fetch ${ref.fullPath}: ${(e as Error).message}`);
      continue;
    }

    const parsed = parseRecord(ref, raw);
    if ("error" in parsed) {
      summary.parse_failures += 1;
      if (VERBOSE) console.error(`  parse-skip ${ref.fullPath}: ${parsed.error}`);
      continue;
    }

    // Dedup by alias (CVE / GHSA) — cross-source primary key.
    if (!FORCE) {
      const cveHit = parsed.cveAliases.find((c) => known.cves.has(c));
      if (cveHit) {
        summary.skipped_existing += 1;
        if (VERBOSE)
          console.error(`  have ${ref.malId}: CVE alias ${cveHit} already covered`);
        continue;
      }
      const ghsaHit = parsed.ghsaAliases.find((g) => known.ghsas.has(g));
      if (ghsaHit) {
        summary.skipped_existing += 1;
        if (VERBOSE)
          console.error(`  have ${ref.malId}: GHSA alias ${ghsaHit} already covered`);
        continue;
      }
    }

    const triage = triageFor(parsed);
    const body = renderProposal(parsed);
    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${ref.malId}.proposal.yaml`);
    } else {
      console.error(
        `  would write ${ref.malId}.proposal.yaml ` +
          `[${parsed.packages.join(",")}] ` +
          `(${triage.ready ? "detection-ready" : "tracking-only"})`,
      );
    }
    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;
    writtenCount += 1;

    // Mark as known within this run to avoid duplicate MAL/aliases in-batch.
    known.mals.add(ref.malId);
    for (const c of parsed.cveAliases) known.cves.add(c);
    for (const g of parsed.ghsaAliases) known.ghsas.add(g);
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::ossf-malicious-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      total_scanned: summary.total_scanned,
      agent_matched: summary.agent_matched,
      skipped_existing: summary.skipped_existing,
      parse_failures: summary.parse_failures,
      truncated_ecosystems: summary.truncated_ecosystems,
    })}`,
  );
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}
