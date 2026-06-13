#!/usr/bin/env npx tsx
/**
 * sync-huntr.ts
 *
 * Pulls Huntr.dev (now ProtectAI) AI/ML vulnerability disclosures and emits
 * ATR rule proposals (proposals/huntr/<CVE-ID-or-HUNTR-ID>.proposal.yaml).
 *
 * Data source strategy -- attempted in order, first success wins:
 *
 *   PRIMARY  Huntr public REST/GraphQL API. As of 2026-05 there is no
 *            documented public endpoint -- /api/v1/bounties returns 404
 *            and the historical AppSync GraphQL key
 *            (mnk2smepzzdp5djxpbthzr6odq.appsync-api.eu-west-1.amazonaws.com)
 *            now returns 400 UnauthorizedException. We probe a small set
 *            of likely paths in case ProtectAI publishes one in future;
 *            an env-only `HUNTR_API_KEY` hook is reserved so a maintainer
 *            with a partner key can switch to the API later.
 *
 *   FALLBACK_A  protectai/ai-exploits GitHub repo. ProtectAI (parent of
 *            Huntr) curates a public collection of nuclei templates that
 *            wrap real disclosed Huntr bounties. Each template includes
 *            CVE-id, CWE-id, CVSS, severity, Huntr bounty URL, and a
 *            working PoC payload. This is the source we actually use.
 *
 *   FALLBACK_B  HTML scrape of https://huntr.com/bounties?category=ml.
 *            INFEASIBLE: Huntr is a Next.js client-rendered SPA with
 *            `meta name=robots noindex`, no sitemap, no bounty slugs in
 *            initial HTML, and JSON state is loaded over authenticated
 *            requests after page mount. A regex-only scrape cannot
 *            extract any bounty fields without a headless browser. The
 *            task constraints forbid adding cheerio/puppeteer/playwright.
 *            Documented and skipped.
 *
 *   FALLBACK_C  No data path available. Emit clear error to JSON summary,
 *            exit code 2 (partial / recoverable), and leave a comment
 *            describing the manual maintainer path (point at a working
 *            endpoint via env var HUNTR_DATA_URL).
 *
 * Each proposal:
 *   - id: CVE-XXXX-NNNNN if the Huntr bounty has been CVE-assigned, else
 *     HUNTR-<8-char-bounty-uuid-prefix>.
 *   - status=draft, maturity=experimental
 *   - tags.confidence=high (Huntr reports are validated by bounty hunters
 *     AND maintainers before publication)
 *   - tags.category derived from vulnerability type
 *   - detection.conditions is left EMPTY with a TODO. If the source has a
 *     PoC body, the PoC is embedded as a YAML comment in detection.conditions
 *     so the human reviewer has the attack input ready to convert to regex.
 *   - test_cases.true_positives populated from the PoC body
 *   - response.actions: [block_input, alert] for high/critical, [alert]
 *     for medium/low
 *
 * Idempotency: skip if CVE-ID or HUNTR-ID already exists in rules/ or
 * proposals/, unless `--force`.
 *
 * TOS: This script respects huntr.com TOS for public bounty reads --
 * 1 req/sec rate limit and a polite User-Agent. In practice we never hit
 * huntr.com (we read GitHub raw URLs); the rate limit is still enforced
 * for any future code path that does. If the maintainer wants to upgrade
 * to an official API key, set HUNTR_API_KEY in env and extend the
 * tryPrimaryApi() probe list.
 *
 * Usage:
 *   npx tsx scripts/sync-huntr.ts                # dry-run, document source
 *   npx tsx scripts/sync-huntr.ts --write        # write proposals
 *   npx tsx scripts/sync-huntr.ts --force        # overwrite existing
 *   npx tsx scripts/sync-huntr.ts --verbose
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network, schema mismatch)
 *   2 no data path available (recoverable -- maintainer needs to point at
 *     a working endpoint via env var)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "huntr");

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

// Polite UA per task TOS note. Used for any direct huntr.com call.
const POLITE_UA =
  "ATR-Sync/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";

// Reserved env hook for an upcoming Huntr API key.
const HUNTR_API_KEY = process.env.HUNTR_API_KEY;

// Rate limit: 1 req/sec for any direct huntr.com request.
const RATE_LIMIT_MS = 1000;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// FALLBACK_A: protectai/ai-exploits — curated GitHub mirror.
// ---------------------------------------------------------------------------

const AI_EXPLOITS_OWNER = "protectai";
const AI_EXPLOITS_REPO = "ai-exploits";
const AI_EXPLOITS_REF = "main";

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

async function listAiExploitsYaml(): Promise<string[]> {
  const u =
    `https://api.github.com/repos/${AI_EXPLOITS_OWNER}/${AI_EXPLOITS_REPO}` +
    `/git/trees/${AI_EXPLOITS_REF}?recursive=1`;
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "User-Agent": POLITE_UA,
  };
  const ghToken = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (ghToken) headers.Authorization = `Bearer ${ghToken}`;
  const res = await fetch(u, { headers });
  if (!res.ok) {
    throw new Error(
      `ai-exploits tree fetch failed: ${res.status} ${res.statusText}`,
    );
  }
  const data = (await res.json()) as GhTreeResponse;
  if (data.truncated) {
    // ai-exploits has ~16 yaml templates as of 2026-05; truncation should
    // never happen, but if it ever does we'd need to paginate via
    // /git/trees/<sha>?recursive=1 per subdir.
    console.error(
      "warning: ai-exploits tree response was truncated -- consider " +
        "paginating per subdirectory.",
    );
  }
  return data.tree
    .filter((t) => t.type === "blob" && /\.ya?ml$/.test(t.path))
    .map((t) => t.path);
}

async function fetchAiExploitFile(path: string): Promise<string> {
  const u =
    `https://raw.githubusercontent.com/${AI_EXPLOITS_OWNER}/` +
    `${AI_EXPLOITS_REPO}/${AI_EXPLOITS_REF}/${path}`;
  const res = await fetch(u, { headers: { "User-Agent": POLITE_UA } });
  if (!res.ok)
    throw new Error(
      `raw fetch failed for ${path}: ${res.status} ${res.statusText}`,
    );
  return await res.text();
}

// ---------------------------------------------------------------------------
// FALLBACK_B: HTML scrape. Confirmed infeasible -- see header comment.
// We keep the function as a stub so the data-source-strategy log line is
// honest about what we tried.
// ---------------------------------------------------------------------------

async function tryHtmlScrape(): Promise<{
  ok: false;
  reason: string;
}> {
  return {
    ok: false,
    reason:
      "huntr.com is a fully client-rendered Next.js SPA with noindex; " +
      "no bounty data in initial HTML, no sitemap. Regex scrape infeasible " +
      "without a headless browser (forbidden by task constraints).",
  };
}

// ---------------------------------------------------------------------------
// PRIMARY: try a handful of plausible API endpoints. If none respond with
// useful JSON, the function returns null and the caller falls back.
// ---------------------------------------------------------------------------

interface BountySummary {
  // Common shape we expect; not all sources fill every field.
  cve_id: string | null;
  huntr_id: string; // bounty UUID or template id
  huntr_url: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  cwe: string[];
  cvss_score: number | null;
  cvss_metrics: string | null;
  vulnerability_type: string;
  package_name: string | null; // ecosystem inferred from path
  package_ecosystem: string | null;
  poc_body: string | null; // raw PoC text, embedded as YAML comment
  tags: string[];
  disclosed_at: string | null;
  authors: string[];
}

async function tryPrimaryApi(): Promise<{
  ok: boolean;
  endpoint: string | null;
  bounties: BountySummary[];
  reason: string;
}> {
  // Probe a small set of likely endpoints. If huntr publishes a real API
  // in the future, add it here. We do NOT auto-discover via the SPA bundle
  // because that needs JS execution; the maintainer should add discovered
  // endpoints manually.
  const candidates = [
    "https://huntr.com/api/v1/bounties?category=ml&status=published",
    "https://huntr.com/api/v2/bounties?category=ml",
    "https://huntr.com/api/bounties.json",
  ];
  for (const url of candidates) {
    try {
      const headers: Record<string, string> = { "User-Agent": POLITE_UA };
      if (HUNTR_API_KEY) headers.Authorization = `Bearer ${HUNTR_API_KEY}`;
      const res = await fetch(url, { headers });
      if (res.ok) {
        // The shape is unknown; we can only commit to processing this once
        // a maintainer has confirmed the schema. Be conservative.
        const text = await res.text();
        if (text.trim().startsWith("{") || text.trim().startsWith("[")) {
          return {
            ok: false,
            endpoint: url,
            bounties: [],
            reason: `endpoint ${url} returned JSON but schema is undocumented -- maintainer must extend tryPrimaryApi() with the field mapping.`,
          };
        }
      }
      await sleep(RATE_LIMIT_MS);
    } catch (e) {
      if (VERBOSE) console.error(`primary probe ${url} failed: ${e}`);
    }
  }
  return {
    ok: false,
    endpoint: null,
    bounties: [],
    reason:
      "no public Huntr API found -- /api/v1, /api/v2, /api/bounties.json " +
      "all 404. Historical AppSync GraphQL is now 400 Unauthorized.",
  };
}

// ---------------------------------------------------------------------------
// Nuclei template -> BountySummary parser.
// ---------------------------------------------------------------------------

interface NucleiTemplate {
  id?: string;
  info?: {
    name?: string;
    author?: string;
    severity?: string;
    description?: string;
    reference?: string[];
    classification?: {
      "cvss-metrics"?: string;
      "cvss-score"?: number;
      "cve-id"?: string;
      "cwe-id"?: string | string[];
    };
    tags?: string;
  };
  requests?: unknown;
  http?: unknown;
}

function parseSeverity(
  s: string | undefined,
): "critical" | "high" | "medium" | "low" {
  const v = (s || "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium") return "medium";
  if (v === "low") return "low";
  // Unknown / info -> default medium so we don't mis-trigger response.actions
  return "medium";
}

function pocFromTemplate(t: NucleiTemplate): string | null {
  const r = (t.requests ?? t.http) as unknown;
  if (!r) return null;
  try {
    return yaml.dump(r, { lineWidth: 100 });
  } catch {
    return null;
  }
}

function pathEcosystem(path: string): {
  ecosystem: string | null;
  pkg: string | null;
} {
  // ai-exploits paths look like "<package-or-product>/.../<name>.yaml" or
  // "<product>/<name>.yaml". Map the top-level directory to an inferred
  // package name and a best-guess ecosystem.
  const top = path.split("/")[0] || "";
  const PKG_TO_ECO: Record<string, [string, string]> = {
    "anything-llm": ["npm", "anythingllm"],
    bentoml: ["pip", "bentoml"],
    fastapi: ["pip", "fastapi"],
    gradio: ["pip", "gradio"],
    h2o: ["pip", "h2o"],
    mlflow: ["pip", "mlflow"],
    "nmap-nse": ["nmap-nse", "nmap-nse"],
    ray: ["pip", "ray"],
    triton: ["pip", "tritonserver"],
  };
  const m = PKG_TO_ECO[top];
  if (m) return { ecosystem: m[0], pkg: m[1] };
  return { ecosystem: null, pkg: top || null };
}

function huntrUrlFromRefs(refs: string[] | undefined): string | null {
  if (!Array.isArray(refs)) return null;
  for (const r of refs) {
    if (typeof r === "string" && /huntr\.(com|dev)\/bounties\//.test(r)) {
      return r.replace(/\/+$/, "");
    }
  }
  return null;
}

function huntrIdFromUrl(url: string | null): string | null {
  if (!url) return null;
  const m = url.match(/bounties\/([a-f0-9-]{36}|[a-z0-9-]+)/i);
  if (!m) return null;
  // UUIDs are 36 chars; we keep the first 8 for the proposal id stub.
  const v = m[1];
  if (v.length === 36) return `HUNTR-${v.split("-")[0]}`;
  return `HUNTR-${v.slice(0, 8)}`;
}

function categoryForBounty(b: BountySummary): string {
  // Match the mapping requested in the task brief:
  // RCE / code-exec  -> tool-poisoning
  // SSRF             -> context-exfiltration
  // prototype-pollution -> tool-poisoning
  // prompt-injection -> prompt-injection
  // info-leak        -> context-exfiltration
  // auth-bypass      -> privilege-escalation
  // default          -> tool-poisoning
  const haystack = `${b.title} ${b.description} ${b.tags.join(" ")}`.toLowerCase();
  if (/prompt[- ]injection|jailbreak/.test(haystack)) return "prompt-injection";
  if (/ssrf|server[- ]side[- ]request[- ]forgery/.test(haystack))
    return "context-exfiltration";
  if (/path[- ]traversal|lfi|local[- ]file[- ](read|include)|info(rmation)?[- ](leak|disclos)|cwe-22\b|cwe-29\b|cwe-200\b/.test(haystack))
    return "context-exfiltration";
  if (/auth(entication)?[- ]bypass|unauthor(i[sz]ed|ised)|cwe-284\b|cwe-287\b|cwe-863\b/.test(haystack))
    return "privilege-escalation";
  if (/proto(type)?[- ]pollution/.test(haystack)) return "tool-poisoning";
  if (/\brce\b|remote[- ]code[- ]exec|command[- ]injection|deserial|pickle|cwe-78\b|cwe-94\b|cwe-95\b|cwe-1188\b|cwe-502\b/.test(haystack))
    return "tool-poisoning";
  return "tool-poisoning";
}

function cwesFromClassification(
  c: NucleiTemplate["info"] extends infer X
    ? X extends { classification?: infer C }
      ? C
      : never
    : never,
): string[] {
  if (!c) return [];
  const v = (c as { "cwe-id"?: string | string[] })["cwe-id"];
  if (!v) return [];
  if (Array.isArray(v))
    return v
      .map((s) => (typeof s === "string" ? s.split("#")[0].trim() : ""))
      .filter((s): s is string => !!s);
  // string may look like "CWE-29" or "CWE-1188 # Insecure ..."
  return [v.split("#")[0].trim()];
}

function authorsFromInfo(authorField: string | undefined): string[] {
  if (!authorField) return [];
  // "DanMcInerney, byt3bl33d3r, pinkdraconian" or
  // "kevin_mizu (Vuln Discovery), byt3bl33d3r (Nuclei Template)"
  return authorField
    .split(",")
    .map((s) => s.trim().replace(/\s*\([^)]*\)\s*$/, ""))
    .filter((s) => s.length > 0);
}

function templateToBounty(
  path: string,
  raw: string,
): BountySummary | { error: string } {
  let doc: NucleiTemplate;
  try {
    doc = yaml.load(raw) as NucleiTemplate;
    if (typeof doc !== "object" || doc === null)
      throw new Error("non-object yaml");
  } catch (e) {
    // Manual fallback: extract just the fields we need with regex. This is
    // brittle but only triggers on the rare template whose YAML breaks
    // js-yaml; the human reviewer still sees the source URL in the proposal.
    const huntrRefMatch = raw.match(/https:\/\/huntr\.(com|dev)\/bounties\/[a-z0-9-]+/i);
    if (!huntrRefMatch)
      return { error: `yaml parse failed and no huntr ref in ${path}: ${(e as Error).message}` };
    const huntrUrl = huntrRefMatch[0].replace(/\/+$/, "");
    const huntrId = huntrIdFromUrl(huntrUrl);
    if (!huntrId)
      return { error: `yaml parse failed and could not parse huntr id from ${huntrUrl}` };
    const cveMatch = raw.match(/cve-id:\s*(CVE-\d{4}-\d+)/i);
    const nameMatch = raw.match(/^\s*name:\s*(.+)$/m);
    const sevMatch = raw.match(/^\s*severity:\s*([a-z]+)/im);
    const descMatch = raw.match(/^\s*description:\s*(.+)$/m);
    const cweMatch = raw.match(/cwe-id:\s*(CWE-\d+)/i);
    return {
      cve_id: cveMatch ? cveMatch[1] : null,
      huntr_id: huntrId,
      huntr_url: huntrUrl,
      title: (nameMatch ? nameMatch[1] : huntrId).trim(),
      description: descMatch ? descMatch[1].trim() : "",
      severity: parseSeverity(sevMatch ? sevMatch[1] : undefined),
      cwe: cweMatch ? [cweMatch[1]] : [],
      cvss_score: null,
      cvss_metrics: null,
      vulnerability_type: "",
      package_name: pathEcosystem(path).pkg,
      package_ecosystem: pathEcosystem(path).ecosystem,
      poc_body: null,
      tags: [],
      disclosed_at: null,
      authors: [],
    };
  }
  if (!doc || typeof doc !== "object") return { error: `no doc in ${path}` };
  const info = doc.info ?? {};
  const huntrUrl = huntrUrlFromRefs(info.reference);
  if (!huntrUrl) {
    return { error: `no huntr.com reference in ${path}` };
  }
  const huntrId = huntrIdFromUrl(huntrUrl);
  if (!huntrId) return { error: `could not parse huntr id from ${huntrUrl}` };
  const cveId =
    (info.classification?.["cve-id"] || "").toString().trim() || null;
  const cwes = cwesFromClassification(info.classification);
  const tags = (info.tags || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const eco = pathEcosystem(path);
  const poc = pocFromTemplate(doc);
  return {
    cve_id: cveId,
    huntr_id: huntrId,
    huntr_url: huntrUrl,
    title: (info.name || doc.id || huntrId).trim(),
    description: (info.description || "").trim(),
    severity: parseSeverity(info.severity),
    cwe: cwes,
    cvss_score: info.classification?.["cvss-score"] ?? null,
    cvss_metrics: info.classification?.["cvss-metrics"] || null,
    vulnerability_type: tags.join(","),
    package_name: eco.pkg,
    package_ecosystem: eco.ecosystem,
    poc_body: poc,
    tags,
    disclosed_at: null,
    authors: authorsFromInfo(info.author),
  };
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE/HUNTR ids across rules/ and proposals/.
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
  huntrs: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const huntrs = new Set<string>();
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
          references?: { cve?: string[]; huntr_id?: string[] | string };
        }
      )?.references;
      if (refs?.cve)
        for (const c of refs.cve) if (typeof c === "string") cves.add(c);
      if (refs?.huntr_id) {
        const v = refs.huntr_id;
        if (typeof v === "string") huntrs.add(v);
        else if (Array.isArray(v))
          for (const h of v) if (typeof h === "string") huntrs.add(h);
      }
      // Also pick up huntr ids from filename pattern HUNTR-xxxxxxxx.proposal.yaml
      const m = f.match(/HUNTR-[a-f0-9]{8}/i);
      if (m) huntrs.add(m[0]);
    }
  }
  return { cves, huntrs };
}

// ---------------------------------------------------------------------------
// Proposal renderer.
// ---------------------------------------------------------------------------

function renderProposal(b: BountySummary): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const proposalId = b.cve_id ?? b.huntr_id;
  const category = categoryForBounty(b);
  const responseActions =
    b.severity === "critical" || b.severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock = b.cve_id ? `  cve:\n    - "${b.cve_id}"\n` : "";
  const cweBlock =
    b.cwe.length > 0
      ? `  cwe:\n${b.cwe.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const huntrBlock = `  huntr_id:\n    - "${b.huntr_url}"\n`;

  // Embed PoC body as YAML comment lines so the human reviewer can convert
  // it to regex/conditions without re-fetching the source.
  const pocCommentLines =
    b.poc_body
      ?.split("\n")
      .filter((s) => s.trim().length > 0)
      .slice(0, 60)
      .map((s) => `    # ${s}`)
      .join("\n") ?? "";

  // test_cases.true_positives from the PoC (first body block, if present).
  const tpBlock = b.poc_body
    ? `  true_positives:\n    - name: "huntr PoC excerpt"\n      input: |\n${b.poc_body
        .split("\n")
        .slice(0, 30)
        .map((s) => `        ${s}`)
        .join("\n")}\n`
    : `  true_positives: []\n`;

  const title = b.title.replace(/"/g, '\\"').slice(0, 120);
  const desc = `${b.description || b.title}`.replace(/\n+/g, " ").trim();
  const packageNote =
    b.package_ecosystem && b.package_name
      ? `${b.package_ecosystem}:${b.package_name}`
      : b.package_name || "unknown";

  return `# ATR rule proposal -- generated by scripts/sync-huntr.ts
# Source: Huntr.dev bounty disclosure via protectai/ai-exploits (FALLBACK_A)
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. PoC excerpt is
#         attached as a YAML comment under detection.conditions for ease of
#         conversion to a precision-safe regex.
title: "${title}"
id: ATR-DRAFT-${proposalId}
rule_version: 1
status: draft
description: >
  Huntr.dev disclosed AI/ML vulnerability${b.cve_id ? ` (${b.cve_id})` : ""}.
  Affected: ${packageNote}.
  ${desc.slice(0, 600)}
author: "ATR Community (Huntr.dev sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${b.severity}

references:
${cveBlock}${cweBlock}${huntrBlock}  external:
    - "${b.huntr_url}"

metadata_provenance:
  huntr_id: huntr-sync
${b.cve_id ? "  cve: huntr-sync\n" : ""}${b.cwe.length ? "  cwe: huntr-sync\n" : ""}
tags:
  category: ${category}
  subcategory: huntr-imported
  scan_target: mcp
  confidence: high

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
    # TODO(human): convert the Huntr PoC below into precision-safe
    # detection.conditions regex/string matchers. Without this work
    # the rule will neither fire nor be promotable to rules/.
    #
    # === PoC excerpt (from protectai/ai-exploits nuclei template) ===
${pocCommentLines || "    # (no PoC body in source template)"}
    []

response:
  actions:
${responseActions.map((a) => `    - ${a}`).join("\n")}
  notify:
    - security_team

confidence: 70

test_cases:
${tpBlock}  true_negatives:
    # TODO(human): add benign inputs that look similar to the PoC but are
    # legitimate -- required before promoting out of draft.
    []

# === sync-huntr.ts provenance ===
_huntr_sync:
  discovered_by: "Huntr.dev via sync-huntr.ts"
  source: "${b.huntr_url}"
  cve: ${b.cve_id ? `"${b.cve_id}"` : "null"}
  cwe: ${JSON.stringify(b.cwe)}
  package: "${packageNote}"
  version_range: "see vendor advisory"
  cvss_score: ${b.cvss_score ?? "null"}
  cvss_metrics: ${b.cvss_metrics ? `"${b.cvss_metrics.replace(/"/g, '\\"')}"` : "null"}
  vulnerability_type: "${b.vulnerability_type.replace(/"/g, '\\"')}"
  authors: ${JSON.stringify(b.authors)}
  imported_at: "${new Date().toISOString()}"
  huntr_disclosed: ${b.disclosed_at ? `"${b.disclosed_at}"` : "null"}
  data_source_used: "FALLBACK_A protectai/ai-exploits"

# Triage flag read by promote-detection-ready.ts. ai-exploits nuclei
# templates embed the exploit request itself (the PoC payload), so a
# template with a parsed PoC body is detection-ready; the generator lifts
# patterns from poc_body, never from advisory prose.
_triage:
  detection_ready: ${b.poc_body ? "true" : "false"}
  reason: ${
    b.poc_body
      ? '"nuclei PoC payload present in ai-exploits template"'
      : '"no PoC body in source template"'
  }
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  bounties_scanned: number;
  ml_category_count: number;
  new_proposals: number;
  skipped_existing: number;
  scrape_failures: number;
  errors: string[];
  data_source_used: string | null;
  written_files: string[];
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    bounties_scanned: 0,
    ml_category_count: 0,
    new_proposals: 0,
    skipped_existing: 0,
    scrape_failures: 0,
    errors: [],
    data_source_used: null,
    written_files: [],
  };

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  console.error("=== sync-huntr.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);

  // --- PRIMARY: REST/GraphQL API probe ---
  const primary = await tryPrimaryApi();
  if (primary.bounties.length > 0) {
    summary.data_source_used = "PRIMARY";
    console.error(`PRIMARY: ${primary.endpoint} -> ${primary.bounties.length} bounties`);
  } else {
    if (VERBOSE) console.error(`PRIMARY skipped: ${primary.reason}`);
    summary.errors.push(`PRIMARY: ${primary.reason}`);
  }

  // --- FALLBACK_A: protectai/ai-exploits ---
  let bounties: BountySummary[] = primary.bounties.slice();
  let aiExploitsErr: string | null = null;
  if (bounties.length === 0) {
    try {
      const paths = await listAiExploitsYaml();
      console.error(`FALLBACK_A: protectai/ai-exploits -> ${paths.length} yaml templates`);
      for (const p of paths) {
        try {
          const raw = await fetchAiExploitFile(p);
          const parsed = templateToBounty(p, raw);
          if ("error" in parsed) {
            summary.scrape_failures += 1;
            if (VERBOSE) console.error(`  parse-skip ${p}: ${parsed.error}`);
            continue;
          }
          summary.bounties_scanned += 1;
          summary.ml_category_count += 1; // ai-exploits is 100% ml-category
          bounties.push(parsed);
          // Rate limit any direct fetch path (raw.githubusercontent.com is
          // generous, but we honor 1 req/sec for symmetry with the policy).
          await sleep(RATE_LIMIT_MS);
        } catch (e) {
          summary.scrape_failures += 1;
          summary.errors.push(`fetch ${p}: ${(e as Error).message}`);
        }
      }
      if (bounties.length > 0) {
        summary.data_source_used = "FALLBACK_A protectai/ai-exploits";
      }
    } catch (e) {
      aiExploitsErr = (e as Error).message;
      summary.errors.push(`FALLBACK_A: ${aiExploitsErr}`);
    }
  }

  // --- FALLBACK_B: HTML scrape (infeasible) ---
  if (bounties.length === 0) {
    const html = await tryHtmlScrape();
    summary.errors.push(`FALLBACK_B: ${html.reason}`);
  }

  // --- FALLBACK_C: no path available ---
  if (bounties.length === 0) {
    summary.errors.push(
      "FALLBACK_C: No data source available. Manual maintainer intervention " +
        "required -- either (1) wait for Huntr/ProtectAI to ship a public " +
        "API and extend tryPrimaryApi(), (2) point HUNTR_API_KEY at a " +
        "partner API key, or (3) wait for protectai/ai-exploits to publish " +
        "more nuclei templates.",
    );
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::huntr-summary::${JSON.stringify({
        new_proposals: 0,
        bounties_scanned: 0,
        ml_category_count: 0,
        scrape_failures: summary.scrape_failures,
        data_source_used: null,
      })}`,
    );
    process.exit(2);
  }

  // --- write proposals ---
  const known = buildKnownIndex();
  let writtenCount = 0;
  for (const b of bounties) {
    if (writtenCount >= LIMIT) break;
    // Skip bounties without an assigned CVE per task brief.
    if (!b.cve_id) {
      if (VERBOSE)
        console.error(
          `  skip ${b.huntr_id}: no CVE-id yet (per task brief, CVE required)`,
        );
      continue;
    }
    const dedupeKey = b.cve_id;
    if (!FORCE && known.cves.has(dedupeKey)) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-rule ${dedupeKey}: already covered`);
      continue;
    }
    if (!FORCE && known.huntrs.has(b.huntr_id)) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-rule ${b.huntr_id}: already covered`);
      continue;
    }
    const outName = `${b.cve_id ?? b.huntr_id}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.skipped_existing += 1;
      if (VERBOSE) console.error(`  have-proposal ${outPath}`);
      continue;
    }
    const body = renderProposal(b);
    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName}`);
    } else {
      console.error(`  would write ${outName}`);
    }
    summary.new_proposals += 1;
    writtenCount += 1;
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::huntr-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      bounties_scanned: summary.bounties_scanned,
      ml_category_count: summary.ml_category_count,
      skipped_existing: summary.skipped_existing,
      scrape_failures: summary.scrape_failures,
      data_source_used: summary.data_source_used,
    })}`,
  );
}

main().catch((e) => {
  console.error("fatal:", e);
  process.exit(1);
});
