#!/usr/bin/env npx tsx
/**
 * sync-jvn.ts
 *
 * Pulls JPCERT/CC JVN + JVNDB (Japan) AI / agent / LLM / MCP vulnerability
 * entries via the public MyJVN API and emits ATR rule proposals under
 * proposals/jvn/<CVE-id-or-JVNDB-id>.proposal.yaml.
 *
 * WHY JVN  Net-new value over GHSA/NVD is JVNDB's coverage of Japanese /
 * Asian vendor entries and JP-language advisories. The same CVE often lands
 * in JVNDB with a richer (Japanese) description, and some agent-platform
 * vulns (e.g. Flowise CVE-2026-46480, surfaced via the JP keyword for
 * "large language model") appear here cross-indexed against an Asian-market
 * vendor profile that the English-only sources under-weight. CVE-id dedup
 * against rules/ + proposals/ means we never duplicate what GHSA/NVD already
 * covered; what survives is the genuinely net-new entry.
 *
 * SOURCE  MyJVN getVulnOverviewList (no auth):
 *   https://jvndb.jvn.jp/myjvn?method=getVulnOverviewList&feed=hnd&keyword=<kw>
 * Returns RDF/RSS 1.0 XML with sec: + dc: namespaces. Each <item> carries:
 *   - <sec:identifier>JVNDB-YYYY-NNNNNN</sec:identifier>
 *   - <title> (Japanese), <link>, <description> (Japanese prose)
 *   - <sec:references source="CVE" id="CVE-...">  (CVE id, may be 0+)
 *   - <sec:references id="CWE-NNN" title="...">   (CWE id, may be 0+)
 *   - <sec:cpe vendor=".." product="..">          (affected product)
 *   - <sec:cvss score=".." severity="Critical|High|Medium|Low" .. />
 *   - <dc:date>ISO-8601</dc:date>
 *
 * The getVulnDetailInfo endpoint exists but returns an EMPTY VULDEF document
 * for the English feed (totalRes=0) and a wholly different schema; the
 * overview list already contains every field a proposal needs, so this
 * script is overview-only -- no N+1 detail fetches.
 *
 * KEYWORD STRATEGY  MyJVN keyword search matches the JP-language title +
 * description. We loop BOTH English agent/LLM terms (catch English-vendor
 * product names that appear verbatim in JP titles, e.g. "flowise") AND the
 * Japanese equivalents (catch JP-language phrasing, e.g. the LLM term), then
 * merge + dedup by JVNDB id. The recent feed (feed=hnd) is a moving window,
 * so most keywords legitimately return 0 on a quiet day -- that is not an
 * error.
 *
 * SCOPE  ATR detects AGENT-runtime threats (prompt injection, tool/MCP
 * poisoning, context exfiltration, excessive autonomy). We reuse sync-ghsa's
 * agentRelevance() second gate (agent-relevant CWE OR agent-threat keyword)
 * to drop ML-infra / generic-DoS entries that JVN also indexes. We do NOT
 * widen scope with a broad ML package list.
 *
 * XML PARSING  Lightweight regex/string extraction of the RDF <item> blocks
 * -- same fallback approach the other sync scripts use, NO new dependency.
 *
 * Idempotency: skip if the entry's CVE-id OR JVNDB-id already exists in
 * rules/ or proposals/, unless --force. CVE id is the cross-source primary
 * key; JVNDB id is the source-native key.
 *
 * Usage:
 *   npx tsx scripts/sync-jvn.ts                 # dry-run
 *   npx tsx scripts/sync-jvn.ts --write         # write proposals
 *   npx tsx scripts/sync-jvn.ts --force         # overwrite existing
 *   npx tsx scripts/sync-jvn.ts --limit 20
 *   npx tsx scripts/sync-jvn.ts --verbose
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network across ALL keywords, schema mismatch)
 *   2 no data path (every keyword request non-200 / timed out -- recoverable,
 *     daily cron retries tomorrow)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "jvn");

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

const POLITE_UA =
  "ATR-Sync/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";

const MYJVN_BASE = "https://jvndb.jvn.jp/myjvn";
const FETCH_TIMEOUT_MS = 30_000;
// Politeness: serialize keyword requests with a small delay.
const RATE_LIMIT_MS = 800;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// AI / agent / LLM / MCP keywords. English forms catch English-vendor product
// names embedded in JP titles; Japanese forms catch JP-language phrasing.
// Verified live (2026-06-12): "AI", "flowise", and the JP LLM term return
// real items; the rest legitimately return 0 on a quiet recent-feed window.
const KEYWORDS: string[] = [
  // English agent / LLM / framework terms
  "LLM",
  "AI",
  "prompt injection",
  "prompt",
  "agent",
  "MCP",
  "Model Context Protocol",
  "langchain",
  "llama-index",
  "llamaindex",
  "flowise",
  "dify",
  "ollama",
  "vllm",
  "openai",
  "anthropic",
  "RAG",
  "chatbot",
  // Japanese equivalents (JVN keyword search runs against JP title+desc)
  "大規模言語モデル", // large language model
  "大規模言語", // LLM (partial, broader)
  "生成AI", // generative AI
  "人工知能", // artificial intelligence
  "プロンプト", // prompt
  "プロンプトインジェクション", // prompt injection
  "エージェント", // agent
];

// ---------------------------------------------------------------------------
// CWE -> ATR category + agent-relevance gate. Reuse sync-ghsa's mappings
// verbatim so JVN proposals categorize identically to GHSA proposals.
// ---------------------------------------------------------------------------

const CWE_TO_CATEGORY: Record<string, string> = {
  "CWE-94": "model-abuse",
  "CWE-78": "tool-poisoning",
  "CWE-89": "data-poisoning",
  "CWE-77": "tool-poisoning",
  "CWE-79": "context-exfiltration",
  "CWE-22": "context-exfiltration",
  "CWE-918": "tool-poisoning",
  "CWE-502": "model-abuse",
  "CWE-611": "context-exfiltration",
  "CWE-200": "context-exfiltration",
  "CWE-20": "prompt-injection",
  "CWE-863": "privilege-escalation",
  "CWE-862": "privilege-escalation",
  "CWE-601": "tool-poisoning",
  "CWE-1336": "prompt-injection",
};

function guessCategory(cwes: string[]): string {
  for (const c of cwes) {
    if (CWE_TO_CATEGORY[c]) return CWE_TO_CATEGORY[c];
  }
  return "model-abuse";
}

// Agent-relevant CWEs (content-layer threats ATR can detect). Memory-safety /
// availability CWEs are intentionally absent -- those are the kernel-crash /
// DoS entries with no agent-runtime meaning.
const AGENT_RELEVANT_CWES = new Set([
  "CWE-94",
  "CWE-95",
  "CWE-77",
  "CWE-78",
  "CWE-917",
  "CWE-1336",
  "CWE-918",
  "CWE-22",
  "CWE-23",
  "CWE-611",
  "CWE-502",
  "CWE-89",
  "CWE-79",
  "CWE-74",
  "CWE-470",
  "CWE-601",
  "CWE-862",
  "CWE-863",
  "CWE-200",
  "CWE-20",
  // prototype-pollution: dominant agent-platform RCE primitive (Flowise et al.)
  "CWE-1321",
  "CWE-915",
]);

// Agent-threat phrases tested against the lowercased title+description. Because
// JVN descriptions are Japanese, we include both English and JP terms so an
// agent-relevant advisory that lacks a mapped CWE is still kept.
const AGENT_THREAT_KEYWORDS: RegExp[] = [
  /prompt injection/,
  /prompt-injection/,
  /system prompt/,
  /jailbreak/,
  /tool call/,
  /tool-calling/,
  /tool poisoning/,
  /model context protocol/,
  /\bmcp\b/,
  /\bssrf\b/,
  /server-side request/,
  /remote code execution/,
  /\brce\b/,
  /arbitrary code/,
  /code execution/,
  /command injection/,
  /deserializ/,
  /sql injection/,
  /path traversal/,
  /template injection/,
  /prototype pollution/,
  /sandbox escape/,
  /exfiltrat/,
  /untrusted (input|data|manifest|model|content)/,
  // Japanese agent-threat phrasing
  /プロンプトインジェクション/, // prompt injection
  /プロンプト/, // prompt
  /大規模言語/, // large language model
  /生成ai/, // generative AI
  /エージェント/, // agent
  /任意のコード/, // arbitrary code
  /コードインジェクション/, // code injection
  /コマンドインジェクション/, // command injection
  /サーバーサイドリクエスト/, // SSRF
  /パストラバーサル/, // path traversal
  /逆シリアル化|デシリアライズ/, // deserialization
];

// Agent-platform / framework product name signal (matched against CPE
// vendor/product + title). Lets an agent-platform CVE through even if its CWE
// and keywords are generic. agentRelevance() is still the final gate.
const AGENT_PRODUCT_RX =
  /(?:langchain|langgraph|llama[-_ ]?index|llamaindex|flowise|dify|\bn8n\b|ollama|vllm|\bmcp\b|model[-_ ]?context[-_ ]?protocol|fastmcp|crew[-_ ]?ai|autogen|semantic[-_ ]?kernel|pydantic[-_ ]?ai|haystack|dspy|embedchain|litellm|anything[-_ ]?llm|open[-_ ]?webui|\bllm\b|\bai[-_ ]?agent|chatbot|copilot)/i;

interface JvnItem {
  jvndb_id: string;
  title: string; // JP
  link: string;
  description: string; // JP
  cves: string[];
  cwes: string[];
  cpe: { vendor: string | null; product: string | null; uri: string | null };
  severity: "critical" | "high" | "medium" | "low";
  cvss_score: number | null;
  cvss_vector: string | null;
  date: string | null;
}

function agentRelevance(it: JvnItem): { relevant: boolean; reason: string } {
  const hitCwe = it.cwes.find((c) => AGENT_RELEVANT_CWES.has(c));
  if (hitCwe) return { relevant: true, reason: `agent-relevant CWE ${hitCwe}` };
  const haystack = `${it.title}\n${it.description}\n${it.cpe.vendor ?? ""}\n${
    it.cpe.product ?? ""
  }`.toLowerCase();
  const hitKw = AGENT_THREAT_KEYWORDS.find((rx) => rx.test(haystack));
  if (hitKw)
    return { relevant: true, reason: `agent-threat keyword /${hitKw.source}/` };
  const productBlob = `${it.cpe.vendor ?? ""} ${it.cpe.product ?? ""} ${it.title}`;
  if (AGENT_PRODUCT_RX.test(productBlob))
    return { relevant: true, reason: "agent-platform product name" };
  return {
    relevant: false,
    reason: `no agent-relevant CWE/keyword/product (cwes: ${
      it.cwes.join(",") || "none"
    })`,
  };
}

// ---------------------------------------------------------------------------
// Fetch + lightweight RDF/XML parse (regex, no dependency).
// ---------------------------------------------------------------------------

async function fetchWithTimeout(url: string): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, {
      headers: { "User-Agent": POLITE_UA, Accept: "application/xml" },
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(t);
  }
}

function decodeXmlEntities(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(parseInt(d, 10)))
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) =>
      String.fromCodePoint(parseInt(h, 16)),
    )
    .replace(/&amp;/g, "&"); // ampersand last to avoid double-decoding
}

function tagText(block: string, tag: string): string | null {
  // tag like "title" or "sec:identifier" or "dc:date"
  const rx = new RegExp(
    `<${tag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[^>]*>([\\s\\S]*?)</${tag.replace(
      /[.*+?^${}()|[\]\\]/g,
      "\\$&",
    )}>`,
    "i",
  );
  const m = block.match(rx);
  return m ? decodeXmlEntities(m[1].trim()) : null;
}

function attrVal(fragment: string, attr: string): string | null {
  const m = fragment.match(
    new RegExp(`${attr}\\s*=\\s*"([^"]*)"`, "i"),
  );
  return m ? decodeXmlEntities(m[1]) : null;
}

function mapSeverity(
  s: string | null,
): "critical" | "high" | "medium" | "low" {
  const v = (s || "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "high") return "high";
  if (v === "medium") return "medium";
  if (v === "low") return "low";
  return "medium"; // unknown / none -> conservative default
}

// Returns null if XML did not contain a recognizable RDF result document.
function parseOverview(xml: string): JvnItem[] | null {
  if (!/<rdf:RDF[\s>]/i.test(xml)) return null;
  const items: JvnItem[] = [];
  const itemRx = /<item\b[\s\S]*?<\/item>/gi;
  let m: RegExpExecArray | null;
  while ((m = itemRx.exec(xml)) !== null) {
    const block = m[0];
    const jvndbId = tagText(block, "sec:identifier");
    // The "no results" sentinel item has no sec:identifier -- skip it.
    if (!jvndbId || !/^JVNDB-/.test(jvndbId)) continue;

    const title = tagText(block, "title") ?? jvndbId;
    const link = tagText(block, "link") ?? "";
    const description = tagText(block, "description") ?? "";
    const date = tagText(block, "dc:date");

    // CVE refs: <sec:references source="CVE" id="CVE-...">
    const cves: string[] = [];
    const cwes: string[] = [];
    const refRx = /<sec:references\b([^>]*)>/gi;
    let r: RegExpExecArray | null;
    while ((r = refRx.exec(block)) !== null) {
      const frag = r[1];
      const source = attrVal(frag, "source");
      const id = attrVal(frag, "id");
      if (!id) continue;
      if (source && /^CVE$/i.test(source) && /^CVE-/i.test(id)) {
        if (!cves.includes(id)) cves.push(id);
      } else if (/^CWE-\d+$/i.test(id)) {
        if (!cwes.includes(id)) cwes.push(id);
      }
    }

    // CPE: <sec:cpe version=".." vendor=".." product="..">uri</sec:cpe>
    let vendor: string | null = null;
    let product: string | null = null;
    let cpeUri: string | null = null;
    const cpeMatch = block.match(/<sec:cpe\b([^>]*)>([\s\S]*?)<\/sec:cpe>/i);
    if (cpeMatch) {
      vendor = attrVal(cpeMatch[1], "vendor");
      product = attrVal(cpeMatch[1], "product");
      cpeUri = decodeXmlEntities(cpeMatch[2].trim()) || null;
    }

    // CVSS: <sec:cvss score=".." severity=".." vector=".." />
    let severityRaw: string | null = null;
    let cvssScore: number | null = null;
    let cvssVector: string | null = null;
    const cvssMatch = block.match(/<sec:cvss\b([^>]*)\/?>/i);
    if (cvssMatch) {
      severityRaw = attrVal(cvssMatch[1], "severity");
      const sc = attrVal(cvssMatch[1], "score");
      cvssScore = sc !== null && sc !== "" ? Number(sc) : null;
      if (Number.isNaN(cvssScore as number)) cvssScore = null;
      cvssVector = attrVal(cvssMatch[1], "vector");
    }

    items.push({
      jvndb_id: jvndbId,
      title,
      link,
      description,
      cves,
      cwes,
      cpe: { vendor, product, uri: cpeUri },
      severity: mapSeverity(severityRaw),
      cvss_score: cvssScore,
      cvss_vector: cvssVector,
      date,
    });
  }
  return items;
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE / JVNDB ids across rules/ and proposals/.
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
  jvndbs: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const jvndbs = new Set<string>();
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
            jvndb?: string[] | string;
          };
        }
      )?.references;
      if (refs?.cve)
        for (const c of refs.cve) if (typeof c === "string") cves.add(c);
      if (refs?.jvndb) {
        const v = refs.jvndb;
        if (typeof v === "string") jvndbs.add(v);
        else if (Array.isArray(v))
          for (const j of v) if (typeof j === "string") jvndbs.add(j);
      }
      // Also pick up JVNDB ids from filename pattern.
      const fm = f.match(/JVNDB-\d{4}-\d+/i);
      if (fm) jvndbs.add(fm[0]);
    }
  }
  return { cves, jvndbs };
}

// ---------------------------------------------------------------------------
// Detection readiness. JVN descriptions are vendor prose (Japanese), almost
// never a PoC/payload -- so detection_ready is usually false. We still flag
// the rare description that embeds a payload-like signal.
// ---------------------------------------------------------------------------

const PAYLOAD_HEURISTICS_RX = new RegExp(
  ["```", "payload", "curl ", "POST /[a-z]", "<script>", "${", "{{"].join("|"),
  "i",
);

function isDetectionReady(it: JvnItem): { ready: boolean; reason: string } {
  const body = `${it.title}\n${it.description}`;
  if (PAYLOAD_HEURISTICS_RX.test(body))
    return { ready: true, reason: "payload-like content in advisory body" };
  return {
    ready: false,
    reason: "JVN advisory body is vendor prose (no reproducer / payload)",
  };
}

// ---------------------------------------------------------------------------
// Proposal renderer -- field-for-field aligned with sync-huntr / sync-ghsa.
// ---------------------------------------------------------------------------

const ADVISORY_BODY_MAX_CHARS = 8000;

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars; see link for full text)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function renderProposal(it: JvnItem): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const cveId = it.cves[0] ?? null;
  const proposalId = cveId ?? it.jvndb_id;
  const draftIdSuffix = cveId ? cveId.replace(/^CVE-/, "") : it.jvndb_id;
  const category = guessCategory(it.cwes);
  const triage = isDetectionReady(it);

  const responseActions =
    it.severity === "critical" || it.severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock =
    it.cves.length > 0
      ? `  cve:\n${it.cves.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const cweBlock =
    it.cwes.length > 0
      ? `  cwe:\n${it.cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const jvndbBlock = `  jvndb:\n    - "${it.jvndb_id}"\n`;
  const externalBlock = it.link
    ? `  external:\n    - "${it.link}"\n`
    : "";

  const packageNote =
    it.cpe.vendor || it.cpe.product
      ? `${it.cpe.vendor ?? "unknown"}:${it.cpe.product ?? "unknown"}`
      : "unknown";

  const title = it.title.replace(/"/g, '\\"').slice(0, 120);
  const descOneLine = (it.description || it.title)
    .replace(/\n+/g, " ")
    .trim()
    .slice(0, 600);

  return `# ATR rule proposal -- generated by scripts/sync-jvn.ts
# Source: JPCERT/CC JVN / JVNDB ${it.jvndb_id} (MyJVN getVulnOverviewList)
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. The JVN advisory body
#         (Japanese prose) is attached under _jvn_sync.advisory_body so the
#         reviewer can extract attack signal; JVN rarely ships a raw PoC.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${draftIdSuffix}
rule_version: 1
status: draft
description: >
  JPCERT/CC JVNDB advisory ${it.jvndb_id}${cveId ? ` (${cveId})` : ""}.
  Affected: ${packageNote}.
  ${descOneLine}
author: "ATR Community (JVN sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${it.severity}

references:
${cveBlock}${cweBlock}${jvndbBlock}${externalBlock}
metadata_provenance:
  jvndb: jvn-sync
${cveId ? "  cve: jvn-sync\n" : ""}${it.cwes.length ? "  cwe: jvn-sync\n" : ""}
tags:
  category: ${category}
  subcategory: jvn-imported
  scan_target: runtime
  confidence: ${triage.ready ? "high" : "low"}

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
    # TODO(human): convert the JVN advisory signal below into precision-safe
    # detection.conditions regex/string matchers. Empty until promoted to
    # rules/. The full advisory body (Japanese) is under _jvn_sync.advisory_body.
    #
    # === JVN advisory excerpt ===
${
    it.description
      ? it.description
          .split("\n")
          .filter((s) => s.trim().length > 0)
          .slice(0, 20)
          .map((s) => `    # ${s}`)
          .join("\n")
      : "    # (no description in source item)"
  }
    []

response:
  actions:
${responseActions.map((a) => `    - ${a}`).join("\n")}
  notify:
    - security_team

confidence: ${triage.ready ? 70 : 40}

test_cases:
  true_positives: []
  true_negatives: []

# === sync-jvn.ts provenance ===
_jvn_sync:
  jvndb_id: "${it.jvndb_id}"
  cve_ids: ${JSON.stringify(it.cves)}
  cwe_ids: ${JSON.stringify(it.cwes)}
  vendor: ${it.cpe.vendor ? `"${it.cpe.vendor.replace(/"/g, '\\"')}"` : "null"}
  product: ${it.cpe.product ? `"${it.cpe.product.replace(/"/g, '\\"')}"` : "null"}
  cpe: ${it.cpe.uri ? `"${it.cpe.uri.replace(/"/g, '\\"')}"` : "null"}
  severity: "${it.severity}"
  cvss_score: ${it.cvss_score ?? "null"}
  cvss_vector: ${it.cvss_vector ? `"${it.cvss_vector.replace(/"/g, '\\"')}"` : "null"}
  published: ${it.date ? `"${it.date}"` : "null"}
  link: "${it.link}"
  imported_at: "${new Date().toISOString()}"
  data_source_used: "MyJVN getVulnOverviewList feed=hnd"
  advisory_body: |
${indentForLiteralBlock(it.description || "(no body provided by MyJVN item)", "    ")}

# Triage flag read by promote-detection-ready.ts. JVN advisory bodies are
# vendor prose, so detection_ready is usually false; the generator must never
# lift patterns from prose -- only from an explicit payload signal.
_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason}"
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  keywords_queried: number;
  keyword_request_failures: number;
  items_seen: number;
  items_filtered_not_agent: number;
  items_already_known: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  data_source_used: string | null;
  written_files: string[];
  errors: string[];
}

async function main(): Promise<void> {
  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    keywords_queried: 0,
    keyword_request_failures: 0,
    items_seen: 0,
    items_filtered_not_agent: 0,
    items_already_known: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    data_source_used: null,
    written_files: [],
    errors: [],
  };

  console.error("=== sync-jvn.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);

  // --- collect + dedup items across all keyword queries ---
  const byJvndb = new Map<string, JvnItem>();
  for (const kw of KEYWORDS) {
    summary.keywords_queried += 1;
    const url = `${MYJVN_BASE}?method=getVulnOverviewList&feed=hnd&keyword=${encodeURIComponent(
      kw,
    )}`;
    let xml: string;
    try {
      const res = await fetchWithTimeout(url);
      if (!res.ok) {
        summary.keyword_request_failures += 1;
        summary.errors.push(`keyword "${kw}": HTTP ${res.status}`);
        if (VERBOSE) console.error(`  kw "${kw}": HTTP ${res.status}`);
        await sleep(RATE_LIMIT_MS);
        continue;
      }
      xml = await res.text();
    } catch (e) {
      summary.keyword_request_failures += 1;
      summary.errors.push(`keyword "${kw}": ${(e as Error).message}`);
      if (VERBOSE) console.error(`  kw "${kw}": fetch error ${e}`);
      await sleep(RATE_LIMIT_MS);
      continue;
    }

    const parsed = parseOverview(xml);
    if (parsed === null) {
      summary.keyword_request_failures += 1;
      summary.errors.push(`keyword "${kw}": response was not RDF`);
      if (VERBOSE) console.error(`  kw "${kw}": non-RDF response`);
      await sleep(RATE_LIMIT_MS);
      continue;
    }
    if (VERBOSE)
      console.error(`  kw "${kw}": ${parsed.length} item(s)`);
    for (const it of parsed) {
      if (!byJvndb.has(it.jvndb_id)) byJvndb.set(it.jvndb_id, it);
    }
    await sleep(RATE_LIMIT_MS);
  }

  // Every keyword request failed -> no data path (recoverable).
  if (summary.keyword_request_failures === summary.keywords_queried) {
    summary.errors.push(
      "All MyJVN keyword requests failed (non-200 / timeout / non-RDF). " +
        "MyJVN may be down or blocking; daily cron will retry.",
    );
    console.error(JSON.stringify(summary, null, 2));
    console.log(
      `::jvn-summary::${JSON.stringify({
        new_proposals: 0,
        items_seen: 0,
        keyword_request_failures: summary.keyword_request_failures,
        data_source_used: null,
      })}`,
    );
    process.exit(2);
  }

  summary.data_source_used = "MyJVN getVulnOverviewList feed=hnd";
  const items = [...byJvndb.values()];
  summary.items_seen = items.length;
  console.error(
    `collected ${items.length} unique JVNDB item(s) across ${summary.keywords_queried} keyword(s)`,
  );

  // --- gate + write ---
  const known = buildKnownIndex();
  let writtenCount = 0;
  let sampleShown = false;

  for (const it of items) {
    if (writtenCount >= LIMIT) break;

    const rel = agentRelevance(it);
    if (!rel.relevant) {
      summary.items_filtered_not_agent += 1;
      if (VERBOSE)
        console.error(`  skip (not agent) ${it.jvndb_id}: ${rel.reason}`);
      continue;
    }

    const cveId = it.cves[0] ?? null;
    if (!FORCE && cveId && known.cves.has(cveId)) {
      summary.items_already_known += 1;
      if (VERBOSE) console.error(`  have ${cveId}: already covered`);
      continue;
    }
    if (!FORCE && known.jvndbs.has(it.jvndb_id)) {
      summary.items_already_known += 1;
      if (VERBOSE) console.error(`  have ${it.jvndb_id}: already covered`);
      continue;
    }

    const outName = `${cveId ?? it.jvndb_id}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.items_already_known += 1;
      if (VERBOSE) console.error(`  have-proposal ${outPath}`);
      continue;
    }

    const triage = isDetectionReady(it);
    const body = renderProposal(it);

    // Self-verification: parse the first rendered proposal to prove the YAML
    // we emit is loadable (catches indentation / escaping regressions early).
    if (!sampleShown) {
      try {
        const loaded = yaml.load(body) as Record<string, unknown>;
        if (!loaded || typeof loaded !== "object" || !loaded.id)
          throw new Error("rendered proposal missing id");
        console.error(
          `  [self-check] sample proposal for ${outName} parses OK (id=${loaded.id}, severity=${loaded.severity})`,
        );
        if (VERBOSE) console.error(body);
      } catch (e) {
        console.error(`fatal: rendered proposal failed to parse: ${e}`);
        process.exit(1);
      }
      sampleShown = true;
    }

    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;

    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName}`);
    } else {
      console.error(`  would write ${outName}`);
    }
    writtenCount += 1;
  }

  console.error(JSON.stringify(summary, null, 2));
  console.log(
    `::jvn-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      items_seen: summary.items_seen,
      items_filtered_not_agent: summary.items_filtered_not_agent,
      items_already_known: summary.items_already_known,
      keywords_queried: summary.keywords_queried,
      keyword_request_failures: summary.keyword_request_failures,
      data_source_used: summary.data_source_used,
    })}`,
  );
}

// Run if invoked as a script (not when imported as a module for tests).
const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}
