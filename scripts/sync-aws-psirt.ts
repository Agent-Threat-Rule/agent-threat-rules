#!/usr/bin/env npx tsx
/**
 * sync-aws-psirt.ts
 *
 * Pulls AWS Security Bulletins (AWS PSIRT) and emits ATR rule proposals under
 * proposals/aws-psirt/<CVE-or-AWS-id>.proposal.yaml.
 *
 * Why AWS PSIRT matters for ATR: AWS now publishes agent-runtime CVEs directly
 * in its security bulletins. As of 2026-06 the live feed already carries, among
 * other agent/AI bulletins:
 *   - AWS-2025-019  Prompt Injection in Kiro and Q Developer IDE plugins
 *   - CVE-2026-4270 AWS API MCP Server file-access restriction bypass
 *   - CVE-2026-9255 Tool execution without authorization via piped stdin (Kiro CLI)
 *   - CVE-2026-0830 Command injection in Kiro GitLab Merge Request Helper
 *   - CVE-2026-4269 Improper S3 ownership verification in Bedrock AgentCore Starter Toolkit
 *   - CVE-2026-8596/8597 SageMaker Python SDK model-artifact integrity (borderline ML)
 *
 * Data source (NO AUTH required):
 *   RSS  https://aws.amazon.com/security/security-bulletins/rss/feed/
 *        (confirmed live 2026-06, HTTP 200, ~61 items). Each <item> carries
 *        <title>, <link>, <guid> (a content SHA, NOT the bulletin id),
 *        <description> (HTML-encoded — this is the FULL bulletin body, so we do
 *        not need to fetch each per-bulletin page), <pubDate>, <category>,
 *        <author>. The bulletin id ("AWS-YYYY-NNN" or "YYYY-NNN-AWS") lives in
 *        the body's "Bulletin ID:" field and the <link> path; CVE ids are in the
 *        title and body text.
 *
 *   Per-bulletin page fetch: only used as a fallback when the RSS <description>
 *   is empty/truncated, since the RSS description already mirrors the page body.
 *
 * Scope discipline (mirrors sync-ghsa.ts — DO NOT widen ATR scope):
 *   ATR detects AGENT-runtime threats (prompt injection / tool·MCP poisoning /
 *   context exfiltration / excessive autonomy). Two gates:
 *     1. AWS-AI-SERVICE keyword set (Bedrock / SageMaker / Q / AgentCore / Kiro /
 *        MCP / "AI agent" ...) on title+body.
 *     2. The shared agentRelevance() gate imported from sync-ghsa.ts (agent CWE
 *        OR agent-threat keyword) so a non-agent AWS-AI bulletin (e.g. a pure
 *        SageMaker training-infra DoS) is dropped.
 *   SageMaker Python SDK CVEs are BORDERLINE ML (model-artifact integrity, not an
 *   agent-runtime threat) — kept only if they pass agentRelevance(), and flagged
 *   in the proposal note (`_aws_psirt_sync.scope_note`).
 *
 * Idempotency: skip if the CVE id OR the AWS bulletin id already exists in
 * rules/ or any proposals/ subtree, unless --force. CVE id is the cross-source
 * primary key.
 *
 * Usage:
 *   npx tsx scripts/sync-aws-psirt.ts                 # dry-run
 *   npx tsx scripts/sync-aws-psirt.ts --write         # write proposals
 *   npx tsx scripts/sync-aws-psirt.ts --force         # overwrite existing
 *   npx tsx scripts/sync-aws-psirt.ts --verbose
 *   npx tsx scripts/sync-aws-psirt.ts --limit 5
 *
 * Secret discipline: this source needs NO auth. There is no API key and no
 * --key arg. A non-200 / timeout on the RSS feed is a no-data path -> exit 2.
 *
 * Exit codes:
 *   0 success
 *   1 fatal (unexpected error, schema mismatch)
 *   2 no data path (RSS non-200 / timeout / empty feed) — recoverable, cron retries
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

// Reuse the battle-tested agent-relevance gate + CWE→category map from sync-ghsa.
import { agentRelevance } from "./sync-ghsa.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const RULES_DIR = resolve(REPO_ROOT, "rules");
const PROPOSALS_BASE = resolve(REPO_ROOT, "proposals");
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "aws-psirt");

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

const RSS_URL =
  "https://aws.amazon.com/security/security-bulletins/rss/feed/";
const FETCH_TIMEOUT_MS = 30_000;
const POLITE_UA =
  "ATR-Sync/1.0 (+https://github.com/Agent-Threat-Rule/agent-threat-rules)";

// ---------------------------------------------------------------------------
// AWS AI/agent service keyword gate (gate #1). Tokens chosen to specifically
// indicate an AGENT / GenAI surface, not generic AWS infra. "Amazon Q" / "Q
// Developer" / Kiro (the Q-powered agentic IDE) / AgentCore / MCP are the
// strongest agent signals; Bedrock + SageMaker are GenAI/ML platforms (SageMaker
// is borderline ML, kept only if agentRelevance also passes).
// ---------------------------------------------------------------------------
const AWS_AI_SERVICE_RX: RegExp[] = [
  /\bbedrock\b/i,
  /\bagentcore\b/i,
  /\bsagemaker\b/i,
  /amazon q\b/i,
  /\bq developer\b/i,
  /\bkiro\b/i, // AWS's agentic IDE (Q-powered)
  /model context protocol/i,
  /\bmcp\b/i,
  /\bai assistant/i,
  /\bai[- ]agent/i,
  /\bgenai\b/i,
  /generative ai/i,
  /\bqnabot\b/i, // QnABot on AWS — Lex/Bedrock conversational bot
  /\bamazon lex\b/i,
];

function awsAiServiceHit(text: string): string | null {
  for (const rx of AWS_AI_SERVICE_RX) {
    if (rx.test(text)) return rx.source;
  }
  return null;
}

// SageMaker SDK = borderline ML (model-artifact / training infra). Flag it so
// the human reviewer knows it is at the edge of ATR scope even when it passes
// the agentRelevance() gate.
function isBorderlineMl(text: string): boolean {
  return /\bsagemaker\b/i.test(text) && !/\bagent|\bmcp\b|prompt injection/i.test(text);
}

// ---------------------------------------------------------------------------
// Shared CWE → ATR category map (kept local to avoid changing sync-ghsa exports;
// mirrors sync-ghsa.ts CWE_TO_CATEGORY exactly). Fallback per contract:
// "model-abuse".
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

function guessCategory(cwes: string[], body: string): string {
  for (const c of cwes) if (CWE_TO_CATEGORY[c]) return CWE_TO_CATEGORY[c];
  // Text fallback when AWS bulletins carry no CWE (most do not).
  const h = body.toLowerCase();
  if (/prompt[- ]injection|jailbreak/.test(h)) return "prompt-injection";
  if (/tool (execution|invocation|call)|without (authorization|confirmation)|excessive|autonom/.test(h))
    return "excessive-agency";
  if (/\bmcp\b|tool poisoning|command injection|\brce\b|remote code execution|arbitrary code|sandbox/.test(h))
    return "tool-poisoning";
  if (/ssrf|server[- ]side request|path traversal|file (access|read)|exfiltrat|information disclosure/.test(h))
    return "context-exfiltration";
  if (/authoriz|authentic|privilege|ownership verification/.test(h))
    return "privilege-escalation";
  return "model-abuse";
}

// ---------------------------------------------------------------------------
// RSS parsing (regex / string extraction — no new dependency).
// ---------------------------------------------------------------------------

interface AwsBulletin {
  bulletin_id: string; // AWS-YYYY-NNN or YYYY-NNN-AWS
  title: string;
  link: string;
  body: string; // de-HTML'd plain text
  raw_description: string; // HTML-decoded but tags intact (for provenance)
  cve_ids: string[];
  cwe_ids: string[];
  pub_date: string | null;
  severity: "critical" | "high" | "medium" | "low";
  category_hint: string | null;
}

function decodeEntities(s: string): string {
  // Two-pass: the AWS feed double-encodes some entities (e.g. &amp;amp;).
  const pass = (t: string) =>
    t
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, '"')
      .replace(/&#0?39;/g, "'")
      .replace(/&#x27;/gi, "'")
      .replace(/&apos;/g, "'")
      .replace(/&nbsp;/g, " ")
      .replace(/&amp;/g, "&");
  return pass(pass(s));
}

function stripCdata(s: string): string {
  const m = s.match(/^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/);
  return m ? m[1] : s;
}

function tagText(itemXml: string, tag: string): string {
  const m = itemXml.match(new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "i"));
  return m ? stripCdata(m[1]).trim() : "";
}

function extractCves(text: string): string[] {
  const set = new Set<string>();
  const rx = /CVE-\d{4}-\d{4,7}/gi;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(text))) set.add(m[0].toUpperCase());
  return [...set];
}

function extractCwes(text: string): string[] {
  const set = new Set<string>();
  const rx = /CWE-\d{1,5}/gi;
  let m: RegExpExecArray | null;
  while ((m = rx.exec(text))) set.add(m[0].toUpperCase());
  return [...set];
}

// Bulletin id: prefer body "Bulletin ID:" field, fall back to the <link> path.
function extractBulletinId(body: string, link: string): string | null {
  const inBody = body.match(/Bulletin ID:\s*([A-Za-z0-9-]+)/i);
  if (inBody) return inBody[1].toUpperCase();
  // link paths look like .../rss/2026-007-aws/ or .../rss/aws-2025-019/
  const inLink = link.match(/\/((?:aws-)?\d{4}-\d{1,4}(?:-aws)?)\/?$/i);
  if (inLink) return inLink[1].toUpperCase();
  return null;
}

// AWS "Content Type" maps loosely to severity:
//   Critical -> critical; Important -> high; everything else -> medium.
function severityFromBody(
  body: string,
): "critical" | "high" | "medium" | "low" {
  const m = body.match(/Content Type:\s*([A-Za-z]+)/i);
  const v = (m ? m[1] : "").toLowerCase();
  if (v === "critical") return "critical";
  if (v === "important") return "high";
  if (v === "low") return "low";
  return "medium";
}

function htmlToText(html: string): string {
  return html
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>/gi, "\n")
    .replace(/<\/li>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function parseRss(xml: string): AwsBulletin[] {
  const items = xml.match(/<item>[\s\S]*?<\/item>/gi) ?? [];
  const out: AwsBulletin[] = [];
  for (const item of items) {
    const title = decodeEntities(tagText(item, "title"));
    const link = tagText(item, "link");
    const descRaw = decodeEntities(tagText(item, "description"));
    const pubDate = tagText(item, "pubDate") || null;
    const categoryHint = decodeEntities(tagText(item, "category")) || null;
    if (!title && !descRaw) continue;
    const body = htmlToText(descRaw);
    const searchText = `${title}\n${body}`;
    const bulletinId = extractBulletinId(body, link);
    if (!bulletinId) {
      if (VERBOSE)
        console.error(`  parse-skip: no bulletin id for "${title.slice(0, 60)}"`);
      continue;
    }
    out.push({
      bulletin_id: bulletinId,
      title,
      link,
      body,
      raw_description: descRaw,
      cve_ids: extractCves(searchText),
      cwe_ids: extractCwes(searchText),
      pub_date: pubDate,
      severity: severityFromBody(body),
      category_hint: categoryHint,
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Per-bulletin page fetch (fallback only — RSS description is normally complete).
// ---------------------------------------------------------------------------
async function fetchBulletinPage(url: string): Promise<string | null> {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    const res = await fetch(url, {
      headers: { "User-Agent": POLITE_UA },
      signal: controller.signal,
    });
    clearTimeout(t);
    if (!res.ok) return null;
    const html = await res.text();
    return htmlToText(html);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Idempotency index across rules/ and proposals/ — CVE ids + AWS bulletin ids.
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
  awsIds: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const awsIds = new Set<string>();
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
          references?: { cve?: string[]; aws_bulletin?: string[] | string };
        }
      )?.references;
      if (refs?.cve)
        for (const c of refs.cve)
          if (typeof c === "string") cves.add(c.toUpperCase());
      if (refs?.aws_bulletin) {
        const v = refs.aws_bulletin;
        if (typeof v === "string") awsIds.add(v.toUpperCase());
        else if (Array.isArray(v))
          for (const a of v)
            if (typeof a === "string") awsIds.add(a.toUpperCase());
      }
      // Also pick up the bulletin id from the proposal filename.
      const m = f.match(/((?:aws-)?\d{4}-\d{1,4}(?:-aws)?)\.proposal\.ya?ml$/i);
      if (m) awsIds.add(m[1].toUpperCase());
    }
  }
  return { cves, awsIds };
}

// ---------------------------------------------------------------------------
// Detection-readiness triage (same spirit as sync-ghsa.ts isDetectionReady).
// AWS bulletins are mostly prose; detection_ready is usually false.
// ---------------------------------------------------------------------------
const PAYLOAD_HEURISTICS_RX = new RegExp(
  [
    "```",
    "Proof of Concept",
    "Reproducer",
    "payload:",
    "curl ",
    "POST /",
    "<script>",
    "find\\s|grep\\s|echo\\s", // the Kiro/Q PoC uses find/grep/echo commands
    "stdin",
  ].join("|"),
  "im",
);

function isDetectionReady(b: AwsBulletin): { ready: boolean; reason: string } {
  if (PAYLOAD_HEURISTICS_RX.test(b.body))
    return { ready: true, reason: "payload-like content in bulletin body" };
  return {
    ready: false,
    reason: "AWS bulletin is prose-only (no reproducer / payload block)",
  };
}

// ---------------------------------------------------------------------------
// Proposal renderer (逐欄 aligned with sync-huntr / sync-ghsa renderProposal).
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

function proposalId(b: AwsBulletin): string {
  // CVE id is the cross-source primary key; fall back to the AWS bulletin id.
  return b.cve_ids[0] ?? b.bulletin_id;
}

function renderProposal(b: AwsBulletin): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const pid = proposalId(b);
  const category = guessCategory(b.cwe_ids, `${b.title}\n${b.body}`);
  const triage = isDetectionReady(b);
  const borderline = isBorderlineMl(`${b.title}\n${b.body}`);

  const responseActions =
    b.severity === "critical" || b.severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock =
    b.cve_ids.length > 0
      ? `  cve:\n${b.cve_ids.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const cweBlock =
    b.cwe_ids.length > 0
      ? `  cwe:\n${b.cwe_ids.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const awsBlock = `  aws_bulletin:\n    - "${b.bulletin_id}"\n`;

  const title = b.title.replace(/"/g, '\\"').slice(0, 120);
  const desc = b.body.replace(/\n+/g, " ").trim().slice(0, 600);

  return `# ATR rule proposal -- generated by scripts/sync-aws-psirt.ts
# Source: AWS Security Bulletin ${b.bulletin_id}
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. The full AWS bulletin
#         body is attached under _aws_psirt_sync.advisory_body for conversion to
#         precision-safe matchers.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${pid}
rule_version: 1
status: draft
description: >
  AWS Security Bulletin ${b.bulletin_id}${b.cve_ids.length ? ` (${b.cve_ids.join(", ")})` : ""}.
  ${desc}
author: "ATR Community (AWS PSIRT sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${b.severity}

references:
${cveBlock}${cweBlock}${awsBlock}  external:
    - "${b.link}"

metadata_provenance:
  aws_psirt: aws-psirt-sync
${b.cve_ids.length ? "  cve: aws-psirt-sync\n" : ""}${b.cwe_ids.length ? "  cwe: aws-psirt-sync\n" : ""}
tags:
  category: ${category}
  subcategory: aws-psirt-imported
  scan_target: runtime
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
    # TODO(human): convert the AWS bulletin body (see
    # _aws_psirt_sync.advisory_body) into precision-safe detection.conditions
    # regex/string matchers. Empty until a human reviewer promotes to rules/.
    []

response:
  actions:
${responseActions.map((a) => `    - ${a}`).join("\n")}
  notify:
    - security_team

test_cases:
  true_positives: []
  true_negatives: []

# === sync-aws-psirt.ts provenance ===
_aws_psirt_sync:
  bulletin_id: "${b.bulletin_id}"
  cve_ids: ${JSON.stringify(b.cve_ids)}
  cwe_ids: ${JSON.stringify(b.cwe_ids)}
  severity: "${b.severity}"
  published: ${b.pub_date ? `"${b.pub_date.replace(/"/g, '\\"')}"` : "null"}
  link: "${b.link}"
  scope_note: ${
    borderline
      ? '"BORDERLINE ML: SageMaker SDK (model/training infra) — at the edge of ATR agent-runtime scope; human reviewer should confirm agent relevance before promotion."'
      : '"agent-runtime relevant"'
  }
  data_source_used: "RSS https://aws.amazon.com/security/security-bulletins/rss/feed/"
  imported_at: "${new Date().toISOString()}"
  advisory_body: |
${indentForLiteralBlock(b.body || "(no body in RSS description)", "    ")}

# Triage flag read by promote-detection-ready.ts. AWS bulletins are usually
# prose; the generator may only crystallize a rule when the body carries a
# concrete payload (e.g. the find/grep/echo prompt-injection commands).
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
  bulletins_seen: number;
  ai_service_hits: number;
  filtered_not_agent: number;
  borderline_ml: number;
  already_known: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  written_files: string[];
  errors: string[];
}

async function fetchRss(): Promise<string | null> {
  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    const res = await fetch(RSS_URL, {
      headers: { "User-Agent": POLITE_UA, Accept: "application/rss+xml, text/xml" },
      signal: controller.signal,
    });
    clearTimeout(t);
    if (!res.ok) {
      console.error(`RSS non-200: ${res.status} ${res.statusText}`);
      return null;
    }
    return await res.text();
  } catch (e) {
    console.error(`RSS fetch failed: ${(e as Error).message}`);
    return null;
  }
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    bulletins_seen: 0,
    ai_service_hits: 0,
    filtered_not_agent: 0,
    borderline_ml: 0,
    already_known: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    written_files: [],
    errors: [],
  };

  console.error("=== sync-aws-psirt.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);

  const xml = await fetchRss();
  if (xml === null) {
    // No-data path — recoverable. Per secret/contract discipline -> exit 2.
    summary.errors.push("RSS feed unavailable (non-200 / timeout).");
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::aws-psirt-summary::${JSON.stringify({
        new_proposals: 0,
        bulletins_seen: 0,
        ai_service_hits: 0,
        data_source_used: null,
      })}`,
    );
    process.exit(2);
  }

  const bulletins = parseRss(xml);
  summary.bulletins_seen = bulletins.length;
  if (bulletins.length === 0) {
    summary.errors.push("RSS parsed but contained zero bulletins.");
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::aws-psirt-summary::${JSON.stringify({
        new_proposals: 0,
        bulletins_seen: 0,
        ai_service_hits: 0,
        data_source_used: null,
      })}`,
    );
    process.exit(2);
  }
  console.error(`RSS: parsed ${bulletins.length} bulletins`);

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  const known = buildKnownIndex();
  let writtenCount = 0;

  for (const b of bulletins) {
    if (writtenCount >= LIMIT) break;
    const searchText = `${b.title}\n${b.body}`;

    // Gate #1 — AWS AI/agent service keyword.
    const svc = awsAiServiceHit(searchText);
    if (!svc) {
      if (VERBOSE)
        console.error(`  skip (not AI svc) ${b.bulletin_id}: ${b.title.slice(0, 50)}`);
      continue;
    }
    summary.ai_service_hits += 1;

    // Gate #2 — shared agentRelevance() from sync-ghsa (agent CWE OR keyword).
    const relevance = agentRelevance({
      summary: b.title,
      description: b.body,
      cwes: b.cwe_ids.map((c) => ({ cwe_id: c })),
    });
    if (!relevance.relevant) {
      summary.filtered_not_agent += 1;
      if (VERBOSE)
        console.error(`  skip (not agent) ${b.bulletin_id}: ${relevance.reason}`);
      continue;
    }

    if (isBorderlineMl(searchText)) summary.borderline_ml += 1;

    // Dedup: CVE id OR AWS bulletin id already known.
    const cveHit = b.cve_ids.find((c) => known.cves.has(c));
    if (!FORCE && cveHit) {
      summary.already_known += 1;
      if (VERBOSE) console.error(`  have-rule ${cveHit}: already covered`);
      continue;
    }
    if (!FORCE && known.awsIds.has(b.bulletin_id)) {
      summary.already_known += 1;
      if (VERBOSE)
        console.error(`  have-rule ${b.bulletin_id}: already covered`);
      continue;
    }

    const outName = `${proposalId(b)}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.already_known += 1;
      if (VERBOSE) console.error(`  have-proposal ${outName}`);
      continue;
    }

    // RSS description is normally the full body; only fall back to the page
    // fetch if the body looks empty/truncated.
    if (b.body.length < 80 && b.link) {
      const page = await fetchBulletinPage(b.link);
      if (page && page.length > b.body.length) b.body = page;
    }

    const triage = isDetectionReady(b);
    const body = renderProposal(b);

    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName}`);
    } else {
      console.error(`  would write ${outName} [${b.cve_ids.join(",") || b.bulletin_id}]`);
      if (VERBOSE) {
        // Parse-check one rendered proposal so dry-run proves YAML validity.
        try {
          yaml.load(body);
          console.error(`    (yaml.load OK, ${body.length} bytes)`);
        } catch (e) {
          summary.errors.push(`yaml.load failed for ${outName}: ${(e as Error).message}`);
          console.error(`    YAML PARSE ERROR: ${(e as Error).message}`);
        }
      }
    }
    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;
    writtenCount += 1;
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::aws-psirt-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      bulletins_seen: summary.bulletins_seen,
      ai_service_hits: summary.ai_service_hits,
      filtered_not_agent: summary.filtered_not_agent,
      borderline_ml: summary.borderline_ml,
      already_known: summary.already_known,
      data_source_used: "RSS",
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
