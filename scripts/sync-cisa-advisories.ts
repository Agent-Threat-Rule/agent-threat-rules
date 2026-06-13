#!/usr/bin/env npx tsx
/**
 * sync-cisa-advisories.ts
 *
 * Pulls the *full* CISA Cybersecurity Advisories stream (NOT just the KEV
 * catalog, which sync-cisa-kev.ts already crawls) and emits ATR rule
 * proposals under proposals/cisa-advisories/<id>.proposal.yaml.
 *
 * Data source -- the machine-readable RSS feed behind
 * https://www.cisa.gov/news-events/cybersecurity-advisories :
 *
 *   https://www.cisa.gov/cybersecurity-advisories/all.xml
 *
 * Verified 2026-06-12: HTTP 200, application/rss+xml, ~320 KB, 30 items
 * (rolling window of the most recent advisories across all CISA advisory
 * types -- ICS advisories `icsa-YY-NNN-NN`, alerts `/alerts/YYYY/MM/DD/slug`,
 * binding operational directives `bod-YY-NN-...`, ICS medical advisories).
 * Each <item> carries <title>, <link>, <description> (HTML body, often with
 * a CVSS table, a "Background / Critical Infrastructure Sectors" block, and
 * one-or-more CVE references) and <pubDate>. There is per-advisory CSAF JSON
 * (linked from the body) but no single all-advisories JSON firehose, so the
 * RSS feed is the source we use; CVE-IDs are extracted from the body with a
 * bounded regex.
 *
 * SCOPE (hard, per ATR doctrine -- see scripts/sync-ghsa.ts AI_PACKAGES note):
 * ATR detects AGENT-runtime threats (prompt injection, tool/MCP poisoning,
 * context exfiltration, excessive autonomy). The CISA advisory stream is
 * overwhelmingly ICS / OT / SCADA / enterprise IT and has essentially ZERO
 * agent-runtime content. We therefore apply TWO hard gates before keeping
 * anything:
 *   (1) an AI/agent/LLM/MCP inclusion filter (title+body must mention an
 *       agent-runtime concept), and
 *   (2) an ICS/OT/SCADA exclusion filter (drop anything that is an ICS
 *       advisory or whose body is dominated by OT/control-system context).
 * Expect FEW or ZERO hits on any given day. That is the honest, correct
 * outcome -- this source exists to catch the rare CISA advisory that lands
 * squarely in agent-runtime territory, not to manufacture volume.
 *
 * Dedup: the primary key is the CVE-ID (shared across all sync-* sources),
 * with the CISA advisory id as a secondary key. We dedup against rules/ AND
 * the entire proposals/ tree -- *including* proposals/cisa-kev/ -- so a CVE
 * already imported from the KEV catalog is never re-imported here.
 *
 * Each proposal:
 *   - id: CVE-id when one is present, else the CISA advisory id
 *     (icsa-... / aa... / bod-... derived from the link slug).
 *   - status=draft, maturity=experimental, empty detection.conditions[].
 *   - The advisory body is preserved verbatim under
 *     _cisa_advisories_sync.advisory_body for promote-detection-ready.ts.
 *   - detection_ready is usually false: CISA advisory prose rarely carries a
 *     copy-pasteable payload, so the human reviewer must author conditions.
 *
 * Usage:
 *   npx tsx scripts/sync-cisa-advisories.ts                 # dry-run
 *   npx tsx scripts/sync-cisa-advisories.ts --write         # write proposals
 *   npx tsx scripts/sync-cisa-advisories.ts --force         # overwrite existing
 *   npx tsx scripts/sync-cisa-advisories.ts --verbose
 *   npx tsx scripts/sync-cisa-advisories.ts --limit 5
 *
 * Exit codes:
 *   0 success
 *   1 fatal (network, schema mismatch)
 *   2 no usable feed (recoverable -- feed moved / unreachable)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "cisa-advisories");

const CISA_ADVISORIES_FEED =
  "https://www.cisa.gov/cybersecurity-advisories/all.xml";
const CISA_HTML_INDEX =
  "https://www.cisa.gov/news-events/cybersecurity-advisories";

const POLITE_UA =
  "ATR-Sync/1.0 (https://github.com/Agent-Threat-Rule/agent-threat-rules)";

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

// ---------------------------------------------------------------------------
// AI / agent inclusion gate (HARD). Title+body must mention an agent-runtime
// concept. Mirrors the keyword sets in sync-ghsa.ts / sync-cisa-kev.ts but is
// strict about ambiguous tokens: bare "agent" false-matches "user agent",
// "Exim Mail Transfer Agent", "Backup Exec Agent" etc., so it is only kept in
// the qualified forms "ai agent" / "llm agent" / "autonomous agent".
// ---------------------------------------------------------------------------
const AI_INCLUDE_RX: RegExp[] = [
  /\bllm\b/i,
  /large language model/i,
  /generative ai/i,
  /\bgen[- ]?ai\b/i,
  /\bai[- ]agent/i,
  /\bllm[- ]agent/i,
  /autonomous agent/i,
  /agentic/i,
  /agent framework/i,
  /prompt injection/i,
  /prompt[- ]injection/i,
  /system prompt/i,
  /jailbreak/i,
  /tool poisoning/i,
  /tool[- ]calling/i,
  /model context protocol/i,
  /\bmcp\b/i,
  /retrieval[- ]augmented/i,
  /vector (store|database|embedding)/i,
  /langchain/i,
  /llama[- ]?index/i,
  /semantic[- ]kernel/i,
  /\bcrew[- ]?ai\b/i,
  /autogen/i,
  /\bcopilot\b/i,
  /chatbot/i,
  /chatgpt/i,
  /\bclaude\b/i,
  /\bollama\b/i,
  /skill\.md/i,
  /claude\.md/i,
];

// ---------------------------------------------------------------------------
// ICS / OT / SCADA exclusion gate (HARD). Even if an ICS advisory body happens
// to contain an AI keyword (e.g. a vendor blurb), it is out of ATR scope. We
// drop anything that is an ICS-advisory by id OR whose body is dominated by
// OT / control-system context.
// ---------------------------------------------------------------------------
const ICS_ID_RX = /^(?:icsa|icsma)-/i; // icsa-26-162-01, icsma-... (medical ICS)
const ICS_EXCLUDE_RX: RegExp[] = [
  /\bICS\b/,
  /\bOT\b/,
  /\bSCADA\b/i,
  /industrial control system/i,
  /operational technology/i,
  /critical infrastructure sector/i,
  /\bPLC\b/,
  /programmable logic controller/i,
  /\bHMI\b/,
  /human[- ]machine interface/i,
  /\bRTU\b/,
  /\bDCS\b/,
  /control system/i,
  /\bModbus\b/i,
  /\bDNP3\b/i,
  /\bBACnet\b/i,
  /\bMQTT\b/i,
  /substation/i,
  /\bPDU\b/,
];

function isAiRelevant(text: string): { match: boolean; reason: string } {
  const rx = AI_INCLUDE_RX.find((r) => r.test(text));
  if (rx) return { match: true, reason: `AI keyword /${rx.source}/` };
  return { match: false, reason: "no AI/agent/LLM/MCP signal" };
}

function isIcsOt(
  advisoryId: string,
  text: string,
): { excluded: boolean; reason: string } {
  if (ICS_ID_RX.test(advisoryId))
    return { excluded: true, reason: `ICS advisory id ${advisoryId}` };
  const rx = ICS_EXCLUDE_RX.find((r) => r.test(text));
  if (rx) return { excluded: true, reason: `ICS/OT marker /${rx.source}/` };
  return { excluded: false, reason: "" };
}

// ---------------------------------------------------------------------------
// CWE -> ATR category (aligned with sync-ghsa.ts CWE_TO_CATEGORY; fallback
// "model-abuse"). CISA advisories rarely expose a structured CWE, so this is
// best-effort over any CWE-IDs found in the body text.
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
  for (const c of cwes) if (CWE_TO_CATEGORY[c]) return CWE_TO_CATEGORY[c];
  return "model-abuse";
}

// ---------------------------------------------------------------------------
// RSS parsing. The feed is small (~30 items); a bounded regex parser avoids
// pulling in an XML dependency, matching the no-new-deps constraint other
// sync-* scripts honor. We extract <item> blocks then pull title/link/
// description/pubDate from each.
// ---------------------------------------------------------------------------
interface CisaAdvisory {
  advisory_id: string; // slug-derived: icsa-26-162-01, aa26-..., bod-..., or alert slug
  title: string;
  link: string;
  pub_date: string | null;
  body_html: string; // raw (entity-decoded) description HTML
  body_text: string; // tag-stripped plaintext for filtering + provenance
  cves: string[];
  cwes: string[];
  advisory_kind: string; // ics-advisories | alerts | directives | ics-medical-advisories | other
}

function decodeEntities(s: string): string {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#0?39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&");
}

function stripCdata(s: string): string {
  return s.replace(/^<!\[CDATA\[/, "").replace(/\]\]>$/, "");
}

function htmlToText(html: string): string {
  return decodeEntities(html)
    .replace(/<\/(p|div|li|tr|h[1-6]|table|ul|ol)>/gi, "\n")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function pickTag(block: string, tag: string): string | null {
  const m = block.match(
    new RegExp(`<${tag}[^>]*>([\\s\\S]*?)</${tag}>`, "i"),
  );
  if (!m) return null;
  return stripCdata(m[1]).trim();
}

// Advisory id + kind from a CISA news-events link.
// .../news-events/ics-advisories/icsa-26-162-01      -> icsa-26-162-01
// .../news-events/alerts/2026/06/11/cisa-adds-one... -> aa-2026-06-11-cisa-adds-one... (slug)
// .../news-events/directives/bod-26-04-...           -> bod-26-04-...
function advisoryIdFromLink(link: string): {
  id: string;
  kind: string;
} {
  const m = link.match(/news-events\/([a-z0-9-]+)\/(.+?)\/?$/i);
  if (!m) {
    // Fallback: last path segment.
    const seg = link.replace(/\/+$/, "").split("/").pop() || "cisa-advisory";
    return { id: slugify(seg), kind: "other" };
  }
  const kind = m[1];
  const rest = m[2].replace(/\/+$/, "");
  // For ics / directives the id is the final slug segment.
  const last = rest.split("/").pop() || rest;
  if (/^(icsa|icsma|bod|ed|aa)/i.test(last)) {
    return { id: last.toLowerCase(), kind };
  }
  // Alerts use date-path slugs; build a stable id prefixed with the kind.
  return { id: slugify(`${kind}-${rest.replace(/\//g, "-")}`), kind };
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^\w]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

const CVE_RX = /\bCVE-\d{4}-\d{4,7}\b/g;
const CWE_RX = /\bCWE-\d{1,5}\b/g;

function uniq(arr: string[]): string[] {
  return Array.from(new Set(arr));
}

export function parseFeed(xml: string): CisaAdvisory[] {
  const items: CisaAdvisory[] = [];
  const itemRx = /<item>([\s\S]*?)<\/item>/gi;
  let m: RegExpExecArray | null;
  while ((m = itemRx.exec(xml)) !== null) {
    const block = m[1];
    const titleRaw = pickTag(block, "title") ?? "";
    const link = (pickTag(block, "link") ?? "").trim();
    const descRaw = pickTag(block, "description") ?? "";
    const pubDate = pickTag(block, "pubDate");
    if (!link) continue;
    const title = decodeEntities(stripCdata(titleRaw)).trim();
    const bodyHtml = decodeEntities(stripCdata(descRaw));
    const bodyText = htmlToText(descRaw);
    const { id, kind } = advisoryIdFromLink(link);
    const haystack = `${title}\n${bodyText}`;
    items.push({
      advisory_id: id,
      title,
      link,
      pub_date: pubDate,
      body_html: bodyHtml,
      body_text: bodyText,
      cves: uniq((haystack.match(CVE_RX) ?? []).map((c) => c.toUpperCase())),
      cwes: uniq((haystack.match(CWE_RX) ?? []).map((c) => c.toUpperCase())),
      advisory_kind: kind,
    });
  }
  return items;
}

async function fetchFeed(): Promise<{ ok: boolean; xml: string; reason: string }> {
  try {
    const res = await fetch(CISA_ADVISORIES_FEED, {
      headers: { "User-Agent": POLITE_UA, Accept: "application/rss+xml, application/xml, text/xml" },
    });
    if (!res.ok) {
      return {
        ok: false,
        xml: "",
        reason: `feed ${CISA_ADVISORIES_FEED} returned ${res.status} ${res.statusText}`,
      };
    }
    const xml = await res.text();
    if (!/<item>/i.test(xml)) {
      return {
        ok: false,
        xml: "",
        reason: `feed ${CISA_ADVISORIES_FEED} returned 200 but no <item> elements (schema changed?)`,
      };
    }
    return { ok: true, xml, reason: "" };
  } catch (e) {
    return { ok: false, xml: "", reason: `feed fetch threw: ${(e as Error).message}` };
  }
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE + CISA advisory ids across rules/ and the
// whole proposals/ tree (INCLUDING proposals/cisa-kev/).
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
  advisoryIds: Set<string>;
}

function buildKnownIndex(): KnownIndex {
  const cves = new Set<string>();
  const advisoryIds = new Set<string>();
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
      const d = doc as {
        references?: { cve?: string[]; external?: string[] };
        _cisa_advisories_sync?: { advisory_id?: string };
      };
      const refs = d?.references;
      if (refs?.cve)
        for (const c of refs.cve)
          if (typeof c === "string") cves.add(c.toUpperCase());
      const ownId = d?._cisa_advisories_sync?.advisory_id;
      if (typeof ownId === "string") advisoryIds.add(ownId.toLowerCase());
      // Pick up advisory ids embedded in external refs / filenames too.
      for (const id of f.matchAll(/\b(icsa|icsma|bod|ed|aa)-[0-9a-z-]+/gi))
        advisoryIds.add(id[0].toLowerCase());
    }
  }
  return { cves, advisoryIds };
}

// ---------------------------------------------------------------------------
// Detection-readiness triage. CISA advisory prose almost never ships a
// payload; mark detection_ready true only when a payload-like fragment is
// present (mirrors sync-ghsa.ts PAYLOAD_HEURISTICS_RX).
// ---------------------------------------------------------------------------
const PAYLOAD_HEURISTICS_RX = new RegExp(
  [
    "```",
    "## *Proof of Concept",
    "## *Reproducer",
    "## *Exploit",
    "payload:",
    "curl ",
    "POST \\/[a-z]",
    "<script>",
    "prompt: ['\"]",
  ].join("|"),
  "im",
);

function isDetectionReady(adv: CisaAdvisory): { ready: boolean; reason: string } {
  if (PAYLOAD_HEURISTICS_RX.test(adv.body_html))
    return { ready: true, reason: "payload-like content in advisory body" };
  if (adv.body_text.match(/poc|exploit-db|proof[- ]of[- ]concept/i))
    return { ready: true, reason: "PoC reference present in advisory body" };
  return {
    ready: false,
    reason: "advisory prose has no reproducer / payload (tracking-only)",
  };
}

// ---------------------------------------------------------------------------
// Proposal renderer (column-for-column aligned with sync-huntr / sync-ghsa).
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

function severityFromBody(adv: CisaAdvisory): "critical" | "high" | "medium" | "low" {
  // CISA bodies frequently include a CVSS v3 score like "v3 9.8". Map it.
  const m = adv.body_text.match(/v3(?:\.\d)?\s*([0-9]{1,2}(?:\.[0-9])?)/i);
  if (m) {
    const score = parseFloat(m[1]);
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    return "low";
  }
  return "high"; // conservative default for an exploited/advised vuln
}

export function renderProposal(adv: CisaAdvisory): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const proposalId = adv.cves[0] ?? adv.advisory_id;
  const category = guessCategory(adv.cwes);
  const severity = severityFromBody(adv);
  const triage = isDetectionReady(adv);
  const responseActions =
    severity === "critical" || severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock =
    adv.cves.length > 0
      ? `  cve:\n${adv.cves.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  const cweBlock =
    adv.cwes.length > 0
      ? `  cwe:\n${adv.cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";

  const title = adv.title.replace(/"/g, '\\"').slice(0, 120) || adv.advisory_id;
  const desc = adv.body_text.replace(/\n+/g, " ").trim().slice(0, 600);

  return `# ATR rule proposal -- generated by scripts/sync-cisa-advisories.ts
# Source: CISA Cybersecurity Advisory ${adv.advisory_id}
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. CISA advisory prose is
#         rarely a copy-pasteable payload; the full advisory body is preserved
#         under _cisa_advisories_sync.advisory_body for conversion to regex.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${proposalId}
rule_version: 1
status: draft
description: >
  CISA Cybersecurity Advisory ${adv.advisory_id}${adv.cves.length ? ` (${adv.cves[0]})` : ""}.
  ${desc}
author: "ATR Community (CISA Advisories sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${severity}

references:
${cveBlock}${cweBlock}  external:
    - "${adv.link}"

metadata_provenance:
  cisa_advisory: cisa-advisories-sync
${adv.cves.length ? "  cve: cisa-advisories-sync\n" : ""}${adv.cwes.length ? "  cwe: cisa-advisories-sync\n" : ""}
tags:
  category: ${category}
  subcategory: cisa-advisory-imported
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
    # TODO(human): convert the CISA advisory body below into precision-safe
    # detection.conditions regex/string matchers. Until this is done the rule
    # will neither fire nor be promotable to rules/.
    #
    # === CISA advisory excerpt ===
${
    adv.body_text
      .split("\n")
      .filter((s) => s.trim().length > 0)
      .slice(0, 40)
      .map((s) => `    # ${s}`)
      .join("\n") || "    # (no advisory body in feed item)"
  }
    []

response:
  actions:
${responseActions.map((a) => `    - ${a}`).join("\n")}
  notify:
    - security_team

test_cases:
  true_positives: []
  true_negatives: []

_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason}"

# === sync-cisa-advisories.ts provenance ===
_cisa_advisories_sync:
  advisory_id: "${adv.advisory_id}"
  advisory_kind: "${adv.advisory_kind}"
  cves: ${JSON.stringify(adv.cves)}
  cwes: ${JSON.stringify(adv.cwes)}
  pub_date: ${adv.pub_date ? `"${adv.pub_date.replace(/"/g, '\\"')}"` : "null"}
  link: "${adv.link}"
  imported_at: "${new Date().toISOString()}"
  data_source_used: "CISA cybersecurity-advisories all.xml RSS feed"
  advisory_body: |
${indentForLiteralBlock(adv.body_text || "(no body provided by CISA feed)", "    ")}
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------
interface RunSummary {
  run_date: string;
  feed_url: string;
  advisories_seen: number;
  excluded_ics_ot: number;
  filtered_not_ai: number;
  ai_relevant: number;
  already_known: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  written_files: string[];
  errors: string[];
}

async function main(): Promise<void> {
  console.error("=== sync-cisa-advisories.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);
  console.error(`feed: ${CISA_ADVISORIES_FEED}`);
  console.error(`html index (for humans): ${CISA_HTML_INDEX}`);

  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    feed_url: CISA_ADVISORIES_FEED,
    advisories_seen: 0,
    excluded_ics_ot: 0,
    filtered_not_ai: 0,
    ai_relevant: 0,
    already_known: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    written_files: [],
    errors: [],
  };

  const feed = await fetchFeed();
  if (!feed.ok) {
    summary.errors.push(`no usable feed: ${feed.reason}`);
    summary.errors.push(
      `checked: ${CISA_ADVISORIES_FEED} (RSS) and html index ${CISA_HTML_INDEX}. ` +
        "No alternate all-advisories JSON firehose is published by CISA; " +
        "per-advisory CSAF JSON exists but requires the RSS feed to enumerate ids. " +
        "Maintainer action: confirm the feed URL or point at a mirror.",
    );
    console.log(JSON.stringify(summary, null, 2));
    console.log(
      `::cisa-advisories-summary::${JSON.stringify({
        new_proposals: 0,
        advisories_seen: 0,
        ai_relevant: 0,
        excluded_ics_ot: 0,
        data_source_used: null,
      })}`,
    );
    process.exit(2);
  }

  const advisories = parseFeed(feed.xml);
  console.error(`feed parsed: ${advisories.length} advisory items`);
  summary.advisories_seen = advisories.length;

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  const known = buildKnownIndex();
  if (VERBOSE)
    console.error(
      `known index: ${known.cves.size} CVEs, ${known.advisoryIds.size} advisory ids ` +
        "(rules/ + all proposals/ incl. cisa-kev/)",
    );

  let writtenCount = 0;
  for (const adv of advisories) {
    if (writtenCount >= LIMIT) break;
    const haystack = `${adv.title}\n${adv.body_text}`;

    // Gate 1: ICS/OT/SCADA exclusion (hard).
    const ics = isIcsOt(adv.advisory_id, haystack);
    if (ics.excluded) {
      summary.excluded_ics_ot += 1;
      if (VERBOSE)
        console.error(`  skip (ICS/OT) ${adv.advisory_id}: ${ics.reason}`);
      continue;
    }

    // Gate 2: AI/agent inclusion (hard).
    const ai = isAiRelevant(haystack);
    if (!ai.match) {
      summary.filtered_not_ai += 1;
      if (VERBOSE)
        console.error(`  skip (not AI) ${adv.advisory_id}: ${ai.reason}`);
      continue;
    }
    summary.ai_relevant += 1;
    console.error(
      `  AI-relevant ${adv.advisory_id}: ${ai.reason} | cves=${adv.cves.join(",") || "none"}`,
    );

    // Dedup: CVE primary key, advisory id secondary -- incl. cisa-kev/.
    const cveHit = adv.cves.find((c) => known.cves.has(c));
    if (cveHit && !FORCE) {
      summary.already_known += 1;
      if (VERBOSE)
        console.error(`  have-rule ${adv.advisory_id}: CVE ${cveHit} already covered`);
      continue;
    }
    if (known.advisoryIds.has(adv.advisory_id.toLowerCase()) && !FORCE) {
      summary.already_known += 1;
      if (VERBOSE)
        console.error(`  have-rule ${adv.advisory_id}: advisory id already covered`);
      continue;
    }

    const outName = `${adv.cves[0] ?? adv.advisory_id}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.already_known += 1;
      if (VERBOSE) console.error(`  have-proposal ${outPath}`);
      continue;
    }

    const triage = isDetectionReady(adv);
    const body = renderProposal(adv);
    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;
    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName}`);
    } else {
      console.error(`  would write ${outName}`);
      if (VERBOSE) {
        // Sanity: re-parse the rendered proposal so a dry-run proves the YAML
        // is well-formed before anyone ever writes it.
        try {
          yaml.load(body);
          console.error(`    (rendered proposal parses as valid YAML)`);
        } catch (e) {
          summary.errors.push(
            `rendered proposal for ${outName} is invalid YAML: ${(e as Error).message}`,
          );
          console.error(`    !! rendered YAML invalid: ${(e as Error).message}`);
        }
      }
    }
    writtenCount += 1;
  }

  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::cisa-advisories-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      advisories_seen: summary.advisories_seen,
      ai_relevant: summary.ai_relevant,
      excluded_ics_ot: summary.excluded_ics_ot,
      filtered_not_ai: summary.filtered_not_ai,
      already_known: summary.already_known,
      data_source_used: "CISA cybersecurity-advisories all.xml RSS feed",
    })}`,
  );
}

// Run only when invoked as a script (not when imported for tests).
const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}
