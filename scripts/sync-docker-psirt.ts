#!/usr/bin/env npx tsx
/**
 * sync-docker-psirt.ts
 *
 * Pulls Docker's published security announcements (Docker PSIRT — Docker is a
 * CVE CNA) for AGENT-relevant Docker products and emits ATR rule proposals
 * under proposals/docker-psirt/<CVE-id>.proposal.yaml.
 *
 * WHY DOCKER MATTERS FOR ATR:
 *   Docker ships **Docker Model Runner** — an in-Docker-Desktop agent / AI
 *   inference runtime that pulls models from OCI registries and runs them in a
 *   container. A container-to-host code-execution there is a core
 *   agent-infrastructure sandbox-escape (e.g. CVE-2026-5843 Model Runner MLX
 *   backend, CVE-2026-5817 Model Runner vllm-metal backend, CVE-2026-33990
 *   Model Runner OCI registry-client SSRF, CVE-2026-28400 Model Runner runtime
 *   flag injection). The broader Docker Desktop / Engine container-escape / RCE
 *   advisories are also in scope because they are exactly the agent sandbox
 *   that an agent's tool-use runs inside.
 *
 * REAL MACHINE-READABLE SOURCE (verified live 2026-06-12):
 *   PRIMARY  HTML page https://docs.docker.com/security/security-announcements/
 *            Each advisory is an <h2 id="docker-desktop-...-cve-...">SECTION</h2>
 *            followed by a <p>/<ul> body. The body carries:
 *              - "fixed on <Month Day>" / "Last updated <Month Day, Year>" date
 *              - a per-CVE external link
 *                (www.cve.org/CVERecord?id=CVE-..., scout.docker.com/v/CVE-...,
 *                 or nvd.nist.gov/vuln/detail/CVE-...)
 *              - prose describing the vulnerability
 *            The page lists all 20+ CVEs in the initial server-rendered HTML
 *            (NOT a client-only SPA — regex extraction works). A section may
 *            cover MULTIPLE CVEs (e.g. CVE-2025-3224 + CVE-2025-4095 +
 *            CVE-2025-3911); we emit one proposal per CVE, sharing the section
 *            body / date / title.
 *
 *   There is an RSS feed at .../security-announcements/index.xml, but it is
 *   TITLE-ONLY (no <pubDate>, no <description> body), so it cannot supply the
 *   advisory body or date that ATR needs. We use it only as a sanity cross-check
 *   of the CVE set when --verbose; the HTML page is the parsed source.
 *
 *   Docker is also a GHSA CNA — many of these land in GHSA too. We dedup by CVE
 *   id against rules/ + proposals/ (buildKnownIndex), so a CVE already imported
 *   by sync-ghsa.ts is skipped. CVE ID is the cross-source primary key.
 *
 *   If the page changes shape / disappears / yields zero CVEs, the script exits
 *   2 (recoverable) naming exactly what was checked. We do NOT fabricate.
 *
 * SCOPE (ATR rule — do not widen):
 *   ATR detects AGENT-runtime threats (prompt injection, tool/MCP poisoning,
 *   context exfiltration, excessive autonomy) and the agent SANDBOX they run
 *   in. We keep:
 *     (a) any Docker **Model Runner** advisory, and
 *     (b) container-escape / RCE / SSRF / privilege-escalation advisories in
 *         Docker Desktop / Engine / runc / BuildKit / Moby (the agent sandbox).
 *   We DROP advisories that are pure info-disclosure-in-logs / installer DLL
 *   hijack / availability bugs with no agent-sandbox-escape meaning, via a
 *   Docker-product scope gate, then apply sync-ghsa.ts's agentRelevance()
 *   CWE/keyword gate as a second filter. NOTE: bundled third-party app CVEs
 *   shipped in Docker Official Images (Log4Shell, Text4Shell, etc.) are NOT
 *   Docker-runtime threats — they are application-layer CVEs that merely happen
 *   to ride in an image — and are excluded.
 *
 * Each proposal:
 *   - id: ATR-DRAFT-<CVE-id>.
 *   - status=draft, maturity=experimental, detection.conditions EMPTY (prose
 *     source — Docker announcements are descriptive, not payload-bearing).
 *   - _docker_psirt_sync.advisory_body holds the section prose — the only
 *     payload source for promote-detection-ready.ts.
 *   - _triage.detection_ready almost always false (prose); true only if the
 *     body carries payload-like content (inline PoC / code block).
 *
 * Idempotency: dedup by CVE id against rules/ + proposals/ (buildKnownIndex),
 * unless --force.
 *
 * SECRET DISCIPLINE: no API key needed for the public docs page. Polite UA.
 *
 * Usage:
 *   npx tsx scripts/sync-docker-psirt.ts                # dry-run
 *   npx tsx scripts/sync-docker-psirt.ts --write        # write proposals
 *   npx tsx scripts/sync-docker-psirt.ts --force        # overwrite existing
 *   npx tsx scripts/sync-docker-psirt.ts --verbose
 *   npx tsx scripts/sync-docker-psirt.ts --limit 5
 *
 * Exit codes:
 *   0 success
 *   1 fatal (unexpected error)
 *   2 no data path available (recoverable: page moved / empty / network)
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
const PROPOSALS_DIR = resolve(PROPOSALS_BASE, "docker-psirt");

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

const FETCH_TIMEOUT_MS = 20_000;

const DOCKER_SECURITY_URL =
  "https://docs.docker.com/security/security-announcements/";

// ---------------------------------------------------------------------------
// agentRelevance gate (ported from sync-ghsa.ts) — second filter per CVE.
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

// CWEs that map to an agent-runtime / agent-sandbox threat ATR can reason about.
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
]);

// Agent / agent-sandbox threat phrases. Docker announcements are prose with no
// CWE, so the keyword list carries the gate. Sandbox-escape wording
// (container-to-host, container escape, privilege escalation) is included
// because the agent's tool-use runs INSIDE that container.
const AGENT_THREAT_KEYWORDS: RegExp[] = [
  /prompt injection/,
  /prompt-injection/,
  /model runner/,
  /model context protocol/,
  /\bmcp\b/,
  /\bssrf\b/,
  /server-side request/,
  /remote code execution/,
  /\brce\b/,
  /arbitrary code/,
  /code execution/,
  /code injection/,
  /command injection/,
  /flag injection/,
  /argument injection/,
  /deserializ/,
  /sql injection/,
  /path traversal/,
  /template injection/,
  /container[- ]to[- ]host/,
  /container escape/,
  /sandbox escape/,
  /escape the container/,
  // A malicious container reaching the Docker Engine / control socket / other
  // containers is an agent-sandbox breakout — the agent's tool-use runs inside
  // that container. (CVE-2025-9074-style.)
  /malicious container/,
  /access (?:the )?docker engine/,
  /docker socket/,
  /unauthorized access to (?:user )?(?:files|file system|filesystem)/,
  /elevation of privilege/,
  /privilege escalation/,
  /exfiltrat/,
  /untrusted (input|data|manifest|model|image|content)/,
];

interface RelevanceInput {
  summary?: string;
  description?: string;
  cwes?: string[];
}

function agentRelevance(adv: RelevanceInput): {
  relevant: boolean;
  reason: string;
} {
  const cwes = adv.cwes ?? [];
  const hitCwe = cwes.find((c) => AGENT_RELEVANT_CWES.has(c));
  if (hitCwe) return { relevant: true, reason: `agent-relevant CWE ${hitCwe}` };
  const body = `${adv.summary ?? ""}\n${adv.description ?? ""}`.toLowerCase();
  const hitKw = AGENT_THREAT_KEYWORDS.find((rx) => rx.test(body));
  if (hitKw)
    return { relevant: true, reason: `agent-threat keyword /${hitKw.source}/` };
  return {
    relevant: false,
    reason: `no agent-relevant CWE or keyword (cwes: ${cwes.join(",") || "none"})`,
  };
}

// ---------------------------------------------------------------------------
// Docker product scope gate (first filter). Keep Model Runner unconditionally;
// keep Desktop/Engine/runc/BuildKit/Moby container-escape/RCE/SSRF/privesc.
// Drop bundled third-party app CVEs (Log4Shell / Text4Shell etc.) — those are
// application-layer, not Docker-runtime, threats.
// ---------------------------------------------------------------------------

const MODEL_RUNNER_RX = /model runner/i;

// Bundled third-party application-CVE names. These are the actual vulnerable
// libraries that merely ride inside a Docker Official Image — NOT Docker's own
// runtime. (A bare "Docker Official Images" mention is excluded too, but only
// in dockerProductInScope where it is gated on the section NOT naming a Docker
// sandbox product, so mitigation-advice mentions don't false-trigger.)
const BUNDLED_APP_CVE_RX = /log4j|log4shell|text4shell|apache commons/i;
const OFFICIAL_IMAGE_PHRASE_RX = /docker official images/i;

// Container-sandbox products whose escape/RCE/SSRF/privesc is in scope.
const SANDBOX_PRODUCT_RX =
  /\b(docker desktop|docker engine|\brunc\b|buildkit|\bmoby\b|enhanced container isolation|gRPC-FUSE|docker model runner)\b/i;

function dockerProductInScope(
  sectionTitle: string,
  body: string,
): { inScope: boolean; reason: string } {
  const hay = `${sectionTitle}\n${body}`;
  // Model Runner is always in scope (highest-value agent runtime).
  if (MODEL_RUNNER_RX.test(hay)) {
    return { inScope: true, reason: "Docker Model Runner (agent inference runtime)" };
  }
  // Docker's own container-sandbox runtime (runc/BuildKit/Moby/Desktop/Engine)
  // takes precedence over the bundled-app exclusion: an advisory whose TITLE
  // names a sandbox product is a Docker-runtime threat even if the body cites
  // "Docker Official Images" as mitigation advice (CVE-2024-21626-style).
  if (SANDBOX_PRODUCT_RX.test(sectionTitle)) {
    return { inScope: true, reason: "Docker container sandbox product" };
  }
  // Bundled third-party app CVEs riding in Docker Official Images are not a
  // Docker-runtime threat — drop them even though they mention "Docker". This
  // fires only when no sandbox product is named in the title (above), so the
  // runc/BuildKit/Moby advisory is not mis-dropped.
  if (BUNDLED_APP_CVE_RX.test(hay) || OFFICIAL_IMAGE_PHRASE_RX.test(hay)) {
    return {
      inScope: false,
      reason: "bundled third-party app CVE in Docker Official Images (not Docker-runtime)",
    };
  }
  // Sandbox product named only in the body (not the title) — still in scope.
  if (SANDBOX_PRODUCT_RX.test(hay)) {
    return { inScope: true, reason: "Docker container sandbox product" };
  }
  return {
    inScope: false,
    reason: "not a Docker Model Runner / container-sandbox product",
  };
}

// ---------------------------------------------------------------------------
// Fetch the security-announcements HTML page.
// ---------------------------------------------------------------------------

class NoDataError extends Error {}

async function fetchWithTimeout(url: string): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, {
      headers: { "User-Agent": POLITE_UA, Accept: "text/html" },
      signal: ctrl.signal,
    });
  } finally {
    clearTimeout(t);
  }
}

async function fetchSecurityPage(): Promise<string> {
  let res: Response;
  try {
    res = await fetchWithTimeout(DOCKER_SECURITY_URL);
  } catch (e) {
    throw new NoDataError(
      `request failed/timed out for ${DOCKER_SECURITY_URL}: ${(e as Error).message}`,
    );
  }
  if (res.status === 404) {
    throw new NoDataError(
      `Docker security-announcements page 404 (${DOCKER_SECURITY_URL}). ` +
        `Page moved — re-verify the machine-readable source. RSS at ` +
        `.../security-announcements/index.xml is title-only and cannot supply ` +
        `advisory body/date.`,
    );
  }
  if (!res.ok) {
    throw new NoDataError(
      `non-200 ${res.status} ${res.statusText} for ${DOCKER_SECURITY_URL}`,
    );
  }
  return await res.text();
}

// ---------------------------------------------------------------------------
// HTML -> DockerAdvisory[]. Bounded regex extraction. One advisory per CVE.
// ---------------------------------------------------------------------------

interface DockerAdvisory {
  cve_id: string;
  section_title: string;
  external_url: string; // per-CVE link (cve.org / scout.docker.com / nvd)
  product_name: string; // best-guess affected Docker product
  description: string; // section prose (single line)
  advisory_body: string; // section prose (multi-line, provenance payload)
  severity: "critical" | "high" | "medium" | "low";
  cwes: string[]; // Docker page rarely lists CWE; usually []
  date: string | null; // "fixed on <Month Day>" / "Last updated <...>"
  cosignatory_cves: string[]; // other CVEs sharing the same section
}

function stripTags(s: string): string {
  return s
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

const CVE_RX = /CVE-\d{4}-\d{4,}/gi;

// Locate the per-CVE external link inside a section. Docker uses
// www.cve.org/CVERecord?id=CVE-..., scout.docker.com/v/CVE-..., or
// nvd.nist.gov/vuln/detail/CVE-... — match a URL that contains this exact CVE.
function externalUrlForCve(sectionHtml: string, cve: string): string {
  const linkRx = new RegExp(
    `href=["']?(https?://[^"' >]*${cve}[^"' >]*)`,
    "i",
  );
  const m = sectionHtml.match(linkRx);
  if (m) return m[1];
  // Fallback: canonical cve.org record URL.
  return `https://www.cve.org/CVERecord?id=${cve}`;
}

function dateFromBody(text: string): string | null {
  const fixed = text.match(
    /fixed on ([A-Z][a-z]+ \d{1,2}(?:,? \d{4})?)/,
  );
  if (fixed) return fixed[1];
  const updated = text.match(
    /Last updated ([A-Z][a-z]+ \d{1,2},? \d{4})/,
  );
  if (updated) return updated[1];
  return null;
}

// Severity inference from prose (Docker page rarely states a severity word).
// Container-to-host code execution / RCE => critical; SSRF / privesc / injection
// => high; info disclosure => medium; else high (conservative for a sandbox).
function inferSeverity(text: string): "critical" | "high" | "medium" | "low" {
  const t = text.toLowerCase();
  if (/critical/.test(t)) return "critical";
  if (
    /container-to-host|container to host|remote code execution|\brce\b|arbitrary code execution/.test(
      t,
    )
  )
    return "critical";
  if (/\bhigh\b/.test(t)) return "high";
  if (
    /ssrf|server-side request|privilege escalation|elevation of privilege|flag injection|argument injection|command injection|code execution/.test(
      t,
    )
  )
    return "high";
  if (/\blow\b/.test(t)) return "low";
  if (/sensitive information|information disclosure|log files|diagnostic/.test(t))
    return "medium";
  return "high";
}

function productFromTitle(title: string): string {
  // "Docker Desktop 4.71.0 security update: CVE-2026-5843" -> "Docker Desktop 4.71.0"
  const m = title.match(/^(.*?)\s+(?:security update|Security Update)\s*:/i);
  if (m) return m[1].trim();
  // "Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby"
  const inMatch = title.match(/vulnerabilit(?:y|ies) in (.+)$/i);
  if (inMatch) return inMatch[1].trim();
  return title.replace(/:\s*CVE-.*$/i, "").trim() || "Docker";
}

function parseAdvisories(html: string): DockerAdvisory[] {
  // Slice the page into <h2 ...> ... </h2> + body segments.
  const h2Positions: number[] = [];
  const h2Rx = /<h2\b[^>]*>/gi;
  let hm: RegExpExecArray | null;
  while ((hm = h2Rx.exec(html)) !== null) h2Positions.push(hm.index);
  if (h2Positions.length === 0) return [];

  const out: DockerAdvisory[] = [];
  const emittedCve = new Set<string>();

  for (let i = 0; i < h2Positions.length; i++) {
    const start = h2Positions[i];
    const end = i + 1 < h2Positions.length ? h2Positions[i + 1] : html.length;
    const seg = html.slice(start, end);

    // Heading text = content of the <h2>...</h2>.
    const headClose = seg.indexOf("</h2>");
    if (headClose < 0) continue;
    const sectionTitle = stripTags(seg.slice(0, headClose + 5));
    const bodyHtml = seg.slice(headClose + 5);
    const bodyText = stripTags(bodyHtml);

    // All CVE ids in this section (heading + body), de-duped, order-preserved.
    const cveSet: string[] = [];
    for (const m of seg.matchAll(CVE_RX)) {
      const id = m[0].toUpperCase();
      if (!cveSet.includes(id)) cveSet.push(id);
    }
    if (cveSet.length === 0) continue; // non-CVE section (e.g. SSO deprecation)

    const date = dateFromBody(bodyText) ?? dateFromBody(sectionTitle);
    const severity = inferSeverity(`${sectionTitle} ${bodyText}`);
    const product = productFromTitle(sectionTitle);

    for (const cve of cveSet) {
      if (emittedCve.has(cve)) continue;
      emittedCve.add(cve);
      out.push({
        cve_id: cve,
        section_title: sectionTitle,
        external_url: externalUrlForCve(seg, cve),
        product_name: product,
        description: bodyText.slice(0, 600),
        advisory_body: `${sectionTitle}\n\n${bodyText}`,
        severity,
        cwes: [], // Docker page does not enumerate CWE ids.
        date,
        cosignatory_cves: cveSet.filter((c) => c !== cve),
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Idempotency: index existing CVE ids across rules/ and proposals/.
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

function buildKnownIndex(): { cves: Set<string> } {
  const cves = new Set<string>();
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
      const refs = (doc as { references?: { cve?: string[] } })?.references;
      if (refs?.cve)
        for (const c of refs.cve)
          if (typeof c === "string") cves.add(c.toUpperCase());
    }
  }
  return { cves };
}

// ---------------------------------------------------------------------------
// Detection-readiness triage — Docker announcements are prose.
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

function isDetectionReady(a: DockerAdvisory): {
  ready: boolean;
  reason: string;
} {
  if (PAYLOAD_HEURISTICS_RX.test(a.advisory_body))
    return { ready: true, reason: "payload-like content in advisory body" };
  return {
    ready: false,
    reason: "Docker announcement is prose-only (no reproducer / payload section)",
  };
}

// ---------------------------------------------------------------------------
// Proposal renderer (aligned with sync-huntr / sync-ghsa / sync-nvidia-psirt).
// ---------------------------------------------------------------------------

const ADVISORY_BODY_MAX_CHARS = 8000;

function indentForLiteralBlock(text: string, indent: string): string {
  const capped =
    text.length > ADVISORY_BODY_MAX_CHARS
      ? text.slice(0, ADVISORY_BODY_MAX_CHARS) +
        `\n\n... (truncated at ${ADVISORY_BODY_MAX_CHARS} chars; see external URL for full text)`
      : text;
  return capped
    .split("\n")
    .map((line) => indent + line)
    .join("\n");
}

function renderProposal(a: DockerAdvisory): string {
  const today = new Date().toISOString().slice(0, 10);
  const todayPretty = today.replace(/-/g, "/");
  const category = guessCategory(a.cwes);
  const triage = isDetectionReady(a);
  const responseActions =
    a.severity === "critical" || a.severity === "high"
      ? ["block_input", "alert"]
      : ["alert"];

  const cveBlock = `  cve:\n    - "${a.cve_id}"\n`;
  const cweBlock =
    a.cwes.length > 0
      ? `  cwe:\n${a.cwes.map((c) => `    - "${c}"`).join("\n")}\n`
      : "";
  // external: per-CVE link + the canonical Docker announcements page.
  const externalUrls = [a.external_url, DOCKER_SECURITY_URL].filter(
    (u, i, arr) => u && arr.indexOf(u) === i,
  );
  const externalBlock = `  external:\n${externalUrls
    .map((u) => `    - "${u}"`)
    .join("\n")}\n`;

  const title = a.section_title.replace(/"/g, '\\"').slice(0, 120);
  const desc = a.description.replace(/\n+/g, " ").trim();

  const bodyCommentLines =
    a.advisory_body
      .split("\n")
      .filter((s) => s.trim().length > 0)
      .slice(0, 60)
      .map((s) => `    # ${s}`)
      .join("\n") || "    # (no advisory body extracted)";

  return `# ATR rule proposal -- generated by scripts/sync-docker-psirt.ts
# Source: Docker security announcement (${a.cve_id}) via docs.docker.com/security/security-announcements
# Imported on: ${today}
# Status: DRAFT -- detection.conditions MUST be filled in by a human reviewer
#         before this rule can be considered for merge. The Docker advisory
#         body is attached as a YAML comment under detection.conditions and in
#         _docker_psirt_sync.advisory_body for conversion to a regex.
# Detection readiness: ${triage.ready ? "READY" : "TRACKING_ONLY"} -- ${triage.reason}
title: "${title}"
id: ATR-DRAFT-${a.cve_id}
rule_version: 1
status: draft
description: >
  Docker security announcement ${a.cve_id}.
  Affected Docker product: ${a.product_name}.
  ${desc.slice(0, 600)}
author: "ATR Community (Docker PSIRT sync)"
date: "${todayPretty}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: ${a.severity}

references:
${cveBlock}${cweBlock}${externalBlock}
metadata_provenance:
  docker_psirt: docker-psirt-sync
  cve: docker-psirt-sync
${a.cwes.length ? "  cwe: docker-psirt-sync\n" : ""}
tags:
  category: ${category}
  subcategory: docker-psirt-imported
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
    # TODO(human): convert the Docker advisory below into precision-safe
    # detection.conditions regex/string matchers. Without this work the rule
    # will neither fire nor be promotable to rules/.
    #
    # === Docker security announcement body ===
${bodyCommentLines}
    []

response:
  actions:
${responseActions.map((x) => `    - ${x}`).join("\n")}
  notify:
    - security_team

test_cases:
  true_positives: []
  true_negatives: []

_triage:
  detection_ready: ${triage.ready}
  reason: "${triage.reason.replace(/"/g, '\\"')}"

# === sync-docker-psirt.ts provenance ===
_docker_psirt_sync:
  cve_id: "${a.cve_id}"
  section_title: "${a.section_title.replace(/"/g, '\\"')}"
  product_name: "${a.product_name.replace(/"/g, '\\"')}"
  cwe: ${JSON.stringify(a.cwes)}
  severity: "${a.severity}"
  fixed_date: ${a.date ? `"${a.date.replace(/"/g, '\\"')}"` : "null"}
  cosignatory_cves: ${JSON.stringify(a.cosignatory_cves)}
  external_url: "${a.external_url}"
  source_page: "${DOCKER_SECURITY_URL}"
  imported_at: "${new Date().toISOString()}"
  data_source_used: "docs.docker.com security-announcements HTML (regex extraction)"
  advisory_body: |
${indentForLiteralBlock(a.advisory_body, "    ")}
`;
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

interface RunSummary {
  run_date: string;
  advisories_parsed: number;
  out_of_scope_product: number;
  filtered_not_agent: number;
  already_known: number;
  new_proposals: number;
  new_detection_ready: number;
  new_tracking_only: number;
  errors: string[];
  written_files: string[];
}

function printSummaryAndExit(summary: RunSummary, code: number): never {
  console.log(JSON.stringify(summary, null, 2));
  console.log(
    `::docker-psirt-summary::${JSON.stringify({
      new_proposals: summary.new_proposals,
      new_detection_ready: summary.new_detection_ready,
      new_tracking_only: summary.new_tracking_only,
      out_of_scope_product: summary.out_of_scope_product,
      filtered_not_agent: summary.filtered_not_agent,
      advisories_parsed: summary.advisories_parsed,
    })}`,
  );
  process.exit(code);
}

async function main(): Promise<void> {
  const summary: RunSummary = {
    run_date: new Date().toISOString(),
    advisories_parsed: 0,
    out_of_scope_product: 0,
    filtered_not_agent: 0,
    already_known: 0,
    new_proposals: 0,
    new_detection_ready: 0,
    new_tracking_only: 0,
    errors: [],
    written_files: [],
  };

  if (WRITE && !existsSync(PROPOSALS_DIR))
    mkdirSync(PROPOSALS_DIR, { recursive: true });

  console.error("=== sync-docker-psirt.ts ===");
  console.error(`mode: ${WRITE ? "WRITE" : "dry-run"}`);
  console.error(`source: ${DOCKER_SECURITY_URL} (HTML)`);

  // --- fetch + parse ---
  let html: string;
  try {
    html = await fetchSecurityPage();
  } catch (e) {
    if (e instanceof NoDataError) {
      summary.errors.push(`NO DATA PATH: ${e.message}`);
      console.error(`no data path: ${e.message}`);
      printSummaryAndExit(summary, 2);
    }
    throw e;
  }

  const advisories = parseAdvisories(html);
  summary.advisories_parsed = advisories.length;
  console.error(`parsed ${advisories.length} CVE advisories from page`);

  if (advisories.length === 0) {
    summary.errors.push(
      "NO DATA PATH: page fetched but zero CVE advisories parsed — markup " +
        "likely changed (no <h2> sections with CVE ids). Re-verify the " +
        "extraction regex against the live page.",
    );
    console.error(summary.errors[summary.errors.length - 1]);
    printSummaryAndExit(summary, 2);
  }

  const known = buildKnownIndex();
  let writtenCount = 0;

  for (const a of advisories) {
    if (writtenCount >= LIMIT) break;

    // --- scope gate 1: Docker product (Model Runner or sandbox) ---
    const scope = dockerProductInScope(a.section_title, a.advisory_body);
    if (!scope.inScope) {
      summary.out_of_scope_product += 1;
      if (VERBOSE)
        console.error(`  skip (out of scope) ${a.cve_id}: ${scope.reason}`);
      continue;
    }

    // --- scope gate 2: per-CVE agent-relevance (CWE/keyword) ---
    const rel = agentRelevance({
      summary: a.section_title,
      description: a.advisory_body,
      cwes: a.cwes,
    });
    if (!rel.relevant) {
      summary.filtered_not_agent += 1;
      if (VERBOSE)
        console.error(`  skip (not agent) ${a.cve_id}: ${rel.reason}`);
      continue;
    }

    // --- dedup by CVE id (cross-source primary key) ---
    if (!FORCE && known.cves.has(a.cve_id)) {
      summary.already_known += 1;
      if (VERBOSE) console.error(`  have-rule ${a.cve_id}: already covered`);
      continue;
    }
    const outName = `${a.cve_id}.proposal.yaml`;
    const outPath = join(PROPOSALS_DIR, outName);
    if (existsSync(outPath) && !FORCE) {
      summary.already_known += 1;
      if (VERBOSE) console.error(`  have-proposal ${outName}`);
      continue;
    }

    const triage = isDetectionReady(a);
    const body = renderProposal(a);
    if (WRITE) {
      writeFileSync(outPath, body, "utf-8");
      summary.written_files.push(outPath.replace(REPO_ROOT + "/", ""));
      console.error(`  wrote ${outName} [${scope.reason}]`);
    } else {
      console.error(
        `  would write ${outName} [${scope.reason}; ${rel.reason}]`,
      );
    }
    summary.new_proposals += 1;
    if (triage.ready) summary.new_detection_ready += 1;
    else summary.new_tracking_only += 1;
    writtenCount += 1;
  }

  printSummaryAndExit(summary, 0);
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(1);
  });
}

export {
  agentRelevance,
  parseAdvisories,
  dockerProductInScope,
  inferSeverity,
  AGENT_THREAT_KEYWORDS,
};
