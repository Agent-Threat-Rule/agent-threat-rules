#!/usr/bin/env npx tsx
/**
 * issue-to-proposal.ts
 *
 * Converts a GitHub "New Rule Proposal" issue into a draft proposal YAML
 * and writes it to proposals/community/.
 *
 * Called by .github/workflows/issue-to-proposal.yml. Can also be run
 * locally for testing.
 *
 * Usage:
 *   npx tsx scripts/issue-to-proposal.ts \
 *     --issue 42 \
 *     --title "[Rule] Prompt injection via tool description" \
 *     --body-file /tmp/issue-body.txt \
 *     --author octocat \
 *     --write
 *
 * Exit codes:
 *   0  proposal written (or dry-run succeeded)
 *   1  fatal parse or IO error
 *   2  issue body missing required fields (attack-type, description, payload)
 */

import {
  existsSync,
  mkdirSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");
const PROPOSALS_DIR = resolve(REPO_ROOT, "proposals/community");

const args = process.argv.slice(2);
const flag = (n: string) => args.includes(n);
const opt = (n: string): string | undefined => {
  const i = args.indexOf(n);
  return i >= 0 ? args[i + 1] : undefined;
};

const WRITE = flag("--write");
const ISSUE_NUMBER = opt("--issue");
const TITLE = opt("--title") ?? "";
const BODY_FILE = opt("--body-file");
const AUTHOR = opt("--author") ?? "anonymous";

if (!ISSUE_NUMBER) {
  console.error("error: --issue <number> is required");
  process.exit(1);
}
if (!BODY_FILE || !existsSync(BODY_FILE)) {
  console.error("error: --body-file <path> is required and must exist");
  process.exit(1);
}

const issueBody = readFileSync(BODY_FILE, "utf8");

// Parse GitHub issue form body: each section is "### Field Name\n\nvalue"
function parseSection(body: string, heading: string): string {
  const re = new RegExp(
    `###\\s*${heading}\\s*\\n+([\\s\\S]*?)(?=\\n###|$)`,
    "i"
  );
  const m = body.match(re);
  if (!m) return "";
  return m[1].trim();
}

const attackType = parseSection(issueBody, "Attack Type");
const description = parseSection(issueBody, "Description");
const references = parseSection(issueBody, "OWASP/MITRE/CVE References");
const payload = parseSection(issueBody, "Example Attack Payload");
const falsePosText = parseSection(issueBody, "Potential False Positives");

const missing: string[] = [];
if (!attackType) missing.push("Attack Type");
if (!description) missing.push("Description");
if (!payload) missing.push("Example Attack Payload");
if (missing.length) {
  console.error(`error: missing required fields: ${missing.join(", ")}`);
  process.exit(2);
}

function slugify(s: string): string {
  return s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60);
}

function inferCategory(type: string): string {
  const t = type.toLowerCase();
  if (/prompt.inject|hijack|jailbreak/.test(t)) return "prompt-injection";
  if (/tool.poison|mcp|malicious.tool|tool.tamper/.test(t)) return "tool-poisoning";
  if (/data.poison|train|finetun/.test(t)) return "data-poisoning";
  if (/exfil|credential|secret|leak|disclosure/.test(t)) return "data-exfiltration";
  if (/denial|dos|flood|rate.limit/.test(t)) return "resource-abuse";
  if (/lateral|pivot|escalat/.test(t)) return "lateral-movement";
  if (/supply.chain|package|dependen/.test(t)) return "supply-chain";
  return "agent-manipulation";
}

function parseRefs(raw: string): string[] {
  if (!raw) return [];
  return raw
    .split(/[\s,;]+/)
    .map((r) => r.trim())
    .filter((r) => r.length > 0);
}

const slug = slugify(attackType);
const issueNum = parseInt(ISSUE_NUMBER, 10);
const category = inferCategory(attackType);
const today = new Date().toISOString().slice(0, 10).replace(/-/g, "/");

const refs = parseRefs(references);
const cveRefs = refs.filter((r) => /^CVE-/i.test(r));
const owaspRefs = refs.filter((r) => /LLM\d|ASI\d/i.test(r));
const atlasRefs = refs.filter((r) => /AML\./i.test(r));
const attackRefs = refs.filter((r) => /T\d{4}/i.test(r));

const falsePosLines = falsePosText
  ? falsePosText
      .split("\n")
      .map((l) => l.replace(/^[-*]\s*/, "").trim())
      .filter((l) => l.length > 0)
  : [];

// Indent a multi-line string for YAML block scalar
function indent(s: string, spaces: number): string {
  const pad = " ".repeat(spaces);
  return s
    .split("\n")
    .map((l) => (l.trim() ? pad + l : l))
    .join("\n");
}

function yamlStringList(items: string[], indentSpaces: number): string {
  if (!items.length) return "[]";
  const pad = " ".repeat(indentSpaces);
  return "\n" + items.map((i) => `${pad}- "${i}"`).join("\n");
}

const fpBlock =
  falsePosLines.length
    ? falsePosLines.map((l) => `    - "${l.replace(/"/g, '\\"')}"`).join("\n")
    : '    - "No false positives identified by submitter."';

const cveBlock = cveRefs.length
  ? `\n  cve:${yamlStringList(cveRefs, 4)}`
  : "";
const owaspBlock = owaspRefs.length
  ? `\n  owasp_llm:${yamlStringList(owaspRefs, 4)}`
  : "";
const atlasBlock = atlasRefs.length
  ? `\n  mitre_atlas:${yamlStringList(atlasRefs, 4)}`
  : "";
const attackBlock = attackRefs.length
  ? `\n  mitre_attack:${yamlStringList(attackRefs, 4)}`
  : "";
const externalBlock = `\n  external:\n    - "https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/${issueNum}"`;

const refsSection = `references:${cveBlock}${owaspBlock}${atlasBlock}${attackBlock}${externalBlock}`;

const payloadIndented = indent(payload, 2);

const yaml = `# ATR rule proposal -- generated from GitHub Issue #${issueNum}
# Submitted by: @${AUTHOR}
# Source: https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/${issueNum}
# Status: DRAFT -- detection.conditions MUST be filled in before merge.
title: "${attackType.replace(/"/g, '\\"')} — community proposal"
id: ATR-COMMUNITY-ISSUE-${issueNum}
rule_version: 1
status: draft
description: >
${indent(description, 2)}
author: "ATR Community (@${AUTHOR})"
date: "${today}"
schema_version: "0.1"
detection_tier: pattern
maturity: experimental
severity: medium

${refsSection}

tags:
  category: ${category}
  scan_target: mcp
  confidence: medium

agent_source:
  type: mcp_exchange
  framework:
    - any
  provider:
    - any

detection:
  condition: any
  false_positives:
${fpBlock}
  conditions: []
    # TODO: author a detection regex based on the example payload below.
    # Run: npx tsx scripts/check-rules-safety.ts <this-file>
    # Required: 0 FP on data/skill-benchmark/benign/ before PR merge.

response:
  actions:
    - alert
  auto_response_threshold: medium
  message_template: >
    [ATR-COMMUNITY-ISSUE-${issueNum}] MEDIUM: ${attackType} detected.

confidence: 50

test_cases:
  true_positives: []
    # TODO: derive from example payload once detection regex is written.
  true_negatives: []

_triage:
  source: github-issue
  issue_number: ${issueNum}
  submitted_by: "@${AUTHOR}"
  detection_ready: false
  example_payload: |
${payloadIndented}
`;

const filename = `ISSUE-${issueNum}-${slug}.proposal.yaml`;
const outPath = resolve(PROPOSALS_DIR, filename);

console.log(`\nProposal: proposals/community/${filename}`);
console.log(`Category: ${category}`);
console.log(`Issue:    #${issueNum} by @${AUTHOR}`);

if (WRITE) {
  if (!existsSync(PROPOSALS_DIR)) mkdirSync(PROPOSALS_DIR, { recursive: true });
  writeFileSync(outPath, yaml, "utf8");
  console.log(`Written:  ${outPath}`);
  console.log(`::proposal-file::proposals/community/${filename}`);
} else {
  console.log("\n--- DRY RUN (pass --write to save) ---");
  console.log(yaml);
}
