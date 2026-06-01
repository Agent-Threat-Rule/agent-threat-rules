#!/usr/bin/env npx tsx
/**
 * author-rule-llm.ts
 *
 * LLM-assisted authoring of an ATR detection rule from a CVE/GHSA proposal.
 * This is the Cisco-grade upgrade to the heuristic generate-detection-from-poc.ts:
 * instead of lifting a single regex line out of a PoC code block (narrow, and
 * historically prone to import-FPs), it gives Claude the full advisory context
 * — description + PoC + the PATCH DIFF (the fix commit) + CWE — and asks for a
 * GENERALIZED deterministic regex rule plus realistic true/false-positive tests.
 *
 * The LLM only PROPOSES. A deterministic gate then verifies the draft and
 * rejects anything unsafe — the regex must compile, must match its own
 * true_positives, and must produce ZERO matches against the benign-code corpus
 * and its own true_negatives. Runtime detection stays pure regex; the LLM is
 * generation-time only and every rule is still human-reviewed before merge.
 *
 * Same CLI contract as generate-detection-from-poc.ts so it is a drop-in for
 * promote-detection-ready.ts:
 *   exit 0  rule emitted (passed the gate) — eligible for the auto-merge gate
 *   exit 2  no usable source / API unavailable
 *   exit 3  routed to human review (LLM said insufficient, or draft failed gate)
 *
 * Env:
 *   ANTHROPIC_API_KEY   required to call the model (else exit 2)
 *   ATR_AUTHOR_MODEL    model id (default claude-haiku-4-5-20251001; set a
 *                       Sonnet/Opus id in CI for best authoring quality)
 *   GITHUB_TOKEN        optional, raises the patch-diff fetch rate limit
 *
 * Usage:
 *   ANTHROPIC_API_KEY=... npx tsx scripts/author-rule-llm.ts \
 *     proposals/ghsa/GHSA-xxxx.proposal.yaml --output rules/.../ATR-....yaml
 *   npx tsx scripts/author-rule-llm.ts <proposal> --dry-run
 */

import { readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import Anthropic from "@anthropic-ai/sdk";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..");
const BENIGN_CODE_DIR = resolve(REPO_ROOT, "data/benign-code");
const DEFAULT_MODEL = "claude-haiku-4-5-20251001";
const PATCH_MAX_CHARS = 6000;
const POC_MAX_CHARS = 4000;

export interface LlmRuleDraft {
  insufficient?: boolean;
  reason?: string;
  category?: string;
  severity?: string;
  conditions?: Array<{ value: string; description?: string }>;
  true_positives?: string[];
  true_negatives?: string[];
  generalization_note?: string;
}

const VALID_CATEGORIES = new Set([
  "agent-manipulation",
  "context-exfiltration",
  "data-poisoning",
  "excessive-autonomy",
  "model-abuse",
  "privilege-escalation",
  "prompt-injection",
  "skill-compromise",
  "tool-poisoning",
]);

// ---------------------------------------------------------------------------
// Deterministic gate (the part that does NOT trust the LLM). Pure + testable.
// ---------------------------------------------------------------------------

/**
 * Convert an ATR pattern value (which may carry a leading inline `(?i)` flag,
 * the convention used in rules/) into a JS RegExp.
 */
export function toJsRegExp(value: string): RegExp {
  let flags = "";
  let src = value;
  const m = src.match(/^\(\?([a-z]+)\)/);
  if (m) {
    if (m[1].includes("i")) flags += "i";
    if (m[1].includes("m")) flags += "m";
    if (m[1].includes("s")) flags += "s";
    src = src.slice(m[0].length);
  }
  return new RegExp(src, flags);
}

function loadBenignCode(): string[] {
  if (!existsSync(BENIGN_CODE_DIR)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(BENIGN_CODE_DIR)) {
    if (!entry.endsWith(".jsonl")) continue;
    let raw: string;
    try {
      raw = readFileSync(join(BENIGN_CODE_DIR, entry), "utf-8");
    } catch {
      continue;
    }
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        const o = JSON.parse(t) as { text?: string };
        if (typeof o.text === "string") out.push(o.text);
      } catch {
        /* skip */
      }
    }
  }
  return out;
}

export interface GateResult {
  ok: boolean;
  reason: string;
}

/**
 * Verify an LLM draft deterministically. Returns ok:false (→ route to human)
 * for anything that would be unsafe to auto-promote.
 */
export function validateDraft(
  draft: LlmRuleDraft,
  benignCode: string[],
): GateResult {
  if (draft.insufficient) {
    return { ok: false, reason: `llm-insufficient: ${draft.reason ?? "no reason given"}` };
  }
  const conditions = draft.conditions ?? [];
  if (conditions.length === 0) return { ok: false, reason: "no conditions" };
  if (conditions.length > 3) return { ok: false, reason: "too many conditions (>3)" };

  const tps = (draft.true_positives ?? []).filter((s) => typeof s === "string" && s.length > 0);
  const tns = (draft.true_negatives ?? []).filter((s) => typeof s === "string" && s.length > 0);
  if (tps.length < 1) return { ok: false, reason: "no true_positives" };
  if (tns.length < 2) return { ok: false, reason: "need >=2 true_negatives" };

  const compiled: RegExp[] = [];
  for (const c of conditions) {
    if (typeof c.value !== "string" || c.value.length < 6) {
      return { ok: false, reason: `condition too short / invalid: ${c.value}` };
    }
    // Specificity floor: reject a bare common token (one word, no structure).
    const bare = c.value.replace(/^\(\?[a-z]+\)/, "");
    if (/^[\w-]{1,12}$/.test(bare) && !/[.\\[\](){}|^$*+?]/.test(bare)) {
      return { ok: false, reason: `pattern too generic: ${c.value}` };
    }
    try {
      compiled.push(toJsRegExp(c.value));
    } catch (e) {
      return { ok: false, reason: `regex does not compile (${c.value}): ${e}` };
    }
  }

  // Every condition must match at least one of the rule's own true_positives.
  for (let i = 0; i < compiled.length; i++) {
    const fires = tps.some((tp) => compiled[i].test(tp));
    if (!fires) {
      return { ok: false, reason: `condition ${i} matches none of its true_positives` };
    }
  }

  // HARD gate: no condition may match any benign-code sample.
  for (const rx of compiled) {
    for (const sample of benignCode) {
      if (rx.test(sample)) {
        return {
          ok: false,
          reason: `benign-CODE FP: /${rx.source}/ matches benign code "${sample.slice(0, 50)}"`,
        };
      }
    }
    // ...nor any of its own declared true_negatives.
    for (const tn of tns) {
      if (rx.test(tn)) {
        return { ok: false, reason: `FP on own true_negative: /${rx.source}/ matches "${tn.slice(0, 50)}"` };
      }
    }
  }

  return { ok: true, reason: "passed" };
}

// ---------------------------------------------------------------------------
// Rule construction (pure + testable)
// ---------------------------------------------------------------------------

export function buildRule(
  proposal: Record<string, unknown>,
  draft: LlmRuleDraft,
): Record<string, unknown> {
  const rule = { ...proposal };
  delete (rule as Record<string, unknown>)._ghsa_sync;
  delete (rule as Record<string, unknown>)._nvd_sync;
  delete (rule as Record<string, unknown>)._triage;
  delete (rule as Record<string, unknown>)._needs_human_poc;

  rule.status = "experimental";
  rule.maturity = "experimental";
  const cat = draft.category && VALID_CATEGORIES.has(draft.category) ? draft.category : undefined;
  const tags = (rule.tags as Record<string, unknown>) ?? {};
  rule.tags = { ...tags, category: cat ?? (tags as { category?: string }).category ?? "model-abuse" };
  if (draft.severity) rule.severity = draft.severity;

  rule.detection = {
    condition: "any",
    false_positives: [],
    conditions: (draft.conditions ?? []).map((c) => ({
      field: "content",
      operator: "regex",
      value: c.value,
      description: c.description ?? "LLM-authored attack-class pattern",
    })),
  };

  rule.test_cases = {
    true_positives: (draft.true_positives ?? []).map((input, i) => ({
      input,
      expected: "triggered",
      description: `LLM-authored attack sample ${i + 1}`,
    })),
    true_negatives: (draft.true_negatives ?? []).map((input, i) => ({
      input,
      expected: "not_triggered",
      description: `LLM-authored benign sample ${i + 1}`,
    })),
  };

  (rule as Record<string, unknown>)._llm_authored = {
    model: process.env.ATR_AUTHOR_MODEL || DEFAULT_MODEL,
    generalization_note: draft.generalization_note ?? "",
    note: "Generation-time LLM authoring; verified by deterministic gate. Runtime detection is pure regex. Human review required before merge.",
  };

  return rule;
}

// ---------------------------------------------------------------------------
// IO + LLM call (the thin, network-bound part)
// ---------------------------------------------------------------------------

function sourceContext(proposal: Record<string, unknown>): {
  description: string;
  poc: string;
  cwes: string[];
  pkg: string;
  commitUrls: string[];
} {
  const description = typeof proposal.description === "string" ? proposal.description : "";
  const ghsa = proposal._ghsa_sync as Record<string, unknown> | undefined;
  const poc =
    ghsa && typeof ghsa.advisory_body === "string"
      ? ghsa.advisory_body.slice(0, POC_MAX_CHARS)
      : "";
  const refs = (proposal.references as { cwe?: string[]; external?: string[] }) ?? {};
  const cwes = Array.isArray(refs.cwe) ? refs.cwe : [];
  const external = Array.isArray(refs.external) ? refs.external : [];
  const commitUrls = external.filter((u) => /\/commit\/[0-9a-f]{7,40}/.test(u));
  const pkgList = Array.isArray(ghsa?.affected_packages)
    ? (ghsa!.affected_packages as string[])
    : [];
  return { description, poc, cwes, pkg: pkgList.join(", "), commitUrls };
}

async function fetchPatchDiff(commitUrls: string[]): Promise<string> {
  for (const url of commitUrls) {
    const m = url.match(/github\.com\/([^/]+)\/([^/]+)\/commit\/([0-9a-f]{7,40})/);
    if (!m) continue;
    const [, owner, repo, sha] = m;
    const api = `https://api.github.com/repos/${owner}/${repo}/commits/${sha}`;
    const headers: Record<string, string> = {
      Accept: "application/vnd.github.diff",
      "User-Agent": "atr-author-rule",
    };
    const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
    if (token) headers.Authorization = `Bearer ${token}`;
    try {
      const resp = await fetch(api, { headers });
      if (resp.ok) {
        const diff = await resp.text();
        if (diff.trim()) return diff.slice(0, PATCH_MAX_CHARS);
      }
    } catch {
      /* try next */
    }
  }
  return "";
}

export function buildPrompt(
  ctx: ReturnType<typeof sourceContext>,
  patch: string,
  benignSamples: string[],
): string {
  const benign = benignSamples.slice(0, 24).map((s) => `  - ${s.replace(/\n/g, " \\n ")}`).join("\n");
  return [
    "You are a senior detection engineer authoring one ATR (Agent Threat Rules) rule from a security advisory.",
    "ATR rules are DETERMINISTIC REGEX that scan AI-agent IO content (tool inputs/outputs, LLM messages) at runtime.",
    "Goal: detect the ATTACK CLASS, generalized beyond the literal PoC, with ZERO false positives on benign code.",
    "",
    "ADVISORY DESCRIPTION:",
    ctx.description || "(none)",
    "",
    `CWE: ${ctx.cwes.join(", ") || "(none)"}`,
    `AFFECTED PACKAGE: ${ctx.pkg || "(unknown)"}`,
    "",
    "PROOF OF CONCEPT / ADVISORY BODY:",
    ctx.poc || "(none)",
    "",
    "PATCH DIFF (the fix — shows the vulnerable code that was changed):",
    patch || "(unavailable)",
    "",
    "HARD CONSTRAINTS:",
    "1. Author 1-3 JS-compatible regex conditions that match the attack payload/technique, GENERALIZED",
    "   (e.g. for SSRF-to-metadata, match the 169.254.169.254 metadata class, not one literal PoC URL).",
    "2. The regex MUST NEVER match benign code: imports, normal library usage, config. It must NOT match any of:",
    benign || "  (corpus unavailable)",
    "3. Give 2-4 true_positives: realistic attack strings the rule MUST match (include variations, not just the PoC).",
    "4. Give 3-5 true_negatives: benign strings the rule must NOT match, incl. normal usage of the same library.",
    "5. Match only the attacker-controlled PAYLOAD, never a legitimate feature or configuration that is ALSO the",
    "   normal way to use the library. Setting api_base/base_url to a custom endpoint, template_format='jinja2',",
    "   msgpack raw=/strict_map_key=, or prevent_outside=True (that is the SECURE setting) are all NORMAL — do not",
    "   match them. For an SSRF-via-config or feature-abuse bug where the config value itself is legitimate, the",
    "   detectable signal is the malicious target (internal/metadata host, traversal), not the config key.",
    "6. Do NOT match the vulnerable library's internal source symbols / function names (e.g. a specific Go method,",
    "   an internal helper). ATR scans agent IO content (tool inputs/outputs, messages), NOT the library's source.",
    "7. For template / SSTI bugs, require a real injection traversal — dunder or builtins access like",
    "   __class__ / __globals__ / __import__ / __builtins__ / __subclasses__ / .mro(). Never match a plain",
    "   template variable like {{ user.name }} or {{ obj.attr }}; those are normal templates.",
    "8. If the vulnerability is only observable in SOURCE CODE or SERVER CONFIG and produces no attacker-controlled",
    "   payload in agent IO (e.g. a missing-authorization check, a serialization marker that is identical for",
    "   benign and malicious objects), set insufficient=true — do NOT force a rule that matches benign traffic.",
    "9. If you cannot author a rule that is BOTH generalized AND zero-FP, set insufficient=true with a reason.",
    "   Do not force a weak or import-matching rule.",
    "",
    "Return ONLY one JSON object, no prose, no markdown fence:",
    '{"insufficient": false, "category": "<one of: agent-manipulation|context-exfiltration|data-poisoning|excessive-autonomy|model-abuse|privilege-escalation|prompt-injection|skill-compromise|tool-poisoning>",',
    ' "severity": "<low|medium|high|critical>",',
    ' "conditions": [{"value": "<regex, may start with (?i)>", "description": "<what it detects>"}],',
    ' "true_positives": ["<attack string>"], "true_negatives": ["<benign string>"],',
    ' "generalization_note": "<how this generalizes beyond the PoC>"}',
  ].join("\n");
}

function extractJson(text: string): LlmRuleDraft | null {
  // Tolerate accidental prose/markdown fences around the JSON object.
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = fence ? fence[1] : text;
  const start = candidate.indexOf("{");
  const end = candidate.lastIndexOf("}");
  if (start < 0 || end <= start) return null;
  try {
    return JSON.parse(candidate.slice(start, end + 1)) as LlmRuleDraft;
  } catch {
    return null;
  }
}

async function callLlm(prompt: string): Promise<LlmRuleDraft | null> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) return null;
  const model = process.env.ATR_AUTHOR_MODEL || DEFAULT_MODEL;
  const client = new Anthropic({ apiKey });
  const resp = await client.messages.create({
    model,
    max_tokens: 1500,
    messages: [{ role: "user", content: prompt }],
  });
  const text = resp.content
    .filter((b): b is Anthropic.TextBlock => b.type === "text")
    .map((b) => b.text)
    .join("\n");
  return extractJson(text);
}

function emit(status: string, extra: Record<string, unknown> = {}): void {
  console.error(JSON.stringify({ status, ...extra }));
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const inputPath = args.find((a) => !a.startsWith("-"));
  if (!inputPath) {
    console.error("usage: author-rule-llm.ts <proposal.yaml> [--output <path>] [--dry-run]");
    process.exit(2);
  }
  if (!process.env.ANTHROPIC_API_KEY) {
    emit("no_api_key");
    process.exit(2);
  }
  const outIdx = args.indexOf("--output");
  const outputPath = outIdx >= 0 ? args[outIdx + 1] : null;
  const dryRun = args.includes("--dry-run");

  let proposal: Record<string, unknown>;
  try {
    proposal = yaml.load(readFileSync(resolve(REPO_ROOT, inputPath), "utf-8")) as Record<string, unknown>;
  } catch (e) {
    emit("parse_error", { error: String(e) });
    process.exit(2);
  }

  const ctx = sourceContext(proposal);
  if (!ctx.description && !ctx.poc) {
    emit("no_source_text");
    process.exit(2);
  }

  const benignCode = loadBenignCode();
  const patch = await fetchPatchDiff(ctx.commitUrls);
  const prompt = buildPrompt(ctx, patch, benignCode);

  let draft: LlmRuleDraft | null;
  try {
    draft = await callLlm(prompt);
  } catch (e) {
    emit("llm_error", { error: String(e) });
    process.exit(2);
  }
  if (!draft) {
    emit("llm_no_json");
    process.exit(3);
  }

  const gate = validateDraft(draft, benignCode);
  if (!gate.ok) {
    // Draft is unsafe / insufficient — route to human review.
    emit("routed_to_human", { reason: gate.reason });
    process.exit(3);
  }

  const rule = buildRule(proposal, draft);
  const ruleYaml = yaml.dump(rule, { lineWidth: 120, noRefs: true });

  if (dryRun) {
    emit("dry_run", {
      proposal_id: proposal.id,
      conditions: (draft.conditions ?? []).length,
      patch_used: patch.length > 0,
    });
  } else if (outputPath) {
    writeFileSync(resolve(REPO_ROOT, outputPath), ruleYaml, "utf-8");
    emit("written", { output: outputPath, proposal_id: proposal.id, patch_used: patch.length > 0 });
  } else {
    console.log(ruleYaml);
  }
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch((e) => {
    console.error("fatal:", e);
    process.exit(2);
  });
}
