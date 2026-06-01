/**
 * Tests for the deterministic gate in author-rule-llm.ts.
 *
 * The LLM only PROPOSES a rule draft; validateDraft() is what decides whether
 * it is safe to auto-promote. These tests use mock drafts (no API key needed)
 * and pin the safety contract: a draft is rejected (→ human review) if it
 * matches benign code, fails to match its own attack samples, is too generic,
 * or the model declared itself insufficient.
 */

import { describe, it, expect } from "vitest";
import {
  validateDraft,
  buildRule,
  toJsRegExp,
  type LlmRuleDraft,
} from "../scripts/author-rule-llm.js";

const BENIGN = [
  "import random\nseed = random.randint(0, 100)",
  "from bs4 import BeautifulSoup as Soup\nsoup = Soup(html)",
  "from langchain_core.load import load\nobj = load(data)",
  'url = "http://127.0.0.1:8000/mcp"',
];

describe("toJsRegExp", () => {
  it("honors a leading (?i) inline flag", () => {
    const rx = toJsRegExp("(?i)Attack");
    expect(rx.test("ATTACK")).toBe(true);
    expect(rx.flags).toContain("i");
  });
});

describe("validateDraft gate", () => {
  it("accepts a generalized SSRF-to-metadata draft", () => {
    const draft: LlmRuleDraft = {
      category: "tool-poisoning",
      severity: "high",
      conditions: [
        { value: "(?i)169\\.254\\.169\\.254/(latest|computeMetadata)", description: "cloud metadata SSRF" },
      ],
      true_positives: [
        "agent.fetch('http://169.254.169.254/latest/meta-data/iam/')",
        "url=http://169.254.169.254/latest/api/token",
      ],
      true_negatives: ["import requests", "base = config.endpoint"],
    };
    expect(validateDraft(draft, BENIGN)).toMatchObject({ ok: true });
  });

  it("REJECTS an import-random draft (benign-CODE FP)", () => {
    const draft: LlmRuleDraft = {
      conditions: [{ value: "(?i)import random" }],
      true_positives: ["import random"],
      true_negatives: ["hello world", "weather forecast"],
    };
    const r = validateDraft(draft, BENIGN);
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("benign-CODE FP");
  });

  it("REJECTS a draft whose regex matches none of its true_positives", () => {
    const draft: LlmRuleDraft = {
      conditions: [{ value: "(?i)NEVER_MATCHES_THIS_TOKEN_XYZ" }],
      true_positives: ["a real attack payload"],
      true_negatives: ["benign one", "benign two"],
    };
    const r = validateDraft(draft, BENIGN);
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("true_positives");
  });

  it("REJECTS a too-generic single-token pattern", () => {
    const draft: LlmRuleDraft = {
      conditions: [{ value: "(?i)load" }],
      true_positives: ["load(data)"],
      true_negatives: ["benign one", "benign two"],
    };
    expect(validateDraft(draft, BENIGN).ok).toBe(false);
  });

  it("REJECTS a draft the model declared insufficient (routes to human)", () => {
    const draft: LlmRuleDraft = { insufficient: true, reason: "no generalizable signature" };
    const r = validateDraft(draft, BENIGN);
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("llm-insufficient");
  });

  it("REJECTS a draft with fewer than 2 true_negatives", () => {
    const draft: LlmRuleDraft = {
      conditions: [{ value: "(?i)169\\.254\\.169\\.254" }],
      true_positives: ["http://169.254.169.254/latest"],
      true_negatives: ["only one"],
    };
    expect(validateDraft(draft, BENIGN).ok).toBe(false);
  });

  it("REJECTS a draft that false-positives on its own true_negative", () => {
    const draft: LlmRuleDraft = {
      conditions: [{ value: "(?i)fetch\\(" }],
      true_positives: ["fetch(attacker_url)"],
      true_negatives: ["fetch(safe_url)", "normal text"],
    };
    const r = validateDraft(draft, BENIGN);
    expect(r.ok).toBe(false);
    expect(r.reason).toMatch(/true_negative/);
  });
});

describe("buildRule", () => {
  it("produces an experimental rule, strips sync metadata, records authorship", () => {
    const proposal = {
      id: "ATR-2026-09999",
      title: "Test",
      tags: { category: "tool-poisoning", scan_target: "runtime" },
      _ghsa_sync: { ghsa_id: "GHSA-x" },
      _triage: { detection_ready: true },
    };
    const draft: LlmRuleDraft = {
      category: "tool-poisoning",
      severity: "high",
      conditions: [{ value: "(?i)169\\.254\\.169\\.254", description: "ssrf" }],
      true_positives: ["http://169.254.169.254/latest"],
      true_negatives: ["a", "b"],
      generalization_note: "matches the metadata IP class",
    };
    const rule = buildRule(proposal, draft) as Record<string, any>;
    expect(rule.status).toBe("experimental");
    expect(rule._ghsa_sync).toBeUndefined();
    expect(rule._triage).toBeUndefined();
    expect(rule.detection.conditions[0].value).toContain("169");
    expect(rule.test_cases.true_positives.length).toBe(1);
    expect(rule.test_cases.true_negatives.length).toBe(2);
    expect(rule._llm_authored).toBeDefined();
  });
});
