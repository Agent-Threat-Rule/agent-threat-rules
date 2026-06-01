/**
 * Regression test for the benign-CODE FP gate (check-rules-safety Check 3c).
 *
 * Context: 11 auto-promoted rules (ATR-2026-00554..00564) reached main with
 * detection patterns that were benign code lines -- e.g. `import random`,
 * `from bs4 import BeautifulSoup`. They passed every existing FP check because
 * those corpora are prose (skill markdown, arxiv, package descriptions), never
 * source code. data/benign-code/corpus.jsonl closes that blind spot.
 *
 * This test guards two failure modes:
 *  1. The corpus is emptied / stripped of the critical lines (gate goes silent).
 *  2. A real attack indicator is accidentally added to the corpus (which would
 *     whitelist real attacks).
 * Plus a live engine match proving an import-pattern rule actually fires on the
 * corpus code (so the gate has something to catch).
 */

import { describe, it, expect } from "vitest";
import {
  readFileSync,
  writeFileSync,
  mkdtempSync,
  rmSync,
  existsSync,
} from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { ATREngine } from "../src/engine.js";
import type { AgentEvent } from "../src/types.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS = join(REPO_ROOT, "data/benign-code/corpus.jsonl");

interface Sample {
  source: string;
  source_id: string;
  text: string;
}

function loadCorpus(): Sample[] {
  return readFileSync(CORPUS, "utf-8")
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l) as Sample);
}

describe("benign-code FP gate corpus", () => {
  const samples = loadCorpus();

  it("exists and is non-trivially sized", () => {
    expect(existsSync(CORPUS)).toBe(true);
    expect(samples.length).toBeGreaterThanOrEqual(40);
    for (const s of samples) {
      expect(typeof s.text).toBe("string");
      expect(s.text.length).toBeGreaterThan(0);
    }
  });

  it("contains the exact benign lines the reverted rules false-positived on", () => {
    const all = samples.map((s) => s.text).join("\n");
    for (const line of [
      "import random",
      "from bs4 import BeautifulSoup",
      "from string import Formatter",
      "from langchain_core.load import load",
      "from pydantic_ai import",
      '@langchain/core/load',
    ]) {
      expect(all).toContain(line);
    }
  });

  it("does NOT contain real attack indicators (would whitelist real attacks)", () => {
    const all = samples.map((s) => s.text).join("\n");
    expect(all).not.toContain("169.254.169.254");
    expect(all).not.toContain("attacker.com");
    expect(all).not.toContain("/etc/passwd");
  });

  it("a synthetic import-pattern rule fires on the benign corpus code (gate has a target)", () => {
    const tmp = mkdtempSync(join(tmpdir(), "atr-fpgate-"));
    const rulePath = join(tmp, "rule.yaml");
    writeFileSync(
      rulePath,
      [
        "title: synthetic import-random rule",
        "id: ATR-2026-09999",
        "rule_version: 1",
        "status: experimental",
        "description: test",
        "author: test",
        "date: 2026/06/02",
        "schema_version: '0.1'",
        "detection_tier: pattern",
        "maturity: experimental",
        "severity: high",
        "tags:",
        "  category: tool-poisoning",
        "  scan_target: runtime",
        "  confidence: high",
        "agent_source:",
        "  type: llm_io",
        "  framework: [any]",
        "  provider: [any]",
        "detection:",
        "  condition: any",
        "  false_positives: []",
        "  conditions:",
        "    - field: content",
        "      operator: regex",
        "      value: (?i)import random",
        "      description: test",
        "response:",
        "  actions: [alert]",
        "test_cases:",
        "  true_positives: []",
        "  true_negatives: []",
      ].join("\n"),
      "utf-8",
    );

    const engine = new ATREngine({});
    engine.addRuleFile(rulePath);

    const sample = samples.find((s) => s.text.startsWith("import random"));
    expect(sample).toBeDefined();
    const event: AgentEvent = {
      type: "llm_input",
      timestamp: "2026-06-02T00:00:00Z",
      content: sample!.text,
    };
    const matches = engine.evaluate(event);
    rmSync(tmp, { recursive: true, force: true });
    expect(matches.some((m) => m.rule.id === "ATR-2026-09999")).toBe(true);
  });
});
