import { describe, it, expect } from "vitest";
import {
  parseATRRule,
  atrRuleToMetadata,
} from "../../../src/quality/adapters/atr.js";

const MINIMAL_YAML = `
title: "Test rule"
id: ATR-TEST-00001
status: experimental
maturity: experimental
severity: high
detection:
  conditions:
    - field: content
      operator: regex
      value: 'test.*pattern'
      description: 'Test pattern 1'
    - field: content
      operator: regex
      value: 'another.*pattern'
      description: 'Test pattern 2'
    - field: content
      operator: regex
      value: 'third.*pattern'
      description: 'Test pattern 3'
  condition: any
  false_positives:
    - 'Legitimate content that mentions test pattern'
response:
  actions: [alert]
references:
  owasp_llm:
    - "LLM01:2025"
  owasp_agentic:
    - "ASI01:2026"
  mitre_atlas:
    - "AML.T0051"
tags:
  category: prompt-injection
test_cases:
  true_positives:
    - input: 'test evil pattern'
      expected: triggered
    - input: 'test malicious pattern'
      expected: triggered
    - input: 'test attack pattern'
      expected: triggered
    - input: 'test harmful pattern'
      expected: triggered
    - input: 'test bad pattern'
      expected: triggered
  true_negatives:
    - input: 'safe content 1'
      expected: not_triggered
    - input: 'safe content 2'
      expected: not_triggered
    - input: 'safe content 3'
      expected: not_triggered
    - input: 'safe content 4'
      expected: not_triggered
    - input: 'safe content 5'
      expected: not_triggered
evasion_tests:
  - input: 'obfuscated pattern'
    expected: not_triggered
    bypass_technique: 'obfuscation'
  - input: 'paraphrased pattern'
    expected: not_triggered
    bypass_technique: 'paraphrase'
  - input: 'encoded pattern'
    expected: not_triggered
    bypass_technique: 'encoding'
agent_source:
  type: mcp_exchange
author: "Test"
`;

describe("parseATRRule", () => {
  it("extracts all metadata fields from a complete rule", () => {
    const metadata = parseATRRule(MINIMAL_YAML);
    expect(metadata.id).toBe("ATR-TEST-00001");
    expect(metadata.title).toBe("Test rule");
    expect(metadata.maturity).toBe("experimental");
    expect(metadata.conditions).toBe(3);
    expect(metadata.truePositives).toBe(5);
    expect(metadata.trueNegatives).toBe(5);
    expect(metadata.evasionTests).toBe(3);
    expect(metadata.hasOwaspRef).toBe(true);
    expect(metadata.hasMitreRef).toBe(true);
    expect(metadata.hasFalsePositiveDocs).toBe(true);
  });

  it("handles a rule with only status field (no maturity)", () => {
    const yaml = `
title: "Test"
id: TEST-001
status: experimental
severity: low
detection:
  conditions:
    - field: content
      operator: regex
      value: 'x'
  condition: any
response:
  actions: [alert]
tags:
  category: prompt-injection
agent_source:
  type: mcp_exchange
`;
    const metadata = parseATRRule(yaml);
    expect(metadata.maturity).toBe("experimental");
  });

  it('normalizes legacy "test" status to experimental', () => {
    const yaml = `
title: "Test"
id: TEST-001
status: draft
maturity: test
severity: low
detection:
  conditions: []
  condition: any
response:
  actions: [alert]
tags:
  category: prompt-injection
agent_source:
  type: mcp_exchange
`;
    const metadata = parseATRRule(yaml);
    expect(metadata.maturity).toBe("experimental");
  });

  it("defaults to draft for unknown maturity", () => {
    const yaml = `
title: "Test"
id: TEST-001
maturity: weirdvalue
severity: low
detection:
  conditions: []
  condition: any
response:
  actions: [alert]
tags:
  category: prompt-injection
agent_source:
  type: mcp_exchange
`;
    const metadata = parseATRRule(yaml);
    expect(metadata.maturity).toBe("draft");
  });

  it("counts named-map conditions format", () => {
    const yaml = `
title: "Test"
id: TEST-001
maturity: experimental
severity: low
detection:
  conditions:
    layer1:
      field: content
      patterns: ['a']
      match_type: regex
    layer2:
      field: content
      patterns: ['b']
      match_type: regex
  condition: "layer1 or layer2"
response:
  actions: [alert]
tags:
  category: prompt-injection
agent_source:
  type: mcp_exchange
`;
    const metadata = parseATRRule(yaml);
    expect(metadata.conditions).toBe(2);
  });

  it("handles missing optional fields gracefully", () => {
    const yaml = `
title: "Minimal"
id: MIN-001
maturity: draft
severity: low
detection:
  conditions:
    - field: content
      operator: regex
      value: 'x'
  condition: any
response:
  actions: [alert]
tags:
  category: prompt-injection
agent_source:
  type: mcp_exchange
`;
    const metadata = parseATRRule(yaml);
    expect(metadata.truePositives).toBe(0);
    expect(metadata.trueNegatives).toBe(0);
    expect(metadata.evasionTests).toBe(0);
    expect(metadata.hasOwaspRef).toBe(false);
    expect(metadata.hasMitreRef).toBe(false);
    expect(metadata.hasFalsePositiveDocs).toBe(false);
  });

  it("detects LLM-generated rules by author field", () => {
    const yaml = `
title: "LLM rule"
id: LLM-001
maturity: experimental
severity: high
author: "ATR Threat Cloud Crystallization"
detection:
  conditions:
    - field: content
      operator: regex
      value: 'x'
  condition: any
response:
  actions: [alert]
tags:
  category: prompt-injection
agent_source:
  type: mcp_exchange
`;
    const metadata = parseATRRule(yaml);
    expect(metadata.llmGenerated).toBe(true);
  });

  it("parses wild validation fields", () => {
    const yaml = `
title: "Stable rule"
id: STABLE-001
maturity: stable
severity: high
wild_samples: 53577
wild_fp_rate: 0.0
wild_validated: "2026/04/08"
detection:
  conditions:
    - field: content
      operator: regex
      value: 'x'
  condition: any
response:
  actions: [alert]
tags:
  category: prompt-injection
agent_source:
  type: mcp_exchange
`;
    const metadata = parseATRRule(yaml);
    expect(metadata.wildSamples).toBe(53577);
    expect(metadata.wildFpRate).toBe(0.0);
    expect(metadata.wildValidatedAt).toBe("2026/04/08");
  });

  it("throws on invalid YAML", () => {
    expect(() => parseATRRule("not: valid: yaml: [[[")).toThrow();
  });

  it("throws on non-object YAML", () => {
    expect(() => parseATRRule("just a string")).toThrow();
  });
});

describe("atrRuleToMetadata", () => {
  it("accepts a pre-parsed rule object", () => {
    const rule = {
      id: "ATR-2026-00001",
      title: "Direct injection",
      maturity: "stable",
      detection: {
        conditions: [{ field: "content" }, { field: "content" }],
        false_positives: ["safe content"],
      },
      test_cases: {
        true_positives: [
          { input: "a" },
          { input: "b" },
          { input: "c" },
          { input: "d" },
          { input: "e" },
        ],
        true_negatives: [
          { input: "f" },
          { input: "g" },
          { input: "h" },
          { input: "i" },
          { input: "j" },
        ],
      },
      references: {
        owasp_llm: ["LLM01:2025"],
        mitre_atlas: ["AML.T0051"],
      },
    };
    const metadata = atrRuleToMetadata(rule);
    expect(metadata.id).toBe("ATR-2026-00001");
    expect(metadata.conditions).toBe(2);
    expect(metadata.truePositives).toBe(5);
    expect(metadata.trueNegatives).toBe(5);
    expect(metadata.hasOwaspRef).toBe(true);
    expect(metadata.hasMitreRef).toBe(true);
    expect(metadata.hasFalsePositiveDocs).toBe(true);
  });
});
