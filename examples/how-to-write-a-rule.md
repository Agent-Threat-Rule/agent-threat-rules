# How to Write an ATR Rule

This guide walks you through creating a new ATR detection rule.

## Step 1: Identify the Attack

Before writing a rule, clearly define:
- What attack does this detect?
- Which OWASP LLM Top 10 category does it map to?
- What data source is needed (LLM I/O, tool calls, agent behavior)?
- What patterns indicate this attack?

## Step 2: Choose the Right Category

| Category | Use When |
|----------|----------|
| `prompt-injection` | User/external input tries to override agent instructions |
| `tool-poisoning` | Tool responses contain malicious or manipulative content |
| `context-exfiltration` | Agent leaks system prompt, API keys, or internal data |
| `agent-manipulation` | One agent manipulates another agent's behavior |
| `privilege-escalation` | Agent accesses resources beyond its authorized scope |
| `excessive-autonomy` | Agent operates beyond intended boundaries (loops, resource abuse) |
| `data-poisoning` | Training or retrieval data has been tampered with |

## Step 3: Write the Rule

```yaml
title: My New Detection Rule
id: ATR-2026-XXX
status: draft
description: |
  Detects [specific attack pattern] by monitoring [data source]
  for [specific indicators].
author: Your Name
date: 2026/03/08
severity: high

references:
  owasp_llm:
    - "LLM01:2025"
  mitre_atlas:
    - "AML.T0054"

tags:
  category: prompt-injection
  subcategory: your-subcategory
  confidence: medium

agent_source:
  type: llm_io
  framework: [any]
  provider: [any]

detection:
  conditions:
    my_patterns:
      field: user_input
      patterns:
        - "pattern one"
        - "pattern two"
      match_type: regex
      case_sensitive: false
  condition: "my_patterns"
  false_positives:
    - "Describe known false positive scenarios"

response:
  actions:
    - block_input
    - alert
  auto_response_threshold: 0.85
  message_template: |
    [ATR] Rule triggered: {rule_id}
    Pattern: {matched_pattern}

test_cases:
  true_positives:
    - input: "Example malicious input that should trigger"
      expected: trigger
    - input: "Another malicious variant"
      expected: trigger
  true_negatives:
    - input: "Legitimate input that should not trigger"
      expected: no_trigger
    - input: "Another legitimate example"
      expected: no_trigger
```

## Step 4: Test Your Rule

1. Ensure regex patterns compile without errors
2. Verify true positives actually match
3. Verify true negatives do NOT match
4. Run the validation script:

```bash
npm run validate
```

## Tips

- **Start broad, then narrow**: Begin with obvious patterns, add edge cases later
- **Document false positives**: Every rule will have legitimate triggers. List them.
- **Test edge cases**: Unicode, mixed case, multi-line inputs, encoded content
- **Keep patterns maintainable**: Prefer readable regex over clever one-liners
- **Map to frameworks**: Always include OWASP LLM or MITRE ATLAS references
