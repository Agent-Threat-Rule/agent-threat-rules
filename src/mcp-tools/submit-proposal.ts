/**
 * atr_submit_proposal MCP tool - Generate ATR rule draft from threat description
 * @module agent-threat-rules/mcp-tools/submit-proposal
 */

import { RuleScaffolder } from '../rule-scaffolder.js';
import type { ATRCategory, ATRSeverity } from '../types.js';

const VALID_CATEGORIES: ReadonlySet<string> = new Set([
  'prompt-injection',
  'tool-poisoning',
  'context-exfiltration',
  'agent-manipulation',
  'privilege-escalation',
  'excessive-autonomy',
  'data-poisoning',
  'model-abuse',
  'model-security',
  'skill-compromise',
]);

const VALID_SEVERITIES: ReadonlySet<string> = new Set([
  'critical',
  'high',
  'medium',
  'low',
  'informational',
]);

export function handleSubmitProposal(args: Record<string, unknown>): {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
} {
  const title = args['title'];
  const category = args['category'];
  const attackDescription = args['attack_description'];
  const examplePayloads = args['example_payloads'];
  const severity = args['severity'] as string | undefined;
  const mitreRefs = args['mitre_refs'] as string[] | undefined;

  // Validate required fields
  if (typeof title !== 'string' || title.trim().length === 0) {
    return {
      content: [{ type: 'text', text: 'Error: "title" is required and must be a non-empty string.' }],
      isError: true,
    };
  }

  if (typeof category !== 'string' || !VALID_CATEGORIES.has(category)) {
    return {
      content: [{ type: 'text', text: `Error: "category" must be one of: ${[...VALID_CATEGORIES].join(', ')}` }],
      isError: true,
    };
  }

  if (typeof attackDescription !== 'string' || attackDescription.trim().length === 0) {
    return {
      content: [{ type: 'text', text: 'Error: "attack_description" is required and must be a non-empty string.' }],
      isError: true,
    };
  }

  if (!Array.isArray(examplePayloads) || examplePayloads.length === 0) {
    return {
      content: [{ type: 'text', text: 'Error: "example_payloads" must be a non-empty array of strings.' }],
      isError: true,
    };
  }

  for (const payload of examplePayloads) {
    if (typeof payload !== 'string') {
      return {
        content: [{ type: 'text', text: 'Error: All items in "example_payloads" must be strings.' }],
        isError: true,
      };
    }
  }

  if (severity && !VALID_SEVERITIES.has(severity)) {
    return {
      content: [{ type: 'text', text: `Error: "severity" must be one of: ${[...VALID_SEVERITIES].join(', ')}` }],
      isError: true,
    };
  }

  if (mitreRefs !== undefined) {
    if (!Array.isArray(mitreRefs) || mitreRefs.some((r: unknown) => typeof r !== 'string')) {
      return {
        content: [{ type: 'text', text: 'Error: "mitre_refs" must be an array of strings.' }],
        isError: true,
      };
    }
  }

  const scaffolder = new RuleScaffolder();
  const result = scaffolder.scaffold({
    title: title.trim(),
    category: category as ATRCategory,
    attackDescription: attackDescription.trim(),
    examplePayloads: examplePayloads.map((p: string) => p.trim()),
    severity: severity as ATRSeverity | undefined,
    mitreRefs: mitreRefs,
  });

  const response = {
    generated_id: result.id,
    warnings: result.warnings,
    yaml_rule: result.yaml,
    next_steps: [
      'Review and refine the generated detection patterns',
      'Add more specific regex patterns for your use case',
      'Test with atr_scan using example payloads',
      'Validate with atr_validate_rule before submitting',
      'Submit as a PR to the ATR repository',
    ],
  };

  return {
    content: [{ type: 'text', text: JSON.stringify(response, null, 2) }],
  };
}
