#!/usr/bin/env node
/**
 * ATR MCP Server - Model Context Protocol server for Agent Threat Rules
 *
 * Exposes ATR functionality as MCP tools for AI agents and IDEs.
 * Start with: atr mcp (stdio transport)
 *
 * @module agent-threat-rules/mcp-server
 */

import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { ATREngine } from './engine.js';
import { handleScan } from './mcp-tools/scan.js';
import { handleScanSkill } from './mcp-tools/scan-skill.js';
import { handleListRules } from './mcp-tools/list-rules.js';
import { handleValidate } from './mcp-tools/validate.js';
import { handleSubmitProposal } from './mcp-tools/submit-proposal.js';
import { handleCoverageGaps } from './mcp-tools/coverage-gaps.js';
import { handleThreatSummary } from './mcp-tools/threat-summary.js';
import { createSemanticJudgeFromConfig } from './cli/semantic-judge-config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const RULES_DIR = resolve(__dirname, '..', 'rules');

const TOOLS = [
  {
    name: 'atr_scan',
    description:
      'Scan text content for AI agent security threats using ATR detection rules. Returns matched rules with severity, confidence, and recommended actions.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        content: {
          type: 'string',
          description: 'The text content to scan for threats (prompt, tool response, agent output, etc.)',
        },
        event_type: {
          type: 'string',
          enum: ['llm_input', 'llm_output', 'tool_call', 'tool_response', 'agent_behavior', 'multi_agent_message'],
          description: 'Type of agent event being scanned. Defaults to "llm_input".',
        },
        min_severity: {
          type: 'string',
          enum: ['informational', 'low', 'medium', 'high', 'critical'],
          description: 'Minimum severity level to include in results. Defaults to "informational".',
        },
      },
      required: ['content'],
    },
  },
  {
    name: 'atr_scan_skill',
    description:
      'Scan SKILL.md file content for AI agent security threats. Uses skill-specific ATR rules to avoid false positives from MCP-oriented rules. Returns matches with severity, content_hash for deduplication, and recommended actions.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        content: {
          type: 'string',
          description: 'The SKILL.md file content to scan for threats.',
        },
        file_name: {
          type: 'string',
          description: 'Optional file name for the SKILL.md being scanned.',
        },
        min_severity: {
          type: 'string',
          enum: ['informational', 'low', 'medium', 'high', 'critical'],
          description: 'Minimum severity level to include in results. Defaults to "medium".',
        },
      },
      required: ['content'],
    },
  },
  {
    name: 'atr_list_rules',
    description:
      'List and filter available ATR detection rules. Search by category, severity, or keyword.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        category: {
          type: 'string',
          enum: [
            'prompt-injection', 'tool-poisoning', 'context-exfiltration',
            'agent-manipulation', 'privilege-escalation', 'excessive-autonomy',
            'data-poisoning', 'model-abuse', 'skill-compromise',
          ],
          description: 'Filter rules by threat category.',
        },
        severity: {
          type: 'string',
          enum: ['informational', 'low', 'medium', 'high', 'critical'],
          description: 'Filter rules by severity level.',
        },
        search: {
          type: 'string',
          description: 'Search rules by keyword in title, description, or ID.',
        },
      },
    },
  },
  {
    name: 'atr_validate_rule',
    description:
      'Validate an ATR rule written in YAML format. Checks required fields, enum values, and structural correctness.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        yaml_content: {
          type: 'string',
          description: 'The ATR rule YAML content to validate.',
        },
      },
      required: ['yaml_content'],
    },
  },
  {
    name: 'atr_submit_proposal',
    description:
      'Generate a draft ATR rule from a threat description. Produces YAML with detection patterns derived from example payloads.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        title: {
          type: 'string',
          description: 'Title for the new rule (e.g., "Multi-turn Context Hijacking").',
        },
        category: {
          type: 'string',
          enum: [
            'prompt-injection', 'tool-poisoning', 'context-exfiltration',
            'agent-manipulation', 'privilege-escalation', 'excessive-autonomy',
            'data-poisoning', 'model-abuse', 'skill-compromise',
          ],
          description: 'Threat category for the rule.',
        },
        attack_description: {
          type: 'string',
          description: 'Detailed description of the attack this rule detects.',
        },
        example_payloads: {
          type: 'array',
          items: { type: 'string' },
          description: 'Example attack payloads to generate detection patterns from.',
        },
        severity: {
          type: 'string',
          enum: ['informational', 'low', 'medium', 'high', 'critical'],
          description: 'Severity level. Defaults to "medium".',
        },
        mitre_refs: {
          type: 'array',
          items: { type: 'string' },
          description: 'Optional MITRE ATLAS reference IDs (e.g., "AML.T0051").',
        },
      },
      required: ['title', 'category', 'attack_description', 'example_payloads'],
    },
  },
  {
    name: 'atr_coverage_gaps',
    description:
      'Analyze ATR rule coverage against security frameworks (OWASP Agentic AI, MITRE ATLAS). Identifies uncovered threat categories.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        framework: {
          type: 'string',
          enum: ['owasp_agentic', 'mitre_atlas', 'all'],
          description: 'Security framework to analyze against. Defaults to "all".',
        },
      },
    },
  },
  {
    name: 'atr_threat_summary',
    description:
      'Get aggregated statistics about loaded ATR rules. Shows distribution by category, severity, status, and test coverage.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        category: {
          type: 'string',
          enum: [
            'prompt-injection', 'tool-poisoning', 'context-exfiltration',
            'agent-manipulation', 'privilege-escalation', 'excessive-autonomy',
            'data-poisoning', 'model-abuse', 'skill-compromise',
          ],
          description: 'Optional: filter statistics to a single threat category.',
        },
      },
    },
  },
];

export async function createMCPServer(): Promise<Server> {
  const semantic = createSemanticJudgeFromConfig();
  const engine = new ATREngine({ rulesDir: RULES_DIR, semanticJudge: semantic.judge });
  const ruleCount = await engine.loadRules();
  if (semantic.enabled) {
    process.stderr.write('[atr-mcp] Semantic judge enabled for method=semantic rules\n');
  }

  const server = new Server(
    {
      name: 'atr-mcp-server',
      version: '0.2.1',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const toolArgs = (args ?? {}) as Record<string, unknown>;

    switch (name) {
      case 'atr_scan':
        return await handleScan(engine, toolArgs);

      case 'atr_scan_skill':
        return await handleScanSkill(engine, toolArgs);

      case 'atr_list_rules':
        return handleListRules(engine, toolArgs);

      case 'atr_validate_rule':
        return handleValidate(toolArgs);

      case 'atr_submit_proposal':
        return handleSubmitProposal(toolArgs);

      case 'atr_coverage_gaps':
        return handleCoverageGaps(engine, toolArgs);

      case 'atr_threat_summary':
        return handleThreatSummary(engine, toolArgs);

      default:
        return {
          content: [{ type: 'text', text: `Error: Unknown tool "${name}".` }],
          isError: true,
        };
    }
  });

  return server;
}

export async function startMCPServer(): Promise<void> {
  const server = await createMCPServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// Auto-start when run directly
const isDirectExecution =
  process.argv[1] &&
  (process.argv[1].endsWith('mcp-server.js') ||
   process.argv[1].endsWith('mcp-server.ts'));

if (isDirectExecution) {
  startMCPServer().catch((err) => {
    process.stderr.write(`ATR MCP Server error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
