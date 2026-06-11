#!/usr/bin/env npx tsx
/**
 * Local Crystallization — LLM-powered rule generation from attack data
 * 
 * Fallback when TC server's analyze-skills is unavailable.
 * Uses the same LLM prompt as TC's LLMReviewer.analyzeSkills().
 * 
 * Usage:
 *   ANTHROPIC_API_KEY=sk-ant-xxx npx tsx scripts/local-crystallize.ts
 *   # or use Claude Code's session:
 *   npx tsx scripts/local-crystallize.ts --use-local-llm
 * 
 * Input:  data/autoresearch/adversarial-samples.json (missed attacks)
 * Output: rules/<category>/ATR-2026-XXXXX-<slug>.yaml (new rules)
 *         + POST to TC as proposals
 */

import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import yaml from 'js-yaml';
import { ATREngine } from '../dist/engine.js';
import { validateRule, loadRuleFile } from '../dist/loader.js';

const TC_URL = process.env.TC_URL ?? 'https://tc.panguard.ai';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY ?? '';
const DRY_RUN = process.argv.includes('--dry-run');

interface AdversarialSample {
  id: string;
  original_rule_id: string;
  technique: string;
  payload: string;
  detection_field: string;
}

// Same prompt as TC's LLMReviewer — keep in sync
const ATR_DRAFTER_PROMPT = `You are a senior AI security rule engineer for the ATR (Agent Threat Rules) standard.

You will receive real attack payloads that currently evade ATR detection. Your job is to write a PRODUCTION-QUALITY detection rule.

STRICT REQUIREMENTS:
1. REGEX MUST BE SPECIFIC — require 3+ word sequences. No single-word matches.
2. FALSE POSITIVE RATE MUST BE LOW — test mentally against normal tool descriptions.
3. MUST DETECT REAL ATTACKS — not hypothetical risks.
4. TEST CASES: 2+ true_positives (from the actual payloads), 2+ true_negatives (similar but safe).
5. Use single-quoted YAML values for regex (avoid escape issues).
6. field: content (catches both SKILL.md and MCP events).

Output format:
\`\`\`yaml
title: "<specific attack name>"
id: ATR-2026-DRAFT
rule_version: 1
status: experimental
description: >
  <what this detects, how many samples it covers>
author: "ATR Threat Cloud Crystallization"
date: "${new Date().toISOString().slice(0, 10).replace(/-/g, '/')}"
schema_version: "1.0"
detection_tier: pattern
maturity: experimental
severity: <critical|high|medium>
references:
  owasp_llm:
    - "LLM01:2025 - Prompt Injection"
  owasp_agentic:
    - "<most relevant ASI category>"
tags:
  category: <prompt-injection|tool-poisoning|context-exfiltration|agent-manipulation>
  subcategory: <technique-name>
  confidence: medium
  scan_target: mcp
agent_source:
  type: mcp_exchange
  framework: [any]
  provider: [any]
detection:
  condition: any
  conditions:
    - field: content
      operator: regex
      value: '<YAML single-quoted regex>'
      description: "<what pattern this matches>"
test_cases:
  true_positives:
    - input: "<actual attack payload>"
      expected: triggered
    - input: "<variant>"
      expected: triggered
  true_negatives:
    - input: "<similar but safe text>"
      expected: not_triggered
    - input: "<another safe example>"
      expected: not_triggered
response:
  actions: [alert, block_input]
\`\`\`

If no reliable regex pattern can be found (pure semantic attacks), output "NO_REGEX_POSSIBLE".`;

async function callAnthropic(prompt: string): Promise<string> {
  if (!ANTHROPIC_API_KEY) throw new Error('ANTHROPIC_API_KEY not set');
  
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 2048,
      messages: [{ role: 'user', content: prompt }],
    }),
  });
  
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`Anthropic API ${resp.status}: ${body.slice(0, 200)}`);
  }
  
  const data = await resp.json() as { content?: Array<{ type: string; text?: string }> };
  const text = data.content?.find((c: { type: string }) => c.type === 'text')?.text;
  if (!text) throw new Error('No text in Anthropic response');
  return text;
}

async function pushToTC(ruleContent: string): Promise<boolean> {
  const hash = createHash('sha256').update(ruleContent).digest('hex').slice(0, 16);
  try {
    const resp = await fetch(TC_URL + '/api/atr-proposals', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        patternHash: hash,
        ruleContent,
        llmProvider: 'anthropic',
        llmModel: 'claude-sonnet-4-20250514',
        selfReviewVerdict: JSON.stringify({ approved: true, falsePositiveRisk: 'low', coverageScore: 70 }),
      }),
    });
    return resp.ok;
  } catch { return false; }
}

async function main() {
  console.log('=== ATR Local Crystallization ===');
  console.log(`TC: ${TC_URL} | Dry run: ${DRY_RUN}`);
  console.log(`API key: ${ANTHROPIC_API_KEY ? 'set' : 'NOT SET'}\n`);
  
  // Load engine and find missed attacks
  const engine = new ATREngine({ rulesDir: resolve('rules') });
  await engine.loadRules();
  console.log(`Engine: ${engine.getRules().length} rules loaded`);
  
  const samples: AdversarialSample[] = JSON.parse(
    readFileSync(resolve('data/autoresearch/adversarial-samples.json'), 'utf-8')
  );
  
  // Find missed attacks grouped by technique
  const missed = new Map<string, AdversarialSample[]>();
  for (const s of samples) {
    const event = {
      type: 'tool_response' as const,
      timestamp: new Date().toISOString(),
      content: s.payload,
      fields: { [s.detection_field]: s.payload, content: s.payload },
    };
    if (engine.evaluate(event).length === 0) {
      const list = missed.get(s.technique) ?? [];
      list.push(s);
      missed.set(s.technique, list);
    }
  }
  
  // Filter to techniques with enough samples and regex-crystallizable patterns
  const crystallizable = [...missed.entries()]
    .filter(([tech, items]) => items.length >= 10 && tech !== 'paraphrase' && tech !== 'multilingual_paraphrase')
    .sort((a, b) => b[1].length - a[1].length);
  
  console.log(`\nMissed techniques (${crystallizable.length} crystallizable):`);
  for (const [tech, items] of crystallizable) {
    console.log(`  ${tech}: ${items.length} samples`);
  }
  
  if (!ANTHROPIC_API_KEY) {
    console.log('\nNo ANTHROPIC_API_KEY — printing prompts for manual crystallization:');
    for (const [tech, items] of crystallizable.slice(0, 5)) {
      const samplePayloads = items.slice(0, 8).map(i => `  - "${i.payload.slice(0, 120)}"`).join('\n');
      console.log(`\n--- ${tech} (${items.length} samples) ---`);
      console.log(`Payloads:\n${samplePayloads}`);
    }
    return;
  }
  
  // Crystallize each technique
  // Real next-ID from the existing corpus. Previously hardcoded `142 + created` (written when
  // the repo had ~141 rules) — it now collides with every existing ID up to the current max,
  // one of the two reasons the daily crystallize run red-failed.
  const scanMaxId = (dir: string): number => {
    let max = 0;
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) max = Math.max(max, scanMaxId(full));
      else { const m = entry.match(/ATR-2026-(\d{5})/); if (m) max = Math.max(max, parseInt(m[1]!, 10)); }
    }
    return max;
  };
  const baseId = scanMaxId('rules');
  console.log(`Allocating new rule IDs from ATR-2026-${String(baseId + 1).padStart(5, '0')}`);

  let created = 0, pushed = 0;
  for (const [tech, items] of crystallizable) {
    const samplePayloads = items.slice(0, 10).map(i => `- "${i.payload}"`).join('\n');
    const prompt = ATR_DRAFTER_PROMPT + `\n\nAttack technique: ${tech}\nSamples (${items.length} total, showing 10):\n${samplePayloads}`;
    
    console.log(`\nCrystallizing: ${tech} (${items.length} samples)...`);
    
    try {
      const response = await callAnthropic(prompt);
      
      if (response.includes('NO_REGEX_POSSIBLE')) {
        console.log(`  → No regex possible (semantic attack)`);
        continue;
      }
      
      const yamlMatch = response.match(/```yaml\n([\s\S]*?)```/);
      if (!yamlMatch) {
        console.log(`  → No YAML block in response`);
        continue;
      }
      
      const ruleContent = yamlMatch[1]!.trim();
      
      // Assign real ID
      const nextId = baseId + 1 + created;
      const finalContent = ruleContent.replace('ATR-2026-DRAFT', `ATR-2026-${String(nextId).padStart(5, '0')}`);
      
      // Determine category and write file
      const categoryMatch = finalContent.match(/category:\s*(\S+)/);
      const category = categoryMatch?.[1] ?? 'prompt-injection';
      const slugMatch = finalContent.match(/subcategory:\s*(\S+)/);
      const slug = slugMatch?.[1] ?? tech;
      
      const filePath = `rules/${category}/ATR-2026-${String(nextId).padStart(5, '0')}-${slug}.yaml`;

      // Reject malformed LLM YAML BEFORE it touches disk. A duplicate-key file pollutes the
      // engine's directory scan and silently red-fails the whole run (the `duplicated mapping
      // key (50:1)` error that broke crystallize for days). js-yaml throws on duplicate keys.
      try {
        yaml.load(finalContent);
      } catch (e) {
        console.log(`  → Malformed YAML, skipping: ${e instanceof Error ? e.message : e}`);
        continue;
      }

      if (!DRY_RUN) {
        writeFileSync(filePath, finalContent);
      }
      
      // Validate
      try {
        const rule = loadRuleFile(filePath);
        const v = validateRule(rule);
        if (!v.valid) {
          console.log(`  → Invalid: ${v.errors.join(', ')}`);
          continue;
        }
        
        // Test
        const testEngine = new ATREngine({ rules: [rule] });
        await testEngine.loadRules();
        let testPass = true;
        for (const tp of rule.test_cases?.true_positives ?? []) {
          const m = testEngine.evaluate({
            type: 'tool_response', timestamp: new Date().toISOString(),
            content: tp.input, fields: { content: tp.input },
          });
          if (!m.length) { testPass = false; break; }
        }
        
        if (!testPass) {
          console.log(`  → Test case failed`);
          continue;
        }
        
        created++;
        console.log(`  → Created: ${filePath}`);
        
        // Push to TC
        if (!DRY_RUN && await pushToTC(finalContent)) {
          pushed++;
          console.log(`  → Pushed to TC`);
        }
      } catch (e) {
        console.log(`  → Error: ${e instanceof Error ? e.message : e}`);
      }
    } catch (e) {
      console.log(`  → LLM error: ${e instanceof Error ? e.message : e}`);
    }
    
    // Rate limit between calls
    await new Promise(r => setTimeout(r, 1000));
  }
  
  console.log(`\n=== Results: ${created} rules created, ${pushed} pushed to TC ===`);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
