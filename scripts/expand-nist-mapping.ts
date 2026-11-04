#!/usr/bin/env npx tsx
/**
 * expand-nist-mapping.ts
 *
 * Expand NIST AI RMF metadata coverage across the ATR rule corpus using
 * Claude Opus + few-shot prompting. Reads existing high-quality mappings
 * as gold standard, generates new mappings for rules missing the
 * `compliance.nist_ai_rmf` block, and emits proposed YAML diffs for human QA.
 *
 * Design principles:
 * - LLM never modifies detection logic, only adds metadata
 * - All output goes to a `proposals/` dir for human review (never auto-merges)
 * - Every proposal carries `provenance: llm_generated` + model ID + timestamp
 * - Few-shot examples drawn from existing manually-curated mappings
 *
 * Usage:
 *   # Dry-run on 5 prompt-injection rules (cost: ~$0.30)
 *   npx tsx scripts/expand-nist-mapping.ts --category prompt-injection --limit 5 --dry-run
 *
 *   # Full prompt-injection batch (cost: ~$5)
 *   npx tsx scripts/expand-nist-mapping.ts --category prompt-injection --output proposals/nist
 *
 *   # All categories (cost: ~$15-30)
 *   npx tsx scripts/expand-nist-mapping.ts --all --output proposals/nist
 *
 *   # Specific rule by ID
 *   npx tsx scripts/expand-nist-mapping.ts --rule-id ATR-2026-00085 --dry-run
 *
 * Env vars required:
 *   ANTHROPIC_API_KEY — for Claude Opus
 *
 * Output:
 *   proposals/nist/<rule-id>.proposal.yaml — full proposed metadata block + provenance
 *   proposals/nist/SUMMARY.md — batch summary for QA review
 */

import Anthropic from '@anthropic-ai/sdk';
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, statSync } from 'node:fs';
import { resolve, basename, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Recursive .yaml walk (replaces glob, which is not in deps)
function walkYaml(dir: string): string[] {
  const out: string[] = [];
  if (!existsSync(dir)) return out;
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) {
      out.push(...walkYaml(full));
    } else if (st.isFile() && entry.endsWith('.yaml')) {
      out.push(full);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const getArg = (flag: string): string | undefined => {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : undefined;
};
const hasFlag = (flag: string): boolean => args.includes(flag);

const REPO_ROOT = resolve(__dirname, '..');
const RULES_DIR = resolve(REPO_ROOT, 'rules');
const OUTPUT_DIR = resolve(REPO_ROOT, getArg('--output') ?? 'proposals/nist');

const MODEL = getArg('--model') ?? 'claude-opus-4-7';
const CATEGORY = getArg('--category');
const RULE_ID = getArg('--rule-id');
const ALL = hasFlag('--all');
const LIMIT = parseInt(getArg('--limit') ?? '0', 10);
const DRY_RUN = hasFlag('--dry-run');
const FEW_SHOT_COUNT = parseInt(getArg('--few-shot') ?? '5', 10);

const apiKey = process.env['ANTHROPIC_API_KEY'];
if (!apiKey) {
  console.error('ERROR: ANTHROPIC_API_KEY env var required');
  console.error('  export ANTHROPIC_API_KEY=sk-ant-...');
  process.exit(1);
}

const client = new Anthropic({ apiKey });

// ---------------------------------------------------------------------------
// NIST AI RMF subcategory reference, built from the validator's allowlist
// (data/compliance-frameworks/nist_ai_rmf.json) so the prompt and CI share one
// source. A hand-written table used to live here; it gave MG.2.3 the meaning of
// MG.2.4, GV.1.2 the meaning of GV.2.1 and MP.5.2 the meaning of MG.1.3, and
// hundreds of generated mappings carried those errors (errata 2026-11-04).
// ---------------------------------------------------------------------------

const NIST_FUNCTIONS: ReadonlyArray<[string, string]> = [
  ["GV", "GOVERN"],
  ["MP", "MAP"],
  ["MS", "MEASURE"],
  ["MG", "MANAGE"],
];

function buildNistReference(): string {
  const allowlistPath = resolve(__dirname, "../data/compliance-frameworks/nist_ai_rmf.json");
  const { valids } = JSON.parse(readFileSync(allowlistPath, "utf-8")) as { valids: Record<string, string> };
  const order = (id: string) => id.split(".").slice(1).map(Number);
  const sections = NIST_FUNCTIONS.map(([prefix, name]) => {
    const rows = Object.entries(valids)
      .filter(([id]) => id.startsWith(`${prefix}.`))
      .sort(([a], [b]) => {
        const [a1, a2] = order(a);
        const [b1, b2] = order(b);
        return a1 - b1 || a2 - b2;
      })
      .map(([id, text]) => `  ${id.padEnd(8)}${text}`);
    return `${name} (${prefix})\n${rows.join("\n")}`;
  });
  return [
    "NIST AI RMF 1.0 (NIST AI 100-1) subcategories. Use only these identifiers, with",
    "the meaning given here; it is the same list CI validates against.",
    "",
    sections.join("\n\n"),
  ].join("\n");
}

const NIST_RMF_REFERENCE = buildNistReference();

// ---------------------------------------------------------------------------
// Few-shot example loader (gold standard from manual mappings)
// ---------------------------------------------------------------------------

interface RuleFile {
  path: string;
  content: string;
  parsed: any;
  hasNistMapping: boolean;
}

function loadRule(filePath: string): RuleFile {
  const content = readFileSync(filePath, 'utf8');
  let parsed: any = {};
  try {
    parsed = yaml.load(content);
  } catch (e) {
    // Some rules have YAML issues; we still want to detect them
    parsed = {};
  }
  const hasNistMapping = !!parsed?.compliance?.nist_ai_rmf;
  return { path: filePath, content, parsed, hasNistMapping };
}

function loadFewShotExamples(count: number): RuleFile[] {
  const priorityCategories = ['agent-manipulation', 'context-exfiltration', 'excessive-autonomy'];
  const examples: RuleFile[] = [];

  for (const cat of priorityCategories) {
    const files = walkYaml(join(RULES_DIR, cat));
    for (const f of files) {
      const rule = loadRule(f);
      if (rule.hasNistMapping && examples.length < count) {
        examples.push(rule);
      }
    }
    if (examples.length >= count) break;
  }

  return examples;
}

// ---------------------------------------------------------------------------
// Prompt construction
// ---------------------------------------------------------------------------

function buildPrompt(targetRule: RuleFile, examples: RuleFile[]): string {
  const exampleBlocks = examples
    .map((ex, i) => {
      const minimal = {
        id: ex.parsed.id,
        title: ex.parsed.title,
        description: ex.parsed.description,
        tags: ex.parsed.tags,
        compliance_nist_ai_rmf: ex.parsed.compliance?.nist_ai_rmf,
      };
      return `### Example ${i + 1}\n\`\`\`yaml\n${yaml.dump(minimal)}\n\`\`\``;
    })
    .join('\n\n');

  const targetMinimal = {
    id: targetRule.parsed.id,
    title: targetRule.parsed.title,
    description: targetRule.parsed.description,
    tags: targetRule.parsed.tags,
    references: targetRule.parsed.references,
    detection: targetRule.parsed.detection
      ? {
          condition: targetRule.parsed.detection.condition,
          conditions_summary: Array.isArray(targetRule.parsed.detection.conditions)
            ? targetRule.parsed.detection.conditions
                .slice(0, 3)
                .map((c: any) => c.description ?? c.field ?? 'condition')
                .join('; ')
            : '(complex)',
        }
      : undefined,
  };

  return `You are mapping ATR (Agent Threat Rules) detection rules to NIST AI RMF 1.0 subcategories.

# NIST AI RMF reference
${NIST_RMF_REFERENCE}

# Mapping principles
- Choose 1-3 subcategories per rule. One MUST be marked \`strength: primary\` (the rule directly evidences this subcategory). Others are \`strength: secondary\`.
- The \`context\` field must be 1-3 sentences explaining WHY this rule's detection signature corresponds to this subcategory. Be specific about what the rule detects and how that detection produces evidence for the subcategory.
- Quote subcategory IDs verbatim (e.g., "GV.1.2", "MG.2.3").
- If the rule is GenAI-specific (prompt injection, jailbreak), prefer GenAI Profile angle.
- Do NOT guess subcategories outside the reference list above.
- Do NOT invent new subcategory IDs.
- Do NOT reference any other framework (no EU AI Act, no ISO, no OWASP).

# Few-shot examples (manually curated by ATR maintainers)

${exampleBlocks}

# Target rule (needs NIST AI RMF mapping)

\`\`\`yaml
${yaml.dump(targetMinimal)}
\`\`\`

# Your task

Output ONLY a YAML block with the proposed \`nist_ai_rmf:\` mapping (the value that goes under \`compliance.nist_ai_rmf:\` in the rule file). Do not include any other text, explanation, or markdown fences. The output should be valid YAML starting with a list (\`- subcategory: ...\`).

Example output format:
\`\`\`
- subcategory: "MG.2.3"
  context: "Specific 1-3 sentence explanation of why this detection corresponds to MG.2.3."
  strength: primary
- subcategory: "GV.1.2"
  context: "Specific 1-3 sentence explanation."
  strength: secondary
\`\`\`

(Do NOT include the triple backticks in your actual response. Just the YAML.)`;
}

// ---------------------------------------------------------------------------
// LLM call + output parsing
// ---------------------------------------------------------------------------

async function generateMapping(rule: RuleFile, examples: RuleFile[]): Promise<{
  yamlBlock: string;
  parsed: any[];
  raw: string;
  cost_estimate_usd: number;
}> {
  const prompt = buildPrompt(rule, examples);

  const resp = await client.messages.create({
    model: MODEL,
    max_tokens: 1200,
    messages: [{ role: 'user', content: prompt }],
  });

  const text = resp.content
    .filter((b: any) => b.type === 'text')
    .map((b: any) => (b as any).text)
    .join('');

  // Strip any leading/trailing whitespace + accidental code fences
  const cleaned = text
    .replace(/^```ya?ml\n?/i, '')
    .replace(/\n?```$/, '')
    .trim();

  let parsed: any[] = [];
  try {
    parsed = yaml.load(cleaned) as any[];
  } catch (e) {
    console.warn(`  ⚠ YAML parse failed for ${rule.parsed.id}: ${(e as Error).message}`);
  }

  // Cost estimate: Opus 4.7 ≈ $15/1M input + $75/1M output
  const inputTokens = resp.usage?.input_tokens ?? 0;
  const outputTokens = resp.usage?.output_tokens ?? 0;
  const cost = (inputTokens / 1_000_000) * 15 + (outputTokens / 1_000_000) * 75;

  return {
    yamlBlock: cleaned,
    parsed,
    raw: text,
    cost_estimate_usd: cost,
  };
}

// ---------------------------------------------------------------------------
// Output writer (proposals dir, never auto-merges)
// ---------------------------------------------------------------------------

interface ProposalRecord {
  rule_id: string;
  rule_path: string;
  rule_title: string;
  proposed_mapping: any[];
  raw_yaml: string;
  provenance: {
    generated_by: string;
    model: string;
    generated_at: string;
    few_shot_examples: string[];
    cost_usd: number;
  };
  qa_status: 'pending';
}

function writeProposal(rule: RuleFile, mapping: { yamlBlock: string; parsed: any[]; cost_estimate_usd: number }, exampleIds: string[]) {
  if (!existsSync(OUTPUT_DIR)) {
    mkdirSync(OUTPUT_DIR, { recursive: true });
  }

  const ruleId = rule.parsed.id ?? basename(rule.path).replace('.yaml', '');
  const proposal: ProposalRecord = {
    rule_id: ruleId,
    rule_path: rule.path.replace(REPO_ROOT, ''),
    rule_title: rule.parsed.title ?? '(unknown)',
    proposed_mapping: mapping.parsed,
    raw_yaml: mapping.yamlBlock,
    provenance: {
      generated_by: 'expand-nist-mapping.ts',
      model: MODEL,
      generated_at: new Date().toISOString(),
      few_shot_examples: exampleIds,
      cost_usd: parseFloat(mapping.cost_estimate_usd.toFixed(4)),
    },
    qa_status: 'pending',
  };

  const outPath = resolve(OUTPUT_DIR, `${ruleId}.proposal.yaml`);
  writeFileSync(outPath, yaml.dump(proposal));
  return outPath;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log('─'.repeat(60));
  console.log('ATR — NIST AI RMF mapping expansion');
  console.log(`Model: ${MODEL}`);
  console.log(`Mode: ${DRY_RUN ? 'DRY-RUN (output to stdout, no file writes)' : 'WRITE'}`);
  console.log(`Output dir: ${OUTPUT_DIR}`);
  console.log('─'.repeat(60));

  // 1. Load few-shot examples
  console.log(`\n[1/4] Loading ${FEW_SHOT_COUNT} few-shot examples from manually-curated rules...`);
  const examples = loadFewShotExamples(FEW_SHOT_COUNT);
  console.log(`      Loaded ${examples.length} examples:`);
  examples.forEach((ex) => console.log(`        - ${ex.parsed.id} (${ex.parsed.title?.slice(0, 60)})`));

  // 2. Determine target rules
  console.log(`\n[2/4] Selecting target rules...`);
  let targetFiles: string[] = [];
  if (RULE_ID) {
    targetFiles = walkYaml(RULES_DIR).filter((f) => f.includes(RULE_ID));
  } else if (CATEGORY) {
    targetFiles = walkYaml(join(RULES_DIR, CATEGORY));
  } else if (ALL) {
    targetFiles = walkYaml(RULES_DIR);
  } else {
    console.error('ERROR: must specify --rule-id, --category, or --all');
    process.exit(1);
  }

  // Filter to only rules WITHOUT existing NIST mapping
  const targets: RuleFile[] = [];
  for (const f of targetFiles) {
    const rule = loadRule(f);
    if (!rule.hasNistMapping && rule.parsed.id) {
      targets.push(rule);
    }
  }

  const finalTargets = LIMIT > 0 ? targets.slice(0, LIMIT) : targets;
  console.log(`      ${targetFiles.length} files matched`);
  console.log(`      ${targets.length} need NIST mapping`);
  console.log(`      ${finalTargets.length} will be processed (limit: ${LIMIT || 'none'})`);

  // 3. Generate mappings
  console.log(`\n[3/4] Generating mappings...`);
  let totalCost = 0;
  let successCount = 0;
  let failCount = 0;
  const exampleIds = examples.map((e) => e.parsed.id);

  for (let i = 0; i < finalTargets.length; i++) {
    const rule = finalTargets[i];
    process.stdout.write(`      [${i + 1}/${finalTargets.length}] ${rule.parsed.id}... `);
    try {
      const result = await generateMapping(rule, examples);
      totalCost += result.cost_estimate_usd;
      successCount++;

      if (DRY_RUN) {
        console.log(`OK ($${result.cost_estimate_usd.toFixed(4)})`);
        console.log(`        Title: ${rule.parsed.title}`);
        console.log(`        Proposed mapping:`);
        console.log(result.yamlBlock.split('\n').map((l) => `          ${l}`).join('\n'));
        console.log('');
      } else {
        const outPath = writeProposal(rule, result, exampleIds);
        console.log(`OK → ${basename(outPath)} ($${result.cost_estimate_usd.toFixed(4)})`);
      }
    } catch (e) {
      failCount++;
      console.log(`FAIL: ${(e as Error).message}`);
    }
  }

  // 4. Summary
  console.log(`\n[4/4] Summary`);
  console.log(`      Success: ${successCount} / ${finalTargets.length}`);
  console.log(`      Failed:  ${failCount}`);
  console.log(`      Cost:    $${totalCost.toFixed(4)} USD`);

  if (!DRY_RUN && successCount > 0) {
    const summaryPath = resolve(OUTPUT_DIR, 'SUMMARY.md');
    const summary = `# NIST AI RMF mapping batch — ${new Date().toISOString()}

Model: ${MODEL}
Few-shot examples: ${exampleIds.join(', ')}

| Rule ID | Status | Output file |
|---|---|---|
${finalTargets.map((r) => `| ${r.parsed.id} | pending QA | ${r.parsed.id}.proposal.yaml |`).join('\n')}

## QA workflow

For each proposal:
1. Open \`<rule-id>.proposal.yaml\`
2. Verify \`subcategory\` IDs match RMF 1.0 / GAI Profile
3. Verify \`context\` is specific (not generic)
4. Verify \`strength\` (primary/secondary) is sensible
5. If OK: copy \`raw_yaml\` block into the rule's \`compliance.nist_ai_rmf:\` slot
6. Bump rule's \`schema_version\` to "0.2"
7. Add to PR titled "feat(compliance): expand NIST AI RMF mapping (batch N)"

## Cost

Total: $${totalCost.toFixed(4)} USD (${successCount} rules)
`;
    writeFileSync(summaryPath, summary);
    console.log(`      Summary: ${summaryPath}`);
  }

  console.log('\nDone.');
}

main().catch((e) => {
  console.error('FATAL:', e);
  process.exit(1);
});
