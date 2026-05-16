#!/usr/bin/env npx tsx
/**
 * generate-detection-from-poc.ts
 *
 * Given a CVE/GHSA proposal yaml (with empty detection.conditions),
 * extract attack signatures from the advisory text and emit a complete
 * rule yaml with detection.conditions + test_cases filled in.
 *
 * Source text is read from (in order):
 *   1. _ghsa_sync.advisory_body  (GHSA proposals — markdown body with
 *      ``` code blocks)
 *   2. description               (NVD proposals — CVE description prose)
 *
 * Extractors run in priority order (highest precision first):
 *   1. code-block    — content inside ``` fences (e.g. PoC scripts)
 *   2. cli-command   — recognized CLI verbs (install, run, exec, clone)
 *   3. http-endpoint — METHOD /path/with/{params}
 *   4. shell-flag    — flags with backtick-quoted values
 *
 * Each extracted pattern becomes one detection.conditions entry with:
 *   - field: content
 *   - operator: regex
 *   - value: case-insensitive escaped pattern
 *   - description: human label
 *
 * test_cases.true_positives = the extracted PoC strings themselves
 *                             (so own-TP-must-match always holds).
 * test_cases.true_negatives = a small corpus of benign agent traffic.
 *
 * The emitted rule will NOT auto-merge if:
 *   - No patterns can be extracted (exit 2)
 *   - check-rules-safety.ts fails on FP / conflict (caller's responsibility)
 *
 * Usage:
 *   npx tsx scripts/generate-detection-from-poc.ts \
 *     proposals/nvd/CVE-2025-64340.proposal.yaml
 *
 *   npx tsx scripts/generate-detection-from-poc.ts \
 *     proposals/nvd/CVE-2025-64340.proposal.yaml \
 *     --output rules/tool-poisoning/ATR-2026-00500-fastmcp-cve-2025-64340.yaml
 *
 *   npx tsx scripts/generate-detection-from-poc.ts \
 *     proposals/nvd/CVE-2025-64340.proposal.yaml --dry-run
 *
 * Exit codes:
 *   0 success (rule emitted)
 *   1 fatal error (parse failure, IO error)
 *   2 no extractable patterns — proposal cannot be auto-completed
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const REPO_ROOT = resolve(__dirname, "..");

interface ExtractedPattern {
  extractor: string;
  regex: string;
  description: string;
  test_input: string;
}

const BENIGN_TRUE_NEGATIVES: string[] = [
  "Please summarize the attached document and email me the result.",
  "What is the weather forecast for Taipei tomorrow?",
  "Translate this paragraph from English to Japanese.",
  "Fetch the latest commit messages from the upstream branch.",
  "Schedule a 30-minute meeting with the design team next Tuesday.",
];

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function sourceText(proposal: Record<string, unknown>): string {
  const parts: string[] = [];
  const description = proposal.description;
  if (typeof description === "string") parts.push(description);
  const ghsa = proposal._ghsa_sync as Record<string, unknown> | undefined;
  if (ghsa && typeof ghsa.advisory_body === "string") {
    parts.push(ghsa.advisory_body);
  }
  return parts.join("\n\n");
}

const codeBlockExtractor = {
  name: "code-block",
  extract(text: string): ExtractedPattern[] {
    const results: ExtractedPattern[] = [];
    const re = /```[\w-]*\n([\s\S]*?)```/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const raw = m[1].trim();
      if (raw.length < 8 || raw.length > 400) continue;
      const firstLine = raw.split("\n")[0].trim();
      if (firstLine.length < 8 || firstLine.length > 200) continue;
      results.push({
        extractor: "code-block",
        regex: `(?i)${escapeRegex(firstLine)}`,
        description: `Literal first line of advisory PoC code block`,
        test_input: firstLine,
      });
    }
    return results;
  },
};

const cliCommandExtractor = {
  name: "cli-command",
  extract(text: string): ExtractedPattern[] {
    const results: ExtractedPattern[] = [];
    const stripped = text.replace(/```[\s\S]*?```/g, " ");
    const re =
      /\b([a-z][\w.-]{1,30}\s+(?:install|run|exec|deploy|clone|create|publish|launch)\s+[a-z][\w./:@-]{2,80})/g;
    const seen = new Set<string>();
    let m: RegExpExecArray | null;
    while ((m = re.exec(stripped)) !== null) {
      const cmd = m[1].trim().replace(/[.,;:!?]+$/, "");
      if (seen.has(cmd)) continue;
      seen.add(cmd);
      if (cmd.length < 10 || cmd.length > 100) continue;
      results.push({
        extractor: "cli-command",
        regex: `(?i)\\b${escapeRegex(cmd)}\\b`,
        description: `CLI invocation pattern from advisory text`,
        test_input: cmd,
      });
    }
    return results;
  },
};

const functionArgExtractor = {
  name: "function-arg",
  extract(text: string): ExtractedPattern[] {
    const results: ExtractedPattern[] = [];
    const seen = new Set<string>();
    const re = /\bfunction\s+([a-z_][\w]{2,40})\s+of\s+the\s+file\s+([^\s,;]+)/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const fn = m[1].trim();
      const file = m[2].trim().replace(/[.,;:!?]+$/, "");
      const key = `${fn}|${file}`;
      if (seen.has(key)) continue;
      seen.add(key);
      results.push({
        extractor: "function-arg",
        regex: `(?i)\\b${escapeRegex(fn)}\\s*\\(`,
        description: `Vulnerable function call ${fn}() from ${file}`,
        test_input: `${fn}(`,
      });
    }
    const argRe =
      /\bargument\s+([a-z_][\w]{2,40})\s+(?:with|to|as|=|of)/gi;
    while ((m = argRe.exec(text)) !== null) {
      const arg = m[1].trim();
      const key = `arg:${arg}`;
      if (seen.has(key)) continue;
      seen.add(key);
      results.push({
        extractor: "function-arg",
        regex: `(?i)\\b${escapeRegex(arg)}\\s*=`,
        description: `Vulnerable argument ${arg}=...`,
        test_input: `${arg}=`,
      });
    }
    return results;
  },
};

const endpointNameExtractor = {
  name: "endpoint-name",
  extract(text: string): ExtractedPattern[] {
    const results: ExtractedPattern[] = [];
    const seen = new Set<string>();
    const re =
      /\b((?:config|api|admin|gateway|tool|agent|service|skill|mcp)\.[a-z][\w]{2,30}(?:\s+and\s+(?:config|api|admin|gateway|tool|agent|service|skill|mcp)\.[a-z][\w]{2,30})?)\s+(?:endpoint|endpoints|tool|tools|method|methods|api|action)/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const phrase = m[1].trim();
      const names = phrase.split(/\s+and\s+/);
      for (const n of names) {
        const name = n.trim();
        if (seen.has(name)) continue;
        seen.add(name);
        results.push({
          extractor: "endpoint-name",
          regex: `(?i)\\b${escapeRegex(name)}\\b`,
          description: `Vulnerable endpoint ${name} from advisory text`,
          test_input: name,
        });
      }
    }
    return results;
  },
};

const httpEndpointExtractor = {
  name: "http-endpoint",
  extract(text: string): ExtractedPattern[] {
    const results: ExtractedPattern[] = [];
    const re =
      /\b(GET|POST|PUT|PATCH|DELETE)\s+(\/[\w./{}*-]{2,80}(?:\?[\w&={}]*)?)/g;
    const seen = new Set<string>();
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const method = m[1];
      const path = m[2];
      const key = `${method} ${path}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const concretePath = path.replace(/\{[^}]+\}/g, "abc123");
      results.push({
        extractor: "http-endpoint",
        regex: `(?i)\\b${method}\\s+${escapeRegex(path).replace(/\\\{[^}]+\\\}/g, "[\\w-]+")}`,
        description: `Vulnerable HTTP endpoint ${method} ${path}`,
        test_input: `${method} ${concretePath}`,
      });
    }
    return results;
  },
};

const EXTRACTORS = [
  codeBlockExtractor,
  cliCommandExtractor,
  httpEndpointExtractor,
  functionArgExtractor,
  endpointNameExtractor,
];

function extractAll(text: string): ExtractedPattern[] {
  const merged: ExtractedPattern[] = [];
  const seenRegex = new Set<string>();
  for (const ex of EXTRACTORS) {
    for (const p of ex.extract(text)) {
      if (seenRegex.has(p.regex)) continue;
      seenRegex.add(p.regex);
      merged.push(p);
    }
  }
  return merged;
}

function buildRule(
  proposal: Record<string, unknown>,
  patterns: ExtractedPattern[],
): Record<string, unknown> {
  const newRule = { ...proposal };
  delete (newRule as Record<string, unknown>)._ghsa_sync;
  delete (newRule as Record<string, unknown>)._nvd_sync;
  delete (newRule as Record<string, unknown>)._triage;

  newRule.detection = {
    condition: "any",
    false_positives: [],
    conditions: patterns.map((p) => ({
      field: "content",
      operator: "regex",
      value: p.regex,
      description: p.description,
    })),
  };

  newRule.test_cases = {
    true_positives: patterns.map((p) => ({
      input: p.test_input,
      expected: "triggered",
      description: `Auto-extracted via ${p.extractor}`,
    })),
    true_negatives: BENIGN_TRUE_NEGATIVES.map((input, i) => ({
      input,
      expected: "not_triggered",
      description: `Benign agent traffic sample ${i + 1}`,
    })),
  };

  if (newRule.status === "draft") newRule.status = "experimental";
  if (newRule.maturity === undefined) newRule.maturity = "experimental";

  return newRule;
}

function main(): void {
  const args = process.argv.slice(2);
  const inputPath = args.find((a) => !a.startsWith("-"));
  if (!inputPath) {
    console.error("usage: generate-detection-from-poc.ts <proposal.yaml> [--output <path>] [--dry-run]");
    process.exit(1);
  }
  const outputIdx = args.indexOf("--output");
  const outputPath = outputIdx >= 0 ? args[outputIdx + 1] : null;
  const dryRun = args.includes("--dry-run");

  const absInput = resolve(REPO_ROOT, inputPath);
  let proposal: Record<string, unknown>;
  try {
    proposal = yaml.load(readFileSync(absInput, "utf-8")) as Record<
      string,
      unknown
    >;
  } catch (e) {
    console.error(`failed to parse ${absInput}: ${e}`);
    process.exit(1);
  }

  const text = sourceText(proposal);
  if (!text || text.length < 20) {
    console.error(
      JSON.stringify({
        status: "no_source_text",
        proposal_id: proposal.id,
        text_length: text.length,
      }),
    );
    process.exit(2);
  }

  const patterns = extractAll(text);
  if (patterns.length === 0) {
    console.error(
      JSON.stringify({
        status: "no_extractable_patterns",
        proposal_id: proposal.id,
        extractors_tried: EXTRACTORS.map((e) => e.name),
      }),
    );
    process.exit(2);
  }

  const rule = buildRule(proposal, patterns);
  const ruleYaml = yaml.dump(rule, { lineWidth: 120, noRefs: true });

  if (dryRun) {
    console.error(
      JSON.stringify(
        {
          status: "dry_run",
          proposal_id: proposal.id,
          patterns: patterns.length,
          extractors_used: [...new Set(patterns.map((p) => p.extractor))],
        },
        null,
        2,
      ),
    );
  } else if (outputPath) {
    writeFileSync(resolve(REPO_ROOT, outputPath), ruleYaml, "utf-8");
    console.error(
      JSON.stringify({
        status: "written",
        output: outputPath,
        proposal_id: proposal.id,
        patterns: patterns.length,
        extractors_used: [...new Set(patterns.map((p) => p.extractor))],
      }),
    );
  } else {
    console.log(ruleYaml);
  }
}

main();
