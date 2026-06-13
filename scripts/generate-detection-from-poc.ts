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
 *   1. code-block    — content inside ``` fences (e.g. PoC scripts) [poc]
 *   2. cli-command   — recognized CLI verbs (install, run, exec)   [prose]
 *   3. http-endpoint — METHOD /path/with/{params}                  [prose]
 *   4. function-arg  — "function foo() of file ..." / "argument x" [prose]
 *   5. endpoint-name — "config.get endpoint" / "mcp.run tool"      [prose]
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
 * GROUNDING — poc vs prose (the MiroFish guard):
 *   Only the code-block extractor is "poc"-grounded: it lifts the literal
 *   exploit payload out of a ``` fence. The other four extractors are
 *   "prose"-grounded: they infer a pattern from advisory DESCRIPTION text
 *   ("the vulnerable function foo()"). A regex built from prose detects the
 *   SENTENCE describing the attack, not the attack — the documented MiroFish
 *   failure mode that got the ATR-PRED-* batch deprecated.
 *
 *   Therefore:
 *   - If >=1 pattern is poc-grounded → the rule is a Cisco-level candidate.
 *     status is promoted to experimental for the maturity + auto-merge gate.
 *   - If every pattern is prose-only → status=draft, maturity=needs-human-poc,
 *     and a `_needs_human_poc` marker is attached. The script exits 3 so the
 *     daily CVE workflow routes it to HUMAN REVIEW instead of the auto-merge
 *     gate. The draft is still written so a maintainer can supply the real
 *     PoC payload and re-promote it.
 *
 * The emitted rule will NOT auto-merge if:
 *   - No patterns can be extracted (exit 2)
 *   - Patterns are prose-only — needs a human PoC (exit 3)
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
 *   0 success (poc-grounded rule emitted, eligible for auto-merge gate)
 *   1 fatal error (parse failure, IO error)
 *   2 no extractable patterns — proposal cannot be auto-completed
 *   3 prose-only — draft written, needs a human-supplied PoC payload
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
  /**
   * Provenance of this pattern. "poc" = extracted from a real proof-of-
   * concept code block (the literal exploit payload). "prose" = inferred
   * from advisory description text (e.g. "the vulnerable function foo()").
   *
   * Prose-inferred patterns are the documented MiroFish failure mode:
   * a regex built from "this CVE allows command injection via X" detects
   * the SENTENCE describing the attack, not the attack. Cisco-level rules
   * MUST be poc-grounded. Prose-only proposals are routed to human review
   * (exit code 3) instead of being auto-promoted to a production rule.
   */
  grounding: "poc" | "prose";
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

// High-confidence attack indicators. A PoC code-block line must contain at
// least one of these to qualify as a detection pattern. This is the fix for
// the import-FP class: the OLD extractor took the first line of the code
// block, which is almost always a benign `import`/setup line (e.g.
// `import random`), producing rules that fired on normal code. Now a line
// only becomes a pattern if it carries a genuine exploit signal; if no line
// in the block qualifies, the extractor yields nothing and the proposal
// routes to human-PoC review.
const ATTACK_INDICATORS: RegExp[] = [
  // SSRF / cloud metadata / dangerous URL schemes
  /169\.254\.169\.254/,
  /metadata\.google\.internal/,
  /\bfile:\/\//i,
  /\bgopher:\/\//i,
  /\bdict:\/\//i,
  // code execution / unsafe deserialization
  /__import__\s*\(/,
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /os\.system\s*\(/,
  /subprocess\.[A-Za-z]+\([^)]*shell\s*=\s*True/,
  /pickle\.loads\s*\(/,
  /\byaml\.load\s*\((?![^)]*Loader)/,
  /__reduce__/,
  /marshal\.loads/,
  // server-side template injection
  /\{\{.*(self|config|request|globals|__|\.\.|class)\b.*\}\}/,
  // path traversal
  /\.\.\/\.\.\//,
  /\.\.\\\.\.\\/,
  /\/etc\/passwd/,
  /\/proc\/self/,
  // command injection
  /;\s*(rm|cat|curl|wget|nc|bash|sh|powershell)\b/i,
  /\|\s*(bash|sh|nc)\b/i,
  /\$\([^)]+\)/,
  // SQL injection
  /UNION\s+SELECT/i,
  /'\s*OR\s+'?1'?\s*=\s*'?1/i,
  /;\s*DROP\s+TABLE/i,
  // XSS
  /<script\b/i,
  /\bonerror\s*=/i,
  /javascript:/i,
  // prompt injection
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /disregard.*instructions/i,
  // exfiltration / OOB interaction services
  /\bexfil/i,
  /\br3dir/i,
  /webhook\.site/i,
  /burpcollaborator/i,
  /\.oastify\.com/i,
  /requestbin/i,
  /interact\.sh/i,
];

// Lines that are setup/benign even if otherwise interesting — never patterns.
const BENIGN_LINE: RegExp[] = [
  /^\s*(#|\/\/|\/\*|\*)/, // comment
  /^\s*from\s+\S+\s+import\b/, // python: from x import y
  /^\s*import\s+\S+/, // python/js: import x  /  import x from 'y'
  /^\s*(const|let|var)\s+\{[^}]*\}\s*=\s*require\s*\(/, // js require destructure
  /^\s*(def|class|async\s+def|function|interface|type|@)\b/, // definitions / decorators
  /^\s*(pip|npm|yarn|pnpm|poetry|uv)\s+(install|add)\b/, // dependency setup
  /^\s*$/, // blank
];

function isBenignLine(line: string): boolean {
  return BENIGN_LINE.some((rx) => rx.test(line));
}

// Number of distinct attack indicators a line matches. 0 = not a payload line.
function attackScore(line: string): number {
  return ATTACK_INDICATORS.reduce((n, rx) => n + (rx.test(line) ? 1 : 0), 0);
}

function sourceText(proposal: Record<string, unknown>): string {
  const parts: string[] = [];
  const description = proposal.description;
  if (typeof description === "string") parts.push(description);
  // Pull the PoC / advisory body from ANY source provenance block. Every
  // sync-*.ts writes a `_<source>_sync` object carrying the raw advisory
  // markdown (advisory_body) and/or the exploit payload (poc_body). Scanning
  // generically means a new CVE source is grounded the moment it lands a
  // proposal — no per-source edit here. (Originally only `_ghsa_sync` was
  // read, which silently starved huntr/osv/mcp/vulnerablemcp/msrc/owasp-asi.)
  for (const [key, val] of Object.entries(proposal)) {
    if (!/^_.*_sync$/.test(key)) continue;
    const prov = val as Record<string, unknown> | undefined;
    if (!prov || typeof prov !== "object") continue;
    if (typeof prov.advisory_body === "string") parts.push(prov.advisory_body);
    if (typeof prov.poc_body === "string") parts.push(prov.poc_body);
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
      if (raw.length < 8) continue;
      // Select the highest-confidence ATTACK-INDICATOR line — not the first
      // line (which is almost always a benign import/setup statement). A line
      // qualifies only if it carries a genuine exploit signal and is not
      // itself setup. If no line qualifies, this block produces no pattern and
      // the proposal routes to human-PoC (the grounding gate exits 3).
      let best: string | null = null;
      let bestScore = 0;
      for (const rawLine of raw.split("\n")) {
        const line = rawLine.trim();
        if (line.length < 8 || line.length > 200) continue;
        if (isBenignLine(line)) continue;
        const score = attackScore(line);
        if (score > bestScore) {
          bestScore = score;
          best = line;
        }
      }
      if (best === null || bestScore === 0) continue;
      results.push({
        extractor: "code-block",
        regex: `(?i)${escapeRegex(best)}`,
        description: `Attack-indicator line from advisory PoC code block (${bestScore} signal${bestScore > 1 ? "s" : ""})`,
        test_input: best,
        grounding: "poc",
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
        grounding: "prose",
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
        grounding: "prose",
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
        grounding: "prose",
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
          grounding: "prose",
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
        grounding: "prose",
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
  // Strip every source-provenance block (_ghsa_sync, _huntr_sync, _osv_sync,
  // _mcp_security_sync, _vulnerablemcp_sync, _msrc_sync, _owasp_asi_sync, …)
  // and the triage flag — these are import scaffolding, not part of the rule.
  for (const key of Object.keys(newRule)) {
    if (/^_.*_sync$/.test(key)) delete (newRule as Record<string, unknown>)[key];
  }
  delete (newRule as Record<string, unknown>)._triage;

  const hasPoc = patterns.some((p) => p.grounding === "poc");

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
      description: `Auto-extracted via ${p.extractor} (${p.grounding}-grounded)`,
    })),
    true_negatives: BENIGN_TRUE_NEGATIVES.map((input, i) => ({
      input,
      expected: "not_triggered",
      description: `Benign agent traffic sample ${i + 1}`,
    })),
  };

  if (hasPoc) {
    // At least one pattern is grounded in a real PoC code block — this is
    // a Cisco-level candidate. Promote to experimental for the maturity
    // pipeline + auto-merge gate.
    if (newRule.status === "draft") newRule.status = "experimental";
    if (newRule.maturity === undefined) newRule.maturity = "experimental";
  } else {
    // Prose-only: every pattern was inferred from advisory description
    // text, not from an exploit payload. This is the MiroFish failure
    // mode. Force the rule to draft + needs-human-poc so it CANNOT pass
    // the auto-merge gate (check-rules-safety.ts) and is surfaced for a
    // human to supply the real PoC payload.
    newRule.status = "draft";
    newRule.maturity = "needs-human-poc";
    (newRule as Record<string, unknown>)._needs_human_poc = {
      reason:
        "No PoC code block in the advisory. All detection patterns were " +
        "inferred from description prose and may detect the text describing " +
        "the attack rather than the attack itself. A maintainer must replace " +
        "detection.conditions with patterns derived from the actual exploit " +
        "payload before this rule can be promoted.",
      generated_at: new Date().toISOString(),
    };
  }

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
  const hasPoc = patterns.some((p) => p.grounding === "poc");
  const grounding = hasPoc ? "poc" : "prose-only";

  if (dryRun) {
    console.error(
      JSON.stringify(
        {
          status: "dry_run",
          proposal_id: proposal.id,
          patterns: patterns.length,
          grounding,
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
        status: hasPoc ? "written" : "written_needs_human_poc",
        output: outputPath,
        proposal_id: proposal.id,
        patterns: patterns.length,
        grounding,
        extractors_used: [...new Set(patterns.map((p) => p.extractor))],
      }),
    );
  } else {
    console.log(ruleYaml);
  }

  // Prose-only proposals must NOT auto-merge: every detection pattern was
  // inferred from advisory description text, which is the MiroFish failure
  // mode (detecting the sentence that describes the attack, not the attack).
  // Exit 3 signals the caller (cve-daily-sync.yml) to route this to human
  // review instead of the auto-merge gate. The draft rule is still written
  // so a maintainer can pick it up and supply the real PoC payload.
  if (!hasPoc) {
    process.exit(3);
  }
}

main();
