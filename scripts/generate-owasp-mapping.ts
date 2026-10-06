#!/usr/bin/env tsx
/**
 * generate-owasp-mapping.ts
 *
 * Walks /rules/**\/*.yaml, buckets every rule by OWASP Agentic Top 10 (2026) ASI category,
 * and emits:
 *   - docs/OWASP-AGENTIC-MAPPING.md   (canonical human-readable mapping)
 *   - docs/owasp-agentic-mapping.json (programmatic consumption)
 *
 * ASI tags are read from two locations (a rule may have either or both):
 *   1. references.owasp_agentic : ["ASI01:2026", ...]
 *   2. compliance.owasp_agentic : [{ id: "ASI01:2026", context, strength }, ...]
 *
 * Bucketing is done on the ASI[0-9]+ prefix only — different rules use legacy taxonomy
 * suffixes ("Tool Poisoning", "Prompt Injection", etc.), but the prefix is canonical.
 *
 * Strength tiers:
 *   STRONG   : >= 8 rules
 *   MODERATE : 4-7 rules
 *   LIMITED  : 1-3 rules
 *
 * Authoritative ASI01-ASI10 names: OWASP Agentic Top 10 v1.0 (December 2025).
 * Source: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
 */

import fs from "node:fs";
import path from "node:path";
import yaml from "js-yaml";

const REPO_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const RULES_DIR = path.join(REPO_ROOT, "rules");
const DOCS_DIR = path.join(REPO_ROOT, "docs");
const OUTPUT_MD = path.join(DOCS_DIR, "OWASP-AGENTIC-MAPPING.md");
const OUTPUT_JSON = path.join(DOCS_DIR, "owasp-agentic-mapping.json");

const ATR_VERSION = `v${JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"), "utf8")).version}`;
const OWASP_VERSION = "v1.0 (December 2025)";
const RUN_DATE = new Date().toISOString().slice(0, 10);

interface AsiCategory {
  readonly key: string; // "ASI01"
  readonly fullId: string; // "ASI01:2026"
  readonly title: string;
  readonly officialDescription: string;
  readonly referenceAttack?: string;
  readonly coverageNote: string;
}

const ASI_CATEGORIES: readonly AsiCategory[] = [
  {
    key: "ASI01",
    fullId: "ASI01:2026",
    title: "Agent Goal Hijack",
    officialDescription:
      "Attackers manipulate the agent's decision pathways or objectives so it pursues an adversary-controlled goal instead of its assigned task. Canonical instance: EchoLeak.",
    referenceAttack: "EchoLeak",
    coverageNote:
      "Direct + indirect prompt injection, persona hijack, encoding evasion, jailbreak chains, multi-turn assembly, multilingual paraphrase.",
  },
  {
    key: "ASI02",
    fullId: "ASI02:2026",
    title: "Tool Misuse and Exploitation",
    officialDescription:
      "Legitimate tools are used unsafely because the agent acts on ambiguous instructions or has over-privileged access. Canonical instance: Amazon Q assistant tool-misuse incident.",
    referenceAttack: "Amazon Q",
    coverageNote:
      "Unauthorized tool calls, SSRF via tool, MCP malicious response, schema-description contradiction, consent bypass.",
  },
  {
    key: "ASI03",
    fullId: "ASI03:2026",
    title: "Identity and Privilege Abuse",
    officialDescription:
      "Agents operate in an attribution gap; leaked credentials or escalated privileges let them act beyond intended scope.",
    coverageNote:
      "API key exposure, OAuth token abuse, env var harvesting, scope creep, credential file theft, privilege escalation.",
  },
  {
    key: "ASI04",
    fullId: "ASI04:2026",
    title: "Agentic Supply Chain Vulnerabilities",
    officialDescription:
      "Runtime composition of third-party capabilities (MCP servers, plugins, skills, A2A endpoints) lets adversaries poison the call graph after deployment. Canonical instance: GitHub MCP exploit.",
    referenceAttack: "GitHub MCP exploit",
    coverageNote:
      "Skill impersonation, hidden capability, polymorphic skill, registry poisoning, malicious skill code, parameter injection.",
  },
  {
    key: "ASI05",
    fullId: "ASI05:2026",
    title: "Unexpected Code Execution (RCE)",
    officialDescription:
      "Agents generate and execute code (\"vibe coding\"), opening RCE paths through natural-language instructions. Canonical instance: AutoGPT RCE.",
    referenceAttack: "AutoGPT RCE",
    coverageNote:
      "eval injection, shell metacharacter escape, dynamic import exploitation, indirect tool injection leading to code exec.",
  },
  {
    key: "ASI06",
    fullId: "ASI06:2026",
    title: "Memory & Context Poisoning",
    officialDescription:
      "Long-term memory, RAG stores, or shared context are corrupted so the agent's future behavior is shaped by attacker payloads. Canonical instance: Gemini Memory Attack.",
    referenceAttack: "Gemini Memory Attack",
    coverageNote:
      "Agent memory manipulation, RAG poisoning, audit evasion, malicious finetuning data, consensus poisoning, persistent context drift.",
  },
  {
    key: "ASI07",
    fullId: "ASI07:2026",
    title: "Insecure Inter-Agent Communication",
    officialDescription:
      "Multi-agent systems exchange messages without authentication or integrity guarantees, letting adversaries spoof or replay messages between agents.",
    coverageNote:
      "A2A message spoofing, agent identity spoofing, consensus sybil attack, cross-agent attack vectors.",
  },
  {
    key: "ASI08",
    fullId: "ASI08:2026",
    title: "Cascading Failures",
    officialDescription:
      "A single fault in one agent, tool, or signal propagates system-wide because automated downstream consumers act on it without independent validation.",
    coverageNote:
      "Runaway agent loop, resource exhaustion, cascading failure detection, model behavior extraction triggering downstream cascade.",
  },
  {
    key: "ASI09",
    fullId: "ASI09:2026",
    title: "Human-Agent Trust Exploitation",
    officialDescription:
      "Adversaries exploit anthropomorphism and authority bias so humans approve harmful agent actions they would otherwise reject.",
    coverageNote:
      "Human trust exploitation, approval fatigue, social engineering via agent, unauthorized financial action, high-risk tool gate bypass.",
  },
  {
    key: "ASI10",
    fullId: "ASI10:2026",
    title: "Rogue Agents",
    officialDescription:
      "Agents deviate from their intended function, optionally collude with other agents, and operate as autonomous threats. Canonical instance: Replit meltdown.",
    referenceAttack: "Replit meltdown",
    coverageNote:
      "Goal hijacking, cross-agent privilege escalation, runaway loop, scope creep, delayed execution bypass, polymorphic behavior.",
  },
];

interface RuleMeta {
  readonly file: string;
  readonly id: string;
  readonly title: string;
  readonly severity: string;
  readonly category: string;
  readonly asiTags: ReadonlySet<string>;
  readonly description: string;
}

function listYaml(dir: string): readonly string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...listYaml(full));
    } else if (entry.isFile() && entry.name.endsWith(".yaml")) {
      out.push(full);
    }
  }
  return out;
}

function extractAsiKeys(raw: unknown): ReadonlySet<string> {
  // Accepts strings like "ASI01:2026" or "ASI01 - Prompt Injection"
  // and objects like { id: "ASI01:2026", ... }.
  const collected = new Set<string>();
  const visit = (value: unknown): void => {
    if (value == null) return;
    if (typeof value === "string") {
      const match = value.match(/ASI(\d{2})/);
      if (match) collected.add(`ASI${match[1]}`);
      return;
    }
    if (Array.isArray(value)) {
      for (const v of value) visit(v);
      return;
    }
    if (typeof value === "object") {
      for (const v of Object.values(value as Record<string, unknown>)) visit(v);
    }
  };
  visit(raw);
  return collected;
}

function loadRule(file: string): RuleMeta | null {
  try {
    const text = fs.readFileSync(file, "utf-8");
    const doc = yaml.load(text) as Record<string, unknown> | null;
    if (!doc) return null;
    const refs = (doc.references as Record<string, unknown> | undefined)?.owasp_agentic;
    const compliance = (doc.compliance as Record<string, unknown> | undefined)?.owasp_agentic;
    const asi = new Set<string>([...extractAsiKeys(refs), ...extractAsiKeys(compliance)]);
    if (asi.size === 0) return null;
    return {
      file: path.relative(REPO_ROOT, file),
      id: String(doc.id ?? path.basename(file, ".yaml")),
      title: String(doc.title ?? "").replace(/^"|"$/g, ""),
      severity: String(doc.severity ?? "unknown"),
      category: path.basename(path.dirname(file)),
      asiTags: asi,
      description: String(doc.description ?? "").trim().replace(/\s+/g, " "),
    };
  } catch (err) {
    process.stderr.write(`failed to parse ${file}: ${(err as Error).message}\n`);
    return null;
  }
}

function strengthTier(count: number): "STRONG" | "MODERATE" | "LIMITED" | "GAP" {
  if (count >= 8) return "STRONG";
  if (count >= 4) return "MODERATE";
  if (count >= 1) return "LIMITED";
  return "GAP";
}

function severityRank(s: string): number {
  const map: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  return map[s.toLowerCase()] ?? 4;
}

function shortDesc(desc: string, max = 90): string {
  if (desc.length <= max) return desc;
  return desc.slice(0, max - 1).trimEnd() + "…";
}

function main(): void {
  const files = listYaml(RULES_DIR);
  const rules: RuleMeta[] = [];
  for (const file of files) {
    const r = loadRule(file);
    if (r) rules.push(r);
  }

  const buckets = new Map<string, RuleMeta[]>();
  for (const cat of ASI_CATEGORIES) buckets.set(cat.key, []);
  let totalMappings = 0;
  for (const rule of rules) {
    for (const tag of rule.asiTags) {
      const bucket = buckets.get(tag);
      if (bucket) {
        bucket.push(rule);
        totalMappings += 1;
      }
    }
  }
  // sort each bucket: severity (critical first) then id
  for (const arr of buckets.values()) {
    arr.sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.id.localeCompare(b.id));
  }

  // Validate every ASI has at least 1 rule
  const empty = ASI_CATEGORIES.filter((c) => (buckets.get(c.key) ?? []).length === 0);
  if (empty.length > 0) {
    process.stderr.write(`ERROR: ASI categories with zero rules: ${empty.map((c) => c.key).join(", ")}\n`);
    process.exit(1);
  }

  // --- markdown output ---
  const lines: string[] = [];
  lines.push("# ATR -> OWASP Agentic Top 10 (2026) Mapping");
  lines.push("");
  lines.push(`Last updated: ${RUN_DATE}`);
  lines.push(`ATR version: ${ATR_VERSION} (${rules.length} rules with OWASP Agentic tags)`);
  lines.push(`OWASP framework: Agentic Top 10 ${OWASP_VERSION}`);
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(`- Categories covered: **10/10**`);
  lines.push(`- Total rule -> category mappings: **${totalMappings}**`);
  lines.push(`- Tagged ATR rules: **${rules.length}** of ${files.length} total rules in repo`);
  lines.push(`- ATR version: \`${ATR_VERSION}\` -- OWASP Agentic Top 10: \`${OWASP_VERSION}\``);
  lines.push("");
  lines.push("Strength tiers: **STRONG** >= 8 rules · **MODERATE** 4-7 rules · **LIMITED** 1-3 rules.");
  lines.push("");

  lines.push("## Coverage by ASI category");
  lines.push("");
  lines.push("| ASI | Title | Rule count | Strength | Reference attack |");
  lines.push("|---|---|---|---|---|");
  for (const cat of ASI_CATEGORIES) {
    const count = (buckets.get(cat.key) ?? []).length;
    const tier = strengthTier(count);
    lines.push(`| ${cat.key} | ${cat.title} | ${count} | ${tier} | ${cat.referenceAttack ?? "n/a"} |`);
  }
  lines.push("");
  lines.push("---");
  lines.push("");

  lines.push("## Per-category detail");
  lines.push("");

  for (const cat of ASI_CATEGORIES) {
    const bucket = buckets.get(cat.key) ?? [];
    const count = bucket.length;
    const tier = strengthTier(count);
    lines.push(`### ${cat.key}: ${cat.title} (${count} rules) -- ${tier}`);
    lines.push("");
    lines.push(`**OWASP description.** ${cat.officialDescription}`);
    lines.push("");
    lines.push(`**ATR coverage shape.** ${cat.coverageNote}`);
    lines.push("");
    if (cat.referenceAttack) {
      lines.push(`**Reference attack (${cat.referenceAttack}).** Covered by the rules below; ATR's general-purpose detection layers match the technique signature without needing an attack-specific rule.`);
      lines.push("");
    }
    if (count === 0) {
      lines.push("_No rules tagged this category yet._");
      lines.push("");
      continue;
    }
    const top = bucket.slice(0, 5);
    lines.push("Top rules by severity:");
    lines.push("");
    lines.push("| Rule ID | Title | Severity | Description |");
    lines.push("|---|---|---|---|");
    for (const r of top) {
      const titleSafe = r.title.replace(/\|/g, "\\|");
      const descSafe = shortDesc(r.description).replace(/\|/g, "\\|");
      lines.push(`| ${r.id} | ${titleSafe} | ${r.severity} | ${descSafe} |`);
    }
    lines.push("");
    if (count > 5) {
      lines.push(`Plus ${count - 5} additional rules tagged ${cat.key} -- see \`docs/owasp-agentic-mapping.json\` for the complete list.`);
      lines.push("");
    }
  }

  lines.push("---");
  lines.push("");
  lines.push("## Methodology");
  lines.push("");
  lines.push("Each YAML file under `rules/` is scanned for OWASP Agentic Top 10 tags in two locations:");
  lines.push("");
  lines.push("1. `references.owasp_agentic` -- string list of bare ids (e.g. `\"ASI01:2026\"`)");
  lines.push("2. `compliance.owasp_agentic[].id` -- structured form (e.g. `id: ASI01:2026`)");
  lines.push("");
  lines.push("Bucketing is done on the `ASI[0-9]{2}` prefix to absorb legacy taxonomy suffixes. A rule mapping to multiple ASI categories counts in each. Strength tiers: **STRONG** >= 8 · **MODERATE** 4-7 · **LIMITED** 1-3.");
  lines.push("");
  lines.push("Regenerate with:");
  lines.push("");
  lines.push("```bash");
  lines.push("npx tsx scripts/generate-owasp-mapping.ts");
  lines.push("```");
  lines.push("");
  lines.push("Outputs `docs/OWASP-AGENTIC-MAPPING.md` (this file) and `docs/owasp-agentic-mapping.json` (programmatic consumption).");
  lines.push("");

  lines.push("## Reciprocal mappings");
  lines.push("");
  lines.push("- MITRE ATLAS -- see per-rule `mitre_atlas` field plus aggregate coverage in [COVERAGE.md](../COVERAGE.md)");
  lines.push("- NIST AI RMF -- see per-rule `compliance.nist_ai_rmf[]` plus the [AI RMF OSCAL catalog](https://github.com/Agent-Threat-Rule/ai-rmf-oscal-catalog)");
  lines.push("- EU AI Act -- per-rule `compliance.eu_ai_act[]` (Article 9, Article 15)");
  lines.push("- ISO/IEC 42001 -- per-rule `compliance.iso_42001[]`");
  lines.push("- OWASP LLM Top 10 (2025) -- per-rule `compliance.owasp_llm[]`");
  lines.push("- SAFE-MCP -- see [SAFE-MCP-MAPPING.md](SAFE-MCP-MAPPING.md) (78/85 techniques, 91.8%)");
  lines.push("- OWASP Agentic Skills Top 10 (AST) -- see [OWASP-AST10-MAPPING.md](OWASP-AST10-MAPPING.md) (skill supply chain framework)");
  lines.push("- OWASP Agentic AI Maturity Model -- see [OWASP-AGENTIC-MATURITY-MAPPING.md](OWASP-AGENTIC-MATURITY-MAPPING.md) (which ASI detections substantiate governance maturity)");
  lines.push("");

  lines.push("## Contributing");
  lines.push("");
  lines.push("To propose a new mapping or correct an existing one:");
  lines.push("");
  lines.push("1. Open a PR editing the relevant rule under `rules/<category>/ATR-2026-NNNNN-*.yaml`");
  lines.push("2. Add or update the `references.owasp_agentic` and/or `compliance.owasp_agentic` block");
  lines.push("3. Run `npx tsx scripts/generate-owasp-mapping.ts` to regenerate this file");
  lines.push("4. Include the regenerated `docs/OWASP-AGENTIC-MAPPING.md` and `docs/owasp-agentic-mapping.json` in the PR");
  lines.push("");
  lines.push("See [CONTRIBUTING.md](../CONTRIBUTING.md) for the full contribution flow.");
  lines.push("");

  lines.push("## References");
  lines.push("");
  lines.push("- OWASP Agentic Top 10 (2026) -- https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/");
  lines.push("- OWASP GenAI Security Project -- https://genai.owasp.org/");
  lines.push("- Project Chair: John Sotiropoulos -- ASI Co-lead");
  lines.push("- Agentic Top 10 Co-leads: Keren Katz, Ron F. Del Rosario");
  lines.push("- Project contact: https://genai.owasp.org/contact/");
  lines.push("- ATR repository: https://github.com/Agent-Threat-Rule/agent-threat-rules");
  lines.push("- ATR npm package: https://www.npmjs.com/package/agent-threat-rules");
  lines.push("");

  fs.mkdirSync(DOCS_DIR, { recursive: true });
  fs.writeFileSync(OUTPUT_MD, lines.join("\n"), "utf-8");

  // --- JSON output ---
  const jsonOut = {
    generated_at: RUN_DATE,
    atr_version: ATR_VERSION,
    owasp_agentic_version: OWASP_VERSION,
    total_rules_in_repo: files.length,
    total_tagged_rules: rules.length,
    total_mappings: totalMappings,
    categories: ASI_CATEGORIES.map((cat) => {
      const bucket = buckets.get(cat.key) ?? [];
      return {
        key: cat.key,
        full_id: cat.fullId,
        title: cat.title,
        official_description: cat.officialDescription,
        reference_attack: cat.referenceAttack ?? null,
        coverage_note: cat.coverageNote,
        rule_count: bucket.length,
        strength: strengthTier(bucket.length),
        rules: bucket.map((r) => ({
          id: r.id,
          title: r.title,
          severity: r.severity,
          category: r.category,
          file: r.file,
        })),
      };
    }),
  };
  fs.writeFileSync(OUTPUT_JSON, JSON.stringify(jsonOut, null, 2) + "\n", "utf-8");

  process.stdout.write(`Wrote ${path.relative(REPO_ROOT, OUTPUT_MD)} and ${path.relative(REPO_ROOT, OUTPUT_JSON)}\n`);
  process.stdout.write(`Tagged rules: ${rules.length} / ${files.length}, total mappings: ${totalMappings}\n`);
  for (const cat of ASI_CATEGORIES) {
    const count = (buckets.get(cat.key) ?? []).length;
    process.stdout.write(`  ${cat.key} ${cat.title}: ${count} rules (${strengthTier(count)})\n`);
  }
}

main();
