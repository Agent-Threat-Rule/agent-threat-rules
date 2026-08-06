/**
 * Backfill missing metadata_provenance fields on existing ATR rules.
 *
 * Adds category-appropriate MITRE ATLAS and OWASP references to rules
 * that are missing them, tagged with `metadata_provenance: auto-generated`
 * so stable promotion still requires human review.
 *
 * This is the ATR-repo dogfood of the "two-dimensional compliance" model
 * from RFC-001 §4:
 *  - Dimension 1: the metadata exists (auto-backfill fixes this)
 *  - Dimension 2: who verified it (provenance field — still "auto-generated")
 *
 * Usage:
 *   npx tsx scripts/backfill-metadata.ts [--dry-run] [--rule <path>]
 */

import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { parseATRRule } from "../src/quality/adapters/atr.js";

const RULES_DIR = join(import.meta.dirname, "..", "rules");
const isDryRun = process.argv.includes("--dry-run");

/**
 * Category → default MITRE/OWASP mappings.
 * These are the most-likely mappings for each category, curated from the
 * rules that already have correct mappings in the repo.
 *
 * Humans should review these in HUMAN_REVIEW_QUEUE.md and either:
 *  - Confirm → change provenance to human-reviewed
 *  - Replace → pick a better ATLAS technique
 *  - Reject → remove the auto-filled mapping
 */
const CATEGORY_DEFAULTS: Record<
  string,
  {
    mitre_atlas: readonly string[];
    owasp_llm?: readonly string[];
    owasp_agentic?: readonly string[];
  }
> = {
  "prompt-injection": {
    mitre_atlas: ["AML.T0051 - LLM Prompt Injection"],
    owasp_llm: ["LLM01:2025"],
    owasp_agentic: ["ASI01:2026"],
  },
  "tool-poisoning": {
    mitre_atlas: ["AML.T0053 - LLM Plugin Compromise"],
    owasp_llm: ["LLM06:2025"],
    owasp_agentic: ["ASI03:2026"],
  },
  "context-exfiltration": {
    mitre_atlas: ["AML.T0057 - LLM Data Leakage"],
    owasp_llm: ["LLM07:2025"],
    owasp_agentic: ["ASI05:2026"],
  },
  "agent-manipulation": {
    mitre_atlas: ["AML.T0051 - LLM Prompt Injection"],
    owasp_agentic: ["ASI07:2026"],
  },
  "privilege-escalation": {
    mitre_atlas: ["AML.T0054 - LLM Jailbreak"],
    owasp_llm: ["LLM06:2025"],
    owasp_agentic: ["ASI06:2026"],
  },
  "skill-compromise": {
    mitre_atlas: ["AML.T0010 - ML Supply Chain Compromise"],
    owasp_llm: ["LLM05:2025"],
    owasp_agentic: ["ASI03:2026"],
  },
  "excessive-autonomy": {
    mitre_atlas: ["AML.T0048 - External Harms"],
    owasp_llm: ["LLM06:2025"],
    owasp_agentic: ["ASI04:2026"],
  },
  "data-poisoning": {
    mitre_atlas: ["AML.T0020 - Poison Training Data"],
    owasp_llm: ["LLM04:2025"],
    owasp_agentic: ["ASI08:2026"],
  },
  "model-security": {
    mitre_atlas: ["AML.T0040 - ML Model Inference API Access"],
    owasp_llm: ["LLM02:2025"],
    owasp_agentic: ["ASI09:2026"],
  },
};

function findYaml(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...findYaml(full));
    else if (e.endsWith(".yaml")) out.push(full);
  }
  return out;
}

function getCategoryFromPath(filePath: string): string | null {
  const rel = filePath.replace(RULES_DIR + "/", "");
  const parts = rel.split("/");
  return parts[0] ?? null;
}

interface BackfillResult {
  file: string;
  category: string;
  addedMitre: boolean;
  addedOwaspLlm: boolean;
  addedOwaspAgentic: boolean;
}

function backfillRule(filePath: string): BackfillResult | null {
  const content = readFileSync(filePath, "utf-8");
  const metadata = parseATRRule(content);
  const category = getCategoryFromPath(filePath);
  if (!category) return null;

  const defaults = CATEGORY_DEFAULTS[category];
  if (!defaults) return null;

  const needsMitre = !metadata.hasMitreRef;
  const needsOwaspLlm =
    !metadata.hasOwaspRef && defaults.owasp_llm !== undefined;
  const needsOwaspAgentic =
    !metadata.hasOwaspRef && defaults.owasp_agentic !== undefined;

  if (!needsMitre && !needsOwaspLlm && !needsOwaspAgentic) {
    return null;
  }

  let newContent = content;

  // Find the references section — match both cases: has references or missing entirely
  const hasReferencesSection = /^references:/m.test(newContent);

  if (hasReferencesSection) {
    // Insert missing subfields under existing references:
    if (needsMitre) {
      // Add mitre_atlas under references:
      newContent = newContent.replace(
        /^references:$/m,
        `references:\n  mitre_atlas:\n${defaults.mitre_atlas.map((t) => `    - "${t}"`).join("\n")}`,
      );
    }
    if (needsOwaspLlm && defaults.owasp_llm) {
      newContent = newContent.replace(
        /^references:$/m,
        `references:\n  owasp_llm:\n${defaults.owasp_llm.map((t) => `    - "${t}"`).join("\n")}`,
      );
    }
    if (needsOwaspAgentic && defaults.owasp_agentic && !needsOwaspLlm) {
      newContent = newContent.replace(
        /^references:$/m,
        `references:\n  owasp_agentic:\n${defaults.owasp_agentic.map((t) => `    - "${t}"`).join("\n")}`,
      );
    }
  } else {
    // Insert a new references: block before tags:
    const refsBlock: string[] = ["references:"];
    if (needsMitre) {
      refsBlock.push("  mitre_atlas:");
      for (const t of defaults.mitre_atlas) refsBlock.push(`    - "${t}"`);
    }
    if (needsOwaspLlm && defaults.owasp_llm) {
      refsBlock.push("  owasp_llm:");
      for (const t of defaults.owasp_llm) refsBlock.push(`    - "${t}"`);
    }
    if (needsOwaspAgentic && defaults.owasp_agentic) {
      refsBlock.push("  owasp_agentic:");
      for (const t of defaults.owasp_agentic) refsBlock.push(`    - "${t}"`);
    }
    const block = refsBlock.join("\n") + "\n";
    newContent = newContent.replace(/^tags:/m, `${block}\ntags:`);
  }

  // Add provenance block before tags: (or append to existing)
  if (!/^metadata_provenance:/m.test(newContent)) {
    const provenanceFields: string[] = ["metadata_provenance:"];
    if (needsMitre) provenanceFields.push("  mitre_atlas: auto-generated");
    if (needsOwaspLlm) provenanceFields.push("  owasp_llm: auto-generated");
    if (needsOwaspAgentic && !needsOwaspLlm)
      provenanceFields.push("  owasp_agentic: auto-generated");
    const block = provenanceFields.join("\n") + "\n";
    // Insert before tags:
    newContent = newContent.replace(/^tags:/m, `${block}\ntags:`);
  }

  if (!isDryRun) {
    writeFileSync(filePath, newContent);
  }

  return {
    file: filePath.replace(RULES_DIR + "/", ""),
    category,
    addedMitre: needsMitre,
    addedOwaspLlm: needsOwaspLlm,
    addedOwaspAgentic: needsOwaspAgentic && !needsOwaspLlm,
  };
}

// Main
const targetArg = process.argv.indexOf("--rule");
const files =
  targetArg !== -1 && process.argv[targetArg + 1]
    ? [process.argv[targetArg + 1]!]
    : findYaml(RULES_DIR);

console.log(
  `${isDryRun ? "[DRY RUN] " : ""}Backfilling ${files.length} rule file(s)\n`,
);

const results: BackfillResult[] = [];
for (const f of files) {
  try {
    const result = backfillRule(f);
    if (result) results.push(result);
  } catch (err) {
    console.error(
      `  Failed ${f}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

console.log(`Modified: ${results.length} rules\n`);

const byCategory: Record<string, number> = {};
for (const r of results) {
  byCategory[r.category] = (byCategory[r.category] ?? 0) + 1;
}
console.log("By category:");
for (const [c, n] of Object.entries(byCategory).sort()) {
  console.log(`  ${c.padEnd(25)} ${n}`);
}

const addedMitre = results.filter((r) => r.addedMitre).length;
const addedOwaspLlm = results.filter((r) => r.addedOwaspLlm).length;
const addedOwaspAgentic = results.filter((r) => r.addedOwaspAgentic).length;
console.log(`\nAdded mitre_atlas:    ${addedMitre}`);
console.log(`Added owasp_llm:      ${addedOwaspLlm}`);
console.log(`Added owasp_agentic:  ${addedOwaspAgentic}`);

if (!isDryRun && results.length > 0) {
  console.log(`\nAll auto-backfilled fields are tagged with:`);
  console.log(`  metadata_provenance:`);
  console.log(`    mitre_atlas: auto-generated`);
  console.log(`\nThese rules will PASS experimental gate but NOT stable gate`);
  console.log(
    `until a human reviewer updates the provenance to human-reviewed.`,
  );
}
