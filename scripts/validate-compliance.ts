/**
 * Compliance Mapping Validator — fails CI when any rule's `compliance:` block
 * cites a framework control identifier that does not exist in the published
 * framework. This is the honesty guardrail: you cannot map a rule to a fake
 * EU AI Act article or a non-existent ISO 42001 clause and have it merge.
 *
 * Allowlists live in data/compliance-frameworks/*.json — one file per framework,
 * each declaring its `idField`, the valid identifier set, and allowed `strength`
 * values. A framework that appears in rules but has no allowlist file is reported
 * as a warning (not a failure) so allowlists can be added incrementally.
 *
 * Checks per `compliance:` item:
 *   1. identifier (allowlist.idField) is present and in the allowlist
 *   2. `context` is a non-empty string (auditor-readable rationale)
 *   3. `strength`, if present, is one of the allowlist's strengthValues
 *
 * The `references:` block is linted too, against the same allowlists but with
 * only check 1 — see validateReferences. It is an index rather than audit
 * evidence, so it carries bare identifiers and needs no rationale. It went
 * unchecked until 2026-08, which is how a fabricated SAF-MCP identifier and a
 * retired prefix survived there.
 *
 * Usage:
 *   npx tsx scripts/validate-compliance.ts          report + non-zero exit on violations
 *   npx tsx scripts/validate-compliance.ts --quiet   only print the summary line
 *
 *   npm run validate:compliance
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { loadAll } from "js-yaml";

const ROOT = join(import.meta.dirname, "..");
const RULES_DIR = join(ROOT, "rules");
const ALLOWLIST_DIR = join(ROOT, "data", "compliance-frameworks");

interface Allowlist {
  readonly framework: string;
  readonly idField: string;
  readonly valids: Record<string, string>;
  readonly strengthValues?: readonly string[];
}

interface Violation {
  readonly rule: string;
  readonly framework: string;
  readonly kind: "unknown-id" | "missing-id" | "missing-context" | "bad-strength" | "not-a-list";
  readonly detail: string;
}

function loadAllowlists(): Map<string, Allowlist> {
  const map = new Map<string, Allowlist>();
  for (const entry of readdirSync(ALLOWLIST_DIR)) {
    if (!entry.endsWith(".json")) continue;
    const key = entry.replace(/\.json$/, "");
    map.set(key, JSON.parse(readFileSync(join(ALLOWLIST_DIR, entry), "utf-8")) as Allowlist);
  }
  return map;
}

function findYamlFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...findYamlFiles(full));
    else if (entry.endsWith(".yaml") || entry.endsWith(".yml")) out.push(full);
  }
  return out;
}

function validateItem(
  ruleId: string,
  framework: string,
  item: unknown,
  allow: Allowlist,
): Violation[] {
  const out: Violation[] = [];
  const o = (item && typeof item === "object" ? item : {}) as Record<string, unknown>;
  const id = o[allow.idField];

  if (id === undefined || id === null) {
    out.push({ rule: ruleId, framework, kind: "missing-id", detail: `item has no '${allow.idField}'` });
  } else if (!(String(id) in allow.valids)) {
    out.push({ rule: ruleId, framework, kind: "unknown-id", detail: `${allow.idField}='${String(id)}' is not a valid ${allow.framework} identifier` });
  }
  if (typeof o.context !== "string" || o.context.trim() === "") {
    out.push({ rule: ruleId, framework, kind: "missing-context", detail: `${allow.idField}='${String(id)}' has no context prose` });
  }
  if (o.strength !== undefined && allow.strengthValues && !allow.strengthValues.includes(String(o.strength))) {
    out.push({ rule: ruleId, framework, kind: "bad-strength", detail: `strength='${String(o.strength)}' not in [${allow.strengthValues.join(", ")}]` });
  }
  return out;
}

/**
 * Lint the `references` block against the same allowlists.
 *
 * references is an index, not audit evidence, so entries stay bare strings and
 * are NOT required to carry context or strength — only to name an identifier
 * that exists. Without this pass the block was entirely unchecked, which is how
 * a fabricated SAF-MCP identifier and a retired prefix lived there while the
 * compliance block beside them was gated.
 *
 * Values are conventionally written "ID - Title" (e.g. "LLM01:2025 - Prompt
 * Injection"), so the leading token is what gets checked.
 *
 * The title half is NOT compared, and the reason is not that it would be
 * pedantic — it is that 821 values in the corpus would fail today. They pair a
 * 2025 identifier with the title that number carried in the 2023 list:
 * LLM04:2025 is labelled "Model Denial of Service" (2023's LLM04; 2025's is
 * "Data and Model Poisoning"), LLM09:2025 is labelled "Overreliance" (2025's is
 * "Misinformation"), and 731 owasp_agentic values are similarly stale. That is
 * the same version-mixing defect as PR.AC-04, and it wants its own change:
 * either drop the embedded titles so the allowlist stays the single source, or
 * rewrite all 821. Turning the check on here would force that decision as a
 * side effect of adding a lint, so it stays off and stays documented.
 *
 * Frameworks with no allowlist are skipped silently here — the compliance pass
 * already reports those by name.
 */
function validateReferences(
  ruleId: string,
  references: Record<string, unknown>,
  allowlists: Map<string, Allowlist>,
): Violation[] {
  const out: Violation[] = [];
  for (const [framework, items] of Object.entries(references)) {
    const allow = allowlists.get(framework);
    if (!allow || !Array.isArray(items)) continue;
    for (const item of items) {
      if (typeof item !== "string") continue;
      const id = item.split(" - ")[0]?.trim() ?? "";
      if (!(id in allow.valids)) {
        out.push({
          rule: ruleId,
          framework: `references.${framework}`,
          kind: "unknown-id",
          detail: `'${id}' is not a valid ${allow.framework} identifier`,
        });
      }
    }
  }
  return out;
}

function validateRule(ruleId: string, compliance: Record<string, unknown>, allowlists: Map<string, Allowlist>): { violations: Violation[]; unknownFrameworks: string[] } {
  const violations: Violation[] = [];
  const unknownFrameworks: string[] = [];
  for (const [framework, items] of Object.entries(compliance)) {
    const allow = allowlists.get(framework);
    if (!allow) {
      unknownFrameworks.push(framework);
      continue;
    }
    if (!Array.isArray(items)) {
      violations.push({ rule: ruleId, framework, kind: "not-a-list", detail: "compliance entry is not a list" });
      continue;
    }
    for (const item of items) violations.push(...validateItem(ruleId, framework, item, allow));
  }
  return { violations, unknownFrameworks };
}

function main(): void {
  const quiet = process.argv.includes("--quiet");
  const allowlists = loadAllowlists();
  const files = findYamlFiles(RULES_DIR);

  const allViolations: Violation[] = [];
  const unknownFrameworks = new Map<string, number>();
  let rulesWithCompliance = 0;
  let rulesWithReferences = 0;

  for (const file of files) {
    let docs: unknown[];
    try {
      docs = (loadAll(readFileSync(file, "utf-8")) ?? []) as unknown[];
    } catch (err) {
      allViolations.push({ rule: file, framework: "-", kind: "not-a-list", detail: `YAML parse error: ${(err as Error).message}` });
      continue;
    }
    for (const doc of docs) {
      if (!doc || typeof doc !== "object") continue;
      const rule = doc as Record<string, unknown>;
      if (typeof rule.id !== "string" || !rule.id.startsWith("ATR-")) continue;
      // Before the compliance guard: a rule may carry references without a
      // compliance block, and those identifiers still have to exist.
      const references = rule.references;
      if (references && typeof references === "object") {
        allViolations.push(
          ...validateReferences(rule.id, references as Record<string, unknown>, allowlists),
        );
        rulesWithReferences++;
      }

      const compliance = rule.compliance;
      if (!compliance || typeof compliance !== "object") continue;
      rulesWithCompliance++;
      const { violations, unknownFrameworks: unknown } = validateRule(rule.id, compliance as Record<string, unknown>, allowlists);
      allViolations.push(...violations);
      for (const fw of unknown) unknownFrameworks.set(fw, (unknownFrameworks.get(fw) ?? 0) + 1);
    }
  }

  if (!quiet) {
    console.log(`\nCompliance Mapping Validator`);
    console.log(`${"─".repeat(64)}`);
    console.log(`Allowlists loaded: ${[...allowlists.keys()].join(", ")}`);
    console.log(`Rules with a compliance block: ${rulesWithCompliance}`);
    console.log(`Rules with a references block: ${rulesWithReferences} (identifiers checked, context not required)\n`);

    if (unknownFrameworks.size > 0) {
      console.log(`WARN — frameworks used in rules but with no allowlist (not validated):`);
      for (const [fw, n] of [...unknownFrameworks.entries()].sort((a, b) => b[1] - a[1])) {
        console.log(`  ${fw}: ${n} rules`);
      }
      console.log("");
    }

    if (allViolations.length === 0) {
      console.log(`PASS — 0 violations across ${rulesWithCompliance} mapped rules.\n`);
    } else {
      const byKind = new Map<string, Violation[]>();
      for (const v of allViolations) {
        if (!byKind.has(v.kind)) byKind.set(v.kind, []);
        byKind.get(v.kind)!.push(v);
      }
      for (const [kind, vs] of byKind) {
        console.log(`FAIL [${kind}] — ${vs.length}:`);
        for (const v of vs.slice(0, 40)) console.log(`  ${v.rule}  ${v.framework}: ${v.detail}`);
        if (vs.length > 40) console.log(`  ... and ${vs.length - 40} more`);
        console.log("");
      }
    }
  }

  console.log(`compliance-validate: ${allViolations.length} violation(s), ${unknownFrameworks.size} unvalidated framework(s)`);
  if (allViolations.length > 0) process.exitCode = 1;
}

main();
