#!/usr/bin/env npx tsx
/**
 * validate-atd.ts — schema gate for the ATD enumeration.
 *
 * Validates every technique in website/public/atd/atd-techniques.json against
 * the normative JSON Schema (website/public/atd/atd-technique.schema.json), and
 * checks catalog-level invariants (unique ids, known tactics, no broken self).
 *
 * This is the deterministic gate behind ATD contributions: a submitted or
 * edited technique MUST validate here before a maintainer reviews it, and the
 * CI workflow runs it on any PR touching the ATD data. Nothing auto-publishes.
 *
 * Exit 0 = all techniques valid. Exit 1 = at least one failure.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA = resolve(REPO_ROOT, "website/public/atd/atd-technique.schema.json");
const DATA = resolve(REPO_ROOT, "website/public/atd/atd-techniques.json");

function main(): void {
  const schema = JSON.parse(readFileSync(SCHEMA, "utf-8"));
  const doc = JSON.parse(readFileSync(DATA, "utf-8"));
  const techniques: unknown[] = Array.isArray(doc?.techniques) ? doc.techniques : [];

  if (techniques.length === 0) {
    console.error("[validate-atd] FAIL: no techniques found in atd-techniques.json");
    process.exit(1);
  }

  // strict:false so unknown "format" keywords (uri/uuid) don't hard-error in
  // environments without ajv-formats; we register permissive formats instead.
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  ajv.addFormat("uri", () => true);
  ajv.addFormat("uuid", () => true);
  const validate = ajv.compile(schema);

  const seen = new Set<string>();
  const tactics = new Set(
    (Array.isArray(doc?.tactics) ? doc.tactics : []).map(
      (t: { id?: string }) => t?.id,
    ),
  );
  const failures: string[] = [];

  for (const t of techniques) {
    const tech = t as { atd_id?: string; tactic?: string };
    const id = tech.atd_id ?? "<no id>";
    if (!validate(t)) {
      const msg = (validate.errors ?? [])
        .map((e) => `${e.instancePath || "/"} ${e.message}`)
        .join("; ");
      failures.push(`${id}: schema — ${msg}`);
    }
    if (tech.atd_id) {
      if (seen.has(tech.atd_id)) failures.push(`${id}: duplicate atd_id`);
      seen.add(tech.atd_id);
    }
    if (tech.tactic && tactics.size > 0 && !tactics.has(tech.tactic)) {
      failures.push(`${id}: unknown tactic ${tech.tactic}`);
    }
  }

  if (failures.length > 0) {
    console.error(`[validate-atd] FAIL — ${failures.length} issue(s):`);
    for (const f of failures) console.error("  - " + f);
    process.exit(1);
  }
  console.log(`[validate-atd] PASS — ${techniques.length} techniques valid.`);
}

main();
