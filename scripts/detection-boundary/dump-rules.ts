/**
 * Dump every rule on disk to rules-dump.json for the Python analysers in this
 * directory. Uses the project's own loader so the dump reflects exactly what
 * the engine sees, including schema-variant normalisation.
 *
 * Usage: npx tsx scripts/detection-boundary/dump-rules.ts
 */
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFileSync } from "node:fs";
import { loadRulesFromDirectory } from "../../src/loader.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

interface DumpedRule {
  id: string;
  title: string;
  maturity: string | null;
  status: string | null;
  category: string | null;
  detection: unknown;
  test_cases: unknown;
  response: unknown;
}

function main(): void {
  const rules = loadRulesFromDirectory(join(REPO_ROOT, "rules")) as unknown as Record<
    string,
    unknown
  >[];
  const out: DumpedRule[] = rules.map((r) => {
    const tags = (r["tags"] ?? {}) as Record<string, unknown>;
    const meta = (r["metadata"] ?? {}) as Record<string, unknown>;
    return {
      id: String(r["id"] ?? ""),
      title: String(r["title"] ?? ""),
      maturity: (r["maturity"] ?? meta["maturity"] ?? null) as string | null,
      status: (r["status"] ?? null) as string | null,
      category: (tags["category"] ?? null) as string | null,
      detection: r["detection"] ?? null,
      test_cases: r["test_cases"] ?? null,
      response: r["response"] ?? null,
    };
  });
  writeFileSync(join(HERE, "rules-dump.json"), JSON.stringify(out, null, 1));
  console.log(`dumped ${out.length} rules`);
}

main();
