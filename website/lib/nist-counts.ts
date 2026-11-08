import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import yaml from "js-yaml";

export interface NistCount {
  id: string;
  count: number;
}

let cache: NistCount[] | null = null;

/**
 * How many times each NIST AI RMF subcategory is cited in the `compliance:`
 * blocks of effective rules (draft and deprecated left out), most cited
 * first. Read from the rule files at build time, so the table never goes
 * stale.
 */
export function loadNistSubcategoryCounts(): NistCount[] {
  if (cache) return cache;
  const walk = (dir: string): string[] =>
    readdirSync(dir).flatMap((f) => {
      const p = join(dir, f);
      return statSync(p).isDirectory() ? walk(p) : p.endsWith(".yaml") ? [p] : [];
    });
  const counts = new Map<string, number>();
  for (const file of walk(join(process.cwd(), "..", "rules"))) {
    const rule = yaml.load(readFileSync(file, "utf-8")) as { status?: string; compliance?: { nist_ai_rmf?: Array<{ subcategory?: string }> } } | null;
    if (!rule || rule.status === "draft" || rule.status === "deprecated") continue;
    for (const item of rule.compliance?.nist_ai_rmf ?? []) {
      if (item?.subcategory) counts.set(item.subcategory, (counts.get(item.subcategory) ?? 0) + 1);
    }
  }
  cache = [...counts].map(([id, count]) => ({ id, count })).sort((a, b) => b.count - a.count || a.id.localeCompare(b.id));
  return cache;
}
