#!/usr/bin/env node
/**
 * prune-published-rules.mjs
 *
 * Removes each rule's test samples (test_cases, evasion_tests) from a rules
 * directory, in place. publish.yml runs it on its own checkout, after the tests
 * and right before staging, so the npm tarball carries the detection rules
 * without the attack samples that exercise them. The repository keeps them.
 *
 * Why: npm's publish-time scanning blocked 4.1.1 through 4.1.4. 4.0.0 passed.
 * The 4.1 line added rules whose test samples are working malware snippets: a
 * crypto-miner command line with a pool URL, PHP/JSP/ASPX webshells, a Node.js
 * reverse shell. None of that is needed to detect anything. The engine reads
 * detection, not test cases (src/loader.ts validates test_cases only when they
 * are present), so detection is unchanged. What a user loses: `atr test` on a
 * bundled rule has no samples to run, and TP/TN counts in `atr stats` read 0.
 * The samples stay in the repository for anyone who wants them.
 *
 * This removes content. It does not encode or disguise any of it.
 *
 * USAGE
 *   node scripts/prune-published-rules.mjs [rulesDir]   (default: rules)
 */
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import yaml from "js-yaml";

export const PRUNED_KEYS = Object.freeze(["test_cases", "evasion_tests"]);

// lineWidth -1: never fold a long regex onto several lines.
const DUMP_OPTIONS = Object.freeze({ lineWidth: -1, noRefs: true });

/** Every rule file under `dir`. */
export function ruleFiles(dir) {
  return readdirSync(dir)
    .sort()
    .flatMap((entry) => {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) return ruleFiles(full);
      return entry.endsWith(".yaml") || entry.endsWith(".yml") ? [full] : [];
    });
}

/** The rule without its test samples; null when it has none to remove. Never mutates `doc`. */
export function prunedRule(doc) {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) return null;
  if (!PRUNED_KEYS.some((k) => k in doc)) return null;
  return Object.fromEntries(Object.entries(doc).filter(([k]) => !PRUNED_KEYS.includes(k)));
}

/** Prune every rule file under `dir`. Returns how many files changed. Throws on a file it cannot parse. */
export function pruneRulesDir(dir) {
  let changed = 0;
  for (const file of ruleFiles(dir)) {
    const doc = yaml.load(readFileSync(file, "utf8"));
    const pruned = prunedRule(doc);
    if (!pruned) continue;
    writeFileSync(file, yaml.dump(pruned, DUMP_OPTIONS));
    changed += 1;
  }
  return changed;
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const dir = process.argv[2] ?? "rules";
  const changed = pruneRulesDir(dir);
  console.log(`[prune-published-rules] removed ${PRUNED_KEYS.join(" and ")} from ${changed} rule file(s) under ${dir}`);
}
