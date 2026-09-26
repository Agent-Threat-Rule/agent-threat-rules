#!/usr/bin/env npx tsx
/**
 * gate-case-sensitivity.ts — rules whose regex means something different than it says.
 *
 * WHY THIS EXISTS
 *   src/engine.ts:933 compiles every rule regex with the 'i' flag, unconditionally:
 *
 *     const rFlags = normalized.includes('\\u{') || normalized.includes('\\p{') ? 'iu' : 'i';
 *
 *   So case is never distinguished at runtime, whatever the author wrote. An author who
 *   writes [A-OQ-Za-z_] to exclude a capital P, or AKIA[0-9A-Z]{16} to pin an AWS key id
 *   to its documented uppercase form, gets neither. The rule silently matches more than
 *   its text claims, and the extra matches are exactly the ones the author was trying to
 *   exclude. Measured on 789 rules, 206 carry case-sensitive constructs with no (?i)
 *   marker, so a quarter of the corpus is broader than it reads.
 *
 *   That gap is invisible everywhere else. validate-rules.ts checks structure, the benign
 *   gate checks a fixed corpus, and neither asks "does this pattern mean the same thing
 *   under the flag the engine actually uses". This gate asks exactly that.
 *
 * WHAT IT CHECKS
 *   For every regex condition, compile it twice -- case-sensitive and case-insensitive --
 *   and compare the match sets over the rule's own test cases plus a set of case-permuted
 *   variants of them. A rule flagged here behaves differently than written.
 *
 * WHAT IT DOES NOT DO
 *   It does not demand every regex be case-insensitive. Plenty of patterns are unaffected
 *   because they are all lowercase or all structure. It flags only the ones where the
 *   distinction is load-bearing and therefore silently lost.
 *
 * RATCHET, not a hard gate: a large pre-existing population is affected, and clearing it
 * means rewriting patterns. Failing every PR until then would stop all rule work.
 */
import { readFileSync, readdirSync, statSync, existsSync, writeFileSync } from "node:fs";
import { join, resolve, relative, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { load as yamlLoad } from "js-yaml";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(REPO_ROOT, "rules");
const BASELINE = join(REPO_ROOT, "data/case-sensitivity-baseline.json");

interface Finding {
  readonly id: string;
  readonly file: string;
  readonly condition: number;
  readonly widenedBy: string;
}

function collect(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...collect(p));
    else if (e.endsWith(".yaml") || e.endsWith(".yml")) out.push(p);
  }
  return out;
}

/** Case permutations of a probe string. Pure. */
function permute(s: string): string[] {
  return [s.toLowerCase(), s.toUpperCase(), s.replace(/\b\w/g, (c) => c.toUpperCase())];
}

/** Strip a leading (?i) so we can compile both ways. Pure. */
function bare(v: string): { source: string; declared: boolean } {
  return v.startsWith("(?i)")
    ? { source: v.slice(4), declared: true }
    : { source: v, declared: false };
}

/**
 * Benign probes only, plus their case permutations.
 *
 * Deliberately NOT the true positives. The forced 'i' flag also makes a rule catch
 * the uppercase spelling of its own attack, and that is the flag helping, not a
 * defect. The only widening worth failing a build over is the kind that pulls a
 * BENIGN string into the match set -- that is a false positive the author cannot
 * see in the pattern they wrote.
 */
function benignProbes(rule: Record<string, unknown>): string[] {
  const tc = (rule.test_cases ?? {}) as Record<string, Array<{ input?: string }>>;
  const inputs = (tc.true_negatives ?? []).map((t) => String(t.input ?? "")).filter(Boolean);
  return inputs.flatMap((i) => [i, ...permute(i)]);
}

function main(argv: readonly string[]): number {
  const write = argv.includes("--write-baseline");
  const findings: Finding[] = [];

  for (const file of collect(RULES_DIR)) {
    let rule: Record<string, unknown>;
    try {
      rule = yamlLoad(readFileSync(file, "utf-8")) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (!rule || typeof rule !== "object") continue;
    const det = (rule.detection ?? {}) as { conditions?: unknown };
    const conds = Array.isArray(det.conditions) ? det.conditions : [];
    const probes = benignProbes(rule);
    if (!probes.length) continue;

    for (const [i, cRaw] of conds.entries()) {
      const c = cRaw as { operator?: string; value?: unknown };
      if (c.operator !== "regex" || typeof c.value !== "string") continue;
      const { source, declared } = bare(c.value);
      if (declared) continue; // author asked for insensitive; engine agrees
      // Mirror the engine's own flag selection exactly (src/engine.ts:933), otherwise
      // the comparison is meaningless: without 'u', a \u{...} escape does not denote a
      // code point at all, and the two sides are not the same pattern. An earlier draft
      // of this gate got that wrong and reported a Unicode-tag rule as broadened when
      // nothing of the sort was happening.
      const needsU = source.includes("\\u{") || source.includes("\\p{");
      let sensitive: RegExp;
      let insensitive: RegExp;
      try {
        sensitive = new RegExp(source, needsU ? "u" : "");
        insensitive = new RegExp(source, needsU ? "iu" : "i");
      } catch {
        continue; // unparseable here is validate-rules.ts's problem, not ours
      }
      // A benign string that matches only under 'i' is a false positive the author
      // could not have seen by reading their own pattern.
      const extra = probes.filter((p) => insensitive.test(p) && !sensitive.test(p));
      if (extra.length) {
        findings.push({
          id: String(rule.id ?? "unknown"),
          file: relative(REPO_ROOT, file),
          condition: i,
          widenedBy: extra[0]!.slice(0, 90),
        });
      }
    }
  }

  const baseline: string[] = existsSync(BASELINE)
    ? (JSON.parse(readFileSync(BASELINE, "utf-8")).rules ?? [])
    : [];
  const known = new Set(baseline);
  const fresh = findings.filter((f) => !known.has(f.id));

  console.log("=== ATR Case Sensitivity GATE ===");
  console.log(`benign inputs pulled in by the engine's forced 'i' flag: ${findings.length}` +
    `   baseline ${baseline.length}`);

  if (write) {
    const ids = [...new Set(findings.map((f) => f.id))].sort();
    writeFileSync(BASELINE, JSON.stringify({
      $comment: "Rules whose regex means something broader than written, because " +
        "src/engine.ts compiles every pattern with the 'i' flag. Frozen debt; " +
        "the gate blocks growth, not the existing population.",
      generated: new Date().toISOString().slice(0, 10),
      rules: ids,
    }, null, 2) + "\n");
    console.log(`baseline written: ${ids.length} rule(s)`);
    return 0;
  }

  if (fresh.length) {
    console.log("\nGATE FAIL -- new rule(s) whose pattern is broader than it reads:");
    for (const f of fresh.slice(0, 20)) {
      console.log(`  - ${f.id}  condition[${f.condition}]  ${f.file}`);
      console.log(`      also matches: ${f.widenedBy}`);
    }
    if (fresh.length > 20) console.log(`  ... and ${fresh.length - 20} more`);
    console.log("\nThe engine compiles every rule regex case-insensitively " +
      "(src/engine.ts:933). If the distinction matters, express it structurally " +
      "rather than by letter case. If it does not, add (?i) so the pattern says " +
      "what it does.");
    return 1;
  }

  console.log("\nGATE PASS -- no new rule relies on a case distinction the engine discards.");
  return 0;
}

if (process.argv[1] !== undefined &&
    resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(main(process.argv.slice(2)));
}
export { bare, permute, benignProbes };
