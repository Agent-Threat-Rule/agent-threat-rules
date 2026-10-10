#!/usr/bin/env node
/**
 * Enforce-lane evidence ratchet -- CI gate over every `maturity: stable` rule.
 *
 * WHAT IT MEASURES
 *   docs/QUALITY-STANDARD.md defines STABLE as "Wild-validated, enterprise-ready
 *   / confidence >= 80, wild FP rate <= 0.5%", and STABLE is the enforce lane:
 *   auto-block, no human in the loop. That is the bar the project published for
 *   itself.
 *
 *   Measured on 2026-08-09: 106 of 106 live stable rules fail it.
 *
 *       no `confidence` field at all      87
 *       confidence < 80                    4
 *       confidence >= 80, no wild evidence 15
 *
 *   None of that means the rules are bad. All 106 measure 0 false positives on
 *   the 5,352-sample public benign corpus. What they lack is the evidence the
 *   standard asks for — and the wild corpus that evidence comes from is private
 *   and unavailable to CI, so the project structurally cannot produce it here.
 *
 * WHY THIS IS A RATCHET AND NOT A HARD GATE
 *   Failing the build on 106 of 106 would either stop all work or, far more
 *   likely, get the standard quietly edited until the numbers agree. The
 *   honest options are (a) demote all 106 and empty the enforce lane, or (b)
 *   change the standard to accept public-corpus evidence. Both are product
 *   decisions with real consequences, and neither belongs in a gate.
 *
 *   So this does the third thing: it freezes the debt at its measured size,
 *   names every rule in it, and fails the moment it grows. The gap stops being
 *   silent without anyone having to pretend it is closed.
 *
 *   Do NOT widen the baseline to silence this. A new entry means a rule entered
 *   the auto-block lane without the evidence the standard requires — which is
 *   the exact thing the standard exists to prevent.
 *
 * WHY FULL-SET AND NOT PR-DIFF SCOPED
 *   Same reasoning as gate-rule-status.ts: rules reach this repo through doors
 *   no `git diff base...HEAD` can see (untracked files gated before commit, the
 *   CVE collector committing straight to main). Comparing the working tree
 *   against a committed baseline sees all of them and needs no git history.
 *
 * WHAT FAILS THE BUILD
 *   - A stable rule fails the standard and is not in the baseline.
 *   - A rule file cannot be parsed, or carries no `maturity`. "Cannot determine
 *     the maturity" must never be reported as "not stable" — that is the class
 *     of silent pass this repo has spent a week removing.
 *
 * WHAT DOES NOT FAIL THE BUILD
 *   - A baselined rule still failing. That is the recorded debt.
 *   - A baselined rule that now passes. Reported so the baseline can shrink.
 *
 * Usage:
 *   npx tsx scripts/gate-enforce-lane-evidence.ts
 *   npx tsx scripts/gate-enforce-lane-evidence.ts --write-baseline   # may only shrink
 */
import { readFileSync, readdirSync, statSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { load as parseYaml } from "js-yaml";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(REPO_ROOT, "rules");
const BASELINE = join(REPO_ROOT, "data/enforce-lane-evidence-baseline.json");

/** docs/QUALITY-STANDARD.md, the STABLE row. Not invented here. */
export const STABLE_MIN_CONFIDENCE = 80;
export const STABLE_MAX_WILD_FP_PCT = 0.5;

export const EXIT_OK = 0;
export const EXIT_FAIL = 1;

export interface Shortfall {
  readonly id: string;
  readonly file: string;
  readonly reasons: readonly string[];
}

interface Baseline {
  readonly _comment?: string;
  readonly measured_at?: string;
  readonly rules?: Record<string, readonly string[]>;
}

function ruleFiles(dir: string): readonly string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...ruleFiles(full));
    else if (e.endsWith(".yaml") || e.endsWith(".yml")) out.push(full);
  }
  return out;
}

/**
 * Why a rule in the enforce lane does not meet the published bar.
 *
 * Returns an empty array when it does. Absent evidence counts as a shortfall,
 * never as a pass: a missing `wild_fp_rate` is "never measured", which #433
 * established after 230 rules carried a `0` that no run ever produced.
 */
export function shortfalls(rule: {
  readonly maturity?: unknown;
  readonly status?: unknown;
  readonly confidence?: unknown;
  readonly wild_fp_rate?: unknown;
  readonly wild_samples?: unknown;
}): readonly string[] {
  const reasons: string[] = [];
  const confidence = rule.confidence;
  if (typeof confidence !== "number") {
    reasons.push("no confidence field");
  } else if (confidence < STABLE_MIN_CONFIDENCE) {
    reasons.push(`confidence ${confidence} < ${STABLE_MIN_CONFIDENCE}`);
  }
  const wildFp = rule.wild_fp_rate;
  if (typeof wildFp !== "number") {
    reasons.push("no wild_fp_rate (never measured)");
  } else if (wildFp > STABLE_MAX_WILD_FP_PCT) {
    reasons.push(`wild_fp_rate ${wildFp} > ${STABLE_MAX_WILD_FP_PCT}`);
  }
  return Object.freeze(reasons);
}

function scan(): { readonly shortfalls: readonly Shortfall[]; readonly stableCount: number } {
  const out: Shortfall[] = [];
  let stableCount = 0;
  for (const file of ruleFiles(RULES_DIR)) {
    let doc: unknown;
    try {
      doc = parseYaml(readFileSync(file, "utf-8"));
    } catch (e) {
      // Unparseable is a shortfall, not a skip. Cannot-determine must never
      // read as does-not-apply.
      out.push({
        id: relative(RULES_DIR, file),
        file: relative(REPO_ROOT, file),
        reasons: [`unparseable: ${String(e).slice(0, 80)}`],
      });
      continue;
    }
    const r = doc as Record<string, unknown>;
    if (typeof r?.id !== "string") continue;
    const maturity = r.maturity;
    if (typeof maturity !== "string") {
      out.push({
        id: r.id,
        file: relative(REPO_ROOT, file),
        reasons: ["no maturity field — cannot tell which lane this runs in"],
      });
      continue;
    }
    if (maturity !== "stable") continue;
    const status = String(r.status ?? "");
    if (status === "draft" || status === "deprecated") continue; // inert, no lane
    stableCount++;
    const reasons = shortfalls(r as never);
    if (reasons.length > 0) {
      out.push({ id: r.id, file: relative(REPO_ROOT, file), reasons });
    }
  }
  return {
    shortfalls: Object.freeze(out.sort((a, b) => a.id.localeCompare(b.id))),
    stableCount,
  };
}

function readBaseline(): Baseline {
  if (!existsSync(BASELINE)) return {};
  try {
    return JSON.parse(readFileSync(BASELINE, "utf-8")) as Baseline;
  } catch {
    return {};
  }
}

function main(argv: readonly string[]): number {
  const { shortfalls: found, stableCount } = scan();
  const baseline = readBaseline();
  const known = new Set(Object.keys(baseline.rules ?? {}));

  if (argv.includes("--write-baseline")) {
    const current = new Set(found.map((s) => s.id));
    const grown = [...current].filter((id) => !known.has(id));
    if (known.size > 0 && grown.length > 0) {
      console.error(
        `[enforce-evidence] REFUSING to write — the baseline may only shrink.\n` +
          `${grown.length} rule(s) would be newly recorded as lacking the evidence\n` +
          `docs/QUALITY-STANDARD.md requires for the auto-block lane:\n` +
          grown.map((id) => `  + ${id}`).join("\n"),
      );
      return EXIT_FAIL;
    }
    writeFileSync(
      BASELINE,
      JSON.stringify(
        {
          _comment:
            "Rules in the enforce (auto-block) lane that do not meet the STABLE bar " +
            "published in docs/QUALITY-STANDARD.md (confidence >= 80, wild FP rate <= 0.5%). " +
            "This file records existing debt so it stops being silent. Do NOT add entries " +
            "to silence the gate — a new entry means a rule reached the auto-block lane " +
            "without the evidence the standard requires. Entries may only be removed, by " +
            "producing the evidence or by demoting the rule.",
          measured_at: new Date().toISOString().slice(0, 10),
          stable_rules_total: stableCount,
          rules: Object.fromEntries(found.map((s) => [s.id, s.reasons])),
        },
        null,
        2,
      ) + "\n",
    );
    console.log(
      `[enforce-evidence] baseline written: ${found.length} of ${stableCount} stable rule(s)`,
    );
    return EXIT_OK;
  }

  const novel = found.filter((s) => !known.has(s.id));
  const fixed = [...known].filter((id) => !found.some((s) => s.id === id));

  console.log(
    `[enforce-evidence] ${stableCount} rule(s) in the enforce lane; ` +
      `${found.length} do not meet docs/QUALITY-STANDARD.md (baseline ${known.size})`,
  );
  if (fixed.length > 0) {
    console.log(
      `\nRATCHET — these now meet the bar and should be removed from the baseline:`,
    );
    for (const id of fixed.sort()) console.log(`  + ${id}`);
    console.log(`  (run --write-baseline to tighten)`);
  }
  if (novel.length === 0) {
    console.log(
      `\nGATE PASS -- no rule newly entered the auto-block lane without evidence.`,
    );
    return EXIT_OK;
  }
  console.error(
    `\n[enforce-evidence] FAIL — ${novel.length} rule(s) are in the enforce lane ` +
      `(maturity: stable = auto-block, no human in the loop) without the evidence\n` +
      `docs/QUALITY-STANDARD.md requires. Absent evidence is not clean evidence:`,
  );
  for (const s of novel) {
    console.error(`  ${s.id}  ${s.file}`);
    for (const r of s.reasons) console.error(`      ${r}`);
  }
  console.error(
    `\nEither produce the evidence, or set maturity to test/experimental until it exists.\n` +
      `Do NOT widen the baseline to silence this.`,
  );
  return EXIT_FAIL;
}

const INVOKED_DIRECTLY =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (INVOKED_DIRECTLY) process.exitCode = main(process.argv.slice(2));
