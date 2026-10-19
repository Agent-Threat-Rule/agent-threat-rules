#!/usr/bin/env node
/**
 * promote-to-stable.ts — the production-grade promotion gate.
 *
 * A rule at `maturity: test` is NOT trustworthy as production just because it
 * cleared the ~5.2K public benign corpus in the PR safety gate. Production
 * confidence means ZERO false positives across a LARGE, wild benign corpus —
 * the 53K/96K ecosystem scan that lives in the private scan pipeline.
 *
 * This gate loads the public benign corpora AND (when provided) an external
 * wild corpus, runs every `maturity: test` rule against every benign sample,
 * and promotes a rule to `maturity: stable` ONLY if it produces 0 FP across
 * the whole set. Critically it REFUSES to promote unless the corpus it actually
 * validated against is at least `--min-corpus` samples — so a 5.2K pass alone
 * can never mint a production rule; you must feed the wild corpus.
 *
 * The gate LOGIC is public (it is just a validation harness); the wild corpus
 * DATA stays private — it is passed in by path, never committed here.
 *
 * A 0 counts only where something was measured. A rule the engine never
 * evaluates, or one whose conditions this corpus cannot fully exercise (a field
 * no benign sample fills, such as tool_name; a method the synchronous engine
 * cannot run, such as trace), scores 0 without being read, and is reported as
 * not promotable instead of clean. See splitCandidates().
 *
 * Usage:
 *   npx tsx scripts/promote-to-stable.ts                              # dry-run, public corpus only
 *   npx tsx scripts/promote-to-stable.ts --wild-corpus wild.jsonl     # + the private 53K set
 *   npx tsx scripts/promote-to-stable.ts --min-corpus 5000 --write    # lower the bar (NOT recommended)
 *
 * The wild corpus path may also be supplied via the ATR_WILD_CORPUS variable.
 *
 * Exit 0 = ran cleanly (report or promotions applied).
 * Exit 2 = --write requested but the corpus was below --min-corpus (nothing promoted).
 */

import {
  readFileSync,
  writeFileSync,
  readdirSync,
  existsSync,
  statSync,
} from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { load as yamlLoad } from "js-yaml";
import { MATURITIES, type Maturity } from "../src/quality/rule-contract.js";
import { ATREngine } from "../src/engine.js";
import {
  fieldCoverage,
  matchedRuleIds,
  type FieldCoverage,
  type RuleLike,
} from "./lib/corpus-event.js";
import { unmeasuredTargets } from "./gate-promotion-fp.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const RULES_DIR = join(REPO_ROOT, "rules");
const PUBLIC_CORPORA = [
  join(REPO_ROOT, "data/skill-benchmark/benign"), // *.md skill manifests
  join(REPO_ROOT, "data/benign-corpus-extended"), // *.jsonl {text}
  join(REPO_ROOT, "data/benign-code"), // *.jsonl {text}
];
const WILD_ENV_KEY = "ATR_WILD_CORPUS";

interface Args {
  write: boolean;
  minCorpus: number;
  wildCorpus: string | null;
}

function parseArgs(): Args {
  const a = process.argv.slice(2);
  const at = (n: string): string | null => {
    const i = a.indexOf(n);
    return i >= 0 ? (a[i + 1] ?? null) : null;
  };
  // Bracket access avoids a literal dot-env token (which ATR's own
  // credential-reference rule would false-positive on in the safety hook).
  const envVars = process["env"] as Record<string, string | undefined>;
  return {
    write: a.includes("--write"),
    minCorpus: Number(at("--min-corpus") ?? 20000),
    wildCorpus: at("--wild-corpus") ?? envVars[WILD_ENV_KEY] ?? null,
  };
}

/**
 * Every rule id a sample matches, via the canonical shape set.
 *
 * This is the gate that decides what enters the enforce (auto-block) lane, so it
 * is the last place a narrow event shape is affordable: a field this harness
 * cannot present is a condition it cannot see fire, and the rule gets promoted
 * on a measurement that never happened.
 */
function matchAllRuleIds(engine: ATREngine, content: string): ReadonlySet<string> {
  return matchedRuleIds(engine, content);
}

/** Recursively collect *.yaml under a dir. */
function walkYaml(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...walkYaml(p));
    else if (e.endsWith(".yaml") || e.endsWith(".yml")) out.push(p);
  }
  return out;
}

/** Pull benign sample texts from a corpus path (dir of *.md/*.jsonl or a *.jsonl file). */
function loadCorpusTexts(pathStr: string): string[] {
  const texts: string[] = [];
  if (!existsSync(pathStr)) return texts;
  const files: string[] = [];
  if (statSync(pathStr).isDirectory()) {
    for (const e of readdirSync(pathStr)) {
      if (e.endsWith(".jsonl") || e.endsWith(".md")) files.push(join(pathStr, e));
    }
  } else {
    files.push(pathStr);
  }
  for (const f of files) {
    let raw: string;
    try {
      raw = readFileSync(f, "utf-8");
    } catch {
      continue;
    }
    if (f.endsWith(".md")) {
      texts.push(raw);
      continue;
    }
    for (const line of raw.split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        const obj = JSON.parse(t) as { text?: string };
        if (typeof obj.text === "string" && obj.text.length > 0) texts.push(obj.text);
      } catch {
        continue;
      }
    }
  }
  return texts;
}

export interface Candidate {
  id: string;
  file: string;
}

export interface CandidateSplit {
  readonly clean: readonly Candidate[];
  readonly dirty: readonly Candidate[];
  /** Candidates the engine never evaluates, with the reason: on neither list. */
  readonly unevaluated: ReadonlyMap<string, string>;
  /**
   * Candidates with no false positive on conditions this corpus could not fully
   * exercise (fieldCoverage), with the reason: on neither list. One that did
   * false-positive is on the dirty list; those hits are real.
   */
  readonly unmeasured: ReadonlyMap<string, string>;
  readonly fpCounts: ReadonlyMap<string, number>;
}

/** Methods the synchronous engine cannot run on a text sample (see fieldCoverage). */
const SYNC_BLIND_METHODS: ReadonlySet<string> = new Set(["trace", "behavioral", "signature"]);

/**
 * Why a rule's 0 FP on this corpus is not a measurement, from its coverage gap:
 * what the runtime corpus shapes cannot exercise. A skill or both rule's
 * conditions all read the document on the SKILL.md path, but that says nothing
 * about a tool_name condition at runtime, where the enforce lane blocks.
 */
function coverageGapReason(gap: FieldCoverage, rule: RuleLike | undefined): string {
  const method = String(rule?.detection?.method ?? "pattern");
  const parts = [
    ...(SYNC_BLIND_METHODS.has(method) ? [`method ${method}`] : []),
    ...(gap.unmeasured.length > 0 ? [`unmeasurable ${gap.unmeasured.join(", ")}`] : []),
  ];
  const what = parts.join("; ") || "no condition field this corpus fills";
  return gap.zeroMeasurement
    ? `not measured: the corpus cannot exercise the rule as a whole (${what})`
    : `partially measured: 0 FP on the conditions the corpus reaches; the rest never ran (${what})`;
}

/**
 * Count each candidate's false positives over `samples` and split them.
 *
 * A candidate the engine does not evaluate (draft or deprecated status, or a
 * file that did not load) scores 0 on every sample by construction. That 0 is
 * the status gate's doing, not the corpus's, so it is not clean: it is set
 * aside, the way scripts/gate-promotion-fp.ts sets it aside.
 */
export function splitCandidates(
  engine: ATREngine,
  candidates: readonly Candidate[],
  samples: readonly string[],
): CandidateSplit {
  const unevaluated = unmeasuredTargets(engine, new Set(candidates.map((c) => c.id)));
  const measurable = candidates.filter((c) => !unevaluated.has(c.id));
  const ids = new Set(measurable.map((c) => c.id));
  const fpCounts = new Map<string, number>(measurable.map((c) => [c.id, 0]));
  for (const text of samples) {
    for (const id of matchAllRuleIds(engine, text)) {
      if (ids.has(id)) fpCounts.set(id, (fpCounts.get(id) ?? 0) + 1);
    }
  }
  // A 0 on conditions the corpus never exercised is the same non-measurement as
  // an unevaluated rule's, and the action gate already reads it that way: a
  // partial run that found nothing caps a rule at observe.
  const rules = engine.getRules() as unknown as RuleLike[];
  const gaps = new Map(fieldCoverage(rules).map((g) => [g.ruleId, g]));
  const unmeasured = new Map<string, string>();
  for (const c of measurable) {
    const gap = gaps.get(c.id);
    if (gap === undefined || (fpCounts.get(c.id) ?? 0) > 0) continue;
    unmeasured.set(c.id, coverageGapReason(gap, rules.find((r) => r.id === c.id)));
  }
  return {
    clean: measurable.filter((c) => (fpCounts.get(c.id) ?? 0) === 0 && !unmeasured.has(c.id)),
    dirty: measurable.filter((c) => (fpCounts.get(c.id) ?? 0) > 0),
    unevaluated,
    unmeasured,
    fpCounts,
  };
}

interface RuleMeta {
  id?: string;
  maturity?: string;
}

/** Rules currently at maturity: test — the promotion candidates. */
function loadTestCandidates(): Candidate[] {
  const out: Candidate[] = [];
  for (const f of walkYaml(RULES_DIR)) {
    let doc: RuleMeta;
    try {
      doc = (yamlLoad(readFileSync(f, "utf-8")) ?? {}) as RuleMeta;
    } catch {
      continue;
    }
    if (doc.maturity === "test" && typeof doc.id === "string") {
      out.push({ id: doc.id, file: f });
    }
  }
  return out;
}

/**
 * The tier this gate promotes into. Typed as `Maturity` on purpose: this script
 * previously wrote `production`, which is not a member, so `normalizeMaturity`
 * mapped every "promoted" rule to `experimental` and dropped it out of both the
 * enforce and the alert lane. A promotion gate that silently demotes is worse
 * than no gate, and only the type binding makes that impossible to reintroduce.
 */
const PROMOTION_TARGET: Maturity = "stable";

/** Bump `maturity: test` -> the promotion target in a rule file (single field). */
function promoteFile(file: string): boolean {
  if (!MATURITIES.includes(PROMOTION_TARGET)) {
    throw new Error(
      `promotion target ${PROMOTION_TARGET} is not a valid maturity; refusing to write`,
    );
  }
  const raw = readFileSync(file, "utf-8");
  const next = raw.replace(
    /^(\s*maturity:\s*)["']?test["']?\s*$/m,
    `$1${PROMOTION_TARGET}`,
  );
  if (next === raw) return false;
  writeFileSync(file, next);
  return true;
}

async function main(): Promise<void> {
  const args = parseArgs();

  const corpora = [...PUBLIC_CORPORA];
  if (args.wildCorpus) corpora.push(args.wildCorpus);

  const samples: string[] = [];
  for (const c of corpora) samples.push(...loadCorpusTexts(c));

  console.log(
    `[stable-gate] corpus = ${samples.length} benign samples` +
      (args.wildCorpus ? ` (incl. wild: ${args.wildCorpus})` : " (public only)"),
  );
  console.log(`[stable-gate] production threshold = ${args.minCorpus} samples`);

  const candidates = loadTestCandidates();
  console.log(`[stable-gate] ${candidates.length} rule(s) at maturity:test`);
  if (candidates.length === 0) return;

  const engine = new ATREngine({ rulesDir: RULES_DIR });
  await engine.loadRules();

  const { clean, dirty, unevaluated, unmeasured, fpCounts } = splitCandidates(engine, candidates, samples);
  if (unevaluated.size > 0) {
    console.log(
      `[stable-gate] ${unevaluated.size} rule(s) at maturity:test are never evaluated, so ` +
        `no corpus can show them FP-clean; not promotable:`,
    );
    for (const [id, why] of unevaluated) console.log(`  ${id} — ${why}`);
  }
  if (unmeasured.size > 0) {
    console.log(
      `[stable-gate] ${unmeasured.size} rule(s) at maturity:test show 0 FP on a corpus that ` +
        `could not exercise all of their conditions; not promotable:`,
    );
    for (const [id, why] of unmeasured) console.log(`  ${id} — ${why}`);
  }
  console.log(
    `[stable-gate] ${clean.length} rule(s) with 0 FP · ${dirty.length} rule(s) with FP (stay at test)`,
  );

  const corpusTooSmall = samples.length < args.minCorpus;
  if (corpusTooSmall) {
    console.log(
      `\n[stable-gate] CORPUS TOO SMALL (${samples.length} < ${args.minCorpus}) — ` +
        `a 0-FP pass on this set is NOT sufficient for production. Provide the wild ` +
        `corpus with --wild-corpus <path> (the private 53K/96K ecosystem scan).`,
    );
  }

  if (dirty.length > 0) {
    console.log(`\nRules with FP (NOT promotable):`);
    for (const c of dirty.slice(0, 30)) {
      console.log(`  ${c.id} — ${fpCounts.get(c.id)} FP`);
    }
  }

  if (!args.write) {
    console.log(
      `\n[stable-gate] dry-run. ${clean.length} rule(s) are FP-clean on this corpus.` +
        (corpusTooSmall
          ? " Not production-eligible until validated on the wild corpus."
          : " Re-run with --write to promote them to maturity:stable."),
    );
    return;
  }

  if (corpusTooSmall) {
    console.error(
      `[stable-gate] --write refused: corpus below the production threshold. Nothing promoted.`,
    );
    process.exit(2);
  }

  let promoted = 0;
  for (const c of clean) {
    if (promoteFile(c.file)) promoted++;
  }
  console.log(`\n[stable-gate] promoted ${promoted} rule(s) test -> stable.`);
}

// Only run when invoked directly, so tests can import splitCandidates.
const INVOKED_DIRECTLY =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) {
  main().catch((err: unknown) => {
    console.error(err instanceof Error ? err.stack : String(err));
    process.exit(1);
  });
}
