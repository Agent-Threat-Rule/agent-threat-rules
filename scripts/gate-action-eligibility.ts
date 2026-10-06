#!/usr/bin/env node
/**
 * gate-action-eligibility.ts — a rule may not declare a response action more
 * destructive than its measured false-positive evidence has earned.
 *
 * WHY THIS GATE EXISTS
 *
 * `src/action-executor.ts` filters on nothing. It has no notion of lane and no
 * notion of maturity — grep it, the words do not appear. The lane gate decides
 * whether a rule may FIRE; after that, `computeVerdict()` unions
 * `response.actions` over every match and the executor dispatches all of them.
 * A `maturity: test` rule in the lane literally named "alert" therefore executes
 * `kill_agent` exactly as readily as a stable rule in the enforce lane. That was
 * reproduced end to end against the real benign corpus, not inferred from the
 * source: see docs/RESPONSE-ACTION-ELIGIBILITY.md.
 *
 * So the eligibility check cannot live at runtime behind a lane — there is no
 * lane filter to hang it on, and adding one would change what the engine blocks.
 * It lives here, in the shape of the maturity-FP, RE2 and rule-status gates: the
 * rule file is the artifact, and the gate refuses to let the artifact claim an
 * authority it has not measured.
 *
 * WHAT IT DELIBERATELY DOES NOT DO
 *
 * It never looks at `detection`. Downgrading an action costs zero recall by
 * construction: the rule still fires, still matches, still reports. Any gate
 * that touched the detection side would be trading recall for precision, which
 * is the one trade this line exists to avoid.
 *
 * EVIDENCE SOURCE
 *
 * `data/benign-fp-measurement.json`, produced by
 * `gate-promotion-fp.ts --emit-measurement`. A rule absent from that file has no
 * measurement; a rule whose `detection_fingerprint` no longer matches the file
 * on disk has a measurement of a detection that no longer exists. Both are
 * UNMEASURED, and unmeasured caps a rule at the observe tier — the gate refuses
 * rather than passes, because that is the failure mode that has already cost
 * this project twice (`?? 0` writing "never measured" as "measured clean", and a
 * green CI run surviving a corpus change).
 *
 * SCOPE
 *
 * Rules the engine cannot load at all (`status: draft` / `deprecated`,
 * `maturity: deprecated`) are skipped: they fire in no lane, so their declared
 * actions are inert. They are gated the moment they are revived, because a
 * revived rule must be re-measured anyway.
 *
 * Exit codes:
 *   0  every live rule's actions are within its earned tier
 *   1  at least one rule declares an unearned action
 *   2  the measurement file is missing or unreadable — no verdict is possible,
 *      and a gate that cannot read its evidence must not report success
 */
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { load as parseYaml } from "js-yaml";
import {
  actionTier,
  detectionFingerprint,
  ineligibleActions,
  maxTierFor,
  TIER_NAMES,
  type ActionTier,
  type EligibilityDecision,
  corpusDigest,
} from "../src/quality/action-eligibility.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const DEFAULT_MEASUREMENT = join(REPO_ROOT, "data/benign-fp-measurement.json");

export const EXIT_OK = 0;
export const EXIT_FAIL = 1;
export const EXIT_NO_EVIDENCE = 2;

interface MeasurementRecord {
  readonly fp_count?: number;
  readonly maturity?: string | null;
  readonly detection_fingerprint?: string | null;
  readonly partial_measurement?: boolean;
  readonly skill_path_unmeasured?: boolean;
}

interface MeasurementFile {
  readonly sample_count?: number;
  readonly corpora?: readonly string[];
  readonly corpus_digest?: string;
  readonly rules?: Record<string, MeasurementRecord>;
}

interface RuleOnDisk {
  readonly file: string;
  readonly id: string;
  readonly messageTemplate: string;
  readonly maturity: string | null;
  readonly status: string | null;
  readonly actions: readonly string[];
  readonly fingerprint: string;
}

export interface Violation {
  readonly id: string;
  readonly file: string;
  readonly unearned: readonly string[];
  readonly maxTier: ActionTier;
  readonly decision: EligibilityDecision;
}

/** Every rule file under a directory, including subdirectories. */
function ruleFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...ruleFiles(full));
    else if (e.endsWith(".yaml") || e.endsWith(".yml")) out.push(full);
  }
  return out;
}

/** A rule the engine skips before any lane gate: its actions cannot be dispatched. */
export function isInert(
  status: string | null,
  maturity: string | null,
): boolean {
  const s = String(status ?? "").trim();
  const m = String(maturity ?? "").trim();
  return s === "draft" || s === "deprecated" || m === "deprecated";
}

function readRules(rulesDir: string): readonly RuleOnDisk[] {
  const out: RuleOnDisk[] = [];
  for (const file of ruleFiles(rulesDir)) {
    let doc: unknown;
    try {
      doc = parseYaml(readFileSync(file, "utf-8"));
    } catch {
      continue; // schema validation is validate-rules' job, not this gate's
    }
    const r = doc as {
      id?: string;
      status?: string;
      maturity?: string;
      response?: { actions?: unknown; message_template?: unknown };
    };
    if (typeof r?.id !== "string") continue;
    const actions = Array.isArray(r.response?.actions)
      ? (r.response.actions as unknown[]).filter(
          (a): a is string => typeof a === "string",
        )
      : [];
    out.push({
      file: relative(REPO_ROOT, file),
      id: r.id,
      maturity: r.maturity ?? null,
      status: r.status ?? null,
      actions,
      messageTemplate:
        typeof r.response?.message_template === "string"
          ? r.response.message_template
          : "",
      fingerprint: detectionFingerprint(doc as never),
    });
  }
  return out;
}

/**
 * Pure core: rules on disk + the measurement file -> the rules that overreach.
 *
 * Exported so the ratchet test can drive it with fixtures instead of the repo.
 */

/**
 * SHA-256 over the benign corpora this measurement claims to describe.
 *
 * `detection_fingerprint` stops a rule drifting out from under its number. It
 * does nothing about the number itself, and the measurement file is committed
 * to the repo — so an integer edit plus one `maturity` line was enough, in
 * review, to hand a rule that false-positives on 52.58% of the corpus a
 * `kill_agent`, with every test still green. A comment reading "do not
 * hand-edit" is a convention, not a control.
 *
 * This is the missing half: the evidence has to be checkable against the thing
 * it was measured on. A digest mismatch is treated exactly like a missing file
 * (EXIT_NO_EVIDENCE), because "the evidence does not describe this corpus" and
 * "there is no evidence" are the same state for a gate whose whole premise is
 * that a declaration is not proof.
 *
 * It does not stop someone regenerating both together — nothing file-local can.
 * It stops the cheap edit, and it makes the expensive one leave a diff that
 * says what it did.
 */


/**
 * A rule may not tell the operator it was not blocked.
 *
 * This policy governs the actions the executor dispatches. It has no effect on
 * `src/verdict.ts`, which derives `permissionDecision` from severity and
 * confidence alone and never reads `response.actions` — so stripping every
 * action off a `severity: critical` rule still leaves the Claude Code hook
 * returning `deny`. Measured during review: of 59 downgraded rules replayed
 * through the real hook path on their own true positives, 41 denied, 6 asked,
 * 0 allowed, and PostToolUse blocks on both deny and ask.
 *
 * The policy document said this. Seven rule files shipped prose saying the
 * opposite, because a human wrote "Advisory only — the tool call was NOT
 * blocked" while looking at a diff that only removed actions. An operator
 * debugging a false positive would read that and conclude the call went
 * through. It did not.
 *
 * Statements about what this rule stopped dispatching are fine. Statements
 * about whether the operation was blocked are not this file's to make.
 */
const BLOCK_CLAIM = /\b(?:was|were|is|are)\s+NOT\s+blocked\b|\bAdvisory only\b/i;

export function messageTemplateClaims(
  rules: readonly RuleOnDisk[],
): readonly { readonly id: string; readonly file: string; readonly quote: string }[] {
  const out: { id: string; file: string; quote: string }[] = [];
  for (const rule of rules) {
    const m = BLOCK_CLAIM.exec(rule.messageTemplate);
    if (m === null) continue;
    const at = Math.max(0, m.index - 40);
    out.push({
      id: rule.id,
      file: rule.file,
      quote: rule.messageTemplate.slice(at, m.index + m[0].length + 40).replace(/\s+/g, " ").trim(),
    });
  }
  return Object.freeze(out.sort((a, b) => a.id.localeCompare(b.id)));
}

export function findViolations(
  rules: readonly RuleOnDisk[],
  measurement: MeasurementFile,
): readonly Violation[] {
  const sampleCount = measurement.sample_count;
  const records = measurement.rules ?? {};
  const out: Violation[] = [];
  for (const rule of rules) {
    if (isInert(rule.status, rule.maturity)) continue;
    const rec = records[rule.id];
    const fingerprintMatches =
      rec !== undefined && rec.detection_fingerprint === rule.fingerprint;
    const decision = maxTierFor(
      fingerprintMatches
        ? {
            fpCount: rec.fp_count,
            sampleCount,
            partial: rec.partial_measurement === true,
            maturity: rule.maturity ?? undefined,
          }
        : { maturity: rule.maturity ?? undefined },
    );
    const unearned = ineligibleActions(rule.actions, decision.maxTier);
    if (unearned.length === 0) continue;
    out.push({
      id: rule.id,
      file: rule.file,
      unearned,
      maxTier: decision.maxTier,
      decision:
        rec !== undefined && !fingerprintMatches
          ? Object.freeze({
              ...decision,
              reason:
                "detection changed since the last benign-corpus measurement " +
                `(recorded ${String(rec.detection_fingerprint)}, on disk ${rule.fingerprint})`,
            })
          : decision,
    });
  }
  return Object.freeze(out.sort((a, b) => a.id.localeCompare(b.id)));
}

function main(argv: readonly string[]): number {
  const asJson = argv.includes("--json");
  const i = argv.indexOf("--measurement");
  const measurementPath =
    i >= 0 ? (argv[i + 1] ?? DEFAULT_MEASUREMENT) : DEFAULT_MEASUREMENT;

  if (!existsSync(measurementPath)) {
    console.error(
      `[action-gate] FAIL — no measurement file at ${measurementPath}.\n` +
        `Produce one with:\n` +
        `  npx tsx scripts/gate-promotion-fp.ts --ids <live-ids> --filter-mode \\\n` +
        `      --emit-dirty /tmp/dirty.txt --emit-measurement data/benign-fp-measurement.json\n` +
        `A gate with no evidence cannot report success.`,
    );
    return EXIT_NO_EVIDENCE;
  }

  let measurement: MeasurementFile;
  try {
    measurement = JSON.parse(
      readFileSync(measurementPath, "utf-8"),
    ) as MeasurementFile;
  } catch (e) {
    console.error(
      `[action-gate] FAIL — unreadable measurement file: ${String(e)}`,
    );
    return EXIT_NO_EVIDENCE;
  }

  // The evidence has to describe the corpus it claims to. A stale or edited
  // measurement is the same state as no measurement: EXIT_NO_EVIDENCE.
  if (measurement.corpus_digest !== undefined && measurement.corpora !== undefined) {
    const actual = corpusDigest(REPO_ROOT, measurement.corpora, { existsSync, readdirSync, statSync, readFileSync }, { join, relative }, createHash);
    if (actual !== measurement.corpus_digest) {
      console.error(
        `[action-gate] FAIL — the measurement was taken on a different corpus.\n` +
          `  recorded ${measurement.corpus_digest}\n` +
          `  on disk  ${actual}\n` +
          `Re-measure; do not hand-edit the numbers.`,
      );
      return EXIT_NO_EVIDENCE;
    }
  } else {
    console.error(
      `[action-gate] FAIL — measurement file carries no corpus_digest. ` +
        `Unverifiable evidence is not evidence; re-emit it with a current ` +
        `scripts/gate-promotion-fp.ts --emit-measurement.`,
    );
    return EXIT_NO_EVIDENCE;
  }

  const rules = readRules(join(REPO_ROOT, "rules"));

  // A rule may not tell the operator it was not blocked — this policy does not
  // govern the hook's verdict, so it has no standing to make that claim.
  const claims = messageTemplateClaims(rules);
  if (claims.length > 0) {
    console.error(
      `\n[action-gate] FAIL — ${claims.length} rule(s) claim in message_template that ` +
        `the operation was not blocked. response.actions does not drive the hook's ` +
        `permissionDecision (src/verdict.ts reads severity + confidence only), so a rule ` +
        `cannot make that promise. Say what stopped dispatching, not what got through:`,
    );
    for (const c of claims) console.error(`  ${c.id}  ${c.file}\n      "…${c.quote}…"`);
    return EXIT_FAIL;
  }

  const violations = findViolations(rules, measurement);

  if (asJson) {
    console.log(JSON.stringify({ checked: rules.length, violations }, null, 2));
    return violations.length === 0 ? EXIT_OK : EXIT_FAIL;
  }

  console.log(
    `[action-gate] ${rules.length} rule file(s); evidence from ${measurementPath} ` +
      `(${String(measurement.sample_count)} benign samples)`,
  );
  if (violations.length === 0) {
    console.log(
      "[action-gate] PASS — every live rule's response actions are within the tier its " +
        "measured false-positive evidence earns.",
    );
    return EXIT_OK;
  }
  console.error(
    `\n[action-gate] FAIL — ${violations.length} rule(s) declare a response action more ` +
      `destructive than their evidence earns (docs/RESPONSE-ACTION-ELIGIBILITY.md):`,
  );
  for (const v of violations) {
    const tiers = v.unearned
      .map((a) => `${a}[${TIER_NAMES[actionTier(a)]}]`)
      .join(", ");
    console.error(
      `  ${v.id}  ceiling=${TIER_NAMES[v.maxTier]}  unearned=${tiers}`,
    );
    console.error(`      ${v.decision.reason}`);
    console.error(`      ${v.file}`);
  }
  console.error(
    "\nFix by removing the unearned actions (zero recall cost — the rule still fires " +
      "and still reports), or by re-measuring the rule and committing the new " +
      "data/benign-fp-measurement.json.",
  );
  return EXIT_FAIL;
}

const INVOKED_DIRECTLY =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) {
  process.exit(main(process.argv.slice(2)));
}
