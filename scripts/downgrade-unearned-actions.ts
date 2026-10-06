#!/usr/bin/env node
/**
 * downgrade-unearned-actions.ts — one-time repair: strip every response action a
 * rule's measured false-positive evidence does not earn, and record why in the
 * rule file.
 *
 * This is the apply half of scripts/gate-action-eligibility.ts. The gate says a
 * rule overreaches; this writes the correction. Same shape as
 * scripts/strip-unmeasured-wild-fp.ts: dry-run by default, `--apply` to write.
 *
 * WHAT IT TOUCHES AND WHAT IT REFUSES TO TOUCH
 *
 * `response.actions` only, plus a `response.actions_rationale` explaining the
 * edit. It never reads or writes `detection`, `test_cases`, `severity` or
 * `maturity`. That restraint is the entire value of this line: removing an
 * unearned action costs zero recall, and the moment a script here could touch a
 * pattern the change would need a recall A/B and would stop being free.
 *
 * `message_template` is deliberately NOT rewritten automatically — a template is
 * prose, and a regex that edits prose produces confident nonsense. Rules whose
 * template still promises an action that was just removed are REPORTED under
 * "TEMPLATE NOW LIES" for a human to rewrite. That promise is a real defect: one
 * rule told operators "The tool call has been blocked" in a lane where it never
 * blocked anything.
 *
 * Usage:
 *   npx tsx scripts/downgrade-unearned-actions.ts             # dry run
 *   npx tsx scripts/downgrade-unearned-actions.ts --apply     # write
 */
import {
  readFileSync,
  writeFileSync,
  readdirSync,
  statSync,
  existsSync,
} from "node:fs";
import { join, resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { load as parseYaml } from "js-yaml";
import {
  actionTier,
  detectionFingerprint,
  eligibleActions,
  ineligibleActions,
  maxTierFor,
  TIER_NAMES,
} from "../src/quality/action-eligibility.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MEASUREMENT = join(REPO_ROOT, "data/benign-fp-measurement.json");
const RULES_DIR = join(REPO_ROOT, "rules");
const doApply = process.argv.includes("--apply");

/** Phrases a template uses to promise an action the rule may no longer take. */
const BLOCK_PROMISE =
  /\b(has been blocked|was blocked|is blocked|blocked\b|quarantin|terminat|kill(ed)? the agent|session (has been )?(ended|killed)|halted)/i;

interface Rec {
  fp_count?: number;
  maturity?: string | null;
  detection_fingerprint?: string | null;
  partial_measurement?: boolean;
}

function ruleFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...ruleFiles(full));
    else if (e.endsWith(".yaml") || e.endsWith(".yml")) out.push(full);
  }
  return out;
}

/** Wrap prose to `width` columns and indent every line. */
function foldScalar(text: string, indent: string, width = 96): string[] {
  const words = text.split(/\s+/).filter(Boolean);
  const out: string[] = [];
  let line = "";
  for (const w of words) {
    if (line !== "" && (indent + line + " " + w).length > width) {
      out.push(indent + line);
      line = w;
    } else {
      line = line === "" ? w : `${line} ${w}`;
    }
  }
  if (line !== "") out.push(indent + line);
  return out;
}

/**
 * Rewrite the `actions:` sequence inside the top-level `response:` block and
 * record the reason as `response.actions_rationale`.
 *
 * Line-based on purpose. Round-tripping the whole document through a YAML
 * emitter would reflow 780 files — folded descriptions, quoting style, comment
 * placement — and bury a two-line semantic change inside an unreviewable diff.
 * Returns null when the block does not have the expected shape, so an unusual
 * file is skipped and reported rather than mangled.
 *
 * The rationale is a FIELD, not a `#` comment, and that is not a style choice:
 * `scripts/quality-upgrade.ts` rewrites rule files with `yaml.dump(parsed)`,
 * which drops every comment in the document. A comment explaining why an action
 * was removed would survive until the next quality-upgrade cron and then vanish,
 * leaving an unexplained edit — exactly the state this line exists to end.
 */
export function rewriteActions(
  text: string,
  keep: readonly string[],
  rationale: string,
): string | null {
  const lines = text.split("\n");
  const responseAt = lines.findIndex((l) => /^response:\s*$/.test(l));
  if (responseAt < 0) return null;

  // Two layouts are in use on disk: a block sequence under `actions:` and a
  // one-line flow sequence `actions: [alert, block_tool]`. Both are rewritten in
  // their own style, because normalising one into the other would put an
  // unrelated formatting change in the same diff as a semantic one.
  let actionsAt = -1;
  let inlineAt = -1;
  for (let i = responseAt + 1; i < lines.length; i++) {
    const l = lines[i]!;
    if (/^\S/.test(l) && l.trim() !== "") break; // left the response block
    if (/^\s{2}actions:\s*$/.test(l)) {
      actionsAt = i;
      break;
    }
    if (/^\s{2}actions:\s*\[[^\]]*\]\s*$/.test(l)) {
      inlineAt = i;
      break;
    }
  }

  if (inlineAt >= 0) {
    let after = inlineAt + 1;
    if (/^ {2}actions_rationale:/.test(lines[after] ?? "")) {
      after++;
      while (after < lines.length && /^ {4}\S/.test(lines[after] ?? ""))
        after++;
    }
    return [
      ...lines.slice(0, inlineAt),
      `  actions: [${keep.join(", ")}]`,
      "  actions_rationale: >-",
      ...foldScalar(rationale, "    "),
      ...lines.slice(after),
    ].join("\n");
  }

  if (actionsAt < 0) return null;

  let end = actionsAt + 1;
  const itemIndent = (lines[end] ?? "").match(/^(\s*)-\s/)?.[1];
  if (itemIndent === undefined) return null;
  while (
    end < lines.length &&
    new RegExp(`^${itemIndent}-\\s`).test(lines[end] ?? "")
  )
    end++;

  // Replace an existing rationale rather than stacking a second one.
  if (/^ {2}actions_rationale:/.test(lines[end] ?? "")) {
    end++;
    while (end < lines.length && /^ {4}\S/.test(lines[end] ?? "")) end++;
  }

  const replacement = [
    ...keep.map((a) => `${itemIndent}- ${a}`),
    "  actions_rationale: >-",
    ...foldScalar(rationale, "    "),
  ];
  return [
    ...lines.slice(0, actionsAt + 1),
    ...replacement,
    ...lines.slice(end),
  ].join("\n");
}

function main(): number {
  if (!existsSync(MEASUREMENT)) {
    console.error(
      `No measurement at ${MEASUREMENT}. Run gate-promotion-fp.ts --emit-measurement first.`,
    );
    return 2;
  }
  const measurement = JSON.parse(readFileSync(MEASUREMENT, "utf-8")) as {
    sample_count?: number;
    rules?: Record<string, Rec>;
  };
  const sampleCount = measurement.sample_count;
  const records = measurement.rules ?? {};

  const changed: string[] = [];
  const skipped: string[] = [];
  const lyingTemplates: string[] = [];

  for (const file of ruleFiles(RULES_DIR)) {
    const text = readFileSync(file, "utf-8");
    let doc: unknown;
    try {
      doc = parseYaml(text);
    } catch {
      continue;
    }
    const r = doc as {
      id?: string;
      status?: string;
      maturity?: string;
      response?: { actions?: unknown; message_template?: unknown };
    };
    if (typeof r?.id !== "string") continue;
    const status = String(r.status ?? "").trim();
    const maturity = String(r.maturity ?? "").trim();
    if (
      status === "draft" ||
      status === "deprecated" ||
      maturity === "deprecated"
    )
      continue;

    const actions = Array.isArray(r.response?.actions)
      ? (r.response.actions as unknown[]).filter(
          (a): a is string => typeof a === "string",
        )
      : [];
    if (actions.length === 0) continue;

    const rec = records[r.id];
    const fingerprint = detectionFingerprint(doc as never);
    const matches =
      rec !== undefined && rec.detection_fingerprint === fingerprint;
    const decision = maxTierFor(
      matches
        ? {
            fpCount: rec.fp_count,
            sampleCount,
            partial: rec.partial_measurement === true,
            maturity: r.maturity,
          }
        : { maturity: r.maturity },
    );
    const unearned = ineligibleActions(actions, decision.maxTier);
    if (unearned.length === 0) continue;

    const keep = eligibleActions(actions, decision.maxTier);
    const rationale =
      `response-action eligibility (docs/RESPONSE-ACTION-ELIGIBILITY.md): ` +
      `${decision.reason}; ceiling = ${TIER_NAMES[decision.maxTier]}. ` +
      `Removed ${unearned.map((a) => `${a}(${TIER_NAMES[actionTier(a)]})`).join(", ")}. ` +
      `Detection unchanged — recall cost is zero.`;

    const rel = relative(REPO_ROOT, file);
    const next = rewriteActions(text, keep, rationale);
    if (next === null) {
      skipped.push(
        `${r.id}  ${rel}  (unexpected response.actions layout — edit by hand)`,
      );
      continue;
    }
    changed.push(
      `${r.id.padEnd(18)} ${TIER_NAMES[decision.maxTier].padEnd(9)} -${unearned.join(",")}  ${decision.reason}`,
    );
    const template =
      typeof r.response?.message_template === "string"
        ? r.response.message_template
        : "";
    if (BLOCK_PROMISE.test(template)) {
      lyingTemplates.push(
        `${r.id}  ${rel}\n      ${template.trim().replace(/\s+/g, " ").slice(0, 160)}`,
      );
    }
    if (doApply) writeFileSync(file, next, "utf-8");
  }

  console.log("RESPONSE-ACTION DOWNGRADE");
  console.log("=".repeat(78));
  console.log(`  rules with unearned actions   ${changed.length}`);
  console.log(`  skipped (odd layout)          ${skipped.length}`);
  console.log(`  templates that now lie        ${lyingTemplates.length}`);
  if (changed.length > 0) {
    console.log("\nDOWNGRADED:");
    for (const c of changed) console.log(`  ${c}`);
  }
  if (skipped.length > 0) {
    console.log("\nSKIPPED:");
    for (const s of skipped) console.log(`  ${s}`);
  }
  if (lyingTemplates.length > 0) {
    console.log(
      "\nTEMPLATE NOW LIES — the message promises an action this rule can no longer take.",
    );
    console.log("Rewrite these by hand to advisory wording:");
    for (const t of lyingTemplates) console.log(`  ${t}`);
  }
  console.log(`\n${"=".repeat(78)}`);
  console.log(
    doApply
      ? `Applied to ${changed.length} rule file(s).`
      : "DRY RUN — no files modified. Re-run with --apply.",
  );
  return 0;
}

const INVOKED_DIRECTLY =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));
if (INVOKED_DIRECTLY) process.exit(main());
