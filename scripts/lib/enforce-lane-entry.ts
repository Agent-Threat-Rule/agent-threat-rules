/**
 * enforce-lane-entry.ts — which rule files a change moves into the enforce
 * (auto-block) lane, judged from the rules as the engine loads them rather than
 * from the text of the diff.
 *
 * WHY THIS EXISTS
 *
 * scripts/gate-promotion-fp.ts --base found a promotion only as an added
 * `maturity: stable|production` line. A rule can enter the enforce lane without
 * one. It happened in #415: ATR-2026-00080 carried `status: draft` with
 * `maturity: stable`, and src/engine.ts skips draft and deprecated rules before
 * the lane gate, so it fired nowhere. One changed status line put it in the
 * enforce lane; maturity-fp-gate.yml printed "nothing to gate" and did not
 * measure it (the only measurement was the PR author's own, on that day's
 * corpus).
 *
 * Reading status lines out of the diff instead does not close that. YAML can
 * make a rule live without a changed `status:` line anywhere in the diff:
 * swallow the line into a multi-line quoted scalar, or change the value under a
 * `? status` key or inside a merge-key anchor. And a rule line that starts with
 * `++ ` shows up in a diff as a `+++ ` header. So each changed rule file is
 * loaded through the engine's own loader twice, at the merge base and in the
 * working tree, and the question is asked of the rule: did its maturity rise
 * into the enforce lane, or did it become live while already holding such a
 * maturity?
 *
 * The first half is what parsePromotedFiles looks for, asked of the rule instead
 * of the line, so `maturity: stable  # promoted` counts too. It includes a rule
 * that is still inert: the gate then has to report that it could not measure
 * it, rather than let the rule reach the enforce lane later through a status
 * edit made in a separate PR.
 *
 * Every doubt resolves toward measuring. A path that did not exist at the merge
 * base, a file that did not load there, a rename (not paired: a moved rule is a
 * new path), a different id at the same path — all count as starting below the
 * enforce lane. Only the same rule at the same path that already held an enforce
 * maturity, and was already live if it is live now, is left alone; an edit to
 * such a rule is not what this module is for.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { loadRuleFile } from "../../src/loader.js";
import { laneAllows } from "../../src/quality/rule-contract.js";

/**
 * Maturities the gate treats as the enforce lane. src/engine.ts admits only
 * `stable` there (normalizeMaturity reads `production` as experimental);
 * counting `production` as well is the gate's existing over-approximation.
 */
export const ENFORCE_MATURITIES: ReadonlySet<string> = new Set([
  "stable",
  "production",
]);

/**
 * Statuses src/engine.ts skips before any lane gate, in both evaluation paths:
 *   if (rule.status === 'deprecated' || rule.status === 'draft') continue;
 * Compared the way the engine compares, so anything else is live: no status at
 * all, `Draft`, `[draft]`.
 */
const INERT_STATUSES: ReadonlySet<unknown> = new Set(["draft", "deprecated"]);

/** What decides whether a rule fires in the enforce lane, as the engine loads it. */
export interface RuleLaneState {
  readonly id: unknown;
  readonly status: unknown;
  readonly maturity: unknown;
}

/** One rule file a change adds or modifies, loaded on each side of it. */
export interface RuleFileChange {
  readonly file: string;
  /** At the merge base. Null: the path did not exist there, or did not load. */
  readonly base: RuleLaneState | null;
  /** In the working tree. Null: it does not load, so it fires in no lane. */
  readonly head: RuleLaneState | null;
}

function isLive(state: RuleLaneState): boolean {
  return !INERT_STATUSES.has(state.status);
}

function hasEnforceMaturity(state: RuleLaneState): boolean {
  // Trimmed as normalizeMaturity() trims it in src/quality/rule-contract.ts.
  return ENFORCE_MATURITIES.has(String(state.maturity ?? "").trim());
}

/** Live (the engine evaluates it at all) with an enforce-lane maturity. */
export function firesInEnforceLane(state: RuleLaneState | null): boolean {
  return state !== null && isLive(state) && hasEnforceMaturity(state);
}

/**
 * The files a change moves into the enforce lane: the maturity rose into it, or
 * the rule became live while already holding it. Compared with the same rule at
 * the same path at the merge base; no base, an unloadable one, or another id
 * there all count as starting below the enforce lane.
 *
 * The two sides are read differently on purpose. Now, `production` counts as
 * enforce, the gate's over-approximation; at the merge base only what the
 * engine admits does (laneAllows), so production -> stable is still a move in.
 */
export function enteringEnforceLane(
  changes: readonly RuleFileChange[],
): readonly string[] {
  return changes.filter(entersEnforceLane).map((c) => c.file);
}

function entersEnforceLane({ base, head }: RuleFileChange): boolean {
  if (head === null || !hasEnforceMaturity(head)) return false;
  const before = base !== null && base.id === head.id ? base : null;
  if (before === null || !laneAllows(before.maturity, "enforce")) return true;
  return isLive(head) && !isLive(before);
}

/** A file the engine would load as a rule: src/loader.ts checks the same extensions. */
function isRuleFile(path: string): boolean {
  const ext = extname(path);
  return ext === ".yaml" || ext === ".yml";
}

/** The rule at `path` as the engine would load it, or why it would not. */
function loadLaneState(path: string): RuleLaneState | Error {
  try {
    const rule = loadRuleFile(path);
    return { id: rule.id, status: rule.status, maturity: rule.maturity };
  } catch (e: unknown) {
    return e instanceof Error ? e : new Error(String(e));
  }
}

/** Whether the engine would load the rule at `path`, and the id it would load. */
export type LoadedRuleId =
  | { readonly loads: false }
  | { readonly loads: true; readonly id: unknown };

export function loadedRuleId(path: string): LoadedRuleId {
  const state = loadLaneState(path);
  return state instanceof Error ? { loads: false } : { loads: true, id: state.id };
}

/**
 * Every rule file `base...HEAD` adds or modifies, loaded at the merge base and
 * in the working tree. -z keeps paths with spaces or non-ASCII unquoted; none of
 * these git calls prints anything a user's diff settings (prefixes, colour, an
 * external diff driver) can change.
 */
export function ruleFileChanges(
  base: string,
  repoRoot: string,
): readonly RuleFileChange[] {
  const git = (args: readonly string[]): string =>
    execFileSync("git", [...args], {
      cwd: repoRoot,
      encoding: "utf-8",
      maxBuffer: 64 * 1024 * 1024,
    });
  const files = git([
    "diff",
    "--name-only",
    "-z",
    "--no-renames",
    "--diff-filter=AMT",
    `${base}...HEAD`,
    "--",
    "rules/",
  ])
    .split("\0")
    .filter(isRuleFile);
  if (files.length === 0) return [];

  const mergeBase = git(["merge-base", base, "HEAD"]).trim();
  const atBase = new Set(
    git(["ls-tree", "-r", "-z", "--name-only", mergeBase, "--", "rules/"]).split("\0"),
  );
  // loadRuleFile reads from disk; base blobs are written here so the merge-base
  // side goes through the same size limit, parse and required-field check.
  const scratch = mkdtempSync(join(tmpdir(), "atr-gate-base-"));
  try {
    return files.map((file, i) => ({
      file,
      base: atBase.has(file)
        ? baseState(repoRoot, `${mergeBase}:${file}`, join(scratch, `${i}.yaml`))
        : null,
      head: headState(repoRoot, file),
    }));
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

function baseState(repoRoot: string, object: string, copy: string): RuleLaneState | null {
  writeFileSync(
    copy,
    execFileSync("git", ["cat-file", "blob", object], {
      cwd: repoRoot,
      maxBuffer: 64 * 1024 * 1024,
    }),
  );
  const state = loadLaneState(copy);
  // Not loadable at the base means it fired nowhere then: an entry if it does now.
  return state instanceof Error ? null : state;
}

function headState(repoRoot: string, file: string): RuleLaneState | null {
  const state = loadLaneState(join(repoRoot, file));
  if (!(state instanceof Error)) return state;
  // JSON-quoted: a path is user input, and a raw newline in it could start a
  // workflow command in the Actions log.
  console.warn(
    `[fp-gate] ${JSON.stringify(file)} does not load, so the engine evaluates it in no lane: ` +
      JSON.stringify(state.message),
  );
  return null;
}
