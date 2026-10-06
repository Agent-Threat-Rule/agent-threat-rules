/**
 * The record of every cluster the semantic lane has authored, read from git.
 *
 * WHY HISTORY, NOT THE TREE
 * author-semantic-rules.ts dedupes against `_semantic_authored.source_cluster`
 * in the rules tree it runs on. That tree only holds rules that still exist. A
 * rolling PR closed without merging, or a rule a reviewer deleted from one,
 * leaves nothing in it, so the next run picks the same clusters again (they
 * sort first) and opens a new PR with a regenerated copy of the rejected rules.
 * Every rule the lane committed survives in the history of the PR it went
 * into: GitHub keeps refs/pull/N/head after the PR is closed, even once the
 * branch itself is overwritten. Reading source_cluster back out of that history
 * gives a record that closing a PR or deleting a rule cannot erase, so the lane
 * authors each cluster at most once and a human's "no" stays a "no".
 *
 * Which refs to read is the caller's decision. The workflow passes main plus
 * the head of every same-repo rolling PR -- never the bare branch, which can
 * hold rules no PR ever showed a reviewer.
 */
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import yaml from "js-yaml";

// Commits are selected by the line that marks a rule as this lane's, so the
// scan reads a handful of blobs rather than every rule in the history.
const LANE_MARKER = "_semantic_authored";
const GIT_MAX_BUFFER = 256 * 1024 * 1024;

/** The proposal a lane-authored rule came from; undefined for anything else. */
export function sourceClusterOf(text: string): string | undefined {
  let doc: unknown;
  try {
    doc = yaml.load(text);
  } catch {
    return undefined;
  }
  if (!doc || typeof doc !== "object") return undefined;
  const meta = (doc as { _semantic_authored?: unknown })._semantic_authored;
  if (!meta || typeof meta !== "object") return undefined;
  const src = (meta as { source_cluster?: unknown }).source_cluster;
  return typeof src === "string" && src.length > 0 ? src : undefined;
}

/** One proposal path per line; blank lines and `#` comments are ignored. */
export function parseExcludeList(text: string): Set<string> {
  const lines = text.split("\n").map((l) => l.trim());
  return new Set(lines.filter((l) => l.length > 0 && !l.startsWith("#")));
}

/** Sorted and newline-terminated, so the same record always writes the same file. */
export function formatExcludeList(clusters: Iterable<string>): string {
  const sorted = [...clusters].sort();
  return sorted.length > 0 ? `${sorted.join("\n")}\n` : "";
}

/** Read an exclude file. A missing file is an error: the caller asked for it. */
export function readExcludeList(path: string): Set<string> {
  return parseExcludeList(readFileSync(path, "utf-8"));
}

function assertRevision(rev: string): void {
  // git log takes options and revisions in the same argv. Only plain refs and
  // --glob are revisions here; anything else starting with "-" is refused.
  if (rev.startsWith("-") && !rev.startsWith("--glob=")) {
    throw new Error(`not a revision: ${rev}`);
  }
}

function git(cwd: string, args: string[]): string {
  return execFileSync("git", args, { cwd, encoding: "utf-8", maxBuffer: GIT_MAX_BUFFER });
}

/** Every (commit, path) under rules/ where a lane-marked rule was added or changed. */
export function laneRuleBlobs(revs: readonly string[], cwd: string): Array<{ commit: string; path: string }> {
  revs.forEach(assertRevision);
  if (revs.length === 0) return [];
  const out = git(cwd, [
    "-c", "core.quotePath=false",
    "log", "--no-show-signature", `-G${LANE_MARKER}`, "--diff-filter=AM", "--name-only", "--format=commit %H",
    ...revs, "--", "rules/",
  ]);
  const blobs: Array<{ commit: string; path: string }> = [];
  let commit = "";
  for (const line of out.split("\n")) {
    if (line.startsWith("commit ")) commit = line.slice("commit ".length);
    else if (line.length > 0 && commit) blobs.push({ commit, path: line });
  }
  return blobs;
}

/**
 * Every cluster a lane-authored rule has ever named, in the history reachable
 * from `revs` (refs, or `--glob=` patterns). Throws if git cannot read a ref:
 * an empty record would quietly let every rejected cluster back in.
 */
export function clustersAuthoredInHistory(revs: readonly string[], cwd: string): Set<string> {
  const clusters = laneRuleBlobs(revs, cwd)
    .map(({ commit, path }) => sourceClusterOf(git(cwd, ["cat-file", "blob", `${commit}:${path}`])))
    .filter((c): c is string => c !== undefined);
  return new Set(clusters);
}
