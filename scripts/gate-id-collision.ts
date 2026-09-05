#!/usr/bin/env npx tsx
/**
 * gate-id-collision.ts — does another branch already claim a rule ID this one introduces?
 *
 * Existing checks look at one tree. tests/validate-rules.ts catches two files
 * sharing an ID inside a branch and sees nothing when they live on different
 * branches. On 2026-09-04 that gap let ATR-2026-02816 and ATR-2026-02818 sit on
 * feat/resweep-rules-b1 and feat/paper-mine-rules simultaneously with different
 * detection logic, both rule_version 1, both green. Whichever PR merged second
 * would have conflicted, and a careless resolution would have silently dropped
 * one version's conditions.
 *
 * Narrow on purpose. An ID is a collision only when this branch INTRODUCES it
 * and a sibling carries the same ID with DIFFERENT content. Identical content is
 * a cherry-pick; an ID already on the base belongs to everyone.
 *
 * Usage:
 *   npx tsx scripts/gate-id-collision.ts                     # base=origin/main, siblings=origin/feat/*
 *   npx tsx scripts/gate-id-collision.ts --base origin/main --pattern 'refs/remotes/origin/feat/*'
 *
 * Exit 0 clean, 1 on collision, 2 on usage error.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { collisions, type BranchRules } from "./lib/id-collision.js";

const EXIT_COLLISION = 1;
const EXIT_USAGE = 2;

function git(args: readonly string[]): string {
  return execFileSync("git", args as string[], { encoding: "utf-8", maxBuffer: 64 * 1024 * 1024 });
}

function argValue(flag: string, fallback: string): string {
  const i = process.argv.indexOf(flag);
  return i >= 0 && process.argv[i + 1] !== undefined ? process.argv[i + 1] : fallback;
}

/**
 * rule id -> blob sha, in ONE `git ls-tree`.
 *
 * The blob sha IS the content hash, so nothing needs reading; and every rule
 * file on main (793/793, checked) carries its id in the filename, so the id
 * needs no parse of the body either. The first cut of this gate ran `git show`
 * per file per branch and took longer than the whole test suite.
 */
function rulesOf(ref: string): BranchRules {
  const out: Record<string, string> = {};
  let listing: string;
  try {
    listing = git(["ls-tree", "-r", ref, "--", "rules/"]);
  } catch {
    return out;
  }
  for (const line of listing.split("\n")) {
    // <mode> blob <sha>\t<path>
    const m = /^\S+\s+blob\s+(\S+)\t(.+)$/.exec(line);
    if (m === null) continue;
    const [, sha, path] = m;
    if (!path.endsWith(".yaml")) continue;
    const id = /\/(ATR-\d{4}-\d{5})-/.exec(path);
    if (id === null) continue;
    out[id[1]] = sha;
  }
  return out;
}

function main(): number {
  const base = argValue("--base", "origin/main");
  const pattern = argValue("--pattern", "refs/remotes/origin/feat/*");
  let head: string;
  try {
    head = git(["rev-parse", "--abbrev-ref", "HEAD"]).trim();
  } catch {
    console.error("[id-gate] usage error: not a git repository");
    return EXIT_USAGE;
  }

  const branch = rulesOf("HEAD");
  const baseRules = rulesOf(base);

  const siblings: Record<string, BranchRules> = {};
  const refs = git(["for-each-ref", "--format=%(refname:short)", pattern])
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((r) => !r.endsWith(`/${head}`) && r !== `origin/${head}`);
  for (const ref of refs) siblings[ref] = rulesOf(ref);

  const found = collisions(branch, baseRules, siblings);
  const introduced = Object.keys(branch).filter((id) => !(id in baseRules)).length;

  if (found.length === 0) {
    console.log(
      `[id-gate] PASS — ${introduced} new rule id(s) on ${head}; none claimed by any of ` +
        `${refs.length} sibling branch(es).`,
    );
    return 0;
  }

  console.error(
    `[id-gate] FAIL — ${found.length} rule id(s) are also claimed, with different content, ` +
      `by another branch:\n`,
  );
  for (const c of found) console.error(`  ${c.id}  also on  ${c.branch}`);
  console.error(
    `\nTwo rules under one id cannot both merge. Decide which version survives, ` +
      `drop the other, and re-run. Do not resolve this at merge time -- ` +
      `that is where a version's conditions get dropped silently.`,
  );
  return EXIT_COLLISION;
}

process.exit(main());
