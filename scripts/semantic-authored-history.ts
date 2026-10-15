#!/usr/bin/env npx tsx
/**
 * semantic-authored-history.ts
 *
 * Writes the list of every cluster the semantic lane has ever authored, read
 * from git history, for author-semantic-rules.ts --exclude-from. Why history
 * and not the rules tree: see scripts/lib/semantic-exclusions.ts.
 *
 * USAGE
 *   npx tsx scripts/semantic-authored-history.ts --out FILE [--glob PATTERN] REF...
 *     REF       a ref whose history to read (e.g. origin/main)
 *     --glob    also read every ref matching PATTERN (e.g. 'refs/semantic-history/*');
 *               a pattern matching nothing adds nothing
 *
 * EXIT CODES
 *   0 written (possibly empty: the lane has authored nothing yet)
 *   1 usage error, or git could not read a ref. Never write a partial record:
 *     a short list lets rejected clusters back in.
 */
import { writeFileSync } from "node:fs";
import { clustersAuthoredInHistory, formatExcludeList } from "./lib/semantic-exclusions.js";

interface Args {
  out: string;
  revs: string[];
}

export function parseArgs(argv: readonly string[]): Args {
  const take = (i: number, flag: string): string => {
    const v = argv[i + 1];
    if (v === undefined || v.startsWith("-")) throw new Error(`${flag} needs a value`);
    return v;
  };
  let out: string | undefined;
  const revs: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--out") out = take(i++, a);
    else if (a === "--glob") revs.push(`--glob=${take(i++, a)}`);
    else if (a.startsWith("-")) throw new Error(`unknown option ${a}`);
    else revs.push(a);
  }
  if (!out) throw new Error("--out FILE is required");
  if (revs.length === 0) throw new Error("name at least one REF or --glob");
  return { out, revs };
}

function main(): void {
  const { out, revs } = parseArgs(process.argv.slice(2));
  const clusters = clustersAuthoredInHistory(revs, process.cwd());
  writeFileSync(out, formatExcludeList(clusters));
  console.log(`[semantic-history] ${clusters.size} cluster(s) already authored by this lane -> ${out}`);
}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  try {
    main();
  } catch (e) {
    console.error(`[semantic-history] fatal: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  }
}
