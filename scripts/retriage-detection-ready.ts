#!/usr/bin/env npx tsx
/**
 * retriage-detection-ready.ts — re-run the readiness heuristic against the FULL advisory body.
 *
 * THE DEFECT
 *   Every sync script decides detection_ready with the same payload heuristic, and every one of
 *   them feeds it only the title and the description:
 *
 *     const body = `${s.title}\n${s.description}`;
 *     if (PAYLOAD_HEURISTICS_RX.test(body)) return { ready: true, ... };
 *
 *   But the proposal each script WRITES carries a much larger field — _<source>_sync.advisory_body,
 *   median 475 characters and up to 1,553 in the sample I took — and the heuristic never sees it.
 *   So an advisory whose mechanism and reproducer live in the body, while its two-line description
 *   does not happen to contain a code fence or the word curl, is filed TRACKING_ONLY and never
 *   reaches the rule-conversion pipeline at all.
 *
 * WHY A SEPARATE SCRIPT RATHER THAN PATCHING THE 19 SYNC SCRIPTS
 *   Two reasons. The backlog is the urgent half: 7,938 proposals are already on disk with the
 *   verdict baked in, and patching the collectors does nothing for them because they only re-triage
 *   what they newly fetch. And the collectors do not hold the body in the same shape at the moment
 *   they decide — the body is assembled later, at write time — so a correct fix there is 19
 *   separate refactors rather than one. This runs over what is on disk, which is where the
 *   evidence actually is.
 *
 * WHAT IT FOUND
 *   Measured over all 7,938 TRACKING_ONLY proposals: 11 flip, of which 8 are agent-relevant.
 *   That is the honest size of the gap. It is not 7,938 and it is not zero, and the number matters
 *   because the same question was asked twice today about two other populations and answered wrong
 *   both times by reasoning from a ratio instead of counting.
 *
 * Default is a dry run. --apply rewrites the two lines in place.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { readdirSync, statSync } from "node:fs";
import { join, resolve, dirname, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { load as yamlLoad } from "js-yaml";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const PROPOSALS = join(REPO_ROOT, "proposals");

/** Kept byte-identical to the copy in the sync scripts, so the two cannot drift apart. */
const PAYLOAD_HEURISTICS_RX = new RegExp(
  [
    "```",
    "## \\*Proof of Concept",
    "## \\*Reproducer",
    "## \\*Exploit",
    "payload:",
    "curl ",
    "POST \\/[a-z]",
    "<script>",
    "prompt: ['\"]",
    "\\$\\{",
    "\\beval\\(",
  ].join("|"),
  "im",
);

const AGENT_RX =
  /(prompt.?inject|\bMCP\b|model context protocol|\bLLM\b|AI agent|agentic|tool.?poison|SKILL\.md|system.?prompt|jailbreak|\bRAG\b|copilot|langchain|autogen|crewai)/i;

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (e.endsWith(".yaml") || e.endsWith(".yml")) out.push(p);
  }
  return out;
}

/** Pure: the longest body-like string anywhere under a _*_sync block. */
export function longestBody(doc: Record<string, unknown>): string {
  let best = "";
  for (const v of Object.values(doc)) {
    if (!v || typeof v !== "object") continue;
    for (const [k, vv] of Object.entries(v as Record<string, unknown>)) {
      if (typeof vv !== "string") continue;
      if (!/body|detail|narrative|repro|evidence|content/i.test(k)) continue;
      if (vv.length > best.length) best = vv;
    }
  }
  return best;
}

/** Pure: would reading the body change the verdict? */
export function flips(titleDesc: string, body: string): boolean {
  return body.length > 0 && PAYLOAD_HEURISTICS_RX.test(body) && !PAYLOAD_HEURISTICS_RX.test(titleDesc);
}

function main(argv: readonly string[]): number {
  const apply = argv.includes("--apply");
  const files = walk(PROPOSALS);
  const changed: Array<{ file: string; title: string; agent: boolean }> = [];
  let scanned = 0;

  for (const file of files) {
    let raw: string;
    try {
      raw = readFileSync(file, "utf-8");
    } catch {
      continue;
    }
    if (!raw.includes("detection_ready: false")) continue;
    scanned += 1;
    let doc: Record<string, unknown>;
    try {
      doc = yamlLoad(raw) as Record<string, unknown>;
    } catch {
      continue;
    }
    if (!doc || typeof doc !== "object") continue;

    const titleDesc = `${doc.title ?? ""}\n${doc.description ?? ""}`;
    const body = longestBody(doc);
    if (!flips(titleDesc, body)) continue;

    const title = String(doc.title ?? "").slice(0, 90);
    const agent = AGENT_RX.test(`${titleDesc}\n${body}`);
    changed.push({ file: relative(REPO_ROOT, file), title, agent });

    if (apply) {
      const next = raw
        .replace(/detection_ready: false/g, "detection_ready: true")
        .replace(
          /# Detection readiness: TRACKING_ONLY -- [^\n]*/g,
          "# Detection readiness: READY -- payload-like content in advisory body " +
            "(re-triaged by scripts/retriage-detection-ready.ts; the collector only " +
            "examined title and description)",
        );
      writeFileSync(file, next, "utf-8");
    }
  }

  console.log(
    `re-triage: scanned ${scanned} not-ready proposal(s) · ${changed.length} flip to ready` +
      (apply ? " (written)" : " (dry run)"),
  );
  console.log(`  of those, agent-relevant: ${changed.filter((c) => c.agent).length}`);
  for (const c of changed) {
    console.log(`  ${c.agent ? "★" : " "} ${c.file}`);
    console.log(`     ${c.title}`);
  }
  if (!apply && changed.length) console.log("\nRe-run with --apply to write.");
  return 0;
}

if (
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
) {
  process.exit(main(process.argv.slice(2)));
}
