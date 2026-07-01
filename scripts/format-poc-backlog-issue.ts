#!/usr/bin/env npx tsx
/**
 * format-poc-backlog-issue.ts
 *
 * Reads a promote-detection-ready.ts report JSON and prints the markdown
 * body for the rolling "proposals awaiting human PoC" issue maintained by
 * cve-daily-sync.yml.
 *
 * Each listed proposal has a CVE/advisory but NO PoC code block, so the
 * auto-generator could only infer detection patterns from description prose.
 * Promoting prose-grounded patterns detects the sentence describing the
 * attack, not the attack (the MiroFish failure mode) -- so these are never
 * auto-promoted. A maintainer must supply a regex from the real payload.
 *
 * Output is plain markdown on stdout (no shell-hostile chars are emitted
 * unescaped). Pipe-table cell content has `|` escaped.
 *
 * Usage:
 *   npx tsx scripts/format-poc-backlog-issue.ts <promote-report.json>
 *
 * Exit codes:
 *   0 body printed
 *   1 report missing / unreadable / malformed
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

export interface PromoteResult {
  proposal: string;
  draft_id?: string;
  title?: string;
  status: string;
  reason?: string;
}

export interface PromoteReport {
  results?: PromoteResult[];
}

function cell(s: string): string {
  // Escape pipe + collapse newlines so a value can't break the md table.
  return s.replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ").trim();
}

/**
 * Build the markdown body for the rolling human-PoC backlog issue. Only
 * proposals with status "needs-human-poc" are listed; promoted / no-pattern
 * rows are excluded. Pure function (no IO) so it is unit-testable.
 */
export function formatBacklogIssue(report: PromoteReport): string {
  const rows = (report.results ?? []).filter(
    (r) => r.status === "needs-human-poc",
  );

  const lines: string[] = [];
  lines.push(
    "Auto-maintained work queue. Each proposal below has a CVE or advisory " +
      "but NO PoC code block, so the auto-generator could only infer detection " +
      "patterns from description prose. Promoting prose-grounded patterns " +
      "detects the sentence that describes the attack, not the attack (the " +
      "MiroFish failure mode), so these are never auto-promoted.",
  );
  lines.push("");
  lines.push(
    "To clear an item: open the proposal, replace detection.conditions with a " +
      "regex derived from the real exploit payload, run " +
      "`scripts/check-rules-safety.ts`, then " +
      "`scripts/promote-detection-ready.ts --write`. It drops off this list " +
      "automatically once promoted.",
  );
  lines.push("");
  lines.push("| Proposal | Draft ID | Title |");
  lines.push("|---|---|---|");
  for (const r of rows) {
    lines.push(
      `| \`${cell(r.proposal)}\` | ${cell(r.draft_id ?? "—")} | ${cell(
        r.title ?? "",
      )} |`,
    );
  }
  lines.push("");
  lines.push(
    `_${rows.length} proposal(s) awaiting a PoC. Updated automatically by the daily CVE collector._`,
  );

  return lines.join("\n");
}

function main(): void {
  const path = process.argv[2];
  if (!path) {
    console.error("usage: format-poc-backlog-issue.ts <promote-report.json>");
    process.exit(1);
  }
  let report: PromoteReport;
  try {
    report = JSON.parse(readFileSync(resolve(path), "utf-8")) as PromoteReport;
  } catch (e) {
    console.error(`failed to read report ${path}: ${e}`);
    process.exit(1);
  }

  process.stdout.write(formatBacklogIssue(report) + "\n");
}

// Run if invoked as a script (not when imported as a module for tests)
const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) main();
