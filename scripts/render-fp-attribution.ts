#!/usr/bin/env node
/**
 * render-fp-attribution.ts — the attribution section of the benign-harvest PR
 * body: per rule, the newly harvested samples it fires on.
 *
 * Reads the report scripts/remeasure-benign-fp.ts --report wrote and, when the
 * response-action gate failed, its `--json` output, so the rules the gate fails
 * are listed first. Writes the capped section for the PR body to --out and
 * prints the uncapped listing to stdout, for the job log that every
 * "… N more" in the body points at. See scripts/lib/fp-attribution.ts.
 *
 * Usage:
 *   render-fp-attribution.ts --report <attribution.json> [--gate-json <gate.json>] --out <section.md>
 *
 * Exit codes:
 *   0  section written
 *   1  the report or the gate output is unreadable or malformed; nothing written
 *   2  usage error
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  parseAttributionReport,
  parseGateViolations,
  renderAttributionSection,
} from "./lib/fp-attribution.js";
import { parseFlagPairs } from "./lib/strict-flags.js";

export const EXIT_OK = 0;
export const EXIT_FAIL = 1;
export const EXIT_USAGE = 2;

export class RenderUsageError extends Error {}

export interface RenderOptions {
  readonly report: string;
  /** Absent when the gate passed: there are no failing rules to put first. */
  readonly gateJson: string | null;
  readonly out: string;
}

const FLAGS: ReadonlySet<string> = new Set(["--report", "--gate-json", "--out"]);

export function parseRenderArgs(argv: readonly string[]): RenderOptions {
  const values = parseFlagPairs(argv, FLAGS, (m) => new RenderUsageError(m));
  const report = values.get("--report");
  const out = values.get("--out");
  if (report === undefined) throw new RenderUsageError("--report is required");
  if (out === undefined) throw new RenderUsageError("--out is required");
  return { report, gateJson: values.get("--gate-json") ?? null, out };
}

export function runRender(options: RenderOptions, print: (line: string) => void = console.log): number {
  let rendered: { readonly markdown: string; readonly log: string };
  try {
    const report = parseAttributionReport(readFileSync(options.report, "utf-8"));
    const violations =
      options.gateJson === null ? undefined : parseGateViolations(readFileSync(options.gateJson, "utf-8"));
    rendered = renderAttributionSection(report, violations);
  } catch (e) {
    console.error(
      `[render-fp-attribution] FAIL — ${e instanceof Error ? e.message : String(e)}. Nothing was written.`,
    );
    return EXIT_FAIL;
  }
  const out = resolve(options.out);
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${rendered.markdown}\n`, "utf-8");
  print(rendered.log);
  return EXIT_OK;
}

export function main(argv: readonly string[]): number {
  try {
    return runRender(parseRenderArgs(argv));
  } catch (e) {
    if (e instanceof RenderUsageError) {
      console.error(`[render-fp-attribution] usage error: ${e.message}`);
      return EXIT_USAGE;
    }
    throw e;
  }
}

const INVOKED_DIRECTLY =
  process.argv[1] !== undefined && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url));

if (INVOKED_DIRECTLY) {
  process.exitCode = main(process.argv.slice(2));
}
