/**
 * Tests for the ATTRIBUTION half of a measurement: not "what was the score",
 * but "which rules produced it".
 *
 * WHY THIS FILE EXISTS
 *
 * `data/measurements/promptinject/latest.json` published recall 1.0 on 1,080
 * adversarial samples, and its `breakdown.top_matching_rules` said:
 *
 *     [{ "rule_id": "unknown", "matches": 3624 }]
 *
 * The engine returns `ATRMatch { rule: ATRRule, ... }` — the rule OBJECT.
 * scripts/atr_recall_analysis.ts read `m.rule_id ?? m.ruleId`, both of which are
 * `undefined` on every match, and fell through to the literal string
 * `"unknown"`. The 3,624 is arithmetically correct — it is the sum over the
 * nine rules that fired — but printed as one row it reads as a single regex
 * matching 3,624 times across 1,080 samples. So a headline 100% recall shipped
 * with no way to answer the only question that makes it safe to quote: is that
 * broad coverage, or one over-broad rule sweeping the whole corpus? (For PINT
 * the answer turned out to be the latter — 226 of 272 detections from
 * ATR-2026-00001 alone.)
 *
 * The failure mode generalises past this one typo: a breakdown that names no
 * real rule is indistinguishable, in the output, from a breakdown that names
 * the right ones. These tests make an unattributable number fail CI.
 *
 * SCOPE: only the measurement each source's `latest.json` POINTS AT is checked.
 * Older dated files are immutable history and are deliberately left alone —
 * the 3.5.2 promptinject/promptbench files still carry "unknown", and rewriting
 * them would be falsifying the record rather than fixing it.
 */

import { describe, it, expect } from "vitest";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const MEASUREMENTS_DIR = join(REPO_ROOT, "data", "measurements");
const RULES_DIR = join(REPO_ROOT, "rules");

/** Canonical ATR rule id: ATR-<year>-<5 digits>. */
const ATR_ID = /^ATR-\d{4}-\d{5}$/;

/** Placeholder strings that mean "attribution was lost", not "a rule". */
const NON_ATTRIBUTIONS = new Set(["unknown", "undefined", "null", "", "-", "n/a"]);

interface TopRule {
  rule_id?: unknown;
  matches?: unknown;
}

interface LatestPointer {
  file?: unknown;
}

function sourceDirs(): string[] {
  if (!existsSync(MEASUREMENTS_DIR)) return [];
  return readdirSync(MEASUREMENTS_DIR)
    .filter((n) => statSync(join(MEASUREMENTS_DIR, n)).isDirectory())
    .sort();
}

/** The measurement each source's latest.json points at, if any. */
function latestMeasurements(): Array<{ source: string; path: string; body: Record<string, unknown> }> {
  const out: Array<{ source: string; path: string; body: Record<string, unknown> }> = [];
  for (const source of sourceDirs()) {
    const pointerPath = join(MEASUREMENTS_DIR, source, "latest.json");
    if (!existsSync(pointerPath)) continue;
    const pointer = JSON.parse(readFileSync(pointerPath, "utf-8")) as LatestPointer;
    if (typeof pointer.file !== "string") continue;
    const measurementPath = join(MEASUREMENTS_DIR, source, pointer.file);
    if (!existsSync(measurementPath)) continue;
    out.push({
      source,
      path: measurementPath,
      body: JSON.parse(readFileSync(measurementPath, "utf-8")) as Record<string, unknown>,
    });
  }
  return out;
}

function topRules(body: Record<string, unknown>): TopRule[] | null {
  const breakdown = body.breakdown;
  if (breakdown === null || typeof breakdown !== "object") return null;
  const list = (breakdown as Record<string, unknown>).top_matching_rules;
  return Array.isArray(list) ? (list as TopRule[]) : null;
}

/** Every rule id that exists as a file on disk today. */
function ruleIdsOnDisk(): Set<string> {
  const ids = new Set<string>();
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name.endsWith(".yaml")) {
        const m = /^(ATR-\d{4}-\d{5})/.exec(entry.name);
        if (m) ids.add(m[1]);
      }
    }
  };
  if (existsSync(RULES_DIR)) walk(RULES_DIR);
  return ids;
}

describe("measurement attribution", () => {
  const latest = latestMeasurements();

  it("finds measurement files to check", () => {
    expect(latest.length).toBeGreaterThan(0);
  });

  it("never names a placeholder instead of a rule", () => {
    const offenders: string[] = [];
    for (const { source, body } of latest) {
      for (const entry of topRules(body) ?? []) {
        const id = typeof entry.rule_id === "string" ? entry.rule_id.trim().toLowerCase() : "";
        if (NON_ATTRIBUTIONS.has(id)) {
          offenders.push(`${source}: rule_id=${JSON.stringify(entry.rule_id)}`);
        }
      }
    }
    expect(
      offenders,
      "a breakdown entry that names no rule is a lost attribution, not a measurement:\n" +
        offenders.join("\n"),
    ).toEqual([]);
  });

  it("only names well-formed ATR ids", () => {
    const offenders: string[] = [];
    for (const { source, body } of latest) {
      for (const entry of topRules(body) ?? []) {
        if (typeof entry.rule_id !== "string" || !ATR_ID.test(entry.rule_id)) {
          offenders.push(`${source}: rule_id=${JSON.stringify(entry.rule_id)}`);
        }
      }
    }
    expect(offenders, offenders.join("\n")).toEqual([]);
  });

  it("only names rules that exist on disk", () => {
    const onDisk = ruleIdsOnDisk();
    const offenders: string[] = [];
    for (const { source, body } of latest) {
      for (const entry of topRules(body) ?? []) {
        if (typeof entry.rule_id !== "string") continue;
        if (!ATR_ID.test(entry.rule_id)) continue; // covered by the previous test
        if (!onDisk.has(entry.rule_id)) offenders.push(`${source}: ${entry.rule_id}`);
      }
    }
    expect(
      offenders,
      "measurement credits a rule id that no file on disk carries:\n" + offenders.join("\n"),
    ).toEqual([]);
  });

  it("never attributes more samples to one rule than the run had true positives", () => {
    const offenders: string[] = [];
    for (const { source, body } of latest) {
      const confusion = body.confusion as { tp?: unknown } | undefined;
      const tp = typeof confusion?.tp === "number" ? confusion.tp : null;
      if (tp === null) continue;
      for (const entry of topRules(body) ?? []) {
        const n = typeof entry.matches === "number" ? entry.matches : null;
        if (n !== null && n > tp) {
          offenders.push(`${source}: ${String(entry.rule_id)} credited ${n} > tp ${tp}`);
        }
      }
    }
    expect(
      offenders,
      "per-rule counts must be per SAMPLE, like true positives. A count above " +
        "tp means either one sample was counted once per matching shape, or " +
        "several rules' tallies were summed into one row (which is how the " +
        "3.5.2 promptinject file reported 3,624 against 1,080 samples):\n" +
        offenders.join("\n"),
    ).toEqual([]);
  });
});

describe("ATRMatch shape — the field the harness must read", () => {
  it("scripts/atr_recall_analysis.ts reads m.rule.id, not m.rule_id", () => {
    const src = readFileSync(join(REPO_ROOT, "scripts", "atr_recall_analysis.ts"), "utf-8");
    // The engine returns the rule OBJECT. Reading a flat rule_id/ruleId off a
    // match silently yields undefined on every single match.
    expect(src).toContain("m.rule.id");
    // Any read of a FLAT rule id off a match variable is the bug returning.
    expect(src).not.toMatch(/\bm\s*\)?\s*\.\s*(?:rule_id|ruleId)\b/);
    expect(src).not.toMatch(/\(\s*m\s+as\s+any\s*\)\s*\.\s*(?:rule_id|ruleId)\b/);
  });
});
