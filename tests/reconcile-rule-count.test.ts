/**
 * Tests for scripts/reconcile-rule-count.mjs — the effective-rule-count
 * computation and the surgical stats edit that publishes it.
 *
 * WHY "EFFECTIVE" EXISTS
 *   `total` counts rule FILES. src/engine.ts skips `status: draft` and
 *   `status: deprecated` in both evaluation paths, so those files fire in no
 *   lane, ever, and counting them as detection coverage overstates it. The two
 *   numbers are now computed together and both published, because the honest
 *   answer to "how many rules does ATR have" needs both.
 *
 * The surgical-edit tests run against the REAL stats.json / data/stats.json
 * contents (read-only, never written): a formatting-preserving regex edit is
 * only trustworthy against the file it will actually run on.
 */

import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
// @ts-expect-error -- stdlib-only .mjs script, deliberately untyped (it runs in
// CI without npm install, so it must not depend on the TypeScript toolchain).
import {
  parseRuleMeta,
  isEffective,
  computeCounts,
  setBlockNumber,
} from "../scripts/reconcile-rule-count.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function rule(id: string, status: string, maturity: string): string {
  return `id: ${id}\ntitle: fixture\nstatus: ${status}\nmaturity: ${maturity}\n`;
}

describe("parseRuleMeta", () => {
  it("reads unquoted status and maturity", () => {
    expect(parseRuleMeta(rule("ATR-2026-00001", "experimental", "test"))).toEqual({
      status: "experimental",
      maturity: "test",
    });
  });

  it("reads quoted values (both spellings exist in the corpus)", () => {
    const text = 'id: ATR-2026-00001\nstatus: "draft"\nmaturity: "stable"\n';
    expect(parseRuleMeta(text)).toEqual({ status: "draft", maturity: "stable" });
  });

  it("returns null for a file that is not a rule", () => {
    expect(parseRuleMeta("title: just some yaml\n")).toBeNull();
  });

  it("normalizes an unknown maturity to experimental, never to stable", () => {
    expect(parseRuleMeta(rule("ATR-2026-00001", "experimental", "needs-human-poc"))).toEqual({
      status: "experimental",
      maturity: "experimental",
    });
  });
});

describe("isEffective", () => {
  it("excludes draft — the engine never evaluates it", () => {
    expect(isEffective({ status: "draft", maturity: "stable" })).toBe(false);
  });

  it("excludes deprecated status", () => {
    expect(isEffective({ status: "deprecated", maturity: "stable" })).toBe(false);
  });

  it("excludes a deprecated maturity, which fires in no lane", () => {
    expect(isEffective({ status: "experimental", maturity: "deprecated" })).toBe(false);
  });

  it("includes a live rule at any firing maturity", () => {
    expect(isEffective({ status: "experimental", maturity: "test" })).toBe(true);
    expect(isEffective({ status: "stable", maturity: "stable" })).toBe(true);
  });
});

describe("computeCounts", () => {
  it("separates file count from effective count and reports lane ceilings", () => {
    const root = mkdtempSync(join(tmpdir(), "atr-counts-"));
    mkdirSync(join(root, "prompt-injection"), { recursive: true });
    const put = (name: string, text: string) =>
      writeFileSync(join(root, "prompt-injection", name), text, "utf-8");

    put("a.yaml", rule("ATR-2026-00001", "stable", "stable"));
    put("b.yaml", rule("ATR-2026-00002", "experimental", "test"));
    put("c.yaml", rule("ATR-2026-00003", "draft", "stable"));
    put("d.yaml", rule("ATR-2026-00004", "deprecated", "test"));
    put("e.yaml", rule("ATR-2026-00005", "experimental", "experimental"));
    put("not-a-rule.yaml", "title: no id here\n");

    const counts = computeCounts(root);
    rmSync(root, { recursive: true, force: true });

    expect(counts.total).toBe(5);
    expect(counts.effective).toBe(3);
    expect(counts.inert).toBe(2);
    expect(counts.byStatus).toEqual({ stable: 1, experimental: 2, draft: 1, deprecated: 1 });
    // The draft rule claims maturity: stable but can never reach the enforce lane.
    expect(counts.lanes).toEqual({ enforce: 1, alert: 2, hunt: 3 });
  });

  it("total always equals effective + inert", () => {
    const counts = computeCounts(join(REPO_ROOT, "rules"));
    expect(counts.effective + counts.inert).toBe(counts.total);
    expect(counts.effective).toBeLessThanOrEqual(counts.total);
  });
});

describe("setBlockNumber", () => {
  const doc = ['{', '  "rules": {', '    "total": 10,', '    "categories": 3', "  }", "}"].join("\n");

  it("replaces an existing field and keeps the file parseable", () => {
    const out = setBlockNumber(doc, "rules", "total", 42);
    expect(out.changed).toBe(true);
    expect(out.before).toBe(10);
    expect(JSON.parse(out.text).rules.total).toBe(42);
  });

  it("inserts a missing field after total", () => {
    const out = setBlockNumber(doc, "rules", "effective", 8);
    expect(out.changed).toBe(true);
    expect(out.before).toBeNull();
    const parsed = JSON.parse(out.text);
    expect(parsed.rules.effective).toBe(8);
    expect(parsed.rules.categories).toBe(3);
  });

  it("reports no change when the value already matches", () => {
    const out = setBlockNumber(doc, "rules", "total", 10);
    expect(out.changed).toBe(false);
    expect(out.text).toBe(doc);
  });

  it("returns null for an absent block instead of silently doing nothing", () => {
    expect(setBlockNumber(doc, "noSuchBlock", "total", 1)).toBeNull();
  });

  it("does not touch a same-named field in a different block", () => {
    const two = ['{', '  "a": { "total": 1 },', '  "b": { "total": 2 }', "}"].join("\n");
    const out = setBlockNumber(two, "b", "total", 99);
    const parsed = JSON.parse(out.text);
    expect(parsed.a.total).toBe(1);
    expect(parsed.b.total).toBe(99);
  });

  it("is idempotent", () => {
    const once = setBlockNumber(doc, "rules", "effective", 8).text;
    const twice = setBlockNumber(once, "rules", "effective", 8);
    expect(twice.changed).toBe(false);
    expect(twice.text).toBe(once);
  });
});

describe("surgical edit against the real stats files (read-only)", () => {
  const cases = [
    { path: "stats.json", block: "ruleCount" },
    { path: "data/stats.json", block: "rules" },
  ];

  for (const { path, block } of cases) {
    it(`inserts effective into ${path} without corrupting it`, () => {
      const original = readFileSync(join(REPO_ROOT, path), "utf-8");
      const out = setBlockNumber(original, block, "effective", 672);
      expect(out).not.toBeNull();
      const parsed = JSON.parse(out.text);
      const before = JSON.parse(original);
      expect(parsed[block].effective).toBe(672);
      // Everything else survives byte-for-byte in meaning.
      expect({ ...parsed[block], effective: undefined }).toEqual({
        ...before[block],
        effective: undefined,
      });
      expect(Object.keys(parsed)).toEqual(Object.keys(before));
    });
  }
});
