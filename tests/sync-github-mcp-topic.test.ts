/**
 * Tests for the pure filter/partition logic in
 * scripts/sync-github-mcp-topic.ts. These are the heuristics that decide
 * what survives into the wild-scan GitHub-topic corpus, so the boundaries
 * matter: too loose and the noisiest wild-scan source stays noisy, too
 * tight and real MCP servers silently disappear.
 *
 * Network calls (search API, contents API, raw.githubusercontent.com) are
 * NOT exercised here — those are covered by the small-sample manual run
 * documented in data/wild-scan/github-topic/README.md. This file only pins
 * down the deterministic logic: fork/staleness checks, the template-junk
 * keyword gate, and the star/date range bisection used by --full-coverage.
 *
 * Run with: npx vitest run tests/sync-github-mcp-topic.test.ts
 */

import { describe, it, expect } from "vitest";
import {
  isForkItem,
  isStaleItem,
  templateJunkVerdict,
  bisectStarRange,
  bisectDateRange,
  TEMPLATE_JUNK_KEYWORDS,
} from "../scripts/sync-github-mcp-topic.js";

describe("isForkItem", () => {
  it("flags fork:true", () => {
    expect(isForkItem({ fork: true })).toBe(true);
  });
  it("does not flag fork:false", () => {
    expect(isForkItem({ fork: false })).toBe(false);
  });
});

describe("isStaleItem", () => {
  const cutoff = "2025-07-12";
  it("flags a repo pushed before the cutoff", () => {
    expect(isStaleItem({ pushed_at: "2024-01-01T00:00:00Z" }, cutoff)).toBe(true);
  });
  it("keeps a repo pushed after the cutoff", () => {
    expect(isStaleItem({ pushed_at: "2026-06-01T00:00:00Z" }, cutoff)).toBe(false);
  });
  it("keeps a repo pushed exactly on the cutoff day", () => {
    expect(isStaleItem({ pushed_at: "2025-07-12T23:59:59Z" }, cutoff)).toBe(false);
  });
  it("treats a missing pushed_at as stale (fail closed)", () => {
    expect(isStaleItem({ pushed_at: "" }, cutoff)).toBe(true);
  });
});

describe("templateJunkVerdict", () => {
  it("drops a repo whose name is a tutorial", () => {
    const v = templateJunkVerdict("someone/mcp-server-tutorial", "Learn MCP");
    expect(v.junk).toBe(true);
    expect(v.field).toBe("name");
  });
  it("drops a repo whose name is an awesome-list, not a server", () => {
    const v = templateJunkVerdict("someone/awesome-mcp-servers", "A curated list");
    expect(v.junk).toBe(true);
  });
  it("drops via description when the name is clean", () => {
    const v = templateJunkVerdict("someone/clean-name-here", "A boilerplate for building MCP servers");
    expect(v.junk).toBe(true);
    expect(v.field).toBe("description");
  });
  it("keeps a real-looking MCP server name and description", () => {
    const v = templateJunkVerdict("acme/postgres-mcp-server", "MCP server for querying Postgres databases");
    expect(v.junk).toBe(false);
  });
  it("does not false-positive on substrings inside unrelated words", () => {
    // "exemplary" contains "example" as a naive substring but not as a
    // bounded token — must NOT match.
    const v = templateJunkVerdict("acme/exemplary-tools", "An exemplary integration");
    expect(v.junk).toBe(false);
  });
  it("every declared keyword is actually catchable via the bounded regex", () => {
    for (const kw of TEMPLATE_JUNK_KEYWORDS) {
      const v = templateJunkVerdict(`someone/mcp-${kw}-server`, null);
      expect(v.junk, `expected "${kw}" to match as a bounded token`).toBe(true);
    }
  });
});

describe("bisectStarRange", () => {
  it("splits a wide range into two non-overlapping halves", () => {
    const r = bisectStarRange(0, 999);
    expect(r).not.toBeNull();
    expect(r!.left).toEqual([0, 499]);
    expect(r!.right).toEqual([500, 999]);
  });
  it("splits adjacent integers into two single-value buckets", () => {
    const r = bisectStarRange(0, 1);
    expect(r).toEqual({ left: [0, 0], right: [1, 1] });
  });
  it("cannot split a single star value further", () => {
    expect(bisectStarRange(5, 5)).toBeNull();
  });
});

describe("bisectDateRange", () => {
  it("splits a wide window into two halves", () => {
    const r = bisectDateRange("2025-01-01", "2025-01-11");
    expect(r).not.toBeNull();
    expect(r!.left[0]).toBe("2025-01-01");
    expect(r!.right[1]).toBe("2025-01-11");
    // No gap or overlap at the boundary.
    const leftEndPlusOne = new Date(r!.left[1]);
    leftEndPlusOne.setUTCDate(leftEndPlusOne.getUTCDate() + 1);
    expect(leftEndPlusOne.toISOString().slice(0, 10)).toBe(r!.right[0]);
  });
  it("cannot split a single-day window further", () => {
    expect(bisectDateRange("2025-01-01", "2025-01-01")).toBeNull();
  });
});
