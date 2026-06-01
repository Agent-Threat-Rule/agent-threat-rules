/**
 * Tests for the collector freshness assessment (scripts/check-collector-freshness.ts).
 * Pure logic only — no filesystem.
 */

import { describe, it, expect } from "vitest";
import { assessSource } from "../scripts/check-collector-freshness.js";

const TODAY = "2026-06-02";
const base = { source: "ghsa", maxAgeDays: 21, exitCode: 0, rateLimited: false, todayDate: TODAY };

describe("assessSource", () => {
  it("is healthy when recent and exit 0", () => {
    const r = assessSource({ ...base, newestDate: "2026-06-01" });
    expect(r.stale).toBe(false);
    expect(r.errored).toBe(false);
    expect(r.ageDays).toBe(1);
  });

  it("flags stale when newest CVE exceeds the threshold", () => {
    const r = assessSource({ ...base, newestDate: "2026-04-01" });
    expect(r.stale).toBe(true);
    expect(r.reasons.join(" ")).toMatch(/old/);
  });

  it("flags errored when the collector exited non-zero", () => {
    const r = assessSource({ ...base, newestDate: "2026-06-01", exitCode: 2 });
    expect(r.errored).toBe(true);
    expect(r.reasons.join(" ")).toMatch(/exit_code=2/);
  });

  it("flags errored when rate-limited", () => {
    const r = assessSource({ ...base, newestDate: "2026-06-01", rateLimited: true });
    expect(r.errored).toBe(true);
    expect(r.reasons.join(" ")).toMatch(/rate-limited/);
  });

  it("flags stale when no dated proposals exist (source produced nothing)", () => {
    const r = assessSource({ ...base, newestDate: null });
    expect(r.stale).toBe(true);
    expect(r.ageDays).toBeNull();
  });

  it("respects a longer threshold for sporadic sources like cisa-kev", () => {
    const r = assessSource({
      ...base,
      source: "cisa-kev",
      maxAgeDays: 120,
      newestDate: "2026-05-11",
    });
    expect(r.stale).toBe(false);
  });
});
