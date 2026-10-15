/**
 * Tests for scripts/lib/fn-mine-gate.ts — which of this run's authored rules a
 * failed safety gate rejected, and what the miner does when it cannot tell.
 *
 * Since the lane resumes fn-mine/rolling, the gate sees two kinds of new rule:
 * the rules already waiting in the rolling PR and the ones this run authored.
 * Check 5 (cross-rule conflict) names the OFFENDER, so when a waiting rule
 * matches a true-negative this run wrote, the failure line names the waiting
 * rule's file. The miner only looked for its own files on those lines, found
 * none, and dropped the whole batch as a quiet "null result". These tests pin
 * the replacement: blame the TN owner this run wrote, and fail loudly when a
 * failure names nothing this run authored.
 */
import { describe, it, expect } from "vitest";
import {
  attributeGateFailures,
  gateAuthoredBatch,
  GateAttributionError,
  type GateRun,
} from "../scripts/lib/fn-mine-gate.js";

const PENDING = "rules/prompt-injection/ATR-2026-99990-pending.yaml";
const A = { id: "ATR-2026-99991", file: "rules/prompt-injection/ATR-2026-99991-authored.yaml" };
const B = { id: "ATR-2026-99992", file: "rules/prompt-injection/ATR-2026-99992-unrelated.yaml" };
const C = { id: "ATR-2026-99993", file: "rules/agent-manipulation/ATR-2026-99993-third.yaml" };

/** The exact line shape check-rules-safety.ts prints for a failure. */
function failLine(file: string, reason: string): string {
  return `  ✗ ${file} — ${reason}`;
}

function crossRule(...owners: string[]): string {
  const shown = owners.slice(0, 2).map((o) => `conflicts with ${o}'s TN: "some benign sample text..."`);
  const more = owners.length > 2 ? `, +${owners.length - 2} more` : "";
  return `cross-rule conflict: ${shown.join(" | ")}${more}`;
}

function gateOutput(...lines: string[]): string {
  return [
    "[safety-gate] base=origin/main",
    "[safety-gate] 3 new rule file(s) detected (2 uncommitted, discovered on disk)",
    `[safety-gate] FAIL — ${lines.length} rule(s) need human review:`,
    ...lines,
    "",
  ].join("\n");
}

const PASS: GateRun = { pass: true, raw: "[safety-gate] PASS — 3 rule(s) safe to auto-merge\n" };
const fail = (...lines: string[]): GateRun => ({ pass: false, raw: gateOutput(...lines) });

describe("attributeGateFailures", () => {
  it("blames this run's TN owner when a waiting rule is the offender", () => {
    const res = attributeGateFailures(gateOutput(failLine(PENDING, crossRule(A.id))), [A, B]);
    expect([...res.blamed.keys()]).toEqual([A.file]);
    expect(res.blamed.get(A.file)?.[0]).toContain(PENDING);
    expect(res.unattributed).toEqual([]);
  });

  it("blames an authored rule the gate names directly", () => {
    const res = attributeGateFailures(gateOutput(failLine(A.file, "own TP not matched")), [A, B]);
    expect([...res.blamed.keys()]).toEqual([A.file]);
  });

  it("accepts the rule id the gate prints when it has no file for it", () => {
    const res = attributeGateFailures(gateOutput(failLine(B.id, "matched 1 benign sample")), [A, B]);
    expect([...res.blamed.keys()]).toEqual([B.file]);
  });

  it("blames every authored owner listed on one line", () => {
    const res = attributeGateFailures(gateOutput(failLine(PENDING, crossRule(A.id, B.id, C.id))), [A, B, C]);
    expect([...res.blamed.keys()].sort()).toEqual([A.file, B.file].sort());
  });

  it("reports a failure that names nothing this run authored", () => {
    const res = attributeGateFailures(
      gateOutput(failLine(PENDING, crossRule("ATR-2026-00003")), "  ✗ git diff failed: bad revision"),
      [A, B],
    );
    expect(res.blamed.size).toBe(0);
    expect(res.unattributed).toHaveLength(2);
    expect(res.unattributed[0]).toContain(PENDING);
  });

  it("finds nothing to blame in a failure without ✗ lines", () => {
    const raw = "[safety-gate] FAIL — 12 new rules exceeds MAX_NEW_PER_PR=10. Human review required.\n";
    const res = attributeGateFailures(raw, [A]);
    expect(res.blamed.size).toBe(0);
    expect(res.unattributed).toEqual([]);
  });
});

function runner(...runs: GateRun[]): { runGate: () => GateRun; calls: () => number } {
  let i = 0;
  return {
    runGate: () => {
      const r = runs[Math.min(i, runs.length - 1)];
      i++;
      return r;
    },
    calls: () => i,
  };
}

describe("gateAuthoredBatch", () => {
  it("drops only the rule whose TN a waiting rule matches, and keeps the rest", () => {
    const discarded: string[] = [];
    const { runGate, calls } = runner(fail(failLine(PENDING, crossRule(A.id))), PASS);
    const kept = gateAuthoredBatch([A, B], runGate, (r) => discarded.push(r.id));
    expect(kept).toEqual([B]);
    expect(discarded).toEqual([A.id]);
    expect(calls()).toBe(2);
  });

  it("hands each discarded rule the gate lines that blamed it", () => {
    const seen: string[][] = [];
    const { runGate } = runner(fail(failLine(PENDING, crossRule(A.id))), PASS);
    gateAuthoredBatch([A, B], runGate, (_r, lines) => seen.push([...lines]));
    expect(seen).toHaveLength(1);
    expect(seen[0][0]).toContain(`conflicts with ${A.id}'s TN`);
  });

  it("re-runs the gate after every drop until it passes — the gate shows two conflicts per offender", () => {
    const { runGate, calls } = runner(
      fail(failLine(PENDING, crossRule(A.id, A.id, B.id))),
      fail(failLine(PENDING, crossRule(B.id))),
      PASS,
    );
    const kept = gateAuthoredBatch([A, B, C], runGate, () => undefined);
    expect(kept).toEqual([C]);
    expect(calls()).toBe(3);
  });

  it("returns an empty batch when the gate rejects every authored rule", () => {
    const { runGate, calls } = runner(fail(failLine(A.file, "own TP not matched"), failLine(PENDING, crossRule(B.id))));
    expect(gateAuthoredBatch([A, B], runGate, () => undefined)).toEqual([]);
    expect(calls()).toBe(1);
  });

  it("fails the run, naming the line, when a failure is not attributable to this run", () => {
    const { runGate } = runner(fail(failLine(PENDING, crossRule("ATR-2026-00003"))));
    const discarded: string[] = [];
    const err = (() => {
      try {
        gateAuthoredBatch([A, B], runGate, (r) => discarded.push(r.id));
      } catch (e) {
        return e;
      }
      return null;
    })();
    expect(err).toBeInstanceOf(GateAttributionError);
    expect(String((err as Error).message)).toContain(PENDING);
    expect(discarded).toEqual([]);
  });

  it("fails the run instead of going quiet when an unattributable failure rides along with an attributable one", () => {
    const { runGate } = runner(fail(failLine(A.file, "own TP not matched"), "  ✗ data/benign-corpus-extended — census below floor"));
    expect(() => gateAuthoredBatch([A], runGate, () => undefined)).toThrow(GateAttributionError);
  });

  it("fails the run when the gate fails without naming any file", () => {
    const { runGate } = runner({ pass: false, raw: "[safety-gate] FAIL — 12 new rules exceeds MAX_NEW_PER_PR=10.\n" });
    expect(() => gateAuthoredBatch([A], runGate, () => undefined)).toThrow(/MAX_NEW_PER_PR/);
  });

  it("does not run the gate for an empty batch", () => {
    const { runGate, calls } = runner(PASS);
    expect(gateAuthoredBatch([], runGate, () => undefined)).toEqual([]);
    expect(calls()).toBe(0);
  });

  it("does not mutate the batch it was given", () => {
    const batch = Object.freeze([A, B]);
    const { runGate } = runner(fail(failLine(PENDING, crossRule(A.id))), PASS);
    expect(() => gateAuthoredBatch(batch, runGate, () => undefined)).not.toThrow();
    expect(batch).toEqual([A, B]);
  });
});
