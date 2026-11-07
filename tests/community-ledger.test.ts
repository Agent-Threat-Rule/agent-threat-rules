/**
 * The ledger decides who holds which tier, so the tests below check mostly
 * that it refuses: bad events, self-verification, money, and seats that only
 * people may grant.
 */
import { readFileSync } from "node:fs";
import { describe, it, expect, vi } from "vitest";
import {
  computeMembers,
  eventProblems,
  parseLedger,
  parseTiers,
  type LedgerEvent,
} from "../scripts/community/ledger.js";

const TODAY = "2026-11-07";
const CODES_ALL = ["E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9"] as const;
const config = parseTiers(readFileSync(new URL("../community/tiers.yaml", import.meta.url), "utf8"));

let n = 0;
function ev(over: Partial<LedgerEvent>): LedgerEvent {
  n += 1;
  return {
    id: `E-test-${n}`,
    code: "E1",
    actor: "gh:alice",
    date: "2026-11-01",
    evidence: "https://github.com/Agent-Threat-Rule/agent-threat-rules/pull/1",
    verified_by: "ci",
    area: "rules",
    ...over,
  } as LedgerEvent;
}

function statusOf(events: LedgerEvent[], actor = "gh:alice") {
  return computeMembers(events, config, TODAY).find((m) => m.actor === actor);
}

describe("community ledger: what counts as an event", () => {
  it("accepts a well-formed event", () => {
    expect(eventProblems(ev({}) as unknown as Record<string, unknown>)).toEqual([]);
  });

  it("refuses self-verification", () => {
    const e = ev({ verified_by: "maintainer:gh:alice" }) as unknown as Record<string, unknown>;
    expect(eventProblems(e)).toContain("nobody verifies their own event");
  });

  it("refuses codes that do not exist, including anything about payment", () => {
    const e = { ...ev({}), code: "PAID" } as unknown as Record<string, unknown>;
    expect(eventProblems(e).join()).toMatch(/unknown code/);
  });

  it("refuses unknown fields so nothing extra rides along", () => {
    const e = { ...ev({}), sponsor_tier: "gold" } as unknown as Record<string, unknown>;
    expect(eventProblems(e)).toContain("unknown field sponsor_tier");
  });

  it("refuses non-https evidence and adoption by a person", () => {
    const e = ev({ code: "E7", evidence: "http://example.com" }) as unknown as Record<string, unknown>;
    const problems = eventProblems(e);
    expect(problems).toContain("evidence must be an https link");
    expect(problems).toContain("E7 (adoption) belongs to an org: actor");
  });

  it("reports invalid JSON and duplicate ids by line", () => {
    const a = JSON.stringify(ev({ id: "E1-dup" }));
    const { events, errors } = parseLedger(`${a}\n\nnot json\n${a}\n`);
    expect(events).toHaveLength(1);
    expect(errors).toEqual(["line 3: not valid JSON", "line 4: duplicate id E1-dup"]);
  });
});

describe("community ledger: tiers", () => {
  it("one accepted contribution makes a contributor", () => {
    expect(statusOf([ev({})])?.granted).toEqual(["contributor"]);
  });

  it("a confirmed defect or an accepted question also counts", () => {
    expect(statusOf([ev({ code: "E3" })])?.granted).toContain("contributor");
    expect(statusOf([ev({ code: "E9", area: "atomics" })])?.granted).toContain("contributor");
  });

  it("reviewer is only nominated, and needs three reviews on two subjects within 60 days", () => {
    const three = [1, 2, 3].map((i) => ev({ code: "E2", subject: i === 3 ? "pr-1" : `pr-${i}` }));
    const status = statusOf(three);
    expect(status?.nominated).toEqual(["reviewer"]);
    expect(status?.granted).not.toContain("reviewer");

    const sameSubject = [1, 2, 3].map(() => ev({ code: "E2", subject: "pr-9" }));
    expect(statusOf(sameSubject)?.nominated).toEqual([]);

    const old = [1, 2, 3].map((i) => ev({ code: "E2", subject: `pr-${i}`, date: "2026-08-01" }));
    expect(statusOf(old)?.nominated).toEqual([]);
  });

  it("re-runner needs a receipt verified by CI, not by a person", () => {
    expect(statusOf([ev({ code: "E4", verified_by: "ci" })])?.granted).toContain("re_runner");
    expect(statusOf([ev({ code: "E4", verified_by: "maintainer:gh:eeee2345" })])?.granted).not.toContain("re_runner");
  });

  it("question author needs three accepted questions and one adoption", () => {
    const three = [1, 2, 3].map((i) => ev({ code: "E9", subject: `AT-${i}`, area: "atomics" }));
    expect(statusOf(three)?.granted).not.toContain("question_author");
    expect(statusOf([...three, ev({ code: "E8", area: "atomics" })])?.granted).toContain("question_author");
  });

  it("never computes advisor or TSC seats, whatever the ledger says", () => {
    const lots = CODES_ALL.flatMap((code) => [1, 2, 3, 4].map((i) => ev({ code, subject: `s-${i}` })));
    const status = statusOf(lots.filter((e) => e.code !== "E7"));
    expect(status?.granted).not.toContain("advisor");
    expect(status?.granted).not.toContain("tsc");
    expect(status?.nominated).not.toContain("advisor");
  });

  it("working-on shows only areas with events in the last 90 days", () => {
    const status = statusOf([ev({ area: "mappings" }), ev({ area: "nodes", date: "2026-06-01" })]);
    expect(status?.working_on).toEqual(["mappings"]);
    expect(status?.last_activity).toBe("2026-11-01");
  });

  it("ignores events dated after today", () => {
    expect(statusOf([ev({ date: "2027-01-01" })])?.granted).toEqual([]);
  });
});

describe("community ledger: the committed files", () => {
  it("community/ledger.jsonl is valid", () => {
    const text = readFileSync(new URL("../community/ledger.jsonl", import.meta.url), "utf8");
    expect(parseLedger(text).errors).toEqual([]);
  });

  it("importing the module does not run the CLI", async () => {
    const write = vi.spyOn(process.stdout, "write");
    try {
      await import("../scripts/community/ledger.js");
      expect(write).not.toHaveBeenCalled();
    } finally {
      write.mockRestore();
    }
  });
});

