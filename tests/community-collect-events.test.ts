/**
 * The collector writes to the ledger without a person looking at each line,
 * so these tests check what it must never record.
 */
import { describe, it, expect } from "vitest";
import { areaFor, eventForPull, newEvents, type PullRequest } from "../scripts/community/collect-events.js";
import type { LedgerEvent } from "../scripts/community/ledger.js";

const pr = (over: Partial<PullRequest> = {}): PullRequest => ({
  number: 812,
  author: "Alice-Dev",
  author_type: "User",
  merged_by: "eeee2345",
  merged_at: "2026-11-01T10:00:00Z",
  url: "https://github.com/Agent-Threat-Rule/agent-threat-rules/pull/812",
  title: "fix rule",
  ...over,
});

describe("collect-events: eventForPull", () => {
  it("records a merged PR as E1, verified by whoever merged it", () => {
    const e = eventForPull(pr(), ["rules/prompt-injection/x.yaml"]);
    expect(e).toMatchObject({
      id: "E1-atr-pr-812",
      code: "E1",
      actor: "gh:alice-dev",
      date: "2026-11-01",
      verified_by: "maintainer:gh:eeee2345",
      area: "rules",
      subject: "pr-812",
    });
  });

  it("skips a PR merged by its own author", () => {
    expect(eventForPull(pr({ author: "eeee2345" }), [])).toEqual({ skip: "merged by its own author" });
  });

  it("skips bots, by type or by name", () => {
    expect(eventForPull(pr({ author: "renovate", author_type: "Bot" }), [])).toEqual({ skip: "bot author" });
    expect(eventForPull(pr({ author: "github-actions[bot]" }), [])).toEqual({ skip: "bot author" });
  });

  it("skips anything not merged", () => {
    expect(eventForPull(pr({ merged_at: null, merged_by: null }), [])).toEqual({ skip: "not merged" });
  });
});

describe("collect-events: areaFor", () => {
  it("uses the area most of the changed files belong to", () => {
    expect(areaFor(["website/app/x.tsx", "website/app/y.tsx", "rules/a.yaml"])).toBe("community");
    expect(areaFor(["GOVERNANCE.md"])).toBe("governance");
    expect(areaFor(["docs/OWASP-AGENTIC-MAPPING.md"])).toBe("mappings");
    expect(areaFor(["src/engine.ts", "tests/engine.test.ts"])).toBe("rules");
  });

  it("falls back to community when nothing matches", () => {
    expect(areaFor(["README.md"])).toBe("community");
    expect(areaFor([])).toBe("community");
  });
});

describe("collect-events: newEvents", () => {
  it("adds only ids the ledger does not have yet, oldest first", () => {
    const a = eventForPull(pr({ number: 1, merged_at: "2026-10-02T00:00:00Z" }), []) as LedgerEvent;
    const b = eventForPull(pr({ number: 2, merged_at: "2026-09-01T00:00:00Z" }), []) as LedgerEvent;
    expect(newEvents([a], [a, b]).map((e) => e.id)).toEqual(["E1-atr-pr-2"]);
    expect(newEvents([], [a, b]).map((e) => e.id)).toEqual(["E1-atr-pr-2", "E1-atr-pr-1"]);
  });
});
