/**
 * Tests for the human-PoC backlog issue formatter
 * (scripts/format-poc-backlog-issue.ts).
 *
 * The formatter turns a promote-detection-ready.ts report into the markdown
 * body for the rolling "proposals awaiting human PoC" issue. It must list
 * ONLY prose-only (needs-human-poc) proposals -- never the PoC-grounded ones
 * that were promoted into rules/.
 *
 * Run with: npx vitest tests/format-poc-backlog-issue.test.ts
 */

import { describe, it, expect } from "vitest";
import {
  formatBacklogIssue,
  type PromoteReport,
} from "../scripts/format-poc-backlog-issue.js";

describe("format-poc-backlog-issue", () => {
  it("lists only needs-human-poc rows, excluding promoted/no-pattern", () => {
    const report: PromoteReport = {
      results: [
        {
          proposal: "proposals/ghsa/CVE-1.proposal.yaml",
          draft_id: "ATR-DRAFT-CVE-1",
          title: "Promoted PoC rule",
          status: "promoted",
        },
        {
          proposal: "proposals/nvd/CVE-2.proposal.yaml",
          draft_id: "ATR-DRAFT-CVE-2",
          title: "Prose only",
          status: "needs-human-poc",
        },
        {
          proposal: "proposals/cisa-kev/CVE-3.proposal.yaml",
          draft_id: "ATR-DRAFT-CVE-3",
          title: "No patterns",
          status: "no-patterns",
        },
      ],
    };
    const body = formatBacklogIssue(report);
    expect(body).toContain("proposals/nvd/CVE-2.proposal.yaml");
    // promoted + no-pattern proposals must NOT appear in the queue
    expect(body).not.toContain("proposals/ghsa/CVE-1.proposal.yaml");
    expect(body).not.toContain("proposals/cisa-kev/CVE-3.proposal.yaml");
    expect(body).toContain("1 proposal(s) awaiting a PoC");
  });

  it("escapes pipe characters in titles so the md table can't break", () => {
    const report: PromoteReport = {
      results: [
        {
          proposal: "proposals/nvd/CVE-9.proposal.yaml",
          draft_id: "ATR-DRAFT-CVE-9",
          title: "SQLi | injection",
          status: "needs-human-poc",
        },
      ],
    };
    const body = formatBacklogIssue(report);
    expect(body).toContain("SQLi \\| injection");
  });

  it("collapses multi-line titles into a single cell", () => {
    const report: PromoteReport = {
      results: [
        {
          proposal: "proposals/nvd/CVE-10.proposal.yaml",
          draft_id: "ATR-DRAFT-CVE-10",
          title: "line one\n  line two",
          status: "needs-human-poc",
        },
      ],
    };
    const body = formatBacklogIssue(report);
    expect(body).toContain("line one line two");
    expect(body).not.toContain("line one\n  line two");
  });

  it("renders an empty table and zero count for no needs-human-poc rows", () => {
    const report: PromoteReport = {
      results: [
        {
          proposal: "proposals/ghsa/CVE-1.proposal.yaml",
          status: "promoted",
        },
      ],
    };
    const body = formatBacklogIssue(report);
    expect(body).toContain("0 proposal(s) awaiting a PoC");
    expect(body).toContain("| Proposal | Draft ID | Title |");
  });

  it("tolerates a report with no results array", () => {
    const body = formatBacklogIssue({});
    expect(body).toContain("0 proposal(s) awaiting a PoC");
  });

  it("falls back to an em dash when draft_id is missing", () => {
    const report: PromoteReport = {
      results: [
        {
          proposal: "proposals/nvd/CVE-11.proposal.yaml",
          title: "no draft id",
          status: "needs-human-poc",
        },
      ],
    };
    const body = formatBacklogIssue(report);
    expect(body).toContain("CVE-11.proposal.yaml");
    expect(body).toContain("| — |");
  });
});
