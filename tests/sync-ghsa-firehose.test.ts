/**
 * Tests for the GHSA firehose discovery gate (scripts/sync-ghsa.ts).
 *
 * The firehose pulls the whole reviewed-advisory stream for pip/npm so NEW
 * agent packages (not in the curated allowlist) self-onboard. firehoseKeep is
 * the gate that decides which of thousands of advisories to look at. It MUST
 * stay narrow: a package name that looks like an agent package, or an
 * unambiguous agent-threat phrase — NOT a generic injection/XSS CVE (which
 * would re-admit the whole ecosystem; that was the 1548-proposal bug).
 */

import { describe, it, expect } from "vitest";
import { firehoseKeep, looksAgentPackage } from "../scripts/sync-ghsa.js";

function adv(name: string, summary = "", description = ""): any {
  return {
    ghsa_id: "GHSA-test",
    summary,
    description,
    vulnerabilities: [{ package: { ecosystem: "pip", name } }],
  };
}

describe("looksAgentPackage", () => {
  it("matches new agent-named packages not in the allowlist", () => {
    for (const n of [
      "some-llm-agent-toolkit",
      "langchain-experimental-foo",
      "my-mcp-server",
      "acme-rag-pipeline",
      "cooltool-genai",
      "autogen-extensions",
    ]) {
      expect(looksAgentPackage(adv(n))).toBe(true);
    }
  });

  it("does not match unrelated packages", () => {
    for (const n of ["requests", "lodash", "express-session", "pillow", "numpy"]) {
      expect(looksAgentPackage(adv(n))).toBe(false);
    }
  });
});

describe("firehoseKeep", () => {
  it("keeps a new agent package by name", () => {
    expect(firehoseKeep(adv("brand-new-llm-agent"))).toBe(true);
  });

  it("keeps a non-agent-named package when the text names an agent threat", () => {
    expect(
      firehoseKeep(adv("random-tool", "Prompt injection in the chat handler")),
    ).toBe(true);
    expect(
      firehoseKeep(adv("some-server", "Tool poisoning via the MCP server config")),
    ).toBe(true);
  });

  it("DROPS a generic SQL-injection CVE in an unrelated package (the 1548 bug)", () => {
    expect(
      firehoseKeep(adv("express-session", "SQL injection vulnerability in session store")),
    ).toBe(false);
  });

  it("DROPS a generic XSS / SSRF CVE in an unrelated web package", () => {
    expect(firehoseKeep(adv("web-widget", "Reflected XSS in the search box"))).toBe(false);
    expect(firehoseKeep(adv("http-proxy", "SSRF in the request forwarder"))).toBe(false);
  });
});
