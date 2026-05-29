/**
 * Tests for the agent-relevance gate in scripts/sync-ghsa.ts.
 *
 * ATR is an AI-AGENT detection standard. The GHSA collector queries an
 * agent-package allowlist, but an allowlisted package can still carry
 * advisories that are real bugs yet have zero agent-runtime relevance
 * (memory-safety crashes, pure DoS, ML-kernel CHECK-fails). agentRelevance()
 * is the second gate that drops those. These tests pin the boundary.
 *
 * Run with: npx vitest tests/sync-ghsa-relevance.test.ts
 */

import { describe, it, expect } from "vitest";
import { agentRelevance } from "../scripts/sync-ghsa.js";

describe("agentRelevance gate", () => {
  it("drops a TensorFlow-style kernel CHECK-fail (no relevant CWE, no keyword)", () => {
    const r = agentRelevance({
      summary: "TensorFlow vulnerable to `CHECK` fail in `AvgPoolGrad`",
      description:
        "A malformed input to AvgPoolGrad triggers a CHECK failure and aborts the process.",
      cwes: [{ cwe_id: "CWE-617" }], // reachable assertion — excluded
    });
    expect(r.relevant).toBe(false);
  });

  it("drops a pure denial-of-service with no injection signal", () => {
    const r = agentRelevance({
      summary: "Denial of service in langchain-community",
      description: "A crafted document causes unbounded memory growth.",
      cwes: [{ cwe_id: "CWE-400" }], // uncontrolled resource consumption — excluded
    });
    expect(r.relevant).toBe(false);
  });

  it("keeps an SSRF advisory via agent-relevant CWE", () => {
    const r = agentRelevance({
      summary:
        "LangChain affected by SSRF via image_url token counting in ChatOpenAI",
      description: "The agent fetches an attacker-controlled URL.",
      cwes: [{ cwe_id: "CWE-918" }],
    });
    expect(r.relevant).toBe(true);
    expect(r.reason).toContain("CWE-918");
  });

  it("keeps a deserialization RCE via agent-relevant CWE", () => {
    const r = agentRelevance({
      summary: "LangSmith SDK deserializes untrusted prompt manifests",
      description: "Pulling a public prompt loads a pickle without a trust boundary.",
      cwes: [{ cwe_id: "CWE-502" }],
    });
    expect(r.relevant).toBe(true);
    expect(r.reason).toContain("CWE-502");
  });

  it("keeps an MCP advisory via keyword even with no mapped CWE", () => {
    const r = agentRelevance({
      summary: "MCP Python SDK vulnerability in the FastMCP Server",
      description: "A validation error in the MCP server leads to a crash.",
      cwes: [],
    });
    expect(r.relevant).toBe(true);
    expect(r.reason).toMatch(/keyword/);
  });

  it("keeps a prompt-injection advisory via keyword", () => {
    const r = agentRelevance({
      summary: "Prompt injection in tool description handling",
      description: "A poisoned tool description overrides the system prompt.",
      cwes: [],
    });
    expect(r.relevant).toBe(true);
    expect(r.reason).toMatch(/keyword/);
  });

  it("keeps an arbitrary-code-execution advisory via keyword", () => {
    const r = agentRelevance({
      summary: "crewai tool allows arbitrary code execution",
      description: "Unsanitized tool args reach exec().",
      cwes: [],
    });
    expect(r.relevant).toBe(true);
  });

  it("drops a generic non-injection bug with no CWE and no keyword", () => {
    const r = agentRelevance({
      summary: "Incorrect default timeout value in langchain",
      description: "The default request timeout is longer than documented.",
      cwes: [],
    });
    expect(r.relevant).toBe(false);
    expect(r.reason).toContain("no agent-relevant CWE or keyword");
  });

  it("does not false-match the substring 'mcp' inside 'fastmcp' alone", () => {
    // 'fastmcp' contains 'mcp' but not as a \\bmcp\\b word; with no other
    // signal this generic note should be dropped.
    const r = agentRelevance({
      summary: "fastmcp documentation typo",
      description: "A docstring in the fastmcp package is misleading.",
      cwes: [],
    });
    expect(r.relevant).toBe(false);
  });
});
