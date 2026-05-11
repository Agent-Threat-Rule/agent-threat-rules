import { describe, it, expect } from "vitest";
import { redactMatchedValue, redactMatchedValues } from "../src/redact.js";

describe("redactMatchedValue", () => {
  it("redacts an AWS access key with class label and head bytes only", () => {
    const out = redactMatchedValue("AKIAIOSFODNN7EXAMPLE");
    expect(out).toContain("aws_access_key_id");
    expect(out).toContain('head="AKIA"');
    expect(out).not.toContain("IOSFODNN7EXAMPLE");
  });

  it("redacts a GitHub PAT", () => {
    const out = redactMatchedValue("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789");
    expect(out).toContain("github_personal_token");
    expect(out).not.toContain("aBcDeFgHi");
  });

  it("redacts an OpenAI key", () => {
    const out = redactMatchedValue("sk-abc123xyz789secretvalue");
    expect(out).toContain("openai_or_compatible_secret");
    expect(out).not.toContain("secretvalue");
  });

  it("redacts a Slack token", () => {
    const out = redactMatchedValue("xoxb-1234-5678-secretvalue");
    expect(out).toContain("slack_token");
    expect(out).not.toContain("secretvalue");
  });

  it("redacts a JWT", () => {
    const out = redactMatchedValue("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature");
    expect(out).toContain("jwt_or_jose");
    expect(out).not.toContain("signature");
  });

  it("redacts an unknown value with generic class", () => {
    const out = redactMatchedValue("totally-random-value-1234567890");
    expect(out).toContain("[redacted");
    expect(out).not.toContain("1234567890");
  });

  it("preserves length information", () => {
    const out = redactMatchedValue("AKIA0123456789012345");
    expect(out).toContain("len=20");
  });

  it("respects headBytes=0", () => {
    const out = redactMatchedValue("AKIAIOSFODNN7EXAMPLE", { headBytes: 0 });
    expect(out).toContain('head=""');
  });

  it("caps output length", () => {
    const long = "AKIA" + "X".repeat(500);
    const out = redactMatchedValue(long, { maxLength: 40 });
    expect(out.length).toBeLessThanOrEqual(40);
  });

  it("handles empty input", () => {
    expect(redactMatchedValue("")).toBe("[redacted:empty]");
  });

  it("handles non-string input safely", () => {
    expect(redactMatchedValue(undefined as unknown as string)).toBe("[redacted:non-string]");
    expect(redactMatchedValue(null as unknown as string)).toBe("[redacted:non-string]");
  });

  it("identifies Bearer tokens case-insensitively", () => {
    const out = redactMatchedValue("Bearer eyJabcDEFsecret");
    expect(out).toContain("bearer_credential");
    expect(out).not.toContain("eyJabcDEFsecret");
  });
});

describe("redactMatchedValues", () => {
  it("redacts every entry", () => {
    const out = redactMatchedValues([
      "AKIA0123456789012345",
      "ghp_abcdefghijklmnopqrstuvwxyz",
      "totally-random-value",
    ]);
    expect(out).toHaveLength(3);
    expect(out[0]).toContain("aws_access_key_id");
    expect(out[1]).toContain("github_personal_token");
    expect(out[2]).toContain("[redacted");
    expect(out[0]).not.toContain("9012345");
    expect(out[1]).not.toContain("ijklmno");
  });
});
