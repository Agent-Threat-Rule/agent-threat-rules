/**
 * src/re2.ts mirrors scanPattern in scripts/audit-re2-portability.ts, which
 * gates the corpus in CI but is not shipped in the package. Both must reach
 * the same verdict on every regex condition in rules/.
 */
import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { loadRulesFromDirectory } from "../src/loader.js";
import { regexConditionSpec } from "../src/regex-dialect.js";
import { re2Constructs, toRe2 } from "../src/re2.js";
import { scanPattern } from "../scripts/audit-re2-portability.js";

const rules = loadRulesFromDirectory(resolve(__dirname, "..", "rules"));

const patterns = rules.flatMap((rule) =>
  Array.isArray(rule.detection.conditions)
    ? rule.detection.conditions
        .filter((c) => c.operator === "regex" && c.value)
        .map((c) => ({ id: rule.id, source: regexConditionSpec(c.value).source }))
    : [],
);

describe("re2Constructs", () => {
  it("agrees with the CI audit on every condition in rules/", () => {
    expect(patterns.length).toBeGreaterThan(1000);
    const disagreements = patterns.filter(
      (p) => JSON.stringify(re2Constructs(p.source)) !== JSON.stringify(scanPattern(p.source).map((f) => f.cls)),
    );
    expect(disagreements).toEqual([]);
  });
});

describe("toRe2", () => {
  it("rewrites JS-only spellings", () => {
    expect(toRe2("a\\u200bb")).toBe("a\\x{200b}b");
    expect(toRe2("\\u{E0041}")).toBe("\\x{E0041}");
    expect(toRe2("(?<word>x)")).toBe("(?P<word>x)");
  });

  it("leaves a literal backslash followed by u alone", () => {
    expect(toRe2("\\\\u2066")).toBe("\\\\u2066");
    expect(toRe2("[\\\\]u200b")).toBe("[\\\\]u200b");
  });

  it("joins surrogate pairs into code points", () => {
    expect(toRe2("\\uD83D\\uDE00")).toBe("\\x{1F600}");
    expect(toRe2("(?:\\uDB40[\\uDC00-\\uDC7F]){3,}")).toBe("(?:[\\x{E0000}-\\x{E007F}]){3,}");
  });

  it("refuses a surrogate escape it cannot join", () => {
    expect(toRe2("\\uD83D")).toBeNull();
    expect(toRe2("\\uDE00")).toBeNull();
    expect(toRe2("[\\uD800-\\uDBFF]")).toBeNull();
  });

  it("refuses constructs RE2 cannot express", () => {
    expect(toRe2("(?<!x)y")).toBeNull();
    expect(toRe2("(?=x)y")).toBeNull();
    expect(toRe2("(a)\\1")).toBeNull();
    expect(toRe2("a{2000}")).toBeNull();
  });
});
