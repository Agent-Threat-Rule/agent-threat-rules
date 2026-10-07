/**
 * Tests for scripts/lib/normalize-references.ts
 *
 * The semantic lane copies `references.owasp_llm` out of a cluster proposal.
 * Proposals carry "ID - Title" strings, and some carry the title an identifier
 * held in an older edition of the list. validate:compliance rejects any
 * embedded title, and an identifier that names a different risk than its title
 * is a wrong mapping, not a formatting problem. These tests pin the repair:
 * bare identifiers only, every one present in the allowlist, a mismatched
 * title resolved by the title rather than by the number.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  loadOwaspAllowlists,
  normalizeFrameworkRefs,
  normalizeReferences,
  DEFAULT_OWASP_AGENTIC_BY_CATEGORY,
  DEFAULT_OWASP_LLM_BY_CATEGORY,
} from "../scripts/lib/normalize-references.js";

const REPO_ROOT = resolve(import.meta.dirname, "..");
const allowlists = loadOwaspAllowlists(REPO_ROOT);

function validIds(framework: "owasp_llm" | "owasp_agentic"): Set<string> {
  const raw = JSON.parse(
    readFileSync(join(REPO_ROOT, "data/compliance-frameworks", `${framework}.json`), "utf-8"),
  ) as { valids: Record<string, string> };
  return new Set(Object.keys(raw.valids));
}

const CATEGORIES = [
  "agent-manipulation",
  "context-exfiltration",
  "data-poisoning",
  "excessive-autonomy",
  "model-abuse",
  "privilege-escalation",
  "prompt-injection",
  "skill-compromise",
  "tool-poisoning",
] as const;

describe("normalizeFrameworkRefs", () => {
  it("strips a matching embedded title down to the bare identifier", () => {
    expect(normalizeFrameworkRefs(["LLM01:2025 - Prompt Injection"], allowlists.owasp_llm)).toEqual([
      "LLM01:2025",
    ]);
  });

  it("keeps a bare identifier that exists in the allowlist", () => {
    expect(normalizeFrameworkRefs(["LLM07:2025"], allowlists.owasp_llm)).toEqual(["LLM07:2025"]);
  });

  // The 02850 defect: LLM06 in the 2025 list is Excessive Agency. The proposal
  // paired it with the 2023 title, which in 2025 is LLM02. The title is the
  // author's intent; the number is the part that drifted.
  it("resolves a mismatched title by the title, not by the number", () => {
    expect(
      normalizeFrameworkRefs(["LLM06:2025 - Sensitive Information Disclosure"], allowlists.owasp_llm),
    ).toEqual(["LLM02:2025"]);
  });

  it("resolves an out-of-edition identifier by its title", () => {
    expect(
      normalizeFrameworkRefs(["LLM06:2023 - Sensitive Information Disclosure"], allowlists.owasp_llm),
    ).toEqual(["LLM02:2025"]);
  });

  it("matches titles regardless of case, spacing and '&' vs 'and'", () => {
    expect(
      normalizeFrameworkRefs(["ASI06:2026 - memory and context   poisoning"], allowlists.owasp_agentic),
    ).toEqual(["ASI06:2026"]);
  });

  it("drops an entry whose title names no risk in the allowlist", () => {
    // ASI03 is Identity and Privilege Abuse; no 2026 risk is titled this.
    expect(
      normalizeFrameworkRefs(["ASI03:2026 - Data Exfiltration via Agent"], allowlists.owasp_agentic),
    ).toEqual([]);
  });

  it("drops an unknown bare identifier and anything that is not a string", () => {
    expect(
      normalizeFrameworkRefs(["LLM11:2025", "LLM01", "", 42 as unknown as string], allowlists.owasp_llm),
    ).toEqual([]);
  });

  it("de-duplicates while keeping first-seen order", () => {
    expect(
      normalizeFrameworkRefs(
        ["LLM07:2025", "LLM01:2025 - Prompt Injection", "LLM07:2025 - System Prompt Leakage", "LLM01:2025"],
        allowlists.owasp_llm,
      ),
    ).toEqual(["LLM07:2025", "LLM01:2025"]);
  });
});

describe("normalizeReferences", () => {
  it("repairs the 02850 proposal references end to end", () => {
    const out = normalizeReferences(
      {
        category: "prompt-injection",
        owaspLlm: ["LLM01:2025 - Prompt Injection", "LLM06:2025 - Sensitive Information Disclosure"],
        owaspAgentic: ["ASI01:2026 - Agent Goal Hijack", "ASI03:2026 - Data Exfiltration via Agent"],
      },
      allowlists,
    );
    expect(out).toEqual({ owasp_llm: ["LLM01:2025", "LLM02:2025"], owasp_agentic: ["ASI01:2026"] });
  });

  it("fills owasp_agentic from the category when the proposal carries none", () => {
    const out = normalizeReferences(
      { category: "prompt-injection", owaspLlm: ["LLM01:2025 - Prompt Injection"], owaspAgentic: [] },
      allowlists,
    );
    expect(out.owasp_agentic).toEqual(["ASI01:2026"]);
  });

  it("fills owasp_llm from the category when nothing valid survives", () => {
    const out = normalizeReferences(
      { category: "context-exfiltration", owaspLlm: ["LLM99:2025 - Not A Risk"], owaspAgentic: undefined },
      allowlists,
    );
    expect(out.owasp_llm).toEqual([DEFAULT_OWASP_LLM_BY_CATEGORY["context-exfiltration"]]);
    expect(out.owasp_agentic).toEqual([DEFAULT_OWASP_AGENTIC_BY_CATEGORY["context-exfiltration"]]);
  });

  it("emits only bare identifiers that exist in the allowlists, for every category", () => {
    const llm = validIds("owasp_llm");
    const agentic = validIds("owasp_agentic");
    for (const category of CATEGORIES) {
      const out = normalizeReferences(
        {
          category,
          owaspLlm: ["LLM06:2025 - Sensitive Information Disclosure", "garbage", "LLM05:2025 - Improper Output Handling"],
          owaspAgentic: ["ASI99:2026 - Imaginary"],
        },
        allowlists,
      );
      expect(out.owasp_llm.length).toBeGreaterThan(0);
      expect(out.owasp_agentic.length).toBeGreaterThan(0);
      for (const id of out.owasp_llm) {
        expect(llm.has(id)).toBe(true);
        expect(id).not.toContain(" - ");
      }
      for (const id of out.owasp_agentic) {
        expect(agentic.has(id)).toBe(true);
        expect(id).not.toContain(" - ");
      }
    }
  });

  it("every category default is itself an allowlisted identifier", () => {
    const llm = validIds("owasp_llm");
    const agentic = validIds("owasp_agentic");
    for (const category of CATEGORIES) {
      expect(llm.has(DEFAULT_OWASP_LLM_BY_CATEGORY[category])).toBe(true);
      expect(agentic.has(DEFAULT_OWASP_AGENTIC_BY_CATEGORY[category])).toBe(true);
    }
  });

  it("does not mutate its input", () => {
    const owaspLlm = Object.freeze(["LLM01:2025 - Prompt Injection"]);
    const input = Object.freeze({ category: "prompt-injection" as const, owaspLlm, owaspAgentic: Object.freeze([]) });
    expect(() => normalizeReferences(input, allowlists)).not.toThrow();
    expect(owaspLlm).toEqual(["LLM01:2025 - Prompt Injection"]);
  });
});
