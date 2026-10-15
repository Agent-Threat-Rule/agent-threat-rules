/**
 * Tests for scripts/generate-saf-mcp-mapping.ts — the reviewed ATR → SAF-MCP
 * mapping. The JSON is hand-reviewed, so validation is what keeps a renamed
 * rule, a deprecated technique or a typo'd relationship from shipping, and the
 * committed Markdown must always be the rendering of the committed JSON.
 */
import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type SafMappingFile,
  renderMarkdown,
  ruleFromDisk,
  validateMapping,
} from "../scripts/generate-saf-mcp-mapping.js";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const SAMPLE: SafMappingFile = {
  framework: {
    name: "SAF Framework Model v2",
    repository: "https://github.com/secure-agentic-framework/saf-mcp",
    path: "research/framework-model.yml",
    commit: "4a74d692127841def59f02307c5662ea4014be5f",
    commit_date: "2026-09-02",
  },
  atr_version_reviewed: "4.1.5",
  reviewed_on: "2026-10-16",
  method: "Pairs were reviewed against the rule patterns.",
  tactics: [{ id: "ATK-TA0001", name: "Initial Access" }],
  techniques: [
    { id: "SAF-T1001", name: "Tool Poisoning Attack", tactics: ["ATK-TA0001"] },
    { id: "SAF-T1002", name: "Supply Chain Compromise", tactics: ["ATK-TA0001"] },
  ],
  mappings: [
    {
      technique_id: "SAF-T1001",
      rule_id: "ATR-2026-00001",
      rule_path: "rules/x/ATR-2026-00001.yaml",
      relationship: "partial",
      modalities: ["content"],
      evidence: "Matches <IMPORTANT> instructions | inside tool descriptions.",
    },
  ],
};

const known = (path: string) => {
  if (path === "rules/x/ATR-2026-00001.yaml") return { id: "ATR-2026-00001", runs: true };
  if (path === "rules/x/ATR-2026-00009.yaml") return { id: "ATR-2026-00009", runs: false };
  return null;
};

describe("validateMapping", () => {
  it("accepts a well-formed file", () => {
    expect(validateMapping(SAMPLE, known)).toEqual([]);
  });

  it("rejects a technique that is not active, a wrong rule id and a bad modality", () => {
    const broken: SafMappingFile = {
      ...SAMPLE,
      mappings: [
        { ...SAMPLE.mappings[0], technique_id: "SAF-T1104" },
        { ...SAMPLE.mappings[0], rule_id: "ATR-2026-00002" },
        { ...SAMPLE.mappings[0], technique_id: "SAF-T1002", modalities: ["telepathy"] },
      ],
    };
    const problems = validateMapping(broken, known);
    expect(problems.some((p) => p.includes("not an active SAF technique"))).toBe(true);
    expect(problems.some((p) => p.includes("declares ATR-2026-00001"))).toBe(true);
    expect(problems.some((p) => p.includes("unknown modality telepathy"))).toBe(true);
  });

  it("rejects duplicate pairs and missing rule files", () => {
    const broken: SafMappingFile = {
      ...SAMPLE,
      mappings: [SAMPLE.mappings[0], SAMPLE.mappings[0], { ...SAMPLE.mappings[0], rule_path: "rules/gone.yaml", technique_id: "SAF-T1002" }],
    };
    const problems = validateMapping(broken, known);
    expect(problems.some((p) => p.includes("duplicate pair"))).toBe(true);
    expect(problems.some((p) => p.includes("not found"))).toBe(true);
  });

  it("rejects a pair whose rule the engine never runs", () => {
    const broken: SafMappingFile = {
      ...SAMPLE,
      mappings: [{ ...SAMPLE.mappings[0], rule_id: "ATR-2026-00009", rule_path: "rules/x/ATR-2026-00009.yaml" }],
    };
    expect(validateMapping(broken, known)).toEqual(["SAF-T1001 ATR-2026-00009: ATR-2026-00009 is draft or deprecated, so the engine never runs it"]);
  });

  it("rejects duplicate or deprecated techniques, duplicate modalities and rule counts in evidence", () => {
    const broken: SafMappingFile = {
      ...SAMPLE,
      techniques: [...SAMPLE.techniques, SAMPLE.techniques[0], { id: "SAF-T1104", name: "Deprecated", tactics: ["ATK-TA0001"] }],
      mappings: [{ ...SAMPLE.mappings[0], modalities: ["content", "content"], evidence: "Shares a pattern with 12 rules." }],
    };
    const problems = validateMapping(broken, known);
    expect(problems).toContain("SAF-T1001: duplicate technique");
    expect(problems).toContain("SAF-T1104: deprecated in the pinned framework model");
    expect(problems.some((p) => p.includes("duplicate modality content"))).toBe(true);
    expect(problems.some((p) => p.includes("rule count that sync-stats would rewrite"))).toBe(true);
  });
});

describe("renderMarkdown", () => {
  const md = renderMarkdown(SAMPLE);

  it("lists mapped and unmapped techniques and escapes table cells", () => {
    expect(md).toContain("### SAF-T1001 — Tool Poisoning Attack");
    expect(md).toContain("| [ATR-2026-00001](../rules/x/ATR-2026-00001.yaml) | partial | content | Matches &lt;IMPORTANT> instructions \\| inside tool descriptions. |");
    expect(md).toContain("## Techniques with no reviewed ATR rule\n\n- SAF-T1002 — Supply Chain Compromise");
  });

  it("carries no percentage and no hard-coded rule count that sync-stats would rewrite", () => {
    expect(md).not.toMatch(/%/);
    expect(md).not.toMatch(/\b\d{2,4}\s*rules/i);
  });
});

describe("committed files", () => {
  const data = JSON.parse(readFileSync(join(ROOT, "docs/saf-mcp-mapping.json"), "utf8")) as SafMappingFile;

  it("the committed mapping validates against the rules on disk", () => {
    expect(validateMapping(data, ruleFromDisk(ROOT))).toEqual([]);
  });

  it("the committed Markdown is the rendering of the committed JSON", () => {
    expect(readFileSync(join(ROOT, "docs/SAFE-MCP-MAPPING.md"), "utf8")).toBe(renderMarkdown(data));
  });

  it("the committed Markdown has no raw HTML tag and nothing sync-stats would rewrite", () => {
    const md = readFileSync(join(ROOT, "docs/SAFE-MCP-MAPPING.md"), "utf8");
    expect(md).not.toMatch(/<[A-Za-z/]/);
    expect(md).not.toMatch(/\d{2,4}\s*rules/i);
    expect(md).not.toMatch(/\d\s*%/);
  });

  it("stats.json and the website cite the counts the mapping file produces", () => {
    const covered = new Set(data.mappings.map((m) => m.technique_id)).size;
    const total = data.techniques.length;
    const stats = JSON.parse(readFileSync(join(ROOT, "stats.json"), "utf8")) as {
      coverage: { safeMcp: { covered: number; total: number; display: string } };
    };
    expect(stats.coverage.safeMcp).toMatchObject({ covered, total, display: `${covered}/${total}` });
    expect(readFileSync(join(ROOT, "website/lib/stats.ts"), "utf8")).toContain(`safeMcp: "${covered}/${total}"`);
    expect(readFileSync(join(ROOT, "README.md"), "utf8")).toContain(`${covered} of ${total} active techniques`);
    const compliance = readFileSync(join(ROOT, "website/app/[locale]/compliance/page.tsx"), "utf8");
    expect(compliance).toContain(`coverage: "${covered}/${total} techniques"`);
    expect(compliance).toContain(`${covered} of ${total} active SAF Framework Model v2 techniques`);
    expect(compliance).toContain(`${total} 項有效技術中，${covered} 項`);
  });

  it("no public surface still cites the retired SAFE-MCP figures", () => {
    const surfaces = [
      "README.md", "COVERAGE.md", "CITATION.cff", "DESIGN.md", "docs/OWASP-AGENTIC-MAPPING.md",
      "website/app/[locale]/page.tsx", "website/app/[locale]/coverage/page.tsx",
      "website/app/[locale]/spec/page.tsx", "website/app/[locale]/compliance/page.tsx",
      "website/app/[locale]/about/page.tsx", "website/lib/i18n.ts", "website/lib/stats.ts",
    ];
    for (const rel of surfaces) {
      expect(readFileSync(join(ROOT, rel), "utf8"), rel).not.toMatch(/91\.8|78\s*\/\s*85|78 of 85|85 項/);
    }
  });
});
