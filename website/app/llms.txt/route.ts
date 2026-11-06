import { buildRuleIndex } from "@/lib/rule-index";
import { categoryDisplayName } from "@/lib/categories";
import { SITE_URL } from "@/lib/seo";

export const dynamic = "force-static";

const REPO_URL = "https://github.com/Agent-Threat-Rule/agent-threat-rules";

/** [title](/en path): note. English pages; every page also exists under /zh. */
const PAGES: ReadonlyArray<{ section: string; links: ReadonlyArray<[string, string, string]> }> = [
  {
    section: "Specification",
    links: [
      ["Specification", "/spec", "the rule format, evaluation semantics, identifiers and conformance"],
      ["Conformance", "/conformance", "conformance levels, the L1 test suite and self-certification"],
      ["Governance", "/governance", "maintainers, merge policy and succession"],
      ["Charter", "/charter", "what ATR is and is not, and how decisions are made"],
      ["Citation", "/citations", "how to cite ATR, with the DOI"],
      ["Errata", "/errata", "errors found in published versions, corrected in the open"],
      ["Glossary", "/glossary", "terms used in the specification"],
      ["Compliance", "/compliance", "framework mappings; ATR's own documents, not endorsements"],
    ],
  },
  {
    section: "Rules",
    links: [
      ["Rule explorer", "/rules", "every rule with maturity, scan target and lane filter"],
      ["Coverage", "/coverage", "coverage against OWASP and other frameworks, with gaps"],
      ["Quality standard", "/quality-standard", "maturity ladder and detection lanes"],
    ],
  },
  {
    section: "Use",
    links: [
      ["Start here", "/start", "entry points by reader: integrate, contribute, audit, cite, governance"],
      ["Integrate", "/integrate", "TypeScript, Python, raw YAML, GitHub Action, SIEM"],
      ["Contribute", "/contribute", "submit a rule, report an evasion or a false positive"],
      ["Responsible use", "/responsible-use", "intended use and misuse"],
    ],
  },
];

async function buildLlmsTxt(): Promise<string> {
  const index = await buildRuleIndex();
  const { counts, versions } = index;
  const byCategory = new Map<string, number>();
  for (const r of index.rules) byCategory.set(r.category, (byCategory.get(r.category) ?? 0) + 1);

  const lines: string[] = [
    "# ATR (Agent Threat Rules)",
    "",
    "> An open detection rule standard for AI agent security threats: YAML rules with permanent ATR-YYYY-NNNNN identifiers, a written core specification, and a reference engine. MIT licensed.",
    "",
    `Figures below are as of ${index.generated_at.slice(0, 10)}, when this file was generated, and each says what it counts.`,
    "",
    `- Rule files on main: ${counts.files}. Effective (loaded by at least one lane): ${counts.effective}. Inert (status draft or deprecated): ${counts.inert}.`,
    `- Rules per lane: enforce ${counts.byLane.enforce} (maturity stable; the lane to run with blocking on), alert ${counts.byLane.alert} (maturity stable or test), hunt ${counts.byLane.hunt} (every effective rule; the engine default).`,
    `- Core specification (SPEC.md): ${versions.spec}`,
    versions.npm_verified
      ? `- Latest npm release: agent-threat-rules@${versions.npm}`
      : `- package.json version: ${versions.package_json} (the npm registry was not reachable when this file was generated)`,
    "- Every page is available in English (/en/...) and Traditional Chinese (/zh/...).",
    "",
  ];

  for (const { section, links } of PAGES) {
    lines.push(`## ${section}`, "");
    for (const [title, path, note] of links) lines.push(`- [${title}](${SITE_URL}/en${path}): ${note}`);
    if (section === "Specification") lines.push(`- [SPEC.md](${REPO_URL}/blob/main/SPEC.md): source text of the core specification`);
    if (section === "Rules") {
      lines.push(
        `- [Rule index, JSON](${SITE_URL}/rules/index.json): every rule with maturity, lanes, scan_target, framework mappings, page URL and raw YAML URL`,
        `- [Rule index, CSV](${SITE_URL}/rules/index.csv): the same data; the first line is a # comment with versions and generation time`,
        `- [ATD techniques, JSON](${SITE_URL}/atd/atd-techniques.json): the agentic threat technique catalog`,
      );
      for (const [category, n] of [...byCategory.entries()].sort((a, b) => b[1] - a[1])) {
        lines.push(`- [${categoryDisplayName(category, "en")} rules](${REPO_URL}/tree/main/rules/${category}): ${n} rule files (YAML)`);
      }
    }
    lines.push("");
  }

  lines.push(
    "## Optional",
    "",
    `- [About](${SITE_URL}/en/about): mission and history`,
    `- [Research](${SITE_URL}/en/research): paper, benchmarks and limitations`,
    `- [Changelog](${SITE_URL}/en/changelog): release history`,
    `- [Repository](${REPO_URL}): rules, engine source and issue tracker`,
    "",
  );
  return lines.join("\n");
}

export async function GET() {
  return new Response(await buildLlmsTxt(), {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}
