import { readFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { join } from "node:path";

/**
 * Framework crosswalks rendered from the repository's docs/*-MAPPING.md.
 * A document whose header says it is an internal draft or not published is
 * listed by name only and never rendered: the site does not publish what the
 * document itself says is unpublished. A superseded document is not listed.
 */

const REPO_ROOT = join(process.cwd(), "..");

export interface CrosswalkDoc {
  slug: string;
  file: string;
  framework: string;
  owner: string;
}

/** Every mapping document, in reading order. OWASP-MAPPING.md is superseded by OWASP-AGENTIC-MAPPING.md and left out. */
export const CROSSWALK_DOCS: ReadonlyArray<CrosswalkDoc> = [
  { slug: "owasp-agentic-top-10", file: "docs/OWASP-AGENTIC-MAPPING.md", framework: "OWASP Top 10 for Agentic Applications (2026)", owner: "OWASP" },
  { slug: "owasp-agentic-skills-top-10", file: "docs/OWASP-AST10-MAPPING.md", framework: "OWASP Agentic Skills Top 10", owner: "OWASP" },
  { slug: "owasp-aivss", file: "docs/OWASP-AIVSS-MAPPING.md", framework: "OWASP AIVSS", owner: "OWASP" },
  { slug: "owasp-aisvs", file: "docs/OWASP-AISVS-MAPPING.md", framework: "OWASP AISVS 1.0", owner: "OWASP" },
  { slug: "owasp-agentic-maturity", file: "docs/OWASP-AGENTIC-MATURITY-MAPPING.md", framework: "OWASP Agentic AI Maturity Model", owner: "OWASP" },
  { slug: "mitre-atlas", file: "docs/MITRE-ATLAS-MAPPING.md", framework: "MITRE ATLAS", owner: "MITRE" },
  { slug: "safe-mcp", file: "docs/SAFE-MCP-MAPPING.md", framework: "SAF-MCP techniques", owner: "SAF-MCP" },
  { slug: "mcp-38", file: "docs/MCP-38-MAPPING.md", framework: "MCP-38 threat taxonomy", owner: "MCP-38" },
  { slug: "nsa-mcp", file: "docs/NSA-MCP-MAPPING.md", framework: "NSA MCP security design guidance", owner: "NSA" },
  { slug: "five-eyes", file: "docs/FIVE-EYES-MAPPING.md", framework: "Five Eyes: Careful Adoption of Agentic AI Services", owner: "Five Eyes agencies" },
  { slug: "csa-maestro", file: "docs/CSA-MAESTRO-MAPPING.md", framework: "CSA MAESTRO", owner: "Cloud Security Alliance" },
  { slug: "etsi-ts-104223", file: "docs/ETSI-TS-104223-MAPPING.md", framework: "ETSI TS 104 223 / UK AI Cyber Security Code of Practice", owner: "ETSI / UK DSIT" },
  { slug: "finos-ai-governance", file: "docs/FINOS-AI-GOVERNANCE-MAPPING.md", framework: "FINOS AI Governance Framework v2.0", owner: "FINOS" },
];

export interface LoadedCrosswalk extends CrosswalkDoc {
  /** False when the document's header marks it as an internal draft or not published. */
  published: boolean;
  /** The document's own "Last updated:" or "Version:" line, if any. */
  declared: string | null;
  /** Date of the last commit touching the file. */
  committed: string | null;
  body: string;
}

// Only the document's own status markers count: "INTERNAL DRAFT", or a
// Version/Status header line saying "not published". A sentence that says
// some other thing is not published (OWASP AIVSS: "the scoring formula ...
// are not published") does not.
const UNPUBLISHED = /INTERNAL DRAFT|^(?:Version|Status):[^\n]*not published/im;

function lastCommit(file: string): string | null {
  try {
    const out = execSync(`git log -1 --format=%cs -- "${file}"`, { cwd: REPO_ROOT, encoding: "utf-8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    return out || null;
  } catch {
    return null;
  }
}

let cache: LoadedCrosswalk[] | null = null;

export function loadCrosswalks(): LoadedCrosswalk[] {
  if (cache && process.env.NODE_ENV === "production") return cache;
  cache = CROSSWALK_DOCS.map((doc) => {
    let body = "";
    try {
      body = readFileSync(join(REPO_ROOT, doc.file), "utf-8");
    } catch {
      body = "";
    }
    const head = body.split("\n").slice(0, 20).join("\n");
    const declared = /^(?:Last updated|Version):\s*(.+)$/im.exec(head)?.[0] ?? null;
    return { ...doc, published: body !== "" && !UNPUBLISHED.test(head), declared, committed: lastCommit(doc.file), body };
  });
  return cache;
}

export function findCrosswalk(slug: string): LoadedCrosswalk | undefined {
  return loadCrosswalks().find((c) => c.slug === slug);
}
