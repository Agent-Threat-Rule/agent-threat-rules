/* ATD enumeration — the technique catalog rendered on /atd.
 *
 * SINGLE SOURCE OF TRUTH: the render model below is DERIVED from the normative,
 * machine-readable enumeration shipped at public/atd/atd-techniques.json — the
 * same artifact the public download and scripts/validate-atd.ts validate. The
 * page never carries its own hand-maintained copy of the catalog; it maps the
 * normative records into the simpler shape the JSX consumes, so the page and
 * the downloadable standard can never drift apart.
 *
 * Every CVE in the normative file was verified against nvd.nist.gov and every
 * MITRE ATLAS id against the authoritative mitre-atlas/atlas-data dist/ATLAS.yaml.
 * Entries with no public CVE carry a "research" reference (a real advisory/paper)
 * or a "vendor" reference (forward-looking; no public instance yet) — never
 * dressed up as a CVE. `atr_rule` links the live, gate-passing ATR detection
 * rule where one exists.
 */
import atdEnumeration from "../public/atd/atd-techniques.json";

export type EvidenceKind = "cve" | "research" | "aspirational";
export type Severity = "critical" | "high" | "medium";

export interface ATDTechnique {
  id: string; // ATD-T####
  tactic: string; // ATD-TA#
  title: string;
  mechanism: string;
  severity: Severity;
  evidence: { kind: EvidenceKind; label: string; url?: string };
  asi: string[]; // OWASP Agentic Top 10 2026
  atlas: string[]; // MITRE ATLAS (verified; [] if none verifiable)
  cwe: string[];
  atrRule?: string; // live ATR rule id, if one ships
}

/* ---- normative-record shape (subset of atd-technique.schema.json we read) ---- */
type ReferenceType = "cve" | "vendor" | "research";

interface ATDReference {
  type: ReferenceType;
  url: string;
}

interface ATDMappings {
  owasp_asi?: string[];
  mitre_atlas?: string[];
  cwe?: string[];
}

interface ATDRecord {
  atd_id: string;
  tactic: string;
  title: string;
  description: string;
  severity: string;
  mappings: ATDMappings;
  references: ATDReference[];
  atr_rule?: string;
}

interface ATDEnumeration {
  techniques: ATDRecord[];
}

const SEVERITIES: ReadonlySet<string> = new Set<Severity>([
  "critical",
  "high",
  "medium",
]);

function toSeverity(value: string): Severity {
  return SEVERITIES.has(value) ? (value as Severity) : "medium";
}

// hostname → human-readable source name for research/vendor evidence labels.
const HOST_LABELS: Record<string, string> = {
  "arxiv.org": "arXiv",
  "github.com": "GitHub advisory",
  "atlas.mitre.org": "MITRE ATLAS",
  "blog.trailofbits.com": "Trail of Bits",
  "www.pillar.security": "Pillar Security",
  "www.levelblue.com": "Trustwave SpiderLabs",
  "vulnerablemcp.info": "Vulnerable MCP Project",
  "modelcontextprotocol.io": "MCP specification",
  "artificialintelligenceact.eu": "EU AI Act",
  "nvd.nist.gov": "NVD advisory",
  "cloud.google.com": "Google Cloud",
  "fidoalliance.org": "FIDO Alliance",
};

function hostnameOf(url: string): string | undefined {
  const match = url.match(/^[a-z]+:\/\/([^/?#]+)/i);
  return match ? match[1].toLowerCase() : undefined;
}

function hostLabel(url: string, fallback: string): string {
  const host = hostnameOf(url);
  if (!host) return fallback;
  return HOST_LABELS[host] ?? host.replace(/^www\./, "");
}

// Derive the render-model `evidence` block from the first normative reference.
function toEvidence(ref: ATDReference): ATDTechnique["evidence"] {
  if (ref.type === "cve") {
    const cve = ref.url.match(/CVE-\d{4}-\d+/i);
    return { kind: "cve", url: ref.url, label: cve ? cve[0] : "CVE advisory" };
  }
  if (ref.type === "vendor") {
    return { kind: "aspirational", url: ref.url, label: hostLabel(ref.url, "Vendor advisory") };
  }
  // research (and any unknown type) — point at the paper/advisory host.
  return { kind: "research", url: ref.url, label: hostLabel(ref.url, "Research") };
}

function toTechnique(record: ATDRecord): ATDTechnique {
  return {
    id: record.atd_id,
    tactic: record.tactic,
    title: record.title,
    mechanism: record.description,
    severity: toSeverity(record.severity),
    asi: record.mappings.owasp_asi ?? [],
    atlas: record.mappings.mitre_atlas ?? [],
    cwe: record.mappings.cwe ?? [],
    atrRule: record.atr_rule || undefined,
    evidence: toEvidence(record.references[0]),
  };
}

export const ATD_TACTICS: { id: string; name: string }[] = [
  { id: "ATD-TA1", name: "Protocol & Interconnect" },
  { id: "ATD-TA2", name: "Memory & Context Integrity" },
  { id: "ATD-TA3", name: "Goal, Planning & Reasoning" },
  { id: "ATD-TA4", name: "Identity, Authz & Delegation" },
  { id: "ATD-TA5", name: "Tool & Supply Chain" },
  { id: "ATD-TA6", name: "Execution & Autonomy" },
  { id: "ATD-TA7", name: "Multi-Agent Dynamics" },
  { id: "ATD-TA8", name: "Model-Intrinsic & Governance" },
  { id: "ATD-TA9", name: "Agentic Commerce (forward)" },
];

// The catalog is derived from the normative enumeration — never hand-edited here.
// Add or change a technique in public/atd/atd-techniques.json; the page follows.
export const ATD_TECHNIQUES: ATDTechnique[] = (
  atdEnumeration as ATDEnumeration
).techniques.map(toTechnique);

export const ATD_STATS = {
  techniques: ATD_TECHNIQUES.length,
  withLiveRule: ATD_TECHNIQUES.filter((t) => t.atrRule).length,
  withCve: ATD_TECHNIQUES.filter((t) => t.evidence.kind === "cve").length,
  tactics: ATD_TACTICS.length,
};

// Map the internal render-model to the normative schema shape used by the
// public, downloadable enumeration (atd-techniques.json) and validated by
// scripts/validate-atd.ts. The page renders the simple model; the published
// artifact conforms to atd-technique.schema.json.
const TACTIC_SURFACE: Record<string, string[]> = {
  "ATD-TA1": ["tool_input", "tool_response"],
  "ATD-TA2": ["memory_op"],
  "ATD-TA3": ["content", "tool_response"],
  "ATD-TA4": ["tool_input"],
  "ATD-TA5": ["tool_input", "tool_response"],
  "ATD-TA6": ["tool_input", "trace"],
  "ATD-TA7": ["inter_agent_msg"],
  "ATD-TA8": ["trace"],
  "ATD-TA9": ["payment_mandate"],
};

export function toATDRecord(t: ATDTechnique) {
  const refType =
    t.evidence.kind === "cve"
      ? "cve"
      : t.evidence.kind === "aspirational"
        ? "vendor"
        : "research";
  return {
    atd_id: t.id,
    schema_version: "0.1.0",
    title: t.title,
    tactic: t.tactic,
    abstraction: "base",
    status: "experimental",
    severity: t.severity,
    description: t.mechanism,
    detection_surface: TACTIC_SURFACE[t.tactic] ?? ["content"],
    mappings: {
      owasp_asi: t.asi,
      mitre_atlas: t.atlas,
      cwe: t.cwe,
      ...(t.asi.length === 0 && t.atlas.length === 0
        ? { gap_note: "No upstream framework names this technique yet." }
        : {}),
    },
    references: t.evidence.url
      ? [{ type: refType, url: t.evidence.url }]
      : [],
    ...(t.atrRule ? { atr_rule: t.atrRule } : {}),
  };
}
