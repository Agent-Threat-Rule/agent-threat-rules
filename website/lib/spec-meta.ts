// ATR spec metadata — single source of truth for Document Status banners
// across the site. SPEC_DOC_VERSION is aligned to the published npm package
// version (agent-threat-rules) for a single, unambiguous external version
// number: once the standard ships in production and is cited by third parties,
// a separate pre-1.0 spec-document number reads as half-baked. Status remains
// "Working Draft" to register the governance transition (BDFL -> TSC) honestly.
// Bump this when the package version bumps.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { loadSiteStats } from "./stats";

/** Public spec-document version, aligned to the npm package version (v3.5.0). */
const SPEC_DOC_VERSION = "3.5.0";

interface StatsJsonShape {
  generatedAt?: string;
}

function readStatsJson(): StatsJsonShape {
  try {
    const raw = readFileSync(
      join(process.cwd(), "..", "data", "stats.json"),
      "utf-8",
    );
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

export type SpecStatus =
  | "Working Draft"
  | "Candidate Recommendation"
  | "Proposed Recommendation"
  | "Recommendation"
  | "Editor's Draft";

export interface SpecMeta {
  /** Semver of the specification document. */
  version: string;
  /** Maturity of this document. */
  status: SpecStatus;
  /** ISO date string this document last received normative changes. */
  lastModified: string;
  /** Canonical URL for the spec authority. */
  canonicalUrl: string;
  /** Editors of record (W3C-style). */
  editors: Array<{ name: string; affiliation?: string; email?: string }>;
  /** Primary repository. */
  repository: string;
  /** Citation DOI for the spec. */
  doi: string;
  /** Rule corpus stats — pulled live from data/stats.json. */
  ruleCount: number;
  ruleCategoryCount: number;
}

export function getSpecMeta(): SpecMeta {
  const stats = loadSiteStats();
  const raw = readStatsJson();
  const generatedAt = raw.generatedAt
    ? raw.generatedAt.slice(0, 10)
    : new Date().toISOString().slice(0, 10);

  return {
    version: SPEC_DOC_VERSION,
    status: "Working Draft",
    lastModified: generatedAt,
    canonicalUrl: "https://agentthreatrule.org/spec",
    editors: [
      {
        name: "Adam Lin",
        affiliation: "ATR Community",
        email: "adam@agentthreatrule.org",
      },
    ],
    repository: "https://github.com/Agent-Threat-Rule/agent-threat-rules",
    doi: "10.5281/zenodo.19178002",
    ruleCount: stats.ruleCount,
    ruleCategoryCount: stats.categoryCount,
  };
}

/** Format an ISO date as e.g. "26 May 2026" (W3C style). */
export function formatSpecDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("en-GB", {
    year: "numeric",
    month: "long",
    day: "numeric",
  });
}
