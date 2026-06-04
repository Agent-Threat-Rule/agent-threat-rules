// ATR spec metadata — single source of truth for Document Status banners
// across the site. Bump SPEC_DOC_VERSION when a new spec-document release
// lands. NOTE: the spec-document version is deliberately DISTINCT from the
// npm package version recorded in data/stats.json — they version different
// things. The package ships rules + engine on its own SemVer line; the spec
// document tracks the maturity of the written standard. Do not source the
// spec-document version from stats.json.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { loadSiteStats } from "./stats";

/** Version of the SPEC DOCUMENT (the written standard), not the npm package. */
const SPEC_DOC_VERSION = "3.0.0-alpha.1";

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
