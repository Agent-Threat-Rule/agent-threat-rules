// ATR spec metadata — single source of truth for Document Status banners
// across the site.
//
// The spec version is the one in SPEC.md's own header. It used to be the npm
// package version (package.json), so the written specification appeared to
// change version with every rules release, and /spec, the footer and npm each
// showed a different number. Package and npm versions now live in
// lib/versions.ts and are shown under their own labels next to this one.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { loadSiteStats } from "./stats";
import { readCoreSpec } from "./versions";

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
  /** Version of the written core specification (SPEC.md header). Not the npm package version. */
  specVersion: string;
  /** Maturity of this document. */
  status: SpecStatus;
  /** ISO date of this spec version (SPEC.md "Date:" header). */
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
  const spec = readCoreSpec();
  const raw = readStatsJson();
  const fallbackDate = raw.generatedAt
    ? raw.generatedAt.slice(0, 10)
    : new Date().toISOString().slice(0, 10);

  return {
    specVersion: spec.version,
    status: "Working Draft",
    lastModified: spec.date || fallbackDate,
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
  // The ISO date is a calendar date (parsed as UTC midnight); format it in UTC
  // or every timezone west of Greenwich shows the day before.
  return d.toLocaleDateString("en-GB", {
    year: "numeric",
    month: "long",
    day: "numeric",
    timeZone: "UTC",
  });
}
