"use client";

import { useState } from "react";
import type { Locale } from "@/lib/i18n";
import { t } from "@/lib/i18n";
import { Sign } from "@/components/Sign";

const FORMATS = ["BibTeX", "APA", "IEEE", "Chicago"] as const;
type Format = (typeof FORMATS)[number];

// Server-supplied subset of SpecMeta. The full SpecMeta lives in
// lib/spec-meta.ts which uses node:fs and so cannot be imported here.
export interface CitationMeta {
  /** Version of the written specification (SPEC.md header). */
  specVersion: string;
  /** Latest agent-threat-rules release on npm, the reference implementation. */
  packageVersion: string;
  /** Where packageVersion was read: "npm", or "package.json" when the registry was not checked at build time. */
  packageSource: string;
  lastModified: string;
  canonicalUrl: string;
  doi: string;
  editorName: string;
}

interface CitationBlockProps {
  locale: Locale;
  meta: CitationMeta;
}

export function CitationBlock({ locale, meta }: CitationBlockProps) {
  const [tab, setTab] = useState<Format>("BibTeX");

  const year = meta.lastModified.slice(0, 4);
  void meta.editorName; // editor surfaced via author block, mark referenced
  const title =
    "ATR: Agent Threat Rules — Open Detection Standard for AI Agent Threats";
  // The specification and the npm package are versioned separately; each
  // citation names both, labelled, so one is never read as the other.
  const versions = `Specification ${meta.specVersion}; agent-threat-rules ${meta.packageVersion} (${meta.packageSource})`;

  const citations: Record<Format, string> = {
    BibTeX: `@misc{atr${year},
  title  = {${title}},
  author = {Lin, Kuan-Hsin and {ATR Community}},
  year   = {${year}},
  version = {${meta.specVersion}},
  doi    = {${meta.doi}},
  url    = {${meta.canonicalUrl}},
  note   = {Specification version ${meta.specVersion}. Reference implementation: agent-threat-rules ${meta.packageVersion} (${meta.packageSource}). MIT license}
}`,
    APA: `Lin, K.-H., & ATR Community. (${year}). ${title} (${versions}) [Computer software]. ${meta.canonicalUrl}. https://doi.org/${meta.doi}`,
    IEEE: `K.-H. Lin and ATR Community, "${title}," ${versions}, ${year}. [Online]. Available: ${meta.canonicalUrl}. DOI: ${meta.doi}.`,
    Chicago: `Lin, Kuan-Hsin, and ATR Community. ${year}. "${title}." ${versions}. Accessed via ${meta.canonicalUrl}. https://doi.org/${meta.doi}.`,
  };

  return (
    <div className="not-prose my-6">
      <div role="tablist" aria-label={t(locale, "cite.tablist_aria")} className="flex gap-1 mb-2 flex-wrap">
        {FORMATS.map((f) => (
          <button
            key={f}
            role="tab"
            aria-selected={tab === f}
            aria-controls={`cite-panel-${f}`}
            onClick={() => setTab(f)}
            className={`font-data text-xs tracking-wide px-3 py-1.5  border transition-colors ${
              tab === f
                ? "bg-ink text-white border-ink"
                : "bg-paper text-stone border-fog hover:text-ink hover:border-stone"
            }`}
          >
            {f}
          </button>
        ))}
      </div>
      <pre
        id={`cite-panel-${tab}`}
        role="tabpanel"
        aria-label={`${tab} citation`}
        className="text-xs leading-relaxed bg-paper border border-fog  p-4 overflow-x-auto"
        style={{ fontFamily: "var(--font-data)" }}
      >
        {citations[tab]}
      </pre>
      <p className="spec-meta mt-3">
        DOI:{" "}
        <a
          href={`https://doi.org/${meta.doi}`}
          target="_blank"
          rel="noopener noreferrer"
          className="text-navy underline"
        >
          {meta.doi}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
        </a>
      </p>
    </div>
  );
}
