"use client";

import { useState } from "react";

export interface AdopterItem {
  name: string;
  org: string;
  integration: string;
  evidence: string;
  since: string;
}

/** "Gen Digital (Norton / Avast / LifeLock parent)" -> "Gen Digital". */
function wordmark(org: string): string {
  return org.replace(/\s*\(.*\)\s*$/, "").trim() || org;
}

/**
 * A row of organization names set as wordmarks, with one panel open: who
 * integrated ATR, what they integrated, since when, and the public evidence.
 * Names are typeset rather than shown as logos, so no third-party mark is
 * reproduced. Every entry comes from ADOPTERS.md.
 */
export function AdopterTabs({ items, locale }: { items: AdopterItem[]; locale: string }) {
  const zh = locale === "zh";
  const [active, setActive] = useState(0);
  const current = items[active];
  if (!current) return null;

  return (
    <div>
      <div role="tablist" aria-label={zh ? "採用者" : "Adopters"} className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 border-t border-fog">
        {items.map((item, i) => (
          <button
            key={item.name + item.org}
            role="tab"
            aria-selected={i === active}
            onClick={() => setActive(i)}
            className={`relative flex items-center justify-center h-24 px-4 text-center border-r border-b md:border-b-0 border-fog md:last:border-r-0 transition-colors ${
              i === active ? "bg-white text-ink" : "text-stone hover:text-ink hover:bg-white/60"
            }`}
          >
            {i === active && <span className="absolute left-0 right-0 top-0 h-[2px] bg-brand" aria-hidden="true" />}
            <span className="text-[17px] leading-tight tracking-[-0.01em] font-medium">{wordmark(item.org)}</span>
          </button>
        ))}
      </div>

      <div role="tabpanel" className="grid md:grid-cols-[220px_1fr] border-t border-fog bg-white">
        <div className="px-8 pt-8 md:pb-8 md:border-r border-fog">
          <div className="text-[13px] text-stone">{zh ? "自" : "Since"}</div>
          <div className="mt-1 text-[15px] text-ink tabular-nums">{current.since}</div>
        </div>
        <div className="p-8 flex flex-col">
          <div className="text-[20px] leading-snug text-ink">{current.name}</div>
          <p className="mt-3 text-[14.5px] leading-[1.7] text-graphite max-w-[640px]">{current.integration}</p>
          <div className="mt-6">
            <a href={current.evidence} target="_blank" rel="noopener noreferrer" className="inline-flex items-stretch bg-ink text-white text-[12.5px] leading-none hover:bg-black transition-colors">
              <span className="px-3 py-2">{zh ? "公開證據" : "Public evidence"}</span>
              <span className="px-2 py-2 border-l border-white/20" aria-hidden="true">↗</span>
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
