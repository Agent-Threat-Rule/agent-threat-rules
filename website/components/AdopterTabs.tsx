"use client";

import { useState } from "react";

export interface AdopterItem {
  name: string;
  org: string;
  integration: string;
  evidence: string;
  since: string;
  logo?: string;
  tier: string;
}

/**
 * Logo row with one panel open: who integrated ATR, what they integrated,
 * since when, and the public evidence. Every entry comes from ADOPTERS.md.
 */
export function AdopterTabs({ items, locale }: { items: AdopterItem[]; locale: string }) {
  const zh = locale === "zh";
  const [active, setActive] = useState(0);
  const current = items[active];
  if (!current) return null;

  return (
    <div>
      <div role="tablist" aria-label={zh ? "採用者" : "Adopters"} className="grid grid-cols-3 md:grid-cols-6 border-t border-fog">
        {items.map((item, i) => (
          <button
            key={item.name + item.org}
            role="tab"
            aria-selected={i === active}
            onClick={() => setActive(i)}
            className={`relative flex flex-col items-start gap-2 px-4 py-4 text-left border-r border-fog last:border-r-0 transition-colors ${
              i === active ? "bg-white" : "hover:bg-white/60"
            }`}
          >
            {i === active && <span className="absolute left-0 right-0 top-0 h-[2px] bg-navy" aria-hidden="true" />}
            <span className="h-7 flex items-center">
              {item.logo ? (
                <img src={item.logo} alt="" className={`h-7 w-7 ${i === active ? "" : "grayscale opacity-70"}`} loading="lazy" />
              ) : (
                <span className="font-data text-[11px] text-stone">{item.org.slice(0, 12)}</span>
              )}
            </span>
            <span className="text-[13px] leading-tight text-ink line-clamp-2">{item.name}</span>
            <span className="font-data text-[10px] uppercase tracking-[0.08em] text-mist">tier {item.tier}</span>
          </button>
        ))}
      </div>

      <div role="tabpanel" className="grid md:grid-cols-[1fr_1.2fr] border-t border-fog bg-white">
        <div className="p-8 border-b md:border-b-0 md:border-r border-fog flex items-center justify-center grid-paper min-h-[220px]">
          {current.logo && <img src={current.logo.replace("size=128", "size=240")} alt={current.org} className="w-24 h-24 shadow-[0_12px_32px_-8px_rgba(0,0,0,0.25)] bg-white" />}
        </div>
        <div className="p-8 flex flex-col">
          <div className="text-[20px] leading-snug text-ink">{current.name}</div>
          <div className="mt-1 text-[13px] text-stone">{current.org}</div>
          <p className="mt-5 text-[14.5px] leading-[1.7] text-graphite flex-1">{current.integration}</p>
          <div className="mt-6 flex items-center justify-between gap-4 font-data text-[11px] text-stone">
            <span>{zh ? "自" : "Since"} {current.since}</span>
            <a href={current.evidence} target="_blank" rel="noopener noreferrer" className="inline-flex items-stretch bg-ink text-white text-[12.5px] leading-none hover:bg-navy transition-colors">
              <span className="px-3 py-2">{zh ? "公開證據" : "Public evidence"}</span>
              <span className="px-2 py-2 border-l border-white/20" aria-hidden="true">↗</span>
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
