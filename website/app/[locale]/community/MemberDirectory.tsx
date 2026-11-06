"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import type { Member, Tier } from "@/lib/community";
import { Sign } from "@/components/Sign";

type Tab = Tier | "all";

const TAB_LABELS: Record<Tab, { en: string; zh: string }> = {
  all: { en: "All members", zh: "全部成員" },
  steering: { en: "Steering", zh: "指導小組" },
  expert: { en: "Experts", zh: "專家" },
  contributor: { en: "Contributors", zh: "貢獻者" },
};

const TIER_NOTE: Record<Tier, { en: string; zh: string }> = {
  steering: { en: "Steering", zh: "指導小組" },
  expert: { en: "Expert", zh: "專家" },
  contributor: { en: "Contributor", zh: "貢獻者" },
};

/** Directory with tier tabs (counts are the number of entries) and a name or organization search. */
export function MemberDirectory({ members, locale }: { members: Member[]; locale: string }) {
  const zh = locale === "zh";
  const [tab, setTab] = useState<Tab>("all");
  const [query, setQuery] = useState("");
  const pick = (t: { en: string; zh: string }) => (zh ? t.zh : t.en);

  const counts = useMemo(
    () => ({
      all: members.length,
      steering: members.filter((m) => m.tier === "steering").length,
      expert: members.filter((m) => m.tier === "expert").length,
      contributor: members.filter((m) => m.tier === "contributor").length,
    }),
    [members],
  );

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return members.filter(
      (m) =>
        (tab === "all" || m.tier === tab) &&
        (!q || m.name.toLowerCase().includes(q) || (m.organization ?? "").toLowerCase().includes(q)),
    );
  }, [members, tab, query]);

  return (
    <div>
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 pb-4 border-b border-fog">
        <div role="tablist" aria-label={zh ? "成員分類" : "Member groups"} className="flex flex-wrap gap-1">
          {(Object.keys(TAB_LABELS) as Tab[]).map((key) => (
            <button
              key={key}
              role="tab"
              aria-selected={tab === key}
              onClick={() => setTab(key)}
              className={`inline-flex items-center gap-2 px-3 py-1.5 text-[13px] rounded-[3px] transition-colors ${
                tab === key ? "bg-ash text-ink" : "text-stone hover:text-ink"
              }`}
            >
              {pick(TAB_LABELS[key])}
              <span className="font-data text-[11px] text-stone border border-fog px-1.5 rounded-[2px] tabular-nums">{counts[key]}</span>
            </button>
          ))}
        </div>
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder={zh ? "搜尋姓名或所屬單位" : "Search by name or organization"}
          aria-label={zh ? "搜尋成員" : "Search members"}
          className="w-full md:w-72 bg-ash border border-fog px-3 py-2 text-[13px] text-ink placeholder:text-mist focus:outline-none focus:border-stone rounded-[3px]"
        />
      </div>

      {shown.length === 0 ? (
        <div className="py-16 text-center">
          <p className="text-[15px] text-stone">
            {query
              ? zh ? "沒有符合的成員。" : "No member matches that search."
              : zh ? "這一組還沒有人列名。" : "No one is listed in this group yet."}
          </p>
          <Link href={`/${locale}/community/join`} className="inline-block mt-3 text-[13px] text-blue hover:underline underline-offset-4">
            {zh ? "成為這一組的創始成員" : "Be a founding member of this group"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
          </Link>
        </div>
      ) : (
        <ul className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 border-l border-fog bg-white/40">
          {shown.map((m) => (
            <li key={`${m.name}-${m.github ?? ""}`} className="border-r border-b border-fog p-4">
              {m.photo ? (
                <img src={m.photo} alt={m.name} loading="lazy" className="w-full aspect-square object-cover grayscale bg-ash" />
              ) : (
                <div className="w-full aspect-square bg-ash" aria-hidden="true" />
              )}
              <div className="mt-3 text-[15px] text-ink">{m.name}</div>
              <div className="mt-0.5 text-[12.5px] leading-snug text-stone">{m.title}</div>
              {m.organization && <div className="mt-0.5 text-[12.5px] text-graphite">{m.organization}</div>}
              <div className="mt-3 flex flex-wrap gap-1.5 font-data text-[10.5px] text-stone">
                <span className="border border-fog px-1.5 rounded-[2px]">{pick(TIER_NOTE[m.tier])}</span>
                {m.founding && <span className="border border-fog px-1.5 rounded-[2px]">{zh ? "創始成員" : "Founding"}</span>}
                <span className="border border-fog px-1.5 rounded-[2px]">{m.country}</span>
              </div>
              {(m.github || m.disclosure) && (
                <div className="mt-3 flex gap-3 text-[12px]">
                  {m.github && <a href={`https://github.com/${m.github}`} className="text-blue hover:underline underline-offset-4">GitHub</a>}
                  {m.disclosure && <a href={m.disclosure} className="text-blue hover:underline underline-offset-4">{zh ? "利益揭露" : "Disclosure"}</a>}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
