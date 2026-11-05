"use client";

import Link from "next/link";
import { useState } from "react";
import { AUDIENCES } from "@/lib/adopt-guide";

/** Pick who you are; read what you run into, what to do, and the first step. */
export function AdoptGuide({ locale }: { locale: string }) {
  const zh = locale === "zh";
  const pick = (t: { en: string; zh: string }) => (zh ? t.zh : t.en);
  const [active, setActive] = useState(0);
  const a = AUDIENCES[active];
  const prefix = `/${locale}`;

  return (
    <div className="grid lg:grid-cols-[260px_1fr] gap-x-16">
      <div role="tablist" aria-label={zh ? "你是誰" : "Who you are"} className="flex flex-wrap lg:flex-nowrap lg:flex-col gap-x-6 border-b lg:border-b-0 border-fog -mx-1 px-1">
        {AUDIENCES.map((item, i) => (
          <button
            key={item.key}
            role="tab"
            aria-selected={i === active}
            onClick={() => setActive(i)}
            className={`shrink-0 text-left py-2.5 lg:py-2.5 text-[16px] lg:text-[18px] whitespace-nowrap transition-colors border-b-2 lg:border-b-0 ${
              i === active ? "text-ink border-brand" : "text-mist border-transparent hover:text-ink"
            }`}
          >
            {pick(item.who)}
          </button>
        ))}
      </div>

      <div role="tabpanel" key={a.key} className="pt-8 lg:pt-2 animate-[fadein_400ms_ease-out]">
        <p className="text-[24px] md:text-[30px] leading-[1.35] tracking-[-0.015em] text-ink max-w-[720px] text-pretty">{pick(a.need)}</p>
        <p className="mt-5 text-[16px] leading-[1.75] text-graphite max-w-[600px] text-pretty">{pick(a.how)}</p>
        <p className="mt-5 text-[13px] text-stone">{pick(a.where)}</p>
        <div className="mt-8 flex flex-wrap items-center gap-4">
          {a.first.code && <code className="font-data text-[13px] bg-ash text-ink px-3 py-2 select-all">{a.first.code}</code>}
          <Link href={`${prefix}${a.first.href}`} className="text-[15px] text-ink underline underline-offset-[6px] decoration-brand decoration-2 hover:decoration-ink">
            {pick(a.first.label)}
          </Link>
        </div>
      </div>
    </div>
  );
}
