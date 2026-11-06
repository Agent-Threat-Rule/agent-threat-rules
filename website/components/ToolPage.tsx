import Link from "next/link";
import type { ReactNode } from "react";
import { SheetRow } from "@/components/Sheet";
import { clauses } from "@/lib/clauses";

type B = { en: string; zh: string };

/** Shared layout for the ATR Router and ATR Eval pages. */
export function ToolHero({ zh, name, status, title, lead }: { zh: boolean; name: string; status: B; title: B; lead: B }) {
  const pick = (b: B) => (zh ? b.zh : b.en);
  return (
    <div className="relative px-6 md:px-14 pt-16 md:pt-24 pb-14">
      <div className="text-[15px] text-stone">
        {name}
        <span className="ml-3 text-[12px] text-stone border border-fog px-1.5 py-0.5">{pick(status)}</span>
      </div>
      <h1 className="mt-6 text-[40px] sm:text-[56px] lg:text-[72px] leading-[1.06] tracking-[-0.01em] font-medium text-ink max-w-[960px] text-balance">{zh ? clauses(title.zh) : title.en}</h1>
      <p className="mt-8 text-[17px] md:text-[19px] leading-[1.7] text-graphite max-w-[680px] text-pretty">{pick(lead)}</p>
    </div>
  );
}

export function ToolFigure({ children }: { children: ReactNode }) {
  return (
    <SheetRow>
      <div className="px-6 md:px-14 py-16 md:py-20 bg-paper">{children}</div>
    </SheetRow>
  );
}

export function ToolPoints({ zh, items }: { zh: boolean; items: ReadonlyArray<{ head: B; body: B }> }) {
  const pick = (b: B) => (zh ? b.zh : b.en);
  return (
    <SheetRow>
      <div className="px-6 md:px-14 py-20 md:py-28 grid gap-14">
        {items.map((item) => (
          <div key={item.head.en} className="grid lg:grid-cols-[1fr_1.4fr] gap-4 lg:gap-20">
            <h2 className="text-[26px] md:text-[32px] leading-[1.2] tracking-[-0.01em] font-medium text-ink text-balance">{zh ? clauses(item.head.zh) : item.head.en}</h2>
            <p className="text-[17px] leading-[1.8] text-graphite max-w-[620px]">{pick(item.body)}</p>
          </div>
        ))}
      </div>
    </SheetRow>
  );
}

export function ToolLimits({ zh, title, children }: { zh: boolean; title: B; children: ReactNode }) {
  return (
    <SheetRow>
      <div className="px-6 md:px-14 py-16 md:py-20 grid lg:grid-cols-[1fr_1.4fr] gap-4 lg:gap-20 bg-ash/50">
        <h2 className="text-[20px] leading-[1.3] text-ink">{zh ? title.zh : title.en}</h2>
        <div className="text-[15.5px] leading-[1.8] text-graphite max-w-[620px] space-y-4">{children}</div>
      </div>
    </SheetRow>
  );
}

export function ToolNext({ href, label }: { href: string; label: string }) {
  return (
    <SheetRow>
      <Link href={href} className="group flex items-center justify-between px-6 md:px-14 py-12 hover:bg-ash/60 transition-colors">
        <span className="text-[24px] md:text-[32px] tracking-[-0.02em] text-ink">{label}</span>
        <span className="text-[24px] text-mist group-hover:text-ink group-hover:translate-x-1 transition-all" aria-hidden="true">→</span>
      </Link>
    </SheetRow>
  );
}
