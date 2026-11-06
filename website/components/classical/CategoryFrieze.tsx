import Link from "next/link";
import Phrased from "@/components/Phrased";

export interface FriezeItem {
  key: string;
  letter: string;
  name: string;
  desc: string;
  count: number;
  href: string;
}

/**
 * The rule categories as an inscribed frieze: a row of metopes, each carrying
 * a Greek letter and the category's name, split by triglyphs, over an
 * architrave inscribed with the frameworks the rules are mapped to. Letters,
 * not pictures: the names are what is carved. On phones the triglyphs drop
 * out and the metopes stack two to a row.
 */
export function CategoryFrieze({ items, inscription, countLabel }: { items: ReadonlyArray<FriezeItem>; inscription: ReadonlyArray<string>; countLabel: string }) {
  // Desktop: two courses of five metopes, each metope preceded by a triglyph
  // and each course closed by one. Phones: a plain two-column grid.
  const firstCourse = (i: number) => (i < 5 ? "lg:border-b lg:border-ink" : "");
  return (
    <Phrased>
    <div className="border border-ink bg-white">
      <svg width="100%" height="14" className="block border-b border-ink text-ink" aria-hidden="true">
        <defs>
          <pattern id="atr-dentil" width="12" height="14" patternUnits="userSpaceOnUse">
            <rect x="3.5" y="5.5" width="6" height="9" fill="none" stroke="currentColor" strokeWidth="1" />
          </pattern>
        </defs>
        <rect width="100%" height="14" fill="url(#atr-dentil)" />
      </svg>
      <ul className="frieze-row grid grid-cols-2 lg:grid-cols-none border-b border-ink">
        {items.map((item, i) => (
          <li key={item.key} className="contents">
            <span className={`hidden lg:block triglyph border-r border-ink ${firstCourse(i)}`} aria-hidden="true" />
            <Link
              href={item.href}
              className={`group flex flex-col items-center text-center px-3 pt-6 pb-5 lg:pt-7 lg:pb-6 border-fog ${i % 2 === 0 ? "border-r" : ""} ${i < items.length - 2 ? "border-b" : ""} lg:border-r-0 ${i < 5 ? "lg:border-b lg:border-ink" : "lg:border-b-0"} hover:bg-ash/40 transition-colors`}
            >
              <span className="font-spec text-[44px] lg:text-[64px] leading-none text-ink" aria-hidden="true">{item.letter}</span>
              <span className="mt-2 w-6 h-px bg-ink/30" aria-hidden="true" />
              <span className="mt-3 text-[14px] leading-snug text-ink group-hover:underline underline-offset-4">{item.name}</span>
              <span className="hidden sm:block mt-1.5 text-[12.5px] leading-[1.55] text-stone max-w-[200px] min-h-[3.1em]">{item.desc}</span>
              <span className="mt-auto pt-2 lg:pt-3 font-data text-[11px] text-graphite tabular-nums">
                {item.count} {countLabel}
              </span>
            </Link>
            {i % 5 === 4 && <span className={`hidden lg:block triglyph ${firstCourse(i)}`} aria-hidden="true" />}
          </li>
        ))}
      </ul>
      <ul className="px-4 py-3 flex flex-col sm:flex-row sm:flex-wrap sm:justify-center gap-x-5 gap-y-1 font-data text-[10.5px] tracking-[0.18em] uppercase text-stone text-center">
        {inscription.map((name) => (
          <li key={name}>{name}</li>
        ))}
      </ul>
    </div>
    </Phrased>
  );
}
