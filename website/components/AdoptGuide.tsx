import Link from "next/link";
import { AUDIENCES } from "@/lib/adopt-guide";

/**
 * Who adopts ATR, set out as a register: one row per reader, with what they
 * run into, what to do, where it runs and the first step. Every row stays
 * visible, so nobody has to guess which tab is theirs.
 */
export function AdoptGuide({ locale }: { locale: string }) {
  const zh = locale === "zh";
  const pick = (t: { en: string; zh: string }) => (zh ? t.zh : t.en);
  const prefix = `/${locale}`;

  return (
    <ol className="border-t border-ink">
      {AUDIENCES.map((a, i) => (
        <li key={a.key} className="grid lg:grid-cols-[48px_220px_1fr] gap-x-8 gap-y-2 py-6 border-b border-fog">
          <span className="hidden lg:block font-title text-[18px] text-stone" aria-hidden="true">{ROMAN[i]}</span>
          <h3 className="font-title text-[21px] leading-snug text-ink">{pick(a.who)}</h3>
          <div className="max-w-[680px]">
            <p className="text-[16px] leading-[1.6] text-ink text-pretty">{pick(a.need)}</p>
            <p className="mt-2 text-[14.5px] leading-[1.7] text-graphite text-pretty">{pick(a.how)}</p>
            <div className="mt-3">
              <Link href={`${prefix}${a.first.href}`} className="text-[15px] text-ink underline underline-offset-[6px] decoration-ink/30 hover:decoration-ink">
                {pick(a.first.label)}
              </Link>
            </div>
          </div>
        </li>
      ))}
    </ol>
  );
}

const ROMAN = ["I", "II", "III", "IV", "V", "VI", "VII"];
