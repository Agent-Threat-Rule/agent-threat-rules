import Link from "next/link";
import type { Metadata } from "next";
import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { START_ROUTES } from "@/lib/start-routes";
import Phrased from "@/components/Phrased";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/start",
    title: locale === "zh" ? "從這裡開始" : "Start here",
    description:
      locale === "zh"
        ? "依你的來意，找到 ATR 裡對應的頁面：整合、寫規則、回報誤判、採購與稽核、引用、治理，也有給政府和標準組織的入口。"
        : "Find the part of ATR you came for: integrating it, writing rules, reporting false positives, procurement and audit, citing it, governance, or representing a government or standards body.",
  });
}

export default async function StartPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;

  return (
    <Phrased>
    <div className="pt-20 pb-16 px-6 md:px-14">
      <Reveal>
        <div className="mb-10">
          <div className="text-[13px] text-stone mb-3">
            {zh ? "從這裡開始" : "Start here"}
          </div>
          <h1 className="text-[32px] md:text-[48px] leading-[1.12] tracking-[-0.01em] font-medium mb-2 text-balance">
            {zh ? "你是為了什麼來的？" : "What brings you to ATR?"}
          </h1>
          <p className="text-base text-stone font-light max-w-[640px]">
            {zh
              ? "找最像你的一列，每一列只連到兩頁。"
              : "Find the row closest to why you are here. Each one links to two pages."}
          </p>
        </div>
      </Reveal>

      <ol className="border-t border-ink">
        {START_ROUTES.map((route) => (
            <li key={route.key} className="grid md:grid-cols-[260px_1fr] gap-x-8 gap-y-2 py-6 border-b border-fog" aria-labelledby={`start-${route.key}`}>
              <h2 id={`start-${route.key}`} className="font-title text-[20px] leading-snug text-ink">
                {zh ? route.title.zh : route.title.en}
              </h2>
              <div>
                <p className="text-[15px] text-graphite leading-[1.7] text-pretty">{zh ? route.body.zh : route.body.en}</p>
                <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-[14px]">
                  {route.links.map((link) => (
                    <Link key={link.href} href={`${prefix}${link.href}`} className="text-ink underline underline-offset-[6px] decoration-ink/30 hover:decoration-ink">
                      {zh ? link.label.zh : link.label.en}
                    </Link>
                  ))}
                </div>
              </div>
            </li>
        ))}
      </ol>
    </div>
    </Phrased>
  );
}
