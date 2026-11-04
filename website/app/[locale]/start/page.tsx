import Link from "next/link";
import type { Metadata } from "next";
import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { START_ROUTES } from "@/lib/start-routes";

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
        ? "看你為什麼來，找到 ATR 對應的入口。整合、寫規則、回報誤判、採購稽核、引用、治理，政府和標準組織也有一張。"
        : "Find the part of ATR you came for. Integrating it, writing rules, reporting false positives, procurement and audit, citing it, governance, and work for governments or standards bodies.",
  });
}

export default async function StartPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;

  return (
    <div className="pt-20 pb-16 px-6 max-w-[1120px] mx-auto">
      <Reveal>
        <div className="mb-10">
          <div className="text-[13px] text-stone mb-3">
            {zh ? "從這裡開始" : "Start here"}
          </div>
          <h1 className="text-[32px] md:text-[44px] leading-[1.12] tracking-[-0.03em] font-medium mb-2 text-balance">
            {zh ? "你是為了什麼來的？" : "What brings you to ATR?"}
          </h1>
          <p className="text-base text-stone font-light max-w-[640px]">
            {zh
              ? "挑一張最像你的卡。每張卡只連到兩頁。"
              : "Pick the card closest to why you are here. Each one links to two pages."}
          </p>
        </div>
      </Reveal>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-fog border border-fog">
        {START_ROUTES.map((route, i) => (
          <Reveal key={route.key} delay={0.04 * i}>
            <section className="bg-paper p-6 h-full flex flex-col" aria-labelledby={`start-${route.key}`}>
              <h2 id={`start-${route.key}`} className="font-display text-lg font-bold text-ink mb-2 text-balance">
                {zh ? route.title.zh : route.title.en}
              </h2>
              <p className="text-sm text-graphite leading-[1.7] mb-5 flex-1 text-pretty">
                {zh ? route.body.zh : route.body.en}
              </p>
              <div className="flex flex-wrap gap-x-4 gap-y-1 font-data text-xs">
                {route.links.map((link) => (
                  <Link key={link.href} href={`${prefix}${link.href}`} className="text-blue hover:underline">
                    {zh ? link.label.zh : link.label.en} &rarr;
                  </Link>
                ))}
              </div>
            </section>
          </Reveal>
        ))}
      </div>
    </div>
  );
}
