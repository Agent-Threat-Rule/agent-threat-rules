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
        ? "依你的來意找到 ATR 的入口:整合、寫規則或回報誤判、採購與稽核、引用、治理,以及政府與標準組織。"
        : "Find the part of ATR you came for: integrating it, writing rules or reporting false positives, procurement and audit, citation, governance, and government or standards work.",
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
          <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
            {zh ? "從這裡開始" : "Start here"}
          </div>
          <h1 className="font-display text-[clamp(28px,4vw,44px)] font-extrabold tracking-[-2px] mb-2 text-balance">
            {zh ? "你為什麼來?" : "What brings you to ATR?"}
          </h1>
          <p className="text-base text-stone font-light max-w-[640px]">
            {zh
              ? "選最接近你來意的一張卡。每張卡只指向兩個現有頁面。"
              : "Pick the card closest to why you are here. Each one points at two existing pages."}
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
