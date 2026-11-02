import Link from "next/link";
import type { Metadata } from "next";
import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";

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

type Bilingual = { en: string; zh: string };

interface Route {
  key: string;
  title: Bilingual;
  body: Bilingual;
  links: ReadonlyArray<{ href: string; label: Bilingual }>;
}

// One sentence and two links per reader. Every link points at a page that
// already exists; this page adds no content of its own.
const ROUTES: ReadonlyArray<Route> = [
  {
    key: "integrate",
    title: { en: "I want to integrate ATR", zh: "我要整合 ATR" },
    body: {
      en: "Load the rules into your scanner, gateway or SIEM, and choose the lane that matches how much you want to block.",
      zh: "把規則載入你的掃描器、閘道或 SIEM,並依你想擋多少選擇對應的 lane。",
    },
    links: [
      { href: "/integrate", label: { en: "Integration paths", zh: "整合方式" } },
      { href: "/rules", label: { en: "Rules by lane", zh: "依 lane 看規則" } },
    ],
  },
  {
    key: "contribute",
    title: { en: "I want to write a rule or report a false positive", zh: "我要寫規則或回報誤判" },
    body: {
      en: "Submit a rule, an evasion or a false positive; every rule passes the same quality gates before it merges.",
      zh: "提交規則、繞過手法或誤判;每條規則合併前都要通過同一套品質閘。",
    },
    links: [
      { href: "/contribute", label: { en: "How to contribute", zh: "如何貢獻" } },
      { href: "/quality-standard", label: { en: "Quality standard", zh: "品質標準" } },
    ],
  },
  {
    key: "audit",
    title: { en: "I am doing procurement or an audit", zh: "我在做採購或稽核" },
    body: {
      en: "See what a conforming engine must do and how rules map to the frameworks you report against; the mappings are ATR's own, not endorsements.",
      zh: "看符規引擎必須做到什麼,以及規則如何對應到你要回報的框架;對應是 ATR 自己的文件,不是背書。",
    },
    links: [
      { href: "/conformance", label: { en: "Conformance", zh: "符規" } },
      { href: "/compliance", label: { en: "Framework mappings", zh: "框架對應" } },
    ],
  },
  {
    key: "cite",
    title: { en: "I want to cite ATR", zh: "我要引用 ATR" },
    body: {
      en: "Cite the specification by version and DOI, so the version you cited stays reachable after the standard moves on.",
      zh: "以版本與 DOI 引用規格,標準往前走之後,你引用的那一版仍然找得到。",
    },
    links: [
      { href: "/citations", label: { en: "Citation formats", zh: "引用格式" } },
      { href: "/spec", label: { en: "Specification", zh: "規格" } },
    ],
  },
  {
    key: "governance",
    title: { en: "I want to see how ATR is governed", zh: "我要看 ATR 怎麼治理" },
    body: {
      en: "Who maintains ATR, how changes merge, how errors are corrected, and how the steering committee is seated.",
      zh: "誰在維護 ATR、變更如何合併、錯誤如何更正,以及技術指導委員會如何就任。",
    },
    links: [
      { href: "/governance", label: { en: "Governance", zh: "治理" } },
      { href: "/charter", label: { en: "Charter", zh: "章程" } },
    ],
  },
  {
    key: "public-sector",
    title: { en: "I represent a government or standards body", zh: "我代表政府或標準組織" },
    body: {
      en: "ATR is a vendor-neutral, MIT-licensed rule format that any country or organization can adopt, audit or fork.",
      zh: "ATR 是廠商中立、MIT 授權的規則格式,任何國家或組織都能採用、稽核或分支。",
    },
    links: [
      { href: "/sovereign-ai-defense", label: { en: "Sovereign AI context", zh: "主權 AI 語境" } },
      { href: "/compliance/nist-ai-rmf", label: { en: "NIST AI RMF mappings", zh: "NIST AI RMF 對應" } },
    ],
  },
];

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
        {ROUTES.map((route, i) => (
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
