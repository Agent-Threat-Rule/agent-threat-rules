import { loadAllRules, getCategories } from "@/lib/rules";
import { loadSiteStats } from "@/lib/stats";
import { RuleExplorer } from "./RuleExplorer";
import { locales, t, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
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
    path: "/rules",
    title: "Rules",
    description: "Browse all ATR detection rules. Filter by category, severity, and search by name or CVE.",
  });
}

export default async function RulesPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const rules = loadAllRules();
  const categories = getCategories(rules);
  const stats = loadSiteStats();
  const zh = locale === "zh";
  const lanes = stats.laneCounts;

  return (
    <div className="pt-20 pb-16 px-6 max-w-[1120px] mx-auto">
      <div className="mb-8">
        <div className="text-[13px] text-stone mb-3">
          {t(locale, "rules.label")}
        </div>
        <h1 className="text-[32px] md:text-[44px] leading-[1.12] tracking-[-0.03em] font-medium mb-2">
          {t(locale, "rules.heading", { count: String(stats.ruleCount) })}
        </h1>
        <p className="text-base text-stone font-light">
          {t(locale, "rules.sub")}
        </p>
        {/* What each count counts. Same calibers as stats.json ruleCount. */}
        <p className="mt-4 font-data text-xs text-stone leading-[1.8] max-w-[860px]">
          {zh
            ? `main 上 ${stats.ruleFileCount} 個規則檔:${stats.ruleCount} 條生效(至少一個 lane 會載入),${stats.ruleInertCount} 條 inert(status 為 draft 或 deprecated,任何 lane 都不載入)。各 lane 載入數:enforce ${lanes.enforce}(maturity stable)· alert ${lanes.alert}(stable + test)· hunt ${lanes.hunt}(預設,全部生效規則)。`
            : `${stats.ruleFileCount} rule files on main: ${stats.ruleCount} effective (loaded by at least one lane), ${stats.ruleInertCount} inert (status draft or deprecated; no lane loads them). Rules per lane: enforce ${lanes.enforce} (maturity stable) · alert ${lanes.alert} (stable + test) · hunt ${lanes.hunt} (the default; every effective rule).`}
        </p>
        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 font-data text-xs">
          <a href="/rules/index.json" className="text-blue hover:underline" download>
            {zh ? "下載 JSON" : "Download JSON"}
          </a>
          <a href="/rules/index.csv" className="text-blue hover:underline" download>
            {zh ? "下載 CSV" : "Download CSV"}
          </a>
          <span className="text-mist">{zh ? "與本頁同一份資料於建置時產生" : "Built from the same data as this page"}</span>
        </div>
      </div>

      <RuleExplorer rules={rules} categories={categories} locale={locale} />
    </div>
  );
}
