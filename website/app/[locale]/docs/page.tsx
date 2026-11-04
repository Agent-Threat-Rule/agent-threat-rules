import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { getSpecMeta } from "@/lib/spec-meta";
import { loadSiteStats } from "@/lib/stats";
import { DOCS_SECTIONS, pick } from "@/lib/docs-nav";
import { DocsShell, Callout, GlanceTable } from "@/components/DocsShell";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/docs",
    title: locale === "zh" ? "文件總覽" : "Documentation overview",
    description:
      locale === "zh"
        ? "ATR 的完整文件：規格、威脅類別、規則、框架對照、實作、分類法、社群與治理。"
        : "The ATR documentation: specification, threat categories, rules, crosswalks, implementation, taxonomies, community and governance.",
  });
}

const SECTION_NOTES: Record<string, { en: string; zh: string }> = {
  standard: { en: "The normative text, how maturity and lanes work, and every change since release.", zh: "規範本文、成熟度與 lane 的運作方式，以及發布以來的每一次變更。" },
  categories: { en: "Ten threat categories, each with its rules, their lanes and the most frequent crosswalks.", zh: "十個威脅類別，各自列出規則、lane 與最常見的框架對照。" },
  crosswalks: { en: "How rules map to OWASP, MITRE ATLAS, NIST AI RMF and regulation. ATR's own documents, not endorsements.", zh: "規則如何對照 OWASP、MITRE ATLAS、NIST AI RMF 與法規。ATR 自己的文件，不是背書。" },
  implement: { en: "Engines, integrations and the conformance suite, and which ATR component each adopter uses.", zh: "引擎、整合與符規測試套件，以及每個採用者用了 ATR 的哪個元件。" },
  evidence: { en: "What a deployment can show an auditor, and how an auditor verifies it from public material.", zh: "部署可以給稽核員看什麼，以及稽核員怎麼用公開資料驗證。" },
  taxonomies: { en: "The ATD technique catalog and the public threat feed.", zh: "ATD 技法目錄與公開威脅情資。" },
  help: { en: "Common questions, who to contact for what, and the privacy notice and terms.", zh: "常見問題、各種事由該找誰，以及隱私說明與使用條款。" },
  governance: { en: "Who maintains ATR, how decisions are made, how to contribute and how to cite.", zh: "誰維護 ATR、怎麼做決定、怎麼貢獻、怎麼引用。" },
};

export default async function DocsOverviewPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const versions = await loadVersionLabels();
  const spec = getSpecMeta();
  const stats = loadSiteStats();

  return (
    <DocsShell
      locale={locale}
      path="/docs"
      eyebrow={zh ? "I. 標準" : "I. Standard"}
      title={zh ? "文件總覽" : "Documentation overview"}
      lead={
        zh
          ? "ATR（Agent Threat Rules）是 AI 代理威脅的開放偵測規則標準：一份規格、一組版本化的規則，以及讓任何引擎都能證明自己符合規格的測試套件。"
          : "ATR (Agent Threat Rules) is an open detection-rule standard for AI agent threats: a specification, a versioned set of rules, and a test suite any engine can use to show it conforms."
      }
      generatedAt={versions.generatedAt}
    >
      <GlanceTable
        rows={[
          { label: zh ? "規格" : "Specification", value: <Link href={`${prefix}/spec`} className="text-blue hover:underline underline-offset-4">{spec.specVersion} · {spec.status}</Link> },
          { label: zh ? "規則" : "Rules", value: zh ? `${stats.ruleCount} 條生效（main 上 ${stats.ruleFileCount} 個檔，${stats.ruleInertCount} 條 inert）` : `${stats.ruleCount} effective (${stats.ruleFileCount} files on main, ${stats.ruleInertCount} inert)` },
          { label: zh ? "發布" : "Release", value: `${versions.npmVerified ? "npm" : "package.json"} ${versions.npm}` },
          { label: zh ? "識別碼" : "Identifiers", value: zh ? "ATR-YYYY-NNNNN，發布後永不改號" : "ATR-YYYY-NNNNN, never reassigned once published" },
          { label: zh ? "授權" : "Licence", value: "MIT" },
          { label: zh ? "治理" : "Governance", value: zh ? "維護者過渡期，TSC 籌組中" : "Maintainer transition; TSC being seated" },
        ]}
      />

      <div className="mt-8 flex flex-col gap-3">
        <Callout label={zh ? "狀態" : "Status"}>
          {zh
            ? "參考引擎是 TypeScript（npm）。Python 與 Go 引擎目前是骨架與介面契約，尚未通過符規測試。"
            : "The reference engine is TypeScript (npm). The Python and Go engines are a skeleton and an interface contract; they have not passed the conformance suite yet."}
        </Callout>
        <Callout label={zh ? "狀態" : "Status"}>
          {zh
            ? "符規測試套件的骨架已在 repository 的 conformance/ 目錄；三個獨立引擎通過 L2 的目標尚未達成。"
            : "The conformance suite skeleton is in the repository under conformance/; three independent engines passing L2 has not happened yet."}
        </Callout>
      </div>

      <section className="mt-14">
        <h2 className="text-[20px] text-ink">{zh ? "文件結構" : "How the documentation is organized"}</h2>
        <div className="mt-5 grid sm:grid-cols-2 border-t border-l border-fog">
          {DOCS_SECTIONS.map((s) => (
            <Link key={s.key} href={`${prefix}${s.links[0].path}`} className="p-6 border-r border-b border-fog bg-white/40 hover:bg-white transition-colors">
              <div className="font-data text-[11px] text-mist">{s.numeral}.</div>
              <div className="mt-1 text-[16px] text-ink">{pick(s.label, locale)}</div>
              <p className="mt-2 text-[13px] leading-[1.6] text-stone">{pick(SECTION_NOTES[s.key], locale)}</p>
              <div className="mt-3 font-data text-[10.5px] text-mist">{s.links.length} {zh ? "頁" : s.links.length === 1 ? "page" : "pages"}</div>
            </Link>
          ))}
        </div>
      </section>

      <section className="mt-14">
        <h2 className="text-[20px] text-ink">{zh ? "給機器讀的" : "For machines"}</h2>
        <ul className="mt-4 border-t border-fog">
          {[
            { href: "/llms.txt", label: "llms.txt", note: zh ? "全站索引，給 AI 代理" : "Site index for AI agents" },
            { href: "/rules/index.json", label: "rules/index.json", note: zh ? "每條規則，含 maturity、lane、對照" : "Every rule with maturity, lanes and mappings" },
            { href: "/rules/index.csv", label: "rules/index.csv", note: zh ? "同一份資料的 CSV" : "The same data as CSV" },
          ].map((x) => (
            <li key={x.href} className="flex justify-between gap-4 py-3 border-b border-fog">
              <a href={x.href} className="font-data text-[12.5px] text-blue hover:underline underline-offset-4">{x.label}</a>
              <span className="text-[12.5px] text-stone">{x.note}</span>
            </li>
          ))}
        </ul>
      </section>
    </DocsShell>
  );
}
