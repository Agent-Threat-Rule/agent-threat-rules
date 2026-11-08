import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { getSpecMeta } from "@/lib/spec-meta";
import { loadSiteStats } from "@/lib/stats";
import { DOCS_SECTIONS, pick } from "@/lib/docs-nav";
import { DocsShell, Callout, GlanceTable } from "@/components/DocsShell";
import Phrased from "@/components/Phrased";

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
        ? "ATR 的文件：規格、威脅類別、規則、框架對照、實作、分類法、社群與治理。"
        : "The ATR documentation: specification, threat categories, rules, crosswalks, implementation, taxonomies, community and governance.",
  });
}

const SECTION_NOTES: Record<string, { en: string; zh: string }> = {
  standard: { en: "The normative text, how maturity and lanes work, and every change since release.", zh: "規範本文，成熟度和 lane 怎麼運作，還有發布以來的每次變更。" },
  categories: { en: "The ten threat categories. Each one lists its rules, their lanes and the crosswalks that come up most.", zh: "十個威脅類別。每一類列出它的規則、lane，和最常出現的框架對照。" },
  crosswalks: { en: "How rules map to OWASP, MITRE ATLAS, NIST AI RMF and regulation. ATR wrote these. They are not endorsements.", zh: "規則怎麼對到 OWASP、MITRE ATLAS、NIST AI RMF 和法規。這些是 ATR 自己寫的，不是背書。" },
  implement: { en: "Engines, integrations, the conformance suite, and which part of ATR each adopter uses.", zh: "引擎、整合、符規測試套件，還有每個採用者用了 ATR 的哪一塊。" },
  evidence: { en: "What a deployment can show an auditor, and how the auditor checks it against public material.", zh: "部署能拿什麼給稽核員看，稽核員又怎麼用公開資料去驗。" },
  taxonomies: { en: "The ATD technique catalog and the public threat feed.", zh: "ATD 技法目錄，和公開的威脅情資。" },
  help: { en: "Common questions, who to contact about what, the privacy notice and the terms.", zh: "常見問題、什麼事該找誰，還有隱私說明和使用條款。" },
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
    <Phrased>
    <DocsShell
      locale={locale}
      path="/docs"
      eyebrow={zh ? "I. 標準" : "I. Standard"}
      title={zh ? "文件總覽" : "Documentation overview"}
      lead={
        zh
          ? "ATR（Agent Threat Rules）是一套開放標準，用規則偵測針對 AI agent 的攻擊。它有一份規格、一組有版本號的規則，還有一套測試，任何引擎都能拿來證明自己符合規格。"
          : "ATR (Agent Threat Rules) is an open standard for detecting threats to AI agents with rules. It has a specification and a versioned set of rules. It also has a test suite any engine can run to show it conforms."
      }
      generatedAt={versions.generatedAt}
    >
      <GlanceTable
        rows={[
          { label: zh ? "規格" : "Specification", value: <Link href={`${prefix}/spec`} className="text-blue hover:underline underline-offset-4">{spec.specVersion} · {spec.status}</Link> },
          { label: zh ? "規則" : "Rules", value: zh ? `${stats.ruleCount} 條生效 · main 上共 ${stats.ruleFileCount} 個檔 · ${stats.ruleInertCount} 條不生效` : `${stats.ruleCount} effective · ${stats.ruleFileCount} files on main · ${stats.ruleInertCount} inert` },
          { label: zh ? "發布" : "Release", value: `${versions.npmVerified ? "npm" : "package.json"} ${versions.npm}` },
          { label: zh ? "識別碼" : "Identifiers", value: zh ? "ATR-YYYY-NNNNN，發布後不會改號" : "ATR-YYYY-NNNNN, never reassigned once published" },
          { label: zh ? "授權" : "License", value: "MIT" },
          { label: zh ? "治理" : "Governance", value: zh ? "維護者過渡期，TSC 籌組中" : "Maintainer transition. The TSC is being seated." },
        ]}
      />

      <div className="mt-8 flex flex-col gap-3">
        <Callout label={zh ? "狀態" : "Status"}>
          {zh
            ? "參考引擎是 TypeScript 版，發布在 npm。Python 和 Go 引擎目前只有骨架和介面契約，還沒通過符規測試。"
            : "The reference engine is the TypeScript one on npm. The Python and Go engines are only a skeleton and an interface contract. Neither has passed the conformance suite yet."}
        </Callout>
        <Callout label={zh ? "狀態" : "Status"}>
          {zh
            ? "符規測試套件的骨架放在 repository 的 conformance/ 目錄。目標是三個獨立引擎通過 L2，目前還沒達成。"
            : "The conformance suite skeleton is in the repository under conformance/. The goal is three independent engines passing L2. That has not happened yet."}
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
            { href: "/llms.txt", label: "llms.txt", note: zh ? "給 AI agent 讀的全站索引" : "Site index for AI agents" },
            { href: "/rules/index.json", label: "rules/index.json", note: zh ? "每條規則，連同 maturity、lane 和對照" : "Every rule with maturity, lanes and mappings" },
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
    </Phrased>
  );
}
