import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { loadSiteStats } from "@/lib/stats";
import type { Metadata } from "next";
import Link from "next/link";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Compliance — ATR",
  description:
    "ATR framework compliance coverage: OWASP Agentic Top 10, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO 42001, and SAFE-MCP. Downloadable compliance mapping for procurement teams.",
};

function buildFrameworks(ruleCount: number) {
  return [
    {
      id: "OWASP Agentic Top 10",
      coverage: "10/10",
      desc_en: "All 10 agentic AI risk categories mapped (mapping under revision).",
      desc_zh: "10 個 agentic AI 風險類別皆有對應（對應修訂中）。",
      link: null,
    },
    {
      id: "MITRE ATLAS",
      coverage: "95.5%",
      desc_en: `402 of ${ruleCount} ATR rules carry MITRE ATLAS technique references. Grouped by tactic in the rule explorer. (ATR's own ATLAS crosswalk; mapping under revision.)`,
      desc_zh: `${ruleCount} 條 ATR 規則中 402 條帶有 MITRE ATLAS 技術參照,在規則瀏覽器中依戰術分組。（ATR 自行整理的 ATLAS 交叉對照;對應修訂中。）`,
      link: null,
    },
    {
      id: "NIST AI RMF",
      coverage: "98.6%",
      desc_en: `415 of ${ruleCount} rules carry NIST AI RMF subcategory mappings, spanning 16 subcategories across GV/MP/MS/MG. A community OSCAL catalog (CC0) is self-published; submission in review (NIST OSCAL collaboration branch #338), not yet a NIST endorsement. (Mapping under revision.)`,
      desc_zh: `${ruleCount} 條規則中 415 條帶有 NIST AI RMF subcategory 對應,涵蓋 GV/MP/MS/MG 四大 function 的 16 個 subcategory。社群版 OSCAL catalog 已自 publish(CC0);submission 審查中(NIST OSCAL collaboration branch #338),尚未是 NIST 官方背書。（對應修訂中。）`,
      link: "nist-ai-rmf",
    },
    {
      id: "SAFE-MCP",
      coverage: "91.8%",
      desc_en: "78 of 85 techniques covered (mapping under revision).",
      desc_zh: "85 項技術中已覆蓋 78 項（對應修訂中）。",
      link: null,
    },
    {
      id: "EU AI Act",
      coverage: "Partial",
      desc_en: "Rules map to high-risk system obligations (Art. 9, 10, 15) for AI systems deployed in agentic contexts. Mapping documented per rule.",
      desc_zh: "規則映射到高風險系統義務（第 9、10、15 條），適用於 agentic context 部署的 AI 系統。每條規則均有文件記錄。",
      link: null,
    },
    {
      id: "ISO 42001",
      coverage: "Partial",
      desc_en: "Rules map to AI management system controls for risk identification, monitoring, and incident response.",
      desc_zh: "規則映射到 AI 管理系統控制項，涵蓋風險識別、監控與事件回應。",
      link: null,
    },
  ];
}

export default async function CompliancePage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const stats = loadSiteStats();
  const frameworks = buildFrameworks(stats.ruleCount);

  return (
    <div className="pt-20 pb-20 px-5 md:px-6 max-w-[1120px] mx-auto">
      <Reveal>
        <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-3">
          {zh ? "合規覆蓋" : "Compliance Coverage"}
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <h1 className="font-display text-[clamp(28px,4vw,48px)] font-extrabold tracking-[-2px] leading-[1.08] text-ink mb-4">
          {zh ? "6 個框架。每條規則都映射。" : "6 frameworks. Every rule mapped."}
        </h1>
      </Reveal>
      <Reveal delay={0.1}>
        <p className="text-base text-stone font-light max-w-[640px] leading-[1.8] mb-4">
          {zh
            ? "ATR 的每條規則均帶有 OWASP、MITRE ATLAS、NIST AI RMF、EU AI Act、ISO 42001、SAFE-MCP 的對應 metadata。所有 metadata 都是 MIT 授權、可下載、可審核的。"
            : "Every ATR rule carries mapping metadata for OWASP, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO 42001, and SAFE-MCP. All metadata is MIT-licensed, downloadable, and auditable."}
        </p>
      </Reveal>

      {/* Procurement download */}
      <Reveal delay={0.15}>
        <div className="bg-ash border border-fog p-5 md:p-6 mb-10 flex flex-col md:flex-row md:items-center md:gap-8">
          <div className="flex-1 mb-4 md:mb-0">
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">
              {zh ? "給採購團隊" : "For procurement teams"}
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {zh
                ? "合規官員無法將 URL 作為採購證據提交。下載結構化的合規映射包（PDF + JSON），包含每條規則的框架對應、rule ID 索引、以及品質分數摘要。"
                : "Compliance officers cannot submit URLs as evidence in procurement. Download the structured compliance mapping package (PDF + JSON) with per-rule framework mappings, rule ID index, and quality score summary."}
            </p>
          </div>
          <div className="flex flex-col gap-3 flex-shrink-0">
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/releases/latest"
              target="_blank"
              rel="noopener noreferrer"
              className="bg-blue text-white px-5 py-2.5 rounded-sm text-sm font-semibold hover:bg-blue-hover transition-colors text-center"
            >
              {zh ? "下載合規映射包 (GitHub Releases) →" : "Download compliance mapping (GitHub Releases) →"}
            </a>
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/compliance/"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline text-center"
            >
              {zh ? "在 GitHub 查看合規文件 →" : "Browse compliance docs on GitHub →"}
            </a>
          </div>
        </div>
      </Reveal>

      {/* Crosswalk disclaimer */}
      <Reveal delay={0.18}>
        <p className="text-xs text-stone leading-[1.7] max-w-[720px] mb-4">
          {zh
            ? "所有對應皆為 ATR 自行整理的交叉對照文件,並非上述各機構的背書。"
            : "All mappings are ATR's own crosswalk documents, not endorsements by the named bodies."}
        </p>
      </Reveal>

      {/* Framework matrix */}
      <Reveal delay={0.2}>
        <div className="space-y-px bg-fog mb-12">
          {frameworks.map((fw) => (
            <div key={fw.id} className="bg-paper p-6 md:p-8">
              <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-start">
                <div className="md:col-span-3">
                  <div className="font-display text-base font-bold text-ink mb-1">{fw.id}</div>
                  <div className="font-data text-xl font-bold text-blue">{fw.coverage}</div>
                </div>
                <div className="md:col-span-7">
                  <p className="text-sm text-graphite leading-[1.7]">
                    {zh ? fw.desc_zh : fw.desc_en}
                  </p>
                </div>
                <div className="md:col-span-2 md:text-right">
                  {fw.link ? (
                    <Link
                      href={`/${locale}/compliance/${fw.link}`}
                      className="font-data text-xs text-blue hover:underline"
                    >
                      {zh ? "詳細頁面 →" : "Detail page →"}
                    </Link>
                  ) : null}
                </div>
              </div>
            </div>
          ))}
        </div>
      </Reveal>

      {/* Per-rule verifiability note */}
      <Reveal>
        <div className="bg-paper border border-fog p-5 md:p-6 mb-8">
          <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">
            {zh ? "可逐條驗證" : "Rule-by-rule verifiability"}
          </div>
          <p className="text-sm text-graphite leading-[1.7] mb-3">
            {zh
              ? "ATR 的合規映射不是行銷話術。每條規則的 YAML 中包含具體的 compliance metadata，引用偵測此攻擊的具體 regex 或 token，而非泛指「符合該框架」。"
              : "ATR's compliance mappings are not marketing claims. Each rule's YAML contains specific compliance metadata citing the exact regex or token that detects the attack — not a generic claim of 'alignment with framework'."}
          </p>
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/main/data/rules"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline"
          >
            {zh ? "在 GitHub 查看 raw rule YAML →" : "Browse raw rule YAML on GitHub →"}
          </a>
        </div>
      </Reveal>

      {/* Links */}
      <Reveal>
        <div className="flex flex-wrap gap-4">
          <Link href={`/${locale}/compliance/nist-ai-rmf`} className="font-data text-xs text-blue hover:underline">
            {zh ? "NIST AI RMF 詳細頁面" : "NIST AI RMF detail"} &rarr;
          </Link>
          <span className="text-fog">|</span>
          <Link href={`/${locale}/coverage`} className="font-data text-xs text-blue hover:underline">
            {zh ? "Benchmark 覆蓋率" : "Benchmark coverage"} &rarr;
          </Link>
          <span className="text-fog">|</span>
          <Link href={`/${locale}/quality-standard`} className="font-data text-xs text-blue hover:underline">
            {zh ? "品質標準" : "Quality standard"} &rarr;
          </Link>
        </div>
      </Reveal>
    </div>
  );
}
