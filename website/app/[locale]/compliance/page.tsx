import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { loadSiteStats } from "@/lib/stats";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import Link from "next/link";

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
    path: "/compliance",
    title: "Compliance",
    description:
      "Regulations say you must manage AI agent risk. ATR maps every rule to the frameworks it answers to: OWASP Agentic, MITRE ATLAS, NIST AI RMF, EU AI Act and ISO 42001, plus candidate SAF-MCP technique mappings. Compliance becomes a detection that runs, not a document that asserts.",
  });
}

// Per-rule mapping completeness is enforced in CI by
// `npm run audit:mappings -- --require-full=...` (validate.yml), so the
// "every rule" claims below cannot silently drift. They say every rule carries
// a mapping, not that ATR covers the whole framework, so the cards read
// "Every rule" rather than "100%". SAFE-MCP is technique-level (not
// per-rule) and is labelled as such. Update copy only alongside the gate.
function buildFrameworks(ruleCount: number) {
  return [
    {
      id: "OWASP LLM Top 10 (2025)",
      coverage: "Every rule",
      coverage_zh: "每條規則",
      desc_en: `All ${ruleCount} rules carry an OWASP LLM Top 10 (2025) reference.`,
      desc_zh: `全部 ${ruleCount} 條規則都標了 OWASP LLM Top 10（2025）的參照。`,
      link: null,
    },
    {
      id: "OWASP Agentic Top 10",
      coverage: "Every rule",
      coverage_zh: "每條規則",
      desc_en: `All ${ruleCount} rules carry an OWASP Agentic Top 10 reference, and all 10 ASI risk categories are covered.`,
      desc_zh: `全部 ${ruleCount} 條規則都標了 OWASP Agentic Top 10 的參照，10 個 ASI 風險類別都有涵蓋。`,
      link: null,
    },
    {
      id: "MITRE ATLAS",
      coverage: "Every rule",
      coverage_zh: "每條規則",
      desc_en: `All ${ruleCount} rules carry a MITRE ATLAS technique reference, and the rule explorer groups them by tactic. The ATLAS crosswalk is ATR's own.`,
      desc_zh: `全部 ${ruleCount} 條規則都標了 MITRE ATLAS 的技術參照，規則瀏覽器裡按戰術分組。這份 ATLAS 對照是 ATR 自己整理的。`,
      link: null,
    },
    {
      id: "NIST AI RMF",
      coverage: "Every rule",
      coverage_zh: "每條規則",
      desc_en: `All ${ruleCount} rules carry NIST AI RMF subcategory mappings across the GV, MP, MS and MG functions. A community-written OSCAL catalog (CC0) is self-published. Two example AI RMF profiles sit in an open pull request (#338) to NIST's OSCAL content repository, waiting for NIST review. This is not a NIST endorsement or adoption.`,
      desc_zh: `全部 ${ruleCount} 條規則都對到 NIST AI RMF 的子類別，涵蓋 GV、MP、MS、MG 四個功能。社群寫的 OSCAL catalog 已經自行發布（CC0）。兩份 AI RMF profile 範例，放在送給 NIST OSCAL 內容 repo 的 PR #338 裡，還開著，等 NIST 審查。這不是 NIST 的背書，也不是 NIST 採用。`,
      link: "nist-ai-rmf",
    },
    {
      id: "EU AI Act",
      coverage: "Every rule",
      coverage_zh: "每條規則",
      desc_en: `All ${ruleCount} rules map to high-risk AI obligations (Articles 9, 10, 12, 13, 14 and 15). The Act names the duty. ATR supplies runtime detection that produces evidence against that article. Detection evidence on its own is not a compliance guarantee.`,
      desc_zh: `全部 ${ruleCount} 條規則都對到高風險 AI 的義務（第 9、10、12、13、14、15 條）。法案寫的是義務，ATR 給的是執行期的偵測，能對著那一條跑出證據。光有偵測證據，不等於保證合規。`,
      link: null,
    },
    {
      id: "ISO 42001",
      coverage: "Every rule",
      coverage_zh: "每條規則",
      desc_en: `All ${ruleCount} rules map to AI management system clauses (6.2, 8.1–8.4, 9.1).`,
      desc_zh: `全部 ${ruleCount} 條規則都對到 AI 管理系統的條款（6.2、8.1–8.4、9.1）。`,
      link: null,
    },
    {
      id: "SAF-MCP",
      coverage: "55/78 techniques",
      coverage_zh: "55/78 項技術",
      desc_en: "Counted per technique: 55 of 78 active SAF Framework Model v2 techniques have at least one reviewed ATR rule, as a partial or adjacent match. These are candidate mappings. SAF has not validated them, and SAF validates outside mappings in its own registry.",
      desc_zh: "按技術算：SAF Framework Model v2 的 78 項有效技術裡，55 項至少有一條審查過的 ATR 規則對到（partial 或 adjacent）。這些是候選對照，SAF 還沒驗證。要不要驗證，由 SAF 在自己的 registry 決定。",
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
        <div className="text-[13px] text-stone mb-3">
          {zh ? "合規對應" : "Compliance coverage"}
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <h1 className="text-[32px] md:text-[44px] leading-[1.12] tracking-[-0.03em] font-medium text-ink mb-4">
          {zh ? "6 個框架，每條規則都對上了。" : "6 frameworks. Every rule mapped."}
        </h1>
      </Reveal>
      <p className="mt-4 mb-6 max-w-[640px] border-l-2 border-high pl-3 text-[13px] leading-[1.7] text-graphite">
        {zh
          ? "部分框架對應已知有誤，正在重做；偵測不受影響。修正發布前，請把對應當成可能相關的參考，不要當成稽核證據。"
          : "Some framework mappings are known to be wrong and are being redone; detection is not affected. Until the corrections ship, treat the mappings as candidate relevance, not as audit evidence."}{" "}
        <a href={`/${locale}/errata`} className="text-blue hover:underline">{zh ? "看勘誤" : "See the errata"}</a>
      </p>
      <Reveal delay={0.1}>
        <p className="text-base text-stone font-light max-w-[640px] leading-[1.8] mb-4">
          {zh
            ? `每一部法規都在講同一件事：你得管好 AI agent 的風險。沒有一部告訴你，怎麼在真實的成品上證明你做到了。ATR 的 ${stats.ruleCount} 條規則，每一條都帶著六個框架的對應：OWASP LLM、OWASP Agentic、MITRE ATLAS、NIST AI RMF、EU AI Act、ISO 42001。CI 會檢查每個對應都合法，每條規則也都有對應。一條義務就這樣接上一個偵測，能在 SKILL.md、MCP 工具說明、agent 設定檔上跑。SAF-MCP 是技術層級的候選對照（${stats.safeMcp}，SAF 尚未驗證）。所有 metadata 都採 MIT 授權，可以下載，也可以稽核。`
            : `Every regulation says the same thing: you must manage AI agent risk. None of them says how to prove it on a real artifact. Each of ATR's ${stats.ruleCount} rules carries six framework mappings: OWASP LLM, OWASP Agentic, MITRE ATLAS, NIST AI RMF, EU AI Act and ISO 42001. CI checks that every mapping is valid and that every rule has one. So each obligation connects to a detection that runs on a SKILL.md file, an MCP tool description or an agent config. SAF-MCP is mapped per technique, as candidate mappings (${stats.safeMcp}, not validated by SAF). All of the metadata is MIT-licensed. You can download it and audit it.`}
        </p>
      </Reveal>

      {/* Procurement download */}
      <Reveal delay={0.15}>
        <div className="bg-ash border border-fog p-5 md:p-6 mb-10 flex flex-col md:flex-row md:items-center md:gap-8">
          <div className="flex-1 mb-4 md:mb-0">
            <div className="text-[13px] text-stone mb-2">
              {zh ? "給採購團隊" : "For procurement teams"}
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {zh
                ? "合規人員不能交一個網址當採購證據。這裡可以下載結構化的合規對應包（PDF + JSON），裡面有每條規則的框架對應、規則編號索引，還有品質分數摘要。ATR 是開放標準，審的人不必相信 ATR，每一條對應都能自己驗。"
                : "A compliance officer can't file a URL as procurement evidence. Download the structured compliance mapping package (PDF + JSON). It holds the framework mappings for each rule, an index by rule ID and a summary of quality scores. Because ATR is an open standard, a reviewer doesn't have to trust it. They can check every mapping themselves."}
            </p>
          </div>
          <div className="flex flex-col gap-3 flex-shrink-0">
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/releases/latest"
              target="_blank"
              rel="noopener noreferrer"
              className="bg-ink text-white px-5 py-2.5  text-sm font-semibold hover:bg-black transition-colors text-center"
            >
              {zh ? "下載合規對應包（GitHub Releases）→" : "Download compliance mapping (GitHub Releases) →"}
            </a>
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/main/docs"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline text-center"
            >
              {zh ? "在 GitHub 看合規文件 →" : "Browse compliance docs on GitHub →"}
            </a>
          </div>
        </div>
      </Reveal>

      {/* Crosswalk disclaimer */}
      <Reveal delay={0.18}>
        <p className="text-xs text-stone leading-[1.7] max-w-[720px] mb-4">
          {zh
            ? "所有對應都是 ATR 自己整理的對照文件，不代表上面這些機構背書。"
            : "Every mapping is ATR's own crosswalk. None is endorsed by the bodies named here."}
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
                  <div className="font-data text-xl font-bold text-blue">{zh ? fw.coverage_zh : fw.coverage}</div>
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
                      {zh ? "看細節 →" : "Details →"}
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
          <div className="text-[13px] text-stone mb-2">
            {zh ? "每一條都能驗" : "Check it rule by rule"}
          </div>
          <p className="text-sm text-graphite leading-[1.7] mb-3">
            {zh
              ? "說「符合某個框架」，是一種宣稱。把偵測攻擊的那段 regex 指出來，才是證據。ATR 的合規對應寫在每條規則的 YAML 裡，引用的是偵測這個攻擊的那段 regex 或 token，不是一句籠統的「與框架對齊」。誰都能把對應和它說要偵測的東西擺在一起比。"
              : "'Aligned with a framework' is an assertion. The regex that detects the attack is evidence. ATR's compliance mappings live in each rule's YAML. They cite the exact regex or token that detects the attack, never a generic 'aligned with the framework'. Anyone can put a mapping next to the thing it claims to detect and check it."}
          </p>
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/main/rules"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline"
          >
            {zh ? "在 GitHub 看規則的原始 YAML →" : "Browse raw rule YAML on GitHub →"}
          </a>
          <p className="text-sm text-graphite leading-[1.7] mt-4 mb-3">
            {zh
              ? "覺得哪一條對應錯了？這是開放標準。fork 它、挑戰它，開 PR 或 issue 來改。"
              : "Think a mapping is wrong? It's an open standard. Fork it, challenge it, and open a PR or an issue to fix the mapping."}
          </p>
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline"
          >
            {zh ? "開 issue 挑戰一條對應 →" : "Open an issue to challenge a mapping →"}
          </a>
        </div>
      </Reveal>

      {/* Links */}
      <Reveal>
        <div className="flex flex-wrap gap-4">
          <Link href={`/${locale}/compliance/nist-ai-rmf`} className="font-data text-xs text-blue hover:underline">
            {zh ? "NIST AI RMF 細節" : "NIST AI RMF detail"} &rarr;
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
