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
    "Regulation says you must manage AI agent risk. ATR maps every rule to the framework it answers to — OWASP Agentic, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO 42001, SAFE-MCP — so compliance becomes a detection that runs, not a document that asserts.",
};

// Per-rule coverage figures are enforced in CI by
// `npm run audit:mappings -- --require-full=...` (validate.yml), so the "100%"
// / "every rule" claims below cannot silently drift. SAFE-MCP is technique-level
// (not per-rule) and is labelled as such. Update copy only alongside the gate.
function buildFrameworks(ruleCount: number) {
  return [
    {
      id: "OWASP LLM Top 10 (2025)",
      coverage: "100%",
      desc_en: `All ${ruleCount} rules carry an OWASP LLM Top 10 (2025) reference.`,
      desc_zh: `全部 ${ruleCount} 條規則皆帶有 OWASP LLM Top 10 (2025) 參照。`,
      link: null,
    },
    {
      id: "OWASP Agentic Top 10",
      coverage: "100%",
      desc_en: `All ${ruleCount} rules carry an OWASP Agentic Top 10 reference; all 10 ASI risk categories are covered.`,
      desc_zh: `全部 ${ruleCount} 條規則皆帶有 OWASP Agentic Top 10 參照；10 個 ASI 風險類別全覆蓋。`,
      link: null,
    },
    {
      id: "MITRE ATLAS",
      coverage: "100%",
      desc_en: `All ${ruleCount} rules carry a MITRE ATLAS technique reference, grouped by tactic in the rule explorer. (ATR's own ATLAS crosswalk.)`,
      desc_zh: `全部 ${ruleCount} 條規則皆帶有 MITRE ATLAS 技術參照，在規則瀏覽器中依戰術分組。（ATR 自行整理的 ATLAS 交叉對照。）`,
      link: null,
    },
    {
      id: "NIST AI RMF",
      coverage: "100%",
      desc_en: `All ${ruleCount} rules carry NIST AI RMF subcategory mappings across the GV/MP/MS/MG functions. A community-authored OSCAL catalog (CC0) is self-published, with the NIST OSCAL collaboration branch #338 in review — collaboration, not a NIST endorsement or adoption.`,
      desc_zh: `全部 ${ruleCount} 條規則皆帶有 NIST AI RMF subcategory 對應,涵蓋 GV/MP/MS/MG 四大 function。社群撰寫的 OSCAL catalog 已自行 publish(CC0),NIST OSCAL collaboration branch #338 審查中——是協作,不是 NIST 背書或採用。`,
      link: "nist-ai-rmf",
    },
    {
      id: "EU AI Act",
      coverage: "100%",
      desc_en: `All ${ruleCount} rules map to high-risk-AI obligations (Articles 9, 10, 12, 13, 14, 15). The Act names the duty; ATR supplies the runtime detection that produces evidence against the named article. It is detection evidence, not a compliance guarantee by itself.`,
      desc_zh: `全部 ${ruleCount} 條規則皆對應到高風險 AI 義務（第 9、10、12、13、14、15 條）。法案說的是義務,ATR 給的是能對著該條文跑出證據的執行期偵測。是偵測證據,本身並非合規保證。`,
      link: null,
    },
    {
      id: "ISO 42001",
      coverage: "100%",
      desc_en: `All ${ruleCount} rules map to AI management system clauses (6.2, 8.1–8.4, 9.1).`,
      desc_zh: `全部 ${ruleCount} 條規則皆對應到 AI 管理系統條款（6.2、8.1–8.4、9.1）。`,
      link: null,
    },
    {
      id: "SAFE-MCP",
      coverage: "78/85 techniques",
      desc_en: "Technique-level coverage: 78 of 85 SAFE-MCP techniques are covered by at least one rule (conservative lower bound; last fully enumerated at v1.0.0).",
      desc_zh: "技術層級覆蓋：85 項 SAFE-MCP 技術中至少有一條規則覆蓋 78 項（保守下限，最後完整列舉於 v1.0.0）。",
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
            ? `每一條法規都說同一句話:你必須管理 AI agent 風險。它們沒說的是怎麼在真實成品上證明你做到了。ATR 的 ${stats.ruleCount} 條規則,每一條都帶有六個框架對應——OWASP LLM、OWASP Agentic、MITRE ATLAS、NIST AI RMF、EU AI Act、ISO 42001——合法性與 100% 覆蓋由 CI 強制。一條義務於是接上一個能在 SKILL.md、MCP tool 描述、agent config 上跑的偵測。SAFE-MCP 為技術層級對應(78/85)。所有 metadata 皆 MIT 授權、可下載、可審核。`
            : `Every regulation says the same thing: you must manage AI agent risk. None of them say how to prove it on a real artifact. Each of ATR's ${stats.ruleCount} rules carries six framework mappings — OWASP LLM, OWASP Agentic, MITRE ATLAS, NIST AI RMF, EU AI Act, and ISO 42001 — with validity and 100% coverage enforced in CI. Each obligation thus connects to a detection that runs on a SKILL.md file, an MCP tool description, an agent config. SAFE-MCP is mapped at the technique level (78/85). All metadata is MIT-licensed, downloadable, and auditable.`}
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
                ? "合規官員無法把一個 URL 當成採購證據提交。下載結構化的合規映射包(PDF + JSON):每條規則的框架對應、rule ID 索引、品質分數摘要。因為是開放標準,審稿者不必信任 ATR——他們可以自己驗每一條對應。"
                : "A compliance officer cannot submit a URL as procurement evidence. Download the structured compliance mapping package (PDF + JSON): per-rule framework mappings, a rule ID index, a quality-score summary. Because it is an open standard, a reviewer does not have to trust ATR — they can verify every mapping themselves."}
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
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/main/docs"
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
              ? "「符合某框架」是宣稱;指出偵測某攻擊的那一段 regex,是證據。ATR 的合規對應寫在每條規則的 YAML 裡——具體的 compliance metadata,引用偵測此攻擊的確切 regex 或 token,而非泛指「與該框架對齊」。任何人都能把對應和它聲稱偵測的東西擺在一起看。"
              : "'Aligned with a framework' is an assertion. The exact regex that detects an attack is evidence. ATR's compliance mappings live in each rule's YAML — specific compliance metadata citing the precise regex or token that detects the attack, never a generic claim of 'alignment with framework.' Anyone can put the mapping next to the thing it claims to detect and check."}
          </p>
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/main/rules"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline"
          >
            {zh ? "在 GitHub 查看 raw rule YAML →" : "Browse raw rule YAML on GitHub →"}
          </a>
          <p className="text-sm text-graphite leading-[1.7] mt-4 mb-3">
            {zh
              ? "認為某條對應有誤？這是開放標準——歡迎 fork、挑戰，並提 PR 或開 issue 修正任何 mapping。"
              : "Think a mapping is wrong? This is an open standard — fork it, challenge it, and open a PR or issue to correct any mapping."}
          </p>
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline"
          >
            {zh ? "開 issue 挑戰某條對應 →" : "Open an issue to challenge a mapping →"}
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
