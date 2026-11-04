import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { loadSiteStats } from "@/lib/stats";
import { loadNistSubcategoryCounts } from "@/lib/nist-counts";
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
  const zh = locale === "zh";
  const stats = loadSiteStats();
  return pageMetadata({
    locale,
    path: "/compliance/nist-ai-rmf",
    title: zh
      ? "ATR 規則的 NIST AI RMF 對應（非官方）"
      : "NIST AI RMF mappings in ATR rules (unofficial)",
    description: zh
      ? `NIST AI RMF 定義了 GOVERN、MAP、MEASURE、MANAGE 四個功能。ATR 的 ${stats.ruleCount} 條規則，每一條都標了子類別對應，把治理流程接到能在真實 agent 成品上觸發的偵測。共 ${loadNistSubcategoryCounts().length} 個子類別，橫跨四個功能。MIT 授權。`
      : `NIST AI RMF defines four functions: GOVERN, MAP, MEASURE and MANAGE. Every one of ATR's ${stats.ruleCount} rules carries subcategory mappings, which tie those functions to detection that fires on real agent artifacts. ${loadNistSubcategoryCounts().length} subcategories across all four. MIT License.`,
  });
}

type Subcat = {
  id: string;
  function: "GV" | "MP" | "MS" | "MG";
  fn_label_zh: string;
  fn_label_en: string;
  desc_zh: string;
  desc_en: string;
};

// Plain-language labels for the subcategories ATR rules cite. Counts are read
// from the rule files; a subcategory without a label here shows its ID only.
const SUBCATEGORY_LABELS: Subcat[] = [
  { id: "MG.2.3", function: "MG", fn_label_zh: "MANAGE", fn_label_en: "MANAGE", desc_zh: "風險回應：隔離與停用機制", desc_en: "Containment / disengage mechanisms" },
  { id: "MS.2.7", function: "MS", fn_label_zh: "MEASURE", fn_label_en: "MEASURE", desc_zh: "安全與韌性評估", desc_en: "Security / resilience evaluation" },
  { id: "MP.5.1", function: "MP", fn_label_zh: "MAP", fn_label_en: "MAP", desc_zh: "風險特徵化與追蹤", desc_en: "Risk characterization & tracking" },
  { id: "MS.2.6", function: "MS", fn_label_zh: "MEASURE", fn_label_en: "MEASURE", desc_zh: "持續性評估", desc_en: "Continuous evaluation" },
  { id: "GV.6.1", function: "GV", fn_label_zh: "GOVERN", fn_label_en: "GOVERN", desc_zh: "第三方與供應鏈治理", desc_en: "Third-party / supply chain governance" },
  { id: "MS.2.10", function: "MS", fn_label_zh: "MEASURE", fn_label_en: "MEASURE", desc_zh: "隱私風險評估", desc_en: "Privacy risk assessment" },
  { id: "MG.3.2", function: "MG", fn_label_zh: "MANAGE", fn_label_en: "MANAGE", desc_zh: "預訓練模型監控", desc_en: "Pre-trained model monitoring" },
  { id: "MG.4.1", function: "MG", fn_label_zh: "MANAGE", fn_label_en: "MANAGE", desc_zh: "部署後監控", desc_en: "Post-deployment monitoring" },
  { id: "MG.3.1", function: "MG", fn_label_zh: "MANAGE", fn_label_en: "MANAGE", desc_zh: "第三方風險管理", desc_en: "Third-party risk management" },
  { id: "MS.2.5", function: "MS", fn_label_zh: "MEASURE", fn_label_en: "MEASURE", desc_zh: "系統韌性評估", desc_en: "Robustness evaluation" },
  { id: "GV.1.2", function: "GV", fn_label_zh: "GOVERN", fn_label_en: "GOVERN", desc_zh: "問責角色設定", desc_en: "Accountability roles" },
  { id: "GV.1.1", function: "GV", fn_label_zh: "GOVERN", fn_label_en: "GOVERN", desc_zh: "法規與法律框架對應", desc_en: "Legal / regulatory framework" },
  { id: "MS.1.1", function: "MS", fn_label_zh: "MEASURE", fn_label_en: "MEASURE", desc_zh: "評估指標", desc_en: "Evaluation metrics" },
  { id: "MP.3.3", function: "MP", fn_label_zh: "MAP", fn_label_en: "MAP", desc_zh: "系統能力文件化", desc_en: "Capabilities documented" },
  { id: "MG.4.2", function: "MG", fn_label_zh: "MANAGE", fn_label_en: "MANAGE", desc_zh: "持續性改善機制", desc_en: "Continuous improvement" },
  { id: "GV.6.2", function: "GV", fn_label_zh: "GOVERN", fn_label_en: "GOVERN", desc_zh: "第三方應變預案", desc_en: "Third-party contingency" },
];

const FUNCTION_COLORS: Record<string, string> = {
  GV: "text-blue",
  MP: "text-ink",
  MS: "text-ink",
  MG: "text-critical",
};

export default async function NistAiRmfPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: rawLocale } = await params;
  const locale = (locales.includes(rawLocale as Locale) ? rawLocale : "en") as Locale;
  const zh = locale === "zh";
  const labels = new Map(SUBCATEGORY_LABELS.map((s) => [s.id, s]));
  const FN_NAMES: Record<string, string> = { GV: "GOVERN", MP: "MAP", MS: "MEASURE", MG: "MANAGE" };
  const rows = loadNistSubcategoryCounts().map((c) => ({ ...c, fn: c.id.slice(0, 2), label: labels.get(c.id) }));
  const stats = loadSiteStats();

  return (
    <div className="pt-20 pb-20 px-5 md:px-6 max-w-[880px] mx-auto">
      {/* Header eyebrow */}
      <Reveal>
        <div className="font-data text-[11px] md:text-xs font-medium text-blue tracking-[1.5px] md:tracking-[3px] uppercase mb-5">
          {zh ? "合規 · NIST AI RMF · v0.2 · 2026 年 5 月" : "Compliance · NIST AI RMF · v0.2 · May 2026"}
        </div>
      </Reveal>

      {/* H1 */}
      <Reveal delay={0.05}>
        <h1 className="text-[38px] md:text-[56px] leading-[1.06] tracking-[-0.035em] font-medium text-ink">
          {zh ? "NIST AI RMF 定義流程。" : "NIST AI RMF defines the process."}
          <br />
          <span className="text-blue">{zh ? "ATR 讓它偵測得到。" : "ATR makes it detectable."}</span>
        </h1>
        <p className="text-sm text-stone mt-3 leading-[1.6]">
          {zh
            ? "GOVERN、MAP、MEASURE、MANAGE 四個功能，每一個底下都掛了 ATR 規則。各子類別怎麼分布，看下面的表。"
            : "Each of GOVERN, MAP, MEASURE and MANAGE has ATR rules under it. The breakdown by subcategory is below."}
        </p>
      </Reveal>

      {/* Speed line */}
      <Reveal delay={0.08}>
        <div className="h-[2px] bg-ink w-20 my-8" />
      </Reveal>

      {/* Lead paragraph */}
      <Reveal delay={0.12}>
        <p className="text-[18px] md:text-[21px] font-medium text-ink leading-[1.55] max-w-[720px]">
          {zh ? (
            <>
              AI RMF 是治理框架。它告訴你要 GOVERN、MAP、MEASURE、MANAGE 哪些風險，本身卻什麼都不偵測。ATR 把
              <strong> compliance.nist_ai_rmf </strong>metadata 寫進規則裡。每條規則標明自己服務哪個子類別，框架的每個功能底下，就都有真的會觸發的偵測。第一版在 2026-05-09 跟著 v2.1.0 發布，當時 330 條規則全部有對應。規則成長到 {stats.ruleCount} 條之後，對應也補到了每一條。
            </>
          ) : (
            <>
              AI RMF is a governance framework. It tells you which risks to GOVERN, MAP, MEASURE and MANAGE, but it detects nothing on its own. ATR writes{" "}
              <strong>compliance.nist_ai_rmf</strong> metadata into the rules themselves. Each rule declares which subcategory it serves, so every function in the framework has detection under it that actually fires. This first shipped on 2026-05-09 with v2.1.0, when all 330 rules then in the corpus carried the mapping. As the corpus grew to {stats.ruleCount} rules, the mapping grew to cover every one.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.7] max-w-[720px] mt-4">
          {zh
            ? "這些對應不是一句「對齊 NIST」。每一條都引用規則實際靠的偵測元素（regex、token 或 signature），跟 YAML 逐行對得起來。可以下載，可以稽核，任何稽核人員都能推翻它。"
            : "The mapping is not an “aligned with NIST” claim. Each one cites the detection element the rule actually relies on (a regex, token or signature), and you can check it against the YAML line by line. Anyone can download and audit it, and any auditor can refute it."}
        </p>
      </Reveal>

      {/* Community OSCAL contribution — submission status (honest framing) */}
      <Reveal delay={0.14}>
        <div className="bg-paper border border-fog p-5 md:p-6 mt-8 mb-4">
          <div className="text-[13px] text-stone mb-2">
            {zh ? "社群 OSCAL 貢獻 · 目前狀態" : "Community OSCAL contribution · current status"}
          </div>
          <p className="text-sm md:text-base text-graphite leading-[1.8] mb-3">
            {zh
              ? "框架本身是一段段文字。要讓機器讀得懂，得有人把它轉成結構化格式。ATR 維護者把 NIST AI RMF 整理成 OSCAL 格式的社群 catalog，共 72 個控制項、176 條交叉參照連結，以 CC0 授權放在 Agent-Threat-Rule/ai-rmf-oscal-catalog。這份 catalog 是社群自己整理的，不是 NIST 官方出的。"
              : "The framework itself is prose. For a machine to read it, someone has to put it into a structured format. The ATR maintainers turned NIST AI RMF into an OSCAL-format community catalog, with 72 controls and 176 cross-reference links, published under CC0 at Agent-Threat-Rule/ai-rmf-oscal-catalog. It is a community contribution, NOT a NIST publication."}
          </p>
          <p className="text-sm md:text-base text-graphite leading-[1.8] mb-3">
            {zh
              ? "另外，兩份 AI RMF profile 範例以 PR #338 送進 NIST 的 usnistgov/oscal-content repo。6 月，NIST 請這個 PR 先等 NIST 自己的 AI RMF catalog。NIST 7 月把 catalog 加進 develop 分支，8 月這個 PR 照著它重做。PR 還開著，等 NIST 審查。要不要用，由 NIST 決定。"
              : "Separately, two example AI RMF profiles were offered to NIST's usnistgov/oscal-content repository as PR #338. In June NIST asked that it wait for NIST's own AI RMF catalog. NIST added that catalog to its develop branch in July, and the PR was reworked against it in August. It is still open, waiting for NIST review. Whether to use any of it is NIST's call."}
          </p>
          <div className="bg-ash/40 border border-fog p-4 text-sm text-stone leading-[1.7]">
            <span className="font-data text-xs text-stone tracking-[2px] uppercase block mb-2">
              {zh ? "這不是什麼" : "What this is NOT"}
            </span>
            {zh
              ? "這不是 NIST 官方背書，不是 NIST AI RMF 合規認證，也不是 NIST 發出的任何「接受層級」。ATR 是 MIT 授權的獨立開放標準。NIST 那邊若有任何正式採用，以 NIST 自己的公告為準，不以這一頁為準。"
              : "This is not an official NIST endorsement, not a NIST AI RMF compliance certification, and not any NIST-issued 'acceptance tier'. ATR is an independent, MIT-licensed open standard. Any formal adoption on NIST's side will be announced by NIST, not by this page."}
          </div>
          <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1">
            <a
              href="https://github.com/Agent-Threat-Rule/ai-rmf-oscal-catalog"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              {zh ? "看社群 catalog（CC0）" : "Community catalog (CC0)"} &rarr;
            </a>
            <a
              href="https://github.com/usnistgov/oscal-content/pull/338"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              {zh ? "看 usnistgov/oscal-content #338（等 NIST 審查）" : "usnistgov/oscal-content #338 (awaiting NIST review)"} &rarr;
            </a>
          </div>
        </div>
      </Reveal>

      {/* Top-line stats */}
      <Reveal delay={0.16}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-8">
          <StatCell label={zh ? "規則" : "Corpus"} value={String(stats.ruleCount)} unit="" note={zh ? "目前規則總數" : "rules in corpus"} valueColor="blue" />
          <StatCell label={zh ? "子類別" : "Subcategories"} value={String(rows.length)} unit="" note={zh ? "橫跨 GV、MP、MS、MG" : "across GV / MP / MS / MG"} />
          <StatCell label={zh ? "功能" : "Functions"} value="4" unit="" note={zh ? "四個功能都有規則" : "all of GOVERN / MAP / MEASURE / MANAGE"} />
          <StatCell label={zh ? "授權" : "License"} value="MIT" unit="" note={zh ? "永遠免費，可以 fork" : "Free forever, and you can fork it"} />
        </div>
      </Reveal>

      {/* Why this matters */}
      <Section label={zh ? "01 · 為什麼重要" : "01 · Why this matters"} delay={0.05}>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh ? (
            <>
              NIST AI 風險管理框架（AI RMF 1.0 加上 GenAI Profile）是 NIST 發布的框架，給各組織自願採用。它把 AI 風險管理拆成 GOVERN、MAP、MEASURE、MANAGE 四個功能。這是治理的語言，告訴你該管什麼，卻沒告訴你怎麼在一份 SKILL.md 或一段 MCP 工具說明裡，把風險抓出來。
            </>
          ) : (
            <>
              The NIST AI Risk Management Framework (AI RMF 1.0 plus the GenAI Profile) is NIST&apos;s framework for managing AI risk, meant for voluntary use. It splits AI risk management into four functions: GOVERN, MAP, MEASURE and MANAGE. That is the language of governance. It tells you what to manage, not how to catch the risk inside one SKILL.md file or one MCP tool description.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? (
            <>
              多數 AI 資安產品，偏偏在這個缺口上做得最草率。它們說自己「對應 NIST AI RMF」，拿出來的通常是一份不公開的文件、一句行銷話，或只對單一框架的對照表。沒有可以逐條稽核的規則層級對應。框架被引用了，底下卻沒接上任何能在真實成品上觸發的東西。
            </>
          ) : (
            <>
              This gap is where most AI security products are sloppiest. They claim &ldquo;NIST AI RMF alignment,&rdquo; but the alignment is usually a closed document, a line of marketing, or a crosswalk to a single framework. There are no per-rule mappings anyone can audit. The framework gets cited, and nothing that fires on a real artifact is wired beneath it.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? (
            <>
              ATR 把這一層接上，做成 MIT 授權、開源、可以重現的規則層級 metadata。AI RMF 就從治理框架，變成一層能驗證的偵測。政府、SOC 或稽核人員，都能下載 YAML 一條一條看：每條規則對到哪個子類別，為什麼這樣對，拿哪個偵測元素當證據。
            </>
          ) : (
            <>
              ATR fills that layer with per-rule metadata that is MIT-licensed, open source and reproducible. The AI RMF goes from a governance framework to a detection layer you can verify. A government, a SOC or an auditor can download the YAML and check, rule by rule, which subcategory each one maps to, why, and which detection element backs it.
            </>
          )}
        </p>
      </Section>

      {/* Subcategory matrix */}
      <Section label={zh ? "02 · 子類別分布" : "02 · Subcategory distribution"} delay={0.08}>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mb-5">
          {zh
            ? `對應分散在 ${rows.length} 個子類別上，GOVERN、MAP、MEASURE、MANAGE 四個功能沒有一個是空的。治理流程的每一段，底下都掛著會觸發的規則。一條規則可以同時對到好幾個子類別（primary 加 secondary strength）。各子類別的對應次數見下表。`
            : `The mappings land on ${rows.length} subcategories, and none of the four functions (GOVERN, MAP, MEASURE, MANAGE) is empty. Every part of the governance process has rules under it that fire. One rule can map to several subcategories, with primary and secondary strength. The table lists the count for each subcategory.`}
        </p>
        <div className="bg-paper border border-fog ">
          <div className="grid grid-cols-[80px_55px_minmax(0,1fr)_55px] sm:grid-cols-[110px_70px_minmax(0,1fr)_70px] gap-2 sm:gap-3 px-3 sm:px-4 py-2.5 border-b border-fog font-data text-[10.5px] tracking-[1.2px] uppercase text-stone">
            <div>{zh ? "子類別" : "Subcategory"}</div>
            <div>{zh ? "功能" : "Function"}</div>
            <div>{zh ? "對應內容" : "What it covers"}</div>
            <div className="text-right">{zh ? "對應數" : "Mappings"}</div>
          </div>
          {rows.map((s) => (
            <div
              key={s.id}
              className="grid grid-cols-[80px_55px_minmax(0,1fr)_55px] sm:grid-cols-[110px_70px_minmax(0,1fr)_70px] gap-2 sm:gap-3 px-3 sm:px-4 py-3 border-b border-fog last:border-b-0 text-sm items-baseline"
            >
              <div className={`font-data font-semibold ${FUNCTION_COLORS[s.fn] ?? "text-ink"}`}>{s.id}</div>
              <div className="font-data text-[11.5px] text-graphite">{FN_NAMES[s.fn] ?? s.fn}</div>
              <div className="text-graphite text-[13px]">{s.label ? (zh ? s.label.desc_zh : s.label.desc_en) : ""}</div>
              <div className="font-data text-[12.5px] text-ink text-right tabular-nums">{s.count}</div>
            </div>
          ))}
        </div>
        <p className="text-[11.5px] text-stone mt-3 leading-[1.6]">
          {zh
            ? `${rows[0]?.id} 出現最多次，${rows[0]?.count} 次。一條規則可以同時對到好幾個子類別。`
            : `${rows[0]?.id} is cited most, ${rows[0]?.count} times. One rule can map to several subcategories.`}
        </p>
      </Section>

      {/* Sample mapping */}
      <Section label={zh ? "03 · 一條實際的對應" : "03 · Sample mapping (auditable)"} delay={0.05}>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mb-5">
          {zh
            ? "對應寫在規則裡，不是寫在投影片上。每條規則的 NIST 對應，都寫明它服務哪個子類別，以及為什麼。下面是 ATR-2026-00118（Approval Fatigue Exploitation）實際的 metadata："
            : "The mapping lives in the rule, not on a slide. Every rule's NIST mapping states which subcategory it serves and why. Below is the actual metadata from ATR-2026-00118 (Approval Fatigue Exploitation):"}
        </p>
        <div className="bg-ink  p-5 overflow-x-auto">
          <pre className="font-data text-[11.5px] md:text-[12.5px] text-paper leading-[1.6] whitespace-pre-wrap break-words">
{`compliance:
  nist_ai_rmf:
    - subcategory: GV.6.1
      context: Approval fatigue exploitation manipulates
        human-in-the-loop oversight by overwhelming operators
        with rapid permission requests or minimizing
        dangerous actions; GV.6.1 requires data and oversight
        governance policies that preserve meaningful human
        review rather than enabling bulk auto-approval of
        risky tool calls.
      strength: primary`}
          </pre>
        </div>
        <p className="text-[12.5px] text-stone mt-3 leading-[1.65]">
          {zh
            ? "context 欄位寫清楚這條規則為什麼歸在 GV.6.1。不是籠統的「治理」，而是 approval fatigue 攻擊破壞監督政策的那條具體路徑。每條規則都照這個格式記錄。"
            : "The context field says why this rule belongs under GV.6.1. Not generic “governance”, but the specific path by which an approval-fatigue attack breaks oversight policy. Every rule is written up this way."}
        </p>
      </Section>

      {/* Methodology */}
      <Section label={zh ? "04 · 對應怎麼做出來" : "04 · Mapping methodology"} delay={0.05}>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh
            ? "對應流程分三段：LLM 輔助批次產生、逐條 QA、原子寫入。全部開源，可以重現。"
            : "The mapping pipeline has three stages: LLM-assisted batch generation, per-rule QA, and an atomic patch. All of it is open source and reproducible."}
        </p>
        <ul className="mt-6 space-y-4 text-sm md:text-base text-graphite leading-[1.7]">
          <li className="grid grid-cols-[130px_1fr] gap-5 max-md:grid-cols-1 max-md:gap-1.5">
            <span className="font-data text-[11px] text-blue tracking-[1.3px] uppercase pt-[3px]">
              {zh ? "輸入" : "Input"}
            </span>
            <span>
              {zh
                ? "v2.1.0 當時的 330 份 ATR 規則 YAML（偵測 pattern、測試案例、既有 metadata）、NIST AI RMF 1.0 參考文件、GenAI Profile，以及手寫的 5-shot 範例。之後新加的規則，用同一套批次流程補上對應。"
                : "The 330 ATR rule YAMLs in v2.1.0 (detection patterns, test cases, existing metadata), the NIST AI RMF 1.0 reference, the GenAI Profile, and hand-written 5-shot examples. Rules added since v2.1.0 get their mappings from the same batch pipeline."}
            </span>
          </li>
          <li className="grid grid-cols-[130px_1fr] gap-5 max-md:grid-cols-1 max-md:gap-1.5">
            <span className="font-data text-[11px] text-blue tracking-[1.3px] uppercase pt-[3px]">
              {zh ? "批次產生" : "Batch generator"}
            </span>
            <span>
              <code className="font-data text-[12.5px]">scripts/expand-nist-mapping.ts</code>
              {zh ? "：" : ": "}
              {zh
                ? "Claude Opus 搭配 5-shot prompt 和結構化輸出。每條規則產出至少 1 個 primary、0 到 3 個 secondary 子類別對應，每一個都附自己的 context。子類別編號全部對照 RMF 規格嚴格驗過，沒有編造出來的編號。"
                : "Claude Opus with a 5-shot prompt and structured output. Each rule gets at least 1 primary and 0 to 3 secondary subcategory mappings, each with its own context field. Every subcategory ID is checked strictly against the RMF reference, so none are made up."}
            </span>
          </li>
          <li className="grid grid-cols-[130px_1fr] gap-5 max-md:grid-cols-1 max-md:gap-1.5">
            <span className="font-data text-[11px] text-blue tracking-[1.3px] uppercase pt-[3px]">
              {zh ? "原子寫入" : "Atomic patcher"}
            </span>
            <span>
              <code className="font-data text-[12.5px]">scripts/apply-nist-mapping.ts</code>
              {zh ? "：" : ": "}
              {zh
                ? "讀每份 proposal YAML，改寫對應規則 YAML 裡的 compliance.nist_ai_rmf 區塊，先寫 tmp 再 rename，寫入是原子的。改完的 YAML 都還能 parse（261 份，0 失敗）。原本人工整理的對應不會被蓋掉。"
                : "Reads each proposal YAML and patches the compliance.nist_ai_rmf block in the matching rule YAML, writing atomically (tmp, then rename). Every patched YAML still parses (0 failures out of 261). Mappings a person already curated are never overwritten."}
            </span>
          </li>
          <li className="grid grid-cols-[130px_1fr] gap-5 max-md:grid-cols-1 max-md:gap-1.5">
            <span className="font-data text-[11px] text-blue tracking-[1.3px] uppercase pt-[3px]">
              {zh ? "成本與時間" : "Cost & time"}
            </span>
            <span>
              {zh
                ? "USD 24.98（原本估 USD 34）· 實際耗時約 52 分鐘 · 261 條新對應疊在 v0.1 原有的 69 條上，當時 v2.1.0 的 330 條規則因此全部有對應。"
                : "USD 24.98 (estimated USD 34) · about 52 minutes wall-clock · 261 new mappings on top of v0.1's 69, covering all 330 rules then in the v2.1.0 corpus."}
            </span>
          </li>
          <li className="grid grid-cols-[130px_1fr] gap-5 max-md:grid-cols-1 max-md:gap-1.5">
            <span className="font-data text-[11px] text-blue tracking-[1.3px] uppercase pt-[3px]">
              {zh ? "來源紀錄" : "Provenance"}
            </span>
            <span>
              {zh
                ? "每條規則的 proposal YAML 都完整留在 proposals/nist/。誰都可以重跑流程、比對輸出，檢查對應是怎麼推出來的。"
                : "Every rule's proposal YAML is kept under proposals/nist/. Anyone can re-run the pipeline, compare the output, and audit the reasoning behind a mapping."}
            </span>
          </li>
        </ul>
      </Section>

      {/* Related NIST work */}
      <Section label={zh ? "05 · 相關的 NIST 工作" : "05 · Related NIST work"} delay={0.05}>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh ? (
            <>
              NIST 有幾項跟 AI agent 安全有關的公開工作：CAISI 針對 AI agent 系統安全發出的資訊徵詢（RFI，docket NIST-2025-0035）；COSAiS 為單一 agent 和多 agent 系統訂的 SP 800-53 控制 overlay；還有 NCCoE 的 Software and SI Agent Identity and Authorization 專案。ATR 是獨立的開源專案，沒有參與這些工作。NIST 沒有選定 ATR，也沒有背書。
            </>
          ) : (
            <>
              NIST has several public lines of work on AI agent security: CAISI&rsquo;s request for information on securing AI agent systems (docket NIST-2025-0035), the COSAiS SP 800-53 control overlays for single-agent and multi-agent systems, and the NCCoE Software and SI Agent Identity and Authorization project. ATR is an independent open-source project and has no role in any of it. NIST has not selected or endorsed ATR.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? (
            <>
              這一頁的對應，是 LLM 協助起草的理由說明，做法見上面第 04 段。它們主張的是關聯，不是量測結果。偵測效能另外量。
            </>
          ) : (
            <>
              The mappings on this page are rationales drafted with LLM help (see Methodology). They are claims about relevance, not measurements. Detection performance is measured separately.
            </>
          )}
        </p>
        <ul className="mt-6 space-y-3 text-sm md:text-base text-graphite leading-[1.7]">
          <li className="flex gap-3">
            <span className="text-blue font-data text-xs pt-[5px]">→</span>
            <span>
              {zh ? "RFI 文件編號：" : "RFI docket: "}
              <a href="https://www.regulations.gov/docket/NIST-2025-0035" target="_blank" rel="noopener noreferrer" className="text-blue underline-offset-4 hover:underline">
                NIST-2025-0035
              </a>
              {zh
                ? "（CAISI Issues Request for Information About Securing AI Agent Systems）"
                : " (CAISI Issues Request for Information About Securing AI Agent Systems)"}
            </span>
          </li>
          <li className="flex gap-3">
            <span className="text-blue font-data text-xs pt-[5px]">→</span>
            <span>
              {zh ? "相關計畫：" : "Related project: "}
              <a href="https://www.nccoe.nist.gov/projects/software-and-si-agent-identity-and-authorization" target="_blank" rel="noopener noreferrer" className="text-blue underline-offset-4 hover:underline">
                NCCoE Software and SI Agent Identity and Authorization
              </a>
              {zh
                ? "，處理 agent 的身分與授權。偵測是另一層，需要身分層提供的脈絡。"
                : ", on identity and authorization for agents. Detection is a separate layer, and it needs that identity context."}
            </span>
          </li>
          <li className="flex gap-3">
            <span className="text-blue font-data text-xs pt-[5px]">→</span>
            <span>
              {zh
                ? "基準測試的數字按 lane 分開報告，也說明了哪些是 closed-book、哪些在樣本內："
                : "Benchmark figures, reported per lane, with closed-book and in-sample caveats: "}
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules#8-evaluation" target="_blank" rel="noopener noreferrer" className="text-blue underline-offset-4 hover:underline">
                README §8 Evaluation
              </a>
              {" · DOI 10.5281/zenodo.19178002"}
            </span>
          </li>
        </ul>
      </Section>

      {/* CTA */}
      <Section label={zh ? "06 · 自己來稽核" : "06 · Audit the mapping yourself"} delay={0.05}>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mb-6">
          {zh
            ? "對應不是只能看的封閉規格，是可以改的公開 metadata。每條規則的 RMF 對應都以 YAML 放在 GitHub 上，誰都讀得到。可以 fork、可以挑戰，也可以送 PR 修正 strength 或 context。"
            : "The mapping is open metadata, not a closed spec you can only read. Every rule's RMF mapping is public YAML on GitHub. Fork it, challenge it, or open a PR to fix its strength or context."}
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <CTACard
            num="GITHUB"
            head={zh ? "原始碼與規則" : "Source + rules"}
            body="github.com/Agent-Threat-Rule/agent-threat-rules"
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules"
          />
          <CTACard
            num="NPM"
            head={zh ? "npm 套件" : "npm package"}
            body="npm install agent-threat-rules"
            href="https://www.npmjs.com/package/agent-threat-rules"
          />
          <CTACard
            num="SPEC"
            head={zh ? "Schema 與文件" : "Schema + docs"}
            body="compliance-metadata.md"
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/spec/compliance-metadata.md"
          />
        </div>
        <Callout borderColor="blue">
          <strong className="text-ink">
            {zh
              ? "NIST AI RMF 定義要管什麼。ATR 在每個功能底下放了能驗證的偵測，寫成可以下載、可以稽核的 YAML metadata，MIT 授權，永遠免費。"
              : "NIST AI RMF defines what to manage. ATR puts detection you can verify under every function, written as YAML metadata you can download and audit. MIT-licensed, free forever."}
          </strong>
        </Callout>
        <div className="mt-8 pt-6 border-t border-fog text-sm text-graphite leading-[1.7]">
          <p>
            {zh ? "更多背景：" : "Broader context: "}
            <Link href={`/${locale}/sovereign-ai-defense`} className="text-blue underline-offset-4 hover:underline">
              {zh ? "Sovereign AI Defense：公開倡議" : "Sovereign AI Defense: Open Call"}
            </Link>
          </p>
        </div>
      </Section>
    </div>
  );
}

function StatCell({
  label,
  value,
  unit,
  note,
  valueColor = "ink",
}: {
  label: string;
  value: string;
  unit: string;
  note: string;
  valueColor?: "ink" | "blue" | "critical";
}) {
  const colorMap = {
    ink: "text-ink",
    blue: "text-blue",
    critical: "text-critical",
  };
  return (
    <div className="bg-paper p-5">
      <div className="font-data text-[10px] text-blue tracking-[1.2px] uppercase mb-2">
        {label}
      </div>
      <div className={`font-display text-2xl md:text-[26px] font-bold leading-[1.1] tracking-[-0.02em] ${colorMap[valueColor]}`}>
        {value}
        <span className="text-[15px] md:text-lg">{unit}</span>
      </div>
      <div className="text-[11.5px] text-stone mt-1.5 leading-[1.4]">{note}</div>
    </div>
  );
}

function Section({
  label,
  children,
  delay = 0,
}: {
  label: string;
  children: React.ReactNode;
  delay?: number;
}) {
  return (
    <Reveal delay={delay}>
      <section className="mt-12 md:mt-16">
        <div className="text-[13px] text-stone mb-4 md:mb-5">
          {label}
        </div>
        {children}
      </section>
    </Reveal>
  );
}

function Callout({
  children,
  borderColor = "blue",
}: {
  children: React.ReactNode;
  borderColor?: "blue" | "critical";
}) {
  const colorMap = {
    blue: "border-blue",
    critical: "border-critical",
  };
  return (
    <div className={`bg-ash border-l-[3px] ${colorMap[borderColor]} px-7 py-6 my-6 text-ink leading-[1.55]`}>
      {children}
    </div>
  );
}

function CTACard({
  num,
  head,
  body,
  href,
}: {
  num: string;
  head: string;
  body: string;
  href: string;
}) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="block bg-paper p-5 hover:bg-ash transition-colors group"
    >
      <div className="font-data text-[10px] text-blue tracking-[1.2px] uppercase mb-2">
        {num}
      </div>
      <div className="font-display text-base font-bold text-ink mb-1.5 leading-[1.2]">
        {head}
      </div>
      <div className="font-data text-[12px] text-graphite break-all leading-[1.4] group-hover:text-ink transition-colors">
        {body}
      </div>
    </a>
  );
}
