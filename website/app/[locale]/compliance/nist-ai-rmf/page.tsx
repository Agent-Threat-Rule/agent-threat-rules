import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { loadSiteStats } from "@/lib/stats";
import type { Metadata } from "next";
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
  return {
    title: zh
      ? "ATR × NIST AI RMF — 近乎完整的 subcategory 覆蓋"
      : "ATR × NIST AI RMF — near-complete subcategory coverage",
    description: zh
      ? `ATR ${stats.ruleCount} 條規則中多數帶有 NIST AI RMF subcategory 對應。16 個 subcategory,跨 GV / MP / MS / MG 四大 function。MIT License。`
      : `ATR — most of ${stats.ruleCount} rules carry NIST AI RMF subcategory mappings. 16 subcategories spanning all four functions (GV / MP / MS / MG). MIT License.`,
  };
}

type Subcat = {
  id: string;
  function: "GV" | "MP" | "MS" | "MG";
  fn_label_zh: string;
  fn_label_en: string;
  count: number;
  desc_zh: string;
  desc_en: string;
};

const SUBCATEGORIES: Subcat[] = [
  { id: "MG.2.3", function: "MG", fn_label_zh: "MANAGE", fn_label_en: "MANAGE", count: 442, desc_zh: "風險回應——隔離與停用機制", desc_en: "Containment / disengage mechanisms" },
  { id: "MS.2.7", function: "MS", fn_label_zh: "MEASURE", fn_label_en: "MEASURE", count: 358, desc_zh: "安全與韌性評估", desc_en: "Security / resilience evaluation" },
  { id: "MP.5.1", function: "MP", fn_label_zh: "MAP", fn_label_en: "MAP", count: 318, desc_zh: "風險特徵化與追蹤", desc_en: "Risk characterization & tracking" },
  { id: "MS.2.6", function: "MS", fn_label_zh: "MEASURE", fn_label_en: "MEASURE", count: 154, desc_zh: "持續性評估", desc_en: "Continuous evaluation" },
  { id: "GV.6.1", function: "GV", fn_label_zh: "GOVERN", fn_label_en: "GOVERN", count: 70, desc_zh: "第三方與供應鏈治理", desc_en: "Third-party / supply chain governance" },
  { id: "MS.2.10", function: "MS", fn_label_zh: "MEASURE", fn_label_en: "MEASURE", count: 58, desc_zh: "隱私風險評估", desc_en: "Privacy risk assessment" },
  { id: "MG.3.2", function: "MG", fn_label_zh: "MANAGE", fn_label_en: "MANAGE", count: 52, desc_zh: "預訓練模型監控", desc_en: "Pre-trained model monitoring" },
  { id: "MG.4.1", function: "MG", fn_label_zh: "MANAGE", fn_label_en: "MANAGE", count: 30, desc_zh: "部署後監控", desc_en: "Post-deployment monitoring" },
  { id: "MG.3.1", function: "MG", fn_label_zh: "MANAGE", fn_label_en: "MANAGE", count: 30, desc_zh: "第三方風險管理", desc_en: "Third-party risk management" },
  { id: "MS.2.5", function: "MS", fn_label_zh: "MEASURE", fn_label_en: "MEASURE", count: 24, desc_zh: "系統韌性評估", desc_en: "Robustness evaluation" },
  { id: "GV.1.2", function: "GV", fn_label_zh: "GOVERN", fn_label_en: "GOVERN", count: 14, desc_zh: "Accountability 角色設定", desc_en: "Accountability roles" },
  { id: "GV.1.1", function: "GV", fn_label_zh: "GOVERN", fn_label_en: "GOVERN", count: 8, desc_zh: "法規與法律框架對應", desc_en: "Legal / regulatory framework" },
  { id: "MS.1.1", function: "MS", fn_label_zh: "MEASURE", fn_label_en: "MEASURE", count: 2, desc_zh: "評估指標", desc_en: "Evaluation metrics" },
  { id: "MP.3.3", function: "MP", fn_label_zh: "MAP", fn_label_en: "MAP", count: 2, desc_zh: "系統能力文件化", desc_en: "Capabilities documented" },
  { id: "MG.4.2", function: "MG", fn_label_zh: "MANAGE", fn_label_en: "MANAGE", count: 2, desc_zh: "持續性改善機制", desc_en: "Continuous improvement" },
  { id: "GV.6.2", function: "GV", fn_label_zh: "GOVERN", fn_label_en: "GOVERN", count: 2, desc_zh: "第三方應變預案", desc_en: "Third-party contingency" },
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
  const stats = loadSiteStats();

  return (
    <div className="pt-20 pb-20 px-5 md:px-6 max-w-[880px] mx-auto">
      {/* Header eyebrow */}
      <Reveal>
        <div className="font-data text-[11px] md:text-xs font-medium text-blue tracking-[1.5px] md:tracking-[3px] uppercase mb-5">
          Compliance · NIST AI RMF · v0.2 · May 2026
        </div>
      </Reveal>

      {/* H1 */}
      <Reveal delay={0.05}>
        <h1 className="font-display text-[clamp(32px,5vw,52px)] font-extrabold tracking-[-2px] md:tracking-[-3px] leading-[1.08] text-ink">
          {zh ? "ATR 規則近乎完整對應" : "Near-complete coverage of"}
          <br />
          <span className="text-blue">{zh ? "NIST AI RMF subcategory。" : "NIST AI RMF subcategories."}</span>
        </h1>
        <p className="text-sm text-stone mt-3 leading-[1.6]">
          {zh ? "(逐條分布見下方表格)" : "(see the subcategory table below)"}
        </p>
      </Reveal>

      {/* Speed line */}
      <Reveal delay={0.08}>
        <div className="h-[2px] bg-blue w-20 my-8" />
      </Reveal>

      {/* Lead paragraph */}
      <Reveal delay={0.12}>
        <p className="text-[18px] md:text-[21px] font-medium text-ink leading-[1.55] max-w-[720px]">
          {zh ? (
            <>
              首版於 2026-05-09 隨 ATR v2.1.0 發布,當時 330 條規則全部對應。隨著 corpus 成長到 {stats.ruleCount} 條,
              <strong> compliance.nist_ai_rmf </strong>metadata 同步擴張到多數規則,逐條分布見下方 subcategory 表格。
            </>
          ) : (
            <>
              First shipped 2026-05-09 with ATR v2.1.0 — all 330 rules then in the corpus carried{" "}
              <strong>compliance.nist_ai_rmf</strong> metadata. As the corpus has grown to {stats.ruleCount} rules,
              the NIST AI RMF metadata now covers most of them; the per-subcategory distribution is in the table below.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.7] max-w-[720px] mt-4">
          {zh
            ? "每條對應引用該規則的具體偵測元素(regex / token / signature),而非制式樣板。可下載、可審核、可逐條驗證。"
            : "Each mapping cites the specific detection element (regex / token / signature) used by that rule — not generic boilerplate. Downloadable, auditable, and verifiable rule by rule."}
        </p>
      </Reveal>

      {/* Community OSCAL contribution — submission status (honest framing) */}
      <Reveal delay={0.14}>
        <div className="bg-paper border border-fog p-5 md:p-6 mt-8 mb-4">
          <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">
            {zh ? "社群 OSCAL 貢獻 · 目前狀態" : "Community OSCAL contribution · current status"}
          </div>
          <p className="text-sm md:text-base text-graphite leading-[1.8] mb-3">
            {zh
              ? "ATR 維護者把 NIST AI RMF 整理成 OSCAL 格式的社群 catalog(72 個控制項 + 31 個交叉參照連結),以 CC0 授權發布在 Agent-Threat-Rule/ai-rmf-oscal-catalog。這份 catalog 是「社群自發整理」,不是 NIST 官方產出。"
              : "The ATR maintainers transcribed NIST AI RMF into an OSCAL-format community catalog (72 controls + 31 cross-reference links), published under CC0 at Agent-Threat-Rule/ai-rmf-oscal-catalog. This catalog is a community contribution, NOT a NIST publication."}
          </p>
          <p className="text-sm md:text-base text-graphite leading-[1.8] mb-3">
            {zh
              ? "我們進一步把 catalog 提交給 NIST 官方的 usnistgov/oscal-content 倉庫:submission 審查中,NIST OSCAL maintainer 已開了 collaboration branch #338 一起調整內容。我們已寄信 oscal@nist.gov 詢問方向,等待 NIST 團隊指引中。"
              : "The catalog was further submitted to NIST's official usnistgov/oscal-content repo. The submission is in review; the NIST OSCAL maintainer opened a collaboration branch (#338) to align on the content. We have emailed oscal@nist.gov asking for direction; awaiting their response."}
          </p>
          <div className="bg-ash/40 border border-fog p-4 text-sm text-stone leading-[1.7]">
            <span className="font-data text-xs text-stone tracking-[2px] uppercase block mb-2">
              {zh ? "我們不主張的事項" : "What this is NOT"}
            </span>
            {zh
              ? "這不是 NIST 官方背書、不是 NIST AI RMF 合規認證、不是任何 NIST issuance 的「接受層級」。ATR 是 MIT 授權的獨立開放標準。任何在 NIST 一側的正式採用,以 NIST 自己的公告為準,不以這個頁面為準。"
              : "This is not a NIST official endorsement, not a NIST AI RMF compliance certification, and not any NIST-issued 'acceptance tier'. ATR is an independent MIT-licensed open standard. Any formal adoption on NIST's side will be announced by NIST itself, not by this page."}
          </div>
          <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1">
            <a
              href="https://github.com/Agent-Threat-Rule/ai-rmf-oscal-catalog"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              {zh ? "查看社群 catalog (CC0)" : "Community catalog (CC0)"} &rarr;
            </a>
            <a
              href="https://github.com/usnistgov/oscal-content/pull/338"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              {zh ? "查看 NIST 一側的 collaboration branch #338(審查中)" : "Collaboration branch #338 on NIST side (in review)"} &rarr;
            </a>
          </div>
        </div>
      </Reveal>

      {/* Top-line stats */}
      <Reveal delay={0.16}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-8">
          <StatCell label="Corpus" value={String(stats.ruleCount)} unit="" note={zh ? "目前規則總數" : "rules in corpus"} valueColor="blue" />
          <StatCell label="Subcategories" value="16" unit="" note={zh ? "跨 GV / MP / MS / MG" : "across GV / MP / MS / MG"} />
          <StatCell label="Functions" value="4" unit="" note={zh ? "GV / MP / MS / MG" : "GV / MP / MS / MG"} />
          <StatCell label="License" value="MIT" unit="" note={zh ? "永久免費,可 fork" : "Forever free, forkable"} />
        </div>
      </Reveal>

      {/* Why this matters */}
      <Section label={zh ? "01 · 為什麼這件事重要" : "01 · Why this matters"} delay={0.05}>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh ? (
            <>
              NIST AI Risk Management Framework(AI RMF 1.0 + GenAI Profile)是美國聯邦 AI 機構採用的事實標準,也是 NIST CAISI 推動 COSAiS Single-Agent / Multi-Agent overlay 工作的測量基底。
            </>
          ) : (
            <>
              The NIST AI Risk Management Framework (AI RMF 1.0 + GenAI Profile) is the de-facto standard adopted by US federal AI agencies, and the measurement foundation NIST CAISI is using for the COSAiS Single-Agent / Multi-Agent overlay work.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? (
            <>
              多數 AI 安全產品宣稱「對應 NIST AI RMF」,但通常只是一份封閉文件、一句行銷話術、或單一框架的交叉對照——沒有可逐條審核的 per-rule mapping。
            </>
          ) : (
            <>
              Most AI security products claim &ldquo;NIST AI RMF alignment.&rdquo; In practice the alignment is usually a closed document, a marketing line, or a single-framework crosswalk — without auditable per-rule mappings.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? (
            <>
              ATR 把它做成 MIT 授權、open-source、可重現的 per-rule metadata。任何政府、任何 SOC、任何稽核人員,皆可下載 YAML 逐條檢視:每條規則對應到哪個 subcategory、為何如此對應、以何 detection element 為證據。
            </>
          ) : (
            <>
              ATR ships it as MIT-licensed, open-source, reproducible per-rule metadata. Any government, any SOC, any auditor can download the YAML and inspect, rule by rule, which subcategory each maps to, why, and which detection element justifies it.
            </>
          )}
        </p>
      </Section>

      {/* Subcategory matrix */}
      <Section label={zh ? "02 · Subcategory 分布" : "02 · Subcategory distribution"} delay={0.08}>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mb-5">
          {zh
            ? "16 個 subcategory,涵蓋 NIST AI RMF 的 4 個 function:GV / MP / MS / MG。每條規則可同時對應多個 subcategory(primary + secondary strength);各 subcategory 的對應次數見下表。"
            : "16 subcategories spanning all 4 NIST AI RMF functions (GV / MP / MS / MG). Each rule can map to multiple subcategories (primary + secondary strength); the per-subcategory mapping counts are listed in the table below."}
        </p>
        <div className="bg-paper border border-fog rounded">
          <div className="grid grid-cols-[80px_55px_minmax(0,1fr)_55px] sm:grid-cols-[110px_70px_minmax(0,1fr)_70px] gap-2 sm:gap-3 px-3 sm:px-4 py-2.5 border-b border-fog font-data text-[10.5px] tracking-[1.2px] uppercase text-stone">
            <div>{zh ? "Subcategory" : "Subcategory"}</div>
            <div>{zh ? "Function" : "Function"}</div>
            <div>{zh ? "對應內容" : "What it covers"}</div>
            <div className="text-right">{zh ? "Mappings" : "Mappings"}</div>
          </div>
          {SUBCATEGORIES.map((s) => (
            <div
              key={s.id}
              className="grid grid-cols-[80px_55px_minmax(0,1fr)_55px] sm:grid-cols-[110px_70px_minmax(0,1fr)_70px] gap-2 sm:gap-3 px-3 sm:px-4 py-3 border-b border-fog last:border-b-0 text-sm items-baseline"
            >
              <div className={`font-data font-semibold ${FUNCTION_COLORS[s.function]}`}>{s.id}</div>
              <div className="font-data text-[11.5px] text-graphite">{zh ? s.fn_label_zh : s.fn_label_en}</div>
              <div className="text-graphite text-[13px]">{zh ? s.desc_zh : s.desc_en}</div>
              <div className="font-data text-[12.5px] text-ink text-right tabular-nums">{s.count}</div>
            </div>
          ))}
        </div>
        <p className="text-[11.5px] text-stone mt-3 leading-[1.6]">
          {zh
            ? "MG.2.3 出現次數最多(442 次),因為多數偵測規則都對應到「containment / disengage」回應路徑——偵測本身就是觸發隔離機制的條件。"
            : "MG.2.3 dominates (442 mappings) because most detection rules link into the &ldquo;containment / disengage&rdquo; response path — detection itself is the condition that triggers the isolation mechanism."}
        </p>
      </Section>

      {/* Sample mapping */}
      <Section label={zh ? "03 · 樣本對應(可審核)" : "03 · Sample mapping (auditable)"} delay={0.05}>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mb-5">
          {zh
            ? "每條規則的 NIST 對應都明確引用該規則所偵測的攻擊元素。以下是 ATR-2026-00118(Approval Fatigue Exploitation)的隨機抽樣:"
            : "Every rule's NIST mapping cites the specific detection element it relies on. Sample drawn from ATR-2026-00118 (Approval Fatigue Exploitation):"}
        </p>
        <div className="bg-ink rounded p-5 overflow-x-auto">
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
            ? "context 欄位明確說明這條規則為何歸屬 GV.6.1——不是泛指「governance」,而是「approval fatigue 攻擊違反 oversight 治理政策的具體路徑」。每條規則皆以此格式記錄。"
            : "The context field specifies why this rule belongs to GV.6.1 — not as generic &ldquo;governance,&rdquo; but as the specific attack path through which approval-fatigue violates oversight policy. Every rule is documented this way."}
        </p>
      </Section>

      {/* Methodology */}
      <Section label={zh ? "04 · Mapping 方法論" : "04 · Mapping methodology"} delay={0.05}>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh
            ? "Mapping pipeline 由三段組成:LLM-assisted 批次產生 + per-rule QA + atomic patch。完全 open-source、可重現。"
            : "The mapping pipeline has three stages: LLM-assisted batch generation, per-rule QA, atomic patch. Fully open-source and reproducible."}
        </p>
        <ul className="mt-6 space-y-4 text-sm md:text-base text-graphite leading-[1.7]">
          <li className="grid grid-cols-[130px_1fr] gap-5 max-md:grid-cols-1 max-md:gap-1.5">
            <span className="font-data text-[11px] text-blue tracking-[1.3px] uppercase pt-[3px]">
              {zh ? "輸入" : "Input"}
            </span>
            <span>
              {zh
                ? "v2.1.0 當時的 330 條 ATR rule YAML(detection patterns、test cases、既有 metadata)、NIST AI RMF 1.0 reference、GenAI Profile、手寫 5-shot 範例。新規則的 mapping 沿用同一 batch pipeline 補上。"
                : "The 330 ATR rule YAMLs that existed in v2.1.0 (detection patterns, test cases, existing metadata), NIST AI RMF 1.0 reference, GenAI Profile, hand-written 5-shot examples. Mappings for new rules added to the corpus since v2.1.0 use the same batch pipeline."}
            </span>
          </li>
          <li className="grid grid-cols-[130px_1fr] gap-5 max-md:grid-cols-1 max-md:gap-1.5">
            <span className="font-data text-[11px] text-blue tracking-[1.3px] uppercase pt-[3px]">
              {zh ? "批次產生" : "Batch generator"}
            </span>
            <span>
              <code className="font-data text-[12.5px]">scripts/expand-nist-mapping.ts</code>
              {" — "}
              {zh
                ? "Claude Opus + 5-shot prompt + structured output。每條規則產出 ≥1 個 primary 加 0–3 個 secondary subcategory,並附上 per-mapping context。所有 subcategory ID 嚴格對照 RMF 規格驗證,零 hallucination。"
                : "Claude Opus + 5-shot prompt + structured output. Each rule produces ≥1 primary plus 0–3 secondary subcategory mappings, each with its own context field. Subcategory IDs validated strictly against the RMF reference — zero hallucination."}
            </span>
          </li>
          <li className="grid grid-cols-[130px_1fr] gap-5 max-md:grid-cols-1 max-md:gap-1.5">
            <span className="font-data text-[11px] text-blue tracking-[1.3px] uppercase pt-[3px]">
              {zh ? "原子套用" : "Atomic patcher"}
            </span>
            <span>
              <code className="font-data text-[12.5px]">scripts/apply-nist-mapping.ts</code>
              {" — "}
              {zh
                ? "讀取 proposal YAML、patch 對應規則 YAML 的 compliance.nist_ai_rmf 區塊、tmp + rename 原子寫入、patch 後 YAML 仍可 parse(0 / 261 失敗)。既有的人工 mapping 不會被覆寫。"
                : "Reads each proposal YAML, patches the compliance.nist_ai_rmf block in the corresponding rule YAML, atomic write (tmp + rename), patched YAML still parses (0 / 261 failures). Human-curated mappings already in place are never overwritten."}
            </span>
          </li>
          <li className="grid grid-cols-[130px_1fr] gap-5 max-md:grid-cols-1 max-md:gap-1.5">
            <span className="font-data text-[11px] text-blue tracking-[1.3px] uppercase pt-[3px]">
              {zh ? "成本與時間" : "Cost & time"}
            </span>
            <span>
              {zh
                ? "USD 24.98(原估 USD 34)· wall-clock 約 52 分鐘 · 261 條新 mapping 疊在 v0.1 既有的 69 條之上,當時 v2.1.0 corpus 內的 330 條規則全數對應。"
                : "USD 24.98 (estimated USD 34) · wall-clock ~52 minutes · 261 new mappings layered on top of v0.1's 69, mapping all 330 rules then in the v2.1.0 corpus."}
            </span>
          </li>
          <li className="grid grid-cols-[130px_1fr] gap-5 max-md:grid-cols-1 max-md:gap-1.5">
            <span className="font-data text-[11px] text-blue tracking-[1.3px] uppercase pt-[3px]">
              {zh ? "Provenance" : "Provenance"}
            </span>
            <span>
              {zh
                ? "每條規則的 proposal YAML 完整保存於 proposals/nist/。任何人皆可重跑 pipeline、比對輸出、驗證 mapping 推論。"
                : "Every rule's proposal YAML is preserved under proposals/nist/. Anyone can re-run the pipeline, compare outputs, and audit the mapping rationale."}
            </span>
          </li>
        </ul>
      </Section>

      {/* CAISI relevance */}
      <Section label={zh ? "05 · NIST CAISI 對應位置" : "05 · NIST CAISI relevance"} delay={0.05}>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh ? (
            <>
              ATR 設計上希望能作為 NIST CAISI 推動 COSAiS Single-Agent / Multi-Agent overlay 工作的 reference implementation,並以此回應 RFI NIST-2025-0035。這是 ATR 自行提交的回應,不代表 NIST 已選定 ATR。
            </>
          ) : (
            <>
              ATR is designed to serve as a reference implementation for NIST CAISI&rsquo;s COSAiS Single-Agent and Multi-Agent overlay work, and responds to RFI NIST-2025-0035 on that basis. This is ATR&rsquo;s own submission, not a selection by NIST.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? (
            <>
              CAISI 在 Research Blog 提出的「measurement-science-first」框架,正是我們設計這份 mapping 的根基:每條規則都有可重現的量測證據(garak inthewild benchmark、SKILL.md FP corpus、公開測試 corpus),不是空口宣稱。
            </>
          ) : (
            <>
              The &ldquo;measurement-science-first&rdquo; framing CAISI uses in its Research Blog is the foundation we designed this mapping around: every rule has a reproducible measurement (garak inthewild benchmark, SKILL.md FP corpus, publicly-released test corpora) — not a marketing claim.
            </>
          )}
        </p>
        <ul className="mt-6 space-y-3 text-sm md:text-base text-graphite leading-[1.7]">
          <li className="flex gap-3">
            <span className="text-blue font-data text-xs pt-[5px]">→</span>
            <span>
              {zh ? "RFI 文件編號:" : "RFI docket: "}
              <a href="https://www.regulations.gov/docket/NIST-2025-0035" target="_blank" rel="noopener noreferrer" className="text-blue underline-offset-4 hover:underline">
                NIST-2025-0035
              </a>
              {zh
                ? "(CAISI Issues Request for Information About Securing AI Agent Systems)"
                : " (CAISI Issues Request for Information About Securing AI Agent Systems)"}
            </span>
          </li>
          <li className="flex gap-3">
            <span className="text-blue font-data text-xs pt-[5px]">→</span>
            <span>
              {zh ? "姊妹計畫:" : "Sister project: "}
              <a href="https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization" target="_blank" rel="noopener noreferrer" className="text-blue underline-offset-4 hover:underline">
                NCCoE AI Agent Identity &amp; Authorization
              </a>
              {zh
                ? "——ATR 的偵測層自然位於身分層之上"
                : " — ATR's detection layer naturally sits above the identity layer"}
            </span>
          </li>
          <li className="flex gap-3">
            <span className="text-blue font-data text-xs pt-[5px]">→</span>
            <span>
              {zh
                ? "效能 benchmark:NVIDIA garak in-the-wild jailbreak recall 98.0%(650 樣本)、完整 23-probe garak 38.5%(3,475 樣本)· 498 條已標註 SKILL.md 上 FP rate 0.20% · DOI 10.5281/zenodo.19178002"
                : "Performance benchmarks: 98.0% recall on NVIDIA garak's in-the-wild jailbreak set (650 samples) and 38.5% across the full 23-probe garak suite (3,475 samples) · 0.20% FP rate on 498 labeled benign SKILL.md samples · DOI 10.5281/zenodo.19178002"}
            </span>
          </li>
        </ul>
      </Section>

      {/* CTA */}
      <Section label={zh ? "06 · 自行審核這份 mapping" : "06 · Audit the mapping yourself"} delay={0.05}>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mb-6">
          {zh
            ? "Mapping 是公開 metadata,不是封閉規格。每條規則的 RMF 對應皆在 GitHub 上以 YAML 形式公開可讀——可 fork、可挑戰、可提 PR 修正 strength 或 context。"
            : "The mapping is open metadata, not a closed spec. Every rule's RMF mapping is publicly readable as YAML on GitHub — fork it, challenge it, open a PR to refine strength or context."}
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
            head={zh ? "v3.4.0 已發布" : "v3.4.0 published"}
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
              ? "近乎完整的 NIST AI RMF subcategory 對應——非行銷話術,是可下載、可審核的 YAML metadata,MIT 授權永久免費。"
              : "Near-complete NIST AI RMF subcategory coverage — not a marketing claim. Downloadable, auditable YAML metadata, MIT-licensed forever."}
          </strong>
        </Callout>
        <div className="mt-8 pt-6 border-t border-fog text-sm text-graphite leading-[1.7]">
          <p>
            {zh ? "更完整的脈絡:" : "Broader context: "}
            <Link href={`/${locale}/sovereign-ai-defense`} className="text-blue underline-offset-4 hover:underline">
              {zh ? "Sovereign AI Defense — 公開倡議" : "Sovereign AI Defense — Open Call"}
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
        <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-4 md:mb-5">
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
