import { Reveal } from "@/components/Reveal";
import { DocumentStatus } from "@/components/spec/DocumentStatus";
import { loadVersionLabels, npmInstallSpec } from "@/lib/versions";
import { locales, t, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import Phrased from "@/components/Phrased";
import { Sign } from "@/components/Sign";
import { loadAllRules } from "@/lib/rules";
import { provenanceBreakdown, shareOf } from "@/lib/provenance";

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
    path: "/quality-standard",
    title: "Quality Standard (RFC-001 v1.1)",
    description:
      "An open detection-rule quality standard for the AI agent era. A maturity ladder with explicit gates, detection lanes measured separately instead of with a single figure, and a vendor-neutral validator anyone can run. MIT licensed. Effective 2026-04-14.",
  });
}

/* =============================================================
   RFC-001 data — the formula, maturity ladder, gauntlet, evidence
   ============================================================= */

const FORMULA_COMPONENTS = [
  {
    name: "Precision",
    nameZh: "精確度",
    weight: "40%",
    formula: "(1 − wild_fp_rate) × 100",
    meaning: "Measured false-positive rate on real-world corpora.",
    meaningZh: "在真實語料上量到的誤報率。",
  },
  {
    name: "Wild validation",
    nameZh: "野外驗證",
    weight: "30%",
    formula: "min(wild_samples / 10,000, 1) × 100",
    meaning: "How much real data the rule has survived.",
    meaningZh: "規則跑過多少真實資料仍然站得住。",
  },
  {
    name: "Coverage",
    nameZh: "涵蓋深度",
    weight: "20%",
    formula: "min(conditions / 5, 1) × 100",
    meaning: "Detection depth: the distinct attack layers covered.",
    meaningZh: "偵測深度，也就是涵蓋了幾個不同的攻擊層。",
  },
  {
    name: "Evasion docs",
    nameZh: "繞過紀錄",
    weight: "10%",
    formula: "min(documented_evasions / 5, 1) × 100",
    meaning: "Honest acknowledgment of known bypass techniques.",
    meaningZh: "老實記下已知的繞過手法。",
  },
];

// Canonical maturity ladder = the rule `status` field progression:
// draft → experimental → test → stable → deprecated. Keep this aligned with
// the glossary `maturity` entry.
const MATURITY_LEVELS = [
  {
    label: "Draft",
    gate: "Valid schema · ≥1 TP + 1 TN · no ReDoS",
    gateZh: "schema 合法 · 至少 1 個 TP 和 1 個 TN · 沒有 ReDoS",
    deploy: "Not deployed",
    deployZh: "不部署",
  },
  {
    label: "Experimental",
    gate: "3+ TP + 3+ TN · CI pass · OWASP + MITRE mapping encouraged (not required) · evasion tests encouraged (not required)",
    gateZh: "3 個以上 TP 和 3 個以上 TN · 通過 CI · 建議（不強制）對應 OWASP 與 MITRE · 建議（不強制）附繞過測試",
    deploy: "Alert-only",
    deployZh: "只告警",
  },
  {
    label: "Test",
    gate: "Canary observation passed · wild FP measured · no unresolved false-positive reports in the canary window",
    gateZh: "通過 canary 觀察期 · 已量測野外誤報 · 觀察期內沒有未解決的誤報回報",
    deploy: "Alert-only, promotion candidate",
    deployZh: "只告警，可列為升級候選",
  },
  {
    label: "Stable",
    gate: "Wild-validated (1,000+ samples) · FP rate ≤ 0.5% · human-verified provenance · ≥3 evasion tests",
    gateZh: "通過野外驗證（1,000 筆以上樣本）· 誤報率 ≤ 0.5% · 來源經人工確認 · 至少 3 個繞過測試",
    deploy: "Block in production",
    deployZh: "可在正式環境封鎖",
  },
  {
    label: "Deprecated",
    gate: "Superseded or demoted · retained for provenance · engines MUST NOT enable by default",
    gateZh: "已被取代或降級 · 為保留來源紀錄而留著 · 引擎預設 MUST NOT 啟用",
    deploy: "Off by default",
    deployZh: "預設關閉",
  },
];

// The path every rule takes today, whoever drafted it. Stages 2 to 4 are CI
// jobs in .github/workflows (validate.yml, rule-quality.yml, redos-gate.yml,
// re2-portability.yml, maturity-fp-gate.yml); stage 6 is publish.yml.
const GAUNTLET_STAGES = [
  {
    stage: "1",
    title: "Pull request",
    titleZh: "Pull request",
    detailZh: "規則來自 CVE 與安全公告掃描、benchmark 漏報挖掘和貢獻者。不管是人寫的還是 LLM 協助起草的，都要開 pull request 才能進 main。",
    detail:
      "Rules come from CVE and advisory sweeps, benchmark-miss mining and contributors. Whether a person or an LLM drafted it, a rule reaches main only through a pull request.",
  },
  {
    stage: "2",
    title: "Schema and own tests",
    titleZh: "Schema 與自身測試",
    detailZh: "規則要符合 schema，對應的框架條款要在允許清單裡，而且要抓到自己列出的每一個真陽性樣本。",
    detail:
      "The rule must match the schema, its framework mappings must be on the allowlists, and it must catch every true positive it lists.",
  },
  {
    stage: "3",
    title: "Benign corpus",
    titleZh: "良性語料",
    detailZh: "新規則在公開的良性 skill 語料和「提到攻擊但不是攻擊」的研究語料上都不能有誤報，也不能命中其他規則的真陰性樣本。",
    detail:
      "A new rule may not fire on the public benign skill corpus or on the corpus of text that mentions attacks without being one, and may not match any other rule's true negatives.",
  },
  {
    stage: "4",
    title: "Regex safety",
    titleZh: "Regex 安全",
    detailZh: "regex 要過 ReDoS 閘和 RE2 可攜性檢查。已知的舊問題記在 baseline 裡，數量只能減少，不能增加。",
    detail:
      "Regexes must pass the ReDoS gate and the RE2 portability check. Known older problems are tracked in a baseline that may shrink but not grow.",
  },
  {
    stage: "5",
    title: "Maintainer review",
    titleZh: "維護者審查",
    detailZh: "由維護者審查後合併。把規則升到 stable 的 PR，還要在良性語料上維持零誤報，否則 CI 不會過。",
    detail:
      "A maintainer reviews and merges. A pull request that promotes a rule to stable must also stay at zero false positives on the benign corpus, or CI fails.",
  },
  {
    stage: "6",
    title: "Staged release",
    titleZh: "分段發布",
    detailZh: "維護者推版本 tag 後，CI 把新版 stage 到 npm，再由維護者用 2FA 核准才會上線。",
    detail:
      "After a maintainer pushes a version tag, CI stages the release on npm, and it goes live only once a maintainer approves it with 2FA.",
  },
];

type ComparisonRow = {
  feature: string;
  featureZh: string;
  atr: "yes" | "no" | "partial";
  sigma: "yes" | "no" | "partial";
  yara: "yes" | "no" | "partial";
  owasp: "yes" | "no" | "partial";
  suricata: "yes" | "no" | "partial";
};

const COMPARISON: ComparisonRow[] = [
  {
    feature: "Maturity ladder with explicit gates",
    featureZh: "成熟度階梯，每一階都有明確門檻",
    atr: "yes",
    sigma: "yes",
    yara: "no",
    owasp: "yes",
    suricata: "yes",
  },
  {
    feature: "Formula-based confidence score (0–100)",
    featureZh: "以公式計算的信心分數（0–100）",
    atr: "yes",
    sigma: "no",
    yara: "no",
    owasp: "no",
    suricata: "partial",
  },
  {
    feature: "Wild validation required for production",
    featureZh: "上正式環境前必須通過野外驗證",
    atr: "partial",
    sigma: "no",
    yara: "no",
    owasp: "no",
    suricata: "no",
  },
  {
    feature: "Per-field provenance tracking",
    featureZh: "逐欄位記錄來源",
    atr: "partial",
    sigma: "no",
    yara: "no",
    owasp: "no",
    suricata: "no",
  },
  {
    feature: "Automatic demotion on quality regression",
    featureZh: "品質退化時自動降級",
    atr: "partial",
    sigma: "no",
    yara: "no",
    owasp: "no",
    suricata: "no",
  },
  {
    feature: "Open-source reference implementation",
    featureZh: "開源的參考實作",
    atr: "yes",
    sigma: "yes",
    yara: "yes",
    owasp: "yes",
    suricata: "yes",
  },
];

function Cell({ v }: { v: "yes" | "no" | "partial" }) {
  if (v === "yes") return <span className="text-ink">✓</span>;
  if (v === "partial") return <span className="text-stone">~</span>;
  return <span className="text-mist">—</span>;
}

// Static evidence literals. This page does not bind to lib/stats.ts, so each
// figure carries an explicit "as of" date. Re-verify against data/stats.json
// before citing externally — rule/scan counts move.
const EVIDENCE = [
  { stat: "Merged", statZh: "已合併", label: "ATR rule pack merged into cisco-ai-defense/skill-scanner (PR #99, 2026-04-22)", labelZh: "ATR 規則包已合併進 cisco-ai-defense/skill-scanner（PR #99，2026-04-22）" },
  { stat: "101,280", statZh: "101,280", label: "Real agent skills and MCP definitions scanned across 5 registries (engine v2.0.0, as of 2026-04-13)", labelZh: "在 5 個 registry 掃描過的真實 agent skill 與 MCP 定義（engine v2.0.0，截至 2026-04-13）" },
  { stat: "1,434", statZh: "1,434", label: "Items flagged by that scan (as of 2026-04-13)", labelZh: "那次掃描標記出的項目（截至 2026-04-13）" },
  { stat: "Withdrawn", statZh: "已撤回", label: "Per-lane false-positive rates, withdrawn pending re-measurement", labelZh: "各車道的誤報率，已撤回，等重新量測" },
];

/* =============================================================
   PAGE
   ============================================================= */

export default async function QualityStandardPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const installSpec = npmInstallSpec(await loadVersionLabels());
  const prov = provenanceBreakdown(loadAllRules());

  return (
    <Phrased>
    <div className="pt-20 pb-16 px-6 md:px-14">
      {/* ── HERO ───────────────────────────────────────────── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {locale === "zh" ? "RFC-001 · 品質標準" : "RFC-001 · Quality Standard"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="text-[32px] md:text-[48px] leading-[1.12] tracking-[-0.01em] font-medium mb-3 leading-[1.05]">
          {locale === "zh" ? (
            <>
              具備
              <br />
              <span>來源追溯</span>的
              <br />
              AI Agent 規則品質標準
            </>
          ) : (
            <>
              An AI agent rule standard
              <br />
              with provenance tracking
            </>
          )}
        </h1>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-base text-stone font-light mb-8 max-w-2xl">
          {locale === "zh"
            ? "一個偵測標準可不可信，要看它敢不敢公開自己最差的數字。每條規則都有可以自己算的信心分數，每個對應都有能查核的來源，誤報率也按偵測車道分開公布，不用單一個好看的數字帶過。公式公開，程式碼開源，資料來自真實環境的掃描。"
            : "A detection standard earns trust by publishing its worst figure. Every rule has a confidence score you can compute yourself, and every mapping has a source you can audit. Each detection lane reports its own false-positive rate, not one flattering number. The formula is public, the code is open source, and the data comes from real-world scans."}
        </p>
      </Reveal>
      {/* DocumentStatus banner — keeps this RFC-001 page visually aligned
          with /spec, /implementers, /conformance, etc. Section anchor lets
          readers know this document covers §RFC-001 of the spec family. */}
      <Reveal delay={0.25}>
        <div className="mb-6">
          <DocumentStatus locale={locale} />
        </div>
      </Reveal>
      <Reveal delay={0.3}>
        <div className="flex flex-wrap items-center gap-4 mb-16">
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/proposals/001-atr-quality-standard-rfc.md"
            target="_blank"
            rel="noopener noreferrer"
            className="text-[15px] text-ink underline underline-offset-[6px] decoration-ink/30 hover:decoration-ink"
          >
            {locale === "zh" ? "閱讀 RFC-001" : "Read RFC-001"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
          </a>
          <a
            href="https://www.npmjs.com/package/agent-threat-rules"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-stone hover:text-ink transition-colors border border-fog px-4 py-2.5 "
          >
            {`npm install ${installSpec}`}
          </a>
        </div>
      </Reveal>

      {/* ── EVIDENCE STRIP ─────────────────────────────────── */}
      <Reveal>
        <dl className="border-t border-ink mb-16">
          {EVIDENCE.map((e) => (
            <div key={e.label} className="grid grid-cols-[120px_1fr] md:grid-cols-[200px_1fr] gap-x-6 py-4 border-b border-fog items-baseline">
              <dt className="font-title text-[22px] text-ink tabular-nums">
                {locale === "zh" ? e.statZh : e.stat}
              </dt>
              <dd className="text-[14px] text-graphite leading-snug">{locale === "zh" ? e.labelZh : e.label}</dd>
            </div>
          ))}
        </dl>
      </Reveal>

      {/* ── PROVENANCE RATIO ─────────────────────────────────
          Counted from rules/ at build time (lib/provenance.ts); no share on
          this page is typed by hand. */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {locale === "zh" ? "規則來源組成" : "Rule provenance breakdown"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-medium tracking-[-1px] mb-2">
          {locale === "zh"
            ? "哪些規則的對應經過人工確認。"
            : "Which rules have mappings a person checked."}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? `規則的 metadata_provenance 欄位記錄每個對應（OWASP、MITRE、CWE 等）是誰或什麼設定的，有些規則也記下 payload 取自哪個語料。下面三個數字在建置時從 ${prov.total} 條生效規則算出。這個欄位描述的是對應，不是偵測邏輯由誰撰寫。`
            : `A rule's metadata_provenance field records who or what set each mapping (OWASP, MITRE, CWE and so on), and for some rules which corpus a payload came from. The three figures below are counted from the ${prov.total} effective rules at build time. The field describes the mappings, not who wrote the detection logic.`}
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog border border-fog mb-6">
          <div className="bg-paper p-5 md:p-6">
            <div className="text-[13px] text-stone mb-2">
              {locale === "zh" ? "有人工確認的對應" : "Human-checked mappings"}
            </div>
            <div className="font-display text-3xl font-medium text-ink mb-1">{shareOf(prov.human, prov.total)}</div>
            <p className="text-sm text-stone leading-relaxed">
              {locale === "zh"
                ? `${prov.human} 條規則至少有一個欄位標記為 human-reviewed 或 human-authored。`
                : `${prov.human} rules mark at least one field human-reviewed or human-authored.`}
            </p>
          </div>
          <div className="bg-paper p-5 md:p-6">
            <div className="text-[13px] text-stone mb-2">
              {locale === "zh" ? "有來源紀錄，沒有人工標記" : "Recorded, not marked by a person"}
            </div>
            <div className="font-display text-3xl font-medium text-ink mb-1">{shareOf(prov.other, prov.total)}</div>
            <p className="text-sm text-stone leading-relaxed">
              {locale === "zh"
                ? `${prov.other} 條規則有這個欄位，但只記了自動產生的對應、同步來源或 payload 語料，沒有欄位標記為人工確認。`
                : `${prov.other} rules have the field, but it records only auto-generated mappings, sync feeds or payload corpora; no field is marked as checked by a person.`}
            </p>
          </div>
          <div className="bg-paper p-5 md:p-6">
            <div className="text-[13px] text-stone mb-2">
              {locale === "zh" ? "沒有來源紀錄" : "No provenance recorded"}
            </div>
            <div className="font-display text-3xl font-medium text-ink mb-1">{shareOf(prov.none, prov.total)}</div>
            <p className="text-sm text-stone leading-relaxed">
              {locale === "zh"
                ? `${prov.none} 條規則沒有 metadata_provenance 欄位，大多早於這個欄位出現。它們的對應無從判斷由誰設定。`
                : `${prov.none} rules have no metadata_provenance field, most of them older than the field. Who set their mappings is not recorded.`}
            </p>
          </div>
        </div>
      </Reveal>
      <Reveal delay={0.2}>
        <div className="border-t border-ink pt-5 mb-16">
          <p className="text-sm text-ink leading-relaxed mb-3">
            {locale === "zh"
              ? `這份標準要求升到 stable 的規則，來源要經過人工確認。目前 ${prov.stable} 條 stable 規則裡，只有 ${prov.stableHuman} 條有這份紀錄，多數 stable 規則早於這項檢查。採用者決定要封鎖哪些規則時，可以自己對照這個欄位。`
              : `The standard asks that a rule reaching stable has provenance a person checked. Today ${prov.stableHuman} of the ${prov.stable} stable rules carry that record; most stable rules predate the check. Adopters deciding which rules to block on can check the field themselves.`}
          </p>
          <p className="text-sm text-stone leading-relaxed">
            {locale === "zh"
              ? "規則集透過 CVE 與安全公告掃描、benchmark 漏報挖掘與貢獻者擴張，每一條都經由維護者合併的 pull request 進入 main。"
              : "The ruleset grows through CVE and advisory sweeps, benchmark-miss mining and contributors, and each rule reaches main through a pull request a maintainer merges."}
          </p>
        </div>
      </Reveal>

      {/* ── THE FORMULA ────────────────────────────────────── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {locale === "zh" ? "公式" : "The Formula"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-medium tracking-[-1px] mb-2">
          {locale === "zh"
            ? "信心分數是數字，不是意見"
            : "Confidence is a number, not an opinion"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "每個組成都由可測量的事實計算而來。公式是公開的，你可以自己跑。"
            : "Every component is computed from measurable facts. Run it yourself — the formula is public."}
        </p>
      </Reveal>

      <Reveal delay={0.1}>
        <div className="border-t border-ink pt-5 mb-6">
          <div className="font-data text-[13px] md:text-sm text-ink bg-fog/40 border border-fog p-4  overflow-x-auto">
            confidence = 0.4 × precision + 0.3 × wild + 0.2 × coverage + 0.1 × evasion
          </div>
        </div>
      </Reveal>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog border border-fog mb-8">
        {FORMULA_COMPONENTS.map((c) => (
          <Reveal key={c.name}>
            <div className="bg-paper p-5 md:p-6 h-full">
              <div className="flex items-center justify-between mb-2">
                <span className="font-display font-semibold text-ink">{locale === "zh" ? c.nameZh : c.name}</span>
                <span className="font-data text-xs text-blue bg-ink/10 px-2 py-0.5 ">
                  {c.weight}
                </span>
              </div>
              <div className="font-data text-xs text-stone mb-2">{c.formula}</div>
              <p className="text-sm text-stone">{locale === "zh" ? c.meaningZh : c.meaning}</p>
            </div>
          </Reveal>
        ))}
      </div>

      <Reveal>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog border border-fog mb-16">
          <div className="bg-paper p-5">
            <div className="font-data text-xs text-blue tracking-wider uppercase mb-1">
              90–100 · Very High
            </div>
            <div className="text-sm text-ink font-semibold">
              {locale === "zh" ? "可在生產環境封鎖" : "Safe to block in production"}
            </div>
          </div>
          <div className="bg-paper p-5">
            <div className="font-data text-xs text-critical tracking-wider uppercase mb-1">
              60–79 · Medium
            </div>
            <div className="text-sm text-ink font-semibold">
              {locale === "zh" ? "僅告警、持續監控" : "Alert-only with monitoring"}
            </div>
          </div>
          <div className="bg-paper p-5">
            <div className="font-data text-xs text-stone tracking-wider uppercase mb-1">
              &lt;40 · Draft
            </div>
            <div className="text-sm text-ink font-semibold">
              {locale === "zh" ? "不得部署" : "Do not deploy"}
            </div>
          </div>
        </div>
      </Reveal>

      {/* ── TWO-DIMENSIONAL COMPLIANCE ─────────────────────── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {locale === "zh" ? "核心差異" : "The Differentiator"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-medium tracking-[-1px] mb-2">
          {locale === "zh"
            ? "雙維度合規模型"
            : "Two-dimensional compliance model"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "將「規則有沒有必要 metadata」與「誰驗證的」分開處理。LLM 只在撰寫階段參與；偵測核心本身是 deterministic regex / AST 比對，執行時不呼叫 LLM。"
            : "Separating 'does the rule have the metadata' from 'who verified it'. The LLM participates only at authoring time; the detection core itself is deterministic regex / AST matching and calls no LLM at evaluation time."}
        </p>
      </Reveal>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog border border-fog mb-8">
        <Reveal>
          <div className="bg-paper p-5 md:p-6 h-full">
            <div className="font-data text-xs text-stone tracking-wider uppercase mb-3">
              {locale === "zh" ? "維度 1 · 技術合規" : "Dimension 1 · Technical compliance"}
            </div>
            <p className="text-sm text-ink mb-4 leading-relaxed">
              {locale === "zh"
                ? "規則有沒有必要的 metadata?偵測條件、test cases、OWASP + MITRE 對應、false positive 文件。機器可在毫秒內驗證。"
                : "Does the rule have the required metadata? Detection conditions, test cases, OWASP and MITRE references, false positive documentation. Machine-verifiable in under a millisecond."}
            </p>
            <code className="font-data text-xs text-stone">
              validateRuleMeetsStandard(rule)
            </code>
          </div>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="bg-paper p-5 md:p-6 h-full border-l border-critical/30">
            <div className="font-data text-xs text-critical tracking-wider uppercase mb-3">
              {locale === "zh" ? "維度 2 · 信任合規" : "Dimension 2 · Trust compliance"}
            </div>
            <p className="text-sm text-ink mb-4 leading-relaxed">
              {locale === "zh"
                ? "誰驗證了 metadata?human-reviewed、community-contributed、auto-generated 或 llm-generated。升級 stable 要求「已驗證來源」，不只是「有」。"
                : "Who verified the metadata? human-reviewed, community-contributed, auto-generated, or llm-generated. Stable promotion requires verified provenance — not just presence."}
            </p>
            <code className="font-data text-xs text-stone">
              {`metadata_provenance: { mitre_atlas: human-reviewed }`}
            </code>
          </div>
        </Reveal>
      </div>

      <Reveal>
        <div className="border-t border-ink pt-5 mb-16">
          <div className="font-data text-xs text-stone tracking-wider uppercase mb-3">
            {locale === "zh" ? "為什麼這件事重要" : "Why this matters"}
          </div>
          <p className="text-sm text-ink leading-relaxed mb-3">
            {locale === "zh"
              ? "傳統的規則標準（Sigma、YARA、OWASP CRS）把合規看成二選一：有 metadata 就過，沒有就不過。結果廠商為了過關而補填 metadata，並沒有真的審核。"
              : "Traditional rule standards (Sigma, YARA, OWASP CRS) treat compliance as binary — either the metadata is there or it is not. This creates a perverse incentive: vendors pad metadata to pass the check without doing the underlying review work."}
          </p>
          <p className="text-sm text-stone leading-relaxed">
            {locale === "zh"
              ? "ATR 將這兩個維度分開。自動生成的對應可以通過 experimental gate 以便快速迭代。升級到 stable — 企業在生產環境會封鎖的層級，要求人工 review。"
              : "ATR separates the two dimensions. Auto-generated mappings can pass the experimental gate for fast iteration. Stable promotion — the level enterprises block in production — requires human review. Fast iteration and honest trust, at the same time."}
          </p>
        </div>
      </Reveal>

      {/* ── MATURITY LADDER ────────────────────────────────── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {locale === "zh" ? "成熟度階梯" : "The Ladder"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-medium tracking-[-1px] mb-2">
          {locale === "zh"
            ? "每條規則都要靠證據往上爬一階"
            : "Every rule climbs by evidence, not by age"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "draft → experimental → test → stable → deprecated。每一階的晉升條件都明確，由機器檢查。規則靠累積的證據往上走，放得再久也不會自己升級。品質退化時，系統會開 PR 把規則降級，由人審查後合併。"
            : "draft → experimental → test → stable → deprecated. Each gate is explicit and mechanical — a rule moves up on the evidence it has accumulated, never on how long it has sat in the repository. When quality regresses, a pull request demotes the rule, and a person reviews it before it merges."}
        </p>
      </Reveal>

      <div className="grid grid-cols-1 gap-px bg-fog border border-fog mb-6">
        {MATURITY_LEVELS.map((m) => (
          <Reveal key={m.label}>
            <div className="bg-paper p-5 md:p-6">
              <div className="flex flex-col md:flex-row md:gap-8 md:items-start">
                <div className="md:w-32 flex-shrink-0 mb-3 md:mb-0">
                  <span className="font-data text-xs text-ink bg-fog/60 px-3 py-1  tracking-wide uppercase font-semibold">
                    {m.label}
                  </span>
                </div>
                <div className="flex-1 grid md:grid-cols-2 gap-5">
                  <div>
                    <div className="font-data text-xs text-stone tracking-wider uppercase mb-2">
                      {locale === "zh" ? "晉升門檻" : "Promotion gate"}
                    </div>
                    <p className="text-sm text-ink leading-relaxed">{locale === "zh" ? m.gateZh : m.gate}</p>
                  </div>
                  <div>
                    <div className="font-data text-xs text-stone tracking-wider uppercase mb-2">
                      {locale === "zh" ? "部署建議" : "Deployment guidance"}
                    </div>
                    <p className="text-sm text-ink leading-relaxed">{locale === "zh" ? m.deployZh : m.deploy}</p>
                  </div>
                </div>
              </div>
            </div>
          </Reveal>
        ))}
      </div>

      <Reveal>
        <div className="bg-paper border border-critical/30 p-5 md:p-6 mb-8">
          <div className="font-data text-xs text-critical tracking-wider uppercase mb-2">
            {locale === "zh" ? "降級" : "Demotion"}
          </div>
          <p className="text-sm text-ink leading-relaxed">
            {locale === "zh"
              ? "每週把每條 stable 規則對目前整份良性語料重跑一次。只要命中任何一筆良性樣本，就自動開 PR 把它從 stable 降到 test，退出封鎖車道，但仍在 alert 和 hunt 車道告警。這個 PR 跟其他規則改動一樣，要過 CI、由人審查後才合併。良性語料會收進確認過的誤報回報，所以會一直變大。"
              : "Every week each stable rule is re-run against the whole current benign corpus. A rule that matches any benign sample is demoted from stable to test in an automatically opened pull request: it leaves the blocking lane but keeps alerting in the alert and hunt lanes. That pull request goes through CI and human review like any other rule change. The benign corpus grows as confirmed false-positive reports are added to it."}
          </p>
        </div>
      </Reveal>

      {/* ── DETECTION LANES ───────────────────────────────────
          v3.5.0: the maturity ladder above drives three lanes. This is
          where the quality model becomes an operational, honest tradeoff —
          FP reported lane by lane, never as one flattering figure. */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {locale === "zh" ? "偵測車道" : "Detection lanes"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-medium tracking-[-1px] mb-2">
          {locale === "zh"
            ? "成熟度決定一條規則被允許做什麼"
            : "Maturity decides what a rule is allowed to do"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "階梯不只是標籤，它決定了三條偵測車道。每條車道都是一個取捨：放行哪些成熟度，能容忍多少誤報。誤報率原本逐車道公開，現在的數字已經撤回，等重新量測。"
            : "The ladder is not just a label — it drives three detection lanes. Each lane is an explicit tradeoff between which maturities it admits and how much false positive it tolerates. Each lane publishes its own false-positive rate — and those figures are currently withdrawn, pending re-measurement."}
        </p>
      </Reveal>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog border border-fog mb-6">
        <Reveal>
          <div className="bg-paper p-5 md:p-6 h-full">
            <div className="font-data text-xs text-blue tracking-wider uppercase mb-2">
              {locale === "zh" ? "enforce 車道" : "enforce lane"}
            </div>
            <div className="font-display text-3xl font-medium text-ink mb-1">
              {locale === "zh" ? "最窄" : "Narrowest"}
            </div>
            <div className="font-data text-xs text-stone mb-3">
              {locale === "zh" ? "僅 stable + confirm · 誤報率待重測" : "stable + confirm only · FP rate pending re-measurement"}
            </div>
            <p className="text-sm text-stone leading-relaxed">
              {locale === "zh"
                ? "只放行最成熟、經人工確認的規則。要換到精確度，就得犧牲召回率。這是刻意的取捨，擺在明處，讓要在生產環境封鎖的人自己選。這條車道原先公布的誤報率已經撤回：量測用的良性語料後來被發現混入真實的越獄樣本，重測完成前不引用任何數字。"
                : "Admits only the most mature, human-confirmed rules. The precision is bought by giving up recall — a deliberate tradeoff, stated openly, for anyone who blocks in production. The false-positive rate previously published for this lane is withdrawn: the benign corpus it was measured on was found to contain real jailbreak samples, so no figure is quoted until the re-measurement lands."}
            </p>
          </div>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="bg-paper p-5 md:p-6 h-full">
            <div className="font-data text-xs text-critical tracking-wider uppercase mb-2">
              {locale === "zh" ? "alert 車道" : "alert lane"}
            </div>
            <div className="font-display text-3xl font-medium text-ink mb-1">
              {locale === "zh" ? "告警" : "Alert"}
            </div>
            <div className="font-data text-xs text-stone mb-3">
              {locale === "zh" ? "stable + test · 不封鎖" : "stable + test · no blocking"}
            </div>
            <p className="text-sm text-stone leading-relaxed">
              {locale === "zh"
                ? "納入晉升候選的 test 規則，只告警、不封鎖。在誤報傷不到使用者的前提下，擴大被看見的攻擊面。"
                : "Adds promotion-candidate test rules, surfacing more of the attack surface — but only as alerts, where a false positive costs a notification, not a blocked user."}
            </p>
          </div>
        </Reveal>
        <Reveal delay={0.2}>
          <div className="bg-paper p-5 md:p-6 h-full">
            <div className="font-data text-xs text-stone tracking-wider uppercase mb-2">
              {locale === "zh" ? "hunt 車道（預設）" : "hunt lane (default)"}
            </div>
            <div className="font-display text-3xl font-medium text-ink mb-1">
              {locale === "zh" ? "最寬" : "Widest"}
            </div>
            <div className="font-data text-xs text-stone mb-3">
              {locale === "zh" ? "全部規則，純建議性 · 誤報率待重測" : "everything, advisory only · FP rate pending re-measurement"}
            </div>
            <p className="text-sm text-stone leading-relaxed">
              {locale === "zh"
                ? "把所有規則都當成建議性訊號打開，讓做威脅獵捕的人看得最多。這條車道的誤報率明顯比 enforce 車道高，這是設計如此，因為它從不自動封鎖任何東西。原先公布的百分比同樣已撤回，等重新量測。"
                : "Runs every rule as an advisory signal, giving threat hunters maximum visibility. Its false-positive rate is materially higher than the enforce lane's — that is the design, not a flaw, because this lane never blocks anything on its own. The percentage previously published here is likewise withdrawn, pending re-measurement."}
            </p>
          </div>
        </Reveal>
      </div>

      <Reveal>
        <div className="border-t border-ink pt-5 mb-16">
          <div className="font-data text-xs text-stone tracking-wider uppercase mb-3">
            {locale === "zh" ? "品質即誠實" : "Quality is honesty"}
          </div>
          <p className="text-sm text-ink leading-relaxed">
            {locale === "zh"
              ? "這個標準對品質的要求有兩條：公開最差的數字，數字站不住時就撤掉。兩條車道的誤報率原本並排印在這裡，後來發現量測用的良性語料混入了真實的越獄樣本，就把數字撤了，等重新量測。採用者拿到的是一張可以自己驗證的取捨表，其中有一格現在是空的。"
              : "This standard defines quality in two halves: publish your worst figure, and withdraw any figure you can no longer stand behind. Both lanes' false-positive rates used to be printed side by side here. The benign corpus they were measured on was then found to contain real jailbreak samples, so the numbers were withdrawn pending re-measurement rather than left standing because they looked good. Adopters get a tradeoff table they can verify themselves — including which cell is currently empty."}
          </p>
        </div>
      </Reveal>

      {/* ── THE GAUNTLET ───────────────────────────────────── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {locale === "zh" ? "六道關卡" : "The Gauntlet"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-medium tracking-[-1px] mb-2">
          {locale === "zh"
            ? "一條規則從 PR 到 npm 要過六關"
            : "Six steps between a pull request and npm"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "每條規則都走同一條路，不管是誰起草的。第 2 到第 4 關是 CI 自動檢查，條件都寫在公開的 workflow 裡。"
            : "Every rule takes the same path, whoever drafted it. Steps 2 to 4 run in CI, and their criteria are in the public workflows."}
        </p>
      </Reveal>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-fog border border-fog mb-16">
        {GAUNTLET_STAGES.map((s) => (
          <Reveal key={s.stage}>
            <div className="bg-paper p-5 md:p-6 h-full">
              <div className="flex items-baseline gap-3 mb-2">
                <span className="font-data text-xs text-stone tracking-wider uppercase">
                  {locale === "zh" ? `階段 ${s.stage}` : `Stage ${s.stage}`}
                </span>
                <h3 className="font-display font-bold text-ink">{locale === "zh" ? s.titleZh : s.title}</h3>
              </div>
              <p className="text-sm text-stone leading-relaxed">{locale === "zh" ? s.detailZh : s.detail}</p>
            </div>
          </Reveal>
        ))}
      </div>

      {/* ── COMPARISON ─────────────────────────────────────── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {locale === "zh" ? "同業比較" : "The Landscape"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-medium tracking-[-1px] mb-2">
          {locale === "zh"
            ? "ATR 與既有規則標準的比較"
            : "How ATR compares to existing rule standards"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "Sigma、YARA、OWASP CRS、Suricata 分別為惡意軟體、SIEM、WAF、IDS 做過規則品質這件事。AI agent 還沒有同類的標準。"
            : "Sigma, YARA, OWASP CRS, and Suricata solved this for malware, SIEM, WAF, and IDS. AI agents do not have an equivalent standard yet."}
        </p>
      </Reveal>

      <Reveal>
        <div className="border border-fog bg-paper overflow-x-auto mb-4">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-fog bg-fog/30">
                <th className="text-left font-data text-xs text-stone uppercase tracking-wider py-3 px-4">
                  {locale === "zh" ? "功能" : "Feature"}
                </th>
                <th className="text-center font-data text-xs text-blue uppercase tracking-wider py-3 px-3">
                  ATR
                </th>
                <th className="text-center font-data text-xs text-stone uppercase tracking-wider py-3 px-3">
                  Sigma
                </th>
                <th className="text-center font-data text-xs text-stone uppercase tracking-wider py-3 px-3">
                  YARA
                </th>
                <th className="text-center font-data text-xs text-stone uppercase tracking-wider py-3 px-3">
                  OWASP CRS
                </th>
                <th className="text-center font-data text-xs text-stone uppercase tracking-wider py-3 px-3">
                  Suricata
                </th>
              </tr>
            </thead>
            <tbody>
              {COMPARISON.map((row, i) => (
                <tr
                  key={row.feature}
                  className={i < COMPARISON.length - 1 ? "border-b border-fog" : ""}
                >
                  <td className="py-3 px-4 text-ink">{locale === "zh" ? row.featureZh : row.feature}</td>
                  <td className="py-3 px-3 text-center text-lg">
                    <Cell v={row.atr} />
                  </td>
                  <td className="py-3 px-3 text-center text-lg">
                    <Cell v={row.sigma} />
                  </td>
                  <td className="py-3 px-3 text-center text-lg">
                    <Cell v={row.yara} />
                  </td>
                  <td className="py-3 px-3 text-center text-lg">
                    <Cell v={row.owasp} />
                  </td>
                  <td className="py-3 px-3 text-center text-lg">
                    <Cell v={row.suricata} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="text-xs text-mist italic mb-16">
          {locale === "zh"
            ? "標成「部分」的三項，是 RFC-001 寫了要求、規則還沒全部做到的地方。2026-10-15 的稽核記錄 103 條 stable 規則都還缺野外證據（data/enforce-lane-evidence-baseline.json），CI 用棘輪擋住缺口擴大；降級要開 PR 由人審，不是自動執行。"
            : "The three marked partial are what RFC-001 requires but the rules do not yet all meet. The 2026-10-15 audit records all 103 stable rules as still lacking wild evidence (data/enforce-lane-evidence-baseline.json), and CI holds the gap from growing; demotion goes through a pull request a person reviews, not an automatic step."}
        </p>
      </Reveal>

      {/* ── VERIFY IT YOURSELF ─────────────────────────────── */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {locale === "zh" ? "自己驗證" : "Verify It Yourself"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-medium tracking-[-1px] mb-2">
          {locale === "zh"
            ? "不用信任誰，自己跑驗證器"
            : "Run the validator yourself"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "每個函式都是純函式，開源，有文件。你可以在一分鐘內為自己的規則（或 ATR 的規則）算出分數。"
            : "Every function is pure, open-source, and documented. Score your own rules — or ours — in under a minute."}
        </p>
      </Reveal>

      <Reveal>
        <div className="bg-paper border border-fog mb-8">
          <div className="border-b border-fog bg-fog/30 px-5 py-3">
            <span className="font-data text-xs text-stone tracking-wider uppercase">
              {locale === "zh" ? "安裝" : "Install"}
            </span>
          </div>
          <pre className="font-data text-xs md:text-sm text-ink p-5 overflow-x-auto">
            {`npm install ${installSpec}`}
          </pre>
        </div>
      </Reveal>

      <Reveal>
        <div className="bg-paper border border-fog mb-16">
          <div className="border-b border-fog bg-fog/30 px-5 py-3">
            <span className="font-data text-xs text-stone tracking-wider uppercase">
              {locale === "zh" ? "為任何規則計算分數" : "Score any rule"}
            </span>
          </div>
          <pre className="font-data text-xs md:text-sm text-ink p-5 overflow-x-auto leading-relaxed">
{`import {
  parseATRRule,
  computeConfidence,
  validateRuleMeetsStandard,
} from 'agent-threat-rules/quality';

const rule = parseATRRule(yamlContent);
const score = computeConfidence(rule);
const gate = validateRuleMeetsStandard(rule, 'stable');

console.log('Confidence:', score.total);    // 0-100
console.log('Passes stable:', gate.passed);
console.log('Issues:', gate.issues);`}
          </pre>
        </div>
      </Reveal>

      {/* ── CTA ─────────────────────────────────────────────── */}
      <Reveal>
        <div className="border-t border-fog pt-10 text-center">
          <h2 className="font-display text-2xl md:text-3xl font-medium tracking-[-1px] mb-3">
            {locale === "zh" ? "公式公開，撤回的數字也公開。" : "The formula is public, and so are the figures we withdrew."}
          </h2>
          <p className="text-sm text-stone mb-6 max-w-xl mx-auto">
            {locale === "zh"
              ? "公式和計分函式庫都公開。各車道的誤報率之前發布過，後來發現量測方法有問題，已經撤回，重新量測後會再公開。任何掃描器都能用同一個函式庫、同樣的維度替規則計分，自己驗證結果。"
              : "The formula and the scoring library are public. Per-lane false-positive rates were published, then withdrawn when the way they were measured turned out to be flawed; they will be published again once re-measured. Any scanner can score rules on the same axes with the same library and check the result itself."}
          </p>
          <div className="flex flex-wrap items-center justify-center gap-4">
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/proposals/001-atr-quality-standard-rfc.md"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[15px] text-ink underline underline-offset-[6px] decoration-ink/30 hover:decoration-ink"
            >
              {locale === "zh" ? "閱讀 RFC" : "Read the RFC"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
            </a>
            <a
              href={`/${locale}/rules`}
              className="font-data text-xs text-stone hover:text-ink transition-colors border border-fog px-4 py-2.5 "
            >
              {locale === "zh" ? "瀏覽規則" : "Browse rules"}
            </a>
          </div>
          <p className="text-xs text-stone mt-10 max-w-xl mx-auto">
            {locale === "zh"
              ? "利益揭露：維護者創辦並控制 PANGUARD AI, INC.，這家公司販售以 ATR 為基礎的 agent 資安產品。"
              : "Interests: the maintainer founded and controls PANGUARD AI, INC., which sells AI agent security products built on ATR."}
          </p>
        </div>
      </Reveal>
    </div>
    </Phrased>
  );
}
