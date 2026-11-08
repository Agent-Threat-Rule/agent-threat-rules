import { Reveal } from "@/components/Reveal";
import { DocumentStatus } from "@/components/spec/DocumentStatus";
import { loadVersionLabels, npmInstallSpec } from "@/lib/versions";
import { locales, type Locale } from "@/lib/i18n";
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

const SCORE_BANDS = [
  { range: "90–100", band: "Very High", bandZh: "很高", use: "Safe to block in production", useZh: "可在生產環境封鎖" },
  { range: "60–79", band: "Medium", bandZh: "中", use: "Alert-only with monitoring", useZh: "僅告警、持續監控" },
  { range: "<40", band: "Draft", bandZh: "草稿", use: "Do not deploy", useZh: "不得部署" },
];

// Canonical maturity ladder = the rule `status` field progression:
// draft, experimental, test, stable, deprecated. Keep this aligned with
// the glossary `maturity` entry.
const MATURITY_LEVELS = [
  {
    label: "draft",
    gate: "Valid schema · ≥1 TP + 1 TN · no ReDoS",
    gateZh: "schema 合法 · 至少 1 個 TP 和 1 個 TN · 沒有 ReDoS",
    deploy: "Not deployed",
    deployZh: "不部署",
  },
  {
    label: "experimental",
    gate: "3+ TP + 3+ TN · CI pass · OWASP + MITRE mapping encouraged (not required) · evasion tests encouraged (not required)",
    gateZh: "3 個以上 TP 和 3 個以上 TN · 通過 CI · 建議（不強制）對應 OWASP 與 MITRE · 建議（不強制）附繞過測試",
    deploy: "Alert-only",
    deployZh: "只告警",
  },
  {
    label: "test",
    gate: "Canary observation passed · wild FP measured · no unresolved false-positive reports in the canary window",
    gateZh: "通過 canary 觀察期 · 已量測野外誤報 · 觀察期內沒有未解決的誤報回報",
    deploy: "Alert-only, promotion candidate",
    deployZh: "只告警，可列為升級候選",
  },
  {
    label: "stable",
    gate: "Wild-validated (1,000+ samples) · FP rate ≤ 0.5% · human-verified provenance · ≥3 evasion tests",
    gateZh: "通過野外驗證（1,000 筆以上樣本）· 誤報率 ≤ 0.5% · 來源經人工確認 · 至少 3 個繞過測試",
    deploy: "Block in production",
    deployZh: "可在正式環境封鎖",
  },
  {
    label: "deprecated",
    gate: "Superseded or demoted · retained for provenance · engines MUST NOT enable by default",
    gateZh: "已被取代或降級 · 為保留來源紀錄而留著 · 引擎預設 MUST NOT 啟用",
    deploy: "Off by default",
    deployZh: "預設關閉",
  },
];

const LANES = [
  {
    lane: "enforce",
    word: "Narrowest",
    wordZh: "最窄",
    admits: "stable + confirm only · FP rate pending re-measurement",
    admitsZh: "僅 stable + confirm · 誤報率待重測",
    detail:
      "Admits only the most mature, human-confirmed rules. The precision is bought by giving up recall — a deliberate tradeoff, stated openly, for anyone who blocks in production. The false-positive rate previously published for this lane is withdrawn: the benign corpus it was measured on was found to contain real jailbreak samples, so no figure is quoted until the re-measurement lands.",
    detailZh:
      "只放行最成熟、經人工確認的規則。要換到精確度，就得犧牲召回率。這是刻意的取捨，擺在明處，讓要在生產環境封鎖的人自己選。這條車道原先公布的誤報率已經撤回：量測用的良性語料後來被發現混入真實的越獄樣本，重測完成前不引用任何數字。",
  },
  {
    lane: "alert",
    word: "Alert",
    wordZh: "告警",
    admits: "stable + test · no blocking",
    admitsZh: "stable + test · 不封鎖",
    detail:
      "Adds promotion-candidate test rules, surfacing more of the attack surface — but only as alerts, where a false positive costs a notification, not a blocked user.",
    detailZh: "納入晉升候選的 test 規則，只告警、不封鎖。在誤報傷不到使用者的前提下，擴大被看見的攻擊面。",
  },
  {
    lane: "hunt",
    word: "Widest (default)",
    wordZh: "最寬（預設）",
    admits: "everything, advisory only · FP rate pending re-measurement",
    admitsZh: "全部規則，純建議性 · 誤報率待重測",
    detail:
      "Runs every rule as an advisory signal, giving threat hunters maximum visibility. Its false-positive rate is materially higher than the enforce lane's — that is the design, not a flaw, because this lane never blocks anything on its own. The percentage previously published here is likewise withdrawn, pending re-measurement.",
    detailZh:
      "把所有規則都當成建議性訊號打開，讓做威脅獵捕的人看得最多。這條車道的誤報率明顯比 enforce 車道高，這是設計如此，因為它從不自動封鎖任何東西。原先公布的百分比同樣已撤回，等重新量測。",
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

type Support = "yes" | "no" | "partial";

type ComparisonRow = {
  feature: string;
  featureZh: string;
  atr: Support;
  sigma: Support;
  yara: Support;
  owasp: Support;
  suricata: Support;
};

const STANDARDS: { key: keyof Omit<ComparisonRow, "feature" | "featureZh">; name: string }[] = [
  { key: "atr", name: "ATR" },
  { key: "sigma", name: "Sigma" },
  { key: "yara", name: "YARA" },
  { key: "owasp", name: "OWASP CRS" },
  { key: "suricata", name: "Suricata" },
];

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

const SUPPORT_WORD: Record<Support, { en: string; zh: string; tone: string }> = {
  yes: { en: "yes", zh: "有", tone: "text-ink" },
  partial: { en: "partial", zh: "部分", tone: "text-stone" },
  no: { en: "no", zh: "無", tone: "text-mist" },
};

function SupportWord({ v, zh }: { v: Support; zh: boolean }) {
  const w = SUPPORT_WORD[v];
  return <span className={w.tone}>{zh ? w.zh : w.en}</span>;
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

const RFC_URL =
  "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/proposals/001-atr-quality-standard-rfc.md";

/* Shared type scale for this page (inner page: 48px title, serif section
   titles, sans body in ink and graphite, mono only for figures and code). */
const KICKER = "text-[13px] text-stone mb-3";
const H2 = "text-[30px] md:text-[36px] leading-[1.2] tracking-[-0.01em] text-ink mb-4 max-w-[760px]";
const INTRO = "text-[16px] text-graphite leading-[1.75] max-w-[720px] mb-8";
const BODY = "text-[15px] text-graphite leading-[1.75]";
const SUBHEAD = "text-[13px] text-stone mb-2";
const LINK = "text-[15px] text-blue underline underline-offset-[5px] decoration-1 hover:text-blue-hover";
const SECTION = "mb-20 md:mb-24";
const isFigure = (s: string) => /\d/.test(s);
const nowrap = (text: string) => <span className="whitespace-nowrap">{text}</span>;

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
  const zh = locale === "zh";
  const installSpec = npmInstallSpec(await loadVersionLabels());
  const prov = provenanceBreakdown(loadAllRules());

  const provenanceRows = [
    {
      label: zh ? "有人工確認的對應" : "Human-checked mappings",
      share: shareOf(prov.human, prov.total),
      detail: zh
        ? `${prov.human} 條規則至少有一個欄位標記為 human-reviewed 或 human-authored。`
        : `${prov.human} rules mark at least one field human-reviewed or human-authored.`,
    },
    {
      label: zh ? "有來源紀錄，沒有人工標記" : "Recorded, not marked by a person",
      share: shareOf(prov.other, prov.total),
      detail: zh
        ? `${prov.other} 條規則有這個欄位，但只記了自動產生的對應、同步來源或 payload 語料，沒有欄位標記為人工確認。`
        : `${prov.other} rules have the field, but it records only auto-generated mappings, sync feeds or payload corpora; no field is marked as checked by a person.`,
    },
    {
      label: zh ? "沒有來源紀錄" : "No provenance recorded",
      share: shareOf(prov.none, prov.total),
      detail: zh
        ? `${prov.none} 條規則沒有 metadata_provenance 欄位，大多早於這個欄位出現。它們的對應無從判斷由誰設定。`
        : `${prov.none} rules have no metadata_provenance field, most of them older than the field. Who set their mappings is not recorded.`,
    },
  ];

  return (
    <Phrased>
    <div className="pt-20 pb-16 px-6 md:px-14">
      {/* ── HERO ───────────────────────────────────────────── */}
      <section className="mb-16 md:mb-20">
        <Reveal>
          <div className={KICKER}>{zh ? "RFC-001 · 品質標準" : "RFC-001 · Quality Standard"}</div>
        </Reveal>
        <Reveal delay={0.1}>
          <h1 className="text-[32px] md:text-[48px] leading-[1.15] tracking-[-0.01em] text-ink mb-6 max-w-[860px] text-wrap">
            {zh ? (
              <>
                具備來源追溯的 <span className="whitespace-nowrap">AI agent</span> 規則品質標準
              </>
            ) : (
              "An AI agent rule standard with provenance tracking"
            )}
          </h1>
        </Reveal>
        <Reveal delay={0.2}>
          <p className="text-[17px] text-graphite leading-[1.75] max-w-[720px] mb-8">
            {zh
              ? "一個偵測標準可不可信，要看它敢不敢公開自己最差的數字。每條規則都有可以自己算的信心分數，對應的來源記在規則裡可以查核，誤報率按偵測車道分開量測，不用單一個好看的數字帶過。之前公布的各車道誤報率已經撤回，重新量測後再公開。公式公開，程式碼開源。"
              : "A detection standard earns trust by publishing its worst figure. Every rule has a confidence score you can compute yourself, and mapping sources are recorded in the rule where you can audit them. False positives are measured per detection lane, not as one flattering number. The per-lane rates published earlier were withdrawn and will be published again once re-measured. The formula is public and the code is open source."}
          </p>
        </Reveal>
        {/* DocumentStatus banner — keeps this RFC-001 page aligned with /spec,
            /implementers, /conformance. SPEC.md's own header says "Draft". */}
        <Reveal delay={0.25}>
          <div className="mb-8">
            <DocumentStatus locale={locale} statusOverride={zh ? "草案" : "Draft"} />
          </div>
        </Reveal>
        <Reveal delay={0.3}>
          <div className="flex flex-wrap items-baseline gap-x-8 gap-y-3">
            <a href={RFC_URL} target="_blank" rel="noopener noreferrer" className={LINK}>
              {zh ? "閱讀 RFC-001" : "Read RFC-001"}
              <Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
            </a>
            <code className="font-data text-[13px] text-stone break-all">{`npm install ${installSpec}`}</code>
          </div>
        </Reveal>
      </section>

      {/* ── EVIDENCE ───────────────────────────────────────── */}
      <Reveal>
        <dl className={`border-t border-ink ${SECTION}`}>
          {EVIDENCE.map((e) => {
            const stat = zh ? e.statZh : e.stat;
            return (
              <div
                key={e.label}
                className="grid grid-cols-1 md:grid-cols-[200px_minmax(0,1fr)] gap-x-6 gap-y-1 py-4 border-b border-fog items-baseline"
              >
                <dt className={isFigure(stat) ? "font-data text-[15px] text-ink tabular-nums" : "text-[15px] text-ink"}>
                  {stat}
                </dt>
                <dd className={BODY}>{zh ? e.labelZh : e.label}</dd>
              </div>
            );
          })}
        </dl>
      </Reveal>

      {/* ── PROVENANCE RATIO ─────────────────────────────────
          Counted from rules/ at build time (lib/provenance.ts); no share on
          this page is typed by hand. */}
      <section className={SECTION}>
        <Reveal>
          <div className={KICKER}>{zh ? "規則來源組成" : "Rule provenance breakdown"}</div>
          <h2 className={H2}>
            {zh ? "哪些規則的對應經過人工確認。" : "Which rules have mappings a person checked."}
          </h2>
          <p className={INTRO}>
            {zh
              ? `規則的 metadata_provenance 欄位記錄每個對應（OWASP、MITRE、CWE 等）是誰或什麼設定的，有些規則也記下 payload 取自哪個語料。下面三個數字在建置時從 ${prov.total} 條生效規則算出。這個欄位描述的是對應，不是偵測邏輯由誰撰寫。`
              : `A rule's metadata_provenance field records who or what set each mapping (OWASP, MITRE, CWE and so on), and for some rules which corpus a payload came from. The three figures below are counted from the ${prov.total} effective rules at build time. The field describes the mappings, not who wrote the detection logic.`}
          </p>
        </Reveal>
        <Reveal delay={0.1}>
          <dl className="border-t border-ink mb-8">
            {provenanceRows.map((r) => (
              <div
                key={r.label}
                className="grid grid-cols-[minmax(0,1fr)_72px] md:grid-cols-[260px_96px_minmax(0,1fr)] gap-x-6 gap-y-1 py-4 border-b border-fog items-baseline"
              >
                <dt className="text-[15px] text-ink">{r.label}</dt>
                <dd className="font-data text-[15px] text-ink tabular-nums text-right md:text-left">{r.share}</dd>
                <dd className={`${BODY} col-span-2 md:col-span-1`}>{r.detail}</dd>
              </div>
            ))}
          </dl>
        </Reveal>
        <Reveal delay={0.2}>
          <div className="max-w-[720px] space-y-4">
            <p className="text-[15px] text-ink leading-[1.75]">
              {zh
                ? `這份標準要求升到 stable 的規則，來源要經過人工確認。目前 ${prov.stable} 條 stable 規則裡，只有 ${prov.stableHuman} 條有這份紀錄，多數 stable 規則早於這項檢查。採用者決定要封鎖哪些規則時，可以自己對照這個欄位。`
                : `The standard asks that a rule reaching stable has provenance a person checked. Today ${prov.stableHuman} of the ${prov.stable} stable rules carry that record; most stable rules predate the check. Adopters deciding which rules to block on can check the field themselves.`}
            </p>
            <p className={BODY}>
              {zh
                ? "規則集透過 CVE 與安全公告掃描、benchmark 漏報挖掘與貢獻者擴張，每一條都經由維護者合併的 pull request 進入 main。"
                : "The ruleset grows through CVE and advisory sweeps, benchmark-miss mining and contributors, and each rule reaches main through a pull request a maintainer merges."}
            </p>
          </div>
        </Reveal>
      </section>

      {/* ── THE FORMULA ────────────────────────────────────── */}
      <section className={SECTION}>
        <Reveal>
          <div className={KICKER}>{zh ? "公式" : "The formula"}</div>
          <h2 className={H2}>
            {zh ? "信心分數是數字，不是意見" : "Confidence is a number, not an opinion"}
          </h2>
          <p className={INTRO}>
            {zh
              ? "每個組成都由可測量的事實計算而來。公式是公開的，你可以自己跑。"
              : "Every component is computed from measurable facts. Run it yourself — the formula is public."}
          </p>
        </Reveal>

        <Reveal delay={0.1}>
          <div className="border-t border-ink py-4 overflow-x-auto">
            <code className="font-data text-[14px] text-ink whitespace-nowrap">
              confidence = 0.4 × precision + 0.3 × wild + 0.2 × coverage + 0.1 × evasion
            </code>
          </div>
        </Reveal>

        <Reveal delay={0.15}>
          <div className="border-t border-fog mb-10">
            <div className="hidden md:grid md:grid-cols-[200px_72px_320px_minmax(0,1fr)] gap-x-6 py-2 border-b border-fog text-[13px] text-stone">
              <span>{zh ? "組成" : "Component"}</span>
              <span>{zh ? "權重" : "Weight"}</span>
              <span>{zh ? "計算" : "Computed as"}</span>
              <span>{zh ? "量的是什麼" : "What it measures"}</span>
            </div>
            {FORMULA_COMPONENTS.map((c) => (
              <div
                key={c.name}
                className="grid grid-cols-[minmax(0,1fr)_56px] md:grid-cols-[200px_72px_320px_minmax(0,1fr)] gap-x-6 gap-y-1 py-4 border-b border-fog items-baseline"
              >
                <div className="text-[15px] text-ink">{zh ? c.nameZh : c.name}</div>
                <div className="font-data text-[14px] text-ink tabular-nums text-right md:text-left">{c.weight}</div>
                <code className="font-data text-[13px] text-graphite col-span-2 md:col-span-1 break-words">{c.formula}</code>
                <p className={`${BODY} col-span-2 md:col-span-1`}>{zh ? c.meaningZh : c.meaning}</p>
              </div>
            ))}
          </div>
        </Reveal>

        <Reveal>
          <div className={SUBHEAD}>{zh ? "分數怎麼用" : "What a score allows"}</div>
          <dl className="border-t border-fog">
            {SCORE_BANDS.map((b) => (
              <div
                key={b.range}
                className="grid grid-cols-[96px_minmax(0,1fr)] md:grid-cols-[200px_160px_minmax(0,1fr)] gap-x-6 gap-y-1 py-3 border-b border-fog items-baseline"
              >
                <dt className="font-data text-[14px] text-ink tabular-nums">{b.range}</dt>
                <dd className="text-[15px] text-stone">{zh ? b.bandZh : b.band}</dd>
                <dd className="text-[15px] text-ink col-start-2 md:col-start-auto">{zh ? b.useZh : b.use}</dd>
              </div>
            ))}
          </dl>
        </Reveal>
      </section>

      {/* ── TWO-DIMENSIONAL COMPLIANCE ─────────────────────── */}
      <section className={SECTION}>
        <Reveal>
          <div className={KICKER}>{zh ? "核心差異" : "The differentiator"}</div>
          <h2 className={H2}>{zh ? "雙維度合規模型" : "Two-dimensional compliance model"}</h2>
          <p className={INTRO}>
            {zh
              ? "將「規則有沒有必要 metadata」與「誰驗證的」分開處理。LLM 只在撰寫階段參與；偵測核心本身是 deterministic regex / AST 比對，執行時不呼叫 LLM。"
              : "Separating 'does the rule have the metadata' from 'who verified it'. The LLM participates only at authoring time; the detection core itself is deterministic regex / AST matching and calls no LLM at evaluation time."}
          </p>
        </Reveal>

        <Reveal delay={0.1}>
          <dl className="border-t border-ink mb-10">
            {[
              {
                title: zh ? "維度 1：技術合規" : "Dimension 1: technical compliance",
                body: zh
                  ? "規則有沒有必要的 metadata？偵測條件、test cases、OWASP + MITRE 對應、false positive 文件。機器可在毫秒內驗證。"
                  : "Does the rule have the required metadata? Detection conditions, test cases, OWASP and MITRE references, false positive documentation. Machine-verifiable in under a millisecond.",
                code: "validateRuleMeetsStandard(rule)",
              },
              {
                title: zh ? "維度 2：信任合規" : "Dimension 2: trust compliance",
                body: zh
                  ? <>誰驗證了 metadata？{nowrap("human-reviewed")}、{nowrap("community-contributed")}、{nowrap("auto-generated")} 或 {nowrap("llm-generated")}。升級 stable 要求「已驗證來源」，不只是「有」。</>
                  : <>Who verified the metadata? {nowrap("human-reviewed")}, {nowrap("community-contributed")}, {nowrap("auto-generated")}, or {nowrap("llm-generated")}. Stable promotion requires verified provenance — not just presence.</>,
                code: "metadata_provenance: { mitre_atlas: human-reviewed }",
              },
            ].map((d) => (
              <div
                key={d.code}
                className="grid grid-cols-1 md:grid-cols-[260px_minmax(0,1fr)] gap-x-6 gap-y-2 py-5 border-b border-fog"
              >
                <dt className="text-[15px] text-ink">{d.title}</dt>
                <dd>
                  <p className={`${BODY} mb-2`}>{d.body}</p>
                  <code className="font-data text-[13px] text-stone break-words">{d.code}</code>
                </dd>
              </div>
            ))}
          </dl>
        </Reveal>

        <Reveal>
          <div className="max-w-[720px]">
            <h3 className="font-title text-[22px] text-ink mb-3">{zh ? "為什麼這件事重要" : "Why this matters"}</h3>
            <p className="text-[15px] text-ink leading-[1.75] mb-3">
              {zh
                ? "傳統的規則標準（Sigma、YARA、OWASP CRS）把合規看成二選一：有 metadata 就過，沒有就不過。結果廠商為了過關而補填 metadata，並沒有真的審核。"
                : "Traditional rule standards (Sigma, YARA, OWASP CRS) treat compliance as binary — either the metadata is there or it is not. This creates a perverse incentive: vendors pad metadata to pass the check without doing the underlying review work."}
            </p>
            <p className={BODY}>
              {zh
                ? "ATR 將這兩個維度分開。自動生成的對應可以通過 experimental 的門檻，方便快速迭代；升到 stable，也就是企業在生產環境會拿來封鎖的層級，則要求人工審查。"
                : "ATR separates the two dimensions. Auto-generated mappings can pass the experimental gate for fast iteration. Stable promotion — the level enterprises block in production — requires human review. Fast iteration and honest trust, at the same time."}
            </p>
          </div>
        </Reveal>
      </section>

      {/* ── MATURITY LADDER ────────────────────────────────── */}
      <section className={SECTION}>
        <Reveal>
          <div className={KICKER}>{zh ? "成熟度階梯" : "The ladder"}</div>
          <h2 className={H2}>
            {zh ? "每條規則都要靠證據往上爬一階" : "Every rule climbs by evidence, not by age"}
          </h2>
          <p className={INTRO}>
            {zh
              ? "階梯共五階：draft、experimental、test、stable、deprecated。每一階的晉升條件都明確，由機器檢查。規則靠累積的證據往上走，放得再久也不會自己升級。品質退化時，系統會開 PR 把規則降級，由人審查後合併。"
              : "Five rungs: draft, experimental, test, stable, deprecated. Each gate is explicit and mechanical — a rule moves up on the evidence it has accumulated, never on how long it has sat in the repository. When quality regresses, a pull request demotes the rule, and a person reviews it before it merges."}
          </p>
        </Reveal>

        <Reveal delay={0.1}>
          <div className="border-t border-ink mb-10">
            <div className="hidden md:grid md:grid-cols-[160px_minmax(0,1fr)_240px] gap-x-6 py-2 border-b border-fog text-[13px] text-stone">
              <span>{zh ? "成熟度" : "Maturity"}</span>
              <span>{zh ? "晉升門檻" : "Promotion gate"}</span>
              <span>{zh ? "部署建議" : "Deployment guidance"}</span>
            </div>
            {MATURITY_LEVELS.map((m) => (
              <div
                key={m.label}
                className="grid grid-cols-1 md:grid-cols-[160px_minmax(0,1fr)_240px] gap-x-6 gap-y-1.5 py-4 border-b border-fog items-baseline"
              >
                <div className="font-data text-[14px] text-ink">{m.label}</div>
                <p className="text-[15px] text-ink leading-[1.7]">
                  <span className="md:hidden text-[13px] text-stone mr-2">{zh ? "晉升門檻" : "Gate"}</span>
                  {zh ? m.gateZh : m.gate}
                </p>
                <p className="text-[15px] text-graphite leading-[1.7]">
                  <span className="md:hidden text-[13px] text-stone mr-2">{zh ? "部署" : "Deploy"}</span>
                  {zh ? m.deployZh : m.deploy}
                </p>
              </div>
            ))}
          </div>
        </Reveal>

        <Reveal>
          <div className="max-w-[720px]">
            <h3 className="font-title text-[22px] text-ink mb-3">{zh ? "降級" : "Demotion"}</h3>
            <p className={BODY}>
              {zh
                ? "每週把每條 stable 規則對目前整份良性語料重跑一次。只要命中任何一筆良性樣本，就自動開 PR 把它從 stable 降到 test，退出封鎖車道，但仍在 alert 和 hunt 車道告警。這個 PR 跟其他規則改動一樣，要過 CI、由人審查後才合併。良性語料會收進確認過的誤報回報，所以會一直變大。"
                : "Every week each stable rule is re-run against the whole current benign corpus. A rule that matches any benign sample is demoted from stable to test in an automatically opened pull request: it leaves the blocking lane but keeps alerting in the alert and hunt lanes. That pull request goes through CI and human review like any other rule change. The benign corpus grows as confirmed false-positive reports are added to it."}
            </p>
          </div>
        </Reveal>
      </section>

      {/* ── DETECTION LANES ───────────────────────────────────
          v3.5.0: the maturity ladder above drives three lanes. FP is
          reported lane by lane, never as one flattering figure. */}
      <section className={SECTION}>
        <Reveal>
          <div className={KICKER}>{zh ? "偵測車道" : "Detection lanes"}</div>
          <h2 className={H2}>
            {zh ? "成熟度決定一條規則被允許做什麼" : "Maturity decides what a rule is allowed to do"}
          </h2>
          <p className={INTRO}>
            {zh
              ? "階梯不只是標籤，它決定了三條偵測車道。每條車道都是一個取捨：放行哪些成熟度，能容忍多少誤報。誤報率原本逐車道公開，現在的數字已經撤回，等重新量測。"
              : "The ladder is not just a label — it drives three detection lanes. Each lane is an explicit tradeoff between which maturities it admits and how much false positive it tolerates. Each lane publishes its own false-positive rate — and those figures are currently withdrawn, pending re-measurement."}
          </p>
        </Reveal>

        <Reveal delay={0.1}>
          <dl className="border-t border-ink mb-10">
            {LANES.map((l) => (
              <div
                key={l.lane}
                className="grid grid-cols-1 md:grid-cols-[260px_minmax(0,1fr)] gap-x-6 gap-y-2 py-5 border-b border-fog"
              >
                <dt>
                  <div className="text-[15px] text-ink">
                    <span className="font-data">{l.lane}</span>
                    {zh ? " 車道" : " lane"}
                    <span className="text-stone">{" · "}{zh ? l.wordZh : l.word}</span>
                  </div>
                  <div className="text-[13px] text-stone mt-1">{zh ? l.admitsZh : l.admits}</div>
                </dt>
                <dd className={BODY}>{zh ? l.detailZh : l.detail}</dd>
              </div>
            ))}
          </dl>
        </Reveal>

        <Reveal>
          <div className="max-w-[720px]">
            <h3 className="font-title text-[22px] text-ink mb-3">{zh ? "品質即誠實" : "Quality is honesty"}</h3>
            <p className={BODY}>
              {zh
                ? "這個標準對品質的要求有兩條：公開最差的數字，數字站不住時就撤掉。兩條車道的誤報率原本並排印在這裡，後來發現量測用的良性語料混入了真實的越獄樣本，就把數字撤了，等重新量測。採用者拿到的是一張可以自己驗證的取捨表，其中有一格現在是空的。"
                : "This standard defines quality in two halves: publish your worst figure, and withdraw any figure you can no longer stand behind. Both lanes' false-positive rates used to be printed side by side here. The benign corpus they were measured on was then found to contain real jailbreak samples, so the numbers were withdrawn pending re-measurement rather than left standing because they looked good. Adopters get a tradeoff table they can verify themselves — including which cell is currently empty."}
            </p>
          </div>
        </Reveal>
      </section>

      {/* ── THE GAUNTLET ───────────────────────────────────── */}
      <section className={SECTION}>
        <Reveal>
          <div className={KICKER}>{zh ? "六道關卡" : "The gauntlet"}</div>
          <h2 className={H2}>
            {zh ? "一條規則從 PR 到 npm 要過六關" : "Six steps between a pull request and npm"}
          </h2>
          <p className={INTRO}>
            {zh
              ? "每條規則都走同一條路，不管是誰起草的。第 2 到第 4 關是 CI 自動檢查，條件都寫在公開的 workflow 裡。"
              : "Every rule takes the same path, whoever drafted it. Steps 2 to 4 run in CI, and their criteria are in the public workflows."}
          </p>
        </Reveal>

        <Reveal delay={0.1}>
          <ol className="border-t border-ink">
            {GAUNTLET_STAGES.map((s) => (
              <li
                key={s.stage}
                className="grid grid-cols-[40px_minmax(0,1fr)] md:grid-cols-[48px_212px_minmax(0,1fr)] gap-x-6 gap-y-1 py-4 border-b border-fog items-baseline"
              >
                <span className="font-data text-[14px] text-stone tabular-nums">{s.stage}</span>
                <h3 className="text-[15px] text-ink font-normal">{zh ? s.titleZh : s.title}</h3>
                <p className={`${BODY} col-start-2 md:col-start-auto`}>{zh ? s.detailZh : s.detail}</p>
              </li>
            ))}
          </ol>
        </Reveal>
      </section>

      {/* ── COMPARISON ─────────────────────────────────────── */}
      <section className={SECTION}>
        <Reveal>
          <div className={KICKER}>{zh ? "同業比較" : "The landscape"}</div>
          <h2 className={H2}>
            {zh ? "ATR 與既有規則標準的比較" : "How ATR compares to existing rule standards"}
          </h2>
          <p className={INTRO}>
            {zh
              ? "Sigma、YARA、OWASP CRS、Suricata 分別為惡意軟體、SIEM、WAF、IDS 做過規則品質這件事。AI agent 還沒有同類的標準。"
              : "Sigma, YARA, OWASP CRS, and Suricata solved this for malware, SIEM, WAF, and IDS. AI agents do not have an equivalent standard yet."}
          </p>
        </Reveal>

        <Reveal>
          {/* Desktop: one table. Phone: one row per feature, one line per standard. */}
          <table className="hidden md:table w-full border-t border-ink mb-5">
            <thead>
              <tr className="border-b border-fog">
                <th className="text-left text-[13px] text-stone font-normal py-2 pr-6">{zh ? "功能" : "Feature"}</th>
                {STANDARDS.map((s) => (
                  <th key={s.key} className="text-left text-[13px] text-stone font-normal py-2 px-3 whitespace-nowrap">
                    {s.name}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {COMPARISON.map((row) => (
                <tr key={row.feature} className="border-b border-fog">
                  <td className="py-3 pr-6 text-[15px] text-ink">{zh ? row.featureZh : row.feature}</td>
                  {STANDARDS.map((s) => (
                    <td key={s.key} className="py-3 px-3 text-[15px]">
                      <SupportWord v={row[s.key]} zh={zh} />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
          <dl className="md:hidden border-t border-ink mb-5">
            {COMPARISON.map((row) => (
              <div key={row.feature} className="py-4 border-b border-fog">
                <dt className="text-[15px] text-ink mb-2">{zh ? row.featureZh : row.feature}</dt>
                <dd className="grid grid-cols-[112px_minmax(0,1fr)] gap-y-0.5 text-[14px]">
                  {STANDARDS.map((s) => (
                    <div key={s.key} className="contents">
                      <span className="text-stone">{s.name}</span>
                      <SupportWord v={row[s.key]} zh={zh} />
                    </div>
                  ))}
                </dd>
              </div>
            ))}
          </dl>
          <p className="text-[14px] text-stone leading-[1.7] max-w-[720px]">
            {zh
              ? "標成「部分」的三項，是 RFC-001 寫了要求、規則還沒全部做到的地方。2026-10-15 的稽核記錄 103 條 stable 規則都還缺野外證據（data/enforce-lane-evidence-baseline.json），CI 用棘輪擋住缺口擴大；降級要開 PR 由人審，不是自動執行。"
              : "The three marked partial are what RFC-001 requires but the rules do not yet all meet. The 2026-10-15 audit records all 103 stable rules as still lacking wild evidence (data/enforce-lane-evidence-baseline.json), and CI holds the gap from growing; demotion goes through a pull request a person reviews, not an automatic step."}
          </p>
        </Reveal>
      </section>

      {/* ── VERIFY IT YOURSELF ─────────────────────────────── */}
      <section className={SECTION}>
        <Reveal>
          <div className={KICKER}>{zh ? "自己驗證" : "Verify it yourself"}</div>
          <h2 className={H2}>{zh ? "不用信任誰，自己跑驗證器" : "Run the validator yourself"}</h2>
          <p className={INTRO}>
            {zh
              ? "每個函式都是純函式，開源，有文件。你可以在一分鐘內為自己的規則（或 ATR 的規則）算出分數。"
              : "Every function is pure, open-source, and documented. Score your own rules — or ours — in under a minute."}
          </p>
        </Reveal>

        <Reveal>
          <div className={SUBHEAD}>{zh ? "安裝" : "Install"}</div>
          <pre className="font-data text-[13px] md:text-[14px] text-ink border-t border-b border-fog py-4 mb-8 overflow-x-auto">
            {`npm install ${installSpec}`}
          </pre>
          <div className={SUBHEAD}>{zh ? "為任何規則計算分數" : "Score any rule"}</div>
          <pre className="font-data text-[13px] md:text-[14px] text-ink border-t border-b border-fog py-4 overflow-x-auto leading-relaxed">
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
        </Reveal>
      </section>

      {/* ── CLOSING ─────────────────────────────────────────── */}
      <Reveal>
        <section className="border-t border-ink pt-8 md:pt-10">
          <h2 className={H2}>
            {zh ? "公式公開，撤回的數字也公開。" : "The formula is public, and so are the figures we withdrew."}
          </h2>
          <p className="text-[16px] text-graphite leading-[1.75] max-w-[720px] mb-6">
            {zh
              ? "公式和計分函式庫都公開。各車道的誤報率之前發布過，後來發現量測方法有問題，已經撤回，重新量測後會再公開。任何掃描器都能用同一個函式庫、同樣的維度替規則計分，自己驗證結果。"
              : "The formula and the scoring library are public. Per-lane false-positive rates were published, then withdrawn when the way they were measured turned out to be flawed; they will be published again once re-measured. Any scanner can score rules on the same axes with the same library and check the result itself."}
          </p>
          <div className="flex flex-wrap items-baseline gap-x-8 gap-y-3">
            <a href={RFC_URL} target="_blank" rel="noopener noreferrer" className={LINK}>
              {zh ? "閱讀 RFC" : "Read the RFC"}
              <Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
            </a>
            <a href={`/${locale}/rules`} className={LINK}>
              {zh ? "瀏覽規則" : "Browse rules"}
              <Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
            </a>
          </div>
          <p className="text-[13px] text-stone leading-[1.7] mt-10 max-w-[720px]">
            {zh
              ? "利益揭露：維護者創辦並控制 PANGUARD AI, INC.，這家公司販售以 ATR 為基礎的 agent 資安產品。"
              : "Interests: the maintainer founded and controls PANGUARD AI, INC., which sells AI agent security products built on ATR."}
          </p>
        </section>
      </Reveal>
    </div>
    </Phrased>
  );
}
