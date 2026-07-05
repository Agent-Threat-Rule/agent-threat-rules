import { Reveal } from "@/components/Reveal";
import { DocumentStatus } from "@/components/spec/DocumentStatus";
import { getSpecMeta } from "@/lib/spec-meta";
import { locales, t, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Quality Standard (RFC-001 v1.1) - ATR",
  description:
    "An open detection-rule quality standard for the AI agent era. A maturity ladder with explicit gates, detection lanes that report false-positive rates per lane instead of a single figure, a vendor-neutral validator anyone can run, wild-validated on 96,096 real agents (as of 2026-04-14). MIT licensed. Effective 2026-04-14.",
};

/* =============================================================
   RFC-001 data — the formula, maturity ladder, gauntlet, evidence
   ============================================================= */

const FORMULA_COMPONENTS = [
  {
    name: "Precision",
    weight: "40%",
    formula: "(1 − wild_fp_rate) × 100",
    meaning: "Measured false-positive rate on real-world corpora.",
  },
  {
    name: "Wild validation",
    weight: "30%",
    formula: "min(wild_samples / 10,000, 1) × 100",
    meaning: "How much real data the rule has survived.",
  },
  {
    name: "Coverage",
    weight: "20%",
    formula: "min(conditions / 5, 1) × 100",
    meaning: "Detection depth — distinct attack layers covered.",
  },
  {
    name: "Evasion docs",
    weight: "10%",
    formula: "min(documented_evasions / 5, 1) × 100",
    meaning: "Honest acknowledgment of known bypass techniques.",
  },
];

// Canonical maturity ladder = the rule `status` field progression:
// draft → experimental → test → stable → deprecated. Keep this aligned with
// the glossary `maturity` entry.
const MATURITY_LEVELS = [
  {
    label: "Draft",
    gate: "Valid schema · ≥1 TP + 1 TN · no ReDoS",
    deploy: "Not deployed",
  },
  {
    label: "Experimental",
    gate: "3+ TP + 3+ TN · CI pass · OWASP + MITRE mapping encouraged (not required) · evasion tests encouraged (not required)",
    deploy: "Alert-only",
  },
  {
    label: "Test",
    gate: "Canary observation passed · wild FP measured · no unresolved false-positive reports in the canary window",
    deploy: "Alert-only, promotion candidate",
  },
  {
    label: "Stable",
    gate: "Wild-validated (1,000+ samples) · FP rate ≤ 0.5% · human-verified provenance · ≥3 evasion tests",
    deploy: "Block in production",
  },
  {
    label: "Deprecated",
    gate: "Superseded or demoted · retained for provenance · engines MUST NOT enable by default",
    deploy: "Off by default",
  },
];

const GAUNTLET_STAGES = [
  {
    stage: "1",
    title: "LLM Drafter",
    detail:
      "Claude Sonnet generates a YAML rule against a strict prompt requiring 3+ conditions, 5+ TP/TN, 3+ evasion tests, and OWASP + MITRE mapping.",
  },
  {
    stage: "2",
    title: "Syntax Gate",
    detail:
      "Regex extraction, invalid pattern rejection, PCRE-to-JS normalization. Broken rules are dropped with logged reasons.",
  },
  {
    stage: "3",
    title: "Quality Gate",
    detail:
      "The RFC-001 formula runs: detection depth, test coverage, reference mapping, documentation completeness. Below the bar — rejected.",
  },
  {
    stage: "4",
    title: "Canary Observation",
    detail:
      "Accepted rules enter a canary window. Independent confirmations and wild FP measurements gate further promotion.",
  },
  {
    stage: "5",
    title: "Human Review",
    detail:
      "Provenance starts as llm-generated. Human review upgrades to human-reviewed before the rule can reach stable.",
  },
  {
    stage: "6",
    title: "Upstream PR",
    detail:
      "Promoted rules open pull requests against the public ATR repository for open review and merge.",
  },
];

type ComparisonRow = {
  feature: string;
  atr: "yes" | "no" | "partial";
  sigma: "yes" | "no" | "partial";
  yara: "yes" | "no" | "partial";
  owasp: "yes" | "no" | "partial";
  suricata: "yes" | "no" | "partial";
};

const COMPARISON: ComparisonRow[] = [
  {
    feature: "Maturity ladder with explicit gates",
    atr: "yes",
    sigma: "yes",
    yara: "no",
    owasp: "yes",
    suricata: "yes",
  },
  {
    feature: "Formula-based confidence score (0–100)",
    atr: "yes",
    sigma: "no",
    yara: "no",
    owasp: "no",
    suricata: "partial",
  },
  {
    feature: "Wild validation required for production",
    atr: "yes",
    sigma: "no",
    yara: "no",
    owasp: "no",
    suricata: "no",
  },
  {
    feature: "Per-field provenance tracking",
    atr: "yes",
    sigma: "no",
    yara: "no",
    owasp: "no",
    suricata: "no",
  },
  {
    feature: "Automatic demotion on quality regression",
    atr: "yes",
    sigma: "no",
    yara: "no",
    owasp: "no",
    suricata: "no",
  },
  {
    feature: "Open-source reference implementation",
    atr: "yes",
    sigma: "yes",
    yara: "yes",
    owasp: "yes",
    suricata: "yes",
  },
];

function Cell({ v }: { v: "yes" | "no" | "partial" }) {
  if (v === "yes") return <span className="text-blue font-semibold">✓</span>;
  if (v === "partial") return <span className="text-critical">~</span>;
  return <span className="text-mist">—</span>;
}

// Static evidence literals. This page does not bind to lib/stats.ts, so each
// figure carries an explicit "as of" date. Re-verify against data/stats.json
// before citing externally — rule/scan counts move.
const EVIDENCE = [
  { stat: "Live", label: "Full ATR rule pack in Cisco AI Defense production" },
  { stat: "96,096", label: "Real agent skills scanned across 6 registries (as of 2026-04-14)" },
  { stat: "99.7%", label: "Precision on the PINT-format adversarial corpus" },
  { stat: "~0.24%", label: "False-positive rate on the enforce lane (mature rules only)" },
];

const EXAMPLE_RULE = {
  title: "Hidden Credential Exfiltration with Silent Execution Override",
  id: "ATR-2026-DRAFT-8f3c9a72",
  severity: "critical",
  layers: 5,
  tpTn: "5 + 5",
  evasions: 3,
  owasp: ["LLM01:2025 — Prompt Injection", "ASI01:2026 — Agent Behaviour Hijack"],
  mitre: "AML.T0051 — LLM Prompt Injection",
  provenance: "llm-generated",
};

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

  return (
    <div className="pt-20 pb-16 px-6 max-w-[1120px] mx-auto">
      {/* ── HERO ───────────────────────────────────────────── */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {locale === "zh" ? "RFC-001 · 品質標準" : "RFC-001 · Quality Standard"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="font-display text-[clamp(28px,4vw,44px)] font-extrabold tracking-[-2px] mb-3 leading-[1.05]">
          {locale === "zh" ? (
            <>
              具備
              <br />
              <span className="text-blue">來源追溯</span>的
              <br />
              AI Agent 規則品質標準
            </>
          ) : (
            <>
              An AI agent rule standard
              <br />
              with <span className="text-blue">provenance tracking</span>
            </>
          )}
        </h1>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-base text-stone font-light mb-8 max-w-2xl">
          {locale === "zh"
            ? "一個偵測標準的可信度,取決於它願不願意公開自己最差的數字。每條規則都有可自行計算的信心分數,每個對應都有可審計的來源,每條偵測車道的誤報率都逐車道揭露——不是用單一個好看的數字概括。沒有黑箱、沒有廠商鎖定:只有公開的公式、開源的程式碼、以及在真實世界存活過的資料。"
            : "A detection standard earns trust by publishing its worst figure, not hiding it. Every rule has a confidence score you can compute yourself, every mapping a provenance you can audit, and every detection lane reports its false-positive rate lane by lane — never as a single flattering number. No black boxes, no vendor lock-in: just a public formula, open-source code, and data that has survived the wild."}
        </p>
      </Reveal>
      {/* DocumentStatus banner — keeps this RFC-001 page visually aligned
          with /spec, /implementers, /conformance, etc. Section anchor lets
          readers know this document covers §RFC-001 of the spec family. */}
      <Reveal delay={0.25}>
        <div className="mb-6">
          <DocumentStatus locale={locale} sectionHref="/spec" />
        </div>
      </Reveal>
      <Reveal delay={0.3}>
        <div className="flex flex-wrap items-center gap-4 mb-16">
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/proposals/001-atr-quality-standard-rfc.md"
            target="_blank"
            rel="noopener noreferrer"
            className="bg-blue text-white px-5 py-2.5 rounded-sm text-sm font-semibold hover:bg-blue-hover transition-colors"
          >
            {locale === "zh" ? "閱讀 RFC-001" : "Read RFC-001"} →
          </a>
          <a
            href="https://www.npmjs.com/package/agent-threat-rules"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-stone hover:text-ink transition-colors border border-fog px-4 py-2.5 rounded-sm"
          >
            {`npm install agent-threat-rules@${getSpecMeta().version}`}
          </a>
        </div>
      </Reveal>

      {/* ── EVIDENCE STRIP ─────────────────────────────────── */}
      <Reveal>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-fog border border-fog mb-16">
          {EVIDENCE.map((e) => (
            <div key={e.label} className="bg-paper p-5 md:p-6">
              <div className="font-display text-2xl md:text-3xl font-extrabold text-ink mb-1">
                {e.stat}
              </div>
              <div className="text-xs text-stone leading-snug">{e.label}</div>
            </div>
          ))}
        </div>
      </Reveal>

      {/* ── PROVENANCE RATIO ───────────────────────────────── */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {locale === "zh" ? "規則來源組成" : "Rule provenance breakdown"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-extrabold tracking-[-1px] mb-2">
          {locale === "zh"
            ? "哪些規則是人工審核的，哪些是 LLM 生成的。"
            : "What fraction is human-reviewed vs. LLM-generated."}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "ATR 公開這個數字，因為任何下游採用者都應該在評估信任度時知道它。"
            : "ATR publishes this number because every downstream adopter should know it when evaluating trust."}
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog border border-fog mb-6">
          <div className="bg-paper p-5 md:p-6">
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">
              {locale === "zh" ? "人工審核" : "Human-reviewed"}
            </div>
            <div className="font-display text-3xl font-extrabold text-ink mb-1">~30%</div>
            <p className="text-sm text-stone leading-relaxed">
              {locale === "zh"
                ? "規則創始時由人工撰寫，或已通過人工 review 升級到 stable。這些規則的 metadata_provenance 標記為 human-reviewed。"
                : "Rules authored by humans at origin or promoted to stable via human review. These rules carry metadata_provenance: human-reviewed."}
            </p>
          </div>
          <div className="bg-paper p-5 md:p-6">
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">
              {locale === "zh" ? "LLM 生成 + 雙重閘門驗證" : "LLM-generated + 2-gate validated"}
            </div>
            <div className="font-display text-3xl font-extrabold text-ink mb-1">~65%</div>
            <p className="text-sm text-stone leading-relaxed">
              {locale === "zh"
                ? "由 LLM 草擬，通過語法關 + RFC-001 品質關 + 0 FP benign corpus 驗證。標記為 llm-generated，信心分數上限 70，直到人工 review。"
                : "Drafted by LLM, passed syntax gate and RFC-001 quality gate, validated against benign corpus with 0 FP. Tagged llm-generated; confidence capped at 70 until human review."}
            </p>
          </div>
          <div className="bg-paper p-5 md:p-6">
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">
              {locale === "zh" ? "語料庫指紋（保留為實驗性）" : "Corpus fingerprints (kept experimental)"}
            </div>
            <div className="font-display text-3xl font-extrabold text-ink mb-1">~5%</div>
            <p className="text-sm text-stone leading-relaxed">
              {locale === "zh"
                ? "非常字面的模式，從特定語料庫取出。泛化這些規則會帶來無法接受的 FP。保留為 experimental，不用於生產封鎖，明確標注。"
                : "Highly literal patterns extracted from specific corpora. Generalizing them would produce unacceptable FP. Kept as experimental, not used for production blocking, explicitly labeled."}
            </p>
          </div>
        </div>
      </Reveal>
      <Reveal delay={0.2}>
        <div className="bg-paper border border-fog p-5 md:p-6 mb-16">
          <p className="text-sm text-ink leading-relaxed mb-3">
            {locale === "zh"
              ? "LLM 生成的規則為什麼可以信任？因為雙重閘門設計讓來源和信任度是分開追蹤的。LLM 生成的規則可以通過 experimental gate 快速迭代；升級到 stable（企業在生產環境封鎖的層級）需要人工 review。採用者可以自己決定：只部署 human-reviewed 規則、只部署 stable、或者兩者都用。"
              : "Why trust LLM-generated rules? Because the two-dimensional compliance model tracks origin and trust separately. LLM-generated rules can pass the experimental gate for fast iteration; stable promotion requires human review. Adopters can decide: deploy only human-reviewed rules, only stable-tier rules, or both."}
          </p>
          <p className="text-sm text-stone leading-relaxed">
            {locale === "zh"
              ? "規則集每天透過自動結晶飛輪擴張,新生成的規則大多先標記為 LLM 生成(雙重閘門驗證)。human-reviewed 的比例隨著人工 review 持續積累而上升——而這個比例本身,是公開的。"
              : "The ruleset grows daily through an auto-crystallization flywheel, and most newly generated rules start tagged LLM-generated (2-gate validated). The human-reviewed share rises as human review accumulates — and that share is itself published."}
          </p>
        </div>
      </Reveal>

      {/* ── THE FORMULA ────────────────────────────────────── */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {locale === "zh" ? "公式" : "The Formula"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-extrabold tracking-[-1px] mb-2">
          {locale === "zh"
            ? "信心分數是數字,不是意見"
            : "Confidence is a number, not an opinion"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "每個組成都由可測量的事實計算而來。公式是公開的 — 你可以自己跑。"
            : "Every component is computed from measurable facts. Run it yourself — the formula is public."}
        </p>
      </Reveal>

      <Reveal delay={0.1}>
        <div className="bg-paper border border-fog p-5 md:p-6 mb-6">
          <div className="font-data text-[13px] md:text-sm text-ink bg-fog/40 border border-fog p-4 rounded-sm overflow-x-auto">
            confidence = 0.4 × precision + 0.3 × wild + 0.2 × coverage + 0.1 × evasion
          </div>
        </div>
      </Reveal>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog border border-fog mb-8">
        {FORMULA_COMPONENTS.map((c) => (
          <Reveal key={c.name}>
            <div className="bg-paper p-5 md:p-6 h-full">
              <div className="flex items-center justify-between mb-2">
                <span className="font-display font-semibold text-ink">{c.name}</span>
                <span className="font-data text-xs text-blue bg-blue/10 px-2 py-0.5 rounded-sm">
                  {c.weight}
                </span>
              </div>
              <div className="font-data text-xs text-stone mb-2">{c.formula}</div>
              <p className="text-sm text-stone">{c.meaning}</p>
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
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {locale === "zh" ? "核心差異" : "The Differentiator"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-extrabold tracking-[-1px] mb-2">
          {locale === "zh"
            ? "雙維度合規模型"
            : "Two-dimensional compliance model"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "將「規則有沒有必要 metadata」與「誰驗證的」分開處理。LLM 只在撰寫階段參與;偵測核心本身是 deterministic regex / AST 比對,執行時不呼叫 LLM。"
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
                ? "誰驗證了 metadata?human-reviewed、community-contributed、auto-generated 或 llm-generated。升級 stable 要求「已驗證來源」,不只是「有」。"
                : "Who verified the metadata? human-reviewed, community-contributed, auto-generated, or llm-generated. Stable promotion requires verified provenance — not just presence."}
            </p>
            <code className="font-data text-xs text-stone">
              {`metadata_provenance: { mitre_atlas: human-reviewed }`}
            </code>
          </div>
        </Reveal>
      </div>

      <Reveal>
        <div className="bg-paper border border-fog p-5 md:p-6 mb-16">
          <div className="font-data text-xs text-stone tracking-wider uppercase mb-3">
            {locale === "zh" ? "為什麼這件事重要" : "Why this matters"}
          </div>
          <p className="text-sm text-ink leading-relaxed mb-3">
            {locale === "zh"
              ? "傳統的規則標準(Sigma、YARA、OWASP CRS)把合規視為二元 — 有就過、沒有就不過。這造成逆向誘因:廠商為了通過檢查而填入 metadata,但並未真正審核。"
              : "Traditional rule standards (Sigma, YARA, OWASP CRS) treat compliance as binary — either the metadata is there or it is not. This creates a perverse incentive: vendors pad metadata to pass the check without doing the underlying review work."}
          </p>
          <p className="text-sm text-stone leading-relaxed">
            {locale === "zh"
              ? "ATR 將這兩個維度分開。自動生成的對應可以通過 experimental gate 以便快速迭代。升級到 stable — 企業在生產環境會封鎖的層級 — 要求人工 review。快速迭代和誠實信任,同時存在。"
              : "ATR separates the two dimensions. Auto-generated mappings can pass the experimental gate for fast iteration. Stable promotion — the level enterprises block in production — requires human review. Fast iteration and honest trust, at the same time."}
          </p>
        </div>
      </Reveal>

      {/* ── MATURITY LADDER ────────────────────────────────── */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {locale === "zh" ? "成熟度階梯" : "The Ladder"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-extrabold tracking-[-1px] mb-2">
          {locale === "zh"
            ? "每條規則都要靠證據往上爬一階"
            : "Every rule climbs by evidence, not by age"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "draft → experimental → test → stable → deprecated。每一階的晉升條件都是明確、機械化的——不是靠規則放著夠久,而是靠它累積的證據。品質退化時降級自動觸發,不需人工決策。"
            : "draft → experimental → test → stable → deprecated. Each gate is explicit and mechanical — a rule moves up on the evidence it has accumulated, never on how long it has sat in the repository. When quality regresses, demotion fires automatically, with no human in the loop."}
        </p>
      </Reveal>

      <div className="grid grid-cols-1 gap-px bg-fog border border-fog mb-6">
        {MATURITY_LEVELS.map((m) => (
          <Reveal key={m.label}>
            <div className="bg-paper p-5 md:p-6">
              <div className="flex flex-col md:flex-row md:gap-8 md:items-start">
                <div className="md:w-32 flex-shrink-0 mb-3 md:mb-0">
                  <span className="font-data text-xs text-ink bg-fog/60 px-3 py-1 rounded-sm tracking-wide uppercase font-semibold">
                    {m.label}
                  </span>
                </div>
                <div className="flex-1 grid md:grid-cols-2 gap-5">
                  <div>
                    <div className="font-data text-xs text-stone tracking-wider uppercase mb-2">
                      {locale === "zh" ? "晉升門檻" : "Promotion gate"}
                    </div>
                    <p className="text-sm text-ink leading-relaxed">{m.gate}</p>
                  </div>
                  <div>
                    <div className="font-data text-xs text-stone tracking-wider uppercase mb-2">
                      {locale === "zh" ? "部署建議" : "Deployment guidance"}
                    </div>
                    <p className="text-sm text-ink leading-relaxed">{m.deploy}</p>
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
            {locale === "zh" ? "自動降級" : "Automatic demotion"}
          </div>
          <p className="text-sm text-ink leading-relaxed">
            {locale === "zh"
              ? "Stable 規則若野外 false positive rate 超過 2%,或 30 天內累積 3 次未解決的 FP 回報,會自動降級為 experimental。不需人工決策。系統自我修正。"
              : "Stable rules with a wild false positive rate above 2%, or three unresolved false positive reports within 30 days, are automatically demoted to experimental. No human decision required. The system self-corrects."}
          </p>
        </div>
      </Reveal>

      {/* ── DETECTION LANES ───────────────────────────────────
          v3.5.0: the maturity ladder above drives three lanes. This is
          where the quality model becomes an operational, honest tradeoff —
          FP reported lane by lane, never as one flattering figure. */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {locale === "zh" ? "偵測車道" : "Detection lanes"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-extrabold tracking-[-1px] mb-2">
          {locale === "zh"
            ? "成熟度決定一條規則被允許做什麼"
            : "Maturity decides what a rule is allowed to do"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "階梯不只是個標籤,它驅動三條偵測車道。每條車道是「放行哪些成熟度」與「對誤報的容忍度」之間,一個明擺著的取捨——而每條車道的誤報率,都各自公開。"
            : "The ladder is not just a label — it drives three detection lanes. Each lane is an explicit tradeoff between which maturities it admits and how much false positive it tolerates. And each lane publishes its own false-positive rate."}
        </p>
      </Reveal>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog border border-fog mb-6">
        <Reveal>
          <div className="bg-paper p-5 md:p-6 h-full">
            <div className="font-data text-xs text-blue tracking-wider uppercase mb-2">
              {locale === "zh" ? "enforce 車道" : "enforce lane"}
            </div>
            <div className="font-display text-3xl font-extrabold text-ink mb-1">~0.24%</div>
            <div className="font-data text-xs text-stone mb-3">
              {locale === "zh" ? "誤報率 · 僅 stable + confirm" : "false positives · stable + confirm only"}
            </div>
            <p className="text-sm text-stone leading-relaxed">
              {locale === "zh"
                ? "只放行最成熟、經人工確認的規則。精確度買來的代價是召回率下降——這是刻意的取捨,擺在明處,讓在生產環境封鎖的人自己選。"
                : "Admits only the most mature, human-confirmed rules. The precision is bought by giving up recall — a deliberate tradeoff, stated openly, for anyone who blocks in production."}
            </p>
          </div>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="bg-paper p-5 md:p-6 h-full">
            <div className="font-data text-xs text-critical tracking-wider uppercase mb-2">
              {locale === "zh" ? "alert 車道" : "alert lane"}
            </div>
            <div className="font-display text-3xl font-extrabold text-ink mb-1">
              {locale === "zh" ? "告警" : "Alert"}
            </div>
            <div className="font-data text-xs text-stone mb-3">
              {locale === "zh" ? "stable + test · 不封鎖" : "stable + test · no blocking"}
            </div>
            <p className="text-sm text-stone leading-relaxed">
              {locale === "zh"
                ? "納入晉升候選的 test 規則,只告警、不封鎖。在誤報傷不到使用者的前提下,擴大被看見的攻擊面。"
                : "Adds promotion-candidate test rules, surfacing more of the attack surface — but only as alerts, where a false positive costs a notification, not a blocked user."}
            </p>
          </div>
        </Reveal>
        <Reveal delay={0.2}>
          <div className="bg-paper p-5 md:p-6 h-full">
            <div className="font-data text-xs text-stone tracking-wider uppercase mb-2">
              {locale === "zh" ? "hunt 車道（預設）" : "hunt lane (default)"}
            </div>
            <div className="font-display text-3xl font-extrabold text-ink mb-1">~9%</div>
            <div className="font-data text-xs text-stone mb-3">
              {locale === "zh" ? "誤報率 · 全部規則,純建議性" : "false positives · everything, advisory only"}
            </div>
            <p className="text-sm text-stone leading-relaxed">
              {locale === "zh"
                ? "把所有規則當作建議性訊號全開,給做威脅獵捕的人最大的可見度。約 9% 的誤報率不是被藏起來的瑕疵——它就印在這裡,因為這條車道從不自動封鎖任何東西。"
                : "Runs every rule as an advisory signal, giving threat hunters maximum visibility. The ~9% false-positive rate is not a flaw hidden in a footnote — it is printed right here, because this lane never blocks anything on its own."}
            </p>
          </div>
        </Reveal>
      </div>

      <Reveal>
        <div className="bg-paper border border-fog p-5 md:p-6 mb-16">
          <div className="font-data text-xs text-stone tracking-wider uppercase mb-3">
            {locale === "zh" ? "品質即誠實" : "Quality is honesty"}
          </div>
          <p className="text-sm text-ink leading-relaxed">
            {locale === "zh"
              ? "0.24% 與 9% 是同一套規則、兩條車道的真實數字。把它們並排印出來,而不是只報那個漂亮的,是這個標準對「品質」的定義:一個標準的可信度,取決於它願不願意公開自己最差的數字。採用者拿到的不是一個被擦亮的承諾,而是一張可以自己驗證的取捨表。"
              : "0.24% and 9% are the real figures from one ruleset across two lanes. Printing them side by side — instead of quoting only the flattering one — is what this standard means by quality: a standard earns trust by publishing its worst figure, not hiding it. Adopters get a tradeoff table they can verify themselves, not a polished promise."}
          </p>
        </div>
      </Reveal>

      {/* ── THE GAUNTLET ───────────────────────────────────── */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {locale === "zh" ? "六道關卡" : "The Gauntlet"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-extrabold tracking-[-1px] mb-2">
          {locale === "zh"
            ? "一條規則在抵達生產環境前要過六關"
            : "Six stages before a rule reaches production"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "LLM 草擬的規則必須通過六個獨立的驗證階段才能保護使用者。每個階段都有機械化、公開的判斷條件。"
            : "An LLM-drafted rule passes through six independent verification stages before it ever protects a user. Each stage has mechanical, public criteria."}
        </p>
      </Reveal>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-fog border border-fog mb-10">
        {GAUNTLET_STAGES.map((s) => (
          <Reveal key={s.stage}>
            <div className="bg-paper p-5 md:p-6 h-full">
              <div className="flex items-baseline gap-3 mb-2">
                <span className="font-data text-xs text-stone tracking-wider uppercase">
                  {locale === "zh" ? `階段 ${s.stage}` : `Stage ${s.stage}`}
                </span>
                <h3 className="font-display font-bold text-ink">{s.title}</h3>
              </div>
              <p className="text-sm text-stone leading-relaxed">{s.detail}</p>
            </div>
          </Reveal>
        ))}
      </div>

      {/* ── REAL RULE EXAMPLE ──────────────────────────────── */}
      <Reveal>
        <div className="bg-paper border border-blue/40 mb-16">
          <div className="border-b border-blue/30 bg-blue/5 px-5 md:px-6 py-3 flex items-center justify-between flex-wrap gap-2">
            <span className="font-data text-xs text-blue tracking-wider uppercase font-semibold">
              {locale === "zh"
                ? "實際結晶輸出 · 通過品質關"
                : "Live Crystallization Output · Gate Passed"}
            </span>
            <code className="font-data text-xs text-stone">{EXAMPLE_RULE.id}</code>
          </div>
          <div className="p-5 md:p-6">
            <h3 className="font-display text-lg md:text-xl font-bold text-ink mb-2">
              {EXAMPLE_RULE.title}
            </h3>
            <div className="inline-block font-data text-xs text-critical bg-critical/10 px-2 py-0.5 rounded-sm tracking-wider uppercase mb-5">
              severity · {EXAMPLE_RULE.severity}
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-fog border border-fog mb-5">
              <div className="bg-paper p-4">
                <div className="font-display text-2xl font-extrabold text-blue mb-1">
                  {EXAMPLE_RULE.layers}
                </div>
                <div className="font-data text-xs text-stone">
                  {locale === "zh" ? "偵測層" : "Detection layers"}
                </div>
              </div>
              <div className="bg-paper p-4">
                <div className="font-display text-2xl font-extrabold text-blue mb-1">
                  {EXAMPLE_RULE.tpTn}
                </div>
                <div className="font-data text-xs text-stone">
                  {locale === "zh" ? "TP + TN 測試" : "TP + TN cases"}
                </div>
              </div>
              <div className="bg-paper p-4">
                <div className="font-display text-2xl font-extrabold text-blue mb-1">
                  {EXAMPLE_RULE.evasions}
                </div>
                <div className="font-data text-xs text-stone">
                  {locale === "zh" ? "規避測試" : "Evasion tests"}
                </div>
              </div>
              <div className="bg-paper p-4">
                <div className="font-display text-2xl font-extrabold text-blue mb-1">
                  100%
                </div>
                <div className="font-data text-xs text-stone">
                  {locale === "zh" ? "必要欄位完備" : "Required fields"}
                </div>
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-5 mb-5">
              <div>
                <div className="font-data text-xs text-stone tracking-wider uppercase mb-2">
                  OWASP
                </div>
                {EXAMPLE_RULE.owasp.map((o) => (
                  <div
                    key={o}
                    className="font-data text-xs text-ink mb-1.5 flex items-center gap-2"
                  >
                    <span className="text-blue">✓</span>
                    {o}
                  </div>
                ))}
              </div>
              <div>
                <div className="font-data text-xs text-stone tracking-wider uppercase mb-2">
                  MITRE ATLAS
                </div>
                <div className="font-data text-xs text-ink flex items-center gap-2">
                  <span className="text-blue">✓</span>
                  {EXAMPLE_RULE.mitre}
                </div>
              </div>
            </div>

            <div className="border-t border-fog pt-4 flex items-center justify-between flex-wrap gap-3">
              <div>
                <div className="font-data text-xs text-stone tracking-wider uppercase mb-1">
                  {locale === "zh" ? "來源" : "Provenance"}
                </div>
                <code className="font-data text-xs text-critical">
                  {EXAMPLE_RULE.provenance}
                </code>
              </div>
              <p className="text-xs text-stone italic text-right max-w-xs">
                {locale === "zh"
                  ? "誠實標記為 LLM 生成。信心分數封頂 70,直到人工 review 升級為 human-reviewed。"
                  : "Tagged honestly as LLM-generated. Confidence capped at 70 until human review upgrades it."}
              </p>
            </div>
          </div>
        </div>
      </Reveal>

      {/* ── COMPARISON ─────────────────────────────────────── */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {locale === "zh" ? "同業比較" : "The Landscape"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-extrabold tracking-[-1px] mb-2">
          {locale === "zh"
            ? "ATR 與既有規則標準的比較"
            : "How ATR compares to existing rule standards"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "Sigma、YARA、OWASP CRS、Suricata 解決了惡意軟體、SIEM、WAF、IDS 的這個問題。還沒有人替 AI agent 解決 — 直到現在。"
            : "Sigma, YARA, OWASP CRS, and Suricata solved this for malware, SIEM, WAF, and IDS. Nobody had solved it for AI agents — until now."}
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
                  <td className="py-3 px-4 text-ink">{row.feature}</td>
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
            ? "ATR 是唯一要求野外掃描驗證、測量 FP rate 並在品質退化時自動降級的標準。"
            : "ATR is the only standard requiring wild-scan validation with measured FP rates and automatic demotion on quality regression."}
        </p>
      </Reveal>

      {/* ── VERIFY IT YOURSELF ─────────────────────────────── */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {locale === "zh" ? "自己驗證" : "Verify It Yourself"}
        </div>
        <h2 className="font-display text-2xl md:text-3xl font-extrabold tracking-[-1px] mb-2">
          {locale === "zh"
            ? "別相信我們,執行驗證器"
            : "Don't trust us — run the validator"}
        </h2>
        <p className="text-sm text-stone mb-6 max-w-2xl">
          {locale === "zh"
            ? "每個 function 都是純函式、開源、有文件。你可以在一分鐘內對自己的規則(或我們的)計算分數。"
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
            {`npm install agent-threat-rules@${getSpecMeta().version}`}
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
          <h2 className="font-display text-2xl md:text-3xl font-extrabold tracking-[-1px] mb-3">
            {locale === "zh" ? "可測量。可審計。公開。" : "Measurable. Auditable. Open."}
          </h2>
          <p className="text-sm text-stone mb-6 max-w-xl mx-auto">
            {locale === "zh"
              ? "公式是公開的,車道的誤報率是公開的,連最差的那個數字也是公開的。任何符合規範的掃描器 — ATR、Cisco、Microsoft AGT 或你自己寫的 — 都能用同一個 library、在同一個維度上計分,並各自驗證。這就是一個開放標準該有的可信度。"
              : "The formula is public, the per-lane false-positive rates are public, and so is the worst of them. Any conformant scanner — ATR, Cisco, Microsoft AGT, or one you write yourself — can score rules on the same axes, with the same library, and verify the result independently. That is what trust in an open standard looks like."}
          </p>
          <div className="flex flex-wrap items-center justify-center gap-4">
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/proposals/001-atr-quality-standard-rfc.md"
              target="_blank"
              rel="noopener noreferrer"
              className="bg-blue text-white px-5 py-2.5 rounded-sm text-sm font-semibold hover:bg-blue-hover transition-colors"
            >
              {locale === "zh" ? "閱讀 RFC" : "Read the RFC"} →
            </a>
            <a
              href={`/${locale}/rules`}
              className="font-data text-xs text-stone hover:text-ink transition-colors border border-fog px-4 py-2.5 rounded-sm"
            >
              {locale === "zh" ? "瀏覽規則" : "Browse rules"}
            </a>
          </div>
        </div>
      </Reveal>
    </div>
  );
}
