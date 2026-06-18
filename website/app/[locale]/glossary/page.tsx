/* ATR Glossary — definitions for key terms used throughout the
 * specification. Terms stay English (memory rule); definitions flip per
 * locale. Each entry anchored by slug for deep linking.
 */
import type { Metadata } from "next";
import { locales, type Locale, t } from "@/lib/i18n";
import { getSpecMeta } from "@/lib/spec-meta";
import { DocumentStatus } from "@/components/spec/DocumentStatus";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  return {
    title: "Glossary — ATR",
    description:
      locale === "zh"
        ? "ATR 規格中關鍵術語的定義。"
        : "Definitions for key terms used throughout the ATR specification.",
  };
}

interface GlossaryEntry {
  term: string;
  en: string;
  zh: string;
}

// Terms remain English regardless of locale; only the definition flips.
// Sorted alphabetically (case-insensitive) at render time.
const ENTRIES: GlossaryEntry[] = [
  {
    term: "agent runtime",
    en: "An execution environment that hosts one or more AI agents and mediates their access to tools, model APIs, and external resources.",
    zh: "承載一個或多個 AI agent,並仲介其對工具、模型 API 及外部資源存取的執行環境。",
  },
  {
    term: "ATR engine",
    en: "An implementation that consumes ATR rules and emits matches. A conforming engine MUST satisfy the requirements in /conformance §1.",
    zh: "消費 ATR 規則並產出 match 的實作。符規引擎 MUST 滿足 /conformance §1 中列出的要求。",
  },
  {
    term: "ATR rule",
    en: "A single YAML document declaring an attack pattern, the field it inspects, its test cases, and its cross-framework mappings.",
    zh: "單一 YAML 文件,宣告攻擊模式、檢測欄位、test cases 與跨框架對應。",
  },
  {
    term: "canary",
    en: "A 24-hour observation window during which a newly generated rule runs in shadow mode before being eligible for production status.",
    zh: "新產生的規則進入 production status 前,先在 shadow 模式下執行的 24 小時觀察窗。",
  },
  {
    term: "confirm",
    en: "An optional rule field requesting a second-stage check before the rule may fire in the enforce or alert lane. The only defined method is confirm: embedding, which re-evaluates a pattern hit against attack-content similarity and keeps the match only when similarity meets the configured threshold. The confirm gate is narrowing only: it may remove a match but never create one. A rule declaring confirm MUST have maturity stable or test, and a detection method of pattern, signature, or semantic — trace and behavioral signals are structural, not content, so content-similarity confirmation does not apply.",
    zh: "選用的規則欄位,要求規則在 enforce 或 alert 車道開火前先通過第二階段檢查。目前唯一定義的方法是 confirm: embedding——將 pattern 命中重新對攻擊內容相似度評估,僅當相似度達到設定門檻時才保留該 match。confirm 閘只會收窄:它可以移除 match,但永不創造 match。宣告 confirm 的規則 MUST 為 stable 或 test 成熟度,且 detection method 為 pattern、signature 或 semantic——trace 與 behavioral 的訊號是結構性的,非內容,故內容相似度確認不適用。",
  },
  {
    term: "conformance level",
    en: "One of L1 (Engine), L2 (Publisher), or L3 (Sub-range Authority). Defined normatively in /conformance.",
    zh: "L1 (Engine)、L2 (Publisher) 或 L3 (Sub-range Authority) 三者之一。於 /conformance 中規範性定義。",
  },
  {
    term: "crystallization",
    en: "The Threat Cloud pipeline that converts an observed attack into a candidate ATR rule and routes it through review. (Reference implementation, not part of the normative standard.)",
    zh: "Threat Cloud pipeline,將觀察到的攻擊轉換為 ATR 候選規則並送入審查。(參考實作,非規範標準的一部分。)",
  },
  {
    term: "detection.conditions",
    en: "The array of field/operator/value triples in a rule body that determine whether the rule matches.",
    zh: "規則內容中由 field/operator/value 三元組構成的陣列,決定規則是否 match。",
  },
  {
    term: "detection lane",
    en: "A consumer-selected gate that decides which rule maturities are allowed to fire, traded against false-positive tolerance. Three lanes are defined. enforce fires stable rules only — the auto-block lane, lowest false-positive rate. alert fires stable and test rules — the analyst / correlation lane. hunt fires every non-deprecated rule as advisory signal — the default, and the eval lane. Deprecated rules fire in no lane. The lane is chosen by the engine consumer, not declared on the rule: the same rule corpus yields a different firing set per lane, which is why ATR reports false-positive rates lane by lane rather than as a single figure.",
    zh: "由消費者選定的閘,決定哪些成熟度的規則允許開火,以此換取對誤報的容忍度。共定義三條車道。enforce 只讓 stable 規則開火——自動封鎖車道,誤報率最低。alert 讓 stable 與 test 規則開火——分析師 / 關聯車道。hunt 讓所有未廢棄的規則以建議性訊號開火——預設車道,也是評估車道。deprecated 規則在任何車道皆不開火。車道由引擎消費者選擇,而非宣告於規則上:同一份規則語料在不同車道下產出不同的開火集合,這也是 ATR 逐車道揭露誤報率、而非用單一數字概括的原因。",
  },
  {
    term: "fixture",
    en: "A YAML file under spec/conformance/ pairing a rule with its expected evaluation outcome on a fixed event.",
    zh: "位於 spec/conformance/ 下的 YAML,將規則與其在固定 event 上的預期評估結果配對。",
  },
  {
    term: "Implementer Report",
    en: "A self-declared public record of an organization's ATR integration, listed on /implementers.",
    zh: "組織對其 ATR 整合的自我宣告公開紀錄,列於 /implementers。",
  },
  {
    term: "MCP exchange",
    en: "A single request/response pair between an MCP client and an MCP server. ATR rules with scan_target: mcp_exchange evaluate against this shape.",
    zh: "MCP client 與 MCP server 之間的單次 request/response。scan_target: mcp_exchange 的 ATR 規則對此形狀進行評估。",
  },
  {
    term: "maturity",
    en: "The promotion stage of a rule, drawn from a fixed ladder: draft → experimental → test → stable → deprecated. A rule advances on evidence (false-positive rate, sample volume, confidence), not on age. Maturity is what each detection lane gates on: enforce admits stable only, alert admits stable and test, hunt admits everything non-deprecated. An unrecognized maturity value normalizes to experimental — a typo never silently reaches the enforce lane. Promotion and demotion rules are defined in RFC-001.",
    zh: "規則的晉升階段,取自固定階梯:draft → experimental → test → stable → deprecated。規則靠證據(誤報率、樣本量、信心分數)晉升,而非靠年資。成熟度正是各偵測車道據以設閘的依據:enforce 只收 stable、alert 收 stable 與 test、hunt 收所有未廢棄規則。無法辨識的成熟度值會正規化為 experimental——一個拼寫錯誤永遠不會默默抵達 enforce 車道。晉升與降級規則由 RFC-001 定義。",
  },
  {
    term: "normative",
    en: "Content that defines requirements for conformance. Engines and rules MUST follow normative sections.",
    zh: "定義符規要求的內容。引擎與規則 MUST 遵守 normative 章節。",
  },
  {
    term: "informative",
    en: "Content that provides context but does not define conformance requirements.",
    zh: "提供脈絡但不定義符規要求的內容。",
  },
  {
    term: "provenance",
    en: "Metadata on a rule describing who authored it, from what source (e.g., garak probe, CVE), and when.",
    zh: "規則上的 metadata,描述其作者、來源 (例如 garak probe、CVE) 與時間。",
  },
  {
    term: "RFC-001",
    en: "The internal numbering of ATR's quality standard for rule promotion. See /quality-standard.",
    zh: "ATR 規則晉升品質標準的內部編號。見 /quality-standard。",
  },
  {
    term: "scan_target",
    en: "A required field on every rule declaring what shape of event the rule expects: skill, mcp_exchange, agent_config, etc.",
    zh: "每條規則必填欄位,宣告規則預期的 event 形狀:skill、mcp_exchange、agent_config 等。",
  },
  {
    term: "severity",
    en: "One of {informational, low, medium, high, critical} declared on every rule.",
    zh: "{informational, low, medium, high, critical} 之一,每條規則皆需宣告。",
  },
  {
    term: "SKILL.md",
    en: "A Markdown manifest format used by some MCP skill ecosystems (OpenClaw, Skills.sh, ClawHub) to declare an agent skill's tools, prompts, and metadata.",
    zh: "部分 MCP skill 生態系 (OpenClaw、Skills.sh、ClawHub) 使用的 Markdown 清單格式,宣告 agent skill 的工具、prompt 與 metadata。",
  },
  {
    term: "status",
    en: "A required field gating whether a rule loads into production matching at all. Rules with status: draft or status: deprecated MUST NOT participate in production matching without explicit opt-in. Status is the coarse load-time gate; maturity is the finer per-lane gate applied to the rules that do load. The two are distinct fields and may differ — a rule may be status: stable yet maturity: experimental, in which case it loads but only fires in the hunt lane.",
    zh: "決定規則是否載入生產環境 match 的必填欄位。status: draft 或 status: deprecated 的規則 MUST NOT 在未明示 opt-in 的情況下參與生產環境 match。status 是載入時的粗閘;maturity 是套用於已載入規則的細閘(逐車道)。兩者是不同欄位,可能不一致——一條規則可以 status: stable 卻 maturity: experimental,此時它會載入但只在 hunt 車道開火。",
  },
  {
    term: "sub-range",
    en: "A contiguous segment of the ATR-YYYY-NNNNN identifier space reserved for a specific publisher (e.g., ATR-TW-2026-NNNNN for Taiwan).",
    zh: "ATR-YYYY-NNNNN 識別碼空間中保留給特定 publisher 的連續區段 (例如台灣的 ATR-TW-2026-NNNNN)。",
  },
  {
    term: "Technical Steering Committee (TSC)",
    en: "The body that governs ATR's evolution. Currently in BDFL transition; see /charter.",
    zh: "治理 ATR 演化的機構。目前處於 BDFL 過渡階段;見 /charter。",
  },
  {
    term: "Threat Cloud",
    en: "An optional reference service operated by the ATR maintainers — not part of the standard. The standard is the spec plus the MIT-licensed rules, fully usable offline via npm / PyPI / raw YAML. Threat Cloud only adds hosted convenience (rule sync, threat submission); the same outcomes are reachable without it. Technically, it is an auto-review backend for community-submitted rules, running the crystallization pipeline and safety gates.",
    zh: "Threat Cloud 是 ATR 維護者運營的選用參考服務,並非標準的一部分。標準本體是規格加上 MIT 授權的規則,透過 npm / PyPI / 純 YAML 完全可離線使用;Threat Cloud 只提供 hosted 便利(規則同步、威脅提交),不用它也能達到同樣結果。技術上,它是對社群提交規則的自動審查後端,執行 crystallization pipeline 與安全閘 (safety gate)。",
  },
];

function slugify(term: string): string {
  return term
    .toLowerCase()
    .replace(/[()._]+/g, "-")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function firstCharLabel(term: string): string {
  const ch = term.trim().charAt(0).toUpperCase();
  return /[A-Z]/.test(ch) ? ch : "#";
}

export default async function GlossaryPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: l } = await params;
  const locale = (locales.includes(l as Locale) ? l : "en") as Locale;
  const meta = getSpecMeta();
  const zh = locale === "zh";

  // Alphabetical sort, case-insensitive.
  const sorted = [...ENTRIES].sort((a, b) =>
    a.term.toLowerCase().localeCompare(b.term.toLowerCase()),
  );

  // Compute first-letter index for the A/B/C jump bar.
  const letters: string[] = [];
  for (const e of sorted) {
    const ch = firstCharLabel(e.term);
    if (!letters.includes(ch)) letters.push(ch);
  }

  return (
    <main
      id="main-content"
      className="spec-document w-full max-w-7xl mx-auto px-5 md:px-8 pt-24 md:pt-28 pb-24"
      lang={zh ? "zh-Hant" : "en"}
    >
      {/* Header */}
      <header className="mb-8 md:mb-10 max-w-3xl">
        <p
          className="text-xs uppercase tracking-[0.18em] text-stone mb-3"
          style={{ fontFamily: "var(--font-data)" }}
        >
          {zh ? "詞彙 — Glossary" : "Glossary"}
        </p>
        <h1
          className="text-3xl md:text-5xl font-bold text-navy-ink mb-4 leading-[1.1]"
          style={{
            fontFamily: "var(--font-display)",
            letterSpacing: "-0.02em",
          }}
        >
          {t(locale, "glossary.title")}
        </h1>
        <p
          className="text-base md:text-xl text-graphite leading-snug mb-6"
          style={{ fontFamily: "var(--font-body)", maxWidth: "42em" }}
        >
          {t(locale, "glossary.subtitle")}
        </p>
        <DocumentStatus locale={locale} />
      </header>

      {/* Two-column spec body */}
      <div className="grid grid-cols-1 lg:grid-cols-[14rem_minmax(0,1fr)] gap-10 lg:gap-14">
        {/* ToC sidebar — index of first-letters */}
        <aside aria-label="Alphabetical index" className="lg:order-first">
          <nav className="spec-toc" aria-label={t(locale, "spec.toc_aria")}>
            <p
              className="text-xs font-semibold uppercase tracking-wider text-stone mb-3"
              style={{ fontFamily: "var(--font-body)" }}
            >
              {zh ? "字母索引" : "Alphabetical Index"}
            </p>
            <ol className="not-prose">
              {letters.map((ch) => (
                <li key={ch}>
                  <a href={`#letter-${ch.toLowerCase()}`}>
                    <span className="toc-section-num">{ch}</span>
                  </a>
                </li>
              ))}
            </ol>
          </nav>
        </aside>

        {/* Main body — alphabetical definition list */}
        <div className="min-w-0 spec-measure-wide">
          <section id="terms" aria-labelledby="terms-heading">
            <h2 id="terms-heading">
              <a href="#terms" className="section-anchor" aria-hidden="true">
                §1
              </a>
              {zh ? "術語定義" : "Term Definitions"}
            </h2>

            <dl className="not-prose">
              {sorted.map((entry, i) => {
                const slug = slugify(entry.term);
                const id = `glossary-${slug}`;
                const ch = firstCharLabel(entry.term);
                const prev = i > 0 ? firstCharLabel(sorted[i - 1].term) : null;
                const showLetterAnchor = prev !== ch;
                const definition = zh ? entry.zh : entry.en;

                return (
                  <div
                    key={id}
                    className="border-t border-fog py-5 first:border-t-0"
                  >
                    {showLetterAnchor ? (
                      <span
                        id={`letter-${ch.toLowerCase()}`}
                        aria-hidden="true"
                        className="block -mt-2"
                      />
                    ) : null}
                    <dt
                      id={id}
                      className="text-lg font-semibold text-navy-ink mb-2 scroll-mt-24"
                      style={{ fontFamily: "var(--font-display)" }}
                    >
                      <a
                        href={`#${id}`}
                        className="section-anchor"
                        aria-hidden="true"
                      >
                        §
                      </a>
                      <span lang="en">{entry.term}</span>
                    </dt>
                    <dd
                      className="text-graphite leading-relaxed"
                      style={{
                        fontFamily: "var(--font-body)",
                        maxWidth: "42em",
                      }}
                    >
                      {definition}
                    </dd>
                  </div>
                );
              })}
            </dl>
          </section>

          {/* End matter */}
          <hr className="my-12 border-fog" />
          <p className="spec-meta">
            {zh ? "編輯" : "Editor"}: {meta.editors[0].name}
            {" <"}
            <a
              href={`mailto:${meta.editors[0].email}`}
              className="text-navy underline"
            >
              {meta.editors[0].email}
            </a>
            {">"} — DOI{" "}
            <a
              href={`https://doi.org/${meta.doi}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-navy underline"
            >
              {meta.doi}
            </a>{" "}
            — MIT License — ISO 8601 {meta.lastModified}
          </p>
        </div>
      </div>
    </main>
  );
}
