/* ATR Project Charter — defines what ATR is, what it is not, how
 * decisions are made, and how the Technical Steering Committee is
 * seated. Single source of truth for project-level governance scope.
 */
import Link from "next/link";
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
    title: "Charter — ATR",
    description:
      locale === "zh"
        ? "ATR 章程:定義 ATR 是什麼、不是什麼、決策如何做成、以及技術指導委員會 (TSC) 如何就任。"
        : "The ATR charter defines what ATR is, what it is not, how decisions are made, and how the Technical Steering Committee is seated.",
  };
}

const GOVERNANCE_URL =
  "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/GOVERNANCE.md";

interface SeatCriterion {
  en: string;
  zh: string;
}

const TSC_CRITERIA: SeatCriterion[] = [
  {
    en: "Demonstrated technical contribution to ATR — rules merged, engine work, benchmark work, or schema work — within the past twelve months.",
    zh: "過去十二個月內對 ATR 有可佐證之技術貢獻 — 合併的規則、engine 開發、benchmark 工作或 schema 工作。",
  },
  {
    en: "Public maintainer of an ATR implementer organization or a downstream library that ships ATR in production.",
    zh: "為某 ATR implementer 組織或將 ATR 投入生產環境之下游 library 的公開維護者。",
  },
  {
    en: "Endorsement from the current maintainer plus one external implementer (the implementer MUST come from a different organization than the candidate).",
    zh: "取得現任維護者背書,加上一位外部 implementer 背書 (該 implementer MUST 來自與候選人不同之組織)。",
  },
  {
    en: "Commitment to attend bi-monthly TSC calls and to respond to charter-level decisions within seven days.",
    zh: "承諾參與每兩個月一次之 TSC 會議,並於七日內回應章程層級之決策。",
  },
];

export default async function CharterPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: l } = await params;
  const locale = (locales.includes(l as Locale) ? l : "en") as Locale;
  const meta = getSpecMeta();
  const prefix = `/${locale}`;
  const zh = locale === "zh";

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
          {zh ? "章程 — Project Charter" : "Project Charter"}
        </p>
        <h1
          className="text-3xl md:text-5xl font-bold text-navy-ink mb-4 leading-[1.1]"
          style={{
            fontFamily: "var(--font-display)",
            letterSpacing: "-0.02em",
          }}
        >
          {t(locale, "charter.title")}
        </h1>
        <p
          className="text-base md:text-xl text-graphite leading-snug mb-6"
          style={{ fontFamily: "var(--font-body)", maxWidth: "42em" }}
        >
          {t(locale, "charter.subtitle")}
        </p>
        <DocumentStatus locale={locale} />
      </header>

      {/* Two-column spec body */}
      <div className="grid grid-cols-1 lg:grid-cols-[14rem_minmax(0,1fr)] gap-10 lg:gap-14">
        {/* ToC sidebar */}
        <aside aria-label="Table of contents" className="lg:order-first">
          <nav className="spec-toc" aria-label={t(locale, "spec.toc_aria")}>
            <p
              className="text-xs font-semibold uppercase tracking-wider text-stone mb-3"
              style={{ fontFamily: "var(--font-body)" }}
            >
              {t(locale, "spec.toc")}
            </p>
            <ol>
              <li>
                <a href="#mission">
                  <span className="toc-section-num">§1</span>
                  {t(locale, "charter.mission.h")}
                </a>
              </li>
              <li>
                <a href="#scope">
                  <span className="toc-section-num">§2</span>
                  {t(locale, "charter.scope.h")}
                </a>
              </li>
              <li>
                <a href="#governance">
                  <span className="toc-section-num">§3</span>
                  {t(locale, "charter.governance.h")}
                </a>
              </li>
              <li>
                <a href="#ip">
                  <span className="toc-section-num">§4</span>
                  {t(locale, "charter.ip.h")}
                </a>
              </li>
              <li>
                <a href="#decisions">
                  <span className="toc-section-num">§5</span>
                  {zh ? "決策機制" : "Decision-Making"}
                </a>
              </li>
              <li>
                <a href="#tsc">
                  <span className="toc-section-num">§6</span>
                  {zh ? "TSC 就任標準" : "TSC Seating Criteria"}
                </a>
              </li>
            </ol>
            <hr className="my-5 border-fog" />
            <p
              className="text-xs uppercase tracking-wider text-stone mb-2"
              style={{ fontFamily: "var(--font-body)" }}
            >
              {zh ? "完整規格" : "Full Specification"}
            </p>
            <Link
              href={`${prefix}/spec`}
              className="text-sm text-navy underline decoration-navy/30 hover:decoration-navy"
              style={{ fontFamily: "var(--font-body)" }}
            >
              {t(locale, "spec.read_full")} →
            </Link>
          </nav>
        </aside>

        {/* Main body */}
        <div className="min-w-0 spec-measure-wide">
          {/* §1 Mission */}
          <section id="mission" aria-labelledby="mission-heading">
            <h2 id="mission-heading">
              <a href="#mission" className="section-anchor" aria-hidden="true">
                §1
              </a>
              {t(locale, "charter.mission.h")}
            </h2>
            <p>{t(locale, "charter.mission.body")}</p>
          </section>

          {/* §2 Scope — in/out side-by-side */}
          <section id="scope" aria-labelledby="scope-heading">
            <h2 id="scope-heading">
              <a href="#scope" className="section-anchor" aria-hidden="true">
                §2
              </a>
              {t(locale, "charter.scope.h")}
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 my-5 not-prose">
              {/* In scope */}
              <div
                className="border-l-4 border-navy bg-paper rounded-sm p-5"
                style={{ borderColor: "#0b1d3a" }}
              >
                <p
                  className="text-xs uppercase tracking-wider text-navy-ink font-semibold mb-3"
                  style={{ fontFamily: "var(--font-data)" }}
                >
                  <span
                    aria-hidden="true"
                    className="inline-block mr-2 text-navy"
                  >
                    ✓
                  </span>
                  {zh ? "範圍內 (In scope)" : "In scope"}
                </p>
                <p
                  className="text-graphite leading-relaxed text-sm"
                  style={{ fontFamily: "var(--font-body)" }}
                >
                  {t(locale, "charter.scope.in")}
                </p>
              </div>

              {/* Out of scope */}
              <div className="border-l-4 border-stone bg-paper rounded-sm p-5">
                <p
                  className="text-xs uppercase tracking-wider text-stone font-semibold mb-3"
                  style={{ fontFamily: "var(--font-data)" }}
                >
                  <span aria-hidden="true" className="inline-block mr-2">
                    ✗
                  </span>
                  {zh ? "範圍外 (Out of scope)" : "Out of scope"}
                </p>
                <p
                  className="text-graphite leading-relaxed text-sm"
                  style={{ fontFamily: "var(--font-body)" }}
                >
                  {t(locale, "charter.scope.out")}
                </p>
              </div>
            </div>
          </section>

          {/* §3 Governance */}
          <section id="governance" aria-labelledby="governance-heading">
            <h2 id="governance-heading">
              <a
                href="#governance"
                className="section-anchor"
                aria-hidden="true"
              >
                §3
              </a>
              {t(locale, "charter.governance.h")}
            </h2>
            <p>{t(locale, "charter.governance.body")}</p>
            <p>
              {zh
                ? "完整治理章程、維護者角色定義、決策升級流程,以及 BDFL → TSC 過渡之時程,規範於 "
                : "The full governance charter, maintainer role definitions, decision-escalation flow, and the BDFL → TSC transition timeline are normatively defined in "}
              <a
                href={GOVERNANCE_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="text-navy underline"
              >
                GOVERNANCE.md ↗
              </a>
              {zh ? "。" : "."}
            </p>
          </section>

          {/* §4 IP */}
          <section id="ip" aria-labelledby="ip-heading">
            <h2 id="ip-heading">
              <a href="#ip" className="section-anchor" aria-hidden="true">
                §4
              </a>
              {t(locale, "charter.ip.h")}
            </h2>
            <p>{t(locale, "charter.ip.body")}</p>
          </section>

          {/* §5 Decision-Making — hand-written, two short paragraphs */}
          <section id="decisions" aria-labelledby="decisions-heading">
            <h2 id="decisions-heading">
              <a
                href="#decisions"
                className="section-anchor"
                aria-hidden="true"
              >
                §5
              </a>
              {zh ? "決策機制" : "Decision-Making"}
            </h2>
            <p className="text-sm text-stone" style={{ maxWidth: "42em" }}>
              {zh
                ? "TSC 尚在籌組。下列程序已先行明訂,於 GOVERNANCE.md 之過渡條件滿足後生效;在此之前,由首席維護者 (BDFL) 行使此角色 —— 把規則先寫好,正是為了不讓單一維護者的判斷成為標準的唯一依靠。"
                : "The TSC is being seated. The procedures below are defined ahead of that and take effect once the transition criteria in GOVERNANCE.md are met; until then the lead maintainer (BDFL) acts in this role — the procedures are written first precisely so that no single maintainer's judgment is the standard's only safeguard."}
            </p>
            <p>
              {zh
                ? "規格層級 (spec-level) 之變更走 RFC process:任何人皆可於 repository 上開立 RFC issue 或 PR 描述提案,維護者標示為 RFC 後啟動公開討論窗 — 通常為十四日,複雜提案得延長至三十日。討論結束後,以 consensus 為主、必要時由維護者裁決 (maintainer call),通過後合併。實作層級 (engine-level) 之缺失修正、文件編輯與 rule 新增等不走 RFC process,以一般 PR 流程處理。"
                : "Spec-level changes go through the RFC process: anyone may open an RFC issue or PR describing the proposal, the maintainer labels it as RFC, and a public discussion window opens — typically fourteen days, extended to thirty for complex proposals. After discussion closes, decisions are reached by consensus where possible and by maintainer call where not. Engine-level fixes, documentation edits, and new rule submissions do not require the RFC process and follow the standard PR flow."}
            </p>
            <p>
              {zh
                ? "通過門檻為「rough consensus from active contributors」 — 即在公開討論窗中,實質貢獻者 (定義見 GOVERNANCE.md) 之間未存在持續且未解決之反對意見。在 TSC 正式就任前,BDFL 對所有 RFC 保有最終裁決權 (final call),並承諾以書面形式公開記錄其裁決理由於 RFC 線程中。"
                : "The threshold for adoption is rough consensus from active contributors — no sustained, unresolved objections from substantive contributors (definition in GOVERNANCE.md) within the public discussion window. Until the TSC is seated, the BDFL retains final call on every RFC and commits to publicly recording the rationale for each call inline on the RFC thread."}
            </p>
            <p className="text-sm text-stone mt-4" style={{ maxWidth: "42em" }}>
              {zh ? "完整流程見 " : "Full procedure: "}
              <a
                href={GOVERNANCE_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="text-navy underline"
              >
                GOVERNANCE.md ↗
              </a>
              .
            </p>
          </section>

          {/* §6 TSC Seating Criteria */}
          <section id="tsc" aria-labelledby="tsc-heading">
            <h2 id="tsc-heading">
              <a href="#tsc" className="section-anchor" aria-hidden="true">
                §6
              </a>
              {zh ? "TSC 就任標準" : "TSC Seating Criteria"}
            </h2>
            <p className="text-sm text-stone" style={{ maxWidth: "42em" }}>
              {zh
                ? "TSC 尚在籌組。下列就任標準已先行明訂,於 GOVERNANCE.md 之過渡條件滿足後生效;在此之前,由首席維護者 (BDFL) 行使此角色。標準先於委員會寫定,意味著委員會一旦就任,是依既有規則承接,而非另起爐灶。"
                : "The TSC is being seated. The criteria below are defined ahead of that and take effect once the transition criteria in GOVERNANCE.md are met; until then the lead maintainer (BDFL) acts in this role. Writing the criteria before the committee exists means that, once seated, it inherits a defined process rather than improvising one."}
            </p>
            <p>
              {zh
                ? "下列四項條件 MUST 同時滿足,方得提名為 ATR Technical Steering Committee 成員。提名以對 GOVERNANCE.md 之 pull request 為之,並於 RFC 流程中公開討論。"
                : "All four criteria below MUST be satisfied to be eligible for nomination to the ATR Technical Steering Committee. Nominations are made via pull request to GOVERNANCE.md and are subject to public review under the RFC process."}
            </p>
            <ol>
              {TSC_CRITERIA.map((c, i) => (
                <li key={i}>
                  <strong>
                    {zh ? `條件 ${i + 1}` : `Criterion ${i + 1}`}.
                  </strong>{" "}
                  {zh ? c.zh : c.en}
                </li>
              ))}
            </ol>
            <p className="text-sm text-stone mt-4" style={{ maxWidth: "42em" }}>
              {zh
                ? "TSC 就任不要求所屬組織為 implementer。學術機構、獨立研究者與政府研究員若滿足上述條件,皆得提名。"
                : "TSC seating does not require the candidate's organization to be an implementer. Academic affiliates, independent researchers, and government researchers are eligible if the four criteria are met."}
            </p>
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
