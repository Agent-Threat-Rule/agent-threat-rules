/* ATR Conformance — normative definition of the three conformance levels
 * (L1 Engine / L2 Publisher / L3 Sub-range Authority), the L1 test suite
 * structure, and the self-certification procedure.
 */
import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale, t } from "@/lib/i18n";
import { getSpecMeta } from "@/lib/spec-meta";
import { DocumentStatus } from "@/components/spec/DocumentStatus";
import { RFC2119 } from "@/components/spec/RFC2119";
import { NormativeBadge } from "@/components/spec/Badges";

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
    title: "Conformance — ATR",
    description:
      locale === "zh"
        ? "ATR 的三個符規等級 (L1 Engine / L2 Publisher / L3 Sub-range Authority) 的規範性定義,以及 L1 測試套件與自我認證程序。"
        : "Normative definition of the three ATR conformance levels (L1 Engine / L2 Publisher / L3 Sub-range Authority), the L1 test suite, and the self-certification procedure.",
  };
}

const ADOPTERS_URL =
  "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ADOPTERS.md";

export default async function ConformancePage({
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
          {zh ? "符規 — Conformance" : "Conformance"}
        </p>
        <h1
          className="text-3xl md:text-5xl font-bold text-navy-ink mb-4 leading-[1.1]"
          style={{
            fontFamily: "var(--font-display)",
            letterSpacing: "-0.02em",
          }}
        >
          {t(locale, "conformance.title")}
        </h1>
        <p
          className="text-base md:text-xl text-graphite leading-snug mb-6"
          style={{ fontFamily: "var(--font-body)", maxWidth: "42em" }}
        >
          {t(locale, "conformance.subtitle")}
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
                <a href="#l1">
                  <span className="toc-section-num">§1</span>
                  {t(locale, "conformance.l1.title")}
                </a>
              </li>
              <li>
                <a href="#l2">
                  <span className="toc-section-num">§2</span>
                  {t(locale, "conformance.l2.title")}
                </a>
              </li>
              <li>
                <a href="#l3">
                  <span className="toc-section-num">§3</span>
                  {t(locale, "conformance.l3.title")}
                </a>
              </li>
              <li>
                <a href="#testsuite">
                  <span className="toc-section-num">§4</span>
                  {t(locale, "conformance.testsuite.h")}
                </a>
              </li>
              <li>
                <a href="#self">
                  <span className="toc-section-num">§5</span>
                  {t(locale, "conformance.self.h")}
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
          {/* RFC 2119 callout between header and §1 */}
          <RFC2119 locale={locale} />

          {/* §1 L1 Engine */}
          <section id="l1" aria-labelledby="l1-heading">
            <h2 id="l1-heading">
              <a href="#l1" className="section-anchor" aria-hidden="true">
                §1
              </a>
              {t(locale, "conformance.l1.title")} <NormativeBadge />
            </h2>
            <p>{t(locale, "conformance.l1.body")}</p>
          </section>

          {/* §2 L2 Publisher */}
          <section id="l2" aria-labelledby="l2-heading">
            <h2 id="l2-heading">
              <a href="#l2" className="section-anchor" aria-hidden="true">
                §2
              </a>
              {t(locale, "conformance.l2.title")} <NormativeBadge />
            </h2>
            <p>{t(locale, "conformance.l2.body")}</p>
          </section>

          {/* §3 L3 Sub-range Authority */}
          <section id="l3" aria-labelledby="l3-heading">
            <h2 id="l3-heading">
              <a href="#l3" className="section-anchor" aria-hidden="true">
                §3
              </a>
              {t(locale, "conformance.l3.title")} <NormativeBadge />
            </h2>
            <p>{t(locale, "conformance.l3.body")}</p>
            <p className="text-sm text-stone mt-3" style={{ maxWidth: "42em" }}>
              {zh
                ? "TSC 尚未就任。授權之核發於 TSC 就任後生效;在此之前,由首席維護者 (BDFL) 行使此角色。"
                : "The TSC is not yet seated. Authority is granted once the TSC is seated; until then the lead maintainer (BDFL) acts in this role."}
            </p>
          </section>

          {/* §4 Test Suite */}
          <section id="testsuite" aria-labelledby="testsuite-heading">
            <h2 id="testsuite-heading">
              <a
                href="#testsuite"
                className="section-anchor"
                aria-hidden="true"
              >
                §4
              </a>
              {t(locale, "conformance.testsuite.h")}
            </h2>
            <p>{t(locale, "conformance.testsuite.body")}</p>
            <pre>
              <code>{`spec/
└── conformance/
    ├── L1/
    │   ├── 001-basic-match.yaml
    │   ├── 002-scan-target-mismatch.yaml
    │   ├── 003-status-draft-skip.yaml
    │   └── …
    ├── L2/
    │   └── …
    └── README.md`}</code>
            </pre>
            <p className="text-sm text-stone mt-4" style={{ maxWidth: "42em" }}>
              {zh
                ? "每個 fixture 為一份 YAML 檔,內含目標規則、輸入 event、與預期評估結果三段。Engine 實作者於本地 clone repo、跑測試套件、產出 pass/fail 報告。"
                : "Each fixture is a YAML file with three blocks: the target rule, the input event, and the expected evaluation outcome. Engine implementers clone the repo, run the test suite locally, and produce a pass/fail report."}
            </p>
          </section>

          {/* §5 Self-Certification */}
          <section id="self" aria-labelledby="self-heading">
            <h2 id="self-heading">
              <a href="#self" className="section-anchor" aria-hidden="true">
                §5
              </a>
              {t(locale, "conformance.self.h")}
            </h2>
            <p>{t(locale, "conformance.self.body")}</p>
            <p className="text-sm text-stone mt-3" style={{ maxWidth: "42em" }}>
              {zh
                ? "TSC 尚未就任。上述驗證職責於 TSC 就任後由 TSC 行使;在此之前,由首席維護者 (BDFL) 行使此角色。"
                : "The TSC is not yet seated. This verification role is exercised by the TSC once it is seated; until then the lead maintainer (BDFL) acts in this role."}
            </p>
            <p>
              {zh
                ? "通過測試套件後,實作者於 "
                : "After passing the test suite, implementers open a pull request against "}
              <a
                href={ADOPTERS_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="text-navy underline"
              >
                ADOPTERS.md ↗
              </a>
              {zh
                ? " 開立 pull request,內容包含組織名稱、規格版本、整合日期 (ISO 8601)、可驗證之公開證據連結、自我宣告之符規等級。維護者以七日內完成 schema 驗證並合併為目標。完整流程與已合併之實作者見 "
                : ", including organization name, spec version, integration date (ISO 8601), a verifiable public evidence link, and a self-declared conformance level. Maintainers aim to validate and merge within seven days. The full procedure and the list of merged implementers live at "}
              <Link href={`${prefix}/implementers`} className="text-navy underline">
                /implementers
              </Link>
              {zh ? "。" : "."}
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
