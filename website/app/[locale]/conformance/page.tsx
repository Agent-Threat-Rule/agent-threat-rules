/* ATR Conformance — normative definition of the three conformance levels
 * (L1 Engine / L2 Publisher / L3 Sub-range Authority), the L1 test suite
 * structure, and the self-certification procedure.
 */
import Link from "next/link";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import { locales, type Locale, t } from "@/lib/i18n";
import { getSpecMeta } from "@/lib/spec-meta";
import { DocumentStatus } from "@/components/spec/DocumentStatus";
import { RFC2119 } from "@/components/spec/RFC2119";
import { NormativeBadge } from "@/components/spec/Badges";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { loadSiteStats } from "@/lib/stats";

const REPO = "https://github.com/Agent-Threat-Rule/agent-threat-rules";
const REPO_ROOT = join(process.cwd(), "..");

/** Number of sub-directories under a repo path (one per rule or case); 0 when missing. */
function countDirs(...parts: string[]): number {
  try {
    return readdirSync(join(REPO_ROOT, ...parts), { withFileTypes: true }).filter((d) => d.isDirectory()).length;
  } catch {
    return 0;
  }
}

/** Fixture counts read from disk at build time, so the page never types them in. */
function loadSuiteCounts() {
  const tpRules = countDirs("conformance", "v1.0", "fixtures", "tp");
  const tnRules = countDirs("conformance", "v1.0", "fixtures", "tn");
  return {
    suiteRules: Math.max(tpRules, tnRules),
    edgeCases: countDirs("conformance", "v1.0", "fixtures", "edge"),
    proposedFixtures: countDirs("spec", "conformance", "baseline", "fixtures"),
  };
}

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
    path: "/conformance",
    title: "Conformance",
    description:
      locale === "zh"
        ? "ATR 三個符規等級（L1 Engine、L2 Publisher、L3 Sub-range Authority）的規範定義，加上 L1 測試套件和自我認證程序。"
        : "The normative definition of ATR's three conformance levels (L1 Engine, L2 Publisher, L3 Sub-range Authority), plus the L1 test suite and the self-certification procedure.",
  });
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
  const suite = loadSuiteCounts();
  const ruleCount = loadSiteStats().ruleCount;

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
          {zh ? "符規" : "Conformance"}
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
          {zh
            ? "在台北寫的規則，要能原封不動跑在西雅圖的引擎上。靠的就是符規。三個等級講清楚，一個系統要做到什麼，才能說自己實作了 ATR。測試 fixture 放在 repository 裡，目前還沒有任何引擎宣稱符規。"
            : "A rule written in Taipei should run unchanged on an engine in Seattle. Conformance is what makes that true. Three levels spell out what a system has to do before it can say it implements ATR. The test fixtures are in the repository, and no engine claims conformance yet."}
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
              {zh ? "完整規格" : "Full specification"}
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
                ? "TSC 還沒就任。授權要等 TSC 就任後才會核發。在那之前，由首席維護者（BDFL）擔任這個角色。"
                : "The TSC is not yet seated. Authority is granted once it is. Until then the lead maintainer (BDFL) acts in this role."}
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
            <p>
              {zh ? (
                <>
                  符規的測試材料放在兩個地方，兩邊還沒有統一。今天能跑的是{" "}
                  <a href={`${REPO}/tree/main/conformance/v1.0`} target="_blank" rel="noopener noreferrer" className="text-navy underline">
                    conformance/v1.0/ ↗
                  </a>
                  。裡面有 {suite.suiteRules} 條規則的 true positive 和 true negative fixture，另有 {suite.edgeCases} 個邊界案例。目前有 {ruleCount} 條規則，其餘的還沒有 fixture。這套測試在參考引擎上還沒有全部跑過，沒過的 fixture 逐一列在它的 README。
                </>
              ) : (
                <>
                  Conformance material lives in two places, and they are not reconciled yet. The suite you can run today is{" "}
                  <a href={`${REPO}/tree/main/conformance/v1.0`} target="_blank" rel="noopener noreferrer" className="text-navy underline">
                    conformance/v1.0/ ↗
                  </a>
                  . It has true-positive and true-negative fixtures for {suite.suiteRules} rules, plus {suite.edgeCases} edge cases. There are {ruleCount} rules, so the rest have no fixture yet. The suite does not yet pass end to end on the reference engine. Its README lists each fixture that fails.
                </>
              )}
            </p>
            <pre>
              <code>{`conformance/v1.0/
├── fixtures/
│   ├── tp/<rule_id>/input.yaml + expect.json
│   ├── tn/<rule_id>/input.yaml + expect.json
│   └── edge/<case_id>/input.yaml + expect.json
├── runner/run-conformance.ts
├── README.md
└── SUITE.md

spec/conformance/        (${zh ? "未批准" : "not ratified"})
├── baseline/
├── README.md
└── SIGNING.md`}</code>
            </pre>
            <p className="text-sm text-stone mt-4" style={{ maxWidth: "42em" }}>
              {zh ? (
                <>
                  <a href={`${REPO}/tree/main/spec/conformance`} target="_blank" rel="noopener noreferrer" className="text-navy underline">
                    spec/conformance/ ↗
                  </a>{" "}
                  是提案中的語料庫，它的 README 標明尚未批准，也寫明目前沒有引擎宣稱符合 ATR。裡面目前只有 {suite.proposedFixtures} 個 fixture。conformance/v1.0 的 README 用測試結果來定義 L1 到 L3，跟本頁的三個等級不是同一套。
                </>
              ) : (
                <>
                  <a href={`${REPO}/tree/main/spec/conformance`} target="_blank" rel="noopener noreferrer" className="text-navy underline">
                    spec/conformance/ ↗
                  </a>{" "}
                  is a proposed corpus. Its README marks it as not ratified and says no engine claims ATR conformance. It holds {suite.proposedFixtures} {suite.proposedFixtures === 1 ? "fixture" : "fixtures"} so far. The conformance/v1.0 README defines L1 to L3 by test results, which is not the same as the three levels on this page.
                </>
              )}
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
                ? "TSC 還沒就任。上面這項驗證，等 TSC 就任後由 TSC 負責。在那之前，由首席維護者（BDFL）來做。"
                : "The TSC is not yet seated. Once it is, the TSC does this verification. Until then the lead maintainer (BDFL) does it."}
            </p>
            <p>
              {zh
                ? "通過測試套件之後，實作者到 "
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
                ? " 開一個 pull request，寫上組織名稱、規格版本、整合日期（ISO 8601）、一個查得到的公開證據連結，以及自己宣告的符規等級。維護者的目標是七天內做完 schema 驗證並合併。完整流程和已合併的實作者，見 "
                : ". The entry gives the organization name, the spec version, the integration date (ISO 8601), a public evidence link anyone can verify, and the conformance level they claim. Maintainers aim to validate and merge within seven days. The full procedure and the list of merged implementers are at "}
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
