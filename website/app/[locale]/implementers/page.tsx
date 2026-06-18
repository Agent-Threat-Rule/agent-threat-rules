/* ATR Implementer Report — W3C-style formal table of organizations
 * shipping ATR in production. Self-declared via PR against ADOPTERS.md.
 * Replaces the older /ecosystem marketing layout with a numbered,
 * peer-reviewable report.
 */
import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale, t } from "@/lib/i18n";
import { getSpecMeta } from "@/lib/spec-meta";
import { DocumentStatus } from "@/components/spec/DocumentStatus";
import { InformativeBadge } from "@/components/spec/Badges";

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
    title: "Implementer Report — ATR",
    description:
      locale === "zh"
        ? "已在生產環境部署 ATR 的組織。透過對 ADOPTERS.md registry 的 pull request 自我宣告。"
        : "Organizations that have shipped ATR in production. Self-declared via pull request to the ADOPTERS.md registry.",
  };
}

// Implementer data — kept in sync with the homepage IMPLEMENTERS array.
// This is the canonical formal report; the homepage shows the same set
// in a condensed adoption section.
const IMPLEMENTERS = [
  {
    org: "Microsoft Agent Governance Toolkit",
    role: "L1 Engine",
    version: "3.0.0-alpha",
    date: "2026-04-26",
    refLabel: "PR #1277",
    refUrl: "https://github.com/microsoft/agent-governance-toolkit/pull/1277",
  },
  {
    org: "Cisco AI Defense (skill-scanner)",
    role: "L1 Engine",
    version: "2.2.0",
    date: "2026-04-22",
    refLabel: "PR #99",
    refUrl: "https://github.com/cisco-ai-defense/skill-scanner/pull/99",
  },
  {
    org: "MISP — CIRCL (galaxy)",
    role: "L1 Galaxy",
    version: "2.2.0",
    date: "2026-05-10",
    refLabel: "galaxy #1207",
    refUrl: "https://github.com/MISP/misp-galaxy/pull/1207",
  },
  {
    org: "MISP — CIRCL (taxonomies)",
    role: "L1 Citation",
    version: "2.2.0",
    date: "2026-05-10",
    refLabel: "taxonomies #323",
    refUrl: "https://github.com/MISP/misp-taxonomies/pull/323",
  },
  {
    org: "OWASP A-S-R-H Project",
    role: "L1 Citation",
    version: "2.2.0",
    date: "2026-05-11",
    refLabel: "PR #74",
    refUrl:
      "https://github.com/OWASP/Agent-Security-Regression-Harness/pull/74",
  },
  {
    org: "Gen Digital Sage (Norton / Avast / LifeLock)",
    role: "L1 Engine",
    version: "2.2.0",
    date: "2026-05-11",
    refLabel: "PR #33",
    refUrl: "https://github.com/gendigitalinc/sage/pull/33",
  },
] as const;

const ADOPTERS_URL =
  "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ADOPTERS.md";
const CONFORMANCE_FIXTURES_URL =
  "https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/main/spec/conformance";

export default async function ImplementersPage({
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
          {zh ? "實作者報告 — Implementer Report" : "Implementer Report"}
        </p>
        <h1
          className="text-3xl md:text-5xl font-bold text-navy-ink mb-4 leading-[1.1]"
          style={{
            fontFamily: "var(--font-display)",
            letterSpacing: "-0.02em",
          }}
        >
          {t(locale, "implementers.title")}
        </h1>
        <p
          className="text-base md:text-xl text-graphite leading-snug mb-6"
          style={{
            fontFamily: "var(--font-body)",
            maxWidth: "42em",
          }}
        >
          {t(locale, "implementers.subtitle")}
        </p>
        <DocumentStatus locale={locale} />
        <p
          className="text-sm text-stone mt-5"
          style={{ maxWidth: "42em", fontFamily: "var(--font-body)" }}
        >
          {zh
            ? "本報告中的「符規等級 (Conformance)」係依 /spec 中定義之 L1 / L2 / L3 等級判讀。"
            : "Conformance levels in this report follow the L1 / L2 / L3 definitions established in /spec."}
          {" "}
          <Link href={`${prefix}/spec`} className="text-navy underline">
            {zh ? "查看符規等級定義" : "View conformance level definitions"} →
          </Link>
        </p>
      </header>

      {/* §1 Current Implementers */}
      <section id="current" aria-labelledby="current-heading" className="spec-measure-wide">
        <h2 id="current-heading">
          <a href="#current" className="section-anchor" aria-hidden="true">
            §1
          </a>
          {zh ? "目前實作者" : "Current Implementers"}
        </h2>
        <p>
          {zh
            ? "下表列出已整合或引用 ATR 的組織。符規等級欄位區分 L1 Engine(在自家偵測引擎中實際執行 ATR 規則)與 L1 Citation / L1 Galaxy(引用或編入分類法)。Engine 一行的份量最重——它代表又有一個獨立團隊只憑規格就把這個格式實作出來,而且在生產環境裡跑得起來。每一筆紀錄連結至構成公開採用證據的合併 pull request 或整合 commit;沒有任何一筆是私下宣稱的,全部可在 GitHub 上自行驗證。"
            : "The following organizations have integrated or referenced ATR. The Conformance column distinguishes L1 Engine (ATR rules actually running inside the organization's own detection engine) from L1 Citation / L1 Galaxy (referenced or incorporated into a taxonomy). An Engine row carries the most weight — it means another independent team implemented the format from the spec alone and ran it in production. Each entry links to the merged pull request or integration commit that constitutes the public adoption record; nothing here is asserted privately — every row is verifiable on GitHub."}
        </p>

        {/* Desktop / tablet table */}
        <div className="hidden md:block overflow-x-auto -mx-2 my-5">
          <table>
            <thead>
              <tr>
                <th>{t(locale, "implementers.col.org")}</th>
                <th>{t(locale, "implementers.col.role")}</th>
                <th>{t(locale, "implementers.col.version")}</th>
                <th>{t(locale, "implementers.col.date")}</th>
                <th>{t(locale, "implementers.col.ref")}</th>
              </tr>
            </thead>
            <tbody>
              {IMPLEMENTERS.map((imp) => (
                <tr key={imp.refUrl}>
                  <td className="font-semibold text-navy-ink">{imp.org}</td>
                  <td className="font-data text-xs tnum">{imp.role}</td>
                  <td className="font-data text-xs tnum">{imp.version}</td>
                  <td className="font-data text-xs tnum">{imp.date}</td>
                  <td>
                    <a
                      href={imp.refUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-navy underline"
                    >
                      {imp.refLabel} ↗
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Mobile stacked cards */}
        <div className="md:hidden my-5 space-y-3">
          {IMPLEMENTERS.map((imp) => (
            <div
              key={imp.refUrl}
              className="border border-fog rounded-sm p-4 bg-paper"
            >
              <p
                className="font-semibold text-navy-ink mb-2"
                style={{ fontFamily: "var(--font-body)" }}
              >
                {imp.org}
              </p>
              <dl
                className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs tnum text-graphite mb-2"
                style={{ fontFamily: "var(--font-data)" }}
              >
                <dt className="text-stone">
                  {t(locale, "implementers.col.role")}
                </dt>
                <dd>{imp.role}</dd>
                <dt className="text-stone">
                  {t(locale, "implementers.col.version")}
                </dt>
                <dd>{imp.version}</dd>
                <dt className="text-stone">
                  {t(locale, "implementers.col.date")}
                </dt>
                <dd>{imp.date}</dd>
              </dl>
              <a
                href={imp.refUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-navy underline text-sm inline-flex items-center min-h-[44px]"
              >
                {imp.refLabel} ↗
              </a>
            </div>
          ))}
        </div>

        <p className="text-sm text-stone mt-4" style={{ maxWidth: "42em" }}>
          {zh
            ? "本報告由 ADOPTERS.md 為單一可信來源 (single source of truth) 自動生成。維護者不預先審核採用者 — 只要 PR 符合 schema、附上可驗證的公開證據連結即可合併。"
            : "This report is generated from ADOPTERS.md as the single source of truth. Maintainers do not pre-approve adopters — a schema-conforming PR with a verifiable public evidence link is sufficient for merge."}
          {" "}
          <a
            href={ADOPTERS_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="text-navy underline"
          >
            ADOPTERS.md ↗
          </a>
        </p>

        {/* Separate aside: standards-body submissions in review — NOT adoptions */}
        <div className="border border-fog rounded-sm p-4 mt-6 bg-paper" style={{ maxWidth: "42em" }}>
          <p className="text-xs uppercase tracking-[0.18em] text-stone mb-2" style={{ fontFamily: "var(--font-data)" }}>
            {zh ? "標準機構 submission(審查中,非採用)" : "Standards-body submissions (in review, not adoptions)"}
          </p>
          <p className="text-sm text-graphite" style={{ fontFamily: "var(--font-body)" }}>
            {zh
              ? "ATR 把 AI RMF 社群版 OSCAL catalog 提交給 NIST 官方 usnistgov/oscal-content,目前 submission 審查中(NIST OSCAL maintainer 開了 collaboration branch #338)。這不是 NIST 採用、不是 NIST 背書,因此不列入上方生產實作者表。"
              : "ATR submitted its community AI RMF OSCAL catalog to NIST's official usnistgov/oscal-content repo; the submission is in review (the NIST OSCAL maintainer opened collaboration branch #338). This is not a NIST adoption or endorsement, so it is not listed in the implementers table above."}
            {" "}
            <a
              href="https://github.com/usnistgov/oscal-content/pull/338"
              target="_blank"
              rel="noopener noreferrer"
              className="text-navy underline"
            >
              #338 ↗
            </a>
          </p>
        </div>
      </section>

      {/* §2 How to self-certify */}
      <section id="self-certify" aria-labelledby="self-certify-heading" className="spec-measure-wide">
        <h2 id="self-certify-heading">
          <a href="#self-certify" className="section-anchor" aria-hidden="true">
            §2
          </a>
          {zh ? "如何自我認證" : "How to self-certify"}
        </h2>
        <p>
          {zh
            ? "ATR 採用 self-certification 模型:符規靠跑出來,不靠宣稱。實作者於本地執行 conformance 測試套件,再對 ADOPTERS.md 提出 PR 加入整合 metadata。沒有審查委員會、沒有付費認證——加入這份報告唯一的門檻,就是公開地通過測試。下列三步驟為 self-certification 的最小流程。"
            : "ATR follows a self-certification model: conformance is demonstrated, not asserted. Implementers run the conformance test suite locally, then open a pull request against ADOPTERS.md with their integration metadata. There is no review board and no paid certification — the only price of admission to this report is passing the tests in the open. The minimal self-certification procedure is three steps."}
        </p>

        <ol>
          <li>
            <strong>
              {zh
                ? "在本地執行 conformance 測試套件"
                : "Run the conformance test suite locally"}
              .
            </strong>{" "}
            {zh
              ? "Test suite 由 YAML fixtures 組成,儲存於主 repository 的 "
              : "The test suite consists of YAML fixtures stored under "}
            <a
              href={CONFORMANCE_FIXTURES_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="text-navy underline"
            >
              <code>spec/conformance/</code> ↗
            </a>
            {zh
              ? "。每個 fixture 配對一條規則與其在固定事件 (event) 上的預期評估結果。實作通過的條件是:每個 fixture 都如宣告般評估。"
              : ". Each fixture pairs a rule with its expected evaluation outcome on a fixed event. An implementation passes if every fixture evaluates as declared."}
          </li>
          <li>
            <strong>
              {zh
                ? "對 ADOPTERS.md 提交 pull request"
                : "Open a pull request against ADOPTERS.md"}
              .
            </strong>{" "}
            {zh ? "提交目標為 " : "Submit against "}
            <a
              href={ADOPTERS_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="text-navy underline"
            >
              ADOPTERS.md ↗
            </a>
            {zh
              ? " 於主分支。維護者通常於 7 日內完成 schema 驗證並合併。"
              : " on the main branch. Maintainers typically validate the schema and merge within seven days."}
          </li>
          <li>
            <strong>
              {zh ? "於 PR 中包含完整整合 metadata" : "Include full integration metadata in the PR"}
              .
            </strong>{" "}
            {zh
              ? "至少包含:組織名稱、整合所使用之規格版本、整合日期 (ISO 8601)、公開可驗證之證據連結 (PR、commit、或對外文件 URL),以及自我宣告之符規等級 (L1 Engine / L2 Publisher / L3 Sub-range Authority)。"
              : "At minimum: organization name, the spec version your integration targets, the integration date (ISO 8601), a publicly verifiable evidence link (PR, commit, or public documentation URL), and a self-declared conformance level (L1 Engine / L2 Publisher / L3 Sub-range Authority)."}
          </li>
        </ol>

        <p className="text-sm text-stone mt-4" style={{ maxWidth: "42em" }}>
          {zh
            ? "TSC 保留隨時對任一已發布之 self-certification 重跑測試套件以驗證其結果之權利。"
            : "The TSC reserves the right to re-run the test suite against any published self-certification at any time to verify the declared outcome."}
        </p>
      </section>

      {/* §3 Conformance levels at a glance — informative summary */}
      <section
        id="levels"
        aria-labelledby="levels-heading"
        className="spec-measure-wide"
      >
        <h2 id="levels-heading">
          <a href="#levels" className="section-anchor" aria-hidden="true">
            §3
          </a>
          {zh ? "符規等級摘要" : "Conformance levels at a glance"}
          {" "}
          <InformativeBadge />
        </h2>
        <p>
          {zh
            ? "本節為非規範性 (informative) 摘要。正式之規範性文字請見 /conformance。"
            : "This section is informative. The normative text for each level lives at /conformance."}
        </p>

        <h3>{t(locale, "conformance.l1.title")}</h3>
        <p>{t(locale, "conformance.l1.body")}</p>

        <h3>{t(locale, "conformance.l2.title")}</h3>
        <p>{t(locale, "conformance.l2.body")}</p>

        <h3>{t(locale, "conformance.l3.title")}</h3>
        <p>{t(locale, "conformance.l3.body")}</p>

        <p className="text-sm text-stone mt-4" style={{ maxWidth: "42em" }}>
          <Link href={`${prefix}/conformance`} className="text-navy underline">
            {zh ? "查看完整規範性文字" : "Read the full normative text"} →
          </Link>
          {" — "}
          {zh
            ? "包含測試套件結構、自我認證程序、與符規驗證流程。"
            : "Includes test-suite structure, self-certification procedure, and conformance verification flow."}
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
    </main>
  );
}
