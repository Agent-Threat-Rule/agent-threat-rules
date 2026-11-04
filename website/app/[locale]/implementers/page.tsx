/* ATR Implementer Report — W3C-style formal table of organizations
 * that have merged ATR into their own public repositories. Self-declared
 * via PR against ADOPTERS.md. A merged PR is not a statement about any
 * vendor's commercial product.
 * Replaces the older /ecosystem marketing layout with a numbered,
 * peer-reviewable report.
 */
import Link from "next/link";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
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
  return pageMetadata({
    locale,
    path: "/implementers",
    title: locale === "zh" ? "實作者報告" : "Implementer Report",
    description:
      locale === "zh"
        ? "已經整合 ATR 的組織。每一筆的憑據，都是公開 repo 裡一個已合併的 pull request。登記方式是自己對 ADOPTERS.md 送 pull request。"
        : "Organizations that have integrated ATR. Each one is backed by a merged pull request in a public repository, and each declared itself with a pull request to ADOPTERS.md.",
  });
}

// Implementer data — kept in sync with the homepage IMPLEMENTERS array.
// This is the canonical formal report; the homepage shows the same set
// in a condensed adoption section.
const IMPLEMENTERS = [
  {
    org: "Microsoft Agent Governance Toolkit",
    role: "L1 Citation",
    version: "3.0.0-alpha",
    date: "2026-06-15",
    refLabel: "PR #3025",
    refUrl: "https://github.com/microsoft/agent-governance-toolkit/pull/3025",
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
          {zh ? "實作者報告" : "Implementer Report"}
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
            ? "這份報告裡的符規等級，照 /spec 定義的 L1、L2、L3 判讀。"
            : "Conformance levels here follow the L1 / L2 / L3 definitions in /spec."}
          {" "}
          <Link href={`${prefix}/spec`} className="text-navy underline">
            {zh ? "看等級怎麼定義" : "See how the levels are defined"} →
          </Link>
        </p>
      </header>

      {/* §1 Current Implementers */}
      <section id="current" aria-labelledby="current-heading" className="spec-measure-wide">
        <h2 id="current-heading">
          <a href="#current" className="section-anchor" aria-hidden="true">
            §1
          </a>
          {zh ? "目前的實作者" : "Current implementers"}
        </h2>
        <p>
          {zh
            ? "下面這些組織整合或引用了 ATR。符規等級欄分兩種。L1 Engine 是 ATR 規則真的在對方自己的偵測引擎裡跑；L1 Citation、L1 Galaxy 是引用，或編進了分類法。Engine 那幾列份量最重：規則在對方維護的引擎裡跑。這幾筆的 PR 是 ATR 維護者開的，由對方的維護者審過後合併。每一筆都連到構成公開採用紀錄的那個已合併 PR 或整合 commit。沒有一筆是私下宣稱的，全都能在 GitHub 上自己查。"
            : "These organizations have integrated or referenced ATR. The Conformance column separates two kinds. L1 Engine means ATR rules actually run inside the organization's own detection engine. L1 Citation and L1 Galaxy mean ATR is referenced, or built into a taxonomy. An Engine row carries the most weight: the rules run in an engine the other organisation maintains. The ATR maintainer opened those pull requests, and that organisation's maintainers reviewed and merged them. Each entry links to the merged pull request or integration commit that makes up the public adoption record. Nothing here is asserted privately, and every row can be checked on GitHub."}
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
              className="border border-fog  p-4 bg-paper"
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
            ? "這份報告從 ADOPTERS.md 自動產生，資料只有這一個來源。維護者不事先審核採用者。PR 符合 schema，附上查得到的公開證據連結，就能合併。"
            : "This report is generated from ADOPTERS.md, the single source of truth. Maintainers do not pre-approve adopters. A PR that fits the schema and links to public evidence anyone can verify is enough to merge."}
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
        <div className="border border-fog  p-4 mt-6 bg-paper" style={{ maxWidth: "42em" }}>
          <p className="text-xs uppercase tracking-[0.18em] text-stone mb-2" style={{ fontFamily: "var(--font-data)" }}>
            {zh ? "送交標準機構的提案（仍開著，不算採用）" : "Standards-body submissions (open, not adoptions)"}
          </p>
          <p className="text-sm text-graphite" style={{ fontFamily: "var(--font-body)" }}>
            {zh
              ? "ATR 把兩份 AI RMF profile 範例以 PR #338 送進 NIST 的 usnistgov/oscal-content。NIST 7 月把自己的 AI RMF catalog 加進 develop 分支，8 月這個 PR 照著它重做，現在還開著，等 NIST 審查。這不是 NIST 採用，也不是 NIST 背書，所以不列在上面的實作者表裡。"
              : "ATR offered two AI RMF profile examples to NIST's usnistgov/oscal-content repo as PR #338. NIST added its own AI RMF catalog to the develop branch in July, and the PR was reworked against it in August. It is still open, waiting for NIST review. This is not a NIST adoption or endorsement, so it is not in the implementers table above."}
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
          {zh ? "怎麼自我認證" : "How to self-certify"}
        </h2>
        <p>
          {zh
            ? "ATR 用的是自我認證：符不符規，要跑出來，不是說出來。實作者在本機跑符規測試套件，再對 ADOPTERS.md 送 PR，附上整合資料。沒有審查委員會，也沒有付費認證。要進這份報告，唯一的門檻是公開通過測試。最精簡的流程是下面三步。"
            : "ATR uses self-certification. Conformance is shown by running the tests, not by saying so. Implementers run the conformance test suite locally, then open a pull request against ADOPTERS.md with their integration metadata. There is no review board and no paid certification. The only way into this report is passing the tests in the open. The minimal procedure has three steps."}
        </p>

        <ol>
          <li>
            <strong>
              {zh
                ? "在本機跑符規測試套件。"
                : "Run the conformance test suite locally."}
            </strong>{" "}
            {zh
              ? "測試套件由 YAML fixture 組成，放在主 repo 的 "
              : "The test suite is a set of YAML fixtures under "}
            <a
              href={CONFORMANCE_FIXTURES_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="text-navy underline"
            >
              <code>spec/conformance/</code> ↗
            </a>
            {zh
              ? "。每個 fixture 把一條規則，和它在一個固定 event 上該有的評估結果配成一對。每個 fixture 都照宣告的結果評估出來，實作就算通過。"
              : ". Each fixture pairs a rule with the result it should give on a fixed event. An implementation passes when every fixture evaluates as declared."}
          </li>
          <li>
            <strong>
              {zh
                ? "對 ADOPTERS.md 送 pull request。"
                : "Open a pull request against ADOPTERS.md."}
            </strong>{" "}
            {zh ? "PR 送到主分支的 " : "Submit against "}
            <a
              href={ADOPTERS_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="text-navy underline"
            >
              ADOPTERS.md ↗
            </a>
            {zh
              ? "。維護者通常七天內做完 schema 驗證並合併。"
              : " on the main branch. Maintainers usually validate the schema and merge within seven days."}
          </li>
          <li>
            <strong>
              {zh ? "PR 裡附上完整的整合資料。" : "Include full integration metadata in the PR."}
            </strong>{" "}
            {zh
              ? "至少要有：組織名稱、整合用的規格版本、整合日期（ISO 8601）、公開查得到的證據連結（PR、commit 或公開文件的網址），以及自己宣告的符規等級（L1 Engine、L2 Publisher 或 L3 Sub-range Authority）。"
              : "At minimum: the organization name, the spec version your integration targets, the integration date (ISO 8601), a public evidence link anyone can check (a PR, a commit or a public documentation URL), and the conformance level you claim (L1 Engine, L2 Publisher or L3 Sub-range Authority)."}
          </li>
        </ol>

        <p className="text-sm text-stone mt-4" style={{ maxWidth: "42em" }}>
          {zh
            ? "TSC 保留權利，隨時可以對任何已發布的自我認證重跑測試套件，確認結果跟宣告的一樣。"
            : "The TSC reserves the right to re-run the test suite against any published self-certification at any time, to check the declared result."}
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
          {zh ? "符規等級一覽" : "Conformance levels at a glance"}
          {" "}
          <InformativeBadge />
        </h2>
        <p>
          {zh
            ? "這一節只是摘要，不具規範效力。正式的規範文字在 /conformance。"
            : "This section is informative. The normative text for each level is at /conformance."}
        </p>

        <h3>{t(locale, "conformance.l1.title")}</h3>
        <p>{t(locale, "conformance.l1.body")}</p>

        <h3>{t(locale, "conformance.l2.title")}</h3>
        <p>{t(locale, "conformance.l2.body")}</p>

        <h3>{t(locale, "conformance.l3.title")}</h3>
        <p>{t(locale, "conformance.l3.body")}</p>

        <p className="text-sm text-stone mt-4" style={{ maxWidth: "42em" }}>
          <Link href={`${prefix}/conformance`} className="text-navy underline">
            {zh ? "看完整的規範文字" : "Read the full normative text"} →
          </Link>
          {zh ? "：" : ": "}
          {zh
            ? "測試套件的結構、自我認證程序，還有符規怎麼驗證。"
            : "the test-suite structure, the self-certification procedure, and how conformance gets verified."}
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
