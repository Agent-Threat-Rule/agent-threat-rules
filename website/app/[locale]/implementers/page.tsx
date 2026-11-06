/* ATR Implementer Report — formal table of pull requests that other
 * organizations merged into their own public repositories. Every one was
 * opened by the ATR maintainer; none is a self-certification or a
 * conformance claim. A merged PR is not a statement about any vendor's
 * commercial product.
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
        ? "別的組織合併進自家公開 repo 的 ATR pull request。每一筆都由 ATR 維護者開出，都不是符規宣告。"
        : "ATR pull requests that other organizations merged into their own public repositories. The ATR maintainer opened each one, and none is a conformance claim.",
  });
}

// Merged pull requests in other organizations' public repositories.
// Checked with `gh pr view` on 2026-11-04: every PR here was opened by the ATR
// maintainer (eeee2345) and merged by that project's maintainer on the date
// shown (UTC). OWASP #74: the four scenario files do not mention ATR.
// Cisco: skill-scanner #289 comment by vineethsai7, 2026-11-02.
// None of these is a conformance claim, so the table has no level column.
const IMPLEMENTERS = [
  {
    org: "Microsoft Agent Governance Toolkit",
    what: {
      en: "Example directory: an adapter that runs ATR rules through the ACS annotator",
      zh: "範例目錄：把 ATR 規則接進 ACS annotator 執行的 adapter",
    },
    date: "2026-06-15",
    mergedBy: "imran-siddique",
    refLabel: "PR #3025",
    refUrl: "https://github.com/microsoft/agent-governance-toolkit/pull/3025",
  },
  {
    org: "Cisco AI Defense (skill-scanner)",
    what: {
      en: "ATR rule pack. On 2026-11-02 a maintainer wrote that they will likely remove ATR because the false-positive rate is too high. A report-only pack (#289) is open.",
      zh: "ATR 規則包。2026-11-02 對方維護者留言，說誤報率太高，大概會把 ATR 移除。改成只回報的規則包（#289）還在審。",
    },
    date: "2026-04-22",
    mergedBy: "vineethsai7",
    refLabel: "PR #99",
    refUrl: "https://github.com/cisco-ai-defense/skill-scanner/pull/99",
  },
  {
    org: "MISP (CIRCL), galaxy",
    what: { en: "ATR galaxy and cluster", zh: "ATR 的 galaxy 和 cluster" },
    date: "2026-05-10",
    mergedBy: "adulau",
    refLabel: "galaxy #1207",
    refUrl: "https://github.com/MISP/misp-galaxy/pull/1207",
  },
  {
    org: "MISP (CIRCL), taxonomies",
    what: { en: "agent-threat-rules taxonomy", zh: "agent-threat-rules 分類法" },
    date: "2026-05-10",
    mergedBy: "adulau",
    refLabel: "taxonomies #323",
    refUrl: "https://github.com/MISP/misp-taxonomies/pull/323",
  },
  {
    org: "OWASP Agent Security Regression Harness",
    what: {
      en: "4 regression scenarios derived from ATR rules. The scenario files do not name ATR.",
      zh: "4 個從 ATR 規則改寫的回歸情境。情境檔裡沒有標註 ATR。",
    },
    date: "2026-05-11",
    mergedBy: "mertsatilmaz",
    refLabel: "PR #74",
    refUrl:
      "https://github.com/OWASP/Agent-Security-Regression-Harness/pull/74",
  },
  {
    org: "Gen Digital Sage",
    what: {
      en: "Agent-layer threat patterns in threats/agent-layer.yaml",
      zh: "threats/agent-layer.yaml 裡的 agent 層威脅 pattern",
    },
    date: "2026-05-11",
    mergedBy: "vaclavbelak",
    refLabel: "PR #33",
    refUrl: "https://github.com/gendigitalinc/sage/pull/33",
  },
] as const;

const ADOPTERS_URL =
  "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ADOPTERS.md";
const CONFORMANCE_FIXTURES_URL =
  "https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/main/conformance/v1.0";

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
      className="spec-document w-full px-6 md:px-14 pt-24 md:pt-28 pb-24"
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
          {zh
            ? "一份規格，要有不只一個引擎用同樣的方式實作出來，才算數。ATR 還沒有這種證據。這份報告列的是別的專案合併的 pull request，全部由 ATR 維護者開出。它們說明 ATR 規則去了哪裡，不代表有人光靠規格就做出了引擎。"
            : "A specification counts once more than one engine implements it the same way. ATR does not have that evidence yet. This report lists pull requests that other projects merged, all opened by the ATR maintainer. They show where ATR rules ended up. They do not show that anyone built an engine from the spec alone."}
        </p>
        <DocumentStatus locale={locale} />
        <p
          className="text-sm text-stone mt-5"
          style={{ maxWidth: "42em", fontFamily: "var(--font-body)" }}
        >
          {zh
            ? "這份報告裡沒有任何一列宣告符規等級。"
            : "No row in this report claims a conformance level."}
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
            ? "每一列都是合併進別的組織公開 repo 的一個 pull request。這些 PR 全都是 ATR 維護者開的，再由對方專案的維護者審過後合併。表裡沒有任何實作跑過符規測試套件，所以這些都不是符規宣告。PR 合併過，表示當時整合過，不代表今天還在用。每一列都能在 GitHub 上自己查。"
            : "Each row is a pull request merged into another organization's public repository. The ATR maintainer opened every one of them, and that project's maintainers reviewed and merged it. No implementation here has run the conformance suite, so none of these is a conformance claim. A merged pull request shows the integration happened. It does not show it is still in use. Every row can be checked on GitHub."}
        </p>

        {/* Desktop / tablet table */}
        <div className="hidden md:block overflow-x-auto -mx-2 my-5">
          <table>
            <thead>
              <tr>
                <th>{t(locale, "implementers.col.org")}</th>
                <th>{zh ? "合併了什麼" : "What was merged"}</th>
                <th>{zh ? "誰開的 PR" : "Opened by"}</th>
                <th>{zh ? "合併（UTC）" : "Merged (UTC)"}</th>
                <th>{t(locale, "implementers.col.ref")}</th>
              </tr>
            </thead>
            <tbody>
              {IMPLEMENTERS.map((imp) => (
                <tr key={imp.refUrl}>
                  <td className="font-semibold text-navy-ink">{imp.org}</td>
                  <td className="text-sm">{zh ? imp.what.zh : imp.what.en}</td>
                  <td className="text-xs">{zh ? "ATR 維護者" : "ATR maintainer"}</td>
                  <td className="font-data text-xs tnum">
                    {imp.date}
                    <br />
                    {zh ? "由 " : "by "}@{imp.mergedBy}
                  </td>
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
                  {zh ? "合併了什麼" : "What was merged"}
                </dt>
                <dd>{zh ? imp.what.zh : imp.what.en}</dd>
                <dt className="text-stone">
                  {zh ? "誰開的 PR" : "Opened by"}
                </dt>
                <dd>{zh ? "ATR 維護者" : "ATR maintainer"}</dd>
                <dt className="text-stone">
                  {zh ? "合併（UTC）" : "Merged (UTC)"}
                </dt>
                <dd>{imp.date} @{imp.mergedBy}</dd>
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
            ? "這張表是手動維護的。完整的採用名單在 ADOPTERS.md。維護者不事先審核採用者，PR 符合 schema，附上查得到的公開證據連結，就能合併。"
            : "This table is kept by hand. The full list of adopters is ADOPTERS.md. Maintainers do not pre-approve adopters. A PR that fits the schema and links to public evidence anyone can verify is enough to merge."}
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
            ? "ATR 用的是自我認證：符不符規，要跑出來，不是說出來。實作者在本機跑符規測試套件，再對 ADOPTERS.md 送 PR，附上整合資料。沒有審查委員會，也沒有付費認證。到目前為止，還沒有人用這個方式自我認證。最精簡的流程是下面三步。"
            : "ATR uses self-certification. Conformance is shown by running the tests, not by saying so. Implementers run the conformance test suite locally, then open a pull request against ADOPTERS.md with their integration metadata. There is no review board and no paid certification. No one has self-certified this way yet. The minimal procedure has three steps."}
        </p>

        <ol>
          <li>
            <strong>
              {zh
                ? "在本機跑符規測試套件。"
                : "Run the conformance test suite locally."}
            </strong>{" "}
            {zh
              ? "測試套件放在主 repo 的 "
              : "The test suite is under "}
            <a
              href={CONFORMANCE_FIXTURES_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="text-navy underline"
            >
              <code>conformance/v1.0/</code> ↗
            </a>
            {zh
              ? "。每個 fixture 是一個以規則編號命名的資料夾，input.yaml 是輸入，expect.json 是預期結果。每個 fixture 都照預期跑出來，實作就算通過。參考引擎目前還沒全部通過，沒過的列在套件的 README。"
              : ". Each fixture is a directory named after the rule, with the input in input.yaml and the expected result in expect.json. An implementation passes when every fixture comes out as expected. The reference engine does not pass all of them yet; the suite's README lists the ones that fail."}
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
