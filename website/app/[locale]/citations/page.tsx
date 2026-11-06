/* ATR Citation — formal citation block (BibTeX / APA / IEEE / Chicago)
 * plus related identifiers (DOI, Zenodo, repository, npm, PyPI). For
 * citing ATR in academic work, security research, and institutional
 * documentation.
 */
import Link from "next/link";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import { locales, type Locale, t } from "@/lib/i18n";
import { getSpecMeta } from "@/lib/spec-meta";
import { loadVersionLabels } from "@/lib/versions";
import { DocumentStatus } from "@/components/spec/DocumentStatus";
import { CitationBlock } from "@/components/spec/CitationBlock";
import Phrased from "@/components/Phrased";

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
    path: "/citations",
    title: "Citation",
    description:
      locale === "zh"
        ? "ATR 的引用格式（BibTeX、APA、IEEE、Chicago）和相關識別碼。"
        : "Citation formats (BibTeX, APA, IEEE, Chicago) and related identifiers for citing ATR.",
  });
}

export default async function CitationsPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: l } = await params;
  const locale = (locales.includes(l as Locale) ? l : "en") as Locale;
  const meta = getSpecMeta();
  const versions = await loadVersionLabels();
  const prefix = `/${locale}`;
  const zh = locale === "zh";

  const doiUrl = `https://doi.org/${meta.doi}`;
  const zenodoUrl = `https://zenodo.org/doi/${meta.doi}`;
  const npmPackage = "agent-threat-rules";
  const npmUrl = `https://www.npmjs.com/package/${npmPackage}`;
  const pypiPackage = "pyatr";
  const pypiUrl = `https://pypi.org/project/${pypiPackage}/`;

  return (
    <Phrased>
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
          {zh ? "引用" : "Citation"}
        </p>
        <h1
          className="text-[32px] md:text-[48px] font-bold text-navy-ink mb-4 leading-[1.1]"
          style={{
            fontFamily: "var(--font-display)",
            letterSpacing: "-0.02em",
          }}
        >
          {t(locale, "citations.title")}
        </h1>
        <p
          className="text-base md:text-xl text-graphite leading-snug mb-6"
          style={{ fontFamily: "var(--font-body)", maxWidth: "42em" }}
        >
          {t(locale, "citations.subtitle")}
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
                <a href="#when">
                  <span className="toc-section-num">§1</span>
                  {zh ? "何時引用 ATR" : "When to cite ATR"}
                </a>
              </li>
              <li>
                <a href="#formats">
                  <span className="toc-section-num">§2</span>
                  {zh ? "引用格式" : "Citation Formats"}
                </a>
              </li>
              <li>
                <a href="#ids">
                  <span className="toc-section-num">§3</span>
                  {zh ? "相關識別碼" : "Related Identifiers"}
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
          {/* §1 When to cite */}
          <section id="when" aria-labelledby="when-heading">
            <h2 id="when-heading">
              <a href="#when" className="section-anchor" aria-hidden="true">
                §1
              </a>
              {zh ? "何時引用 ATR" : "When to cite ATR"}
            </h2>
            <p>
              {zh
                ? "網址會搬，專案會改名，網頁會 404。引用是把一個會變的東西，釘成一個不會變的錨點。所以在下面這些場合，請引用這份規格，不要只貼網址。引用的版本，以撰寫當下 /spec 上的最新版為準，並在引用裡寫出版本號。版本會往前走，你引用的那一版永遠找得回來。"
                : "URLs move, projects get renamed, pages 404. A citation pins something that changes to an anchor that does not. So in the contexts below, cite this specification instead of only linking to a URL. Cite the latest version on /spec at the time you write, and include its version number. Versions move forward. The one you cited stays reachable."}
            </p>
            <ul>
              <li>
                <strong>
                  {zh ? "學術出版品" : "Academic publications"}.
                </strong>{" "}
                {zh
                  ? "會議論文、期刊文章、學位論文，提到 ATR 規則格式、ATR engine、ATR benchmark 結果，或拿 ATR 當 baseline 來比較。"
                  : "Conference papers, journal articles and theses that reference the ATR rule format, an ATR engine or ATR benchmark results, or use ATR as a baseline for comparison."}
              </li>
              <li>
                <strong>
                  {zh ? "安全研究與技術報告" : "Security research and technical reports"}.
                </strong>{" "}
                {zh
                  ? "外部報告重用 ATR 規則、引用 ATR 的偵測覆蓋數字，或在威脅情報文件裡用 ATR-YYYY-NNNNN 識別碼指稱某個威脅。"
                  : "External reports that reuse ATR rules, cite ATR coverage figures, or reference specific threats by their ATR-YYYY-NNNNN identifier in threat-intelligence documents."}
              </li>
              <li>
                <strong>
                  {zh ? "機構文件" : "Institutional documentation"}.
                </strong>{" "}
                {zh
                  ? "標準組織、研究機構或政府機關的出版品、白皮書和建議書，把 ATR 列為參考標準或互通格式。"
                  : "Standards-body publications, research-institute white papers, and government recommendations that list ATR as a reference standard or interoperability format."}
              </li>
              <li>
                <strong>
                  {zh ? "主權 AI 的合規與符規申報" : "Sovereign-AI compliance and conformance filings"}.
                </strong>{" "}
                {zh
                  ? "交給主管機關的 AI 風險管理或 agent 安全文件，引用 ATR 作為偵測規則層的依據，或用 L1、L2、L3 符規等級，宣告組織把 ATR 整合到哪一層。"
                  : "AI risk-management and agent-security filings to regulators that cite ATR as the basis for the detection-rule layer, or declare an organization's ATR integration level as L1, L2 or L3 conformance."}
              </li>
            </ul>
          </section>

          {/* §2 Citation Formats */}
          <section id="formats" aria-labelledby="formats-heading">
            <h2 id="formats-heading">
              <a href="#formats" className="section-anchor" aria-hidden="true">
                §2
              </a>
              {zh ? "引用格式" : "Citation Formats"}
            </h2>
            <p>
              {zh
                ? "寫工程論文的、寫政策白皮書的、寫合規申報的，碰到的是同一層 agent 威脅。所以同一個標準，要在四種引用體例裡都讀得通。BibTeX 是 LaTeX 原生的格式，APA 是社會科學的標準，IEEE 是工程學科的標準，Chicago 常見於人文學科。照目標期刊或機構的要求選一種。四種指向的都是同一份規格、同一個 DOI。"
                : "An engineer writing a paper, an analyst writing a policy white paper and an officer filing for compliance are all describing the same layer of agent threats. So the same standard has to read cleanly in four citation styles. BibTeX is native to LaTeX. APA is the social-sciences standard. IEEE is the engineering standard. Chicago is common in the humanities. Pick the one your target journal or institution asks for. All four point to the same specification and the same DOI."}
            </p>
            <CitationBlock
              locale={locale}
              meta={{
                // Cited as software ([Computer software] in APA), so the
                // version is the npm release, not the written spec's.
                version: versions.npm,
                lastModified: meta.lastModified,
                canonicalUrl: meta.canonicalUrl,
                doi: meta.doi,
                editorName: meta.editors[0].name,
              }}
            />
          </section>

          {/* §3 Related Identifiers */}
          <section id="ids" aria-labelledby="ids-heading">
            <h2 id="ids-heading">
              <a href="#ids" className="section-anchor" aria-hidden="true">
                §3
              </a>
              {zh ? "相關識別碼" : "Related Identifiers"}
            </h2>
            <p>
              {zh
                ? "一個標準有很多對外的入口，但錨點只有一個。下面這些識別碼，指向這份規格的等效或衍生發布物。DOI 就是那個錨點，也是學術引用的規範性錨點。npm 每出一版、GitHub 每個分支都在動，DOI 指向的那份 snapshot 不會變。其他的，像 GitHub、npm、PyPI、Zenodo、canonical URL，是給實作者用的散佈形式。它們是錨點周圍的鷹架，不是錨點本身。"
                : "A standard has many doors facing the world but only one anchor. The identifiers below point to equivalent or derived distributions of this specification. The DOI is the anchor, the normative one for academic citation. Every npm version and every GitHub branch keeps moving. The snapshot the DOI points at never changes. The rest, GitHub, npm, PyPI, Zenodo and the canonical URL, are distribution forms for implementers. They are scaffolding around the anchor, not the anchor itself."}
            </p>

            <div className="hidden md:block overflow-x-auto -mx-2 my-5">
              <table>
                <thead>
                  <tr>
                    <th>{zh ? "識別碼類型" : "Identifier"}</th>
                    <th>{zh ? "值" : "Value"}</th>
                    <th>{zh ? "連結" : "Link"}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td className="font-data text-xs tnum">DOI</td>
                    <td className="font-data text-xs tnum">{meta.doi}</td>
                    <td>
                      <a
                        href={doiUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-navy underline"
                      >
                        {doiUrl} ↗
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td className="font-data text-xs tnum">Zenodo</td>
                    <td className="font-data text-xs tnum">{meta.doi}</td>
                    <td>
                      <a
                        href={zenodoUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-navy underline"
                      >
                        {zenodoUrl} ↗
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td className="font-data text-xs tnum">GitHub</td>
                    <td className="font-data text-xs tnum">
                      Agent-Threat-Rule/agent-threat-rules
                    </td>
                    <td>
                      <a
                        href={meta.repository}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-navy underline"
                      >
                        {meta.repository} ↗
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td className="font-data text-xs tnum">npm</td>
                    <td className="font-data text-xs tnum">{npmPackage}</td>
                    <td>
                      <a
                        href={npmUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-navy underline"
                      >
                        {npmUrl} ↗
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td className="font-data text-xs tnum">PyPI</td>
                    <td className="font-data text-xs tnum">{pypiPackage}</td>
                    <td>
                      <a
                        href={pypiUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-navy underline"
                      >
                        {pypiUrl} ↗
                      </a>
                    </td>
                  </tr>
                  <tr>
                    <td className="font-data text-xs tnum">Canonical URL</td>
                    <td className="font-data text-xs tnum">
                      {meta.canonicalUrl}
                    </td>
                    <td>
                      <a
                        href={meta.canonicalUrl}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-navy underline"
                      >
                        {meta.canonicalUrl} ↗
                      </a>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            {/* Mobile list */}
            <div className="md:hidden my-5 space-y-3">
              {[
                {
                  label: "DOI",
                  value: meta.doi,
                  url: doiUrl,
                },
                {
                  label: "Zenodo",
                  value: meta.doi,
                  url: zenodoUrl,
                },
                {
                  label: "GitHub",
                  value: "Agent-Threat-Rule/agent-threat-rules",
                  url: meta.repository,
                },
                {
                  label: "npm",
                  value: npmPackage,
                  url: npmUrl,
                },
                {
                  label: "PyPI",
                  value: pypiPackage,
                  url: pypiUrl,
                },
                {
                  label: "Canonical URL",
                  value: meta.canonicalUrl,
                  url: meta.canonicalUrl,
                },
              ].map((row) => (
                <div
                  key={row.label}
                  className="border border-fog  p-4 bg-paper"
                >
                  <p
                    className="text-xs uppercase tracking-wider text-stone mb-1"
                    style={{ fontFamily: "var(--font-data)" }}
                  >
                    {row.label}
                  </p>
                  <p
                    className="font-data text-xs tnum text-navy-ink mb-2 break-all"
                    style={{ fontFamily: "var(--font-data)" }}
                  >
                    {row.value}
                  </p>
                  <a
                    href={row.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-navy underline text-sm inline-flex items-center min-h-[44px] break-all"
                  >
                    {row.url} ↗
                  </a>
                </div>
              ))}
            </div>

            <p className="text-sm text-stone mt-4" style={{ maxWidth: "42em" }}>
              {zh
                ? "引用的規範性錨點是 DOI。Zenodo 替每個發布版本存一份獨立、不會變的 snapshot。GitHub repository 是持續演進的原始碼。npm 和 PyPI 套件是給實作者用的散佈形式。到了規格底下、單條規則這一層，用的是 CVE、CWE 風格的 ATR-YYYY-NNNNN 識別碼。發布後 ID 不會改。規則內容可以修訂，識別碼不動，所以論文、威脅情報和 CI 腳本都能放心指向某一條規則，而不是整份標準。識別碼穩定，標準才能被當成基礎建設來依賴。"
                : "The DOI is the normative anchor for citation. Zenodo holds an immutable snapshot of each release. The GitHub repository tracks ongoing changes. The npm and PyPI packages are distribution artifacts for implementers. Below the specification, at the level of a single rule, threats are referenced by CVE- and CWE-style ATR-YYYY-NNNNN identifiers. An ID never changes after publication. A rule's content may be revised while its identifier stays put, so a paper, a threat-intel feed or a CI script can safely point at one specific rule instead of the whole standard. A standard can be depended on as infrastructure only if its identifiers are stable."}
            </p>
          </section>

          {/* End matter */}
          <hr className="my-12 border-fog" />
          <p className="spec-meta">
            {zh ? "編輯：" : "Editor: "}{meta.editors[0].name}
            {" <"}
            <a
              href={`mailto:${meta.editors[0].email}`}
              className="text-navy underline"
            >
              {meta.editors[0].email}
            </a>
            {">"} · DOI{" "}
            <a
              href={`https://doi.org/${meta.doi}`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-navy underline"
            >
              {meta.doi}
            </a>{" "}
            · MIT License · ISO 8601 {meta.lastModified}
          </p>
        </div>
      </div>
    </main>
    </Phrased>
  );
}
