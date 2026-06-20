/* ATR Citation — formal citation block (BibTeX / APA / IEEE / Chicago)
 * plus related identifiers (DOI, Zenodo, repository, npm, PyPI). For
 * citing ATR in academic work, security research, and institutional
 * documentation.
 */
import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale, t } from "@/lib/i18n";
import { getSpecMeta } from "@/lib/spec-meta";
import { DocumentStatus } from "@/components/spec/DocumentStatus";
import { CitationBlock } from "@/components/spec/CitationBlock";

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
    title: "Citation — ATR",
    description:
      locale === "zh"
        ? "ATR 引用格式 (BibTeX / APA / IEEE / Chicago) 與相關識別碼。"
        : "Citation formats (BibTeX / APA / IEEE / Chicago) and related identifiers for citing ATR.",
  };
}

export default async function CitationsPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: l } = await params;
  const locale = (locales.includes(l as Locale) ? l : "en") as Locale;
  const meta = getSpecMeta();
  const prefix = `/${locale}`;
  const zh = locale === "zh";

  const doiUrl = `https://doi.org/${meta.doi}`;
  const zenodoUrl = `https://zenodo.org/doi/${meta.doi}`;
  const npmPackage = "agent-threat-rules";
  const npmUrl = `https://www.npmjs.com/package/${npmPackage}`;
  const pypiPackage = "pyatr";
  const pypiUrl = `https://pypi.org/project/${pypiPackage}/`;

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
          {zh ? "引用 — Citation" : "Citation"}
        </p>
        <h1
          className="text-3xl md:text-5xl font-bold text-navy-ink mb-4 leading-[1.1]"
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
                ? "URL 會搬家,專案會改名,網頁會 404。引用是把一個會動的東西釘成不會動的錨點——所以下列場景請引用本規格,而非僅以 URL 連結。引用之版本應以引用時 /spec 所載之最新版本為準,並於引用文字中標示該版本號 (例如 v3.5.0)。版本會前進,但被引用的那一版永遠指得回去。"
                : "URLs move, projects get renamed, pages 404. A citation pins something that changes into an anchor that does not — so in the following contexts, cite this specification rather than only linking to a URL. The cited version should be the latest version published on /spec at the time of writing, and the citation should include that version number (e.g. v3.5.0). The version moves forward, but the version you cited remains reachable."}
            </p>
            <ul>
              <li>
                <strong>
                  {zh ? "學術出版品" : "Academic publications"}.
                </strong>{" "}
                {zh
                  ? "會議論文、期刊文章、學位論文中提及 ATR 規則格式、ATR engine、ATR benchmark 結果,或將 ATR 作為 baseline 比較對象。"
                  : "Conference papers, journal articles, theses that reference the ATR rule format, an ATR engine, ATR benchmark results, or use ATR as a baseline for comparison."}
              </li>
              <li>
                <strong>
                  {zh ? "安全研究與技術報告" : "Security research and technical reports"}.
                </strong>{" "}
                {zh
                  ? "在外部報告中重用 ATR 規則、引用 ATR 之偵測涵蓋率數字、或在威脅情報文件中以 ATR-YYYY-NNNNN 識別碼指涉特定威脅。"
                  : "External reports that reuse ATR rules, cite ATR coverage figures, or reference specific threats by their ATR-YYYY-NNNNN identifier in threat-intelligence documents."}
              </li>
              <li>
                <strong>
                  {zh ? "機構文件" : "Institutional documentation"}.
                </strong>{" "}
                {zh
                  ? "標準組織、研究機構、政府機構之白皮書或建議書中,將 ATR 列為參考標準或互通格式。"
                  : "Standards-body publications, research-institute white papers, and government recommendations that list ATR as a reference standard or interoperability format."}
              </li>
              <li>
                <strong>
                  {zh ? "主權 AI 合規與符規申報" : "Sovereign-AI compliance and conformance filings"}.
                </strong>{" "}
                {zh
                  ? "向監管機關提交之 AI 風險管理或 agent 安全文件中,引用 ATR 作為偵測規則層 (detection-rule layer) 之依據,或以 L1 / L2 / L3 符規等級宣告其組織之 ATR 整合層級。"
                  : "AI risk-management and agent-security filings submitted to regulators that cite ATR as the basis for the detection-rule layer, or declare an organization's ATR integration level by L1 / L2 / L3 conformance."}
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
                ? "AI agent 的攻擊面不分學科——寫工程論文的、寫政策白皮書的、寫合規申報的,面對的是同一層威脅。所以同一個標準要在四種引用體裁裡都讀得通。下方四種格式對應四個學術傳統:BibTeX 為 LaTeX 之原生格式;APA 為社會科學標準;IEEE 為工程學科標準;Chicago 為人文學科常見格式。請依目標期刊或機構之要求選用——背後指向的,是同一份規格、同一個 DOI。"
                : "The AI-agent attack surface does not respect disciplinary lines — the engineer writing a paper, the analyst writing a policy white paper, the officer filing for compliance are all describing the same layer of threat. So the same standard has to read cleanly across four citation traditions. The four formats below map to four of them: BibTeX is native to LaTeX; APA is the social-sciences standard; IEEE is the engineering standard; Chicago is common in the humanities. Select the one your target journal or institution requires — each points back to the same specification, the same DOI."}
            </p>
            <CitationBlock
              locale={locale}
              meta={{
                version: meta.version,
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
                ? "一個標準有很多個面向世界的入口,但只有一個錨。下列識別碼指向本規格之等效或衍生發布物:DOI 是那個錨——學術引用的規範性錨點,即使每個 npm 版本、每支 GitHub 分支都在動,它指向的那份 snapshot 永不改變。其餘 (GitHub / npm / PyPI / Zenodo / canonical URL) 是給實作者用的散佈格式 (distribution form),是錨周圍的鷹架,不是錨本身。"
                : "A standard has many doors facing the world, but only one anchor. The identifiers below point to equivalent or derived distributions of this specification. The DOI is the anchor — the normative anchor for academic citation, pointing at a snapshot that never changes even as every npm version and every GitHub branch keeps moving. The rest (GitHub, npm, PyPI, Zenodo, canonical URL) are distribution forms for implementers — scaffolding around the anchor, not the anchor itself."}
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
                  className="border border-fog rounded-sm p-4 bg-paper"
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
                ? "規範性之引用錨點 (normative anchor) 為 DOI。儲存於 Zenodo 之版本為每一發布版本之獨立 snapshot;GitHub 倉庫為持續演進之原始碼;npm 與 PyPI 套件為實作者使用之分發格式。在規格之下、單條規則之層級,則以 CVE / CWE 風格之 ATR-YYYY-NNNNN 識別碼指涉——一經發布永不改 ID,規則內容可修訂,但識別碼穩定,讓論文、威脅情報與 CI 腳本得以安全引用某一條具體規則,而非整份標準。穩定的識別碼,是一個標準能被當作基礎建設依賴的前提。"
                : "The normative anchor for citation is the DOI. Zenodo holds an immutable snapshot per release; the GitHub repository tracks ongoing evolution; the npm and PyPI packages are distribution artifacts used by implementers. Below the specification, at the level of a single rule, threats are referenced by CVE / CWE-style ATR-YYYY-NNNNN identifiers — the ID never changes after publication; the rule's content may be revised, but the identifier stays stable, so a paper, a threat-intel feed, or a CI script can safely reference one specific rule rather than the whole standard. A stable identifier is the precondition for a standard to be depended on as infrastructure."}
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
