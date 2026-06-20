/* ATR Errata — published list of errors discovered in released spec
 * versions, sourced from data/errata.json as the single source of truth.
 * Empty by default; forward-compatible with a tabular report.
 */
import Link from "next/link";
import type { Metadata } from "next";
import { readFileSync } from "node:fs";
import { join } from "node:path";
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
    title: "Errata — ATR",
    description:
      locale === "zh"
        ? "ATR 規格已發布版本中發現之錯誤的公開常設紀錄。錯誤公開更正、留下紀錄,而非靜默修補。"
        : "A public, standing record of errors found in published versions of the ATR specification — corrected in the open, never silently patched.",
  };
}

interface ErrataEntry {
  /** Affected spec version (e.g. "3.5.0"). */
  version: string;
  /** Section identifier (e.g. "§3.5"). */
  section: string;
  /** Plain-text summary (English). */
  summary_en: string;
  /** Plain-text summary (Traditional Chinese). */
  summary_zh?: string;
  /** ISO 8601 publication date. */
  date: string;
  /** Optional canonical PR or commit URL. */
  url?: string;
  /** Optional stable ID for deep links. */
  id?: string;
}

interface ErrataFile {
  lastUpdated: string;
  entries: ErrataEntry[];
}

function loadErrata(): ErrataFile {
  try {
    const raw = readFileSync(
      join(process.cwd(), "data", "errata.json"),
      "utf-8",
    );
    return JSON.parse(raw);
  } catch {
    return { lastUpdated: "", entries: [] };
  }
}

const ISSUE_URL =
  "https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new";

export default async function ErrataPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: l } = await params;
  const locale = (locales.includes(l as Locale) ? l : "en") as Locale;
  const meta = getSpecMeta();
  const zh = locale === "zh";
  const errata = loadErrata();
  const hasEntries = errata.entries.length > 0;

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
          {zh ? "勘誤 — Errata" : "Errata"}
        </p>
        <h1
          className="text-3xl md:text-5xl font-bold text-navy-ink mb-4 leading-[1.1]"
          style={{
            fontFamily: "var(--font-display)",
            letterSpacing: "-0.02em",
          }}
        >
          {t(locale, "errata.title")}
        </h1>
        <p
          className="text-base md:text-xl text-graphite leading-snug mb-6"
          style={{ fontFamily: "var(--font-body)", maxWidth: "42em" }}
        >
          {t(locale, "errata.subtitle")}
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
                <a href="#registry">
                  <span className="toc-section-num">§1</span>
                  {zh ? "勘誤紀錄" : "Errata Registry"}
                </a>
              </li>
              <li>
                <a href="#report">
                  <span className="toc-section-num">§2</span>
                  {zh ? "如何回報勘誤" : "How to report an erratum"}
                </a>
              </li>
            </ol>
          </nav>
        </aside>

        {/* Main body */}
        <div className="min-w-0 spec-measure-wide">
          {/* §1 Errata Registry */}
          <section id="registry" aria-labelledby="registry-heading">
            <h2 id="registry-heading">
              <a href="#registry" className="section-anchor" aria-hidden="true">
                §1
              </a>
              {zh ? "勘誤紀錄" : "Errata Registry"}
            </h2>

            {hasEntries ? (
              <>
                <div className="hidden md:block overflow-x-auto -mx-2 my-5">
                  <table>
                    <thead>
                      <tr>
                        <th>{t(locale, "errata.col.version")}</th>
                        <th>{t(locale, "errata.col.section")}</th>
                        <th>{t(locale, "errata.col.summary")}</th>
                        <th>{t(locale, "errata.col.date")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {errata.entries.map((e, i) => {
                        const summary =
                          zh && e.summary_zh ? e.summary_zh : e.summary_en;
                        const key = e.id ?? `${e.version}-${i}`;
                        return (
                          <tr key={key} id={`erratum-${key}`}>
                            <td className="font-data text-xs tnum">
                              {e.version}
                            </td>
                            <td className="font-data text-xs tnum">
                              {e.section}
                            </td>
                            <td>
                              {e.url ? (
                                <a
                                  href={e.url}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-navy underline"
                                >
                                  {summary} ↗
                                </a>
                              ) : (
                                summary
                              )}
                            </td>
                            <td className="font-data text-xs tnum">{e.date}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Mobile cards */}
                <div className="md:hidden my-5 space-y-3">
                  {errata.entries.map((e, i) => {
                    const summary =
                      zh && e.summary_zh ? e.summary_zh : e.summary_en;
                    const key = e.id ?? `${e.version}-${i}`;
                    return (
                      <div
                        key={key}
                        id={`erratum-mobile-${key}`}
                        className="border border-fog rounded-sm p-4 bg-paper"
                      >
                        <p
                          className="font-semibold text-navy-ink mb-2"
                          style={{ fontFamily: "var(--font-body)" }}
                        >
                          {summary}
                        </p>
                        <dl
                          className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs tnum text-graphite"
                          style={{ fontFamily: "var(--font-data)" }}
                        >
                          <dt className="text-stone">
                            {t(locale, "errata.col.version")}
                          </dt>
                          <dd>{e.version}</dd>
                          <dt className="text-stone">
                            {t(locale, "errata.col.section")}
                          </dt>
                          <dd>{e.section}</dd>
                          <dt className="text-stone">
                            {t(locale, "errata.col.date")}
                          </dt>
                          <dd>{e.date}</dd>
                        </dl>
                        {e.url ? (
                          <a
                            href={e.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-navy underline text-sm inline-flex items-center min-h-[44px] mt-2"
                          >
                            {zh ? "查看勘誤" : "View erratum"} ↗
                          </a>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              </>
            ) : (
              <div
                className="border border-fog rounded-sm p-6 bg-paper not-prose"
                role="status"
              >
                <p
                  className="text-graphite leading-relaxed"
                  style={{
                    fontFamily: "var(--font-body)",
                    maxWidth: "42em",
                  }}
                >
                  {t(locale, "errata.empty")}
                </p>
              </div>
            )}

            {errata.lastUpdated ? (
              <p className="spec-meta mt-4">
                {zh ? "最後更新" : "Last updated"}: {errata.lastUpdated}
              </p>
            ) : null}
          </section>

          {/* §2 How to report an erratum */}
          <section id="report" aria-labelledby="report-heading">
            <h2 id="report-heading">
              <a href="#report" className="section-anchor" aria-hidden="true">
                §2
              </a>
              {zh ? "如何回報勘誤" : "How to report an erratum"}
            </h2>
            <p>
              {zh
                ? "勘誤回報是公開審查的一環,任何人都可以提。若你在規格中發現錯誤,請於 ATR repository 開立 issue。內容請包含:受影響之版本、所在章節 (如 §3.5)、目前的錯誤文字、建議的更正、以及任何可驗證之參考資料。維護者會於合理時間內審查;一經確認,即加入上方紀錄,並標明來源。錯誤不會被悄悄改掉——它會留下紀錄。"
                : "Reporting an erratum is part of open review, and anyone may do it. If you discover an error in this specification, open an issue on the ATR repository. The report should include: the affected version, the section (e.g. §3.5), the erroneous text as published, the proposed correction, and any verifiable references. Maintainers review reports in reasonable time; once confirmed, the entry is added to the registry above, with attribution. Errors are not silently overwritten — they leave a record."}
            </p>
            <ul>
              <li>
                <a
                  href={ISSUE_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-navy underline"
                >
                  {zh ? "開立 issue" : "Open an issue"} ↗
                </a>{" "}
                — {ISSUE_URL.replace(/^https?:\/\//, "")}
              </li>
              <li>
                {zh ? "編輯聯絡信箱" : "Editor contact"}:{" "}
                <a
                  href={`mailto:${meta.editors[0].email}`}
                  className="text-navy underline"
                >
                  {meta.editors[0].email}
                </a>
              </li>
            </ul>
            <p className="text-sm text-stone mt-4" style={{ maxWidth: "42em" }}>
              {zh
                ? "勘誤更正的是文字,不是規範本身——它不視為規格變更。實質性的語意修改另以新版本發布,並於 /changelog 標註為 [Breaking] 或 [Compatible]。這條界線讓引用本規格的人清楚知道:勘誤永遠不會在他們腳下改動規則的意義。"
                : "An erratum corrects the text, not the normative content — it is not treated as a spec change. Substantive semantic changes ship as new versions, tagged on /changelog as [Breaking] or [Compatible]. The line is deliberate: anyone citing this specification can rely on errata never shifting a rule's meaning underneath them."}
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
