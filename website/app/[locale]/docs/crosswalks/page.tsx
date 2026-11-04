import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { loadCrosswalks } from "@/lib/crosswalks";
import { DocsShell, Callout } from "@/components/DocsShell";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/docs/crosswalks",
    title: locale === "zh" ? "框架對照" : "Framework crosswalks",
    description:
      locale === "zh"
        ? "ATR 規則對照到外部框架與指引的文件。ATR 自己的文件，不是框架方的背書，也不是合規保證。"
        : "Documents mapping ATR rules to external frameworks and guidance. ATR's own documents: not endorsements by the framework owners, and not a compliance guarantee.",
  });
}

export default async function CrosswalksIndexPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const versions = await loadVersionLabels();
  const docs = loadCrosswalks();
  const published = docs.filter((d) => d.published);
  const drafts = docs.filter((d) => !d.published);

  return (
    <DocsShell
      locale={locale}
      path="/docs/crosswalks"
      eyebrow={zh ? "III. 框架對照" : "III. Crosswalks"}
      title={zh ? "框架對照" : "Framework crosswalks"}
      lead={
        zh
          ? "每一份對照都是 ATR 維護者寫的文件，說明哪些規則回應框架的哪些條目。框架方沒有審查或背書這些對照；對照也不代表符合任何法規。"
          : "Each crosswalk is a document written by ATR maintainers, saying which rules answer which items of a framework. The framework owners have not reviewed or endorsed them, and a mapping is not evidence of compliance with any regulation."
      }
      generatedAt={versions.generatedAt}
    >
      <Callout label={zh ? "日期" : "Dates"}>
        {zh
          ? "每份文件裡的規則數與引用是撰寫當時的快照。表中列出文件自己寫的日期，以及最後一次提交的日期。"
          : "Rule counts and citations inside each document are a snapshot from when it was written. The table shows the date each document declares and the date of its last commit."}
      </Callout>

      <div className="mt-8 overflow-x-auto">
        <table className="w-full text-left border-t border-fog min-w-[620px]">
          <thead>
            <tr className="border-b border-fog font-data text-[10px] uppercase tracking-[0.08em] text-mist">
              <th className="py-2.5 pr-4 font-normal">{zh ? "框架" : "Framework"}</th>
              <th className="py-2.5 pr-4 font-normal">{zh ? "發布方" : "Owner"}</th>
              <th className="py-2.5 pr-4 font-normal">{zh ? "文件日期" : "Document date"}</th>
              <th className="py-2.5 font-normal">{zh ? "最後提交" : "Last commit"}</th>
            </tr>
          </thead>
          <tbody>
            {published.map((d) => (
              <tr key={d.slug} className="border-b border-fog align-top">
                <td className="py-3 pr-4 text-[14px]">
                  <Link href={`${prefix}/docs/crosswalks/${d.slug}`} className="text-blue hover:underline underline-offset-4">{d.framework}</Link>
                </td>
                <td className="py-3 pr-4 text-[13px] text-graphite">{d.owner}</td>
                <td className="py-3 pr-4 font-data text-[11.5px] text-stone">{d.declared?.replace(/^(Last updated|Version):\s*/i, "") ?? "—"}</td>
                <td className="py-3 font-data text-[11.5px] text-stone whitespace-nowrap">{d.committed ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {drafts.length > 0 && (
        <section className="mt-12">
          <h2 className="text-[18px] text-ink">{zh ? "內部草稿（未發布）" : "Internal drafts (not published)"}</h2>
          <p className="mt-2 text-[13.5px] leading-[1.6] text-stone max-w-[640px]">
            {zh
              ? "以下文件的標頭寫明是內部草稿、尚未發布，所以網站只列名稱，不顯示內容。"
              : "These documents say in their own header that they are internal drafts and not published, so the site lists their names and does not show their content."}
          </p>
          <ul className="mt-4 border-t border-fog">
            {drafts.map((d) => (
              <li key={d.slug} className="flex justify-between gap-4 py-2.5 border-b border-fog text-[13px]">
                <span className="text-graphite">{d.framework}</span>
                <span className="font-data text-[11px] text-mist">{zh ? "內部草稿" : "internal draft"}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </DocsShell>
  );
}
