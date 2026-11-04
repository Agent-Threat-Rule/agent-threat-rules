import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { loadCrosswalks, findCrosswalk } from "@/lib/crosswalks";
import { renderMarkdown } from "@/lib/markdown";
import { DocsShell, Callout } from "@/components/DocsShell";

const REPO_BLOB = "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main";

export function generateStaticParams() {
  const slugs = loadCrosswalks().filter((d) => d.published).map((d) => d.slug);
  return locales.flatMap((locale) => slugs.map((slug) => ({ locale, slug })));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string; slug: string }> }): Promise<Metadata> {
  const { locale, slug } = await params;
  const doc = findCrosswalk(slug);
  if (!doc || !doc.published) return { title: "Crosswalk not found" };
  return pageMetadata({
    locale,
    path: `/docs/crosswalks/${slug}`,
    title: `ATR × ${doc.framework}`,
    description: `How ATR detection rules map to ${doc.framework}. Written by ATR maintainers, not endorsed by ${doc.owner}.`,
  });
}

export default async function CrosswalkPage({ params }: { params: Promise<{ locale: string; slug: string }> }) {
  const { locale: raw, slug } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const doc = findCrosswalk(slug);
  if (!doc || !doc.published) notFound();
  const versions = await loadVersionLabels();
  const baseDir = doc.file.split("/").slice(0, -1).join("/");

  return (
    <DocsShell
      locale={locale}
      path={`/docs/crosswalks/${slug}`}
      eyebrow={zh ? "III. 框架對照" : "III. Crosswalks"}
      title={`ATR × ${doc.framework}`}
      generatedAt={versions.generatedAt}
    >
      <div className="flex flex-col gap-3">
        <Callout label={zh ? "不是背書" : "Not an endorsement"}>
          {zh
            ? `這份對照是 ATR 維護者寫的。${doc.owner} 沒有審過，也沒有背書。對照不代表符合任何法規。`
            : `ATR maintainers wrote this mapping. ${doc.owner} has not reviewed or endorsed it. It is not evidence of compliance with any regulation.`}
        </Callout>
        <Callout label={zh ? "來源" : "Source"}>
          <a href={`${REPO_BLOB}/${doc.file}`} className="text-blue hover:underline underline-offset-4" target="_blank" rel="noopener noreferrer">{doc.file}</a>
          {doc.committed && <> · {zh ? "最後提交" : "last commit"} {doc.committed}</>}
          {doc.declared && <> · {doc.declared}</>}
          {zh && <> · 原文是英文</>}
        </Callout>
      </div>
      <div className="mt-6 max-w-[780px]">{renderMarkdown(doc.body, { locale, baseDir })}</div>
    </DocsShell>
  );
}
