import Link from "next/link";
import type { ReactNode } from "react";
import { DOCS_SECTIONS, pick } from "@/lib/docs-nav";
import { SheetRow } from "./Sheet";

const REPO = "https://github.com/Agent-Threat-Rule/agent-threat-rules";

/**
 * Documentation layout: a sidebar of the standard's sections on the left and
 * one document on the right, inside the site sheet. Every page ends with the
 * date it was generated and a feedback link that opens a pre-filled issue.
 */
export function DocsShell({
  locale,
  path,
  eyebrow,
  title,
  lead,
  generatedAt,
  children,
}: {
  locale: string;
  /** This page's path below the locale prefix, to mark it in the sidebar. */
  path: string;
  eyebrow: string;
  title: string;
  lead?: string;
  generatedAt: string;
  children: ReactNode;
}) {
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const feedback = `${REPO}/issues/new?title=${encodeURIComponent(`Docs feedback: ${path}`)}&labels=documentation`;

  return (
    <div className="sheet">
      <SheetRow>
        <div className="grid lg:grid-cols-[250px_1fr]">
          <aside className="hidden lg:block border-r border-fog">
            <nav aria-label={zh ? "文件目錄" : "Documentation"} className="sticky top-28 max-h-[calc(100vh-8rem)] overflow-y-auto py-8 px-5">
              {DOCS_SECTIONS.map((section) => (
                <div key={section.key} className="mb-6">
                  <div className="font-data text-[10px] uppercase tracking-[0.1em] text-mist mb-2">
                    {section.numeral}. {pick(section.label, locale)}
                  </div>
                  <ul className="flex flex-col">
                    {section.links.map((link) => {
                      const active = link.path === path;
                      return (
                        <li key={link.path}>
                          <Link
                            href={`${prefix}${link.path}`}
                            aria-current={active ? "page" : undefined}
                            className={`block text-[13px] leading-snug py-1.5 pl-3 border-l ${
                              active ? "border-navy text-ink bg-[#E7ECF6]/60" : "border-fog text-stone hover:text-ink hover:border-stone"
                            }`}
                          >
                            {pick(link.label, locale)}
                          </Link>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
            </nav>
          </aside>

          <article className="min-w-0 px-8 md:px-12 pt-12 pb-16">
            <div className="text-[13px] text-stone">{eyebrow}</div>
            <h1 className="mt-2 text-[32px] md:text-[36px] leading-[1.15] tracking-[-0.02em] text-ink text-balance">{title}</h1>
            {lead && <p className="mt-4 text-[16px] leading-[1.6] text-ink/75 max-w-[680px] text-pretty">{lead}</p>}
            <div className="mt-10">{children}</div>
            <div className="mt-16 pt-6 border-t border-fog flex flex-wrap items-center justify-between gap-3 font-data text-[11px] text-stone">
              <span>{zh ? `本頁產生於 ${generatedAt}` : `Page generated ${generatedAt}`}</span>
              <a href={feedback} target="_blank" rel="noopener noreferrer" className="hover:text-ink">
                {zh ? "這頁有幫助嗎？回饋 →" : "Was this page helpful? Send feedback →"}
              </a>
            </div>
          </article>
        </div>
      </SheetRow>
    </div>
  );
}

/** Status callout, for saying plainly what is not built yet. */
export function Callout({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="border border-fog bg-white/60 px-5 py-4 text-[14px] leading-[1.6] text-graphite">
      <span className="font-data text-[10px] uppercase tracking-[0.1em] text-navy mr-2">{label}</span>
      {children}
    </div>
  );
}

/** "At a glance" table that opens process pages: two columns, label and value. */
export function GlanceTable({ rows }: { rows: ReadonlyArray<{ label: string; value: ReactNode }> }) {
  return (
    <dl className="border-t border-fog">
      {rows.map((r) => (
        <div key={r.label} className="grid grid-cols-[160px_1fr] gap-4 py-3 border-b border-fog">
          <dt className="text-[13px] text-stone">{r.label}</dt>
          <dd className="text-[14px] text-ink">{r.value}</dd>
        </div>
      ))}
    </dl>
  );
}
