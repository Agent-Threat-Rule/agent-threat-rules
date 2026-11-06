import Link from "next/link";
import type { ReactNode } from "react";
import { DOCS_SECTIONS, pick } from "@/lib/docs-nav";
import { SheetRow } from "./Sheet";
import Phrased from "@/components/Phrased";
import { Sign } from "@/components/Sign";

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
    <Phrased>
    <>
      <SheetRow>
        <div className="grid lg:grid-cols-[minmax(0,1fr)_260px]">
          <article className="min-w-0 px-6 md:px-14 pt-20 pb-16">
            <div className="text-[13px] text-stone">{eyebrow}</div>
            <h1 className="mt-3 text-[32px] md:text-[48px] leading-[1.12] tracking-[-0.01em] text-ink text-balance">{title}</h1>
            {lead && <p className="mt-4 text-[16px] leading-[1.6] text-ink/75 max-w-[680px] text-pretty">{lead}</p>}
            <div className="mt-10">{children}</div>
            <div className="mt-16 pt-6 border-t border-fog flex flex-wrap items-center justify-between gap-3 text-[13px] text-stone">
              <span>{zh ? <>本頁產生於 <span className="font-data">{generatedAt}</span></> : <>Page generated <span className="font-data">{generatedAt}</span></>}</span>
              <a href={feedback} target="_blank" rel="noopener noreferrer" className="hover:text-ink">
                {zh ? "哪裡寫錯或漏了？開 issue 回報" : "Something wrong or missing? Open an issue"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
              </a>
            </div>
          </article>

          {/* The section list sits to the right so the document keeps the
              site's one left edge. Only the section holding this page is
              opened, so the current page is always in view. */}
          <aside className="hidden lg:block border-l border-fog">
            <nav aria-label={zh ? "文件目錄" : "Documentation"} className="sticky top-28 max-h-[calc(100vh-8rem)] overflow-y-auto pt-20 pb-8 px-6">
              {DOCS_SECTIONS.map((section) => {
                const open = section.links.some((link) => link.path === path);
                const first = section.links[0];
                return (
                  <div key={section.key} className={open ? "mb-5" : "mb-2"}>
                    {open ? (
                      <div className="text-[13px] text-stone mb-2">
                        {section.numeral}. {pick(section.label, locale)}
                      </div>
                    ) : (
                      <Link href={`${prefix}${first.path}`} className="block text-[13px] text-stone hover:text-ink">
                        {section.numeral}. {pick(section.label, locale)}
                      </Link>
                    )}
                    {open && (
                      <ul className="flex flex-col">
                        {section.links.map((link) => {
                          const active = link.path === path;
                          return (
                            <li key={link.path}>
                              <Link
                                href={`${prefix}${link.path}`}
                                aria-current={active ? "page" : undefined}
                                className={`block text-[13px] leading-snug py-1.5 pl-3 border-l ${
                                  active ? "border-blue text-blue" : "border-fog text-stone hover:text-ink hover:border-stone"
                                }`}
                              >
                                {pick(link.label, locale)}
                              </Link>
                            </li>
                          );
                        })}
                      </ul>
                    )}
                  </div>
                );
              })}
            </nav>
          </aside>
        </div>
      </SheetRow>
    </>
    </Phrased>
  );
}

/** Status callout, for saying plainly what is not built yet. */
export function Callout({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Phrased>
    <div className="border-t border-fog pt-4 text-[14px] leading-[1.6] text-graphite max-w-[720px]">
      <span className="text-[13px] text-ink mr-2">{label}</span>
      {children}
    </div>
    </Phrased>
  );
}

/** "At a glance" table that opens process pages: two columns, label and value. */
export function GlanceTable({ rows }: { rows: ReadonlyArray<{ label: string; value: ReactNode }> }) {
  return (
    <Phrased>
    <dl className="border-t border-fog">
      {rows.map((r) => (
        <div key={r.label} className="grid grid-cols-[160px_1fr] gap-4 py-3 border-b border-fog">
          <dt className="text-[13px] text-stone">{r.label}</dt>
          <dd className="text-[14px] text-ink">{r.value}</dd>
        </div>
      ))}
    </dl>
    </Phrased>
  );
}
