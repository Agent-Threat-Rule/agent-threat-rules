"use client";

import { useState } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import type { Locale } from "@/lib/i18n";
import { NAV_GROUPS, pick } from "@/lib/site-nav";

export interface HeaderMeta {
  specVersion: string;
  npmLabel: string;
  npmVersion: string;
  updated: string;
}

/**
 * Announcement bar, then a two-row header laid out on the sheet's columns:
 * row one is the logo and the facts every page is true as of; row two is the
 * six navigation groups on the left and two fixed actions in ruled cells on
 * the right.
 */
export function Nav({ locale, meta }: { locale: Locale; meta: HeaderMeta }) {
  const [menuOpen, setMenuOpen] = useState(false);
  const pathname = usePathname();
  const prefix = `/${locale}`;
  const zh = locale === "zh";
  const otherLocale = locale === "en" ? "zh" : "en";
  const isActive = (path: string) => pathname === `${prefix}${path}` || pathname.startsWith(`${prefix}${path}/`);
  // One active group: the one whose matching link path is longest, so
  // /docs/integrations marks Adopt (exact link) rather than Standard (/docs).
  const matchLength = (path: string) => (isActive(path) ? path.length : -1);
  const activeGroupKey = NAV_GROUPS.map((g) => ({ key: g.key, len: Math.max(...g.links.map((l) => matchLength(l.path))) }))
    .filter((g) => g.len >= 0)
    .sort((a, b) => b.len - a.len)[0]?.key;
  const cell = "hidden md:flex flex-col justify-center px-4 border-l border-fog w-[200px]";

  return (
    <>
      <header className="sticky top-0 z-50 bg-paper/95 backdrop-blur-sm">
        <div className="max-w-[1120px] mx-auto border-x border-fog">
          <div className="flex items-stretch h-16 border-b border-fog">
            <Link href={prefix} className="flex items-center px-6 mr-auto" aria-label={zh ? "ATR 首頁" : "ATR home"}>
              <img src="/atr-logo-ink.png" alt="Agent Threat Rules (ATR)" className="h-11 w-auto" />
            </Link>
            <div className={cell}>
              <span className="text-[11px] text-stone leading-tight">{zh ? "規格與發布" : "Spec and release"}</span>
              <span className="text-[13px] text-ink leading-tight mt-1 whitespace-nowrap">
                {meta.specVersion} · {meta.npmLabel} {meta.npmVersion}
              </span>
            </div>
            <div className={cell}>
              <span className="text-[11px] text-stone leading-tight">{zh ? "維護者" : "Maintained by"}</span>
              <span className="text-[13px] text-ink leading-tight mt-1 whitespace-nowrap">{zh ? "ATR 維護者，TSC 籌組中" : "ATR maintainers, TSC forming"}</span>
            </div>
            <Link
              href={`/${otherLocale}${pathname.replace(/^\/(en|zh)/, "")}`}
              className="flex items-center justify-center px-4 border-l border-fog font-data text-[11px] text-stone hover:text-ink min-w-[56px]"
              aria-label={otherLocale === "zh" ? "Switch to Chinese" : "Switch to English"}
            >
              {otherLocale === "zh" ? "中文" : "EN"}
            </Link>
            <button
              onClick={() => setMenuOpen(!menuOpen)}
              className="md:hidden flex flex-col gap-1.5 items-center justify-center px-5 border-l border-fog"
              aria-label={menuOpen ? (zh ? "關閉選單" : "Close menu") : zh ? "開啟選單" : "Open menu"}
              aria-expanded={menuOpen}
              aria-controls="mobile-nav-drawer"
            >
              <span className={`block w-5 h-px bg-ink transition-transform ${menuOpen ? "rotate-45 translate-y-[3.5px]" : ""}`} />
              <span className={`block w-5 h-px bg-ink ${menuOpen ? "opacity-0" : ""}`} />
              <span className={`block w-5 h-px bg-ink transition-transform ${menuOpen ? "-rotate-45 -translate-y-[3.5px]" : ""}`} />
            </button>
          </div>

          <nav className="relative hidden md:flex items-stretch h-11 border-b border-fog" aria-label={zh ? "主選單" : "Main"}>
            <span className="corner-mark corner-mark-l !top-auto -bottom-[4px]" aria-hidden="true" />
            <span className="corner-mark corner-mark-r !top-auto -bottom-[4px]" aria-hidden="true" />
            <ul className="flex items-stretch mr-auto pl-3">
              {NAV_GROUPS.map((group) => {
                const active = group.key === activeGroupKey;
                return (
                  <li key={group.key} className="relative group flex">
                    <Link
                      href={`${prefix}${group.path}`}
                      className={`relative px-3 inline-flex items-center text-[14px] transition-colors ${active ? "text-ink" : "text-stone hover:text-ink"}`}
                      aria-haspopup="true"
                    >
                      {pick(group.label, locale)}
                      {active && <span className="absolute left-3 right-3 -bottom-px h-[2px] bg-brand" aria-hidden="true" />}
                    </Link>
                    <div className="invisible opacity-0 group-hover:visible group-hover:opacity-100 group-focus-within:visible group-focus-within:opacity-100 transition-opacity absolute top-full left-0 min-w-[240px] bg-paper border border-fog shadow-[0_8px_24px_rgba(0,0,0,0.06)] py-2 z-50">
                      {group.links.map((link) => (
                        <Link
                          key={link.path}
                          href={`${prefix}${link.path}`}
                          className={`block px-4 py-2 text-[13px] hover:bg-ash ${isActive(link.path) ? "text-ink" : "text-graphite"}`}
                        >
                          {pick(link.label, locale)}
                        </Link>
                      ))}
                    </div>
                  </li>
                );
              })}
            </ul>
            <Link href={`${prefix}/spec`} className="flex items-center px-4 border-l border-fog w-[200px] text-[14px] text-ink hover:bg-white transition-colors">
              {zh ? "讀規格" : "Read the spec"}
            </Link>
            <Link href={`${prefix}/community`} className="flex items-center px-4 border-l border-fog w-[200px] text-[14px] text-ink hover:bg-white transition-colors">
              {zh ? "社群" : "Community"}
            </Link>
          </nav>
        </div>

      </header>
      {menuOpen && (
        <div id="mobile-nav-drawer" role="dialog" aria-modal="true" aria-label={zh ? "主選單" : "Main menu"} className="fixed inset-0 z-[60] md:hidden">
          <div className="absolute inset-0 bg-ink/10" onClick={() => setMenuOpen(false)} aria-hidden="true" />
          <div className="absolute top-0 right-0 w-80 max-w-full h-full overflow-y-auto bg-paper border-l border-fog px-6 pb-6">
            <div className="sticky top-0 -mx-6 mb-4 px-6 h-16 flex items-center justify-end bg-paper border-b border-fog">
              <button onClick={() => setMenuOpen(false)} className="text-[22px] leading-none text-ink px-2 py-1" aria-label={zh ? "關閉選單" : "Close menu"}>×</button>
            </div>
            {NAV_GROUPS.map((group) => (
              <div key={group.key} className="mb-6">
                <div className="font-data text-[10px] uppercase tracking-[0.08em] text-mist mb-2">{pick(group.label, locale)}</div>
                {group.links.map((link) => (
                  <Link key={link.path} href={`${prefix}${link.path}`} onClick={() => setMenuOpen(false)} className="block py-2 text-[15px] text-ink border-b border-fog">
                    {pick(link.label, locale)}
                  </Link>
                ))}
              </div>
            ))}
            <div className="font-data text-[11px] text-stone leading-relaxed">
              {zh ? "規格" : "Spec"} {meta.specVersion} · {meta.npmLabel} {meta.npmVersion} · {zh ? "更新" : "Updated"} {meta.updated}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
