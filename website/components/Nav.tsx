"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import type { Locale } from "@/lib/i18n";
import { t } from "@/lib/i18n";

export function Nav({ locale }: { locale: Locale }) {
  const [scrolled, setScrolled] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 10);
    };
    window.addEventListener("scroll", handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const pathname = usePathname();
  const prefix = `/${locale}`;
  const otherLocale = locale === "en" ? "zh" : "en";
  const pages = [
    "rules",
    "threats",
    "coverage",
    "integrate",
    "ecosystem",
    "red-team",
    "contribute",
    "research",
    "about",
    "changelog",
    "quality-standard",
  ] as const;

  return (
    <>
      <nav
        className={`fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-6 md:px-12 h-16 transition-all duration-300 ${
          scrolled
            ? "bg-paper/92 backdrop-blur-md border-b border-fog shadow-[0_1px_8px_rgba(0,0,0,0.04)]"
            : "bg-transparent border-b border-transparent"
        }`}
      >
        <Link href={prefix} className="flex items-center py-2.5 -my-2.5">
          <img src="/atr-logo-black.png" alt="ATR" className="h-7 md:h-8" />
        </Link>

        <div className="hidden md:flex items-center gap-8">
          {pages.map((page) => {
            const isActive = pathname === `${prefix}/${page}`;
            return (
              <Link
                key={page}
                href={`${prefix}/${page}`}
                className={`text-sm font-medium transition-colors ${
                  isActive ? "text-ink" : "text-stone hover:text-ink"
                }`}
              >
                {t(locale, `nav.${page}`)}
              </Link>
            );
          })}
        </div>

        <div className="flex items-center gap-3">
          <Link
            href={`/${otherLocale}${pathname.replace(/^\/(en|zh)/, "")}`}
            className="font-data text-xs text-stone hover:text-ink transition-colors tracking-wide inline-flex items-center justify-center min-w-[44px] min-h-[44px] -mx-2"
            aria-label={
              otherLocale === "zh" ? "Switch to Chinese" : "Switch to English"
            }
          >
            {otherLocale === "zh" ? "ZH" : "EN"}
          </Link>
          <Link
            href={`${prefix}/integrate`}
            className="bg-blue text-white px-5 py-2 rounded-sm text-sm font-semibold hover:bg-blue-hover transition-colors hidden sm:inline-block"
          >
            {t(locale, "nav.cta")}
          </Link>
          {/* Hamburger */}
          <button
            onClick={() => setMenuOpen(!menuOpen)}
            className="md:hidden flex flex-col gap-1.5 p-2 min-w-[44px] min-h-[44px] items-center justify-center -mr-2"
            aria-label="Toggle menu"
          >
            <span
              className={`block w-5 h-px bg-ink transition-all duration-300 ${menuOpen ? "rotate-45 translate-y-[3.5px]" : ""}`}
            />
            <span
              className={`block w-5 h-px bg-ink transition-all duration-300 ${menuOpen ? "opacity-0" : ""}`}
            />
            <span
              className={`block w-5 h-px bg-ink transition-all duration-300 ${menuOpen ? "-rotate-45 -translate-y-[3.5px]" : ""}`}
            />
          </button>
        </div>
      </nav>

      {/* Mobile drawer */}
      {menuOpen && (
        <div className="fixed inset-0 z-40 md:hidden">
          <div
            className="absolute inset-0 bg-ink/10"
            onClick={() => setMenuOpen(false)}
          />
          <div className="absolute top-16 right-0 w-72 bg-paper border-l border-fog shadow-lg p-6 flex flex-col gap-4">
            {pages.map((page) => (
              <Link
                key={page}
                href={`${prefix}/${page}`}
                onClick={() => setMenuOpen(false)}
                className="text-base font-medium text-ink py-2 border-b border-fog"
              >
                {t(locale, `nav.${page}`)}
              </Link>
            ))}
            <Link
              href={`${prefix}/integrate`}
              onClick={() => setMenuOpen(false)}
              className="bg-blue text-white px-5 py-3 rounded-sm text-sm font-semibold text-center mt-2"
            >
              {t(locale, "nav.cta")}
            </Link>
          </div>
        </div>
      )}
    </>
  );
}
