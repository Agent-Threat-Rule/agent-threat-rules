import type { Metadata } from "next";
import { locales, type Locale } from "./i18n";

/**
 * Per-page canonical URL, hreflang alternates and Open Graph URL.
 *
 * Next.js merges metadata shallowly, so `alternates` set in a layout is
 * inherited verbatim by every page below it that does not set its own. The
 * locale layout used to set a canonical pointing at the locale home page,
 * which told search engines and citation tools that every page was a
 * duplicate of /en or /zh. No layout sets `alternates` any more: each page
 * passes its own path here, and scripts/check-seo.mjs fails the build output
 * check when an exported page has no canonical or one that is not its own URL.
 */

export const SITE_URL = "https://agentthreatrule.org";
export const SITE_NAME = "ATR - Agent Threat Rules";

/** hreflang value per locale. Matches the lang HtmlLang puts on <html>. */
export const HREFLANG: Readonly<Record<Locale, string>> = { en: "en", zh: "zh-Hant" };

const OG_LOCALE: Readonly<Record<Locale, string>> = { en: "en_US", zh: "zh_TW" };

/** Open Graph fields every page shares. A page that sets openGraph replaces the layout's whole object. */
export const BASE_OPEN_GRAPH = {
  siteName: SITE_NAME,
  type: "website" as const,
  images: [
    {
      url: `${SITE_URL}/og-image.png`,
      width: 1200,
      height: 630,
      alt: "ATR - Agent Threat Rules: The open detection standard for AI agent security",
    },
  ],
};

export function toLocale(raw: string): Locale {
  return (locales as readonly string[]).includes(raw) ? (raw as Locale) : "en";
}

/** "" for the locale home page, otherwise "/segment[/segment]" with no trailing slash. */
function normalizePath(path: string): string {
  const trimmed = path.trim().replace(/^\/+|\/+$/g, "");
  return trimmed === "" ? "" : `/${trimmed}`;
}

/** Absolute URL of `path` (the part after the locale prefix) in `locale`. */
export function localeUrl(locale: Locale, path: string): string {
  return `${SITE_URL}/${locale}${normalizePath(path)}`;
}

/** canonical = this page in this locale; hreflang = the same page in every locale, English as x-default. */
export function pageAlternates(locale: string, path: string): NonNullable<Metadata["alternates"]> {
  const languages = Object.fromEntries(locales.map((l) => [HREFLANG[l], localeUrl(l, path)]));
  return {
    canonical: localeUrl(toLocale(locale), path),
    languages: { ...languages, "x-default": localeUrl("en", path) },
  };
}

interface PageMetadataInput {
  locale: string;
  /** Path below the locale prefix, e.g. "/spec" or "/rules/ATR-2026-00001"; "" for the locale home. */
  path: string;
  /** Page title without the site suffix; the root layout's template appends " | ATR". */
  title?: string;
  description?: string;
  /** Open Graph overrides, for a page whose share card should differ from its title and description. */
  openGraph?: { title?: string; description?: string };
}

export function pageMetadata({ locale, path, title, description, openGraph }: PageMetadataInput): Metadata {
  const lang = toLocale(locale);
  const ogTitle = openGraph?.title ?? (title ? `${title} | ATR` : undefined);
  const ogDescription = openGraph?.description ?? description;
  return {
    ...(title !== undefined ? { title } : {}),
    ...(description !== undefined ? { description } : {}),
    alternates: pageAlternates(lang, path),
    openGraph: {
      ...BASE_OPEN_GRAPH,
      url: localeUrl(lang, path),
      locale: OG_LOCALE[lang],
      alternateLocale: locales.filter((l) => l !== lang).map((l) => OG_LOCALE[l]),
      ...(ogTitle !== undefined ? { title: ogTitle } : {}),
      ...(ogDescription !== undefined ? { description: ogDescription } : {}),
    },
  };
}
