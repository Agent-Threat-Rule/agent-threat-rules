import type { Locale } from "@/lib/i18n";
import { locales } from "@/lib/i18n";
import { Nav } from "@/components/Nav";
import { Footer } from "@/components/Footer";
import { HtmlLang } from "@/components/HtmlLang";
import { ScrollProgress } from "@/components/ScrollProgress";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export default async function LocaleLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ locale: string }>;
}) {
  const { locale } = await params;
  const lang = (locales.includes(locale as Locale) ? locale : "en") as Locale;

  return (
    <>
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[100] focus:bg-blue focus:text-white focus:px-4 focus:py-2 focus:rounded-sm focus:text-sm focus:font-semibold"
      >
        Skip to content
      </a>
      <HtmlLang locale={lang} />
      <ScrollProgress />
      <Nav locale={lang} />
      <main id="main-content" className="flex-1">{children}</main>
      <Footer locale={lang} />
    </>
  );
}
