import Link from "next/link";
import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { posts } from "@/lib/posts";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/blog",
    title: "Blog",
    description:
      "Dated notes from the Agent Threat Rules project: new detection rules, campaign analysis, and public calls on where agent security is heading. Each one is open to scrutiny.",
  });
}

export default async function BlogIndexPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: rawLocale } = await params;
  const locale = (locales.includes(rawLocale as Locale) ? rawLocale : "en") as Locale;
  const zh = locale === "zh";

  return (
    <div className="pt-20 pb-20 px-6 md:px-14 max-w-[972px]">
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          Blog
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <h1 className="text-[32px] md:text-[48px] leading-[1.06] tracking-[-0.01em] font-medium text-ink">
          {zh ? "判斷，都留日期。" : "Calls, with dates."}
        </h1>
      </Reveal>
      <Reveal delay={0.1}>
        <p className="text-sm md:text-base text-graphite max-w-[640px] mt-5 md:mt-6 leading-[1.8]">
          {zh
            ? "新規則、攻擊活動分析，還有對 agent 安全走向的公開判斷。每一篇都標日期、附證據，隨時可以被檢驗。"
            : "New rules, campaign analysis, and public calls on where agent security is heading. Each one is dated, backed by evidence, and open to scrutiny."}
        </p>
      </Reveal>

      <div className="mt-12 grid grid-cols-1 gap-px bg-fog border border-fog">
        {posts.map((post, i) => (
          <Reveal key={post.slug} delay={0.15 + i * 0.05}>
            <Link
              href={`/${locale}/blog/${post.slug}`}
              className="block bg-paper p-5 md:p-6 hover:bg-ash transition-colors"
            >
              <div className="font-data text-xs text-mist mb-2">{post.date}</div>
              <div className="font-display text-base md:text-lg font-semibold text-ink mb-2 leading-snug">
                {zh ? post.title.zh : post.title.en}
              </div>
              <p className="text-sm text-stone leading-[1.7] mb-3">
                {zh ? post.summary.zh : post.summary.en}
              </p>
              <div className="flex flex-wrap gap-2">
                {post.atrRules.map((rule) => (
                  <span
                    key={rule}
                    className="font-data text-[11px] text-stone bg-ash px-1.5 py-0.5"
                  >
                    {rule}
                  </span>
                ))}
              </div>
            </Link>
          </Reveal>
        ))}
      </div>
    </div>
  );
}
