/* ATR home page, laid out as one drawing sheet: hero with the ATR plate,
 * a facts strip, public adoption, the category figure, reader routes, how a
 * rule is made, community, frameworks and the latest releases. Every figure
 * says what it counts; nothing animates. */
import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { loadSiteStats } from "@/lib/stats";
import { getSpecMeta } from "@/lib/spec-meta";
import { loadVersionLabels } from "@/lib/versions";
import { loadAllRules, categoryDisplayName } from "@/lib/rules";
import { rulesLanes } from "@/lib/lanes";
import { loadChangelog } from "@/lib/changelog";
import { posts } from "@/lib/posts";
import { loadAdopters, adopterLogoUrl } from "@/lib/adopters";
import { loadGithubContributors } from "@/lib/community";
import { START_ROUTES } from "@/lib/start-routes";
import { CATEGORY_DESC } from "@/lib/category-desc";
import { CATEGORY_ORDER } from "@/lib/docs-nav";
import { pageMetadata, SITE_NAME } from "@/lib/seo";
import { SheetRow, Eyebrow, ArrowButton, SolidButton, OutlineButton, FigureLabel } from "@/components/Sheet";
import { Plate } from "@/components/Plate";
import { CategoryRing } from "@/components/CategoryRing";
import { AdopterTabs, type AdopterItem } from "@/components/AdopterTabs";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  const stats = loadSiteStats();
  // No title: the home page keeps the root layout's default title.
  return pageMetadata({
    locale,
    path: "",
    openGraph: {
      title: SITE_NAME,
      description: `The open detection standard for AI agent threats. ${stats.ruleCount} effective rules, MIT licensed.`,
    },
  });
}

type B = { en: string; zh: string };

const REFERENCES = ["MITRE ATLAS", "OWASP Agentic", "OWASP LLM", "NIST AI RMF", "EU AI Act", "ISO/IEC 42001"];

const STEPS: ReadonlyArray<{ title: B; body: B; path: string }> = [
  { title: { en: "Threat observed", zh: "觀察到威脅" }, body: { en: "A CVE, an advisory, a red-team finding or a missed detection.", zh: "一個 CVE、公告、紅隊發現，或一次漏報。" }, path: "/threats" },
  { title: { en: "Technique named", zh: "命名技法" }, body: { en: "The attack is described once in the ATD technique catalog.", zh: "攻擊手法在 ATD 技法目錄裡描述一次。" }, path: "/atd" },
  { title: { en: "Rule written", zh: "撰寫規則" }, body: { en: "YAML with true-positive and true-negative test cases.", zh: "YAML，附正例與反例測試。" }, path: "/contribute" },
  { title: { en: "Gates passed", zh: "通過關卡" }, body: { en: "Schema, tests and a benign-corpus check, then human review.", zh: "格式、測試、良性語料檢查，再經人工審查。" }, path: "/quality-standard" },
  { title: { en: "Released", zh: "發布" }, body: { en: "Merged to main and published to npm under a permanent ID.", zh: "合併進 main，以永久 ID 發布到 npm。" }, path: "/changelog" },
];

export default async function Home({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const pick = (t: B) => (zh ? t.zh : t.en);

  const stats = loadSiteStats();
  const versions = await loadVersionLabels();
  const specVersion = getSpecMeta().specVersion;
  const rules = loadAllRules();
  const contributors = loadGithubContributors();
  const adopters = loadAdopters();
  // The first CHANGELOG heading can be "Unreleased", which has no date.
  const latestRelease = loadChangelog().find((e) => /^\d+\.\d+\.\d+/.test(e.version) && e.date);
  const latestPosts = [...posts].sort((a, b) => b.date.localeCompare(a.date)).slice(0, 2);

  const effectiveByCategory = new Map<string, number>();
  for (const r of rules) {
    if (rulesLanes(r).length > 0) effectiveByCategory.set(r.category, (effectiveByCategory.get(r.category) ?? 0) + 1);
  }
  // Fixed order and letters, the same as the docs sidebar and category pages.
  const categories = [...CATEGORY_ORDER];

  const adopterItems: AdopterItem[] = [...adopters.tierS, ...adopters.tier1, ...adopters.tier2]
    .filter((a) => a.status === "shipped")
    .slice(0, 6)
    .map((a) => ({ name: a.name, org: a.org, integration: a.integration, evidence: a.evidence, since: a.since, logo: adopterLogoUrl(a), tier: a.tier }));

  const facts = [
    { value: stats.ruleCount, label: zh ? "生效規則" : "Effective rules", note: zh ? `main 上 ${stats.ruleFileCount} 個檔，${stats.ruleInertCount} 條 inert` : `${stats.ruleFileCount} files on main, ${stats.ruleInertCount} inert` },
    { value: stats.laneCounts.enforce, label: zh ? "enforce lane 規則" : "Enforce-lane rules", note: zh ? "maturity stable，可開阻擋" : "maturity stable; run with blocking on" },
    { value: stats.categoryCount, label: zh ? "威脅類別" : "Threat categories", note: zh ? `規格 ${specVersion}` : `specification ${specVersion}` },
    { value: contributors?.length ?? "—", label: zh ? "GitHub 貢獻者" : "GitHub contributors", note: zh ? "人數，不含機器人" : "people, bots excluded" },
  ];

  return (
    <>
      {/* Hero */}
      <SheetRow grid className="min-h-[640px]">
        <div className="grid lg:grid-cols-[1fr_1fr] items-center gap-10 px-8 md:px-12 py-24 md:py-32">
          <div>
            <Eyebrow>{zh ? "ATR 開放標準" : "ATR open standard"}</Eyebrow>
            <h1 className="mt-5 text-[34px] md:text-[40px] leading-[1.15] tracking-[-0.02em] font-normal text-ink max-w-[520px] text-balance">
              {zh ? "AI 代理威脅的開放偵測標準。" : "The open detection standard for AI agent threats."}
            </h1>
            <p className="mt-4 text-[16px] leading-[1.55] text-ink/80 max-w-[460px] text-pretty">
              {zh
                ? "版本化、機器可讀的規則，每條都有永久 ID 與公開測試。任何符規引擎都能執行。MIT 授權，社群維護。"
                : "Versioned, machine-readable rules, each with a permanent ID and public tests. Any conforming engine can run them. MIT licensed, community maintained."}
            </p>
            <div className="mt-7 flex flex-wrap gap-2">
              <SolidButton href={`${prefix}/spec`}>{zh ? "閱讀規格" : "Read the specification"}</SolidButton>
              <OutlineButton href={`${prefix}/rules`}>{zh ? "瀏覽規則" : "Browse rules"}</OutlineButton>
            </div>
          </div>
          <div className="flex justify-center lg:justify-end lg:pr-6">
            <Plate specVersion={specVersion} ruleCount={stats.ruleCount} />
          </div>
        </div>
      </SheetRow>

      {/* Facts strip */}
      <SheetRow>
        <div className="px-8 md:px-12 pt-6 pb-2 flex items-center justify-between">
          <span className="text-[13px] text-stone">{zh ? "數字與口徑" : "Figures, and what each counts"}</span>
          <span className="font-data text-[10.5px] text-mist">{zh ? `截至 ${versions.generatedAt}` : `as of ${versions.generatedAt}`}</span>
        </div>
        <dl className="grid grid-cols-2 md:grid-cols-4 px-8 md:px-12 pb-8">
          {facts.map((f) => (
            <div key={f.label} className="pt-5 pr-6 border-t border-fog">
              <dd className="text-[34px] leading-none tracking-[-0.02em] text-ink tabular-nums">{f.value}</dd>
              <dt className="mt-3 text-[13px] text-ink">{f.label}</dt>
              <div className="mt-1 font-data text-[10.5px] text-stone leading-snug">{f.note}</div>
            </div>
          ))}
        </dl>
      </SheetRow>

      {/* Public adoption */}
      <SheetRow>
        <div className="px-8 md:px-12 pt-24 pb-10">
          <Eyebrow>{zh ? "公開採用" : "Adopted in public"}</Eyebrow>
          <h2 className="mt-4 text-[30px] leading-[1.2] tracking-[-0.015em] text-ink">{zh ? "整合進別人的程式碼" : "Integrated in other people's code"}</h2>
          <p className="mt-3 text-[15px] leading-[1.6] text-ink/75 max-w-[520px]">
            {zh
              ? "每一筆都來自 ADOPTERS.md，附公開證據。合併過的 PR 證明曾經整合，不代表今天仍在使用。"
              : "Every entry comes from ADOPTERS.md with public evidence. A merged pull request shows an integration happened; it does not prove it is still in use today."}
          </p>
        </div>
        <AdopterTabs items={adopterItems} locale={locale} />
      </SheetRow>

      {/* FIG. 02 coverage */}
      <SheetRow>
        <div className="grid lg:grid-cols-[1fr_1fr] gap-12 px-8 md:px-12 py-24">
          <div className="lg:sticky lg:top-36 self-start">
            <CategoryRing
              title={zh ? "威脅覆蓋" : "Threat coverage"}
              categories={categories.map((c) => categoryDisplayName(c, "en"))}
              references={REFERENCES}
            />
          </div>
          <div>
            <div className="text-[13px] text-stone">{zh ? "類別" : "Categories"}</div>
            <h2 className="mt-3 text-[30px] leading-[1.2] tracking-[-0.015em] text-ink">{zh ? "十個威脅類別" : "Ten threat categories"}</h2>
            <p className="mt-3 text-[15px] leading-[1.6] text-ink/75">
              {zh
                ? "每條規則屬於一個類別，並標出它回應的框架條目。對照是 ATR 自己的文件，不是框架方的背書，也不是合規保證。"
                : "Every rule belongs to one category and names the framework items it answers to. Mappings are ATR's own documents: not endorsements by the framework owners, and not a compliance guarantee."}
            </p>
            <ol className="mt-8">
              {categories.map((c, i) => (
                <li key={c} className="py-5 border-t border-fog">
                  <div className="flex items-baseline justify-between gap-4">
                    <h3 className="text-[16px] text-ink">
                      <span className="font-data text-[12px] text-stone mr-2">{String.fromCharCode(65 + i)}.</span>
                      <Link href={`${prefix}/docs/categories/${c}`} className="hover:underline underline-offset-4">{categoryDisplayName(c, locale)}</Link>
                    </h3>
                    <span className="font-data text-[10.5px] text-stone whitespace-nowrap">
                      {effectiveByCategory.get(c) ?? 0} {zh ? "條生效" : "effective"}
                    </span>
                  </div>
                  <p className="mt-1.5 text-[13.5px] leading-[1.6] text-ink/70">{pick(CATEGORY_DESC[c])}</p>
                </li>
              ))}
            </ol>
            <div className="pt-5 border-t border-fog flex justify-end">
              <ArrowButton href={`${prefix}/rules`}>{zh ? "看全部規則" : "View all rules"}</ArrowButton>
            </div>
          </div>
        </div>
      </SheetRow>

      {/* Reader routes */}
      <SheetRow>
        <div className="px-8 md:px-12 pt-24 pb-10">
          <Eyebrow>{zh ? "從這裡開始" : "Start here"}</Eyebrow>
          <h2 className="mt-4 text-[30px] leading-[1.2] tracking-[-0.015em] text-ink">{zh ? "你為什麼來？" : "What brings you to ATR?"}</h2>
        </div>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 border-t border-fog">
          {START_ROUTES.map((route) => (
            <div key={route.key} className="p-8 border-b border-r border-fog lg:[&:nth-child(3n)]:border-r-0 flex flex-col min-h-[220px] bg-white/40">
              <h3 className="text-[17px] text-ink">{pick(route.title)}</h3>
              <p className="mt-2 text-[13.5px] leading-[1.6] text-ink/70 flex-1">{pick(route.body)}</p>
              <div className="mt-6 flex flex-wrap gap-2">
                {route.links.map((link, i) =>
                  i === 0 ? (
                    <ArrowButton key={link.href} href={`${prefix}${link.href}`}>{pick(link.label)}</ArrowButton>
                  ) : (
                    <Link key={link.href} href={`${prefix}${link.href}`} className="inline-flex items-center text-[12.5px] px-3 py-2 border border-fog bg-white hover:border-ink">
                      {pick(link.label)}
                    </Link>
                  ),
                )}
              </div>
            </div>
          ))}
        </div>
      </SheetRow>

      {/* FIG. 03 how a rule is made */}
      <SheetRow>
        <div className="px-8 md:px-12 pt-24 pb-24">
          <div className="flex items-end justify-between gap-6 flex-wrap">
            <div>
              <Eyebrow>{zh ? "方法" : "Method"}</Eyebrow>
              <h2 className="mt-4 text-[30px] leading-[1.2] tracking-[-0.015em] text-ink">{zh ? "一條規則怎麼誕生" : "How a rule is made"}</h2>
            </div>
            <FigureLabel fig="03" title={zh ? "規則生命週期" : "Rule lifecycle"} />
          </div>
          <ol className="mt-10 grid md:grid-cols-5 border border-fog bg-white/50">
            {STEPS.map((step, i) => (
              <li key={step.path + i} className="p-5 border-b md:border-b-0 md:border-r border-fog last:border-r-0 last:border-b-0 relative">
                <div className="font-data text-[11px] text-mist">{String(i + 1).padStart(2, "0")}</div>
                <Link href={`${prefix}${step.path}`} className="block mt-3 text-[15px] text-ink hover:underline underline-offset-4">{pick(step.title)}</Link>
                <p className="mt-2 text-[13px] leading-[1.6] text-ink/70">{pick(step.body)}</p>
              </li>
            ))}
          </ol>
        </div>
      </SheetRow>

      {/* Community */}
      <SheetRow grid>
        <div className="grid lg:grid-cols-[1fr_1fr] gap-12 px-8 md:px-12 py-24 items-center">
          <div>
            <Eyebrow>{zh ? "社群" : "Community"}</Eyebrow>
            <h2 className="mt-4 text-[30px] leading-[1.2] tracking-[-0.015em] text-ink">{zh ? "由維護它的人決定" : "Kept by the people who maintain it"}</h2>
            <p className="mt-3 text-[15px] leading-[1.6] text-ink/75 max-w-[480px]">
              {zh
                ? "任何人都能提 issue 與 pull request。專家為覆蓋優先順序與框架對照提供意見，貢獻者撰寫與審查規則。"
                : "Anyone can open issues and pull requests. Experts advise on coverage priorities and crosswalks; contributors write and review rules."}
            </p>
            <div className="mt-7 flex flex-wrap gap-2">
              <SolidButton href={`${prefix}/community/join`}>{zh ? "加入社群" : "Join the community"}</SolidButton>
              <OutlineButton href={`${prefix}/community`}>{zh ? "看成員" : "See the people"}</OutlineButton>
            </div>
          </div>
          {contributors && contributors.length > 0 && (
            <ul className="grid grid-cols-4 sm:grid-cols-6 gap-px bg-fog border border-fog">
              {contributors.slice(0, 12).map((c) => (
                <li key={c.login} className="bg-paper aspect-square">
                  <a href={c.profile} target="_blank" rel="noopener noreferrer" title={c.login} className="block w-full h-full">
                    {c.avatar && <img src={`${c.avatar}&s=160`} alt={c.login} className="w-full h-full object-cover grayscale hover:grayscale-0 transition" loading="lazy" />}
                  </a>
                </li>
              ))}
            </ul>
          )}
        </div>
      </SheetRow>

      {/* Frameworks */}
      <SheetRow>
        <div className="px-8 md:px-12 pt-16 pb-6 flex items-end justify-between gap-6 flex-wrap">
          <div>
            <Eyebrow>{zh ? "框架對照" : "Crosswalks"}</Eyebrow>
            <h2 className="mt-4 text-[30px] leading-[1.2] tracking-[-0.015em] text-ink">{zh ? "接到你要回報的框架" : "Wired to the frameworks you report against"}</h2>
          </div>
          <ArrowButton href={`${prefix}/coverage`}>{zh ? "看框架對照" : "View crosswalks"}</ArrowButton>
        </div>
        <ul className="grid grid-cols-2 md:grid-cols-6 border-t border-fog">
          {REFERENCES.map((ref) => (
            <li key={ref} className="py-6 px-4 border-r border-fog last:border-r-0 text-center font-data text-[11px] tracking-[0.1em] uppercase text-stone">
              {ref}
            </li>
          ))}
        </ul>
      </SheetRow>

      {/* Latest */}
      <SheetRow>
        <div className="px-8 md:px-12 pt-16 pb-6">
          <Eyebrow>{zh ? "最新" : "Latest"}</Eyebrow>
        </div>
        <div className="grid md:grid-cols-3 border-t border-fog">
          {latestRelease && (
            <Link href={`${prefix}/changelog`} className="p-8 border-b md:border-b-0 md:border-r border-fog hover:bg-white/60 transition-colors">
              <div className="font-data text-[11px] text-mist">{latestRelease.date} · {zh ? "發版" : "Release"}</div>
              <div className="mt-3 text-[18px] text-ink">v{latestRelease.version}</div>
              <div className="mt-2 font-data text-[11px] text-stone">{versions.npmVerified ? `npm ${versions.npm}` : `package.json ${versions.npm}`}</div>
            </Link>
          )}
          {latestPosts.map((post) => (
            <Link key={post.slug} href={`${prefix}/blog/${post.slug}`} className="p-8 border-b md:border-b-0 md:border-r border-fog last:border-r-0 hover:bg-white/60 transition-colors">
              <div className="font-data text-[11px] text-mist">{post.date} · {zh ? "文章" : "Note"}</div>
              <div className="mt-3 text-[15px] leading-snug text-ink line-clamp-3">{pick(post.title)}</div>
            </Link>
          ))}
        </div>
      </SheetRow>
    </>
  );
}
