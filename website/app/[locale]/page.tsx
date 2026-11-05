/* ATR home page. Hero: three agent sessions with ATR's real verdicts. Then
 * who has merged ATR, why it matters now, how one real incident became a
 * rule, what the rules cover, the frameworks they map to, the three tools,
 * where to start, and the latest. Every number is read at build time. */
import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { loadSiteStats } from "@/lib/stats";
import { getSpecMeta } from "@/lib/spec-meta";
import { loadAdopters } from "@/lib/adopters";
import { loadAllRules, loadRuleDetail, categoryDisplayName } from "@/lib/rules";
import { rulesLanes, type Lane } from "@/lib/lanes";
import { loadCrosswalks } from "@/lib/crosswalks";
import { loadChangelog } from "@/lib/changelog";
import { posts } from "@/lib/posts";
import { CATEGORY_DESC } from "@/lib/category-desc";
import { CATEGORY_ORDER } from "@/lib/docs-nav";
import { pageMetadata, SITE_NAME } from "@/lib/seo";
import { SheetRow } from "@/components/Sheet";
import { CategoryFrieze } from "@/components/classical/CategoryFrieze";
import { Emblem, Meander, Seal } from "@/components/classical/Emblem";
import { CATEGORY_EMBLEM, type EmblemName } from "@/lib/emblems";
import { AgentConsole } from "@/components/home/AgentConsole";
import { RuleBirth, type BirthRule } from "@/components/home/RuleBirth";
import { AdoptGuide } from "@/components/AdoptGuide";
import { TOOLS } from "@/lib/adopt-guide";
import { clauses } from "@/lib/clauses";

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
      description: `Open security rules for AI agents. ${stats.ruleCount} effective rules, MIT licensed.`,
    },
  });
}

type B = { en: string; zh: string };

// The rule the "how a rule is born" section follows, from incident to release.
const BIRTH_RULE = "ATR-2026-02403";
// Fixed historical dates for that rule, all UTC:
// - reported: the Manifold Security report date cited in the rule file itself.
// - mergedToMain: GitHub mergedAt of Agent-Threat-Rule/agent-threat-rules#390, the
//   PR that added the rule file (git log --diff-filter=A: commit 0d12b20).
// - firstNpm: the first npm release whose tarball contains the file (3.5.11 does
//   not, 3.5.12 does), dated by `npm view agent-threat-rules time`.
const BIRTH_REPORTED = "2026-07-22";
const BIRTH_MERGED_TO_MAIN = "2026-08-03";
const BIRTH_FIRST_NPM = { version: "3.5.12", date: "2026-08-11" };

const DAY_MS = 24 * 60 * 60 * 1000;
function daysBetween(from: string, to: string): number {
  return Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / DAY_MS);
}

function laneSentence(lanes: ReadonlyArray<Lane>, maturity: string, zh: boolean): string {
  if (lanes.length === 0) return zh ? "它目前不在任何偵測車道裡。" : "No detection lane loads it today.";
  const list = lanes.join(zh ? "、" : " and ");
  if (lanes.includes("enforce")) {
    return zh ? `它的成熟度是 ${maturity}，${list} 車道都會載入。` : `Its maturity is ${maturity}, so the ${list} lanes load it.`;
  }
  return zh
    ? `它的成熟度是 ${maturity}，所以只在 ${list} 車道裡跑，enforce 車道不會載入。`
    : `Its maturity is ${maturity}, so it runs in the ${list} lanes and the enforce lane does not load it.`;
}

// Individual maintainers listed in ADOPTERS.md; the strip names organisations.
const INDIVIDUALS = new Set(["Independent", "Ajay Nyayapathi"]);

const REFERENCES = ["MITRE ATLAS", "OWASP Agentic", "OWASP LLM", "NIST AI RMF", "EU AI Act", "ISO/IEC 42001"];

const H2 = "text-[32px] md:text-[44px] leading-[1.12] tracking-[-0.03em] font-medium text-ink";
const KICKER = "text-[13px] text-stone";
const BUTTON = "inline-flex items-center h-11 px-5 text-[14px] transition-colors";
const TEXT_LINK = "text-[14px] text-ink underline underline-offset-[6px] decoration-2 hover:decoration-ink";

function shortOrg(org: string) {
  return org.replace(/\s*\(.*\)\s*$/, "").replace(/^CNCF \/ /, "");
}

export default async function Home({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const pick = (t: B) => (zh ? t.zh : t.en);
  const title = (text: string) => (zh ? clauses(text) : text);

  const stats = loadSiteStats();
  const specVersion = getSpecMeta().specVersion;
  const rules = loadAllRules();
  const adopters = loadAdopters();
  const crosswalks = loadCrosswalks().filter((c) => c.published);
  const latestRelease = loadChangelog().find((e) => /^\d+\.\d+\.\d+/.test(e.version) && e.date);
  const latestPosts = [...posts].sort((a, b) => b.date.localeCompare(a.date)).slice(0, 2);

  const shipped = [...adopters.tierS, ...adopters.tier1, ...adopters.tier2].filter((a) => a.status === "shipped");
  const orgs = [...new Set(shipped.map((a) => shortOrg(a.org)).filter((o) => !INDIVIDUALS.has(o)))];

  const effectiveByCategory = new Map<string, number>();
  for (const r of rules) {
    if (rulesLanes(r).length > 0) effectiveByCategory.set(r.category, (effectiveByCategory.get(r.category) ?? 0) + 1);
  }
  const categories = [...CATEGORY_ORDER];

  const detail = loadRuleDetail(BIRTH_RULE);
  const birth: BirthRule | null = detail
    ? {
        id: detail.id,
        title: detail.title,
        severity: detail.severity,
        maturity: detail.maturity ?? "",
        category: detail.category,
        date: detail.date.replace(/\//g, "-"),
        truePositives: detail.truePositives.length,
        trueNegatives: detail.trueNegatives.length,
        mappings: [...detail.owaspAgentic, ...detail.owaspLlm, ...detail.mitreAtlas.map((m) => m.split(" - ")[0])],
        reported: BIRTH_REPORTED,
        mergedToMain: BIRTH_MERGED_TO_MAIN,
        firstNpmVersion: BIRTH_FIRST_NPM.version,
        firstNpmDate: BIRTH_FIRST_NPM.date,
      }
    : null;
  const birthLanes = detail ? rulesLanes({ status: detail.status, maturity: detail.maturity }) : [];

  const figures: Array<[string, string]> = [
    [String(stats.ruleCount), zh ? "條生效規則" : "effective rules"],
    [String(stats.categoryCount), zh ? "個威脅類別" : "threat categories"],
    [String(orgs.length), zh ? "個組織合併過" : "organisations have merged it"],
    [specVersion, zh ? "規格版本" : "specification"],
    ["MIT", zh ? "授權，免費" : "licence, free"],
  ];

  return (
    <>
      {/* Hero */}
      <SheetRow>
        <div className="grid lg:grid-cols-[1fr_1.08fr] gap-12 lg:gap-14 items-center px-6 md:px-14 pt-14 md:pt-20 pb-16">
          <div className="min-w-0">
            <div className={`${KICKER} flex items-center gap-2`}>
              <span className="w-2 h-2 bg-brand" aria-hidden="true" />
              {zh ? "開放標準 · Agent Threat Rules" : "Open standard · Agent Threat Rules"}
            </div>
            <h1 className="mt-6 text-[42px] sm:text-[54px] lg:text-[62px] leading-[1.05] tracking-[-0.035em] font-medium text-ink">
              {zh ? <>AI agent 的<br />資安規則。</> : <>Security rules<br />for AI agents.</>}
            </h1>
            <p className="mt-6 text-[17px] leading-[1.7] text-graphite max-w-[500px] text-pretty">
              {zh
                ? "agent 會讀網頁、收信、裝工具，也會照著裡面藏的指令做事。ATR 把有紀錄的攻擊寫成規則，每條都有編號、有測試。規則在你自己的環境裡跑，比對到就回報。誰都能用。"
                : "Agents read web pages, open mail and install tools, and they follow instructions hidden inside them. ATR writes documented attacks down as rules, each with an ID and tests. The rules run in your own environment and report what they match. Anyone can use them."}
            </p>
            <div className="mt-8 flex flex-wrap gap-2">
              <Link href={`${prefix}/start`} className={`${BUTTON} bg-ink text-white hover:bg-black`}>{zh ? "從這裡開始" : "Start here"}</Link>
              <Link href={`${prefix}/rules`} className={`${BUTTON} border border-fog bg-white text-ink hover:border-ink`}>{zh ? "看全部規則" : "Browse the rules"}</Link>
            </div>
          </div>
          <AgentConsole locale={locale} ruleCount={stats.ruleCount} />
        </div>
        <dl className="grid grid-cols-2 sm:grid-cols-5 border-t border-fog">
          {figures.map(([value, label], i) => (
            <div key={label} className={`px-6 md:px-8 py-5 border-fog ${i > 0 ? "sm:border-l" : ""} ${i % 2 === 1 ? "border-l sm:border-l" : ""} ${i >= 2 ? "border-t sm:border-t-0" : ""}`}>
              <dt className="sr-only">{label}</dt>
              <dd className="text-[24px] tracking-[-0.02em] text-ink tabular-nums">{value}</dd>
              <dd className="mt-0.5 text-[12.5px] text-stone">{label}</dd>
            </div>
          ))}
        </dl>
      </SheetRow>

      {/* Who has merged it */}
      <SheetRow>
        <div className="px-6 md:px-14 py-10">
          <div className="flex flex-wrap items-baseline justify-between gap-4">
            <div className={KICKER}>{zh ? "這些組織的維護者審過之後，合併了 ATR" : "Maintainers at these organisations reviewed ATR and merged it"}</div>
            <Link href={`${prefix}/ecosystem`} className="text-[13px] text-ink hover:underline underline-offset-4">{zh ? "每一筆的合併紀錄 →" : "Every merge, with evidence →"}</Link>
          </div>
          <ul className="mt-6 flex flex-wrap items-center gap-x-10 gap-y-4">
            {orgs.map((o) => (
              <li key={o} className="text-[19px] md:text-[21px] tracking-[-0.01em] text-ink/70 whitespace-nowrap">{o}</li>
            ))}
          </ul>
        </div>
      </SheetRow>

      {/* Why now */}
      <SheetRow>
        <div className="px-6 md:px-14 py-24 md:py-32 grid lg:grid-cols-[1fr_1.15fr] gap-10 lg:gap-20">
          <div>
            <div className={KICKER}>{zh ? "為什麼是現在" : "Why now"}</div>
            <h2 className={`mt-4 ${H2}`}>{title(zh ? "以前，我們有幾十年，可以慢慢來。" : "We used to have decades.")}</h2>
          </div>
          <div className="space-y-5 text-[17px] md:text-[18px] leading-[1.8] text-graphite max-w-[600px]">
            <p>
              {zh
                ? "飛機發明四十年後，各國才坐下來訂出共同的航空規則。軟體漏洞有了全世界通用的編號，是網路普及之後的事。每一次，我們都等得起。"
                : "Forty years passed between the first powered flight and the treaty that gave the world common rules for flying. Software flaws got shared numbers only after the internet was everywhere. Each time, we could afford to wait."}
            </p>
            <p>
              {zh
                ? "agent 不一樣。模型幾個禮拜就換一代，agent 已經在醫院、銀行、公家機關裡做事。攻擊傳得很快，防守的人之間，還在寄信、開會、等報告。"
                : "Agents are different. Models turn over in weeks, and agents already work in hospitals, banks and government offices. Attacks spread fast. Defenders are still trading emails and waiting on reports."}
            </p>
            <p className="text-ink">
              {zh
                ? "ATR 做的事情很小：把有紀錄的攻擊寫下來，讓下一個人認得出同一招。"
                : "What ATR does is small. It writes down attacks that have been documented, so the next person can spot the same trick."}
            </p>
          </div>
        </div>
      </SheetRow>

      {/* How a rule is born */}
      {birth && (
        <SheetRow>
          <div className="px-6 md:px-14 pt-24 md:pt-28 pb-24">
            <div className={KICKER}>{zh ? "一條規則怎麼來" : "How a rule is made"}</div>
            <h2 className={`mt-4 ${H2} max-w-[820px]`}>{title(zh ? "一個人碰到的攻擊，變成所有人的規則。" : "One team's incident becomes everyone's rule.")}</h2>
            <p className="mt-5 text-[16px] leading-[1.75] text-graphite max-w-[620px]">
              {zh
                ? `以 ${birth.id} 為例：事件在 ${birth.reported} 被回報，規則日期是 ${birth.date}。${birth.mergedToMain} 合進 main，${birth.firstNpmDate} 跟著 npm ${birth.firstNpmVersion} 發出。從回報到使用者裝得到，花了 ${daysBetween(birth.reported, birth.firstNpmDate)} 天。`
                : `Take ${birth.id}. The incident was reported on ${birth.reported} and the rule is dated ${birth.date}. It reached main on ${birth.mergedToMain} and shipped on npm in ${birth.firstNpmVersion} on ${birth.firstNpmDate}: ${daysBetween(birth.reported, birth.firstNpmDate)} days from report to users.`}{" "}
              {laneSentence(birthLanes, birth.maturity, zh)}
            </p>
            <div className="mt-12">
              <RuleBirth locale={locale} rule={birth} />
            </div>
          </div>
        </SheetRow>
      )}

      {/* Coverage */}
      <SheetRow>
        <div className="px-6 md:px-14 py-24 md:py-28">
          <div className={KICKER}>{zh ? "涵蓋範圍" : "Coverage"}</div>
          <h2 className={`mt-4 ${H2} max-w-[820px]`}>{title(zh ? "有紀錄的攻擊，就有名字。" : "A documented attack gets a name.")}</h2>
          <p className="mt-5 text-[16px] leading-[1.75] text-graphite max-w-[620px]">
            {zh ? "十個類別，從被下毒的工具說明，到被悄悄換掉的目標。每一格都連到該類別的規則。" : "Ten categories, from a poisoned tool description to a goal quietly swapped for another. Each panel opens the rules in its category."}
          </p>
          <div className="mt-12">
            <CategoryFrieze
              countLabel={zh ? "條規則" : "rules"}
              inscription={REFERENCES}
              items={categories.map((c, i) => ({
                key: c,
                letter: String.fromCharCode(65 + i),
                name: categoryDisplayName(c, locale),
                desc: pick(CATEGORY_DESC[c]),
                count: effectiveByCategory.get(c) ?? 0,
                href: `${prefix}/docs/categories/${c}`,
                emblem: CATEGORY_EMBLEM[c] ?? "aspis",
              }))}
            />
          </div>
        </div>
      </SheetRow>

      {/* Crosswalks */}
      <SheetRow>
        <div className="px-6 md:px-14 py-24 md:py-28">
          <div className={KICKER}>{zh ? "框架對照" : "Crosswalks"}</div>
          <h2 className={`mt-4 ${H2} max-w-[820px]`}>{title(zh ? "一條規則，對到你要交代的每一份框架。" : "One rule, mapped to the frameworks you answer to.")}</h2>
          <div className="mt-14 grid lg:grid-cols-[380px_1fr] gap-10 lg:gap-0 items-center">
            {birth && (
              <div className="relative bg-white border border-ink p-5 lg:mr-12">
                <div className="font-data text-[12px] text-brand-ink">{birth.id}</div>
                <div className="mt-1 text-[14px] leading-snug text-ink">{birth.title}</div>
                <ul className="mt-4 flex flex-wrap gap-1.5">
                  {birth.mappings.map((m) => (
                    <li key={m} className="font-data text-[10.5px] px-1.5 py-0.5 border border-fog text-graphite">{m}</li>
                  ))}
                  <li className="font-data text-[10.5px] px-1.5 py-0.5 border border-fog text-graphite">EU AI Act Art. 14, 15</li>
                  <li className="font-data text-[10.5px] px-1.5 py-0.5 border border-fog text-graphite">NIST AI RMF Map · Measure · Manage</li>
                </ul>
                <span className="hidden lg:block absolute top-1/2 -right-12 w-12 h-px bg-ink" aria-hidden="true" />
              </div>
            )}
            <ul className="relative lg:border-l lg:border-ink grid sm:grid-cols-2 gap-x-8">
              {crosswalks.map((c) => (
                <li key={c.slug} className="relative lg:pl-8">
                  <span className="hidden lg:block absolute left-0 top-1/2 w-5 h-px bg-fog" aria-hidden="true" />
                  <Link href={`${prefix}/docs/crosswalks/${c.slug}`} className="block py-3 border-b border-fog group">
                    <span className="block text-[11.5px] text-stone">{c.owner}</span>
                    <span className="block text-[14px] text-ink group-hover:underline underline-offset-4">{c.framework}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
          <p className="mt-6 text-[12.5px] text-stone">
            {zh ? "左邊的對照取自規則檔本身；右邊每一份對照文件都公開在 repository 裡。部分對應已知有誤、正在重做，修正前只能當作參考，不能當稽核證據。" : "The mappings on the left come from the rule file itself. Each crosswalk on the right is a public document in the repository. Some mappings are known to be wrong and are being redone; until then treat them as a reference, not audit evidence."}{" "}
            <Link href={`${prefix}/errata`} className="underline underline-offset-4 hover:text-ink">{zh ? "看勘誤" : "See the errata"}</Link>
          </p>
        </div>
      </SheetRow>

      {/* Three tools */}
      <SheetRow>
        <div className="px-6 md:px-14 pt-24 md:pt-28 pb-12">
          <div className={KICKER}>{zh ? "三件工具" : "Three tools"}</div>
          <h2 className={`mt-4 ${H2}`}>{title(zh ? "認出攻擊，挑對測試，再把它證明出來。" : "Spot the attack, pick the tests, prove it.")}</h2>
        </div>
        <ul className="grid md:grid-cols-3 border-t border-fog">
          {(["rules", "router", "eval"] as const).map((key, i) => {
            const tool = TOOLS[key];
            return (
              <li key={key} className={`border-fog ${i > 0 ? "border-t md:border-t-0 md:border-l" : ""}`}>
                <Link href={`${prefix}${tool.href}`} className="group flex flex-col h-full p-6 md:p-8 hover:bg-ash/50 transition-colors">
                  <div className="relative h-[170px] mb-6 flex items-center justify-center">
                    <div className="absolute inset-0 grid-paper grid-paper-fade" aria-hidden="true" />
                    <ToolGlyph kind={key} />
                  </div>
                  <div className="flex items-baseline justify-between gap-3">
                    <span className="text-[17px] text-ink">{tool.name}</span>
                    <span className={`text-[11.5px] ${tool.released ? "text-brand-ink" : "text-alert-ink"}`}>{tool.released ? (zh ? "已發布" : "Released") : zh ? "尚未公開" : "Not yet public"}</span>
                  </div>
                  <p className="mt-2 text-[15px] text-ink">{pick(tool.line)}</p>
                  <p className="mt-1.5 text-[14px] leading-[1.65] text-graphite flex-1">{pick(tool.body)}</p>
                  <span className="mt-5 text-[13px] text-ink group-hover:underline underline-offset-4">{zh ? "了解更多 →" : "Learn more →"}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      </SheetRow>

      {/* Where to start */}
      <SheetRow>
        <div className="px-6 md:px-14 py-24 md:py-28">
          <div className={KICKER}>{zh ? "怎麼採用" : "Adopting ATR"}</div>
          <h2 className={`mt-4 mb-12 ${H2}`}>{title(zh ? "從哪裡開始，看你是誰。" : "Where you start depends on who you are.")}</h2>
          <AdoptGuide locale={locale} />
        </div>
      </SheetRow>

      {/* Latest */}
      <SheetRow>
        <div className="px-6 md:px-14 pt-24 pb-8 flex items-end justify-between gap-6">
          <div>
            <div className={KICKER}>{zh ? "最新" : "Latest"}</div>
            <h2 className={`mt-4 ${H2}`}>{zh ? "最近發生的事" : "Recent work"}</h2>
          </div>
          <Link href={`${prefix}/blog`} className="text-[13px] text-ink hover:underline underline-offset-4 whitespace-nowrap">{zh ? "全部文章 →" : "All posts →"}</Link>
        </div>
        <div className="grid md:grid-cols-3 gap-6 px-6 md:px-14 pb-24">
          {latestRelease && (
            <Link href={`${prefix}/changelog`} className="group">
              <Thumb emblem="laurel" wreath label={`v${latestRelease.version}`} />
              <div className="mt-4 text-[15px] leading-snug text-ink group-hover:underline underline-offset-4">{zh ? `版本 ${latestRelease.version} 發布` : `Release ${latestRelease.version}`}</div>
              <div className="mt-1 font-data text-[11px] text-stone">{zh ? "發版" : "Release"} · {latestRelease.date}</div>
            </Link>
          )}
          {latestPosts.map((post) => (
            <Link key={post.slug} href={`${prefix}/blog/${post.slug}`} className="group">
              <Thumb emblem={post.atrRules[0] ? "stele" : "scroll"} label={post.atrRules[0] ?? (zh ? "文章" : "Note")} />
              <div className="mt-4 text-[15px] leading-snug text-ink line-clamp-2 group-hover:underline underline-offset-4">{pick(post.title)}</div>
              <div className="mt-1 font-data text-[11px] text-stone">{zh ? "文章" : "Note"} · {post.date}</div>
            </Link>
          ))}
        </div>
      </SheetRow>

      {/* Close */}
      <SheetRow>
        <div className="relative overflow-hidden px-6 md:px-14 py-24 md:py-32">
          <div className="absolute inset-0 grid-paper opacity-60 pointer-events-none" aria-hidden="true" />
          <div className="absolute inset-x-0 bottom-0 h-2/3 bg-gradient-to-t from-brand-tint to-transparent pointer-events-none" aria-hidden="true" />
          <div className="relative">
            <p className="text-[28px] md:text-[40px] leading-[1.25] tracking-[-0.025em] text-ink max-w-[820px] text-balance">
              {title(zh ? "ATR 永遠免費、開放。沒有一條規則能用錢買進來。" : "ATR is free and open, for good. No rule can be bought into it.")}
            </p>
            <div className="mt-10 flex flex-wrap items-center gap-2">
              <Link href={`${prefix}/start`} className={`${BUTTON} bg-ink text-white hover:bg-black`}>{zh ? "從這裡開始" : "Start here"}</Link>
              <Link href={`${prefix}/community/join`} className={`${BUTTON} border border-fog bg-white text-ink hover:border-ink`}>{zh ? "加入社群" : "Join the community"}</Link>
              <Link href={`${prefix}/contribute`} className={`ml-2 ${TEXT_LINK} decoration-brand`}>{zh ? "寫一條規則" : "Write a rule"}</Link>
            </div>
          </div>
        </div>
      </SheetRow>
    </>
  );
}

/** Card image for the latest items: an engraved emblem framed by two Greek-key bands. */
function Thumb({ emblem, label, wreath = false }: { emblem: EmblemName; label: string; wreath?: boolean }) {
  return (
    <div className="relative aspect-[16/10] bg-white border border-fog overflow-hidden flex flex-col">
      <Meander className="text-fog" height={10} />
      <div className="relative flex-1 flex flex-col items-center justify-center gap-3">
        <div className="absolute inset-0 grid-paper grid-paper-fade opacity-60" aria-hidden="true" />
        {wreath ? (
          <div className="relative flex items-center justify-center">
            <Emblem name="laurel" size={124} stroke={1.05} className="text-graphite" />
            <span className="absolute pb-2 text-[19px] tracking-[-0.02em] text-ink">{label}</span>
          </div>
        ) : (
          <>
            <Emblem name={emblem} size={64} stroke={1.15} className="relative text-ink" />
            <span className="relative font-data text-[12.5px] text-ink">{label}</span>
          </>
        )}
      </div>
      <div className="rotate-180">
        <Meander className="text-fog" height={10} />
      </div>
    </div>
  );
}

const TOOL_EMBLEM: Record<"rules" | "router" | "eval", EmblemName> = { rules: "stele", router: "labyrinth", eval: "scales" };

/** An engraved emblem for each tool card: the rule tablet, the labyrinth, the scales. */
function ToolGlyph({ kind }: { kind: "rules" | "router" | "eval" }) {
  return <Seal name={TOOL_EMBLEM[kind]} size={136} className="relative text-ink" />;
}
