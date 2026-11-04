import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadGithubContributors, loadMembers } from "@/lib/community";
import { SectionHead } from "@/components/SectionHead";
import { SheetRow } from "@/components/Sheet";
import { MemberDirectory } from "./MemberDirectory";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/community",
    title: locale === "zh" ? "社群" : "Community",
    description:
      locale === "zh"
        ? "維護 ATR 的人：Steering、專家與貢獻者，以及 GitHub 上的貢獻紀錄。"
        : "The people who maintain ATR: steering, experts and contributors, and the contributions GitHub records.",
  });
}

const DISCUSSIONS = "https://github.com/Agent-Threat-Rule/agent-threat-rules/discussions";

const WORKING_GROUPS: ReadonlyArray<{ name: { en: string; zh: string }; scope: { en: string; zh: string } }> = [
  {
    name: { en: "Rule quality and evasion", zh: "規則品質與繞過" },
    scope: { en: "Red-team the rules, report bypasses and false positives, and tighten the rules that cause them.", zh: "對規則做紅隊測試、回報繞過與誤判，並收窄造成誤判的規則。" },
  },
  {
    name: { en: "Framework crosswalks", zh: "框架對照" },
    scope: { en: "Map OWASP, MITRE ATLAS, NIST AI RMF, EU AI Act and ISO/IEC 42001 item by item, with a gap column.", zh: "逐條對照 OWASP、MITRE ATLAS、NIST AI RMF、EU AI Act 與 ISO/IEC 42001，附缺口欄。" },
  },
  {
    name: { en: "Engine conformance", zh: "引擎符規" },
    scope: { en: "Keep the conformance suite honest across engines and languages.", zh: "讓符規測試套件在不同引擎與語言之間都站得住。" },
  },
];

const CADENCE: ReadonlyArray<{ when: { en: string; zh: string }; what: { en: string; zh: string } }> = [
  { when: { en: "Monthly", zh: "每月" }, what: { en: "A written community update in GitHub Discussions, also sent by email to members.", zh: "一則書面社群更新，發在 GitHub Discussions，並寄給成員。" } },
  { when: { en: "Quarterly", zh: "每季" }, what: { en: "A coverage-priorities survey. Results are published and cited in the release notes.", zh: "一次「優先覆蓋」問卷，結果公開，並寫進版本說明。" } },
  { when: { en: "Every release", zh: "每次發版" }, what: { en: "Contributors are named in the release notes and on the rules they wrote.", zh: "版本說明與規則頁點名貢獻者。" } },
  { when: { en: "Optional", zh: "選擇性" }, what: { en: "An open call when there is something to decide live. Decisions are written back to GitHub.", zh: "有需要即時討論的事才開線上會議；決定一律寫回 GitHub。" } },
];

export default async function CommunityPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const pick = (t: { en: string; zh: string }) => (zh ? t.zh : t.en);
  const members = loadMembers();
  const contributors = loadGithubContributors();

  return (
    <>
      <SheetRow grid>
      <section className="grid lg:grid-cols-[1.3fr_1fr] gap-12 px-8 md:px-12 pt-24 pb-20">
        <div>
          <div className="font-data text-[11px] uppercase tracking-[0.1em] text-stone mb-6">{zh ? "社群" : "Community"}</div>
          <h1 className="text-[40px] md:text-[48px] leading-[1.1] tracking-[-0.02em] font-medium text-ink max-w-[620px] text-balance">
            {zh ? "維護 ATR 的人" : "The people who maintain ATR"}
          </h1>
          <p className="mt-6 text-[17px] leading-[1.6] text-graphite max-w-[560px] text-pretty">
            {zh
              ? "專家為覆蓋優先順序與框架對照提供意見；貢獻者撰寫與審查規則。每個人都能提 issue 與 pull request，合併權限只給有 repository 權限的維護者。"
              : "Experts advise on coverage priorities and framework crosswalks; contributors write and review rules. Anyone may open issues and pull requests; merging is limited to maintainers with repository permission."}
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link href={`${prefix}/community/join`} className="bg-ink text-white text-[14px] px-5 py-2.5 hover:bg-black transition-colors">
              {zh ? "加入社群" : "Join the community"}
            </Link>
            <Link href={`${prefix}/community/membership`} className="border border-ink/20 text-ink text-[14px] px-5 py-2.5 rounded-[3px] hover:border-ink transition-colors">
              {zh ? "機構會員" : "Organization membership"}
            </Link>
          </div>
        </div>
        <div className="self-end border-t border-fog pt-4 font-data text-[11.5px] leading-[1.7] text-stone">
          <div className="text-ink mb-2">{zh ? "創始成員 — 2026 年 11 月" : "Founding members — November 2026"}</div>
          {zh
            ? "名錄只列本人同意公開的人，列名文字經本人確認。所屬單位的列名不代表該單位背書。要求移除，不問理由。"
            : "Only people who agreed to be listed appear here, with text they confirmed. Listing an organization is not an endorsement by it. Removal on request, no questions asked."}
        </div>
      </section>
      </SheetRow>

      <SheetRow>
        <div className="px-8 md:px-12 py-10">
          <MemberDirectory members={members} locale={locale} />
        </div>
      </SheetRow>

      <SheetRow>
      <section className="px-8 md:px-12 py-20">
        <SectionHead
          mark="§1"
          label={zh ? "GitHub 貢獻紀錄" : "On GitHub"}
          title={zh ? "在 repository 留下貢獻的人" : "People with contributions in the repository"}
          body={
            contributors
              ? zh
                ? `GitHub 列為 contributor 的 ${contributors.length} 人，不含機器人與維護者的次要帳號。這是公開紀錄，與上方名錄分開計算。`
                : `The ${contributors.length} people GitHub lists as contributors, bots and maintainers' secondary accounts excluded. This is the public record, counted apart from the directory above.`
              : zh
                ? "本次建置未能讀到 GitHub 的貢獻者清單。"
                : "The GitHub contributor list could not be read when this page was built."
          }
        />
        {contributors && contributors.length > 0 && (
          <ul className="flex flex-wrap gap-x-6 gap-y-5">
            {contributors.map((c) => (
              <li key={c.login}>
                <a href={c.profile} className="flex items-center gap-3 group" target="_blank" rel="noopener noreferrer">
                  {c.avatar && <img src={`${c.avatar}&s=80`} alt="" className="w-9 h-9 rounded-full grayscale" loading="lazy" />}
                  <span>
                    <span className="block text-[13px] text-ink group-hover:underline underline-offset-4">{c.login}</span>
                    <span className="block font-data text-[10.5px] text-stone">{c.contributions} {zh ? "次提交" : c.contributions === 1 ? "commit" : "commits"}</span>
                  </span>
                </a>
              </li>
            ))}
          </ul>
        )}
      </section>

      </SheetRow>

      <SheetRow>
      <section className="px-8 md:px-12 py-20 grid lg:grid-cols-[1fr_1.4fr] gap-12">
        <SectionHead
          mark="§2"
          label={zh ? "工作組" : "Working groups"}
          title={zh ? "三個工作組，負責人從缺" : "Three working groups, leads wanted"}
          body={zh ? "工作在 GitHub Discussions 非同步進行。負責人由維護者依貢獻提名，目前三組都在徵求。" : "Work happens asynchronously in GitHub Discussions. Leads are nominated by maintainers from contribution; all three seats are open."}
        />
        <ul className="border-t border-fog">
          {WORKING_GROUPS.map((wg) => (
            <li key={wg.name.en} className="border-b border-fog py-5 grid sm:grid-cols-[1fr_auto] gap-2">
              <div>
                <div className="text-[15px] text-ink">{pick(wg.name)}</div>
                <p className="mt-1 text-[13px] leading-[1.6] text-stone">{pick(wg.scope)}</p>
              </div>
              <div className="font-data text-[11px] text-high sm:text-right">{zh ? "徵求負責人" : "Lead wanted"}</div>
            </li>
          ))}
        </ul>
      </section>

      </SheetRow>

      <SheetRow>
      <section className="px-8 md:px-12 py-20 grid lg:grid-cols-[1fr_1.4fr] gap-12">
        <SectionHead
          mark="§3"
          label={zh ? "成員會收到什麼" : "What members get"}
          title={zh ? "只承諾做得到的事" : "Only what we can keep doing"}
        />
        <dl className="border-t border-fog">
          {CADENCE.map((c) => (
            <div key={c.when.en} className="border-b border-fog py-4 grid grid-cols-[120px_1fr] gap-4">
              <dt className="font-data text-[11px] uppercase tracking-[0.08em] text-stone pt-0.5">{pick(c.when)}</dt>
              <dd className="text-[14px] leading-[1.6] text-graphite">{pick(c.what)}</dd>
            </div>
          ))}
          <div className="py-4">
            <a href={DISCUSSIONS} className="text-[13px] text-blue hover:underline underline-offset-4">GitHub Discussions →</a>
          </div>
        </dl>
      </section>
      </SheetRow>
    </>
  );
}
