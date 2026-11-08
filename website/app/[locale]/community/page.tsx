import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadGithubContributors, loadMembers } from "@/lib/community";
import { SectionHead } from "@/components/SectionHead";
import { SheetRow } from "@/components/Sheet";
import { MemberDirectory } from "./MemberDirectory";
import Phrased from "@/components/Phrased";
import { Sign } from "@/components/Sign";
import workgroups from "@/data/workgroups.json";

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
        ? "維護 ATR 的人：維護者和貢獻者，還有 GitHub 上的貢獻紀錄。TSC 籌組中。"
        : "The people who maintain ATR: maintainers and contributors, and the contributions GitHub records. The TSC is being formed.",
  });
}

const REPO = "https://github.com/Agent-Threat-Rule/agent-threat-rules";
const DISCUSSIONS = `${REPO}/discussions`;
/** Permanent invite made for the website, tracked apart from the other invites. */
const DISCORD = "https://discord.gg/UQrujeDYU3";
const GOOD_FIRST = 'is:open label:"good first issue"';

const FIRST_STEPS: ReadonlyArray<{ time: { en: string; zh: string }; what: { en: string; zh: string }; href: string }> = [
  {
    time: { en: "5 min", zh: "5 分鐘" },
    what: { en: "Report something ATR flagged by mistake. A confirmed report counts as a contribution.", zh: "回報 ATR 誤判的正常內容。確認成立就算一次貢獻。" },
    href: `${REPO}/issues/new?template=false-positive.yml`,
  },
  {
    time: { en: "10 min", zh: "10 分鐘" },
    what: { en: "Submit an attack sample with a harmless look-alike. No setup needed.", zh: "交一個攻擊樣本，附一段長得像但無害的對照。不用裝任何東西。" },
    href: `${REPO}/issues/new?template=red-team-probe.yml`,
  },
  {
    time: { en: "30 min", zh: "30 分鐘" },
    what: { en: "Read the open problems. Each says which files to touch and how to test. To take one, apply to join.", zh: "看公開的題目。每題都寫了要改哪些檔、怎麼測。想認領，先申請加入。" },
    href: `${REPO}/issues?q=${encodeURIComponent(GOOD_FIRST)}`,
  },
  {
    time: { en: "Any time", zh: "隨時" },
    what: { en: "Ask a question in GitHub Discussions, no Discord needed. In Discord, /start lists these steps and /now what each area needs.", zh: "在 GitHub Discussions 發問，不需要 Discord。在 Discord 裡，/start 會列出這些步驟，/now 會列出各區現在需要什麼。" },
    href: DISCUSSIONS,
  },
];

type Area = (typeof workgroups.groups)[number];

const REPOS: Record<string, string> = {
  "agent-threat-rules": REPO,
  "atr-eval": "https://github.com/Agent-Threat-Rule/atr-eval",
};

function areaIssues(area: Area): string {
  const base = REPOS[area.repo];
  if (!base) return "";
  return `${base}/issues?q=${encodeURIComponent(`${GOOD_FIRST} label:${area.label}`)}`;
}

const WORKING_GROUPS: ReadonlyArray<{ name: { en: string; zh: string }; scope: { en: string; zh: string } }> = [
  {
    name: { en: "Rule quality and evasion", zh: "規則品質與繞過" },
    scope: { en: "Red-team the rules, report bypasses and false positives, and tighten the rules that cause them.", zh: "拿規則做紅隊測試，回報繞過和誤判，把造成誤判的規則收窄。" },
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
  { when: { en: "Monthly", zh: "每月" }, what: { en: "A written community update in GitHub Discussions (planned).", zh: "一則書面社群更新，發在 GitHub Discussions（規劃中）。" } },
  { when: { en: "Quarterly", zh: "每季" }, what: { en: "A survey on what to cover next, with the results published (planned).", zh: "一份問卷，問接下來該優先覆蓋什麼，結果公開（規劃中）。" } },
  { when: { en: "Every release", zh: "每次發版" }, what: { en: "Contributors are named in the author field of the rules they wrote and in CONTRIBUTORS.md.", zh: "貢獻者的名字寫在他們規則的 author 欄位，也列在 CONTRIBUTORS.md。" } },
  { when: { en: "Optional", zh: "選擇性" }, what: { en: "An open call when there is something to decide live. Decisions are written back to GitHub.", zh: "有需要即時討論的事才開線上會議；決定一律寫回 GitHub。" } },
];

export default async function CommunityPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const pick = (t: { en: string; zh: string }) => (zh ? t.zh : t.en);
  const members = loadMembers();
  const contributors = loadGithubContributors();

  return (
    <Phrased>
    <>
      <SheetRow grid>
      <section className="grid lg:grid-cols-[1.3fr_1fr] gap-12 px-6 md:px-14 pt-24 pb-20">
        <div>
          <div className="font-data text-[11px] uppercase tracking-[0.1em] text-stone mb-6">{zh ? "社群" : "Community"}</div>
          <h1 className="text-[32px] md:text-[48px] leading-[1.1] tracking-[-0.01em] font-medium text-ink max-w-[620px] text-balance">
            {zh ? "維護 ATR 的人" : "The people who maintain ATR"}
          </h1>
          <p className="mt-6 text-[17px] leading-[1.6] text-graphite max-w-[560px] text-pretty">
            {zh
              ? "貢獻者寫規則，也審規則。誰都可以提 issue 和 pull request，但只有握有 repo 權限的維護者能合併。專家要在書面同意後才會列在這裡，目前還沒有。"
              : "Contributors write and review rules. Anyone may open issues and pull requests; only maintainers with repository permission can merge. Experts will be listed here once they agree in writing; none are listed yet."}
          </p>
          <div className="mt-8 flex flex-wrap items-center gap-x-6 gap-y-3">
            <a href={DISCORD} target="_blank" rel="noopener noreferrer" className="bg-ink text-paper px-5 py-2.5 text-[14px] hover:opacity-90 transition-opacity">
              {zh ? "加入 Discord" : "Join the Discord"}
            </a>
            <a href={`/${locale}/community/join`} className="border border-ink text-ink px-5 py-2.5 text-[14px] hover:bg-white transition-colors">
              {zh ? "申請加入" : "Apply to join"}
            </a>
            <a href="#start" className="text-[14px] text-blue hover:underline underline-offset-4">
              {zh ? "從哪裡開始" : "Where to start"}
              <Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
            </a>
          </div>
          <p className="mt-4 text-[13px] text-stone max-w-[560px]">
            {zh
              ? "題目公開，任何人都能看、了解可以怎麼解。想認領題目、成為貢獻者，先申請加入，Adam 看過後親自邀請。"
              : "Anyone can read the problems and how they might be solved. To take one and become a contributor, apply to join; Adam reads every application and invites people personally."}
          </p>
          <p className="mt-3 text-[13px] text-stone max-w-[560px]">
            {zh ? "利益揭露：ATR 首席維護者林冠辛創辦並控制 PANGUARD AI, INC.，這家公司販售以 ATR 為基礎的 AI agent 資安產品。在這裡貢獻的成果以 MIT 授權釋出，任何人都能使用，包括這家公司。兩者如何區隔，寫在" : "Interests: ATR's lead maintainer, Adam Lin, founded and controls PANGUARD AI, INC., which sells AI agent security products built on ATR. Work contributed here is MIT-licensed and anyone may use it, including that company. How the two are kept apart is on the "}
            <a href={`/${locale}/governance`} className="text-blue hover:underline underline-offset-4">{zh ? "治理頁" : "governance page"}</a>
            {zh ? "。" : "."}
          </p>
        </div>
        <div className="self-end border-t border-fog pt-4 font-data text-[11.5px] leading-[1.7] text-stone">
          <div className="text-ink mb-2">{zh ? "名錄 · 2026 年 11 月開放" : "Directory · opened November 2026"}</div>
          {zh
            ? "名錄只列本人同意公開的人，文字也經過本人確認。列出所屬單位，不代表該單位背書。要求移除，不問理由。"
            : "Only people who agreed to be listed appear here, with text they confirmed. Listing an organization is not an endorsement by it. Removal on request, no questions asked."}
        </div>
      </section>
      </SheetRow>

      <SheetRow>
      <section id="start" className="px-6 md:px-14 py-20 grid lg:grid-cols-[1fr_1.4fr] gap-12 scroll-mt-24">
        <SectionHead
          mark="§1"
          label={zh ? "從哪裡開始" : "Where to start"}
          title={zh ? "照你有的時間，挑第一件事" : "Pick a first thing for the time you have"}
          body={
            zh
              ? "Discord 用來討論，決定和功勞記在 GitHub，不用 Discord 也能參與。回報誤判和交樣本任何人都能直接做；認領題目要先申請加入，由 Adam 指派，避免兩個人做同一件事。"
              : "Discord is for talking; decisions and credit are recorded on GitHub, and you can take part without Discord. Anyone can report a false positive or submit a sample. Problems are assigned to invited members: apply to join to take one, so two people don't do the same work."
          }
        />
        <dl className="border-t border-fog">
          {FIRST_STEPS.map((step) => (
            <div key={step.time.en} className="border-b border-fog py-4 grid grid-cols-[96px_1fr] gap-4">
              <dt className="font-data text-[11px] uppercase tracking-[0.08em] text-stone pt-0.5">{pick(step.time)}</dt>
              <dd className="text-[14px] leading-[1.6] text-graphite">
                <a href={step.href} target="_blank" rel="noopener noreferrer" className="hover:underline underline-offset-4">
                  {pick(step.what)}
                  <Sign name="diple" size={10} className="ml-1.5 align-[-1px] text-blue" />
                </a>
              </dd>
            </div>
          ))}
        </dl>
      </section>
      </SheetRow>

      <SheetRow>
      <section className="px-6 md:px-14 py-20">
        <SectionHead
          mark="§2"
          label={zh ? "現在在做什麼" : "Being worked on now"}
          title={zh ? "各區的進行中與缺人的工作" : "What is in progress, and where help is needed"}
          body={
            zh
              ? `只列專案名稱，細節在各自的 issue 與 Discord 頻道。這些是目前工作所在的區域，不是治理頁說的正式工作組。最後更新 ${workgroups.updated}。`
              : `Project names only; the details live in each issue and Discord channel. These are the areas where work happens today, not the formal working groups described on the governance page. Last updated ${workgroups.updated}.`
          }
        />
        <div className="grid md:grid-cols-2 border-t border-fog">
          {workgroups.groups.map((area) => {
            const issues = areaIssues(area);
            const states = workgroups.states as Record<string, { en: string; zh: string }>;
            return (
              <div key={area.id} className="border-b border-fog py-6 md:pr-10">
                <div className="flex items-baseline justify-between gap-4">
                  <div className="text-[15px] text-ink">{pick(area.name)}</div>
                  <div className="font-data text-[11px] text-stone">
                    {area.discord ? `#${area.discord}` : zh ? "尚無頻道" : "No channel yet"}
                  </div>
                </div>
                <p className="mt-1 text-[13px] leading-[1.6] text-stone">
                  {pick(area.covers)}
                  {area.repo === "atr-eval" && (
                    <>
                      {" "}
                      <a href="https://github.com/Agent-Threat-Rule/atr-eval/blob/main/DISCLOSURES.md" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline underline-offset-4">
                        {zh ? "利益揭露" : "Disclosures"}
                      </a>
                    </>
                  )}
                </p>
                <ul className="mt-4 flex flex-col gap-1.5">
                  {area.now.map((item) => (
                    <li key={item.en} className="grid grid-cols-[96px_1fr] gap-3 text-[13px] leading-[1.6]">
                      <span className={`font-data text-[11px] pt-0.5 ${item.state === "needs-help" ? "text-blue" : "text-stone"}`}>
                        {pick(states[item.state])}
                      </span>
                      <span className="text-graphite">{pick(item)}</span>
                    </li>
                  ))}
                </ul>
                <div className="mt-4 text-[13px]">
                  {issues ? (
                    <a href={issues} target="_blank" rel="noopener noreferrer" className="text-blue hover:underline underline-offset-4">
                      {zh ? "這一區的新手任務" : "First issues in this area"}
                      <Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
                    </a>
                  ) : (
                    <span className="text-stone">
                      {area.status === "planned"
                        ? zh ? "規劃中" : "Planned"
                        : zh ? "尚無題目" : "No problems listed yet"}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </section>
      </SheetRow>

      <SheetRow>
        <div className="px-6 md:px-14 py-10">
          <MemberDirectory members={members} locale={locale} />
        </div>
      </SheetRow>

      <SheetRow>
      <section className="px-6 md:px-14 py-20">
        <SectionHead
          mark="§3"
          label={zh ? "GitHub 貢獻紀錄" : "On GitHub"}
          title={zh ? "在 repo 裡留下貢獻的人" : "People with contributions in the repository"}
          body={
            contributors
              ? zh
                ? `GitHub 列為貢獻者的 ${contributors.length} 人，不算機器人，也不算維護者的次要帳號。這是公開紀錄，跟上面的名錄分開計算。`
                : `The ${contributors.length} people GitHub lists as contributors, not counting bots or maintainers' secondary accounts. This is the public record, counted separately from the directory above.`
              : zh
                ? "這次建置沒有讀到 GitHub 的貢獻者清單。"
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
      <section className="px-6 md:px-14 py-20 grid lg:grid-cols-[1fr_1.4fr] gap-12">
        <SectionHead
          mark="§4"
          label={zh ? "工作組" : "Working groups"}
          title={zh ? "三個規劃中的工作組，都還沒成立" : "Three planned working groups, none formed yet"}
          body={zh ? "這三組是規劃，目前都還沒成立，也沒有負責人。成立的條件寫在治理頁：三個以上彼此獨立的實作者提出同樣的需求。在那之前，相關的工作都在 GitHub 上非同步進行。" : "These are planned, not running: none has formed and none has a lead. The governance page sets the condition for starting one, three or more independent implementers asking for the same thing. Until then the work happens asynchronously on GitHub."}
        />
        <ul className="border-t border-fog">
          {WORKING_GROUPS.map((wg) => (
            <li key={wg.name.en} className="border-b border-fog py-5 grid sm:grid-cols-[1fr_auto] gap-2">
              <div>
                <div className="text-[15px] text-ink">{pick(wg.name)}</div>
                <p className="mt-1 text-[13px] leading-[1.6] text-stone">{pick(wg.scope)}</p>
              </div>
              <div className="font-data text-[11px] text-high sm:text-right">{zh ? "規劃中" : "Planned"}</div>
            </li>
          ))}
        </ul>
      </section>

      </SheetRow>

      <SheetRow>
      <section className="px-6 md:px-14 py-20 grid lg:grid-cols-[1fr_1.4fr] gap-12">
        <SectionHead
          mark="§5"
          label={zh ? "成員會收到什麼" : "What members get"}
          title={zh ? "只承諾做得到的事" : "Only promises that can be kept"}
        />
        <dl className="border-t border-fog">
          {CADENCE.map((c) => (
            <div key={c.when.en} className="border-b border-fog py-4 grid grid-cols-[120px_1fr] gap-4">
              <dt className="font-data text-[11px] uppercase tracking-[0.08em] text-stone pt-0.5">{pick(c.when)}</dt>
              <dd className="text-[14px] leading-[1.6] text-graphite">{pick(c.what)}</dd>
            </div>
          ))}
          <div className="py-4">
            <a href={DISCUSSIONS} className="text-[13px] text-blue hover:underline underline-offset-4">GitHub Discussions<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" /></a>
          </div>
        </dl>
      </section>
      </SheetRow>
    </>
    </Phrased>
  );
}
