import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { SectionHead } from "@/components/SectionHead";
import { SheetRow } from "@/components/Sheet";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/community/join",
    title: locale === "zh" ? "加入社群" : "Join the community",
    description:
      locale === "zh"
        ? "以專家或貢獻者身分加入 ATR 社群：誰適合、做什麼、怎麼申請，以及我們如何處理你的資料。"
        : "Join the ATR community as an expert or a contributor: who it is for, what you do, how to apply, and how your data is handled.",
  });
}

const ISSUE_FORM = "https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=join-community.yml";
// Form for applicants without a GitHub account. Set once the form exists;
// until then the page offers email instead of a dead link.
const NO_GITHUB_FORM_URL: string | null = null;
const CONTACT = "contact@agentthreatrule.org";

type B = { en: string; zh: string };

const ROWS: ReadonlyArray<{ label: B; expert: B; contributor: B }> = [
  {
    label: { en: "Who", zh: "誰" },
    expert: { en: "CISOs, heads of AI security, auditors, policy and insurance specialists who decide how agents are deployed or assessed.", zh: "決定 AI 代理怎麼部署或怎麼被評估的人：CISO、AI 安全主管、稽核、政策與保險專家。" },
    contributor: { en: "Practitioners: detection engineers, red-teamers, researchers, engine and integration developers.", zh: "實務者：偵測工程師、紅隊、研究者、引擎與整合開發者。" },
  },
  {
    label: { en: "What you do", zh: "做什麼" },
    expert: { en: "Set the quarterly coverage priorities and review framework crosswalks. Advisory: no merge or veto rights.", zh: "訂每季的覆蓋優先順序、審框架對照。屬於建議性質，沒有合併或否決權。" },
    contributor: { en: "Write, test and review rules; report evasions and false positives; join a working group.", zh: "撰寫、測試、審查規則；回報繞過與誤判；加入工作組。" },
  },
  {
    label: { en: "Rights", zh: "權利" },
    expert: { en: "Open issues and pull requests like anyone. Merging is limited to maintainers with repository permission.", zh: "跟任何人一樣可以提 issue 與 pull request。合併權限只給有 repository 權限的維護者。" },
    contributor: { en: "The same. Sustained review work is how contributors are nominated as maintainers.", zh: "相同。長期投入審查的貢獻者，會被提名為維護者。" },
  },
  {
    label: { en: "Intake", zh: "收件" },
    expert: { en: "Rolling.", zh: "隨時。" },
    contributor: { en: "Rolling; listings are batched once a month.", zh: "隨時；名錄每月更新一次。" },
  },
];

const STEPS: ReadonlyArray<B> = [
  { en: "You apply through the GitHub form, or by email if you do not use GitHub.", zh: "用 GitHub 表單申請；不用 GitHub 的人用 email。" },
  { en: "A maintainer reviews the application and drafts your directory entry.", zh: "維護者審閱申請，並草擬你在名錄上的文字。" },
  { en: "You confirm the exact text, photo and organization line, or change them.", zh: "你確認名錄上的文字、照片、所屬單位，或要求修改。" },
  { en: "The entry is merged by pull request and appears on the community page.", zh: "以 pull request 合併後，出現在社群頁。" },
];

const PRIVACY: ReadonlyArray<B> = [
  { en: "Your email address is used to reply to you and is never published.", zh: "你的 email 只用來回覆你，絕不公開。" },
  { en: "Nothing is listed until you confirm the exact text. Your organization appears only if you allow it, and listing it is not an endorsement by it.", zh: "你確認文字之前，什麼都不會公開。所屬單位只有你同意才列，而且列名不代表該單位背書。" },
  { en: "A photo is optional and shown in greyscale; without one, your GitHub avatar is used.", zh: "照片可不提供，網頁上灰階顯示；沒有提供就用你的 GitHub 頭像。" },
  { en: `To be removed or to have an unsuccessful application deleted, write to ${CONTACT}. No reason needed.`, zh: `要求移除，或刪除未通過的申請，寫信到 ${CONTACT}，不需說明理由。` },
  { en: "A GitHub application is a public issue. Use email if you would rather apply privately.", zh: "用 GitHub 申請會是一則公開的 issue。想私下申請，請用 email。" },
];

export default async function JoinPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const pick = (t: B) => (zh ? t.zh : t.en);
  const noGithubHref = NO_GITHUB_FORM_URL ?? `mailto:${CONTACT}?subject=${encodeURIComponent("Joining the ATR community")}`;

  return (
    <>
      <SheetRow grid>
      <div className="max-w-[860px] mx-auto px-8 md:px-12 pt-24 pb-24">
      <div className="font-data text-[11px] uppercase tracking-[0.1em] text-stone mb-6">
        <Link href={`${prefix}/community`} className="hover:text-ink">{zh ? "社群" : "Community"}</Link> <span className="text-mist">/ {zh ? "加入" : "Join"}</span>
      </div>
      <h1 className="text-[36px] md:text-[44px] leading-[1.1] tracking-[-0.02em] font-medium text-ink text-balance">
        {zh ? "加入 ATR 社群" : "Join the ATR community"}
      </h1>
      <p className="mt-5 text-[17px] leading-[1.6] text-graphite max-w-[620px] text-pretty">
        {zh
          ? "ATR 是一份開放標準，由寫規則的人與用規則做決策的人一起維護。加入免費。機構會員是另一回事，見機構會員頁。"
          : "ATR is an open standard kept by the people who write rules and the people who make decisions with them. Joining is free. Organization membership is separate; see the membership page."}
      </p>

      <section className="mt-12" aria-labelledby="tiers-heading">
        <h2 id="tiers-heading" className="font-data text-[11px] uppercase tracking-[0.1em] text-stone mb-4">{zh ? "兩種身分" : "Two ways to take part"}</h2>
        <div className="border-t border-fog">
          <div className="grid grid-cols-[100px_1fr_1fr] gap-4 py-3 border-b border-fog text-[14px] text-ink">
            <span />
            <span>{zh ? "專家" : "Expert"}</span>
            <span>{zh ? "貢獻者" : "Contributor"}</span>
          </div>
          {ROWS.map((row) => (
            <div key={row.label.en} className="grid grid-cols-[100px_1fr_1fr] gap-4 py-4 border-b border-fog">
              <span className="font-data text-[11px] uppercase tracking-[0.08em] text-stone pt-0.5">{pick(row.label)}</span>
              <span className="text-[13.5px] leading-[1.6] text-graphite">{pick(row.expert)}</span>
              <span className="text-[13.5px] leading-[1.6] text-graphite">{pick(row.contributor)}</span>
            </div>
          ))}
        </div>
        <p className="mt-4 text-[13px] text-stone">
          {zh ? "Steering（TSC 與維護者）不開放申請，依章程由貢獻提名。" : "Steering (the TSC and maintainers) is not by application; seats follow the charter, by nomination from contribution."}
        </p>
      </section>

      <section className="mt-14 grid sm:grid-cols-2 gap-px bg-fog border border-fog">
        <a href={ISSUE_FORM} className="bg-paper p-6 hover:bg-ash transition-colors">
          <div className="font-data text-[10px] uppercase tracking-[0.08em] text-mist">{zh ? "有 GitHub 帳號" : "With a GitHub account"}</div>
          <div className="mt-2 text-[16px] text-ink">{zh ? "用 GitHub 表單申請 →" : "Apply with the GitHub form →"}</div>
          <p className="mt-2 text-[13px] leading-[1.6] text-stone">{zh ? "會建立一則公開的 issue。" : "Creates a public issue."}</p>
        </a>
        <a href={noGithubHref} className="bg-paper p-6 hover:bg-ash transition-colors">
          <div className="font-data text-[10px] uppercase tracking-[0.08em] text-mist">{zh ? "沒有 GitHub 帳號" : "Without a GitHub account"}</div>
          <div className="mt-2 text-[16px] text-ink">{NO_GITHUB_FORM_URL ? (zh ? "填申請表 →" : "Fill in the form →") : (zh ? "用 email 申請 →" : "Apply by email →")}</div>
          <p className="mt-2 text-[13px] leading-[1.6] text-stone">
            {zh ? "請附：姓名、職稱、所屬單位、想擔任的身分、專長。" : "Include your name, title, organization, the role you want and your expertise."}
          </p>
        </a>
      </section>

      <section className="mt-14">
        <SectionHead mark="§1" label={zh ? "接下來" : "What happens next"} title={zh ? "四個步驟" : "Four steps"} />
        <ol className="border-t border-fog">
          {STEPS.map((step, i) => (
            <li key={step.en} className="grid grid-cols-[40px_1fr] gap-3 py-4 border-b border-fog">
              <span className="font-data text-[11px] text-mist pt-0.5">{String(i + 1).padStart(2, "0")}</span>
              <span className="text-[14px] leading-[1.6] text-graphite">{pick(step)}</span>
            </li>
          ))}
        </ol>
      </section>

      <section className="mt-14">
        <SectionHead mark="§2" label={zh ? "你的資料" : "Your data"} title={zh ? "我們怎麼處理你的資料" : "How your data is handled"} />
        <ul className="border-t border-fog">
          {PRIVACY.map((p) => (
            <li key={p.en} className="py-3 border-b border-fog text-[14px] leading-[1.6] text-graphite">{pick(p)}</li>
          ))}
        </ul>
      </section>
      </div>
      </SheetRow>
    </>
  );
}
