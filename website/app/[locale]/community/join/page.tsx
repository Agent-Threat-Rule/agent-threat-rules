import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { SectionHead } from "@/components/SectionHead";
import { SheetRow } from "@/components/Sheet";
import Phrased from "@/components/Phrased";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  return {
    ...pageMetadata({
      locale,
      path: "/community/join",
      title: locale === "zh" ? "加入社群" : "Join the community",
      description:
        locale === "zh"
          ? "以專家或貢獻者的身分加入 ATR 社群：誰適合、要做什麼、怎麼申請，以及你的資料怎麼處理。"
          : "Join the ATR community as an expert or a contributor: who it is for, what you do, how to apply, and how your data is handled.",
    }),
  };
}

const CONTACT = "adam@agentthreatrule.org";
const APPLY_GITHUB = "https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=join-community.yml";
const PRIVACY_UPDATED = "2026-11-08";

type B = { en: string; zh: string };

const ROWS: ReadonlyArray<{ label: B; expert: B; contributor: B }> = [
  {
    label: { en: "Who", zh: "誰" },
    expert: { en: "CISOs, heads of AI security, auditors, policy and insurance specialists who decide how agents are deployed or assessed.", zh: "決定 AI 代理怎麼部署或怎麼被評估的人：CISO、AI 安全主管、稽核、政策與保險專家。" },
    contributor: { en: "Practitioners: detection engineers, red-teamers, researchers, engine and integration developers.", zh: "動手做的人：偵測工程師、紅隊、研究人員、寫引擎和整合的開發者。" },
  },
  {
    label: { en: "What you do", zh: "做什麼" },
    expert: { en: "Set the quarterly coverage priorities and review the framework crosswalks. The role is advisory, with no merge or veto rights.", zh: "排定每季該優先覆蓋什麼，審查框架對照。只提供建議，沒有合併權，也沒有否決權。" },
    contributor: { en: "Write, test and review rules; report evasions and false positives; join a working group.", zh: "寫規則、測規則、審規則，回報繞過和誤判，也可以加入工作組。" },
  },
  {
    label: { en: "Rights", zh: "權利" },
    expert: { en: "Open issues and pull requests like anyone. Merging is limited to maintainers with repository permission.", zh: "跟所有人一樣，可以提 issue 和 pull request。只有握有 repo 權限的維護者能合併。" },
    contributor: { en: "The same. Contributors are nominated as maintainers through sustained review work.", zh: "一樣。長期投入審查的貢獻者，會被提名為維護者。" },
  },
  {
    label: { en: "Intake", zh: "收件" },
    expert: { en: "Rolling.", zh: "隨時。" },
    contributor: { en: "Rolling; listings are batched once a month.", zh: "隨時；名錄每月更新一次。" },
  },
];

const STEPS: ReadonlyArray<B> = [
  { en: "You apply through the GitHub form, or by email if you would rather apply privately. You do not need to apply to contribute: anyone can open issues and pull requests.", zh: "用 GitHub 表單申請；想私下申請就用 email。貢獻不需要先申請，任何人都可以直接開 issue 和 pull request。" },
  { en: "Adam Lin, the maintainer, reads every application and invites people personally.", zh: "維護者 Adam Lin 會看每一份申請，親自邀請。" },
  { en: "Once invited, we draft your directory entry for you to confirm.", zh: "受邀後，名錄文字由我們草擬、你確認。" },
  { en: "Your merged work is recorded in the public community ledger under your GitHub name, and your tier follows from it.", zh: "你被合併的貢獻會以 GitHub 名稱記進公開的社群帳本，階別依帳本計算。" },
];

const PRIVACY: ReadonlyArray<{ head: B; body: B }> = [
  {
    head: { en: "Who is responsible", zh: "誰負責" },
    body: {
      en: `Adam Lin, the maintainer of ATR, is responsible for the data you send with an application. The ATR Project is not a legal entity, so he is responsible personally. Contact: ${CONTACT}.`,
      zh: `你隨申請送出的資料，由 ATR 維護者 Adam Lin 負責。ATR Project 不是法人，所以由他個人負責。聯絡：${CONTACT}。`,
    },
  },
  {
    head: { en: "What is collected", zh: "收集什麼" },
    body: {
      en: "What you put in the application: your name, title, country, optional organization, GitHub or ORCID name, areas and problems you are interested in, your conflict-of-interest disclosure, your consent choices, and an optional photo. Email applications also include your email address.",
      zh: "你在申請裡填的內容：名字、職稱、國家、所屬單位（選填）、GitHub 或 ORCID 名稱、有興趣的領域與題目、利益揭露、你勾選的同意項目、照片（選填）。用 email 申請的，還有你的 email 地址。",
    },
  },
  {
    head: { en: "Why", zh: "用途" },
    body: {
      en: "To review your application, reply to you, assign work, list you in the directory if you agree, and record your contributions. Nothing else.",
      zh: "審閱申請、回覆你、指派工作、在你同意時列入名錄、記錄你的貢獻。不做別的用途。",
    },
  },
  {
    head: { en: "Where it is kept and who sees it", zh: "存在哪裡、誰看得到" },
    body: {
      en: "A GitHub application is a public issue. Email applications and member records are kept privately by the maintainer, not in any public repository. Only the maintainer, and maintainers he names to review applications, can see them. They are never sold and never shared with any company, including PANGUARD AI, INC., the maintainer's company.",
      zh: "用 GitHub 申請是一則公開的 issue。email 申請與成員資料由維護者私下保存，不放在任何公開的 repository。只有維護者，以及他指定審閱申請的維護者看得到。絕不出售，也不提供給任何公司，包括維護者的公司 PANGUARD AI, INC.。",
    },
  },
  {
    head: { en: "How long", zh: "保存多久" },
    body: {
      en: "Applications that are not accepted are deleted within six months. Member records are kept while you are a member and deleted when you ask.",
      zh: "沒有通過的申請，六個月內刪除。成員資料在你是成員期間保存，你要求就刪除。",
    },
  },
  {
    head: { en: "Your choices", zh: "你可以要求" },
    body: {
      en: `Write to ${CONTACT} to see what we hold about you, correct it, have it deleted, or be removed from the directory. No reason needed; we reply within 30 days. Your organization is listed only if you allow it, and a listing is not an endorsement by your organization.`,
      zh: `寫信到 ${CONTACT}，可以查看我們保存了你哪些資料、更正、刪除，或從名錄移除。不需要說明理由，我們 30 天內回覆。所屬單位只有你同意才列，列名不代表該單位背書。`,
    },
  },
  {
    head: { en: "What stays public", zh: "哪些會一直公開" },
    body: {
      en: "Issues, pull requests and commits on GitHub are public and stay in the project's history, and the community ledger records them under your GitHub name. Leaving the directory does not remove that history.",
      zh: "GitHub 上的 issue、pull request 與 commit 是公開的，會留在專案歷史裡；社群帳本也以你的 GitHub 名稱記錄它們。從名錄移除，不會刪掉這些歷史。",
    },
  },
];

export default async function JoinPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const pick = (t: B) => (zh ? t.zh : t.en);

  return (
    <Phrased>
    <>
      <SheetRow grid>
      <div className="max-w-[972px] px-6 md:px-14 pt-24 pb-24">
      <div className="font-data text-[11px] uppercase tracking-[0.1em] text-stone mb-6">
        <Link href={`${prefix}/community`} className="hover:text-ink">{zh ? "社群" : "Community"}</Link> <span className="text-mist">/ {zh ? "加入" : "Join"}</span>
      </div>
      <h1 className="text-[32px] md:text-[48px] leading-[1.1] tracking-[-0.01em] font-medium text-ink text-balance">
        {zh ? "加入 ATR 社群" : "Join the ATR community"}
      </h1>
      <p className="mt-5 text-[17px] leading-[1.6] text-graphite max-w-[620px] text-pretty">
        {zh
          ? "ATR 是一份開放標準，由寫規則的人與用規則做決策的人一起維護。加入免費。機構會員是另一回事，目前還沒開放。"
          : "ATR is an open standard kept by the people who write rules and the people who make decisions with them. Joining is free. Organization membership is separate and not open yet."}
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
          {zh ? "指導小組（TSC 與維護者）不開放申請。席位依章程，從貢獻中提名。" : "Steering (the TSC and maintainers) is not open to applications. Seats follow the charter: people are nominated from their contributions."}
        </p>
      </section>

      <section className="mt-14 border-t border-ink pt-6" aria-labelledby="apply-heading">
        <h2 id="apply-heading" className="font-data text-[11px] uppercase tracking-[0.1em] text-stone mb-4">{zh ? "申請" : "Apply"}</h2>
        <div className="flex flex-wrap gap-3">
          <a href={APPLY_GITHUB} className="inline-flex items-center px-5 py-2.5 bg-ink text-paper text-[14px] hover:opacity-90">
            {zh ? "用 GitHub 申請（公開）" : "Apply on GitHub (public)"}
          </a>
          <span className="inline-flex items-center px-5 py-2.5 border border-fog text-[14px] text-ink select-all">
            {CONTACT}
          </span>
        </div>
        <p className="mt-3 text-[13px] text-stone">
          {zh ? "想私下申請，寄信到上面的地址，內容照 GitHub 表單的欄位寫即可。申請前請先看下面「你的資料怎麼處理」。" : "To apply privately, email the address above with the same fields as the GitHub form. Please read how your data is handled, below, before you apply."}
        </p>
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
        <SectionHead mark="§2" label={zh ? "你的資料" : "Your data"} title={zh ? "你的資料怎麼處理" : "How your data is handled"} />
        <dl className="border-t border-fog">
          {PRIVACY.map((p) => (
            <div key={p.head.en} className="grid md:grid-cols-[200px_1fr] gap-2 md:gap-6 py-4 border-b border-fog">
              <dt className="text-[14px] text-ink">{pick(p.head)}</dt>
              <dd className="text-[14px] leading-[1.6] text-graphite">{pick(p.body)}</dd>
            </div>
          ))}
        </dl>
        <p className="mt-3 font-data text-[11.5px] text-stone">{zh ? `最後更新 ${PRIVACY_UPDATED}` : `Last updated ${PRIVACY_UPDATED}`}</p>
      </section>
      </div>
      </SheetRow>
    </>
    </Phrased>
  );
}
