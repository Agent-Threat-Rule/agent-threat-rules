/* Partner live sync: a hosted endpoint for integrators to poll new rules was
 * planned, and is not open. The page says so and shows the public ways to
 * stay current today (npm, PyPI, the YAML in the repository). */
import Link from "next/link";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import { locales, type Locale } from "@/lib/i18n";
import { loadVersionLabels } from "@/lib/versions";
import { SheetRow } from "@/components/Sheet";
import { ToolHero, ToolLimits } from "@/components/ToolPage";

const RULES_URL = "https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/main/rules";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  const zh = locale === "zh";
  return pageMetadata({
    locale,
    path: "/partner-sync",
    title: zh ? "夥伴即時同步" : "Partner live sync",
    description: zh
      ? "給整合方即時拉取新規則的端點目前沒有開放。現在要跟上最新規則，請用 npm、PyPI 或 repo 裡的 YAML。"
      : "The endpoint for integrators to poll new rules is not open. To stay current today, use npm, PyPI or the YAML in the repository.",
  });
}

const H2 = "text-[26px] md:text-[32px] leading-[1.2] tracking-[-0.02em] font-medium text-ink text-balance";
const BODY = "text-[17px] leading-[1.8] text-graphite max-w-[620px]";
const LINK = "text-ink underline underline-offset-4 decoration-fog hover:decoration-ink";
const CODE = "block font-data text-[13px] bg-ash text-ink px-3 py-2 select-all";

export default async function PartnerSyncPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const versions = await loadVersionLabels();

  return (
    <>
      <SheetRow>
        <ToolHero
          emblem="key"
          zh={zh}
          name={zh ? "夥伴即時同步" : "Partner live sync"}
          status={{ en: "Not open", zh: "目前沒有開放" }}
          title={{ en: "To stay current today, use the public packages.", zh: "要跟上最新規則，現在就用公開的套件。" }}
          lead={{
            en: "This page was meant for an endpoint that lets integrators poll newly confirmed rules with a key, instead of reinstalling a package each time. That endpoint is not open. No keys are issued, and there is no date.",
            zh: "這一頁原本是給一個同步端點用的：整合方拿金鑰定時拉取剛確認的規則，不必每次重新安裝套件。這個端點目前沒有開放，也不發放金鑰，開放時間還沒定。",
          }}
        />
      </SheetRow>

      <SheetRow>
        <div className="px-6 md:px-14 py-20 md:py-24 grid lg:grid-cols-[1fr_1.4fr] gap-4 lg:gap-20">
          <h2 className={H2}>{zh ? "現在怎麼跟上" : "How to stay current now"}</h2>
          <div className={`${BODY} space-y-5`}>
            <p>
              {zh
                ? `規則跟著版本發布到 npm 和 PyPI。npm 上目前是 ${versions.npm}。不用金鑰，執行時也不用連網。`
                : `Rules ship with each release on npm and PyPI. npm is at ${versions.npm} today. No key, and no network at runtime.`}
            </p>
            <div className="space-y-2">
              <code className={CODE}>npm install agent-threat-rules</code>
              <code className={CODE}>pip install pyatr</code>
            </div>
            <p>
              {zh
                ? "要自動跟上新版本，最簡單的是在 CI 裡定期跑 npm update，或鎖定版本、由 CI 開升級 PR。"
                : "To follow new releases automatically, run npm update on a schedule in CI, or pin the version and let CI open the upgrade pull request."}
            </p>
            <p>
              {zh ? (
                <>也可以直接從 repository 拉 <a className={LINK} href={RULES_URL} target="_blank" rel="noopener noreferrer">rules/ 裡的 YAML</a>，拿到的就是 main 上的最新內容。</>
              ) : (
                <>You can also pull <a className={LINK} href={RULES_URL} target="_blank" rel="noopener noreferrer">the YAML under rules/</a> straight from the repository and get whatever is on main.</>
              )}
            </p>
          </div>
        </div>
      </SheetRow>

      <ToolLimits zh={zh} title={{ en: "Not open yet", zh: "目前沒有開放" }}>
        <p>
          {zh
            ? "以前寫在這一頁的端點網址、金鑰申請方式和輪詢範例都已經不適用。照著做不會成功。"
            : "The endpoint address, key request steps and polling example that used to be on this page no longer apply. Following them will not work."}
        </p>
        <p>
          {zh ? (
            <>如果你的整合需要比套件版本更快拿到規則，可以透過<Link className={LINK} href={`/${locale}/contact`}>聯絡頁</Link>說明你的情況。</>
          ) : (
            <>If your integration needs rules faster than package releases deliver them, describe your case through the <Link className={LINK} href={`/${locale}/contact`}>contact page</Link>.</>
          )}
        </p>
      </ToolLimits>

      <SheetRow>
        <div className="px-6 md:px-14 py-12 flex flex-wrap gap-x-10 gap-y-3 text-[15px]">
          <Link className={LINK} href={`/${locale}/integrate`}>{zh ? "其他整合方式" : "Other ways to integrate"}</Link>
          <Link className={LINK} href={`/${locale}/changelog`}>{zh ? "版本紀錄" : "Changelog"}</Link>
        </div>
      </SheetRow>
    </>
  );
}
