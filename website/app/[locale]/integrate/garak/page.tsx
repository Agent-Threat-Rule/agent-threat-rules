/* NVIDIA garak × ATR: what exists today (a public script that turns garak
 * prompts ATR misses into rule proposals, and recall measured on two garak
 * corpora) and what does not (an outside submission path; it is not open).
 * Recall figures come from the stats loader, never typed in. */
import Link from "next/link";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import { loadSiteStats } from "@/lib/stats";
import { GARAK_BOTH_CLOSED_BOOK, LANES_EXPLAINED, commonStamp, count, findBenchmark, recallLanes, toFullWidth } from "@/lib/recall";
import { locales, type Locale } from "@/lib/i18n";
import { SheetRow } from "@/components/Sheet";
import { ToolHero, ToolLimits } from "@/components/ToolPage";
import Phrased from "@/components/Phrased";

const SCRIPT_URL = "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/scripts/garak-miss-to-proposals.ts";
const GARAK_URL = "https://github.com/NVIDIA/garak";
const GARAK_PR_URL = "https://github.com/NVIDIA/garak/pull/1676";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  const zh = locale === "zh";
  return pageMetadata({
    locale,
    path: "/integrate/garak",
    title: "NVIDIA garak × ATR",
    description: zh
      ? "garak 找到攻擊，ATR 把它寫成規則。garak 沒有內建 ATR；讓外部團隊送 garak 報告進來的管道目前沒有開放。"
      : "garak finds the attack and ATR writes the rule. garak does not ship ATR, and there is no open path yet for outside teams to submit garak reports.",
  });
}

const H2 = "text-[26px] md:text-[32px] leading-[1.2] tracking-[-0.02em] font-medium text-ink text-balance";
const BODY = "text-[17px] leading-[1.8] text-graphite max-w-[620px]";
const LINK = "text-ink underline underline-offset-4 decoration-fog hover:decoration-ink";

export default async function GarakIntegratePage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const stats = loadSiteStats();
  const garak = findBenchmark(stats, "garak");
  const full = findBenchmark(stats, "garak-full");

  return (
    <Phrased>
    <>
      <SheetRow>
        <ToolHero
          zh={zh}
          name="NVIDIA garak × ATR"
          status={{ en: "Submissions not open", zh: "目前沒有開放提交" }}
          title={{ en: "garak finds the attack. ATR writes the rule.", zh: "garak 找到攻擊，ATR 把它寫成規則。" }}
          lead={{
            en: "garak is NVIDIA's red-teaming tool. It looks for attacks at the model layer. ATR covers the agent layer: tool calls, skills, MCP. Some ATR rules were written from garak's probe corpus, and each one names its source on the author line. garak itself does not ship ATR.",
            zh: "garak 是 NVIDIA 的紅隊工具，在模型這一層找攻擊。ATR 守的是 agent 這一層：工具呼叫、skill、MCP。有一部分 ATR 規則就是從 garak 的 probe 語料寫出來的，每一條都在 author 欄位寫明出處。garak 本身沒有內建 ATR。",
          }}
        />
      </SheetRow>

      <SheetRow>
        <div className="px-6 md:px-14 py-20 md:py-24 grid gap-14">
          <div className="grid lg:grid-cols-[1fr_1.4fr] gap-4 lg:gap-20">
            <h2 className={H2}>{zh ? "現在怎麼運作" : "How it works today"}</h2>
            <div className={`${BODY} space-y-4`}>
              <p>
                {zh
                  ? "公開 repo 裡有一支腳本，把 ATR 在完整 garak 語料上漏抓的 prompt，按攻擊家族分組，寫成規則提案，交給維護者審。"
                  : "A script in the public repository takes the prompts ATR misses on the full garak corpus, groups them by attack family, and writes them up as rule proposals for a maintainer to review."}
              </p>
              <p>
                {zh
                  ? "它只收攻擊 agent 的家族，例如提示注入、越獄人設、編碼混淆。要模型產出有害內容的 probe，例如武器或毒品，不是 agent 威脅，不在 ATR 的範圍裡。"
                  : "It keeps only the families that attack the agent, such as prompt injection, jailbreak personas and encoded injection. Probes that ask a model for harmful content, such as weapons or drugs, are not agent threats and are outside ATR's scope."}
              </p>
              <p>
                <a className={`font-data text-[14px] ${LINK}`} href={SCRIPT_URL} target="_blank" rel="noopener noreferrer">scripts/garak-miss-to-proposals.ts</a>
              </p>
            </div>
          </div>

          {garak && full && (
            <div className="grid lg:grid-cols-[1fr_1.4fr] gap-4 lg:gap-20">
              <h2 className={H2}>{zh ? "量出來的結果" : "What it measures"}</h2>
              <div className={`${BODY} space-y-4`}>
                <p>
                  {zh
                    ? `在 garak 公開的 in-the-wild 越獄集（${count(garak.samples)} 筆）上，recall 是 ${recallLanes(garak)}。在完整的 garak 語料（${count(full.samples)} 筆，涵蓋所有 probe 家族）上，是 ${recallLanes(full)}。兩個數字都是 ${commonStamp([garak, full], true, true)}。`
                    : `On garak's public in-the-wild jailbreak set (${count(garak.samples)} samples), recall is ${recallLanes(garak)}. On the full garak corpus (${count(full.samples)} samples, every probe family) it is ${recallLanes(full)}. Both figures: ${commonStamp([garak, full], false)}.`}
                </p>
                <p>{zh ? toFullWidth(LANES_EXPLAINED.zh) : LANES_EXPLAINED.en}</p>
                <p>{zh ? toFullWidth(GARAK_BOTH_CLOSED_BOOK.zh) : GARAK_BOTH_CLOSED_BOOK.en}</p>
                <p>
                  {zh
                    ? "兩份語料的落差，有一部分是刻意的。規則的比對層不去追某些家族，像純語意的越獄；硬追只會換來脆弱的比對條件和誤報。比較低的那個數字，一樣公開。"
                    : "Part of the gap between the two corpora is deliberate. The pattern layer does not chase some families, such as purely semantic jailbreaks; forcing it would buy brittle patterns and false positives. The lower figure is published too."}
                </p>
              </div>
            </div>
          )}

          <div className="grid lg:grid-cols-[1fr_1.4fr] gap-4 lg:gap-20">
            <h2 className={H2}>{zh ? "garak 裡沒有 ATR" : "ATR is not inside garak"}</h2>
            <p className={BODY}>
              {zh ? (
                <>曾經有一個 PR 提議把 ATR 偵測器放進 garak（<a className={LINK} href={GARAK_PR_URL} target="_blank" rel="noopener noreferrer">garak #1676</a>）。提出它的 ATR 作者在 2026-08-04 撤回，沒有合併。</>
              ) : (
                <>A pull request once proposed ATR detectors inside garak (<a className={LINK} href={GARAK_PR_URL} target="_blank" rel="noopener noreferrer">garak #1676</a>). Its ATR author withdrew it on 2026-08-04, unmerged.</>
              )}
            </p>
          </div>
        </div>
      </SheetRow>

      <ToolLimits zh={zh} title={{ en: "Not open yet", zh: "目前沒有開放" }}>
        <p>
          {zh
            ? "讓外部團隊把自己的 garak 報告送進來、自動變成規則提案的管道，目前沒有開放，也不發放存取金鑰，開放時間還沒定。"
            : "There is no open path yet for outside teams to send in their own garak reports and have them turned into rule proposals. No access keys are issued, and there is no date."}
        </p>
        <p>
          {zh ? (
            <>現在要貢獻 garak 找到的攻擊，請走公開 repo 的流程：開 issue 或送 PR。做法寫在<Link className={LINK} href={`/${locale}/contribute`}>貢獻頁</Link>。</>
          ) : (
            <>To contribute an attack garak found today, use the public repository: open an issue or send a pull request. The <Link className={LINK} href={`/${locale}/contribute`}>contribute page</Link> shows how.</>
          )}
        </p>
      </ToolLimits>

      <SheetRow>
        <div className="px-6 md:px-14 py-12 flex flex-wrap gap-x-10 gap-y-3 text-[15px]">
          <Link className={LINK} href={`/${locale}/integrate`}>{zh ? "其他整合方式" : "Other ways to integrate"}</Link>
          <a className={LINK} href={GARAK_URL} target="_blank" rel="noopener noreferrer">NVIDIA garak</a>
        </div>
      </SheetRow>
    </>
    </Phrased>
  );
}
