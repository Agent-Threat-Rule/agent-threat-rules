/* ATR Eval: tests whether content an agent reads can hijack it, runs every
 * test many times, and signs the result. Not published yet; the page says
 * so. Claims follow the ATR Eval README and specification draft 0.9. */
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { SheetRow } from "@/components/Sheet";
import { EvalRun } from "@/components/EvalRun";
import { ToolHero, ToolFigure, ToolPoints, ToolLimits, ToolNext } from "@/components/ToolPage";
import Phrased from "@/components/Phrased";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  const zh = locale === "zh";
  return pageMetadata({
    locale,
    path: "/eval",
    title: "ATR Eval",
    description: zh
      ? "測你的 agent 讀到的內容能不能把它拐走。每題重跑多次，結果簽名，誰都能重算。尚未公開。"
      : "Tests whether what your agent reads can hijack it. Every test runs many times, and the signed result can be recomputed by anyone. Not yet public.",
  });
}

const POINTS = [
  {
    head: { en: "The checks get checked first", zh: "先確認檢查本身可靠" },
    body: {
      en: "Before every run, two scripted agents go first. One obeys every attack and must succeed on every test. The other does nothing and must succeed on none. If either result is off, the run doesn't start.",
      zh: "每次開跑前，先讓兩個寫死的 agent 上場。一個對所有攻擊都照做，每一題攻擊都必須得手；另一個什麼都不做，任何一題攻擊都不能得手。只要其中一個結果不對，這一輪就不開跑。",
    },
  },
  {
    head: { en: "Every test has a twin", zh: "每一題都有雙胞胎" },
    body: {
      en: "The same task runs the same number of times with the attack taken out. That's how you tell a setting that stops attacks from one that just stops the agent from doing its job.",
      zh: "同一個任務，把攻擊拿掉，再跑一樣多次。這樣你才分得出來，一個設定是真的擋下攻擊，還是乾脆讓 agent 什麼事都做不成。",
    },
  },
  {
    head: { en: "No model grades the result", zh: "不靠模型打分數" },
    body: {
      en: "Every test sets up a small mock world: mail, files, a payment account, a memory store, none of it real and none of it on the network. A fixed check reads what happened in that world and decides whether the attacker got what they wanted.",
      zh: "每一題都會搭一個小小的模擬世界：信箱、檔案、付款帳戶、記憶，全都是假的，也不連網。由固定的檢查去看那個世界裡發生了什麼，判定攻擊者有沒有得手。",
    },
  },
  {
    head: { en: "A receipt anyone can recompute", zh: "誰都能重算的收據" },
    body: {
      en: "The result is an in-toto statement signed with Ed25519, and the signature covers every verdict and the evidence behind it. Whoever holds it can check the signature and recompute every verdict from the evidence. The report comes in English and Traditional Chinese.",
      zh: "結果寫成一張 in-toto 收據，用 Ed25519 簽名，每一個判定和背後的證據都在簽章範圍裡。拿到收據的人可以驗簽，也能從證據把每個判定重算一遍。報告有中文和英文兩份。",
    },
  },
];

export default async function EvalPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";

  return (
    <Phrased>
    <>
      <SheetRow>
        <ToolHero
          zh={zh}
          name="ATR Eval"
          status={{ en: "Not yet public", zh: "尚未公開" }}
          title={{ en: "Once is luck. Ten times is evidence.", zh: "跑一次是運氣，跑十次才算數。" }}
          lead={{
            en: "ATR Eval tests whether what your agent reads can steer it into leaking data, running code, changing records or spending money. Each test runs at least ten times, each time in a fresh environment. A fixed check decides the outcome, and the result is signed.",
            zh: "ATR Eval 測的是：你的 agent 讀到的內容，能不能把它拐去洩漏資料、執行程式、改紀錄、花錢。每一題在全新的環境裡至少跑十次，由固定的檢查判定結果，最後簽名。",
          }}
        />
      </SheetRow>

      <ToolFigure>
        <div className="pt-8">
          <EvalRun locale={locale} />
        </div>
      </ToolFigure>

      <ToolPoints zh={zh} items={POINTS} />

      <ToolLimits zh={zh} title={{ en: "Where it falls short", zh: "現在的限制" }}>
        <p>
          {zh
            ? "照著收據把整輪從頭重跑，目前只在同一台機器上驗證過。測試庫有 10 題自己寫的，加上從公開基準匯入的題目。規格是 0.9 草案，由一個專案維護，還不是標準。"
            : "Reperformance, running everything again from the receipt, has only been shown on the same machine. The library has 10 tests of its own plus tests imported from public benchmarks. The specification is a 0.9 draft maintained by one project. It is not a standard."}
        </p>
        <p>
          {zh
            ? "利益揭露：維護者創辦並控制 PANGUARD AI, INC.，這家公司販售以 ATR 為基礎的 agent 資安產品。維護者自己跑出的結果，不算獨立評估。"
            : "Interests: the maintainer founded and controls PANGUARD AI, INC., which sells AI agent security products built on ATR. Results the maintainer produces are not independent."}
        </p>
        <p>{zh ? "ATR Eval 還沒公開，發布時間還沒定。" : "ATR Eval is not public yet, and there is no release date."}</p>
      </ToolLimits>

      <ToolNext href={`/${locale}/router`} label={zh ? "要測哪幾題，由 ATR Router 決定" : "Which tests to run is ATR Router's job"} />
    </>
    </Phrased>
  );
}
