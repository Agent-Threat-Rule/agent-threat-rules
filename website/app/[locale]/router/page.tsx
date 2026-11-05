/* ATR Router: the layer in front of ATR Eval that decides which tests apply
 * to an agent, how to run them, and in what format the result goes back.
 * Not published yet; the page says so. Status of each part follows
 * docs/designs/agent-eval-v1/ROUTER.md in the operations repo. */
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { SheetRow } from "@/components/Sheet";
import { RouterFlow } from "@/components/RouterFlow";
import { ToolHero, ToolFigure, ToolPoints, ToolLimits, ToolNext } from "@/components/ToolPage";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  const zh = locale === "zh";
  return pageMetadata({
    locale,
    path: "/router",
    title: "ATR Router",
    description: zh
      ? "先讀出 agent 碰得到什麼，只挑跟它有關的測試，結果用對方習慣的格式交回。尚未公開。"
      : "Reads what an agent can reach, keeps only the tests that apply, and returns the result in the format the reader uses. Not yet public.",
  });
}

const POINTS = [
  {
    head: { en: "What it can reach", zh: "它碰得到什麼" },
    body: {
      en: "Router starts each of your MCP servers once and reads the tool list. From each tool's name it works out what the tool does: reading mail, sending it out, changing records, spending money. Anything it can't work out is treated as possibly consequential. If it guessed wrong, correct it in agent.yaml.",
      zh: "Router 會把你的每一台 MCP 伺服器各啟動一次，讀出工具清單，再從工具名稱推它會做什麼：讀信、往外寄、改資料、花錢。推不出來的，一律當成可能有後果。推錯了，在 agent.yaml 裡改掉就好。",
    },
  },
  {
    head: { en: "What to test", zh: "要測什麼" },
    body: {
      en: "Every test states what it needs: where the attack comes in, and what it wants the agent to do. When an agent doesn't have those, the test is marked not applicable and isn't run. The choice follows fixed rules, not a model's judgement, so anyone who runs it gets the same list.",
      zh: "每一題測試都寫明它需要什麼：攻擊從哪裡進來，想讓 agent 做什麼。你的 agent 沒有這些，那一題就標成不適用，不跑。挑選照固定的規則走，不交給模型判斷，所以誰來跑，挑出來的都一樣。",
    },
  },
  {
    head: { en: "Who gets the result", zh: "結果交給誰" },
    body: {
      en: "Developers get SARIF that drops straight into CI. GRC tools get OSCAL, valid against the OSCAL schema. Auditors and insurers get the signed receipt from ATR Eval.",
      zh: "開發者拿到 SARIF，直接進 CI。GRC 工具拿 OSCAL，格式符合 OSCAL schema。稽核和保險公司，拿 ATR Eval 簽過名的收據。",
    },
  },
];

export default async function RouterPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";

  return (
    <>
      <SheetRow>
        <ToolHero
          zh={zh}
          name="ATR Router"
          emblem="labyrinth"
          status={{ en: "Not yet public", zh: "尚未公開" }}
          title={{ en: "First, work out what to test.", zh: "先想清楚，要測什麼。" }}
          lead={{
            en: "Every agent reaches different things. One reads mail, another can pay, another runs code. Test them all with the same list and you either miss what matters or waste the run. Router reads what your agent can reach first, keeps the tests that apply, and hands the result back in the format your reader already uses.",
            zh: "每個 agent 碰得到的東西都不一樣。有的會讀信，有的能付錢，有的會執行程式。拿同一份清單去測，不是漏掉重要的，就是白跑一場。Router 先讀出你的 agent 碰得到什麼，只留下適用的測試，結果再用對方習慣的格式交回去。",
          }}
        />
      </SheetRow>

      <ToolFigure>
        <RouterFlow locale={locale} />
      </ToolFigure>

      <ToolPoints zh={zh} items={POINTS} />

      <ToolLimits zh={zh} title={{ en: "Not done yet", zh: "還沒做到的" }}>
        <p>
          {zh
            ? "目前能直接測的是 Claude Code、Grok Build，以及任何能讀標準 MCP 設定檔的 agent。Codex、goose、OpenHands 還沒有轉接。"
            : "Today it can test Claude Code, Grok Build, and any agent that reads a standard MCP config file. Codex, goose and OpenHands have no adapter yet."}
        </p>
        <p>
          {zh
            ? "還沒做的，還有 Inspect 格式，讓政府評測單位能用同一批測試自己重跑；夾在真實 agent 和工具之間的代理模式；以及把結果對到 EU AI Act 附件 IV 的頁面。"
            : "Also not built: Inspect support, so government evaluators can rerun the same tests themselves; a proxy mode that sits between a real agent and its tools; and a page that maps results to Annex IV of the EU AI Act."}
        </p>
        <p>
          {zh
            ? "Router 還沒公開。現在只在維護者手上跑，發布時間還沒定。"
            : "Router is not public. It runs on the maintainers' machines today, and there is no release date."}
        </p>
      </ToolLimits>

      <ToolNext href={`/${locale}/eval`} label={zh ? "挑好之後，交給 ATR Eval 去跑" : "Once the tests are picked, ATR Eval runs them"} />
    </>
  );
}
