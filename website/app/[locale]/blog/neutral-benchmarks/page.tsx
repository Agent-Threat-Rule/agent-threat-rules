import Link from "next/link";
import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { getPost } from "@/lib/posts";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

const post = getPost("neutral-benchmarks")!;

export const metadata: Metadata = {
  title: `${post.title.en} — ATR`,
  description: post.summary.en,
};

export default async function NeutralBenchmarksPostPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: rawLocale } = await params;
  const locale = (locales.includes(rawLocale as Locale) ? rawLocale : "en") as Locale;
  const zh = locale === "zh";

  return (
    <div className="pt-20 pb-20 px-5 md:px-6 max-w-[760px] mx-auto">
      <Reveal>
        <Link
          href={`/${locale}/blog`}
          className="font-data text-xs text-stone hover:text-ink transition-colors"
        >
          ← Blog
        </Link>
      </Reveal>
      <Reveal delay={0.05}>
        <div className="font-data text-xs text-mist mt-6 mb-3">{post.date}</div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="font-display text-[clamp(26px,3.6vw,40px)] font-extrabold tracking-[-1.5px] leading-[1.15] text-ink mb-10">
          {zh ? post.title.zh : post.title.en}
        </h1>
      </Reveal>

      {zh ? (
        <article className="text-[15px] text-graphite leading-[1.9] space-y-5">
          <p>
            一個偵測標準,可信度就等於它背後那些數字——而自己發布的數字,是最容易灌水的一種。
            所以我們反過來做:拿 Agent Threat Rules(ATR)去跑兩個我們沒有參與製作的獨立開放
            benchmark,用它們自己的 harness,把結果原樣公開——包括 ATR 表現差的地方。
          </p>
          <p>
            用兩個 benchmark,是因為它們量的是兩件不同的事。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">OpenGuardrails:runtime 偵測</h2>
          <p>
            OpenGuardrails 的 benchmark 用一批共用的 agent runtime 事件語料——prompt injection、
            惡意命令、資料外洩、憑證洩漏——替偵測器打分,以 macro-F1 排名並帶 p95 延遲預算。這是
            ATR 的主場:它是一套偵測 agent 即時輸入、輸出、工具呼叫與 MCP 交換中攻擊的規則標準。
          </p>
          <p>
            把現行 ATR 規則集丟進 OpenGuardrails 的 harness,ATR 在 seed suite 的七個參考偵測器裡
            <strong className="text-ink">排第一</strong>——贏過 config 加 LLM 的組合偵測器——而且對
            benign 語料<strong className="text-ink">零誤報</strong>。它在惡意命令與資料外洩最強;
            最弱的一條是改寫過的自然語言注入,那正是純 pattern 層的已知極限,也正是語意層能補的地方。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">OASB:靜態 skill 與套件掃描</h2>
          <p>
            Open Agent Security Benchmark(OASB)量的是另一件事:對一批標記過的 skill 與套件
            工件——agent 會安裝的靜態原始碼——做偵測,裡面有三千八百多個良性樣本、數百個惡意樣本。
          </p>
          <p>
            這裡的結果是兩面的,值得直說。對全部 3,881 個良性 skill,ATR 觸發了
            <strong className="text-ink">零誤報</strong>——是那張榜上所有掃描器裡誤報率最低的,
            比專門做靜態掃描的工具還低。但它的 recall 很低:惡意 skill 工件大約每五個抓到一個。
          </p>
          <p>
            這個落差不是 bug,我們也不會替它擦脂抹粉。ATR 偵測的是 runtime 的 agent 行為,它不是
            原始碼掃描器或套件掃描器,而 OASB 裡多數惡意工件是靜態的供應鏈 pattern——寫死在
            manifest 裡的持久化、埋在程式碼中稍後才執行的外洩邏輯——這些是一個 runtime 偵測器在
            執行前本來就看不到的。在這個語料上,AST 型的靜態掃描器 recall 贏 ATR 是應該的,因為那
            就是它們生來要做的。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">我們的結論</h2>
          <p>
            ATR 是一個精準的 runtime 偵測層,不是靜態套件掃描器,而這兩個 benchmark 從相反方向
            都這麼說。它被設計來運作的地方——即時 agent 流量——它領先;它不擅長的地方——靜態供應鏈
            原始碼——它誠實、安靜、覆蓋低。貫穿兩者的那條線是精準度:跨兩個 benchmark、數千個
            良性輸入,它一次都沒亂叫。
          </p>
          <p>
            對任何在做 agent 安全的人,實務上的讀法是:runtime 發生的事,用一個 runtime 偵測標準;
            供應鏈裡出貨的東西,配一個原始碼與套件掃描器;不要相信任何宣稱一個層就把兩件事都做掉
            的東西。縱深防禦在這裡不是口號,是 benchmark 量得出來的。
          </p>
          <p>
            我們公開的是我們跑到的數字,不是我們希望看到的數字。只有這種數字,值得站在後面。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">來源</h2>
          <ul className="space-y-2">
            <li>
              <a href="https://github.com/openguardrails/openguardrails-bench" target="_blank" rel="noopener noreferrer" className="text-ink underline decoration-mist hover:decoration-ink">OpenGuardrails Benchmark</a>
            </li>
            <li>
              <a href="https://github.com/opena2a-org/oasb" target="_blank" rel="noopener noreferrer" className="text-ink underline decoration-mist hover:decoration-ink">Open Agent Security Benchmark (OASB)</a>
            </li>
          </ul>
        </article>
      ) : (
        <article className="text-[15px] text-graphite leading-[1.9] space-y-5">
          <p>
            A detection standard is only as trustworthy as the numbers behind it — and self-published
            numbers are the easiest kind to game. So we did the opposite: we ran Agent Threat Rules
            (ATR) through two independent, open agent-security benchmarks we did not build, using their
            own harnesses, and we&apos;re publishing the results as they came out — including where ATR
            is weak.
          </p>
          <p>Two benchmarks, because they measure two different things.</p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">OpenGuardrails: runtime detection</h2>
          <p>
            The OpenGuardrails benchmark scores detectors on a shared corpus of agent runtime events —
            prompt injection, malicious commands, data exfiltration, secret leakage — and ranks them by
            macro-F1 with a p95-latency budget. This is ATR&apos;s home turf: it is a rule standard for
            detecting attacks in an agent&apos;s live input, output, tool calls, and MCP exchanges.
          </p>
          <p>
            Running the current ATR rule set through the OpenGuardrails harness, ATR placed{" "}
            <strong className="text-ink">first</strong> among the seven reference detectors in the seed
            suite — ahead of the composed config-plus-LLM detector — with{" "}
            <strong className="text-ink">zero false positives</strong> on the benign set. It was
            strongest on malicious-command and data-exfiltration detection, and its weakest lane,
            paraphrased natural-language injection, is exactly where a pure pattern layer has known
            limits and where a semantic layer helps.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">OASB: static skill and package scanning</h2>
          <p>
            The Open Agent Security Benchmark (OASB) measures something different: detection over a
            labeled corpus of skill and package artifacts — the static source an agent would install —
            with over 3,800 benign samples and a few hundred malicious ones.
          </p>
          <p>
            Here the result is two-sided, and worth stating plainly. Across every one of the 3,881
            benign skills, ATR raised <strong className="text-ink">zero false positives</strong> — the
            lowest false-positive rate of any scanner on that board, better than the purpose-built
            static scanners. But its recall was low: it caught roughly one in five of the malicious
            skill artifacts.
          </p>
          <p>
            That gap is not a bug, and we are not going to dress it up. ATR detects agent behavior at
            runtime. It is not a source-code or package scanner, and most of the malicious artifacts in
            OASB are static supply-chain patterns — persistence baked into a manifest, exfiltration
            logic in code that only runs later — that a runtime detector is not designed to find before
            execution. On this corpus the AST-based static scanners rightly beat ATR on recall, because
            that is what they are built for.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">What we take from it</h2>
          <p>
            ATR is a precise runtime detection layer, not a static package scanner, and the two
            benchmarks say so in opposite directions. Where ATR is designed to work — live agent
            traffic — it leads. Where it isn&apos;t — static supply-chain source — it is honest, quiet,
            and low-coverage. The through-line across both is precision: on thousands of benign inputs
            across both benchmarks, it did not cry wolf once.
          </p>
          <p>
            The practical read for anyone building agent security: use a runtime detection standard for
            what happens at runtime, pair it with a source and package scanner for what ships in the
            supply chain, and don&apos;t trust any single layer that claims to do both. Defense in depth
            is not a slogan here; the benchmarks make it measurable.
          </p>
          <p>
            We&apos;re publishing the numbers we got, not the numbers we wish we had. That is the only
            kind worth standing behind.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">Sources</h2>
          <ul className="space-y-2">
            <li>
              <a href="https://github.com/openguardrails/openguardrails-bench" target="_blank" rel="noopener noreferrer" className="text-ink underline decoration-mist hover:decoration-ink">OpenGuardrails Benchmark</a>
            </li>
            <li>
              <a href="https://github.com/opena2a-org/oasb" target="_blank" rel="noopener noreferrer" className="text-ink underline decoration-mist hover:decoration-ink">Open Agent Security Benchmark (OASB)</a>
            </li>
          </ul>
        </article>
      )}
    </div>
  );
}
