import Link from "next/link";
import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { getPost } from "@/lib/posts";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

const post = getPost("unit42-skill-supply-chain")!;

export const metadata: Metadata = {
  title: `${post.title.en} — ATR`,
  description: post.summary.en,
};

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="font-data text-[13px] bg-ash px-1.5 py-0.5">{children}</code>
  );
}

export default async function Unit42SkillSupplyChainPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: rawLocale } = await params;
  const locale = (locales.includes(rawLocale as Locale) ? rawLocale : "en") as Locale;
  const zh = locale === "zh";

  const blogUrl = "https://unit42.paloaltonetworks.com/ai-agent-supply-chain-risks/";
  const paperUrl = "https://arxiv.org/abs/2605.11770";
  const crosswalkUrl =
    "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/crosswalks/atr-unit42-biv-crosswalk.md";

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
            2026 年 6 月,Palo Alto Networks 的 Unit 42 發表了一份 agent-skill 供應鏈研究,
            提出 Behavioral Integrity Verification(BIV)。他們靜態掃了一個公開 registry 上的{" "}
            <strong className="text-ink">49,943 個 skill</strong>,發現{" "}
            <strong className="text-ink">80% 的 skill 實際行為與它宣告的不符</strong>,其中
            18.9% 帶對抗性意圖。
          </p>
          <p>
            這對我們不是新聞——是<strong className="text-ink">第二份獨立資料集,落在我們早就到過的結論上</strong>。
            我們掃過六個公開 registry 的 96,096 個 skill:1,302 個被標記、人工複審後 552 個確認惡意、
            歸因到三個協同發布者。兩支團隊、兩個資料集、兩套方法,得到同一句話:
            <strong className="text-ink">agent-skill 供應鏈就是攻擊面。</strong>沒有人在猜。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">BIV 和 ATR 是不同的兩層</h2>
          <p>
            這件事值得講清楚,因為它決定了怎麼防。BIV 是一套<strong className="text-ink">驗證</strong>框架:
            它解析 skill 的 manifest 宣告了哪些能力、再從程式碼靜態推論它<em>實際</em>有哪些能力,
            當兩個集合對不上就標記。訊號是「宣告 ≠ 實際」這個落差本身,發生在安裝時。
          </p>
          <p>
            ATR 是<strong className="text-ink">runtime 偵測內容</strong>——一套機讀規則,對 agent 的輸入、
            輸出、工具描述、skill 與呼叫序列裡的攻擊 pattern 開火。所以 ATR 對映到 BIV 的
            <strong className="text-ink">「實際行為」那半</strong>:對某個能力,ATR 回答的是
            「當它被<em>惡意地</em>使用時,有沒有規則會 fire?」這兩層互補——安裝時的 static 驗證,
            加上 runtime 的攻擊偵測。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">我們把他們的 taxonomy 對映進來——結果戳到我們自己一個洞</h2>
          <p>
            我們把 BIV 的 7 個能力家族、29 個能力,逐一對映到 ATR 的規則類別。過程裡,他們論文的
            canonical 憑證外洩範例——一段 Python:<Code>os.environ</Code> 讀密鑰 →{" "}
            <Code>base64</Code> 編碼 → <Code>requests.post</Code> 送出——我們拿去打全部 748 條規則,
            <strong className="text-ink">0 條命中</strong>。
          </p>
          <p>
            原因很誠實:我們既有的憑證外洩鏈規則(<Code>ATR-2026-00201</Code>、
            <Code>ATR-2026-00224</Code>)綁的是 shell 語法(<Code>cat ~/.aws/credentials | base64 | curl</Code>),
            漏掉了程式碼面(Python/Node)的等價行為。所以我們補了一條語言無關的規則,
            <Code>ATR-2026-02261</Code>:偵測「密鑰讀取 → 編碼 → 對外送出」三段依序、鄰近出現的鏈,
            過了 65K 良性語料 0 誤報與泛化 gate。這條規則<strong className="text-ink">從攻擊機制寫,不是從報告文字寫</strong>——
            後者正是一種會偵測「報告本身」而非「攻擊」的失敗模式,我們的 generalization gate 就是擋這個。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">這裡 ATR 不做什麼</h2>
          <p>
            一個標準的可信度,取決於它願不願意畫出邊界。BIV 的核心機制——比對 manifest 宣告與程式碼實際、
            算出兩個 typed set 的差集——<strong className="text-ink">不是 ATR 做的事</strong>。ATR 不解析 manifest,
            供不了「宣告」那半,所以 declared-vs-actual 的差集這一步在 ATR 範圍之外。ATR 是那個
            runtime 偵測層,不是驗證器。把它當其中一層,不是唯一一層。完整的對映——29 個能力、4 個
            compound threat,每一項都標了 Detection / Partial / Out-of-scope——
            {" "}
            <a href={crosswalkUrl} target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">
              在這裡
            </a>
            。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">跑起來</h2>
          <pre className="bg-ink text-paper font-data text-[13px] p-4 overflow-x-auto">
            <code>npm install -g agent-threat-rules{"\n"}npx agent-threat-rules scan .</code>
          </pre>
          <p>
            指向你的 skill 目錄或 MCP 設定。規則是開放、MIT 授權的——讀它、測它、把我們漏掉的變種寄給我們。
            這次那條 <Code>ATR-2026-02261</Code> 就是這樣來的:一份公開研究的 payload,戳出一個真缺口。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">來源</h2>
          <ul className="space-y-2">
            <li>
              <a href={blogUrl} target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline break-all">
                Palo Alto Unit 42: AI Agent Supply Chain Risks (Behavioral Integrity Verification)
              </a>
            </li>
            <li>
              <a href={paperUrl} target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline break-all">
                Behavioral Integrity Verification for AI Agent Skills — arXiv:2605.11770
              </a>
            </li>
            <li>
              <a href={crosswalkUrl} target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline break-all">
                ATR → Unit 42 BIV crosswalk (7 families / 29 capabilities, per-item)
              </a>
            </li>
          </ul>
        </article>
      ) : (
        <article className="text-[15px] text-graphite leading-[1.9] space-y-5">
          <p>
            In June 2026 Palo Alto Networks&rsquo; Unit 42 published research on the agent-skill supply
            chain, introducing Behavioral Integrity Verification (BIV). They statically scanned{" "}
            <strong className="text-ink">49,943 skills</strong> on a public registry and found that{" "}
            <strong className="text-ink">80% of skills deviate from their declared behavior</strong>,
            18.9% of them with adversarial intent.
          </p>
          <p>
            To us that isn&rsquo;t news — it&rsquo;s a{" "}
            <strong className="text-ink">second independent dataset landing on a conclusion we had already
            reached</strong>. We scanned 96,096 skills across six public registries: 1,302 flagged, 552
            confirmed malicious after manual review, attributed to three coordinated publishers. Two
            teams, two datasets, two methods, one sentence:{" "}
            <strong className="text-ink">the agent-skill supply chain is the attack surface.</strong>{" "}
            Nobody is guessing.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">BIV and ATR are two different layers</h2>
          <p>
            This is worth stating because it decides how you defend. BIV is a{" "}
            <strong className="text-ink">verification</strong> framework: it parses which capabilities a
            skill&rsquo;s manifest <em>declares</em>, statically infers which capabilities its code{" "}
            <em>actually</em> has, and flags the skill when the two sets diverge. The signal is the
            declared-vs-actual gap itself, at install time.
          </p>
          <p>
            ATR is <strong className="text-ink">runtime detection content</strong> — machine-readable
            rules that fire on attack patterns in an agent&rsquo;s inputs, outputs, tool descriptions,
            skills, and call sequences. So ATR maps onto the{" "}
            <strong className="text-ink">observed-behavior half</strong> of BIV&rsquo;s comparison: for a
            given capability, ATR answers &ldquo;is there a rule that fires when this is exercised{" "}
            <em>maliciously</em>?&rdquo; The two layers are complementary — static verification at
            install, plus attack detection at runtime.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">
            We mapped their taxonomy in — and it found a hole in ours
          </h2>
          <p>
            We mapped BIV&rsquo;s 7 capability families and 29 capabilities onto ATR&rsquo;s rule
            classes. Along the way, their paper&rsquo;s canonical credential-exfiltration example — a
            Python chain that reads a secret with <Code>os.environ</Code>, encodes it with{" "}
            <Code>base64</Code>, and ships it with <Code>requests.post</Code> — we ran against all 748
            rules and got <strong className="text-ink">zero hits</strong>.
          </p>
          <p>
            The reason is honest: our existing exfil-chain rules (<Code>ATR-2026-00201</Code>,{" "}
            <Code>ATR-2026-00224</Code>) key on shell syntax (<Code>cat ~/.aws/credentials | base64 | curl</Code>)
            and miss the code-surface (Python/Node) equivalent. So we shipped a language-agnostic rule,{" "}
            <Code>ATR-2026-02261</Code>, that fires on the ordered, proximate chain of secret-read →
            encode → outbound send, passing the 65K-sample benign 0-false-positive gate and the
            generalization gate. It is written{" "}
            <strong className="text-ink">from the attack mechanism, not from the report&rsquo;s prose</strong>{" "}
            — the latter is a failure mode that detects the report rather than the attack, which our
            generalization gate exists to block.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">What ATR does not do here</h2>
          <p>
            A standard earns trust by drawing its boundary. BIV&rsquo;s core mechanism — comparing the
            manifest&rsquo;s declared capabilities against the code&rsquo;s actual ones and taking the
            set difference — <strong className="text-ink">is not something ATR does</strong>. ATR does
            not parse a manifest and cannot supply the declared half, so the declared-vs-actual
            set-difference step is out of its scope. ATR is the runtime detection layer, not the
            verifier. Run it as one layer, not the only one. The full mapping — 29 capabilities, 4
            compound threats, each rated Detection / Partial / Out-of-scope — is{" "}
            <a href={crosswalkUrl} target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">
              here
            </a>
            .
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">Run it</h2>
          <pre className="bg-ink text-paper font-data text-[13px] p-4 overflow-x-auto">
            <code>npm install -g agent-threat-rules{"\n"}npx agent-threat-rules scan .</code>
          </pre>
          <p>
            Point it at your skill directory or MCP config. The rules are open and MIT-licensed — read
            them, test them, send us a variant we miss. That is exactly how{" "}
            <Code>ATR-2026-02261</Code> got here: a payload from public research that exposed a real gap.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">Sources</h2>
          <ul className="space-y-2">
            <li>
              <a href={blogUrl} target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline break-all">
                Palo Alto Unit 42: AI Agent Supply Chain Risks (Behavioral Integrity Verification)
              </a>
            </li>
            <li>
              <a href={paperUrl} target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline break-all">
                Behavioral Integrity Verification for AI Agent Skills — arXiv:2605.11770
              </a>
            </li>
            <li>
              <a href={crosswalkUrl} target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline break-all">
                ATR → Unit 42 BIV crosswalk (7 families / 29 capabilities, per-item)
              </a>
            </li>
          </ul>
        </article>
      )}
    </div>
  );
}
