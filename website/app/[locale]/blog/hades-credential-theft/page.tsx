import Link from "next/link";
import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { getPost } from "@/lib/posts";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

const post = getPost("hades-credential-theft")!;

export const metadata: Metadata = {
  title: `${post.title.en} — ATR`,
  description: post.summary.en,
};

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="font-data text-[13px] bg-ash px-1.5 py-0.5">{children}</code>
  );
}

export default async function HadesPostPage({
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
            2026 年 6 月 8 日，Socket 標記了 Shai-Hulud 蠕蟲的新一波攻擊——追蹤代號
            「Hades」/ Mini-Shai-Hulud / Miasma。6 月 9 日媒體跟進。新的部分，也是這裡要談的原因：
            這一波獵的是 AI agent 憑證。
          </p>
          <p>
            這些是惡意的 npm 與 PyPI 套件，許多是 MCP 函式庫的 typosquat——
            <Code>langchain-core-mcp</Code>、<Code>instructor-mcp</Code>、<Code>openai-mcp</Code>、
            <Code>tiktoken-mcp</Code>、<Code>ray-mcp-server</Code>。
            裝了或 import 了其中一個，就會跑起一個 Bun/Node 竊取程式。它讀你的{" "}
            <Code>ANTHROPIC_API_KEY</Code>、你的 Claude desktop 設定、你的 <Code>.mcp.json</Code>，
            接著掃 <Code>.npmrc</Code>、<Code>.pypirc</Code>、SSH 金鑰、雲端憑證，
            整包送到攻擊者的 endpoint。這個攻擊活動每隔幾天就換一輪套件名。
          </p>
          <p>
            再讀一次那份目標清單。你的 Anthropic key。你的 MCP 設定。
            AI agent 開發者隨手放著的那些檔案，現在就是獎品。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">ATR 偵測什麼</h2>
          <p>
            ATR 是 AI agent 威脅的開放、廠商中立偵測標準——652 條機器可讀規則，MIT 授權，
            一經發布 ID 永不更動，任何符合規範的引擎都能評估。當一個攻擊活動每隔幾天就換套件名，
            穩定、可引用的規則 ID 正是讓多方對得上同一條偵測的東西。規則 ATR-2026-00576 涵蓋
            Hades 的憑證竊取階段，與 ATR-2026-00575 互補——後者偵測 Miasma 的 agent 設定檔
            後門，同一個攻擊活動的另一半。
          </p>
          <p>規則在兩種形狀上觸發：</p>
          <p>
            <strong className="text-ink">定向讀取加外送。</strong>
            程式碼讀取 AI agent 機密——<Code>ANTHROPIC_API_KEY</Code>、Claude 設定、
            <Code>.mcp.json</Code>——而且與對外網路傳送(<Code>requests.post</Code>、
            <Code>fetch</Code>、<Code>urllib</Code>、<Code>curl</Code>)共現。
            單純的讀取沒事；讀取緊鄰著外滲，才是攻擊。
          </p>
          <p>
            <strong className="text-ink">全面收割。</strong>
            程式碼撈兩個以上的憑證庫——<Code>.npmrc</Code>、<Code>.pypirc</Code>、AWS 憑證、
            SSH 金鑰——其中之一是 AI agent 機密，然後把整包導向遠端主機。
          </p>
          <p>
            說清楚這是什麼：它比對的是簽名——agent 憑證讀取緊鄰外滲。它不會讀心。
            用 char code 拼出環境變數名稱的變種，或走 DNS 外滲的變種，會滑過 pattern 比對——
            字面 token 根本不出現。Pattern 偵測抓的是已知形狀。把它當其中一層，不是唯一一層。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">跑起來</h2>
          <pre className="bg-ink text-paper font-data text-[13px] p-4 overflow-x-auto">
            <code>npm install -g agent-threat-rules@3.5.0{"\n"}npx agent-threat-rules scan .</code>
          </pre>
          <p>
            如果它標記了一個你沒寫的套件或檔案，把整個 checkout 當成已被入侵。
            先輪替你的 Anthropic API key——那是有即時爆炸半徑的一把——再輪替
            npm、PyPI、雲端、SSH 憑證。然後稽核最近安裝的套件，找 typosquat 的 MCP 套件名。
          </p>
          <p>規則是開放的。讀它、測它、把我們漏掉的變種寄給我們。</p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">來源</h2>
          <ul className="space-y-2">
            <li>
              <a
                href="https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                Socket: Mini-Shai-Hulud, Miasma and Hades worms target MCP developers
              </a>
            </li>
            <li>
              <a
                href="https://thehackernews.com/2026/06/hades-pypi-attack-19-packages-poisoned.html"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                The Hacker News: Hades PyPI attack — 19 packages poisoned
              </a>
            </li>
          </ul>
        </article>
      ) : (
        <article className="text-[15px] text-graphite leading-[1.9] space-y-5">
          <p>
            On June 8, 2026, Socket flagged a new wave of the Shai-Hulud worm — tracked as
            &ldquo;Hades&rdquo; / Mini-Shai-Hulud / Miasma. By June 9 the press had it. The novel
            part, and the reason it matters here: this wave hunts AI-agent credentials.
          </p>
          <p>
            The packages are malicious npm and PyPI uploads, many of them typosquats of MCP
            libraries — <Code>langchain-core-mcp</Code>, <Code>instructor-mcp</Code>,{" "}
            <Code>openai-mcp</Code>, <Code>tiktoken-mcp</Code>, <Code>ray-mcp-server</Code>.
            Install or import one and a Bun/Node stealer runs. It reads your{" "}
            <Code>ANTHROPIC_API_KEY</Code>, your Claude desktop config, and your{" "}
            <Code>.mcp.json</Code>, then sweeps <Code>.npmrc</Code>, <Code>.pypirc</Code>, SSH
            keys, and cloud credentials, and ships the lot to an attacker endpoint. The campaign
            rotates package names every couple of days.
          </p>
          <p>
            Read that target list again. Your Anthropic key. Your MCP config. The files an
            AI-agent developer has lying around are now the prize.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">What ATR detects</h2>
          <p>
            ATR is an open, vendor-neutral detection standard for AI agent threats — 652
            machine-readable rules, MIT licensed, with IDs that never change once published and
            that any conformant engine can evaluate. When a campaign rotates package names every
            few days, a stable, citable rule ID is exactly what lets different parties point at the
            same detection. Rule ATR-2026-00576 covers the Hades credential-theft stage, and it
            complements ATR-2026-00575, which detects the Miasma agent-config backdoor — the
            config-injection half of the same campaign.
          </p>
          <p>The rule fires on two shapes:</p>
          <p>
            <strong className="text-ink">The targeted read-and-send.</strong> Code that reads an
            AI-agent secret — <Code>ANTHROPIC_API_KEY</Code>, the Claude config,{" "}
            <Code>.mcp.json</Code> — and is co-located with an outbound network send (
            <Code>requests.post</Code>, <Code>fetch</Code>, <Code>urllib</Code>,{" "}
            <Code>curl</Code>). The read alone is fine; the read next to an exfil is the attack.
          </p>
          <p>
            <strong className="text-ink">The harvest-everything sweep.</strong> Code that pulls
            two or more credential stores — <Code>.npmrc</Code>, <Code>.pypirc</Code>, AWS
            credentials, SSH keys — where one of them is an AI-agent secret, and pipes the bundle
            to a remote host.
          </p>
          <p>
            Be clear about what this is. It matches the signature: an agent-credential read beside
            an exfil. It does not read minds. A variant that builds the env-var name from char
            codes, or exfiltrates over DNS, will slip past a pattern match — the literal tokens
            never appear. Pattern detection catches the known shape. Run it as one layer, not the
            only one.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">Run it</h2>
          <pre className="bg-ink text-paper font-data text-[13px] p-4 overflow-x-auto">
            <code>npm install -g agent-threat-rules@3.5.0{"\n"}npx agent-threat-rules scan .</code>
          </pre>
          <p>
            If it flags a package or a file you did not write, treat the checkout as compromised.
            Rotate your Anthropic API key first — that is the one with a live blast radius — then
            the npm, PyPI, cloud, and SSH credentials. Then audit recent installs for typosquatted
            MCP package names.
          </p>
          <p>The rules are open. Read them, test them, send us a variant we miss.</p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">Sources</h2>
          <ul className="space-y-2">
            <li>
              <a
                href="https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                Socket: Mini-Shai-Hulud, Miasma and Hades worms target MCP developers
              </a>
            </li>
            <li>
              <a
                href="https://thehackernews.com/2026/06/hades-pypi-attack-19-packages-poisoned.html"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                The Hacker News: Hades PyPI attack — 19 packages poisoned
              </a>
            </li>
          </ul>
        </article>
      )}
    </div>
  );
}
