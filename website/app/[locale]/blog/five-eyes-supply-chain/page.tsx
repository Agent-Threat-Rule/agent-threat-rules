import Link from "next/link";
import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { getPost } from "@/lib/posts";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

const post = getPost("five-eyes-supply-chain")!;

export const metadata: Metadata = {
  title: `${post.title.en} — ATR`,
  description: post.summary.en,
};

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="font-data text-[13px] bg-ash px-1.5 py-0.5">{children}</code>
  );
}

export default async function FiveEyesPostPage({
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
            2026 年 4 月底，Five Eyes 的網路安全機構——美國 CISA 與 NSA、澳洲 ASD-ACSC、
            加拿大 Cyber Centre，以及英國與紐西蘭的 NCSC——發布了《Careful Adoption of
            Agentic AI Services》。其中一句話扛起整份指引的重量：
          </p>
          <p>
            <strong className="text-ink">
              understand dependencies — manage supply chain risk for third-party components,
              models, tools and integrations.
            </strong>
          </p>
          <p>
            他們很明確地指出風險藏在哪。指引寫道，MCP「驗證的是工具介面，而非底層實作」——
            你的 agent 信任了它從未讀過的外部程式碼。
          </p>
          <p>
            所以我們去讀了。我們掃了五個公開 registry 的 96,096 個 AI agent skill 與 MCP
            server 定義檔。其中 1,302 個觸發了偵測規則，人工複審後 552 個確認為惡意——
            憑證竊取、靜默外滲、把命令執行藏在 agent 當成指令照單全收的工具描述裡。三個
            協同的發布者帳號出貨了其中絕大多數。
          </p>
          <p>
            指引要你驗證第三方元件。Agent Threat Rules(ATR)就是做這件事的開放、廠商中立、MIT
            授權標準——652 條機器可讀的偵測規則，對任何 skill 或 MCP manifest 秒級掃描，
            任何符合規範的引擎都能評估。就像 Sigma 把 SIEM 的偵測寫成共用格式、YARA 之於
            malware：機構點出了缺口，標準把它寫成大家都能跑的規則。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">指引點名的，正是我們抓到的</h2>
          <p>
            那批惡意元件不是理論。許多是不安全或被入侵的 MCP server，允許未認證的遠端命令
            執行——<Code>ATR-2026-00531</Code>(PraisonAI 未認證 agent API，CVE-2026-44338)、
            <Code>ATR-2026-00538</Code>(LangChain-ChatChat MCP RCE，CVE-2026-30617)、
            <Code>ATR-2026-00415</Code>(Flowise MCP 注入，CVE-2026-40933)各覆蓋一種。
            另一半是工具描述下毒——<Code>ATR-2026-00161</Code> 抓 MCP 工具描述裡的
            <Code>IMPORTANT</Code> 標籤跨工具遮蔽攻擊，<Code>ATR-2026-00103</Code> 抓藏在工具
            描述裡、要 LLM 無視安全機制的指令。
          </p>
          <p>
            說清楚這是什麼：pattern 偵測抓的是已知形狀，不是讀心。用 char code 拼出名稱、
            或走 DNS 外滲的變種會滑過。一個標準的可信度，取決於它願不願意說清楚自己抓不到什麼——
            所以把它當其中一層，不是唯一一層。但這一層，是指引要你建立的「第三方元件驗證」裡，
            唯一可以今天就跑起來的那塊。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">跑起來</h2>
          <pre className="bg-ink text-paper font-data text-[13px] p-4 overflow-x-auto">
            <code>npm install -g agent-threat-rules@3.5.0{"\n"}npx agent-threat-rules scan .</code>
          </pre>
          <p>
            指向你的 skill 目錄或 MCP 設定。如果它標記了一個你沒寫的元件，把它當成不可信，
            在你的 agent 接上它之前先處理掉。規則是開放的——讀它、測它、把我們漏掉的變種寄
            給我們。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">來源</h2>
          <ul className="space-y-2">
            <li>
              <a
                href="https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                Five Eyes: Careful Adoption of Agentic AI Services (2026-04-30)
              </a>
            </li>
            <li>
              <Link
                href={`/${locale}/research`}
                className="font-data text-xs text-blue hover:underline break-all"
              >
                ATR: 96,096 Skills, 552 Confirmed Malware — large-scale ecosystem scan
              </Link>
            </li>
          </ul>
        </article>
      ) : (
        <article className="text-[15px] text-graphite leading-[1.9] space-y-5">
          <p>
            In late April 2026 the Five Eyes cyber agencies — CISA and NSA in the US, Australia&rsquo;s
            ASD-ACSC, Canada&rsquo;s Cyber Centre, and the UK and New Zealand NCSCs — published{" "}
            <em>Careful Adoption of Agentic AI Services</em>. One line carries the weight of the
            whole document:
          </p>
          <p>
            <strong className="text-ink">
              understand dependencies — manage supply chain risk for third-party components,
              models, tools and integrations.
            </strong>
          </p>
          <p>
            They were specific about where the risk hides. MCP, the guidance says,
            &ldquo;validates tool interfaces rather than inspecting underlying implementations&rdquo;
            — your agent trusts external code it has never read.
          </p>
          <p>
            So we read it. We scanned 96,096 AI agent skills and MCP server definitions across
            five public registries. 1,302 tripped our detection rules; 552 were confirmed
            malicious after manual review — credential theft, silent exfiltration, command
            execution buried in tool descriptions an agent ingests as instructions. Three
            coordinated publisher accounts shipped most of them.
          </p>
          <p>
            The guidance asks you to verify third-party components. Agent Threat Rules (ATR) is
            the open, vendor-neutral, MIT-licensed standard that does exactly that — 652
            machine-readable detection rules, evaluable by any conformant engine, running against
            any skill or MCP manifest in seconds. The way Sigma made SIEM detections a shared
            format and YARA did it for malware: the agencies named the gap, and a standard turns it
            into rules anyone can run.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">
            What the guidance named is what we caught
          </h2>
          <p>
            That malicious set is not theoretical. Many were insecure or compromised MCP servers
            allowing unauthenticated remote code execution — <Code>ATR-2026-00531</Code>{" "}
            (PraisonAI unauthenticated agent API, CVE-2026-44338), <Code>ATR-2026-00538</Code>{" "}
            (LangChain-ChatChat MCP RCE, CVE-2026-30617), and <Code>ATR-2026-00415</Code>{" "}
            (Flowise MCP injection, CVE-2026-40933) each cover one. The other half is tool-description
            poisoning — <Code>ATR-2026-00161</Code> catches the <Code>IMPORTANT</Code>-tag
            cross-tool shadowing attack inside MCP tool descriptions, and{" "}
            <Code>ATR-2026-00103</Code> catches instructions hidden in a tool description that tell
            the LLM to ignore its safety mechanisms.
          </p>
          <p>
            Be clear about what this is. Pattern detection catches the known shape; it does not
            read minds. A variant that builds names from char codes, or exfiltrates over DNS, will
            slip past. A standard earns trust by being explicit about what it cannot catch — so run
            it as one layer, not the only one. But it is the one layer of the &ldquo;third-party
            component verification&rdquo; the guidance asks for that you can run today.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">Run it</h2>
          <pre className="bg-ink text-paper font-data text-[13px] p-4 overflow-x-auto">
            <code>npm install -g agent-threat-rules@3.5.0{"\n"}npx agent-threat-rules scan .</code>
          </pre>
          <p>
            Point it at your skill directory or MCP config. If it flags a component you did not
            write, treat it as untrusted and deal with it before your agent wires it in. The rules
            are open — read them, test them, send us a variant we miss.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">Sources</h2>
          <ul className="space-y-2">
            <li>
              <a
                href="https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                Five Eyes: Careful Adoption of Agentic AI Services (2026-04-30)
              </a>
            </li>
            <li>
              <Link
                href={`/${locale}/research`}
                className="font-data text-xs text-blue hover:underline break-all"
              >
                ATR: 96,096 Skills, 552 Confirmed Malware — large-scale ecosystem scan
              </Link>
            </li>
          </ul>
        </article>
      )}
    </div>
  );
}
