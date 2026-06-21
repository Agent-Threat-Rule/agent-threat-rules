import Link from "next/link";
import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { getPost } from "@/lib/posts";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

const post = getPost("this-weeks-mcp-cves")!;

export const metadata: Metadata = {
  title: `${post.title.en} — ATR`,
  description: post.summary.en,
};

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="font-data text-[13px] bg-ash px-1.5 py-0.5">{children}</code>
  );
}

export default async function ThisWeeksMcpCvesPostPage({
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
            「持續更新的偵測層」很好宣稱,也很好測。測法只有一個問題:這個規則庫,看得到
            <strong className="text-ink">本週</strong>的攻擊嗎?所以我們拿 ATR 跑了一次。
          </p>
          <p>本週 GitHub Advisory Database 發布了一批 MCP 與 agent 工具的 Critical 漏洞:</p>
          <ul className="space-y-2 list-disc pl-5">
            <li>
              <Code>gemini-mcp-tool</Code> — CVE-2026-0755,CVSS 9.8 — 經 MCP 工具參數的命令注入。
            </li>
            <li>
              <Code>PraisonAI</Code> — 四個 CVE:<Code>parse_mcp_command</Code> CLI 參數注入、
              一個 MCP 路徑遍歷 <Code>.pth</Code> RCE、一個 <Code>tool_override.py</Code> 未認證
              RCE,以及一個預設關閉認證的設定。
            </li>
            <li>
              <Code>agentic-flow</Code>、<Code>network-ai</Code>、<Code>dbt-mcp</Code> — 同一種形態:
              不可信內容經工具呼叫直達 shell。
            </li>
          </ul>
          <p>
            每一個底層都是同一個模式——被下毒的輸入經一個工具參數流進執行。攻擊者不需要帳號,
            只需要 agent 讀到某個東西。這種「一致性」正是重點:它代表這些攻擊是可偵測的——
            <strong className="text-ink">前提是你的規則夠新</strong>。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">ATR 今天抓得到什麼</h2>
          <ul className="space-y-2 list-disc pl-5">
            <li>
              <strong className="text-ink">gemini-mcp-tool(CVSS 9.8)</strong> — 已覆蓋。
              ATR-2026-01931 偵測 <Code>execAsync</Code> 命令注入與 <Code>@file</Code> 外洩路徑。
            </li>
            <li>
              <strong className="text-ink">PraisonAI——全部四個 CVE</strong> — 已覆蓋。
              ATR-2026-00540(CLI 命令注入)、00544(路徑遍歷 <Code>.pth</Code> RCE)、
              00545(<Code>tool_override</Code> RCE)、00528(預設關閉認證設定)。
            </li>
            <li>
              <strong className="text-ink">agentic-flow / network-ai / dbt-mcp</strong> — 同樣是
              「命令注入經工具參數」的形態;通用規則能抓到一部分,專屬規則正在撰寫中。
            </li>
          </ul>
          <p>
            本週五個 CVE 家族裡,有兩個已經有專屬偵測——包含每一個 PraisonAI CVE 與 gemini-mcp-tool
            的那個 9.8——而且都在揭露後幾天內到位。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">為什麼「幾天內」就是整個故事</h2>
          <p>
            CVE 落地到一條專屬規則上線之間的差距,是 agent 安全真正該看的指標,因為攻擊模式會在
            不同工具間重複出現。委員會驅動的框架用「週」或「季」量這個差距;一個開放、持續更新的
            規則層用「天」量——而且還在縮短。這就是 checklist 與「跟得上的防禦」之間的差別。
          </p>
          <p>
            每一條 ATR 規則都對映回 OWASP Agentic 與 LLM Top 10、MITRE ATLAS、NIST AI RMF、
            ISO 42001 與 EU AI Act,所以「我們偵測到本週這個 CVE」同時也代表「這是它在你本來就要
            申報的框架裡的位置」。開放標準、MIT 授權、免費採用。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">來源</h2>
          <ul className="space-y-2">
            <li>
              <a
                href="https://github.com/advisories/GHSA-4h5r-5jm8-jxjm"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                gemini-mcp-tool — CVE-2026-0755 (GitHub Advisory)
              </a>
            </li>
            <li>
              <a
                href="https://github.com/advisories/GHSA-vcv2-r9jh-99m5"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                agentic-flow — GHSA-vcv2-r9jh-99m5 (GitHub Advisory)
              </a>
            </li>
            <li>
              <Link
                href={`/${locale}/blog/static-guardrails-lose`}
                className="font-data text-xs text-blue hover:underline break-all"
              >
                Part 1: The math says static guardrails lose
              </Link>
            </li>
          </ul>
        </article>
      ) : (
        <article className="text-[15px] text-graphite leading-[1.9] space-y-5">
          <p>
            A continuously-updated detection layer is easy to claim and easy to test. The test is
            one question: does the ruleset already see <strong className="text-ink">this week&rsquo;s</strong>{" "}
            attacks? So we ran it on ATR.
          </p>
          <p>
            This week the GitHub Advisory Database shipped a batch of Critical vulnerabilities in
            MCP and agent tooling:
          </p>
          <ul className="space-y-2 list-disc pl-5">
            <li>
              <Code>gemini-mcp-tool</Code> — CVE-2026-0755, CVSS 9.8 — command injection through an
              MCP tool parameter.
            </li>
            <li>
              <Code>PraisonAI</Code> — four CVEs: a <Code>parse_mcp_command</Code> CLI argument
              injection, an MCP path-traversal <Code>.pth</Code> RCE, a <Code>tool_override.py</Code>{" "}
              unauthenticated RCE, and an auth-disabled-by-default config.
            </li>
            <li>
              <Code>agentic-flow</Code>, <Code>network-ai</Code>, <Code>dbt-mcp</Code> — the same
              shape: untrusted content reaching a shell through a tool call.
            </li>
          </ul>
          <p>
            Every one of these is the same underlying pattern — a poisoned input flows through a
            tool parameter into execution. The attacker needs no account; they need the agent to
            read something. That sameness is the point: it means the attacks are detectable,{" "}
            <strong className="text-ink">if your rules are current</strong>.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">What ATR catches today</h2>
          <ul className="space-y-2 list-disc pl-5">
            <li>
              <strong className="text-ink">gemini-mcp-tool (CVSS 9.8)</strong> — covered.
              ATR-2026-01931 detects the <Code>execAsync</Code> command injection and the{" "}
              <Code>@file</Code> exfiltration path.
            </li>
            <li>
              <strong className="text-ink">PraisonAI — all four CVEs</strong> — covered.
              ATR-2026-00540 (CLI command injection), 00544 (path-traversal <Code>.pth</Code> RCE),
              00545 (<Code>tool_override</Code> RCE), and 00528 (auth-disabled config).
            </li>
            <li>
              <strong className="text-ink">agentic-flow / network-ai / dbt-mcp</strong> — the same
              command-injection-through-a-tool-parameter shape; generic rules catch part of it, and
              dedicated rules are being written.
            </li>
          </ul>
          <p>
            Two of this week&rsquo;s five CVE families already have dedicated detection — including
            every PraisonAI CVE and the 9.8 in gemini-mcp-tool — within days of disclosure.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">Why &ldquo;within days&rdquo; is the whole story</h2>
          <p>
            The gap between a CVE landing and a dedicated rule shipping is the metric that matters
            for agent security, because the attack patterns repeat across tools. A committee-driven
            framework measures that gap in weeks or quarters. An open, continuously-updated rule
            layer measures it in days — and shrinking. That is the difference between a checklist and
            a defense that keeps up.
          </p>
          <p>
            Every ATR rule maps back to OWASP Agentic and LLM Top 10, MITRE ATLAS, NIST AI RMF, ISO
            42001, and the EU AI Act, so &ldquo;we detect this week&rsquo;s CVE&rdquo; also means
            &ldquo;here is where it sits in the framework you report against.&rdquo; Open standard,
            MIT-licensed, free to adopt.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">Sources</h2>
          <ul className="space-y-2">
            <li>
              <a
                href="https://github.com/advisories/GHSA-4h5r-5jm8-jxjm"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                gemini-mcp-tool — CVE-2026-0755 (GitHub Advisory)
              </a>
            </li>
            <li>
              <a
                href="https://github.com/advisories/GHSA-vcv2-r9jh-99m5"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                agentic-flow — GHSA-vcv2-r9jh-99m5 (GitHub Advisory)
              </a>
            </li>
            <li>
              <Link
                href={`/${locale}/blog/static-guardrails-lose`}
                className="font-data text-xs text-blue hover:underline break-all"
              >
                Part 1: The math says static guardrails lose
              </Link>
            </li>
          </ul>
        </article>
      )}
    </div>
  );
}
