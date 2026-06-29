import Link from "next/link";
import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { getPost } from "@/lib/posts";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

const post = getPost("nsa-mcp-security")!;

export const metadata: Metadata = {
  title: `${post.title.en} — ATR`,
  description: post.summary.en,
};

function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="font-data text-[13px] bg-ash px-1.5 py-0.5">{children}</code>
  );
}

export default async function NsaMcpPostPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: rawLocale } = await params;
  const locale = (locales.includes(rawLocale as Locale) ? rawLocale : "en") as Locale;
  const zh = locale === "zh";

  const mappingUrl =
    "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/NSA-MCP-MAPPING.md";
  const csiUrl =
    "https://media.defense.gov/2026/Jun/02/2003943289/-1/-1/0/CSI_MCP_SECURITY.PDF";

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
            2026 年 5 月,NSA 的人工智慧安全中心發布了《Model Context Protocol (MCP):
            Security Design Considerations for AI-Driven Automation》。它把 MCP 的風險拆成
            8 項具名安全顧慮,給了 9 條建議——而且如同所有政府指引,零條可執行的偵測規則。
          </p>
          <p>
            它的核心判斷是一句話:<strong className="text-ink">
            「MCP 的快速擴散,已超前其安全模型的發展。」
            </strong>NSA 說,安全的預設行為「必須靠實作的嚴謹、良好的編碼實務、更清楚的協定規範,
            以及健全的驗證工具來落實」。ATR 就是其中一種驗證工具層——而且,刻意地,只是其中一層。
          </p>
          <p>
            九條建議裡,有兩條的形狀就是規則:
          </p>
          <p>
            <strong className="text-ink">「追蹤並修補 MCP 相關漏洞」</strong>——CSI 要的是一套正式流程,
            監看 CVE、廠商公告、開源 issue tracker,訂閱安全情報。這正是 ATR 的 CVE 飛輪:
            橫跨 15 個來源追蹤 2,262 個 CVE,產出 594 條 detection-ready 簽章。
            <Code>ATR-2026-00451</Code> 覆蓋進了 CISA KEV 的 LiteLLM 管理端 SQLi,
            <Code>ATR-2026-00534</Code> 覆蓋 Akamai 六月揭露的阿里雲 RDS MCP 未認證 metadata 外滲。
            一則 Microsoft Semantic Kernel 的 MSRC 公告,從揭露到一條經回歸測試、已發布的規則,
            大約兩小時。
          </p>
          <p>
            <strong className="text-ink">「過濾並監控輸出管線與鏈式執行」</strong>——把每個工具輸出
            都當成不可信、偵測間接注入與工具鏈跳轉。這是 ATR 最密的一群規則:
            <Code>ATR-2026-00002</Code>(間接 prompt 注入)、<Code>ATR-2026-00010</Code>(惡意工具回應)。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">其餘七條,我們也老實說</h2>
          <p>
            一個標準的可信度,取決於它願不願意說清楚自己不做什麼。CSI 也說「掃描你的本地網路、
            找出開放或有漏洞的 MCP server」,並點名了掃描工具——MCP Scanner、Ramparts、CyberMCP、
            Proximity。<strong className="text-ink">ATR 不是其中之一。</strong>ATR 是掃描器跑的規則
            內容,不是掃描器本身,也不做網路探索。「為日誌與偵測埋點」是 SIEM 的工作;
            ATR 自己不產生任何 log——它是 SIEM 消費的偵測內容。身分綁定、訊息簽章、沙箱隔離,
            這些是基礎設施,不是 pattern 偵測。所以把 ATR 當其中一層,不是唯一一層。
          </p>
          <p>
            我們把全部 8 項顧慮、9 條建議都對映到具體規則,每一條都標了誠實的強度評級——
            包含哪些只是「互補」、哪些 ATR 根本不碰。
            {" "}
            <a
              href={mappingUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue hover:underline"
            >
              完整對映在這裡
            </a>
            。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">跑起來</h2>
          <pre className="bg-ink text-paper font-data text-[13px] p-4 overflow-x-auto">
            <code>npm install -g agent-threat-rules{"\n"}npx agent-threat-rules scan .</code>
          </pre>
          <p>
            指向你的 skill 目錄或 MCP 設定。規則是開放、MIT 授權的——讀它、測它、把我們漏掉的
            變種寄給我們。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">來源</h2>
          <ul className="space-y-2">
            <li>
              <a
                href={csiUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                NSA: Model Context Protocol (MCP) Security Design Considerations (May 2026 Ver. 1.0)
              </a>
            </li>
            <li>
              <a
                href={mappingUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                ATR → NSA MCP CSI mapping (8 concerns + 9 recommendations, per-rule)
              </a>
            </li>
          </ul>
        </article>
      ) : (
        <article className="text-[15px] text-graphite leading-[1.9] space-y-5">
          <p>
            In May 2026 the NSA&rsquo;s Artificial Intelligence Security center published{" "}
            <em>Model Context Protocol (MCP): Security Design Considerations for AI-Driven
            Automation</em>. It breaks MCP risk into 8 named security concerns and gives 9
            recommendations — and, like every piece of government guidance, ships zero executable
            detection rules.
          </p>
          <p>
            Its thesis is one line:{" "}
            <strong className="text-ink">
              &ldquo;MCP&rsquo;s rapid proliferation has outpaced the development of its security
              model.&rdquo;
            </strong>{" "}
            Secure-by-default behavior, the NSA says, &ldquo;must be enforced through implementation
            rigor, proper coding practices, clearer protocol specifications, and robust validation
            tools.&rdquo; ATR is one such validation-tool layer — and, deliberately, only one layer.
          </p>
          <p>Two of the nine recommendations are rule-shaped:</p>
          <p>
            <strong className="text-ink">&ldquo;Track and patch MCP related vulnerabilities&rdquo;</strong>{" "}
            — the CSI asks for a formal process monitoring CVEs, vendor advisories, and open-source
            issue trackers, subscribing to security feeds. That is ATR&rsquo;s CVE flywheel: 2,262
            CVEs tracked across 15 feeds, 594 detection-ready signatures. <Code>ATR-2026-00451</Code>{" "}
            covers the LiteLLM admin SQLi that landed in CISA&rsquo;s KEV; <Code>ATR-2026-00534</Code>{" "}
            covers the Alibaba RDS MCP unauthenticated metadata exfil Akamai disclosed in June. One
            Microsoft Semantic Kernel MSRC advisory went from disclosure to a published,
            regression-tested rule in about two hours.
          </p>
          <p>
            <strong className="text-ink">
              &ldquo;Filter and monitor output pipelines and chained execution&rdquo;
            </strong>{" "}
            — treat every tool output as untrusted; detect indirect injection and toolchain pivots.
            That is ATR&rsquo;s densest cluster: <Code>ATR-2026-00002</Code> (indirect prompt
            injection) and <Code>ATR-2026-00010</Code> (malicious tool response).
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">
            About the other seven — honestly
          </h2>
          <p>
            A standard earns trust by being explicit about what it does not do. The CSI also says
            &ldquo;scan your local network for open or vulnerable MCP servers,&rdquo; and names the
            scanners — MCP Scanner, Ramparts, CyberMCP, Proximity.{" "}
            <strong className="text-ink">ATR is not one of them.</strong> ATR is the rule content a
            scanner runs, not the scanner, and it does no network discovery. &ldquo;Instrument for
            logging and detection&rdquo; is a SIEM&rsquo;s job; ATR emits no logs of its own — it is
            the detection content a SIEM consumes. Identity binding, message signing, sandboxing:
            those are infrastructure, not pattern detection. Run ATR as one layer, not the only one.
          </p>
          <p>
            We mapped all 8 concerns and all 9 recommendations to specific rules, each with an honest
            strength rating — including the ones where ATR is only complementary, and the ones it
            does not touch at all.{" "}
            <a
              href={mappingUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue hover:underline"
            >
              The full mapping is here
            </a>
            .
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">Run it</h2>
          <pre className="bg-ink text-paper font-data text-[13px] p-4 overflow-x-auto">
            <code>npm install -g agent-threat-rules{"\n"}npx agent-threat-rules scan .</code>
          </pre>
          <p>
            Point it at your skill directory or MCP config. The rules are open and MIT-licensed —
            read them, test them, send us a variant we miss.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">Sources</h2>
          <ul className="space-y-2">
            <li>
              <a
                href={csiUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                NSA: Model Context Protocol (MCP) Security Design Considerations (May 2026 Ver. 1.0)
              </a>
            </li>
            <li>
              <a
                href={mappingUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                ATR → NSA MCP CSI mapping (8 concerns + 9 recommendations, per-rule)
              </a>
            </li>
          </ul>
        </article>
      )}
    </div>
  );
}
