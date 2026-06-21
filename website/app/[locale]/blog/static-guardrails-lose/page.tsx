import Link from "next/link";
import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { getPost } from "@/lib/posts";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

const post = getPost("static-guardrails-lose")!;

export const metadata: Metadata = {
  title: `${post.title.en} — ATR`,
  description: post.summary.en,
};

export default async function StaticGuardrailsPostPage({
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
            2026 年 6 月 9 日,一位 NIST 資深科學家發表了一份數學證明:沒有任何有限的
            guardrail 集合,能普遍抵禦對抗式 prompt。論證借用哥德爾——任何固定的防禦,都留有
            一個攻擊者找得到的縫。
          </p>
          <p>
            結論不是「把牆蓋得更高」,而是停止把 AI 安全當成「一次到位」,改成{" "}
            <strong className="text-ink">持續監測與更新</strong>:不斷找出新攻擊、不斷更新防禦,
            把攻擊成本推過「不划算」那條線。
          </p>
          <p>
            對任何在防守 AI agent 的人,這份證明替整個策略劃了底線:一個你發布一次就不再管的
            靜態規則集,可以被證明,是一個有縫的規則集。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">這個方向,業界已經在走</h2>
          <p>
            你不必只聽標準機構說。2026 年 6 月 16 日,NVIDIA 發布了 SkillSpector——一個開源
            掃描器,在 agent skill 安裝前檢查其中的惡意模式。當全球最大的 AI 硬體公司都做起
            安裝前 skill 掃描,這個品類就不再是空想。
          </p>
          <p>
            所以剩下的問題不再是「要不要持續掃描 agent 行為」,而是兩個更窄的問題:
            <strong className="text-ink">你用什麼規則掃,以及新攻擊出現時這些規則多快更新</strong>。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">持續更新的規則層長什麼樣</h2>
          <p>
            Agent Threat Rules(ATR)就是為這個問題而生的開放標準:可執行的偵測規則——YAML 與
            JSON,不是 checklist——在 agent 攻擊發生時觸發。目前 652 條規則,對映 OWASP Agentic
            與 LLM Top 10、MITRE ATLAS、NIST AI RMF、ISO 42001 與 EU AI Act,所以一個偵測可以
            追回到團隊本來就在用的合規框架。
          </p>
          <p>
            真正關鍵的是更新迴圈。新的攻擊 payload 進來,一條規則被起草、對乾淨語料做 0 誤報
            機審、然後上線。社群貢獻加上自動審核,把規則更新週期從委員會的數週,壓縮到一小時內。
            攻擊跑得快,防禦就得至少一樣快——這正是靜態 guardrail 做不到、而 NIST 證明說你不能
            跳過的事。
          </p>
          <p>
            這些規則扎根於真實世界,不是假設。我們掃了五個公開 registry 的 96,096 個 agent
            skill,人工複審後確認 552 個惡意——憑證竊取、靜默外洩、藏在工具描述裡的命令執行。
            在 PINT 語料上 ATR 的 recall 是 63.6%、precision 99.7%:抓得到真攻擊,又幾乎不亂叫,
            這是讓一個持續規則層「能用」而不是「太吵」的關鍵。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">結論</h2>
          <p>
            能規模化的防禦,是更新得跟攻擊一樣快的那種。現在這件事有了形式化證明,而且這個
            品類裡已經有 NVIDIA。ATR 就是它的開放、MIT 授權規則層——免費採用、對映框架、持續
            更新。
          </p>
          <p>
            下一篇,我們拿它對本週這批 MCP CVE 做實測。
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">來源</h2>
          <ul className="space-y-2">
            <li>
              <a
                href="https://www.nist.gov/news-events/news/2026/06/nist-mathematical-proof-supports-transition-continuous-monitor-and-update"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                NIST: Mathematical Proof Supports Transition to Continuous Monitor-and-Update (2026-06-09)
              </a>
            </li>
            <li>
              <a
                href="https://github.com/NVIDIA/SkillSpector"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                NVIDIA SkillSpector — install-time agent-skill scanner (2026-06)
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
            On June 9, 2026, a senior NIST scientist published a mathematical proof that no finite
            set of guardrails is universally robust against adversarial prompts. The argument
            borrows from G&ouml;del: any fixed defense leaves a gap an attacker can find.
          </p>
          <p>
            The conclusion is not &ldquo;build a taller wall.&rdquo; It is to stop treating AI
            safety as one-and-done and shift to{" "}
            <strong className="text-ink">continuous monitor-and-update</strong> — keep finding new
            attacks, keep updating the defense, and push the cost of attacking past the point of
            being worth it.
          </p>
          <p>
            For anyone defending AI agents, that proof just put a floor under the whole strategy. A
            static rule set you ship once and forget is, provably, a rule set with a gap.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">The industry is already moving this way</h2>
          <p>
            You do not have to take a standards body&rsquo;s word for it. On June 16, 2026, NVIDIA
            shipped SkillSpector — an open-source scanner that inspects agent skills for malicious
            patterns before they install. When the largest AI hardware company builds an
            install-time skill scanner, the category stops being speculative.
          </p>
          <p>
            So the open question is no longer <em>whether</em> to scan agent behavior continuously.
            It is two narrower questions:{" "}
            <strong className="text-ink">
              what rules do you scan with, and how fast do those rules update
            </strong>{" "}
            when a new attack appears.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">What a continuously-updated rules layer looks like</h2>
          <p>
            Agent Threat Rules (ATR) is an open standard built for exactly that question:
            executable detection rules — YAML and JSON, not a checklist — that fire when an agent
            attack happens. 652 rules today, mapped to OWASP Agentic and LLM Top 10, MITRE ATLAS,
            NIST AI RMF, ISO 42001, and the EU AI Act, so a detection traces back to the framework a
            team already reports against.
          </p>
          <p>
            The part that matters is the update loop. A new attack payload arrives; a rule is
            drafted, machine-reviewed for false positives against a clean corpus, and shipped.
            Community contribution plus automated review compresses the rule-update cycle from the
            weeks a committee takes to under an hour. The attacks move fast, so the defense has to
            move at least as fast — the exact thing a static guardrail cannot do, and the exact
            thing the NIST proof says you cannot skip.
          </p>
          <p>
            The rules are grounded in what is actually in the wild, not hypotheticals. A scan of
            96,096 published agent skills confirmed 552 as malicious after manual review — credential
            theft, silent exfiltration, command execution buried in tool descriptions an agent
            ingests as instructions. On the PINT corpus ATR runs at 63.6% recall and 99.7%
            precision: it catches real attacks while almost never crying wolf, which is what keeps a
            continuous rules layer usable instead of noisy.
          </p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">The takeaway</h2>
          <p>
            The defense that scales is the one that updates as fast as the attacks. The proof is now
            formal, and the category now has NVIDIA in it. ATR is the open, MIT-licensed rules layer
            for it — free to adopt, framework-mapped, updated continuously.
          </p>
          <p>Next post: we put that to the test against this week&rsquo;s batch of MCP CVEs.</p>

          <h2 className="font-display text-xl font-bold text-ink pt-4">Sources</h2>
          <ul className="space-y-2">
            <li>
              <a
                href="https://www.nist.gov/news-events/news/2026/06/nist-mathematical-proof-supports-transition-continuous-monitor-and-update"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                NIST: Mathematical Proof Supports Transition to Continuous Monitor-and-Update (2026-06-09)
              </a>
            </li>
            <li>
              <a
                href="https://github.com/NVIDIA/SkillSpector"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline break-all"
              >
                NVIDIA SkillSpector — install-time agent-skill scanner (2026-06)
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
