import { Reveal } from "@/components/Reveal";
import { locales, t, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Contribute - ATR",
  description: "Four ways to contribute to ATR: report evasions, false positives, submit rules, or use AI-native workflows.",
};

export default async function ContributePage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";

  return (
    <div className="pt-20 pb-16 px-6 max-w-[1120px] mx-auto">
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {t(locale, "contribute.label")}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="font-display text-[clamp(28px,4vw,44px)] font-extrabold tracking-[-2px] mb-2 max-w-[600px]">
          {zh
            ? "ATR 是社群驅動的。你的每一個貢獻都在保護整個生態系。"
            : "ATR is community-driven. Every contribution protects the entire ecosystem."}
        </h1>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-base text-stone font-light mb-10 max-w-[520px]">
          {zh
            ? "MIT 授權。零專有工具。零 CLA。從回報一個繞過方法開始,15 分鐘。"
            : "MIT licensed. No proprietary tooling. No CLA. Start by reporting an evasion, 15 minutes."}
        </p>
      </Reveal>

      {/* ── Integrating ATR into your project (top — most asked path) ── */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-3">
          {zh ? "把 ATR 接到你的專案" : "Integrating ATR into your project"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog mb-12 grid grid-cols-1 md:grid-cols-2">
          <div className="p-6 md:p-7 border-b md:border-b-0 md:border-r border-fog">
            <div className="font-data text-[11px] text-stone tracking-wide uppercase mb-2">
              {zh ? "規劃中 / 實作中" : "Planning or implementing"}
            </div>
            <h3 className="font-display text-base font-semibold text-ink mb-2">
              {zh ? "開 Integration Request issue" : "Open an Integration Request issue"}
            </h3>
            <p className="text-sm text-stone leading-relaxed mb-3">
              {zh
                ? "結構化表單,5 分鐘填完。需要 spec walkthrough、design review、語言 sample code、或合規 mapping 就走這條。維護者七天內回覆。"
                : "Structured intake form, 5 minutes. Use this path if you need a spec walkthrough, design review, sample code for your language, or framework-compliance mapping. Maintainers respond within seven days."}
            </p>
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=integration-request.yml"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              {zh ? "開 issue" : "Open the issue"} &rarr;
            </a>
          </div>
          <div className="p-6 md:p-7">
            <div className="font-data text-[11px] text-stone tracking-wide uppercase mb-2">
              {zh ? "已經 ship 了" : "Already shipped"}
            </div>
            <h3 className="font-display text-base font-semibold text-ink mb-2">
              {zh ? "提 PR 加進 ADOPTERS.md" : "Open a PR against ADOPTERS.md"}
            </h3>
            <p className="text-sm text-stone leading-relaxed mb-3">
              {zh
                ? "你的整合公開可驗證了就走這條。Schema 對、有 evidence link 就 merge — 維護者不預先審核採用者,這跟 Sigma 一樣。"
                : "Take this path when your integration is publicly verifiable. Schema-conforming entries with a verifiable evidence link get merged — maintainers do not pre-approve adopters. Same model as Sigma."}
            </p>
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ADOPTERS.md"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              ADOPTERS.md &rarr;
            </a>
          </div>
        </div>
      </Reveal>

      {/* ── Quick Actions (the most important part) ── */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-3">
          {zh ? "改進規則本身" : "Improve the rules themselves"}
        </div>
      </Reveal>
      <Reveal delay={0.3}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-12">
          {[
            {
              title: zh ? "回報繞過方式" : "Report an Evasion",
              desc: zh
                ? "找到了繞過規則的方法？每個確認的繞過都會觸發規則改進。這是最有影響力的貢獻。"
                : "Found a way to bypass a rule? Every confirmed evasion triggers a rule improvement. Most impactful contribution.",
              time: "~15 min",
              href: "https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=evasion-report.md",
              cta: zh ? "開一個 Issue" : "Open an Issue",
            },
            {
              title: zh ? "回報誤判" : "Report a False Positive",
              desc: zh
                ? "規則誤判了正常內容？幫我們維持 99.6% precision 的真實性。"
                : "Rule triggered on legitimate content? Help us keep 99.6% precision real.",
              time: "~20 min",
              href: "https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=false-positive.md",
              cta: zh ? "開一個 Issue" : "Open an Issue",
            },
            {
              title: zh ? "提交新規則" : "Submit a New Rule",
              desc: zh
                ? "為新的攻擊模式撰寫偵測規則。YAML 格式，有完整教學。"
                : "Write a detection rule for a new attack pattern. YAML format, full walkthrough available.",
              time: "1-2 hr",
              href: "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/examples/how-to-write-a-rule.md",
              cta: zh ? "查看教學" : "See the Guide",
            },
            {
              title: zh ? "AI 原生貢獻" : "AI-Native Contribution",
              desc: zh
                ? "用 Claude Code 或 Cursor 搭配 ATR MCP server。AI 寫 YAML，你審查。"
                : "Use Claude Code or Cursor with ATR's MCP server. The AI writes YAML, you review.",
              time: zh ? "不定" : "Variable",
              href: "https://github.com/Agent-Threat-Rule/agent-threat-rules#mcp-server",
              cta: zh ? "查看 MCP 設定" : "See MCP Setup",
            },
          ].map((item, i) => (
            <Reveal key={item.title} delay={0.1 * i}>
              <div className="border border-fog p-6 h-full flex flex-col">
                <div className="flex items-start justify-between gap-3 mb-3">
                  <h2 className="font-display text-base font-semibold text-ink">{item.title}</h2>
                  <span className="font-data text-xs text-stone whitespace-nowrap mt-0.5">{item.time}</span>
                </div>
                <p className="text-sm text-stone leading-[1.6] mb-4 flex-1">{item.desc}</p>
                <a
                  href={item.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-data text-sm text-blue hover:underline"
                >
                  {item.cta} &rarr;
                </a>
              </div>
            </Reveal>
          ))}
        </div>
      </Reveal>

      {/* ── Spec amendments ── */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-3">
          {zh ? "想改 spec 本身" : "Want to change the spec itself"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog p-6 mb-12">
          <p className="text-sm text-stone leading-relaxed mb-3">
            {zh
              ? "Spec(ATR-SPEC-v1)是所有相容引擎的契約。改動 spec 不像加規則那麼直接 — 流程是:先開 RFC issue 標題以 [RFC] 開頭,描述要改什麼、為什麼;留 7 天公開評論窗口讓所有 implementer 看到並回饋;接下來才接受 PR。Breaking change(SemVer 主版號)需要額外 30 天提前公告。"
              : "The spec (ATR-SPEC-v1) is the contract between all conforming engines. Spec changes are not as direct as rule additions — the process is: open an RFC issue with title prefixed [RFC] describing what you want to change and why; leave a 7-day public comment window so every implementer sees it and can respond; then submit the PR. Breaking changes (SemVer major bump) require an additional 30-day advance notice."}
          </p>
          <p className="text-sm text-stone leading-relaxed mb-3">
            {zh
              ? "完整流程在 governance 頁的 Decision-making 區段。"
              : "Full process documented under Decision-making on the governance page."}
          </p>
          <div className="flex flex-wrap gap-4">
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?title=%5BRFC%5D+"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              {zh ? "開 RFC issue" : "Open an RFC issue"} &rarr;
            </a>
            <span className="text-fog">|</span>
            <a
              href={`/${locale}/governance`}
              className="font-data text-xs text-blue hover:underline"
            >
              {zh ? "決策流程細節" : "Decision-making process"} &rarr;
            </a>
            <span className="text-fog">|</span>
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ATR-SPEC-v1.md"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-blue hover:underline"
            >
              ATR-SPEC-v1.md &rarr;
            </a>
          </div>
        </div>
      </Reveal>

      {/* ── First-time contributors ── */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-3">
          {zh ? "第一次貢獻" : "First time contributing"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog p-6 mb-12 text-sm text-graphite leading-relaxed space-y-3">
          <p>
            {zh
              ? "如果你想開始但不確定從哪開始,有兩條低門檻入口:"
              : "If you want to contribute but don't know where to start, two low-friction entry points:"}
          </p>
          <ul className="list-disc pl-6 space-y-2">
            <li>
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22"
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue hover:underline"
              >
                {zh ? "「good first issue」標籤的 open issue" : "Open issues labelled 'good first issue'"}
              </a>
              {zh
                ? " — 維護者標記過、範圍清楚的入門任務。"
                : " — maintainer-tagged starter tasks with clear scope."}
            </li>
            <li>
              {zh
                ? "規則的 false-positive 報告 — 你的工作流程中遇到誤判,15 分鐘填表格,就直接幫到下游所有採用者。維護者最重視這類回饋。"
                : "False-positive reports — if you hit a misfire in your workflow, a 15-minute report directly helps every downstream adopter. Maintainers prioritise this class of feedback."}
            </li>
          </ul>
        </div>
      </Reveal>

      {/* ── Become a maintainer ── */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-3">
          {zh ? "想成為維護者" : "Want to become a maintainer"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog p-6 mb-12 text-sm text-graphite leading-relaxed">
          <p className="mb-3">
            {zh
              ? "ATR 目前是 single-maintainer,正在主動招募第二位、第三位。候選條件、決策結構、以及申請方式都在 governance 頁。"
              : "ATR is currently single-maintainer and is actively recruiting a second and third. Candidate criteria, the decision-making structure, and how to apply are all on the governance page."}
          </p>
          <a href={`/${locale}/governance`} className="font-data text-xs text-blue hover:underline">
            {zh ? "看治理頁的「想成為維護者」段" : "See 'Become a maintainer' on the governance page"} &rarr;
          </a>
        </div>
      </Reveal>

      {/* ── How Threat Cloud Crystallization Works ── */}
      <Reveal>
        <div className="border border-fog mb-10">
          <div className="px-6 py-4 border-b border-fog bg-ash">
            <h2 className="font-display text-base font-semibold">
              {zh ? "Threat Cloud 結晶流程" : "How Threat Cloud Crystallization Works"}
            </h2>
            <p className="text-sm text-stone mt-1">
              {zh
                ? "傳統規則需要數週撰寫、審查、發布。Threat Cloud 目標數小時。"
                : "Traditional rules take weeks to write, review, and ship. Threat Cloud targets hours."}
            </p>
          </div>
          <div className="p-5 md:p-6">
            <div className="font-data text-sm leading-[2.2] text-graphite">
              {(zh
                ? [
                    "在野外偵測到新的攻擊模式",
                    "LLM 分析攻擊結構和意圖",
                    "自動產生 YAML 規則提案和測試案例",
                    "社群審查 + precision 測試閘門",
                    "合併至 ATR。所有下游引擎自動更新。",
                  ]
                : [
                    "New attack pattern detected in the wild",
                    "LLM analyzes attack structure + intent",
                    "Auto-generates YAML rule proposal with test cases",
                    "Community reviews + precision test gate",
                    "Merged into ATR. Every downstream engine updates.",
                  ]
              ).map((step, i) => (
                <div key={i}>
                  {i > 0 && <div className="text-mist text-center pl-6">|</div>}
                  <div className="flex items-center gap-3">
                    <span className="text-blue font-bold">{i + 1}.</span>
                    <span>{step}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </Reveal>

      {/* ── Resources ── */}
      <Reveal>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog">
          <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/GOVERNANCE.md" target="_blank" rel="noopener noreferrer" className="bg-paper p-6 hover:bg-ash transition-colors">
            <div className="font-display text-sm font-semibold mb-1">{t(locale, "contribute.governance")}</div>
            <p className="text-sm text-stone">{t(locale, "contribute.governance.desc")}</p>
          </a>
          <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/CONTRIBUTORS.md" target="_blank" rel="noopener noreferrer" className="bg-paper p-6 hover:bg-ash transition-colors">
            <div className="font-display text-sm font-semibold mb-1">{t(locale, "contribute.contributors")}</div>
            <p className="text-sm text-stone">{t(locale, "contribute.contributors.desc")}</p>
          </a>
          <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/examples/how-to-write-a-rule.md" target="_blank" rel="noopener noreferrer" className="bg-paper p-6 hover:bg-ash transition-colors">
            <div className="font-display text-sm font-semibold mb-1">{t(locale, "contribute.guide")}</div>
            <p className="text-sm text-stone">{t(locale, "contribute.guide.desc")}</p>
          </a>
        </div>
      </Reveal>
    </div>
  );
}
