import { Reveal } from "@/components/Reveal";
import { loadSiteStats } from "@/lib/stats";
import { locales, t, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import Link from "next/link";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/integrate",
    title: "Integrate",
    description: "Five ways to run ATR: TypeScript, Python, raw YAML, a GitHub Action, or SIEM queries.",
  });
}

const PATHS = [
  {
    title: "TypeScript / Node.js",
    cmd: "npm install agent-threat-rules",
    code: `import { ATREngine } from 'agent-threat-rules';

const engine = new ATREngine();
const matches = engine.evaluate({
  type: 'tool_response',
  content: toolOutput,
  timestamp: new Date().toISOString(),
});

if (matches.length > 0) {
  // Threat detected: block or alert
}`,
    doc: "https://github.com/Agent-Threat-Rule/agent-threat-rules#quick-start",
  },
  {
    title: "Python (pyATR)",
    cmd: "pip install pyatr",
    code: `from pyatr import ATREngine

engine = ATREngine()
result = engine.evaluate(event={
    "type": "llm_input",
    "content": user_message,
})

if result.outcome == "deny":
    # Block the request`,
    doc: "https://github.com/Agent-Threat-Rule/agent-threat-rules/tree/main/python",
  },
  {
    title: "Raw YAML (any language)",
    cmd: "git submodule add https://github.com/Agent-Threat-Rule/agent-threat-rules.git",
    code: `# Point your scanner at the rules/ directory
# Each .yaml file uses the rule format in SPEC.md
# Parse with any YAML library
# Schema: spec/atr-schema.yaml

rules/
  prompt-injection/
  tool-poisoning/
  agent-manipulation/
  ... (10 categories)`,
    doc: "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/SPEC.md",
  },
  {
    title: "GitHub Action (CI/CD)",
    cmd: "# Add to .github/workflows/atr-scan.yml",
    code: `name: ATR Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Agent-Threat-Rule/agent-threat-rules@main
        with:
          path: '.'            # Scan entire repo
          severity: 'medium'   # Minimum severity
          fail-on-finding: 'true'
          upload-sarif: 'true' # Results in GitHub Security tab`,
    doc: "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/action.yml",
  },
  {
    title: "SIEM Integration",
    cmd: "atr convert splunk --output splunk-queries.txt",
    code: `# Turn ATR rules into SIEM queries
atr convert splunk    # Output SPL queries
atr convert elastic   # Output Elasticsearch Query DSL
atr convert sarif     # Output SARIF v2.1.0 for CI/CD`,
    doc: "https://github.com/Agent-Threat-Rule/agent-threat-rules#siem-integration",
  },
];

export default async function IntegratePage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const stats = loadSiteStats();

  return (
    <div className="pt-20 pb-16 px-6 max-w-[1120px] mx-auto">
      <Reveal>
        <div className="text-[13px] text-stone mb-3">{t(locale, "integrate.label")}</div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="text-[32px] md:text-[44px] leading-[1.12] tracking-[-0.03em] font-medium mb-2">
          {t(locale, "integrate.heading")}
        </h1>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-base text-stone font-light mb-10">
          {t(locale, "integrate.ready", { count: String(stats.ruleCount) })}
        </p>
      </Reveal>

      {/* Integration tiers — choose your level */}
      <Reveal>
        <div className="mb-12">
          <div className="text-[13px] text-stone mb-4">
            {locale === "zh" ? "同一份規則，任何符合規範的引擎都能跑。看你要接多深。" : "One ruleset, and any conforming engine can run it. Pick how deep you go."}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog">
            {[
              {
                level: "L1",
                title: locale === "zh" ? "掃描" : "Scan",
                who: locale === "zh" ? "個人開發者" : "Individual developers",
                how: locale === "zh" ? "一行指令，或 GitHub Action" : "One command, or the GitHub Action",
                what: locale === "zh" ? "知道你的 AI 工具有沒有被下毒" : "Find out whether your AI tools are poisoned",
                update: locale === "zh" ? "每次跑 npx 都會拉最新規則" : "npx pulls the latest rules every run",
              },
              {
                level: "L2",
                title: locale === "zh" ? "嵌入" : "Embed",
                who: locale === "zh" ? "平台方（IDE、agent 框架）" : "Platforms (IDEs, agent frameworks)",
                how: locale === "zh" ? "npm install，再呼叫 ATR engine" : "npm install, then call the ATR engine",
                what: locale === "zh" ? `用戶什麼都不用做，就有 ${stats.ruleCount} 條規則在保護` : `Your users get ${stats.ruleCount} rules without lifting a finger`,
                update: locale === "zh" ? "npm update，或 lockfile 搭配 CI" : "npm update, or a lockfile plus CI",
              },
              {
                level: "L3",
                title: locale === "zh" ? "雙向（選用）" : "Bidirectional (optional)",
                who: locale === "zh" ? "資安平台、企業 SOC" : "Security platforms, enterprise SOCs",
                how: locale === "zh" ? "先嵌入，想要的話再接上 Threat Cloud 參考服務" : "Embed, then connect the Threat Cloud reference service if you want it",
                what: locale === "zh" ? "可以上報威脅、同步規則。不接，標準照樣完整能用" : "You can send threats in and sync rules. The standard works fully without it",
                update: locale === "zh" ? "npm update。接上 TC 的話，還有即時推送" : "npm update. With TC connected, you also get real-time push",
              },
            ].map((tier) => (
              <div key={tier.level} className="bg-paper p-5 md:p-6">
                <div className="flex items-center gap-2 mb-2">
                  <span className="font-data text-xs font-bold text-blue bg-ink/10 px-2 py-0.5 ">{tier.level}</span>
                  <span className="font-display text-sm font-semibold text-ink">{tier.title}</span>
                </div>
                <div className="text-xs text-blue font-medium mb-2">{tier.who}</div>
                <div className="text-xs text-stone leading-[1.7] mb-2">{tier.how}</div>
                <div className="text-xs text-ink font-medium leading-[1.7] mb-2">{tier.what}</div>
                <div className="font-data text-[10px] text-mist mt-2 pt-2 border-t border-fog">{locale === "zh" ? "更新方式" : "Updates"}: {tier.update}</div>
              </div>
            ))}
          </div>
        </div>
      </Reveal>

      {/* Quick Start — Try it in 30 seconds */}
      <Reveal>
        <div className="border-2 border-ink mb-12">
          <div className="px-6 py-4 border-b border-ink bg-ink text-white">
            <h2 className="font-display text-lg font-semibold">{locale === "zh" ? "30 秒試一次" : "Try it in 30 seconds"}</h2>
          </div>
          <div className="p-6">
            <p className="text-sm text-graphite mb-4 leading-relaxed">
              {locale === "zh"
                ? "不用註冊，不用 API key。一行指令就能掃你的 SKILL.md 或 MCP 設定檔。你在本機跑的這份 YAML，跟 Cisco、Gen Digital 開源工具裡合併的是同一份規則。"
                : "No signup, no API key. One command scans your SKILL.md or MCP config. The YAML you run locally is the same ruleset that was merged into Cisco's and Gen Digital's open-source tooling."}
            </p>
            <div className="space-y-3">
              <div>
                <div className="font-data text-xs text-stone mb-1">{locale === "zh" ? "掃一個 SKILL.md" : "Scan a SKILL.md file"}</div>
                <div className="font-data text-sm bg-[#0B0B0F] text-[#4ade80] px-4 py-3  overflow-x-auto">
                  <span className="text-stone">$</span> npx agent-threat-rules scan your-skill.md
                </div>
              </div>
              <div>
                <div className="font-data text-xs text-stone mb-1">{locale === "zh" ? "掃整個目錄" : "Scan a directory"}</div>
                <div className="font-data text-sm bg-[#0B0B0F] text-[#4ade80] px-4 py-3  overflow-x-auto">
                  <span className="text-stone">$</span> npx agent-threat-rules scan ./my-mcp-skills/
                </div>
              </div>
              <div>
                <div className="font-data text-xs text-stone mb-1">{locale === "zh" ? "裝成 Claude Code 的即時防護" : "Install as a real-time guard for Claude Code"}</div>
                <div className="font-data text-sm bg-[#0B0B0F] text-[#4ade80] px-4 py-3  overflow-x-auto">
                  <span className="text-stone">$</span> npx agent-threat-rules init --global
                </div>
              </div>
            </div>
            <p className="text-xs text-mist mt-4">
              {locale === "zh"
                ? `${stats.ruleCount} 條規則 · ${stats.categoryCount} 個威脅類別 · 預設在你的程式裡跑，不連網 · MIT 授權`
                : `${stats.ruleCount} rules · ${stats.categoryCount} threat categories · runs in process, no network calls by default · MIT license`}
            </p>
          </div>
        </div>
      </Reveal>

      {/* SDK Integration Paths */}
      <Reveal>
        <div className="text-[13px] text-stone mb-4">
          {locale === "zh" ? "同一份規則，五種接法" : "Same rules, five ways to load them"}
        </div>
      </Reveal>

      <div className="space-y-8">
        {PATHS.map((path, i) => (
          <Reveal key={path.title} delay={0.1 * i}>
            <div className="border border-fog">
              <div className="flex items-center justify-between px-6 py-4 border-b border-fog bg-ash">
                <h2 className="font-display text-lg font-semibold">{path.title}</h2>
                <a href={path.doc} target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">
                  {locale === "zh" ? "文件" : "Docs"} &rarr;
                </a>
              </div>
              <div className="p-6">
                <div className="font-data text-sm text-stone bg-ash border border-fog px-4 py-3 mb-4">
                  $ <span className="text-ink">{path.cmd}</span>
                </div>
                <pre className="font-data text-sm text-graphite bg-ash border border-fog p-4 overflow-x-auto leading-relaxed">
                  {path.code}
                </pre>
              </div>
            </div>
          </Reveal>
        ))}
      </div>

      {/* GitHub Action Adopters */}
      <Reveal>
        <div className="mt-12 border border-fog">
          <div className="px-6 py-4 border-b border-fog bg-ash">
            <h2 className="font-display text-lg font-semibold">
              {locale === "zh" ? "誰在用 GitHub Action" : "GitHub Action adopters"}
            </h2>
          </div>
          <div className="p-6 space-y-5">
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? <>把 ATR 掛進任何 GitHub repo 的 CI。結果寫成 SARIF，出現在 GitHub 的 Security 分頁，跟 CodeQL、Dependabot 在同一個地方。</>
                : <>Wire ATR into any GitHub repo&apos;s CI. Results are written as SARIF and show up in the repo&apos;s Security tab, next to CodeQL and Dependabot.</>}
            </p>
            <div>
              <div className="text-[13px] text-stone mb-2">
                {locale === "zh" ? "最精簡的設定" : "Minimal workflow"}
              </div>
              <pre className="font-data text-xs md:text-sm text-graphite bg-ash border border-fog p-4 overflow-x-auto leading-[1.7]">
{`# .github/workflows/atr-scan.yml
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # for SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: Agent-Threat-Rule/agent-threat-rules@main
        with:
          severity: medium
          fail-on-finding: true`}
              </pre>
            </div>
            <div>
              <div className="text-[13px] text-stone mb-3">
                {locale === "zh" ? "公開採用" : "Public adopters"}
              </div>
              <p className="text-sm text-graphite leading-[1.7]">
                {locale === "zh" ? (
                  <>目前還沒有公開的採用紀錄。你的 repo 有用 ATR Action 的話，開一個{" "}
                    <a
                      href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue hover:underline"
                    >GitHub issue</a>，就會列在這裡。</>
                ) : (
                  <>None tracked publicly yet. If your repo uses the ATR Action, open a{" "}
                    <a
                      href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue hover:underline"
                    >GitHub issue</a>{" "}and it will be listed here.</>
                )}
              </p>
              <p className="text-xs text-mist mt-2 leading-[1.7]">
                {locale === "zh"
                  ? "採用不只 GitHub Action 一種。Cisco AI Defense 的開源 skill-scanner（PR #79 PoC，後來的 PR #99）透過 rule-packs CLI 載入規則集。Microsoft AGT（PR #2308、PR #3025）的範例目錄示範匯入 ATR 規則，交給 ACS annotator 執行；早期 PR #908、#1277 的規則包 YAML 已經不在 repo 裡。Gen Digital Sage（PR #33）把整套規則包進它的 agentic-AI 風險評分層。這三筆算上游採用，每一筆都是公開 repo 裡已合併的 PR，不算在 Action 的使用統計裡。"
                  : "The Action isn't the only way in. Cisco AI Defense's open-source skill-scanner (PR #79 PoC, then PR #99) loads the rule pack through a rule-packs CLI. Microsoft AGT (PR #2308 and PR #3025) has example directories that import ATR rules and run them through an ACS annotator. The rule-pack YAML from its earlier PRs #908 and #1277 is no longer in the repo. Gen Digital Sage (PR #33) ships the rule pack inside its agentic-AI risk-scoring layer. These three count as upstream adoption. Each one is a merged pull request in a public repository, and none is counted as Action usage."}
              </p>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Schema Stability & Upstream Guarantee */}
      <Reveal>
        <div className="mt-12 border border-fog">
          <div className="px-6 py-4 border-b border-fog bg-ash">
            <h2 className="font-display text-lg font-semibold">{t(locale, "integrate.schema.title")}</h2>
          </div>
          <div className="p-6">
            <p className="text-sm text-graphite leading-relaxed mb-5">
              {locale === "zh"
                ? "把 ATR 當上游依賴，就得確定格式不會突然壞掉。ATR 承諾的是這些："
                : "If ATR sits upstream of your product, you need to know the format won\u0027t break. This is what ATR commits to:"}
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div>
                  <div className="font-display text-sm font-semibold mb-1">SPEC.md ({locale === "zh" ? "草案" : "Draft"})</div>
                  <p className="text-sm text-stone leading-[1.6]">
                    {locale === "zh"
                      ? "以草案發布，內容已經穩定，可以照著實作。新增的欄位一律選填。現有欄位要移除或改名，一定等到主版本升級。"
                      : "Published as a Draft, and stable enough to implement against. New fields are always optional. No existing field is removed or renamed without a major version bump."}
                  </p>
                </div>
                <div>
                  <div className="font-display text-sm font-semibold mb-1">{locale === "zh" ? "向後相容" : "Backward compatibility"}</div>
                  <p className="text-sm text-stone leading-[1.6]">
                    {locale === "zh"
                      ? "會壞相容的變更，只出現在主版本升級（v1 → v2）。到時會附遷移指南，新舊兩版至少並行支援 6 個月。"
                      : "Breaking changes only come with a major version (v1 \u2192 v2). Each one ships with a migration guide, and both versions stay supported for at least 6 months."}
                  </p>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <div className="font-display text-sm font-semibold mb-1">{locale === "zh" ? "多久更新一次" : "How often it updates"}</div>
                  <p className="text-sm text-stone leading-[1.6]">
                    {locale === "zh"
                      ? <>規則一直在加，活躍的時候平均每週 2 到 5 條。每一條合併前都要過 CI 驗證和 precision 測試。更新日誌請訂閱{" "}<a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/releases" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">GitHub Releases</a>。</>
                      : <>Rules are added all the time, on average 2 to 5 a week in active periods. Each one passes CI validation and a precision test before it merges. Subscribe to{" "}<a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/releases" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">GitHub Releases</a>{" "}for the changelog.</>}
                  </p>
                </div>
                <div>
                  <div className="font-display text-sm font-semibold mb-1">{locale === "zh" ? "怎麼同步" : "Ways to sync"}</div>
                  <div className="font-data text-sm text-stone leading-[1.8]">
                    <span className="text-ink">git submodule</span> &mdash; {locale === "zh" ? "鎖在某個 tag，自己決定什麼時候更新" : "pin a tag, update when you choose"}<br />
                    <span className="text-ink">npm install</span> &mdash; {locale === "zh" ? "照語意化版本走，版本由 lockfile 鎖住" : "semver, and the lockfile decides the version"}<br />
                    <span className="text-ink">GitHub Action</span> &mdash; {locale === "zh" ? "CI 每次自動用最新規則掃" : "CI scans with the latest rules on its own"}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Why ATR vs Internal Rules */}
      <Reveal>
        <div className="mt-8 border border-fog">
          <div className="px-6 py-4 border-b border-fog bg-ash">
            <h2 className="font-display text-lg font-semibold">{t(locale, "integrate.why.title")}</h2>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog">
              {[
                { label: locale === "zh" ? "覆蓋範圍" : "Coverage", atr: locale === "zh" ? `${stats.ruleCount} 條規則，${stats.cveCount} 個 CVE 對應，${stats.categoryCount} 個威脅類別` : `${stats.ruleCount} rules, ${stats.cveCount} CVEs mapped, ${stats.categoryCount} threat categories`, own: locale === "zh" ? "規則庫要自己從頭建" : "You build the rule set yourself" },
                { label: locale === "zh" ? "新攻擊反應" : "New attack response", atr: locale === "zh" ? "社群和 CI 流程一直在加規則，目標是幾小時內出來。選用的 Threat Cloud 能讓回報更快" : "The community and the CI pipeline keep adding rules, aiming for hours. The optional Threat Cloud can speed up reporting", own: locale === "zh" ? "看你的團隊有多少人力" : "Depends on how much time your team has" },
                { label: locale === "zh" ? "繞過測試" : "Evasion testing", atr: locale === "zh" ? "附 evasion_tests、記下已知繞過手法的規則，不到一半" : "Fewer than half the rules carry evasion tests that record known bypasses", own: locale === "zh" ? "要另外花時間建" : "Takes dedicated time to build" },
                { label: locale === "zh" ? "OWASP / MITRE 對應" : "OWASP / MITRE mapping", atr: locale === "zh" ? "內建。Agentic 10/10，每條規則也都對到 MITRE ATLAS" : "Built in. Agentic 10/10, and every rule maps to MITRE ATLAS", own: locale === "zh" ? "要手動對上好幾個小時" : "Hours of mapping by hand" },
                { label: locale === "zh" ? "維護成本" : "Maintenance", atr: locale === "zh" ? "社群維護，MIT 授權，不用錢。" : "Maintained by the community. MIT. Free.", own: locale === "zh" ? "要一直有人顧" : "Needs engineering time, indefinitely" },
                { label: locale === "zh" ? "誰在用" : "Ecosystem", atr: locale === "zh" ? "Cisco、Microsoft、MISP 的開源專案都已合併" : "Merged into open-source projects at Cisco, Microsoft and MISP", own: locale === "zh" ? "各自維護，規則不共用" : "Kept on its own, shared with no one" },
              ].map((row) => (
                <div key={row.label} className="bg-paper text-sm">
                  {/* Desktop: 3-column */}
                  <div className="hidden md:grid grid-cols-[140px_1fr_1fr]">
                    <div className="px-4 py-3 font-semibold text-ink border-r border-fog">{row.label}</div>
                    <div className="px-4 py-3 text-ink border-r border-fog">{row.atr}</div>
                    <div className="px-4 py-3 text-stone">{row.own}</div>
                  </div>
                  {/* Mobile: stacked */}
                  <div className="md:hidden p-4 space-y-2">
                    <div className="font-semibold text-ink">{row.label}</div>
                    <div className="text-ink"><span className="font-data text-xs text-blue mr-1">ATR</span>{row.atr}</div>
                    <div className="text-stone"><span className="font-data text-xs text-mist mr-1">{locale === "zh" ? "自建" : "DIY"}</span>{row.own}</div>
                  </div>
                </div>
              ))}
            </div>
            <div className="flex gap-8 mt-3 text-xs font-data text-stone uppercase tracking-wider">
              <span>&nbsp;</span>
              <span className="ml-[140px] text-blue">ATR</span>
              <span className="ml-auto">{locale === "zh" ? "自建規則" : "Your own rules"}</span>
            </div>
          </div>
        </div>
      </Reveal>

      {/* License */}
      <Reveal>
        <div className="mt-8 border border-fog">
          <div className="px-6 py-4 border-b border-fog bg-ash">
            <h2 className="font-display text-lg font-semibold">{t(locale, "integrate.license.title")}</h2>
          </div>
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 text-sm">
              <div>
                <div className="font-display text-sm font-semibold mb-1">MIT License</div>
                <p className="text-stone leading-[1.6]">{locale === "zh" ? "可以商用、修改、散布、再授權，沒有限制。" : "Use it commercially, change it, redistribute it, sublicense it. No restrictions."}</p>
              </div>
              <div>
                <div className="font-display text-sm font-semibold mb-1">{locale === "zh" ? "無 CLA" : "No CLA"}</div>
                <p className="text-stone leading-[1.6]">{locale === "zh" ? "不用簽貢獻者授權協議。貢獻一律採 MIT 授權，屬於社群。" : "There is no Contributor License Agreement. Contributions are MIT-licensed and belong to the community."}</p>
              </div>
              <div>
                <div className="font-display text-sm font-semibold mb-1">{locale === "zh" ? "不屬於任何廠商" : "Vendor neutral"}</div>
                <p className="text-stone leading-[1.6]">{locale === "zh" ? "ATR 不歸任何一家公司，是由社群治理的開放標準。" : "No company owns ATR. It is an open standard, governed by its community."}</p>
              </div>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Integrated by */}
      <Reveal>
        <div className="mt-12 mb-px">
          <div className="text-[13px] text-stone mb-5">
            {locale === "zh" ? "整合進了哪裡" : "Integrated by"}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-fog">
            {[
              { label: "Cisco AI Defense", detail: locale === "zh" ? "ATR 規則包 · 開源 skill-scanner repo（PR #99）" : "ATR rule pack · open-source skill-scanner repo (PR #99)", highlight: true },
              { label: locale === "zh" ? `${stats.ruleCount} 條偵測規則` : `${stats.ruleCount} detection rules`, detail: locale === "zh" ? `${stats.categoryCount} 個威脅類別` : `${stats.categoryCount} threat categories`, highlight: false },
              { label: locale === "zh" ? `掃過 ${stats.megaScanTotal.toLocaleString()} 個` : `${stats.megaScanTotal.toLocaleString()} scanned`, detail: locale === "zh" ? `5 個 registry · 標記 ${stats.megaScanFlagged.toLocaleString()} 個（${stats.megaScanDate}）` : `5 registries · ${stats.megaScanFlagged.toLocaleString()} flagged (${stats.megaScanDate})`, highlight: false },
              { label: locale === "zh" ? `${stats.ecosystemIntegrations.length} 個生態整合` : `${stats.ecosystemIntegrations.length} ecosystem integrations`, detail: locale === "zh" ? `已合併 ${stats.ecosystemIntegrations.filter(e => e.type === "merged").length} · 審查中 ${stats.ecosystemIntegrations.filter(e => e.type === "open").length}` : `${stats.ecosystemIntegrations.filter(e => e.type === "merged").length} merged · ${stats.ecosystemIntegrations.filter(e => e.type === "open").length} under review`, highlight: false },
            ].map((item) => (
              <div key={item.label} className="bg-paper p-5">
                <div className={`font-display text-sm font-semibold ${item.highlight ? "text-blue" : "text-ink"}`}>{item.label}</div>
                <p className="text-xs text-stone mt-1">{item.detail}</p>
              </div>
            ))}
          </div>
        </div>
      </Reveal>

      {/* Threat Cloud — optional reference service */}
      <Reveal>
        <div className="mt-12 border border-fog">
          <div className="px-6 py-4 border-b border-fog bg-[#0B0B0F]">
            <h2 className="font-display text-lg font-semibold text-white">
              {locale === "zh" ? "Threat Cloud：選用的參考服務" : "Threat Cloud: an optional reference service"}
            </h2>
          </div>
          <div className="p-6 space-y-6">
            <div className="bg-ash border border-fog px-4 py-3 ">
              <p className="text-sm text-graphite leading-[1.8] max-w-[640px]">
                {locale === "zh"
                  ? "Threat Cloud 是 ATR 維護者營運的選用參考服務，不是標準的一部分。標準本身就是規格加上 MIT 授權的規則，透過 npm、PyPI 或純 YAML，完全可以離線用。Threat Cloud 只是多一份託管的方便：同步規則、上報威脅。不用它，一樣做得到。"
                  : "Threat Cloud is an optional reference service run by the ATR maintainers. It is not part of the standard. The standard is the spec plus the MIT-licensed rules, and it works fully offline through npm, PyPI or raw YAML. Threat Cloud only adds hosted conveniences: rule sync and threat submission. You can get the same results without it."}
              </p>
            </div>
            <p className="text-sm text-stone leading-[1.8] max-w-[560px]">
              {locale === "zh"
                ? "接上之後，掃描器發現新威脅，可以上報到 Threat Cloud。維護者把它寫成偵測規則，審過之後合併進 MIT 規則集發出去。接法如下。"
                : "Once connected, your scanner can submit a new threat to Threat Cloud when it finds one. Maintainers turn it into a detection rule, review it, and merge it into the MIT rule set that goes out to everyone. Here is how to connect."}
            </p>

            <div className="space-y-4">
              <div>
                <div className="font-data text-xs text-stone mb-2">{locale === "zh" ? "方式 1：CLI，最簡單" : "Option 1: the CLI, simplest"}</div>
                <div className="font-data text-sm bg-[#0B0B0F] text-[#4ade80] px-4 py-3  overflow-x-auto">
                  <span className="text-[#808089]">$</span> npx agent-threat-rules scan . --report-to-cloud
                </div>
              </div>

              <div>
                <div className="font-data text-xs text-stone mb-2">{locale === "zh" ? "方式 2：程式庫，給平台整合用" : "Option 2: the library, for platforms"}</div>
                <div className="font-data text-xs bg-[#0B0B0F] text-[#E0E0E8] px-4 py-3  overflow-x-auto leading-[1.8]">
                  <div className="text-[#6B6B76]">{"// "}{locale === "zh" ? "平台偵測到威脅就自動上報" : "Report automatically when your platform detects a threat"}</div>
                  <div>{"import { ATREngine, createTCReporter } from 'agent-threat-rules';"}</div>
                  <div className="mt-1">{"const engine = new ATREngine({"}</div>
                  <div>{"  reporter: createTCReporter(), "}<span className="text-[#6B6B76]">{"// "}{locale === "zh" ? "匿名，不用 API key" : "anonymous, no API key"}</span></div>
                  <div>{"});"}</div>
                  <div className="mt-1 text-[#6B6B76]">{"// "}{locale === "zh" ? "偵測結果會自動分批送到 TC" : "detections are batched and sent to TC"}</div>
                </div>
              </div>

              <div>
                <div className="font-data text-xs text-stone mb-2">{locale === "zh" ? "方式 3：API，全部自己來" : "Option 3: the API, fully custom"}</div>
                <div className="font-data text-xs bg-[#0B0B0F] text-[#E0E0E8] px-4 py-3  overflow-x-auto leading-[1.8]">
                  <div className="text-[#6B6B76]">{"# "}{locale === "zh" ? "直接呼叫 TC API" : "Call the TC API directly"}</div>
                  <div>{"curl -X POST https://tc.agentthreatrule.org/api/threats \\"}</div>
                  <div>{"  -H 'Content-Type: application/json' \\"}</div>
                  <div>{"  -d '{\"ruleId\":\"ATR-2026-00121\",\"severity\":\"critical\","}</div>
                  <div>{"       \"contentHash\":\"abc123\",\"scanTarget\":\"my-skill\"}"}</div>
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-fog">
              <div className="text-[13px] text-stone mb-2">
                {locale === "zh" ? "上報之後" : "What happens after you report"}
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs text-stone">
                <div className="bg-ash p-3 ">
                  <div className="font-data text-ink font-medium mb-1">1. {locale === "zh" ? "聚合" : "Aggregate"}</div>
                  {locale === "zh" ? "TC 收集各個端點送來的訊號" : "TC collects signals from many endpoints"}
                </div>
                <div className="bg-ash p-3 ">
                  <div className="font-data text-ink font-medium mb-1">2. {locale === "zh" ? "結晶" : "Crystallize"}</div>
                  {locale === "zh" ? "AI 找出模式，寫出規則草稿" : "AI looks for patterns and drafts rules"}
                </div>
                <div className="bg-ash p-3 ">
                  <div className="font-data text-ink font-medium mb-1">3. {locale === "zh" ? "審核" : "Review"}</div>
                  {locale === "zh" ? "人工檢查誤判，替攻擊分類" : "A person checks for false positives and classifies the attack"}
                </div>
                <div className="bg-ash p-3 ">
                  <div className="font-data text-ink font-medium mb-1">4. {locale === "zh" ? "分發" : "Distribute"}</div>
                  {locale === "zh" ? "合併進 ATR → npm publish → 全球更新" : "Merged into ATR → npm publish → global update"}
                </div>
              </div>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Cisco Case Study */}
      <Reveal>
        <div className="mt-8 border border-fog">
          <div className="px-6 py-4 border-b border-fog bg-ash">
            <h2 className="font-display text-lg font-semibold">{t(locale, "integrate.cisco.title")}</h2>
          </div>
          <div className="p-6 grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
              <div className="font-data text-3xl font-bold text-ink mb-1">{locale === "zh" ? "規則包" : "rule pack"}</div>
              <div className="text-sm text-stone">{locale === "zh" ? "放在開源的 skill-scanner repo" : "in the open-source skill-scanner repo"}</div>
            </div>
            <div>
              <div className="font-data text-3xl font-bold text-ink mb-1">{locale === "zh" ? "3 PR" : "3 PRs"}</div>
              <div className="text-sm text-stone">{locale === "zh" ? "PoC（#79）→ CLI（#80）→ 規則包（#99）" : "PoC (#79) → CLI (#80) → rule pack (#99)"}</div>
            </div>
            <div>
              <div className="font-data text-3xl font-bold text-ink mb-1">{locale === "zh" ? "隔天" : "next day"}</div>
              <div className="text-sm text-stone">{locale === "zh" ? "第一個 PR 從開出到合併" : "first PR, opened to merged"}</div>
            </div>
          </div>
          <div className="px-6 pb-6">
            <p className="text-sm text-graphite leading-relaxed mb-4">
              {locale === "zh"
                ? <>Cisco AI Defense 團隊維護的開源 repo <span className="font-data">cisco-ai-defense/skill-scanner</span>，把 ATR 規則當成上游依賴。ATR 維護者在 2026-04-02 開了 PR #79，帶進 34 條 PoC 規則，Cisco 的維護者隔天合併。接著 Cisco 的維護者自己寫了 PR #80，做出 <span className="font-data">--rule-packs</span> CLI，讓 ATR 成為一級規則來源。ATR 維護者再開 PR #99，把規則包從 34 條擴到 314 條，2026-04-22 合併。這些是開源 repo 裡已合併的 PR，不能當成 Cisco 商業產品已經出貨。</>
                : <>The Cisco AI Defense team maintains the open-source repo <span className="font-data">cisco-ai-defense/skill-scanner</span>, and it takes ATR rules as an upstream dependency. The ATR maintainer opened PR #79 on 2026-04-02 with a 34-rule PoC, and Cisco&rsquo;s maintainers merged it the next day. A Cisco maintainer then wrote PR #80, the <span className="font-data">--rule-packs</span> CLI, so ATR loads as a first-class rule source. The ATR maintainer opened PR #99 to grow the pack from 34 to 314 rules, merged on 2026-04-22. These are merged pull requests in an open-source repository. They say nothing about whether a Cisco commercial product ships ATR.</>}
            </p>
            <div className="flex flex-wrap gap-4">
              <a href="https://github.com/cisco-ai-defense/skill-scanner/pull/79" target="_blank" rel="noopener noreferrer" className="font-data text-sm text-blue hover:underline">
                PR #79: PoC (34 rules) &rarr;
              </a>
              <a href="https://github.com/cisco-ai-defense/skill-scanner/pull/80" target="_blank" rel="noopener noreferrer" className="font-data text-sm text-blue hover:underline">
                PR #80: rule-packs CLI &rarr;
              </a>
              <a href="https://github.com/cisco-ai-defense/skill-scanner/pull/99" target="_blank" rel="noopener noreferrer" className="font-data text-sm text-blue hover:underline">
                PR #99: rule pack &rarr;
              </a>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Self-serve close: what to do after you ship. No sales step anywhere
          in the loop — integrate, ask if stuck, then list yourself. */}
      <Reveal>
        <div className="mt-12 border border-fog px-6 py-6">
          <div className="text-[13px] text-stone mb-4">
            {locale === "zh" ? "上線之後" : "After you ship"}
          </div>
          <ol className="grid grid-cols-1 md:grid-cols-3 gap-6 list-none">
            <li>
              <div className="font-data text-xs text-stone mb-1">1</div>
              <h3 className="font-display text-sm font-semibold text-ink mb-1">
                {locale === "zh" ? "卡住了？開一張 Integration Request" : "Stuck? Open an Integration Request"}
              </h3>
              <p className="text-sm text-stone leading-relaxed mb-2">
                {locale === "zh"
                  ? "可以請維護者帶你讀規格、幫你看設計，或給你一份用你的語言寫的範例。七天內會回覆。"
                  : "Ask for a walk through the spec or a design review, or for sample code in your language. A maintainer replies within seven days."}
              </p>
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=integration-request.yml"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline"
              >
                {locale === "zh" ? "開 issue →" : "Open issue →"}
              </a>
            </li>
            <li>
              <div className="font-data text-xs text-stone mb-1">2</div>
              <h3 className="font-display text-sm font-semibold text-ink mb-1">
                {locale === "zh" ? "上線了？自己登記進 ADOPTERS.md" : "Shipped? List yourself in ADOPTERS.md"}
              </h3>
              <p className="text-sm text-stone leading-relaxed mb-2">
                {locale === "zh"
                  ? "採用者自己送 PR 登記，維護者不事先審核。格式符合 schema，附上誰都查得到的證據連結，就會合併。你的 PR 本身就是紀錄。"
                  : "Adopters add themselves with a PR. Nobody approves it in advance. If the entry fits the schema and links to evidence anyone can check, it gets merged. Your PR is the record."}
              </p>
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/.github/PULL_REQUEST_TEMPLATE/adopter.md"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline"
              >
                {locale === "zh" ? "登記用的 PR 範本 →" : "Adopter PR template →"}
              </a>
            </li>
            <li>
              <div className="font-data text-xs text-stone mb-1">3</div>
              <h3 className="font-display text-sm font-semibold text-ink mb-1">
                {locale === "zh" ? "進採用者牆，證據每週重驗" : "You're on the wall. The evidence is rechecked weekly"}
              </h3>
              <p className="text-sm text-stone leading-relaxed mb-2">
                {locale === "zh"
                  ? "生態頁直接從 ADOPTERS.md 產生。CI 每週拿每個證據連結去 GitHub 重驗一次，蓋上日期。"
                  : "The ecosystem page is built straight from ADOPTERS.md. Every week, CI rechecks each evidence link against GitHub and stamps the date."}
              </p>
              <Link
                href={`/${locale}/ecosystem`}
                className="font-data text-xs text-blue hover:underline"
              >
                {locale === "zh" ? "看採用者牆 →" : "See the wall →"}
              </Link>
            </li>
          </ol>
        </div>
      </Reveal>
    </div>
  );
}
