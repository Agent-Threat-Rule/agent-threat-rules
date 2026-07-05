import { Reveal } from "@/components/Reveal";
import { loadSiteStats } from "@/lib/stats";
import { locales, t, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
import Link from "next/link";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Integrate - ATR",
  description: "Five integration paths for ATR: TypeScript, Python, raw YAML, GitHub Action, or SIEM queries.",
};

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
  // Threat detected — block or alert
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
    code: `# Point your scanner at rules/ directory
# Each .yaml file follows ATR-SPEC-v1 schema
# Parse with any YAML library
# Schema: spec/atr-schema.yaml

rules/
  prompt-injection/
  tool-poisoning/
  agent-manipulation/
  ... (10 categories)`,
    doc: "https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ATR-FRAMEWORK-SPEC.md",
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
    code: `# Convert ATR rules to SIEM query language
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
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">{t(locale, "integrate.label")}</div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="font-display text-[clamp(28px,4vw,44px)] font-extrabold tracking-[-2px] mb-2">
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
          <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-4">
            {locale === "zh" ? "一份規則 · 任何符合規範的引擎 · 選擇你的整合程度" : "One ruleset · Any conforming engine · Choose your integration level"}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog">
            {[
              {
                level: "L1",
                title: locale === "zh" ? "掃描" : "Scan",
                who: locale === "zh" ? "個人開發者" : "Individual developers",
                how: locale === "zh" ? "一行指令或 GitHub Action" : "One command or GitHub Action",
                what: locale === "zh" ? "即時知道你的 AI 工具有沒有被下毒" : "Know if your AI tools are poisoned",
                update: locale === "zh" ? "每次 npx 自動拉最新規則" : "npx pulls latest rules automatically",
              },
              {
                level: "L2",
                title: locale === "zh" ? "嵌入" : "Embed",
                who: locale === "zh" ? "平台方（IDE、agent 框架）" : "Platforms (IDEs, agent frameworks)",
                how: locale === "zh" ? "npm install + 呼叫 ATR engine" : "npm install + call ATR engine",
                what: locale === "zh" ? `你的用戶自動受到 ${stats.ruleCount} 條規則保護` : `Your users protected by ${stats.ruleCount} rules automatically`,
                update: locale === "zh" ? "npm update 或 lockfile + CI" : "npm update or lockfile + CI",
              },
              {
                level: "L3",
                title: locale === "zh" ? "雙向（選用）" : "Bidirectional (optional)",
                who: locale === "zh" ? "安全平台、企業 SOC" : "Security platforms, enterprise SOC",
                how: locale === "zh" ? "嵌入 + 選用接上 Threat Cloud 參考服務" : "Embed + optionally connect Threat Cloud reference service",
                what: locale === "zh" ? "選用便利:上報威脅與同步規則;不接也能用標準完整運作" : "Optional convenience: submit threats and sync rules; the standard works fully without it",
                update: locale === "zh" ? "npm update（接上 TC 可加即時推送）" : "npm update (TC adds real-time push if connected)",
              },
            ].map((tier) => (
              <div key={tier.level} className="bg-paper p-5 md:p-6">
                <div className="flex items-center gap-2 mb-2">
                  <span className="font-data text-xs font-bold text-blue bg-blue/10 px-2 py-0.5 rounded-sm">{tier.level}</span>
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
            <h2 className="font-display text-lg font-semibold">{locale === "zh" ? "30 秒試用" : "Try it in 30 seconds"}</h2>
          </div>
          <div className="p-6">
            <p className="text-sm text-graphite mb-4 leading-relaxed">
              {locale === "zh"
                ? "不需要註冊、不需要 API key。一行指令掃描你的 SKILL.md 或 MCP config——你在本機跑的這份 YAML,正是 Cisco 與 Microsoft 在 production 跑的同一份規則。"
                : "No signup, no API key. One command scans your SKILL.md or MCP config — the same YAML you run locally is the same ruleset Cisco and Microsoft run in production."}
            </p>
            <div className="space-y-3">
              <div>
                <div className="font-data text-xs text-stone mb-1">{locale === "zh" ? "掃描一個 SKILL.md 檔案" : "Scan a SKILL.md file"}</div>
                <div className="font-data text-sm bg-[#0B0B0F] text-[#4ade80] px-4 py-3 rounded-sm overflow-x-auto">
                  <span className="text-stone">$</span> npx agent-threat-rules scan your-skill.md
                </div>
              </div>
              <div>
                <div className="font-data text-xs text-stone mb-1">{locale === "zh" ? "掃描整個目錄" : "Scan a directory"}</div>
                <div className="font-data text-sm bg-[#0B0B0F] text-[#4ade80] px-4 py-3 rounded-sm overflow-x-auto">
                  <span className="text-stone">$</span> npx agent-threat-rules scan ./my-mcp-skills/
                </div>
              </div>
              <div>
                <div className="font-data text-xs text-stone mb-1">{locale === "zh" ? "安裝為 Claude Code 即時防護" : "Install as Claude Code real-time guard"}</div>
                <div className="font-data text-sm bg-[#0B0B0F] text-[#4ade80] px-4 py-3 rounded-sm overflow-x-auto">
                  <span className="text-stone">$</span> npx agent-threat-rules init --global
                </div>
              </div>
            </div>
            <p className="text-xs text-mist mt-4">
              {locale === "zh"
                ? `${stats.ruleCount} 條規則 · ${stats.categoryCount} 個威脅類別 · < 5ms 延遲 · 零依賴 · MIT 授權`
                : `${stats.ruleCount} rules · ${stats.categoryCount} threat categories · < 5ms latency · zero dependencies · MIT license`}
            </p>
          </div>
        </div>
      </Reveal>

      {/* SDK Integration Paths */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-4">
          {locale === "zh" ? "SDK 整合 · 同一份規則,五種讀法" : "SDK Integration · Same rules, five ways to read them"}
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
              {locale === "zh" ? "GitHub Action 採用者" : "GitHub Action Adopters"}
            </h2>
          </div>
          <div className="p-6 space-y-5">
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? <>把 ATR 掛進任何 GitHub repo 的 CI。結果寫入 SARIF，出現在 GitHub Security 分頁——跟 CodeQL / dependabot 同一個位置。</>
                : <>Wire ATR into any GitHub repo&apos;s CI. Results write to SARIF and surface in the repo&apos;s GitHub Security tab — same place as CodeQL and dependabot.</>}
            </p>
            <div>
              <div className="font-data text-[11px] text-stone tracking-[2px] uppercase mb-2">
                {locale === "zh" ? "最小工作流" : "Minimal Workflow"}
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
              <div className="font-data text-[11px] text-stone tracking-[2px] uppercase mb-3">
                {locale === "zh" ? "公開採用" : "Public Adopters"}
              </div>
              <p className="text-sm text-graphite leading-[1.7]">
                {locale === "zh" ? (
                  <>目前尚無公開採用紀錄。如果你在 repo 使用 ATR Action，請透過{" "}
                    <a
                      href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue hover:underline"
                    >GitHub issue</a>{" "}告訴我們，我們會列在這裡。</>
                ) : (
                  <>No public adopters tracked yet. If your repo uses the ATR Action, let us know via a{" "}
                    <a
                      href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue hover:underline"
                    >GitHub issue</a>{" "}and we&apos;ll list it here.</>
                )}
              </p>
              <p className="text-xs text-mist mt-2 leading-[1.7]">
                {locale === "zh"
                  ? "採用形式不只 GitHub Action——Cisco AI Defense (PR #79 PoC + PR #99 production) 以 rule-packs CLI 整合完整規則集;Microsoft AGT (PR #908 PoC + PR #1277 production) 以 PolicyDocument 格式整合規則(提 PR 時為 287 條,後續每週自動同步至 ATR main);Gen Digital Sage (PR #33) 整套規則包進 agentic-AI 風險評分層。這三筆算「上游採用」,不屬於 Action 使用統計。"
                  : "Adoption forms vary — Cisco AI Defense (PR #79 PoC + PR #99 production) integrates the full rule pack via a rule-packs CLI; Microsoft AGT (PR #908 PoC + PR #1277 production) integrates rules as PolicyDocument (287 rules at time of PR, auto-synced to ATR main since via a weekly workflow); Gen Digital Sage (PR #33) ships the rule pack inside the agentic-AI risk-scoring layer. These three count as upstream adoption, separate from Action usage."}
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
                ? "如果你把 ATR 當作上游依賴，你需要確保格式不會壞掉。以下是我們的承諾："
                : "If you depend on ATR as upstream, you need to know the format won\u0027t break. Here\u0027s our commitment:"}
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div>
                  <div className="font-display text-sm font-semibold mb-1">ATR-SPEC-v1 ({locale === "zh" ? "穩定版" : "stable"})</div>
                  <p className="text-sm text-stone leading-[1.6]">
                    {locale === "zh"
                      ? "已發布且穩定。所有新增欄位皆為選填。現有欄位不會在主版本升級前被移除或重新命名。"
                      : "Published and stable. All new fields are optional additions. No existing field will be removed or renamed without a major version bump."}
                  </p>
                </div>
                <div>
                  <div className="font-display text-sm font-semibold mb-1">{locale === "zh" ? "向後相容" : "Backward Compatibility"}</div>
                  <p className="text-sm text-stone leading-[1.6]">
                    {locale === "zh"
                      ? "破壞性變更只會發生在主版本轉換時（v1 → v2）。我們提供遷移指南，並至少有 6 個月的重疊期同時支援兩個版本。"
                      : "Breaking changes only happen on major version transitions (v1 \u2192 v2). We provide migration guides and a minimum 6-month overlap period where both versions are supported."}
                  </p>
                </div>
              </div>
              <div className="space-y-4">
                <div>
                  <div className="font-display text-sm font-semibold mb-1">{locale === "zh" ? "更新頻率" : "Update Frequency"}</div>
                  <p className="text-sm text-stone leading-[1.6]">
                    {locale === "zh"
                      ? <>持續新增規則（活躍期平均每週 2-5 條）。每條規則在合併前都通過 CI 驗證 + precision 測試。訂閱{" "}<a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/releases" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">GitHub Releases</a>{" "}取得更新日誌。</>
                      : <>New rules are added continuously (avg 2-5 per week during active periods). Every rule passes CI validation + precision test before merge. Subscribe to{" "}<a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/releases" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">GitHub Releases</a>{" "}for changelogs.</>}
                  </p>
                </div>
                <div>
                  <div className="font-display text-sm font-semibold mb-1">{locale === "zh" ? "同步方式" : "Sync Methods"}</div>
                  <div className="font-data text-sm text-stone leading-[1.8]">
                    <span className="text-ink">git submodule</span> &mdash; {locale === "zh" ? "鎖定 tag，按你的節奏更新" : "pin to tag, update on your schedule"}<br />
                    <span className="text-ink">npm install</span> &mdash; {locale === "zh" ? "語意版本控制，lockfile 鎖定版本" : "semver, lockfile controls version"}<br />
                    <span className="text-ink">GitHub Action</span> &mdash; {locale === "zh" ? "CI 自動使用最新規則掃描" : "CI scans with latest rules automatically"}
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
                { label: locale === "zh" ? "覆蓋範圍" : "Coverage", atr: locale === "zh" ? `${stats.ruleCount} 條規則，${stats.cveCount} 個 CVE 對應，${stats.categoryCount} 個威脅類別` : `${stats.ruleCount} rules, ${stats.cveCount} CVEs mapped, ${stats.categoryCount} threat categories`, own: locale === "zh" ? "需要自行建立規則庫" : "You build your own rule set" },
                { label: locale === "zh" ? "新攻擊反應" : "New attack response", atr: locale === "zh" ? "社群與 CI 流程持續新增規則,目標數小時內產出(選用的 Threat Cloud 可加速回報)" : "Community + CI pipeline add rules continuously, targeting hours (optional Threat Cloud can speed up reporting)", own: locale === "zh" ? "取決於你團隊的頻寬" : "Depends on your team's bandwidth" },
                { label: locale === "zh" ? "繞過測試" : "Evasion testing", atr: locale === "zh" ? "64 種已記錄的繞過技術，規則附帶 evasion_tests" : "64 documented evasion techniques, with per-rule evasion_tests", own: locale === "zh" ? "需要額外投入時間建立" : "Requires dedicated effort to build" },
                { label: locale === "zh" ? "OWASP / MITRE 對應" : "OWASP / MITRE mapping", atr: locale === "zh" ? "內建。Agentic 10/10 + 每條規則對應 MITRE ATLAS" : "Pre-built. 10/10 Agentic + MITRE ATLAS per rule", own: locale === "zh" ? "數小時的手動對應工作" : "Hours of manual mapping work" },
                { label: locale === "zh" ? "維護成本" : "Maintenance", atr: locale === "zh" ? "社群維護。MIT 授權。零成本。" : "Community-maintained. MIT. Zero cost.", own: locale === "zh" ? "需要持續的人力投入" : "Requires ongoing engineering effort" },
                { label: locale === "zh" ? "生態系" : "Ecosystem", atr: locale === "zh" ? "Cisco、Microsoft、MISP 已整合，OWASP PR 審查中" : "Cisco, Microsoft, MISP integrated; OWASP PRs under review", own: locale === "zh" ? "獨立維護，無共享規則" : "Maintained independently, no shared rules" },
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
              <span className="ml-auto">{locale === "zh" ? "自建規則" : "Internal Rules"}</span>
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
                <p className="text-stone leading-[1.6]">{locale === "zh" ? "可商用、修改、分發、再授權。無任何限制。" : "Use commercially, modify, distribute, sublicense. No restrictions."}</p>
              </div>
              <div>
                <div className="font-display text-sm font-semibold mb-1">{locale === "zh" ? "無 CLA" : "No CLA"}</div>
                <p className="text-stone leading-[1.6]">{locale === "zh" ? "無貢獻者授權協議。所有貢獻皆以 MIT 授權，屬於社群所有。" : "No Contributor License Agreement. Contributions are MIT-licensed and belong to the community."}</p>
              </div>
              <div>
                <div className="font-display text-sm font-semibold mb-1">{locale === "zh" ? "廠商中立" : "Vendor Neutral"}</div>
                <p className="text-stone leading-[1.6]">{locale === "zh" ? "ATR 不屬於任何公司。它是社群治理的開放標準。" : "ATR is not owned by any company. It is a community-governed open standard."}</p>
              </div>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Integrated by */}
      <Reveal>
        <div className="mt-12 mb-px">
          <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-5">
            {locale === "zh" ? "生態整合" : "Integrated by"}
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-fog">
            {[
              { label: "Cisco AI Defense", detail: locale === "zh" ? "完整 ATR 規則包 · skill-scanner production (PR #99)" : "Full ATR rule pack · skill-scanner production (PR #99)", highlight: true },
              { label: locale === "zh" ? `${stats.ruleCount} 條偵測規則` : `${stats.ruleCount} detection rules`, detail: locale === "zh" ? `${stats.categoryCount} 個威脅類別` : `${stats.categoryCount} threat categories`, highlight: false },
              { label: locale === "zh" ? `${stats.megaScanTotal.toLocaleString()} 已掃描` : `${stats.megaScanTotal.toLocaleString()} skills scanned`, detail: locale === "zh" ? "6 個 registry · 552 確認惡意軟體" : "6 registries · 552 confirmed malware", highlight: false },
              { label: locale === "zh" ? `${stats.ecosystemIntegrations.length} 個生態系整合` : `${stats.ecosystemIntegrations.length} ecosystem integrations`, detail: `${stats.ecosystemIntegrations.filter(e => e.type === "merged").length} merged · ${stats.ecosystemIntegrations.filter(e => e.type === "open").length} under review`, highlight: false },
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
              {locale === "zh" ? "Threat Cloud — 選用參考服務" : "Threat Cloud — Optional Reference Service"}
            </h2>
          </div>
          <div className="p-6 space-y-6">
            <div className="bg-ash border border-fog px-4 py-3 rounded-sm">
              <p className="text-sm text-graphite leading-[1.8] max-w-[640px]">
                {locale === "zh"
                  ? "Threat Cloud 是 ATR 維護者運營的選用參考服務,並非標準的一部分。標準本體是規格加上 MIT 授權的規則,透過 npm / PyPI / 純 YAML 完全可離線使用;Threat Cloud 只提供 hosted 便利(規則同步、威脅提交),不用它也能達到同樣結果。"
                  : "Threat Cloud is an optional reference service operated by the ATR maintainers — not part of the standard. The standard is the spec plus the MIT-licensed rules, fully usable offline via npm / PyPI / raw YAML. Threat Cloud only adds hosted convenience (rule sync, threat submission); the same outcomes are reachable without it."}
              </p>
            </div>
            <p className="text-sm text-stone leading-[1.8] max-w-[560px]">
              {locale === "zh"
                ? "若你選擇接上:掃描器發現新威脅時可上報到 Threat Cloud,維護者會將其結晶成偵測規則,審核通過後合併進 MIT 規則集分發。以下是接上的技術文件——完全選用。"
                : "If you choose to connect it: when your scanner finds a new threat, you can submit it to Threat Cloud, where maintainers crystallize it into a detection rule, review it, and merge it into the MIT rule set for distribution. The technical docs below cover connecting it — entirely optional."}
            </p>

            <div className="space-y-4">
              <div>
                <div className="font-data text-xs text-stone mb-2">{locale === "zh" ? "方式 1：CLI（最簡單）" : "Method 1: CLI (simplest)"}</div>
                <div className="font-data text-sm bg-[#0B0B0F] text-[#4ade80] px-4 py-3 rounded-sm overflow-x-auto">
                  <span className="text-[#808089]">$</span> npx agent-threat-rules scan . --report-to-cloud
                </div>
              </div>

              <div>
                <div className="font-data text-xs text-stone mb-2">{locale === "zh" ? "方式 2：程式庫（平台整合）" : "Method 2: Library (platform integration)"}</div>
                <div className="font-data text-xs bg-[#0B0B0F] text-[#E0E0E8] px-4 py-3 rounded-sm overflow-x-auto leading-[1.8]">
                  <div className="text-[#6B6B76]">{"// "}{locale === "zh" ? "你的平台發現威脅時自動上報" : "Auto-report when your platform detects threats"}</div>
                  <div>{"import { ATREngine, createTCReporter } from 'agent-threat-rules';"}</div>
                  <div className="mt-1">{"const engine = new ATREngine({"}</div>
                  <div>{"  reporter: createTCReporter(), "}<span className="text-[#6B6B76]">{"// "}{locale === "zh" ? "匿名，不需 API key" : "anonymous, no API key"}</span></div>
                  <div>{"});"}</div>
                  <div className="mt-1 text-[#6B6B76]">{"// "}{locale === "zh" ? "偵測結果自動批次上報 TC" : "detections auto-batched to TC"}</div>
                </div>
              </div>

              <div>
                <div className="font-data text-xs text-stone mb-2">{locale === "zh" ? "方式 3：API（完全自訂）" : "Method 3: API (fully custom)"}</div>
                <div className="font-data text-xs bg-[#0B0B0F] text-[#E0E0E8] px-4 py-3 rounded-sm overflow-x-auto leading-[1.8]">
                  <div className="text-[#6B6B76]">{"# "}{locale === "zh" ? "直接呼叫 TC API" : "Direct TC API call"}</div>
                  <div>{"curl -X POST https://tc.agentthreatrule.org/api/threats \\"}</div>
                  <div>{"  -H 'Content-Type: application/json' \\"}</div>
                  <div>{"  -d '{\"ruleId\":\"ATR-2026-00121\",\"severity\":\"critical\","}</div>
                  <div>{"       \"contentHash\":\"abc123\",\"scanTarget\":\"my-skill\"}"}</div>
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-fog">
              <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">
                {locale === "zh" ? "上報後會發生什麼" : "What happens after reporting"}
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs text-stone">
                <div className="bg-ash p-3 rounded-sm">
                  <div className="font-data text-ink font-medium mb-1">1. {locale === "zh" ? "聚合" : "Aggregate"}</div>
                  {locale === "zh" ? "TC 收集多個端點的訊號" : "TC collects signals from endpoints"}
                </div>
                <div className="bg-ash p-3 rounded-sm">
                  <div className="font-data text-ink font-medium mb-1">2. {locale === "zh" ? "結晶" : "Crystallize"}</div>
                  {locale === "zh" ? "AI 分析模式，產出規則草稿" : "AI analyzes patterns, drafts rules"}
                </div>
                <div className="bg-ash p-3 rounded-sm">
                  <div className="font-data text-ink font-medium mb-1">3. {locale === "zh" ? "審核" : "Review"}</div>
                  {locale === "zh" ? "人工審核 FP + 攻擊類型分類" : "Human reviews FP + attack classification"}
                </div>
                <div className="bg-ash p-3 rounded-sm">
                  <div className="font-data text-ink font-medium mb-1">4. {locale === "zh" ? "分發" : "Distribute"}</div>
                  {locale === "zh" ? "合併到 ATR → npm publish → 全球更新" : "Merged to ATR → npm publish → global update"}
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
              <div className="font-data text-3xl font-bold text-ink mb-1">{locale === "zh" ? "完整規則包" : "full pack"}</div>
              <div className="text-sm text-stone">{locale === "zh" ? "在 skill-scanner production" : "in skill-scanner production"}</div>
            </div>
            <div>
              <div className="font-data text-3xl font-bold text-ink mb-1">{locale === "zh" ? "2 PR" : "2 PRs"}</div>
              <div className="text-sm text-stone">{locale === "zh" ? "PoC (#79) → production (#99)" : "PoC (#79) → production (#99)"}</div>
            </div>
            <div>
              <div className="font-data text-3xl font-bold text-ink mb-1">{locale === "zh" ? "3 天" : "3 days"}</div>
              <div className="text-sm text-stone">{locale === "zh" ? "首次提交到合併" : "first PR to merge"}</div>
            </div>
          </div>
          <div className="px-6 pb-6">
            <p className="text-sm text-graphite leading-relaxed mb-4">
              {locale === "zh"
                ? <>Cisco 的 AI Defense 團隊把 ATR 規則整合為上游依賴。第一個 PR #79(2026-04-03)合併 34 條 PoC 規則,3 天內 merge。隨後 PR #80 建置 <span className="font-data">--rule-packs</span> CLI 把 ATR 作為第一級規則來源。production PR #99(2026-04-22)把完整 ATR 規則集送進 Cisco AI Defense 的 skill-scanner 生產環境。</>
                : <>Cisco&apos;s AI Defense team integrated ATR rules as an upstream dependency. The first PR #79 (2026-04-03) merged a 34-rule PoC in three days. Follow-up PR #80 built the <span className="font-data">--rule-packs</span> CLI to consume ATR as a first-class rule source. Production PR #99 (2026-04-22) landed the full ATR rule pack inside Cisco AI Defense&apos;s skill-scanner.</>}
            </p>
            <div className="flex flex-wrap gap-4">
              <a href="https://github.com/cisco-ai-defense/skill-scanner/pull/79" target="_blank" rel="noopener noreferrer" className="font-data text-sm text-blue hover:underline">
                PR #79: PoC (34 rules) &rarr;
              </a>
              <a href="https://github.com/cisco-ai-defense/skill-scanner/pull/80" target="_blank" rel="noopener noreferrer" className="font-data text-sm text-blue hover:underline">
                PR #80: rule-packs CLI &rarr;
              </a>
              <a href="https://github.com/cisco-ai-defense/skill-scanner/pull/99" target="_blank" rel="noopener noreferrer" className="font-data text-sm text-blue hover:underline">
                PR #99: production &rarr;
              </a>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Self-serve close: what to do after you ship. No sales step anywhere
          in the loop — integrate, ask if stuck, then list yourself. */}
      <Reveal>
        <div className="mt-12 border border-fog px-6 py-6">
          <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-4">
            {locale === "zh" ? "出貨之後" : "After you ship"}
          </div>
          <ol className="grid grid-cols-1 md:grid-cols-3 gap-6 list-none">
            <li>
              <div className="font-data text-xs text-stone mb-1">1</div>
              <h3 className="font-display text-sm font-semibold text-ink mb-1">
                {locale === "zh" ? "卡住了?開 Integration Request" : "Stuck? Open an Integration Request"}
              </h3>
              <p className="text-sm text-stone leading-relaxed mb-2">
                {locale === "zh"
                  ? "spec walkthrough、design review、你的語言的 sample code。維護者七天內回覆。"
                  : "Spec walkthrough, design review, sample code for your language. Maintainers respond within seven days."}
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
                {locale === "zh" ? "上線了?自己列進 ADOPTERS.md" : "Shipped? List yourself in ADOPTERS.md"}
              </h3>
              <p className="text-sm text-stone leading-relaxed mb-2">
                {locale === "zh"
                  ? "採用者自行提 PR,維護者不預先審核——schema 對、附公開可驗證的證據連結就 merge。你的 PR 本身就是紀錄。"
                  : "Adopters self-declare via PR — no pre-approval. A schema-conforming entry with a verifiable evidence link gets merged. Your PR is the record."}
              </p>
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/.github/PULL_REQUEST_TEMPLATE/adopter.md"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline"
              >
                {locale === "zh" ? "adopter PR 模板 →" : "Adopter PR template →"}
              </a>
            </li>
            <li>
              <div className="font-data text-xs text-stone mb-1">3</div>
              <h3 className="font-display text-sm font-semibold text-ink mb-1">
                {locale === "zh" ? "進採用者牆,證據週週重驗" : "You join the wall — evidence re-verified weekly"}
              </h3>
              <p className="text-sm text-stone leading-relaxed mb-2">
                {locale === "zh"
                  ? "生態頁直接讀 ADOPTERS.md 渲染,CI 每週對 GitHub 重驗每個證據連結並蓋上日期。"
                  : "The ecosystem page renders straight from ADOPTERS.md, and CI re-verifies every evidence link against GitHub weekly, stamping the date."}
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
