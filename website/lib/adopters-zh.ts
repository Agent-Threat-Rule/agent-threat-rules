/**
 * Traditional Chinese versions of the one-sentence `Integration` field in
 * ADOPTERS.md, keyed by the entry's `### Project Name` heading exactly as
 * written there. ADOPTERS.md stays the English source of truth; this map only
 * supplies the text shown on /zh/ecosystem. A missing key falls back to the
 * English sentence, so a new adopter renders correctly before it is
 * translated.
 *
 * When an entry's English sentence changes in ADOPTERS.md, update the Chinese
 * here too, keeping every fact, number, date and name.
 *
 * @module lib/adopters-zh
 */

import type { Adopter } from "./adopters";

export const ADOPTER_INTEGRATION_ZH: Readonly<Record<string, string>> = {
  // Tier S
  "MISP / CIRCL":
    "ATR 規則 ID 分類（taxonomy）與威脅情資 galaxy 已合併進 MISP 的核心發行版。",
  "OWASP Agent Security Regression Harness":
    "貢獻給這套 harness 的四個回歸測試情境，改寫自 ATR（目標劫持、MCP 信任邊界、提示注入、敏感資料外洩）。上游的情境檔沒有標註 ATR，所以這筆是 ATR 對 harness 的貢獻，不是 harness 引用 ATR。",
  "OpenTelemetry — semantic-conventions-genai":
    "提案新增 `agent.threat.detection.*` 語意慣例屬性（ATR 會把這些屬性寫進 agent span），審查中。",
  "FINOS Common Cloud Controls":
    "ATR 的 guideline 對應已合併進 Common Cloud Controls 目錄（CN01/CN02/CN04/CN06），並附 Gemara MappingReference 條目。",
  Gemara:
    "把 ATR 的偵測類別對應到 Gemara 的 capability catalog 格式；`examples/ai-agent/` 底下的範例目錄是這個專案唯一的完整範例。由 ATR 貢獻，Gemara 維護者 jpower432 合併。",
  "IBM AI Atlas Nexus":
    "IBM 的 AI 風險知識圖譜在 OWASP Agentic Skills Top 10 的關聯資料裡，把 Agent Threat Rules 列為外部參考，也列為建議措施（「Use Agent Threat Rules as a supplementary shareable detection layer」）。由 IBM 維護者 ingelise 撰寫並合併，不是 ATR 開的 PR。",

  // Tier 1
  "Cisco AI Defense":
    "ATR 規則包已合併進開源的 cisco-ai-defense/skill-scanner repository。這裡說的是那個 repository，不是任何 Cisco 產品。",
  "Gen Digital Sage":
    "改寫自 ATR 的 agent 層威脅模式，貢獻給 Sage 的 agentic AI 風險評分層。",
  "NVIDIA NeMo Agent Toolkit":
    "NVIDIA 自己的 README 在 Public Plugin API for Third-Party Tools 底下，把 `NeMo-Agent-Toolkit-ATR` 和 Tavily、Redis 外掛列在一起。由 NVIDIA 維護者 bbednarski9 撰寫並合併，不是 ATR 開的 PR。",

  // Tier 2
  "AG2 (AutoGen)":
    "`ATRGuardrail` contrib capability，透過 `pyatr` 引擎用 ATR 規則集掃描工具輸出和 LLM 輸入。由 ATR 維護者貢獻給 ag2-classic 框架並承諾持續維護，AG2 維護者 marklysze 審查、修改後合併。",
  "BerriAI LiteLLM":
    "以 LiteLLM proxy callback 的形式整合 ATR guardrail，在 proxy 層用規則庫掃描 LLM 的輸入與輸出。",
  Promptfoo:
    "MCP 紅隊輸出掃描採用 ATR 規則，在評測執行中標出對抗性回應。",
  SigmaHQ:
    "列入 Sigma 工具目錄；agent-threat-rules 被列為同類的偵測規則格式。",
  "Microsoft PyRIT":
    "ATR 對抗 payload 資料集載入器已合併進 PyRIT（PR #1715，維護者 Roman Lutz 於 2026-05-27 合併）。後續的 AgentThreatRulesScorer（PR #1893）在 2026-08-17 合併，2026-08-18 被 PR #2410 撤回；目前隨 PyRIT 釋出的只有資料集載入器。",
  "Microsoft Agent Framework":
    "範例程式：在 Microsoft Agent Framework 裡把 ATR 當成確定性的動作邊界驗證器。",
  "Microsoft Agent Governance Toolkit":
    "AGT repository 裡的兩個範例目錄：examples/acs-atr-annotator（ACS annotator adapter）與 examples/atr-import（把 ATR YAML 編譯成 ACS manifest 和 Rego bundle）。早期範例 PR 放在 examples/atr-community-rules 底下的規則包 YAML，上游已於 2026-07-30 移除，該目錄的每週同步 workflow 也固定在舊版 ATR。由 ATR 維護者貢獻、AGT 維護者合併；之後 AGT 維護者在自己的重構裡更新過這些範例（2026-07、2026-09）。",
  "Cisco AI BOM":
    "`security_enrichment.py` 用 pyatr 替偵測到的 skill、prompt、agent 與 MCP 元件標上 MITRE ATLAS 技術 ID。",
  "Google ADK":
    "ATR guardrail 外掛收錄在 Google 官方的 ADK 整合目錄，網址是 adk.dev/integrations/atr-guardrail/。由 ATR 貢獻，Google 維護者 koverholt 合併。",
  "Cisco mcp-scanner":
    "改寫自 ATR 的 tool_shadowing YARA 規則，貢獻給 Cisco mcp-scanner 的偵測規則集。",
  "Splunk security_content":
    "三條改寫自 ATR 的 MCP 偵測，貢獻給 Splunk 的 Suspicious MCP Activity analytic story。",
  "rulezet (CIRCL)":
    "`atr_format.py` 匯入／轉換器，比照既有的 `sigma_format` 模組實作（24 個單元測試），讓 ATR 規則在 rulezet 裡成為一級支援的格式。",
  "NVIDIA NeMo Guardrails":
    "替 NeMo Guardrails 函式庫加上 Agent Threat Rules 偵測 rail。",
  "atr-to-yaral":
    "把 ATR YAML 規則轉成 Google SecOps（Chronicle）用的 YARA-L 2.0 規則，內含實際執行的 RE2 編譯檢查閘、Unicode 跳脫字元轉換，並拿每條規則自己的測試案例做 canary 測試。",
  "prompt-protection":
    "`prompt-protection/atr` 把 ATR 規則包編譯進這個函式庫自己的評分引擎，輸出規格定義的 ScanResult 結構，並遵守 scan-target、agent-source、status 與 maturity lane 篩選；無法忠實表達的條件會註明原因後跳過，不拿近似條件代替。",
  "Tencent AI-Infra-Guard":
    "涵蓋 ATR 各類攻擊的 MCP 威脅偵測 prompt 範本，由 ATR 維護者貢獻、AI-Infra-Guard 維護者合併進掃描器的 `data/mcp/` 規則集，採用它自己的 `prompt_template` schema，每個新增檔案的作者都標為 `ATR (Agent Threat Rules)`。",

  // Tier 3
  "killertcell428/aigis":
    "Aigis↔ATR 對照表：以兩邊共用的 MITRE ATLAS 技術為軸，把 Aigis 的偵測模式對應到 ATR 規則 ID，並附雙向的 ATLAS 覆蓋缺口分析；已合併進 Aigis repo。",
  "ottosulin/awesome-ai-security": "ATR 列在 MCP Security 一節。",
  "CryptoAILab/Awesome-LM-SSP": "ATR 列入這份 LLM 安全與資安 awesome-list。",
  "precize/Agentic-AI-Top10-Vulnerability":
    "在一份第三方目錄裡，把 ATR 偵測對應到各個 agentic AI 弱點類別。",
  "wearetyomsmnv/Awesome-LLM-agent-Security":
    "ATR 列入這份 LLM agent 資安工具 awesome-list。",
  "nibzard/awesome-agentic-patterns":
    "「Deterministic Threat Rule Scanning」pattern 已被收錄，內容引用 ATR。",
  "OWASP Agentic Skills Top 10":
    "ATR 對 AST 的對照表與野外掃描資料集被收為外部參考；兩個 PR 都由專案負責人 kenhuangus 合併。",
  "xlabs-club/awesome-x-ops":
    "維護者 l10178 把 ATR 加進英文與簡體中文清單，不是 ATR 開的 PR。",
  "AMD GAIA":
    "GAIA 官方整合文件：用離線的 ATR 輸入／輸出防護守住 Lemonade 模型端點（提示注入偵測模式）。",
  "ProjectRecon/awesome-ai-agents-security":
    "ATR 列在 Static Analysis & Linters 一節。",
  "raphabot/awesome-cybersecurity-agentic-ai": "ATR 列在 Tools 一節。",
};

/**
 * The integration sentence to show for an adopter in the given locale: the
 * Chinese version when one exists, otherwise the English from ADOPTERS.md.
 */
export function adopterIntegrationText(
  adopter: Pick<Adopter, "name" | "integration">,
  locale: "en" | "zh",
): string {
  if (locale !== "zh") return adopter.integration;
  return ADOPTER_INTEGRATION_ZH[adopter.name] ?? adopter.integration;
}
