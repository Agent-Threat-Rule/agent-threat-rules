/** One-line description of each rule category, shown on the home page coverage figure. */

export const CATEGORY_DESC: Record<string, { en: string; zh: string }> = {
  "prompt-injection": {
    en: "Hijacking agent behavior through crafted inputs",
    zh: "透過精心構造的輸入劫持 agent 行為",
  },
  "skill-compromise": {
    en: "Malicious or vulnerable MCP skills and SKILL.md",
    zh: "惡意或有漏洞的 MCP skill 和 SKILL.md",
  },
  "context-exfiltration": {
    en: "Stealing conversation context and sensitive data",
    zh: "竊取對話上下文和敏感資料",
  },
  "agent-manipulation": {
    en: "Social engineering and behavioral manipulation of agents",
    zh: "對 agent 的社交工程和行為操控",
  },
  "tool-poisoning": {
    en: "Poisoned tool descriptions and malicious tool responses",
    zh: "被下毒的工具描述和惡意工具回應",
  },
  "privilege-escalation": {
    en: "Unauthorized elevation of agent capabilities",
    zh: "未授權提升 agent 權限",
  },
  "excessive-autonomy": {
    en: "Agents exceeding intended operational boundaries",
    zh: "Agent 超越預期的操作邊界",
  },
  "data-poisoning": {
    en: "Corrupting training data, memory, or retrieval sources to bias agent behavior",
    zh: "污染訓練資料、記憶體或檢索來源以扭曲 agent 行為",
  },
  "model-abuse": {
    en: "Misusing model capabilities — jailbreaks, harmful generation, resource abuse",
    zh: "濫用模型能力——越獄、有害內容生成、資源濫用",
  },
  "model-security": {
    en: "Attacks on the model itself — extraction, inversion, adversarial inputs",
    zh: "針對模型本身的攻擊——模型提取、逆向還原、對抗式輸入",
  },
};
