/** One-line description of each rule category, shown on the home page coverage figure. */

export const CATEGORY_DESC: Record<string, { en: string; zh: string }> = {
  "prompt-injection": {
    en: "Crafted inputs that hijack what an agent does",
    zh: "用特製的輸入，劫持 agent 的行為",
  },
  "skill-compromise": {
    en: "Malicious or vulnerable MCP skills and SKILL.md files",
    zh: "有惡意或有漏洞的 MCP skill 與 SKILL.md",
  },
  "context-exfiltration": {
    en: "Stealing conversation context and sensitive data",
    zh: "偷走對話內容和敏感資料",
  },
  "agent-manipulation": {
    en: "Social engineering that talks an agent into behaving differently",
    zh: "對 agent 下手的社交工程，騙它改變行為",
  },
  "tool-poisoning": {
    en: "Poisoned tool descriptions and malicious tool responses",
    zh: "工具說明被下毒，或工具回傳惡意內容",
  },
  "privilege-escalation": {
    en: "An agent gaining capabilities nobody authorised",
    zh: "agent 拿到沒人授權的權限",
  },
  "excessive-autonomy": {
    en: "Agents going past the limits they were meant to work within",
    zh: "agent 做的事，超出原本劃好的範圍",
  },
  "data-poisoning": {
    en: "Tainted training data, memory or retrieval sources that bend what an agent does",
    zh: "污染訓練資料、記憶或檢索來源，把 agent 的行為帶歪",
  },
  "model-abuse": {
    en: "Misusing what a model can do: jailbreaks, harmful output, burning resources",
    zh: "濫用模型的能力，像是越獄、產出有害內容、耗用資源",
  },
  "model-security": {
    en: "Attacks on the model itself, such as extraction, inversion and adversarial inputs",
    zh: "直接攻擊模型本身，例如提取模型、逆向還原、對抗式輸入",
  },
};
