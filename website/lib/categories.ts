/**
 * Category display logic. Kept in its own module so client components (like
 * RuleExplorer) can import it without pulling in node:fs via lib/rules.ts.
 */

const CATEGORY_DISPLAY_NAMES: Record<string, { en: string; zh: string }> = {
  "prompt-injection": { en: "Prompt Injection", zh: "提示注入" },
  "skill-compromise": { en: "Skill Compromise", zh: "Skill 入侵" },
  "context-exfiltration": { en: "Context Exfiltration", zh: "上下文外洩" },
  "agent-manipulation": { en: "Agent Manipulation", zh: "Agent 操控" },
  "tool-poisoning": { en: "Tool Poisoning", zh: "工具下毒" },
  "privilege-escalation": { en: "Privilege Escalation", zh: "權限提升" },
  "excessive-autonomy": { en: "Excessive Autonomy", zh: "過度自主" },
  "model-level-attacks": { en: "Model-Level Attacks", zh: "模型層級攻擊" },
  "data-poisoning": { en: "Data Poisoning", zh: "資料投毒" },
  "model-abuse": { en: "Model Abuse", zh: "模型濫用" },
  "model-security": { en: "Model Security", zh: "模型安全" },
};

export function categoryDisplayName(category: string, locale: string = "en"): string {
  const entry = CATEGORY_DISPLAY_NAMES[category];
  if (entry) return locale === "zh" ? entry.zh : entry.en;
  return category
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}
