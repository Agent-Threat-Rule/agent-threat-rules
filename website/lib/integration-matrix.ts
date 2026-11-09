import { loadAdopters, type Adopter } from "./adopters";

/**
 * Integrations matrix: every ADOPTERS.md entry mapped to the ATR component it
 * consumes and the layer it runs in. The classification reads only the
 * entry's own integration sentence and type, so it never claims more than
 * ADOPTERS.md says; an entry whose sentence names no component is shown as
 * "not stated" rather than guessed. Every adopter is treated by the same
 * rules, and no implementer is ranked or recommended.
 */

export type Bilingual = { en: string; zh: string };

export interface Component {
  key: string;
  label: Bilingual;
  /** Where the component lives in the ATR repository, or null for a concept. */
  repoPath: string | null;
  note: Bilingual;
}

/** ATR components an integration can consume, in the order the matrix shows them. */
export const COMPONENTS: ReadonlyArray<Component> = [
  { key: "engine-py", label: { en: "Python engine (pyatr)", zh: "Python 引擎（pyatr）" }, repoPath: "python", note: { en: "Evaluates rules in process from Python.", zh: "在 Python 程序內評估規則。" } },
  { key: "engine-npm", label: { en: "Reference engine (npm)", zh: "參考引擎（npm）" }, repoPath: "src", note: { en: "The TypeScript reference engine, agent-threat-rules on npm.", zh: "TypeScript 參考引擎，npm 套件 agent-threat-rules。" } },
  { key: "rules", label: { en: "Rule YAML", zh: "規則 YAML" }, repoPath: "rules", note: { en: "Rules imported or packaged as they are.", zh: "原樣匯入或打包的規則。" } },
  { key: "converted", label: { en: "Converted or ported rules", zh: "轉換或移植的規則" }, repoPath: "src/converters", note: { en: "Rules translated to another format: YARA, YARA-L, a native scoring engine.", zh: "轉成其他格式的規則：YARA、YARA-L、自家計分引擎。" } },
  { key: "patterns", label: { en: "Detection logic, rewritten", zh: "改寫的偵測邏輯" }, repoPath: null, note: { en: "Patterns or templates derived from ATR rules in the adopter's own form.", zh: "依 ATR 規則改寫成對方格式的樣式或範本。" } },
  { key: "dataset", label: { en: "Test cases as a dataset", zh: "測試案例資料集" }, repoPath: "rules", note: { en: "True-positive payloads used as adversarial test data.", zh: "把正例 payload 當對抗測試資料。" } },
  { key: "scenarios", label: { en: "Test scenarios", zh: "測試情境" }, repoPath: null, note: { en: "Regression scenarios written from ATR rules.", zh: "依 ATR 規則寫成的回歸測試情境。" } },
  { key: "taxonomy", label: { en: "Rule-ID taxonomy", zh: "規則 ID 分類法" }, repoPath: null, note: { en: "ATR identifiers and categories used as a threat-intel vocabulary.", zh: "以 ATR 的 ID 與類別當威脅情資詞彙。" } },
  { key: "mapping", label: { en: "Framework mapping", zh: "框架對照" }, repoPath: "docs", note: { en: "ATR categories or rules mapped onto a control catalog.", zh: "把 ATR 類別或規則對照到控制項目錄。" } },
  { key: "telemetry", label: { en: "Event attributes", zh: "事件屬性" }, repoPath: "spec", note: { en: "Detection fields carried on agent telemetry.", zh: "把偵測欄位帶進 agent 遙測資料。" } },
  { key: "listing", label: { en: "Directory listing", zh: "目錄收錄" }, repoPath: null, note: { en: "Listed as a tool or format; no code consumed.", zh: "被列為工具或格式，沒有使用程式碼。" } },
  { key: "unstated", label: { en: "Not stated in ADOPTERS.md", zh: "ADOPTERS.md 未說明" }, repoPath: null, note: { en: "The entry does not name the component it uses.", zh: "該筆沒有寫明使用哪個元件。" } },
];

export const LAYERS: Record<string, Bilingual> = {
  runtime: { en: "Runtime guardrail", zh: "執行期防護" },
  proxy: { en: "LLM proxy", zh: "LLM 代理" },
  scanner: { en: "Scanner", zh: "掃描器" },
  siem: { en: "SIEM / detection content", zh: "SIEM／偵測內容" },
  redteam: { en: "Red team and evaluation", zh: "紅隊與評測" },
  intel: { en: "Threat intelligence", zh: "威脅情資" },
  catalog: { en: "Control catalog", zh: "控制項目錄" },
  telemetry: { en: "Observability", zh: "可觀測性" },
  inventory: { en: "Component inventory", zh: "元件盤點" },
  directory: { en: "Directory", zh: "目錄" },
  other: { en: "Other", zh: "其他" },
};

export interface MatrixRow {
  name: string;
  org: string;
  tier: string;
  status: Adopter["status"];
  integration: string;
  evidence: string;
  component: string;
  layer: string;
}

function componentOf(a: Adopter): string {
  const t = a.integration;
  if (/pyatr/i.test(t)) return "engine-py";
  if (/dataset|payload loader/i.test(t)) return "dataset";
  if (/YARA-L|converter|importer|compiles ATR rule packs/i.test(t)) return "converted";
  if (/YARA rule/i.test(t)) return "converted";
  if (/semantic-convention|attributes/i.test(t)) return "telemetry";
  if (/taxonomy|galaxy/i.test(t)) return "taxonomy";
  if (/scenario/i.test(t)) return "scenarios";
  if (/mapping|crosswalk|mapped/i.test(t)) return "mapping";
  if (/rule pack|consumes ATR rules|detection rail|rule corpus|ruleset/i.test(t)) return "rules";
  if (/patterns|templates|detections contributed|ATR-derived/i.test(t)) return "patterns";
  if (/listed|listing|cross-listing|pattern accepted|lists/i.test(t)) return "listing";
  return "unstated";
}

function layerOf(a: Adopter): string {
  const t = `${a.name} ${a.integration}`;
  if (a.type === "sidecar-proxy" || /proxy/i.test(t)) return "proxy";
  if (/Splunk|SecOps|Chronicle|SIEM/i.test(t)) return "siem";
  if (/PyRIT|red-team|regression|evaluation|Promptfoo/i.test(t)) return "redteam";
  if (/guardrail|guard\b|validator|action-boundary|rail\b|Guardrails/i.test(t)) return "runtime";
  if (/scanner|scan/i.test(t)) return "scanner";
  if (/MISP|taxonom|galaxy|rulezet/i.test(t)) return "intel";
  if (/OpenTelemetry|semantic-convention/i.test(t)) return "telemetry";
  if (/\bBOM\b|enrichment|inventory/i.test(t)) return "inventory";
  if (/mapping|crosswalk|catalog|controls/i.test(t)) return "catalog";
  if (/listed|awesome|directory/i.test(t)) return "directory";
  return "other";
}

export function loadMatrix(): MatrixRow[] {
  const a = loadAdopters();
  return [...a.tierS, ...a.tier1, ...a.tier2, ...a.tier3, ...a.tier4]
    .filter((x) => x.status !== "planning")
    .map((x) => ({
      name: x.name,
      org: x.org,
      tier: x.tier,
      status: x.status,
      integration: x.integration,
      evidence: x.evidence,
      component: componentOf(x),
      layer: layerOf(x),
    }));
}
