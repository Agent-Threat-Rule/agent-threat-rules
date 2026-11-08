import { loadAllRules, ruleLastModified, type RuleSummary } from "./rules";
import { countLanes, normalizeMaturity, rulesLanes, type Lane, type LaneCounts } from "./lanes";
import { loadVersionLabels, type VersionLabels } from "./versions";
import { SITE_URL } from "./seo";

/**
 * Machine-readable rule index: /rules/index.json, /rules/index.csv and the
 * counts in /llms.txt all come from here, and from the same rule loader the
 * /rules page uses, so the downloads cannot drift from the page.
 */

const REPO = "Agent-Threat-Rule/agent-threat-rules";
const SOURCE_BASE = `https://github.com/${REPO}/blob/main`;
const RAW_BASE = `https://raw.githubusercontent.com/${REPO}/main`;

export interface RuleIndexEntry {
  id: string;
  title: string;
  category: string;
  subcategory: string | null;
  severity: string;
  status: string | null;
  maturity: string;
  lanes: Lane[];
  scan_target: string | null;
  cves: string[];
  owasp_agentic: string[];
  owasp_llm: string[];
  mitre_atlas: string[];
  /** YAML `date`: when the rule was written. */
  date: string | null;
  /** Last commit touching the YAML, when git history was available at build time. */
  last_modified: string | null;
  page_url: string;
  source_url: string;
  raw_url: string;
}

export interface RuleIndex {
  generated_at: string;
  versions: {
    spec: string;
    npm: string;
    npm_verified: boolean;
    package_json: string;
  };
  counts: LaneCounts;
  calibers: Record<string, string>;
  rules: RuleIndexEntry[];
}

function toEntry(rule: RuleSummary): RuleIndexEntry {
  const path = rule.filePath.split("\\").join("/");
  return {
    id: rule.id,
    title: rule.title,
    category: rule.category,
    subcategory: rule.subcategory ?? null,
    severity: rule.severity,
    status: rule.status ?? null,
    maturity: normalizeMaturity(rule.maturity),
    lanes: rulesLanes(rule),
    scan_target: rule.scanTarget ?? null,
    cves: rule.cves,
    owasp_agentic: rule.owaspAgentic,
    owasp_llm: rule.owaspLlm,
    mitre_atlas: rule.mitreAtlas,
    date: rule.date || null,
    last_modified: ruleLastModified(rule.id) ?? null,
    page_url: `${SITE_URL}/en/rules/${rule.id}`,
    source_url: `${SOURCE_BASE}/${path}`,
    raw_url: `${RAW_BASE}/${path}`,
  };
}

export const CALIBERS: Readonly<Record<string, string>> = {
  files: "Rule YAML files under rules/ on the built commit.",
  effective: "Files the reference engine loads in at least one lane.",
  inert: "Files no lane loads: status draft or deprecated.",
  "byLane.enforce": "Rules with maturity stable (the lane to run with blocking on).",
  "byLane.alert": "Rules with maturity stable or test.",
  "byLane.hunt": "Every effective rule (the engine default).",
};

export async function buildRuleIndex(): Promise<RuleIndex> {
  const rules = loadAllRules();
  const versions: VersionLabels = await loadVersionLabels();
  return {
    generated_at: new Date().toISOString(),
    versions: {
      spec: versions.spec.version,
      npm: versions.npm,
      npm_verified: versions.npmVerified,
      package_json: versions.packageVersion,
    },
    counts: countLanes(rules),
    calibers: CALIBERS,
    rules: rules.map(toEntry),
  };
}

const CSV_COLUMNS: ReadonlyArray<keyof RuleIndexEntry> = [
  "id", "title", "category", "subcategory", "severity", "status", "maturity", "lanes",
  "scan_target", "cves", "owasp_agentic", "owasp_llm", "mitre_atlas", "date", "last_modified",
  "page_url", "raw_url",
];

/** RFC 4180 field; a leading = + - @ is prefixed with ' so spreadsheets do not run it as a formula. */
function csvField(value: unknown): string {
  const text = Array.isArray(value) ? value.join(";") : value == null ? "" : String(value);
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

/** First line is a # comment with the versions and generation time (read with comment="#"), then header and rows. */
export function ruleIndexToCsv(index: RuleIndex): string {
  const { versions, counts } = index;
  const comment =
    `# ATR rule index; generated ${index.generated_at}; spec ${versions.spec}; ` +
    `${versions.npm_verified ? "npm" : "package.json"} ${versions.npm}; ` +
    `${counts.files} rule files, ${counts.effective} effective, ${counts.inert} inert`;
  const rows = index.rules.map((r) => CSV_COLUMNS.map((c) => csvField(r[c])).join(","));
  return [comment, CSV_COLUMNS.join(","), ...rows].join("\r\n") + "\r\n";
}
