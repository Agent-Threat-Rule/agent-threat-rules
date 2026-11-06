import { readFileSync, readdirSync, statSync } from "node:fs";
import { execSync } from "node:child_process";
import { join, extname, relative, basename, dirname, sep } from "node:path";
import yaml from "js-yaml";

/**
 * Display-layer category aliases. Merges thin categories into parent groups
 * without modifying the canonical rule YAML on disk.
 *
 * Empty: the 10 on-disk categories are now all substantial (model-abuse has 37
 * rules, data-poisoning 5) and are shown 1:1 with data/stats.json byCategory.
 * The old model-abuse+data-poisoning → "model-level-attacks" merge dated from
 * when those categories held 1 and 2 rules; it now hid 42 rules and displayed
 * both as 0, so it was removed.
 */
const CATEGORY_ALIASES: Record<string, string> = {};

function aliasCategory(category: string): string {
  return CATEGORY_ALIASES[category] ?? category;
}

export { categoryDisplayName } from "./categories";

export interface RuleSummary {
  id: string;
  title: string;
  severity: string;
  category: string;
  subcategory?: string;
  description: string;
  scanTarget?: string;
  cves: string[];
  owaspAgentic: string[];
  owaspLlm: string[];
  mitreAtlas: string[];
  author: string;
  date: string;
  filePath: string;
  status?: string;
  /** YAML `maturity`; decides which lanes load the rule (lib/lanes.ts). */
  maturity?: string;
  responseActions?: string[];
  detectionTier?: string;
  confidence?: string;
}

interface RawRule {
  id?: string;
  title?: string;
  severity?: string;
  description?: string;
  author?: string;
  date?: string;
  status?: string;
  maturity?: string;
  detection_tier?: string;
  tags?: {
    category?: string;
    subcategory?: string;
    scan_target?: string;
    confidence?: string;
  };
  references?: {
    cve?: string[];
    owasp_agentic?: string[];
    owasp_llm?: string[];
    mitre_atlas?: string[];
  };
  response?: {
    actions?: string[];
  };
}

function loadRulesRecursive(dir: string, rootDir: string): RuleSummary[] {
  const results: RuleSummary[] = [];
  const entries = readdirSync(dir);

  for (const entry of entries) {
    const fullPath = join(dir, entry);
    const stat = statSync(fullPath);

    if (stat.isDirectory()) {
      results.push(...loadRulesRecursive(fullPath, rootDir));
    } else if (stat.isFile() && (extname(entry) === ".yaml" || extname(entry) === ".yml")) {
      try {
        const content = readFileSync(fullPath, "utf-8");
        const raw = yaml.load(content, { schema: yaml.CORE_SCHEMA }) as RawRule;

        if (!raw?.id || !raw?.title) continue;

        results.push({
          id: raw.id,
          title: raw.title,
          severity: raw.severity ?? "medium",
          // Category is canonical = the directory the rule lives in (matches
          // data/stats.json byCategory). tags.category drifts on some rules and
          // must not drive the public per-category counts.
          category: aliasCategory(basename(dir)),
          subcategory: raw.tags?.subcategory,
          description: raw.description ?? "",
          scanTarget: raw.tags?.scan_target,
          cves: raw.references?.cve ?? [],
          owaspAgentic: raw.references?.owasp_agentic ?? [],
          owaspLlm: raw.references?.owasp_llm ?? [],
          mitreAtlas: raw.references?.mitre_atlas ?? [],
          author: raw.author ?? "ATR Community",
          date: raw.date ?? "",
          filePath: relative(rootDir, fullPath),
          status: raw.status,
          maturity: typeof raw.maturity === "string" ? raw.maturity : undefined,
          responseActions: raw.response?.actions,
          detectionTier: raw.detection_tier,
          confidence: raw.tags?.confidence,
        });
      } catch {
        // Skip malformed files
      }
    }
  }

  return results;
}

// Every page (and the layout, footer and metadata of every page) asks for the
// rule set; parsing 844 YAML files each time ran static generation past the
// 60 s page timeout. The parsed set is cached per build worker and frozen, so
// a caller that tried to sort or splice it in place would throw instead of
// corrupting every later page. Development reloads it each time so YAML edits
// show up without a restart.
let allRulesCache: RuleSummary[] | null = null;

export function loadAllRules(): RuleSummary[] {
  if (allRulesCache && process.env.NODE_ENV === "production") return allRulesCache;
  const rulesDir = join(process.cwd(), "..", "rules");
  const rules = loadRulesRecursive(rulesDir, join(process.cwd(), ".."));
  allRulesCache = Object.freeze(rules.sort((a, b) => a.id.localeCompare(b.id))) as RuleSummary[];
  return allRulesCache;
}

export function findRuleById(rules: RuleSummary[], id: string): RuleSummary | undefined {
  return rules.find((r) => r.id === id);
}

export function getRelatedRules(rules: RuleSummary[], rule: RuleSummary, limit = 5): RuleSummary[] {
  return rules
    .filter((r) => r.id !== rule.id && r.category === rule.category)
    .slice(0, limit);
}

export function getCategories(rules: RuleSummary[]): { name: string; count: number }[] {
  const map = new Map<string, number>();
  for (const r of rules) {
    map.set(r.category, (map.get(r.category) ?? 0) + 1);
  }
  return Array.from(map.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count);
}

export interface DetectionCondition {
  field?: string;
  operator?: string;
  description?: string;
  value?: string;
}

export interface TestCase {
  input: string;
  expected?: string;
  description?: string;
  matched_condition?: string;
}

export interface EvasionTest {
  input: string;
  expected?: string;
  bypass_technique?: string;
  notes?: string;
}

/**
 * Event fields a test case may carry instead of `input` (a tool call, a tool
 * result, an agent reply...), in the order a reader meets them in a session.
 */
const EVENT_FIELDS = ["user_input", "content", "agent_output", "tool_name", "tool_description", "tool_args", "tool_call", "tool_response"] as const;

function asText(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return yaml.dump(value, { lineWidth: 100 }).trimEnd();
  } catch {
    return String(value);
  }
}

/** A test case with no `input`: show its event fields, each under its name. */
function eventText(tc: Record<string, unknown>): string {
  return EVENT_FIELDS.filter((k) => tc[k] !== undefined && tc[k] !== null)
    .map((k) => `${k}:\n${asText(tc[k])}`)
    .join("\n\n");
}

function normalizeTestCase<T extends { input?: unknown }>(
  tc: T,
): Omit<T, "input"> & { input: string } {
  const { input, ...rest } = tc;
  if (typeof input === "string") {
    return { ...(rest as Omit<T, "input">), input };
  }
  if (input === undefined || input === null) {
    return { ...(rest as Omit<T, "input">), input: eventText(tc as Record<string, unknown>) };
  }
  try {
    return {
      ...(rest as Omit<T, "input">),
      input: yaml.dump(input, { lineWidth: 100 }).trimEnd(),
    };
  } catch {
    return { ...(rest as Omit<T, "input">), input: String(input) };
  }
}

export interface RuleDetail extends RuleSummary {
  rawYaml: string;
  detectionConditions: DetectionCondition[];
  detectionCombinator?: string;
  falsePositives: string[];
  truePositives: TestCase[];
  trueNegatives: TestCase[];
  evasionTests: EvasionTest[];
  wildValidated?: string;
  wildSamples?: number;
  wildFpRate?: number;
  messageTemplate?: string;
  lastModified?: string;
}

interface RawRuleDetail {
  id?: string;
  title?: string;
  severity?: string;
  description?: string;
  author?: string;
  date?: string;
  status?: string;
  maturity?: string;
  detection_tier?: string;
  tags?: {
    category?: string;
    subcategory?: string;
    scan_target?: string;
    confidence?: string;
  };
  references?: {
    cve?: string[];
    owasp_agentic?: string[];
    owasp_llm?: string[];
    mitre_atlas?: string[];
  };
  response?: {
    actions?: string[];
    message_template?: string;
  };
  detection?: {
    conditions?: DetectionCondition[];
    condition?: string;
    false_positives?: string[];
  };
  test_cases?: {
    true_positives?: Array<Record<string, unknown>>;
    true_negatives?: Array<Record<string, unknown>>;
  };
  evasion_tests?: Array<Record<string, unknown>>;
  wild_validated?: string;
  wild_samples?: number;
  wild_fp_rate?: number;
}

/**
 * Build-time caches, populated once per worker and reused across all rule
 * detail page renders. SSG otherwise walks the rules tree O(N) times for N
 * rules, and runs `git log` for every rule on every render.
 */
let rulePathCache: Map<string, string> | null = null;
let lastModifiedCache: Map<string, string> | null = null;

function getRulePathMap(): Map<string, string> {
  if (rulePathCache) return rulePathCache;
  const map = new Map<string, string>();
  const repoRoot = join(process.cwd(), "..");
  const rulesDir = join(repoRoot, "rules");

  function walk(dir: string): void {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) {
        walk(full);
      } else if (
        st.isFile() &&
        (extname(entry) === ".yaml" || extname(entry) === ".yml")
      ) {
        const match = entry.match(/^(ATR-\d{4}-\d{5})/);
        if (match) map.set(match[1], full);
      }
    }
  }

  try {
    walk(rulesDir);
  } catch {
    // Leave map empty; detail pages will fall back gracefully.
  }
  rulePathCache = map;
  return map;
}

/** Date (YYYY-MM-DD) of the last commit touching the rule's YAML, when git can say. */
export function ruleLastModified(id: string): string | undefined {
  return getLastModifiedMap().get(id);
}

function getLastModifiedMap(): Map<string, string> {
  if (lastModifiedCache) return lastModifiedCache;
  const repoRoot = join(process.cwd(), "..");
  const pathMap = getRulePathMap();

  // One `git log` over rules/, newest commit first: the first date seen for a
  // path is the date `git log -1 -- <path>` gives. One process instead of one
  // per rule; the per-rule calls took ~0.7 s each on a loaded machine, so the
  // first rule page in every build worker ran past Next's 60 s page timeout.
  const latestByPath = new Map<string, string>();
  try {
    const log = execSync("git log --format=%x00%cs --name-only -- rules", {
      cwd: repoRoot,
      encoding: "utf-8",
      maxBuffer: 256 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
    });
    for (const commit of log.split("\0")) {
      const [date, ...paths] = commit.split("\n").map((l) => l.trim());
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date ?? "")) continue;
      for (const path of paths) {
        if (path && !latestByPath.has(path)) latestByPath.set(path, date);
      }
    }
  } catch {
    // git unavailable or not a repository: rule pages show no last-modified date.
  }

  const map = new Map<string, string>();
  for (const [id, fullPath] of pathMap.entries()) {
    const date = latestByPath.get(relative(repoRoot, fullPath).split(sep).join("/"));
    if (date) map.set(id, date);
  }
  lastModifiedCache = map;
  return map;
}

export function loadRuleDetail(id: string): RuleDetail | undefined {
  const filePath = getRulePathMap().get(id);
  if (!filePath) return undefined;
  const rawYaml = readFileSync(filePath, "utf-8");
  let parsed: RawRuleDetail;
  try {
    parsed = yaml.load(rawYaml, { schema: yaml.CORE_SCHEMA }) as RawRuleDetail;
  } catch {
    return undefined;
  }
  if (!parsed?.id || !parsed?.title) return undefined;

  const repoRoot = join(process.cwd(), "..");
  const relFile = relative(repoRoot, filePath);

  return {
    id: parsed.id,
    title: parsed.title,
    severity: parsed.severity ?? "medium",
    category: aliasCategory(basename(dirname(filePath))),
    subcategory: parsed.tags?.subcategory,
    description: parsed.description ?? "",
    scanTarget: parsed.tags?.scan_target,
    cves: parsed.references?.cve ?? [],
    owaspAgentic: parsed.references?.owasp_agentic ?? [],
    owaspLlm: parsed.references?.owasp_llm ?? [],
    mitreAtlas: parsed.references?.mitre_atlas ?? [],
    author: parsed.author ?? "ATR Community",
    date: parsed.date ?? "",
    filePath: relFile,
    status: parsed.status,
    maturity: typeof parsed.maturity === "string" ? parsed.maturity : undefined,
    responseActions: parsed.response?.actions,
    detectionTier: parsed.detection_tier,
    confidence: parsed.tags?.confidence,
    rawYaml,
    detectionConditions: parsed.detection?.conditions ?? [],
    detectionCombinator: parsed.detection?.condition,
    falsePositives: ((parsed.detection?.false_positives ?? []) as unknown[]).map(
      (fp) =>
        typeof fp === "string"
          ? fp
          : fp && typeof fp === "object"
            ? Object.entries(fp as Record<string, unknown>)
                .map(([k, v]) => `${k}: ${v}`)
                .join("")
            : String(fp),
    ),
    truePositives: (parsed.test_cases?.true_positives ?? []).map((tc) =>
      normalizeTestCase(tc as { input?: unknown }),
    ) as TestCase[],
    trueNegatives: (parsed.test_cases?.true_negatives ?? []).map((tc) =>
      normalizeTestCase(tc as { input?: unknown }),
    ) as TestCase[],
    evasionTests: (parsed.evasion_tests ?? []).map((tc) =>
      normalizeTestCase(tc as { input?: unknown }),
    ) as EvasionTest[],
    wildValidated: parsed.wild_validated,
    wildSamples: parsed.wild_samples,
    wildFpRate: parsed.wild_fp_rate,
    messageTemplate: parsed.response?.message_template,
    lastModified: getLastModifiedMap().get(parsed.id),
  };
}
