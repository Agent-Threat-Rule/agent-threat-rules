/**
 * Which cluster proposals already have a rule under rules/.
 *
 * The semantic lane used to dedupe on `_semantic_authored.source_cluster`
 * alone, which only rules this lane wrote carry. A cluster promoted another way
 * keeps its proposal id as the rule id instead:
 * proposals/hackaprompt-clusters/secret-key-reveal-demand.proposal.yaml declares
 * ATR-2026-00453 (maturity stable), so the cluster looked unauthored and the lane
 * wrote it again as ATR-2026-02863 (PR #719, closed as a duplicate). A proposal
 * is covered when a rule under rules/ declares the proposal's id, whatever that
 * rule's status, or names the proposal in _semantic_authored.source_cluster.
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import yaml from "js-yaml";
import { topLevelRuleId } from "./rule-ids.js";

export interface RuleRef {
  readonly id: string;
  /** Path relative to the repository root. */
  readonly file: string;
}

export interface ExistingRules {
  /** Rule id -> the first rule file declaring it. */
  readonly byId: ReadonlyMap<string, RuleRef>;
  /** Proposal path (repository-relative) -> the rule authored from it. */
  readonly bySourceCluster: ReadonlyMap<string, RuleRef>;
}

export interface ExistingRuleMatch extends RuleRef {
  readonly via: "proposal-id" | "source-cluster";
}

export interface RuleFileText {
  /** Path relative to the repository root. */
  readonly file: string;
  readonly text: string;
}

export const NO_EXISTING_RULES: ExistingRules = { byId: new Map(), bySourceCluster: new Map() };

function sourceClusterOf(doc: unknown): string | null {
  if (!doc || typeof doc !== "object") return null;
  const meta = (doc as { _semantic_authored?: unknown })._semantic_authored;
  if (!meta || typeof meta !== "object") return null;
  const src = (meta as { source_cluster?: unknown }).source_cluster;
  return typeof src === "string" && src.length > 0 ? src : null;
}

/**
 * One rule file's id and source cluster. A file that does not parse still
 * counts by the top-level id it declares: skipping a cluster on a broken rule
 * is safe, authoring a duplicate of it is not.
 */
function readRuleFile({ file, text }: RuleFileText): { id: string | null; sourceCluster: string | null } {
  let doc: unknown;
  try {
    doc = yaml.load(text);
  } catch {
    return { id: topLevelRuleId(text), sourceCluster: null };
  }
  const declared = doc && typeof doc === "object" ? (doc as { id?: unknown }).id : undefined;
  return {
    id: typeof declared === "string" && declared.length > 0 ? declared : topLevelRuleId(text),
    sourceCluster: sourceClusterOf(doc),
  };
}

export function indexExistingRules(files: readonly RuleFileText[]): ExistingRules {
  const byId = new Map<string, RuleRef>();
  const bySourceCluster = new Map<string, RuleRef>();
  for (const f of files) {
    const { id, sourceCluster } = readRuleFile(f);
    if (!id) continue;
    const ref: RuleRef = { id, file: f.file };
    if (!byId.has(id)) byId.set(id, ref);
    if (sourceCluster && !bySourceCluster.has(sourceCluster)) bySourceCluster.set(sourceCluster, ref);
  }
  return { byId, bySourceCluster };
}

function walkRuleFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) return walkRuleFiles(full);
    return entry.endsWith(".yaml") || entry.endsWith(".yml") ? [full] : [];
  });
}

/** Every rule under `repoRoot/dir`, any status. A repository without the directory has none. */
export function loadExistingRules(repoRoot: string, dir = "rules"): ExistingRules {
  const files = walkRuleFiles(join(repoRoot, dir)).map((full) => ({
    file: relative(repoRoot, full).split("\\").join("/"),
    text: readFileSync(full, "utf-8"),
  }));
  return indexExistingRules(files);
}

/** The rule that already covers this proposal, or null when it has none. */
export function existingRuleFor(
  proposalRel: string,
  proposalId: unknown,
  rules: ExistingRules,
): ExistingRuleMatch | null {
  const byId = typeof proposalId === "string" ? rules.byId.get(proposalId) : undefined;
  if (byId) return { ...byId, via: "proposal-id" };
  const bySource = rules.bySourceCluster.get(proposalRel);
  return bySource ? { ...bySource, via: "source-cluster" } : null;
}

export function describeExistingRule(m: ExistingRuleMatch): string {
  const how =
    m.via === "proposal-id"
      ? "declares the proposal's id"
      : "was authored from it (_semantic_authored.source_cluster)";
  return `already has a rule: ${m.id} (${m.file}) ${how}`;
}
