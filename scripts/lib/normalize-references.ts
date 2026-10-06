/**
 * OWASP reference normalisation for machine-authored rules.
 *
 * WHY THIS EXISTS
 *   Cluster proposals carry `references.owasp_llm` / `owasp_agentic` as
 *   "ID - Title" strings, and the semantic lane used to copy them verbatim.
 *   Rolling PR #632 then failed validate:compliance on the embedded titles,
 *   and one proposal paired "LLM06:2025" with the title that number carried in
 *   the 2023 list ("Sensitive Information Disclosure"); in 2025 LLM06 is
 *   Excessive Agency, and Sensitive Information Disclosure is LLM02. Stripping
 *   the title alone would have kept the wrong mapping.
 *
 * THE RULE
 *   data/compliance-frameworks/owasp_llm.json and owasp_agentic.json are the
 *   only source of identifiers and titles. For each entry:
 *     - id = entry.split(" - ")[0]
 *     - no title: keep the id if the allowlist has it, else drop it
 *     - title agrees with the allowlist title for id: keep the id
 *     - title disagrees (or id unknown): resolve the id FROM the title; the
 *       title is the author's intent, the number is what drifted. No allowlist
 *       risk carries that title -> drop the entry.
 *   Output is bare ids, de-duplicated, first-seen order. An empty result falls
 *   back to the category default below, so audit:mappings --require-full never
 *   sees a rule without both OWASP blocks.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ATRCategory } from "../../src/types.js";

export interface OwaspAllowlist {
  readonly framework: string;
  /** id -> title, verbatim from the allowlist file. */
  readonly valids: Readonly<Record<string, string>>;
}

export interface OwaspAllowlists {
  readonly owasp_llm: OwaspAllowlist;
  readonly owasp_agentic: OwaspAllowlist;
}

export interface ReferenceInput {
  readonly category: ATRCategory;
  readonly owaspLlm?: readonly string[];
  readonly owaspAgentic?: readonly string[];
}

export interface NormalizedOwaspReferences {
  readonly owasp_llm: string[];
  readonly owasp_agentic: string[];
}

/*
 * Category defaults, used only when nothing valid survives normalisation.
 *
 * Chosen by counting, not by judgment: for each category, the identifier
 * carried by the most rules already on disk (rules/<category>/, every
 * references.owasp_* entry, counted 2026-10-06 over 825 rules, cross-checked
 * with `git grep -l '<ID>' -- rules/<category>/`). Counts in parentheses are
 * rules carrying that id / rules in the category.
 *
 *   owasp_agentic                                 owasp_llm
 *   prompt-injection      ASI01 (243/246)         LLM01 (245/246)
 *   agent-manipulation    ASI01 (91/108)          LLM01 (98/108)
 *   context-exfiltration  ASI01 (75/133)          LLM02 (97/133)
 *   data-poisoning        ASI06 (4/10)            LLM01 (9/10)
 *   excessive-autonomy    ASI03 (19/40)           LLM01 (21/40; LLM06 20)
 *   model-abuse           ASI01 (35/43)           LLM01 (27/43; LLM02 27)
 *   privilege-escalation  ASI03 (34/78)           LLM06 (35/78)
 *   skill-compromise      ASI04 (18/48)           LLM01 (17/48)
 *   tool-poisoning        ASI05 (47/118)          LLM06 (70/118)
 *
 * Ties go to the identifier that was also most often listed FIRST. Every
 * default is an automatic template value; _semantic_authored says so, and a
 * human reviews mappings before a rule is promoted to stable.
 */
export const DEFAULT_OWASP_AGENTIC_BY_CATEGORY: Readonly<Record<ATRCategory, string>> = Object.freeze({
  "prompt-injection": "ASI01:2026",
  "agent-manipulation": "ASI01:2026",
  "context-exfiltration": "ASI01:2026",
  "data-poisoning": "ASI06:2026",
  "excessive-autonomy": "ASI03:2026",
  "model-abuse": "ASI01:2026",
  "privilege-escalation": "ASI03:2026",
  "skill-compromise": "ASI04:2026",
  "tool-poisoning": "ASI05:2026",
});

export const DEFAULT_OWASP_LLM_BY_CATEGORY: Readonly<Record<ATRCategory, string>> = Object.freeze({
  "prompt-injection": "LLM01:2025",
  "agent-manipulation": "LLM01:2025",
  "context-exfiltration": "LLM02:2025",
  "data-poisoning": "LLM01:2025",
  "excessive-autonomy": "LLM01:2025",
  "model-abuse": "LLM01:2025",
  "privilege-escalation": "LLM06:2025",
  "skill-compromise": "LLM01:2025",
  "tool-poisoning": "LLM06:2025",
});

function readAllowlist(repoRoot: string, name: string): OwaspAllowlist {
  const path = join(repoRoot, "data", "compliance-frameworks", `${name}.json`);
  const raw = JSON.parse(readFileSync(path, "utf-8")) as Partial<OwaspAllowlist>;
  if (!raw.valids || typeof raw.valids !== "object") {
    throw new Error(`${path} has no 'valids' map; cannot normalise ${name} references`);
  }
  return { framework: String(raw.framework ?? name), valids: { ...raw.valids } };
}

export function loadOwaspAllowlists(repoRoot: string): OwaspAllowlists {
  return {
    owasp_llm: readAllowlist(repoRoot, "owasp_llm"),
    owasp_agentic: readAllowlist(repoRoot, "owasp_agentic"),
  };
}

/** Case, spacing, punctuation and '&'/'and' do not distinguish two risk titles. */
function canonicalTitle(title: string): string {
  return title
    .toLowerCase()
    .replace(/&/g, " and ")
    .replace(/[^a-z0-9]+/g, " ")
    .trim();
}

function idForTitle(title: string, allow: OwaspAllowlist): string | null {
  const want = canonicalTitle(title);
  if (want === "") return null;
  const hit = Object.entries(allow.valids).find(([, t]) => canonicalTitle(t) === want);
  return hit ? hit[0] : null;
}

/** Resolve one "ID" or "ID - Title" entry to an allowlisted id, or null. */
function resolveEntry(entry: unknown, allow: OwaspAllowlist): string | null {
  if (typeof entry !== "string") return null;
  const [head, ...rest] = entry.split(" - ");
  const id = (head ?? "").trim();
  const title = rest.join(" - ").trim();
  const known = Object.prototype.hasOwnProperty.call(allow.valids, id);
  if (title === "") return known ? id : null;
  if (known && canonicalTitle(allow.valids[id]!) === canonicalTitle(title)) return id;
  return idForTitle(title, allow);
}

/** Bare, allowlisted, de-duplicated ids in first-seen order. Never mutates input. */
export function normalizeFrameworkRefs(entries: readonly unknown[], allow: OwaspAllowlist): string[] {
  const resolved = entries
    .map((e) => resolveEntry(e, allow))
    .filter((id): id is string => id !== null);
  return [...new Set(resolved)];
}

export function normalizeReferences(
  input: ReferenceInput,
  allowlists: OwaspAllowlists,
): NormalizedOwaspReferences {
  const llm = normalizeFrameworkRefs(input.owaspLlm ?? [], allowlists.owasp_llm);
  const agentic = normalizeFrameworkRefs(input.owaspAgentic ?? [], allowlists.owasp_agentic);
  return {
    owasp_llm: llm.length > 0 ? llm : [DEFAULT_OWASP_LLM_BY_CATEGORY[input.category]],
    owasp_agentic: agentic.length > 0 ? agentic : [DEFAULT_OWASP_AGENTIC_BY_CATEGORY[input.category]],
  };
}
