/**
 * Community ledger: validate community/ledger.jsonl and compute tiers from it.
 *
 *   npx tsx scripts/community/ledger.ts validate   # exit 1 on any invalid line
 *   npx tsx scripts/community/ledger.ts compute    # JSON: tiers per person
 *
 * Tiers come only from public events (community/ledger.schema.json) and the
 * rules in community/tiers.yaml. Automatic grants stop at "nominate"; advisor
 * and TSC seats are never computed. Importing this file does not run the CLI.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import yaml from "js-yaml";

export const CODES = ["E1", "E2", "E3", "E4", "E5", "E6", "E7", "E8", "E9"] as const;
export const AREAS = ["rules", "eval", "atomics", "mappings", "nodes", "community", "governance"] as const;

export type Code = (typeof CODES)[number];
export type Area = (typeof AREAS)[number];

export interface LedgerEvent {
  readonly id: string;
  readonly code: Code;
  readonly actor: string;
  readonly date: string;
  readonly evidence: string;
  readonly verified_by: string;
  readonly area: Area;
  readonly subject?: string;
  readonly note?: string;
}

export interface Condition {
  readonly code: Code;
  readonly min: number;
  readonly within_days?: number;
  readonly distinct_subjects?: number;
  readonly verified_by?: string;
}

export interface TierRule {
  readonly id: string;
  readonly grant: "auto" | "nominate" | "invite" | "charter";
  readonly any_of?: readonly Condition[];
  readonly all_of?: readonly Condition[];
}

export interface TierConfig {
  readonly version: number;
  readonly working_on_window_days: number;
  readonly tiers: readonly TierRule[];
}

export interface MemberStatus {
  readonly actor: string;
  readonly granted: readonly string[];
  readonly nominated: readonly string[];
  readonly working_on: readonly Area[];
  readonly last_activity: string;
  readonly counts: Readonly<Partial<Record<Code, number>>>;
}

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{2,120}$/;
const ACTOR = /^(gh:[a-z0-9](?:[a-z0-9-]{0,38})|orcid:\d{4}-\d{4}-\d{4}-\d{3}[\dX]|org:[a-z0-9][a-z0-9-]{1,60})$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const VERIFIER = /^(ci|maintainer:gh:[a-z0-9](?:[a-z0-9-]{0,38}))$/;
const ALLOWED = new Set(["id", "code", "actor", "date", "evidence", "verified_by", "area", "subject", "note"]);

/** Problems with one event, empty when it is valid. Mirrors ledger.schema.json. */
export function eventProblems(e: Record<string, unknown>): string[] {
  const problems: string[] = [];
  const str = (k: string) => (typeof e[k] === "string" ? (e[k] as string) : "");
  for (const key of Object.keys(e)) if (!ALLOWED.has(key)) problems.push(`unknown field ${key}`);
  if (!ID.test(str("id"))) problems.push("id is missing or malformed");
  if (!(CODES as readonly string[]).includes(str("code"))) problems.push(`unknown code ${String(e.code)}`);
  if (!ACTOR.test(str("actor"))) problems.push("actor must be gh:<login>, orcid:<id> or org:<slug>");
  if (!DATE.test(str("date")) || Number.isNaN(Date.parse(str("date")))) problems.push("date must be YYYY-MM-DD");
  if (!str("evidence").startsWith("https://")) problems.push("evidence must be an https link");
  if (!VERIFIER.test(str("verified_by"))) problems.push("verified_by must be ci or maintainer:gh:<login>");
  if (str("verified_by") === `maintainer:${str("actor")}`) problems.push("nobody verifies their own event");
  if (!(AREAS as readonly string[]).includes(str("area"))) problems.push(`unknown area ${String(e.area)}`);
  if (e.code === "E7" && !str("actor").startsWith("org:")) problems.push("E7 (adoption) belongs to an org: actor");
  return problems;
}

/** Parse ledger.jsonl text. Blank lines are allowed; ids must be unique. */
export function parseLedger(text: string): { events: LedgerEvent[]; errors: string[] } {
  const events: LedgerEvent[] = [];
  const errors: string[] = [];
  const seen = new Set<string>();
  text.split("\n").forEach((line, i) => {
    if (!line.trim()) return;
    let raw: Record<string, unknown>;
    try {
      raw = JSON.parse(line);
    } catch {
      errors.push(`line ${i + 1}: not valid JSON`);
      return;
    }
    const problems = eventProblems(raw);
    if (typeof raw.id === "string" && seen.has(raw.id)) problems.push(`duplicate id ${raw.id}`);
    if (problems.length) {
      errors.push(...problems.map((p) => `line ${i + 1}: ${p}`));
      return;
    }
    seen.add(raw.id as string);
    events.push(raw as unknown as LedgerEvent);
  });
  return { events, errors };
}

export function parseTiers(text: string): TierConfig {
  return yaml.load(text) as TierConfig;
}

function daysBefore(today: string, days: number): string {
  const d = new Date(`${today}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() - days);
  return d.toISOString().slice(0, 10);
}

export function meets(events: readonly LedgerEvent[], c: Condition, today: string): boolean {
  const since = c.within_days === undefined ? "" : daysBefore(today, c.within_days);
  const hits = events.filter(
    (e) =>
      e.code === c.code &&
      e.date >= since &&
      e.date <= today &&
      (c.verified_by === undefined || e.verified_by === c.verified_by),
  );
  if (hits.length < c.min) return false;
  if (c.distinct_subjects === undefined) return true;
  return new Set(hits.map((e) => e.subject ?? e.id)).size >= c.distinct_subjects;
}

export function qualifies(events: readonly LedgerEvent[], rule: TierRule, today: string): boolean {
  if (rule.grant === "invite" || rule.grant === "charter") return false;
  const all = rule.all_of ?? [];
  const any = rule.any_of ?? [];
  if (all.length === 0 && any.length === 0) return false;
  return all.every((c) => meets(events, c, today)) && (any.length === 0 || any.some((c) => meets(events, c, today)));
}

function statusFor(actor: string, mine: readonly LedgerEvent[], config: TierConfig, today: string): MemberStatus {
  const qualified = config.tiers.filter((t) => qualifies(mine, t, today));
  const recentSince = daysBefore(today, config.working_on_window_days);
  const working = AREAS.filter((a) => mine.some((e) => e.area === a && e.date >= recentSince && e.date <= today));
  const counts = Object.fromEntries(CODES.map((c) => [c, mine.filter((e) => e.code === c).length]).filter(([, n]) => n));
  return {
    actor,
    granted: qualified.filter((t) => t.grant === "auto").map((t) => t.id),
    nominated: qualified.filter((t) => t.grant === "nominate").map((t) => t.id),
    working_on: working,
    last_activity: mine.map((e) => e.date).sort().at(-1) ?? "",
    counts,
  };
}

/** Tier status for every person in the ledger, sorted by actor. Pure. */
export function computeMembers(events: readonly LedgerEvent[], config: TierConfig, today: string): MemberStatus[] {
  const actors = [...new Set(events.map((e) => e.actor))].sort();
  return actors.map((a) => statusFor(a, events.filter((e) => e.actor === a), config, today));
}

function main(argv: string[]): number {
  const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
  const { events, errors } = parseLedger(readFileSync(resolve(root, "community/ledger.jsonl"), "utf8"));
  if (argv[0] === "validate") {
    errors.forEach((e) => console.error(e));
    console.log(`${events.length} valid event(s), ${errors.length} problem(s)`);
    return errors.length ? 1 : 0;
  }
  if (argv[0] === "compute") {
    if (errors.length) {
      errors.forEach((e) => console.error(e));
      return 1;
    }
    const config = parseTiers(readFileSync(resolve(root, "community/tiers.yaml"), "utf8"));
    const today = argv[1] ?? new Date().toISOString().slice(0, 10);
    console.log(JSON.stringify(computeMembers(events, config, today), null, 2));
    return 0;
  }
  console.error("usage: ledger.ts validate | compute [YYYY-MM-DD]");
  return 2;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
