/**
 * Collect ledger events from GitHub, so the ledger fills itself instead of
 * waiting for someone to type entries in.
 *
 *   GITHUB_TOKEN=... npx tsx scripts/community/collect-events.ts           # print new events (JSONL)
 *   GITHUB_TOKEN=... npx tsx scripts/community/collect-events.ts --write   # append them to community/ledger.jsonl
 *
 * Today it records one kind of event: E1, a merged pull request, verified by
 * the person who merged it. A pull request merged by its own author is skipped
 * (nobody verifies their own work), and so are bot authors. Review comments
 * (E2) and the other event types still need a person to record them.
 *
 * The token is read from the environment only, never from an argument.
 * Importing this file does not run the CLI.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { eventProblems, parseLedger, type Area, type LedgerEvent } from "./ledger.js";

export const REPO = "Agent-Threat-Rule/agent-threat-rules";

export interface PullRequest {
  readonly number: number;
  readonly author: string;
  readonly author_type: string;
  readonly merged_by: string | null;
  readonly merged_at: string | null;
  readonly url: string;
  readonly title: string;
}

/** Which working group a set of changed paths belongs to; the most common area wins. */
const AREA_RULES: ReadonlyArray<readonly [RegExp, Area]> = [
  [/^(GOVERNANCE|TSC-CHARTER|TSC-ONBOARDING|TRADEMARK|CODE_OF_CONDUCT)\.md$|^docs\/(BDFL-charter|REVIEWER-GUIDE)\.md$|^governance\//, "governance"],
  [/^(community|website)\//, "community"],
  [/MAPPING|crosswalk|^data\/mappings\/|^mappings\//i, "mappings"],
  [/^sovereign\//, "nodes"],
  [/^(rules|src|engines|conformance|tests|scripts|spec|python)\/|^SPEC\.md$|^ATR-SPEC/, "rules"],
];

export function areaFor(paths: readonly string[]): Area {
  const tally = new Map<Area, number>();
  for (const path of paths) {
    const hit = AREA_RULES.find(([pattern]) => pattern.test(path));
    const area = hit ? hit[1] : "community";
    tally.set(area, (tally.get(area) ?? 0) + 1);
  }
  const ranked = [...tally.entries()].sort((a, b) => b[1] - a[1]);
  return ranked.length ? ranked[0][0] : "community";
}

const isBot = (login: string, type: string) => type === "Bot" || /\[bot\]$/.test(login);

/** One E1 event for a merged pull request, or the reason it is skipped. Pure. */
export function eventForPull(pr: PullRequest, paths: readonly string[]): LedgerEvent | { skip: string } {
  if (!pr.merged_at || !pr.merged_by) return { skip: "not merged" };
  if (isBot(pr.author, pr.author_type)) return { skip: "bot author" };
  const author = pr.author.toLowerCase();
  const merger = pr.merged_by.toLowerCase();
  if (author === merger) return { skip: "merged by its own author" };
  const event: LedgerEvent = {
    id: `E1-atr-pr-${pr.number}`,
    code: "E1",
    actor: `gh:${author}`,
    date: pr.merged_at.slice(0, 10),
    evidence: pr.url,
    verified_by: `maintainer:gh:${merger}`,
    area: areaFor(paths),
    subject: `pr-${pr.number}`,
  };
  const problems = eventProblems(event as unknown as Record<string, unknown>);
  return problems.length ? { skip: problems.join("; ") } : event;
}

/** Events not already in the ledger (by id), oldest first. Pure. */
export function newEvents(existing: readonly LedgerEvent[], candidates: readonly LedgerEvent[]): LedgerEvent[] {
  const known = new Set(existing.map((e) => e.id));
  return candidates.filter((e) => !known.has(e.id)).sort((a, b) => a.date.localeCompare(b.date) || a.id.localeCompare(b.id));
}

async function github<T>(path: string, token: string): Promise<T> {
  const res = await fetch(`https://api.github.com/${path}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/vnd.github+json", "User-Agent": "atr-community-ledger" },
  });
  if (!res.ok) throw new Error(`GitHub ${res.status} for ${path}`);
  return (await res.json()) as T;
}

interface SearchPage { items: Array<{ number: number }>; }
interface PullDetail {
  number: number; html_url: string; title: string; merged_at: string | null;
  user: { login: string; type: string }; merged_by: { login: string } | null;
}

async function mergedPullNumbers(token: string): Promise<number[]> {
  const numbers: number[] = [];
  for (let page = 1; page <= 10; page += 1) {
    const q = encodeURIComponent(`repo:${REPO} is:pr is:merged`);
    const res = await github<SearchPage>(`search/issues?q=${q}&per_page=100&page=${page}`, token);
    numbers.push(...res.items.map((i) => i.number));
    if (res.items.length < 100) break;
  }
  return numbers;
}

async function collect(token: string): Promise<{ events: LedgerEvent[]; skipped: Record<string, number> }> {
  const events: LedgerEvent[] = [];
  const skipped: Record<string, number> = {};
  for (const number of await mergedPullNumbers(token)) {
    const d = await github<PullDetail>(`repos/${REPO}/pulls/${number}`, token);
    const pr: PullRequest = {
      number, author: d.user.login, author_type: d.user.type, merged_by: d.merged_by?.login ?? null,
      merged_at: d.merged_at, url: d.html_url, title: d.title,
    };
    const quick = eventForPull(pr, []);
    if ("skip" in quick) {
      skipped[quick.skip] = (skipped[quick.skip] ?? 0) + 1;
      continue;
    }
    const files = await github<Array<{ filename: string }>>(`repos/${REPO}/pulls/${number}/files?per_page=100`, token);
    const result = eventForPull(pr, files.map((f) => f.filename));
    if ("skip" in result) skipped[result.skip] = (skipped[result.skip] ?? 0) + 1;
    else events.push(result);
  }
  return { events, skipped };
}

async function main(argv: string[]): Promise<number> {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;
  if (!token) {
    console.error("GITHUB_TOKEN (or GH_TOKEN) must be set in the environment");
    return 2;
  }
  const root = resolve(fileURLToPath(new URL("../..", import.meta.url)));
  const ledgerPath = resolve(root, "community/ledger.jsonl");
  const existing = parseLedger(readFileSync(ledgerPath, "utf8"));
  if (existing.errors.length) {
    existing.errors.forEach((e) => console.error(e));
    return 1;
  }
  const { events, skipped } = await collect(token);
  const fresh = newEvents(existing.events, events);
  console.error(`${fresh.length} new event(s); skipped: ${JSON.stringify(skipped)}`);
  const lines = fresh.map((e) => JSON.stringify(e)).join("\n");
  if (argv.includes("--write")) {
    const before = readFileSync(ledgerPath, "utf8");
    const joined = [before.trimEnd(), lines].filter(Boolean).join("\n");
    writeFileSync(ledgerPath, joined ? `${joined}\n` : "");
  } else if (lines) {
    console.log(lines);
  }
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => process.exit(code), (err) => {
    console.error(String(err));
    process.exit(1);
  });
}
