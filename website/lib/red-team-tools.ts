/**
 * The /red-team page's list of offensive tools and corpora, read from
 * data/red-team-tools.json.
 *
 * Every status here is a claim about someone else's repository, and the list
 * used to be written by hand inside the page: NVIDIA/garak#1676 stayed listed
 * as under review for ten weeks after it was withdrawn. scripts/verify-red-team-links.mjs
 * now re-checks every link against GitHub in CI (in-review must be open,
 * in-production must be a merged PR, corpus a merged PR or a commit on the
 * default branch, and the stillPresent file of an in-production or corpus
 * entry must still hold its text). Edit the JSON, not the page.
 */
import raw from "@/data/red-team-tools.json";

export const RED_TEAM_STATUSES = ["in-production", "in-review", "corpus"] as const;
export type RedTeamStatus = (typeof RED_TEAM_STATUSES)[number];

export interface RedTeamTool {
  readonly name: string;
  readonly org: string;
  readonly status: RedTeamStatus;
  readonly homepage: string;
  /** The PR or issue behind the status; for a corpus entry it may be a commit URL instead. */
  readonly prUrl?: string;
  /** `<path> contains "<text>"` on the linked repo's default branch; required and checked in CI for in-production and corpus entries. */
  readonly stillPresent?: string;
  readonly hook: string;
  readonly what_atr_did: string;
  /** Measurements quoted after what_atr_did, read from data/measurements/ with their lanes. */
  readonly figures?: readonly { readonly source: string; readonly label: string }[];
}

function isStatus(value: string): value is RedTeamStatus {
  return (RED_TEAM_STATUSES as readonly string[]).includes(value);
}

function toTool(entry: (typeof raw)[number]): RedTeamTool {
  if (!isStatus(entry.status)) {
    throw new Error(`data/red-team-tools.json: "${entry.name}" has unknown status "${entry.status}"`);
  }
  return { ...entry, status: entry.status };
}

export const RED_TEAM_TOOLS: readonly RedTeamTool[] = raw.map(toTool);
