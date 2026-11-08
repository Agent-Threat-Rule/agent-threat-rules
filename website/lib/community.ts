import { readFileSync } from "node:fs";
import { join } from "node:path";
import yaml from "js-yaml";

/**
 * Community data: members who chose to be listed (community/members.yaml,
 * added by pull request with their consent) and the people GitHub records as
 * contributors (.generated/github-contributors.json, written before the build
 * by scripts/fetch-contributors.mjs). The page shows both, labelled apart.
 */

export const TIERS = ["steering", "expert", "contributor"] as const;
export type Tier = (typeof TIERS)[number];

export interface Member {
  name: string;
  github: string | null;
  tier: Tier;
  title: string;
  /** Traditional Chinese role line for /zh; null when none was given (the English title is shown). */
  titleZh: string | null;
  organization: string | null;
  country: string;
  expertise: string[];
  joined: string;
  founding: boolean;
  /** Absolute or site-relative URL of the portrait. */
  photo: string | null;
  disclosure: string | null;
}

export interface GithubContributor {
  login: string;
  avatar: string | null;
  profile: string;
  contributions: number;
}

const REPO_ROOT = join(process.cwd(), "..");
const MEMBERS_FILE = join(REPO_ROOT, "community", "members.yaml");
const CONTRIBUTORS_FILE = join(process.cwd(), ".generated", "github-contributors.json");

const str = (v: unknown): string | null => (typeof v === "string" && v.trim() !== "" ? v.trim() : null);
// Contact details never belong in the public file; refuse an entry carrying one.
const CONTACT = /@[\w-]+\.[\w.]+|linkedin\.com|\+?\d[\d\s-]{8,}\d/i;

function toMember(raw: unknown, index: number): Member | null {
  if (typeof raw !== "object" || raw === null) return null;
  const r = raw as Record<string, unknown>;
  const name = str(r.name);
  const title = str(r.title);
  const country = str(r.country);
  const joined = str(r.joined) ?? (typeof r.joined === "number" ? String(r.joined) : null);
  const tier = TIERS.find((t) => t === r.tier);
  if (r.consent !== true) {
    console.warn(`community/members.yaml entry ${index}: no consent: true, not rendered`);
    return null;
  }
  if (!name || !title || !country || !joined || !tier) {
    console.warn(`community/members.yaml entry ${index}: missing name, title, country, joined or tier, not rendered`);
    return null;
  }
  const titleZh = str(r.title_zh);
  const text = [name, title, titleZh ?? "", str(r.organization) ?? ""].join(" ");
  if (CONTACT.test(text)) {
    console.warn(`community/members.yaml entry ${index}: looks like it carries contact details, not rendered`);
    return null;
  }
  const github = str(r.github);
  const photo = str(r.photo);
  return {
    name,
    github,
    tier,
    title,
    titleZh,
    organization: str(r.organization),
    country: country.toUpperCase(),
    expertise: Array.isArray(r.expertise) ? r.expertise.filter((e): e is string => typeof e === "string") : [],
    joined,
    founding: r.founding === true,
    photo: photo ? `/community/${photo.replace(/^\/+/, "")}` : github ? `https://github.com/${github}.png?size=240` : null,
    disclosure: str(r.disclosure),
  };
}

export function loadMembers(): Member[] {
  try {
    const parsed = yaml.load(readFileSync(MEMBERS_FILE, "utf-8"), { schema: yaml.CORE_SCHEMA });
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map(toMember)
      .filter((m): m is Member => m !== null)
      .sort((a, b) => TIERS.indexOf(a.tier) - TIERS.indexOf(b.tier) || a.joined.localeCompare(b.joined));
  } catch (err) {
    console.warn("community/members.yaml could not be read:", err);
    return [];
  }
}

/** People GitHub lists as contributors; null when the list was not fetched before the build. */
export function loadGithubContributors(): GithubContributor[] | null {
  try {
    const raw = JSON.parse(readFileSync(CONTRIBUTORS_FILE, "utf-8")) as { contributors?: unknown };
    if (!Array.isArray(raw.contributors)) return null;
    return raw.contributors.filter(
      (c): c is GithubContributor =>
        typeof c === "object" && c !== null && typeof (c as GithubContributor).login === "string",
    );
  } catch {
    return null;
  }
}

export function tierCounts(members: ReadonlyArray<Member>): Record<Tier | "all", number> {
  return {
    all: members.length,
    steering: members.filter((m) => m.tier === "steering").length,
    expert: members.filter((m) => m.tier === "expert").length,
    contributor: members.filter((m) => m.tier === "contributor").length,
  };
}
