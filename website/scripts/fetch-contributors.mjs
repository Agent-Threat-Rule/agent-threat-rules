#!/usr/bin/env node
// Reads the public contributor list of the ATR repository from the GitHub API
// once before the build and writes the public fields to
// .generated/github-contributors.json for the community page. Bots and the
// maintainers' secondary or tooling accounts are left out, so the count is
// people. Never fails the build: on any error it writes an empty list and the
// page says the list was not available.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const URL = "https://api.github.com/repos/Agent-Threat-Rule/agent-threat-rules/contributors?per_page=100";
const OUT = join(process.cwd(), ".generated", "github-contributors.json");
// Accounts that are not separate people: AI co-author identities and a
// maintainer's secondary account.
const NOT_PEOPLE = new Set(["claude", "attlab0527-lab"]);

async function contributors() {
  try {
    const res = await fetch(URL, {
      headers: { Accept: "application/vnd.github+json", "User-Agent": "atr-website-build" },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const rows = await res.json();
    if (!Array.isArray(rows)) throw new Error("unexpected response");
    return rows
      .filter((r) => r && r.type === "User" && typeof r.login === "string" && !NOT_PEOPLE.has(r.login) && !r.login.endsWith("[bot]"))
      .map((r) => ({
        login: r.login,
        avatar: typeof r.avatar_url === "string" ? r.avatar_url : null,
        profile: `https://github.com/${r.login}`,
        contributions: Number.isInteger(r.contributions) ? r.contributions : 0,
      }));
  } catch (err) {
    console.warn(`fetch-contributors: GitHub not read (${err.message}); the community page will say so`);
    return null;
  }
}

const list = await contributors();
mkdirSync(join(process.cwd(), ".generated"), { recursive: true });
writeFileSync(OUT, JSON.stringify({ fetched_at: new Date().toISOString(), contributors: list }, null, 2) + "\n");
console.log(`fetch-contributors: ${list === null ? "not available" : `${list.length} people`} -> .generated/github-contributors.json`);
