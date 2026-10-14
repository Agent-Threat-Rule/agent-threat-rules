/**
 * No workflow may update a pull request with `gh pr edit`.
 *
 * gh's edit command reads the PR's review requests. A bot PR that touches a path
 * CODEOWNERS gives to a team (stats.json -> @Agent-Threat-Rule/tsc) carries a
 * team review request, and the repository PAT cannot read teams, so the edit
 * fails — after the branch has already been pushed. measure-all.yml failed
 * exactly so on 2026-10-14 (run 38635654851): the measurements landed on the
 * rolling branch and the PR body was never rewritten. The REST endpoint
 * `PATCH repos/{owner}/{repo}/pulls/{n}` does not read review requests.
 *
 * demote-fp-rules.yml and atd-ingest.yml had the same call. They still worked
 * only because the paths they touch have no code owner, so this checks every
 * workflow rather than the one that broke.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const WORKFLOWS = resolve(__dirname, "..", ".github", "workflows");

describe("workflows", () => {
  it("never update a pull request with gh pr edit", () => {
    const offenders = readdirSync(WORKFLOWS)
      .filter((f) => /\.ya?ml$/.test(f))
      .flatMap((f) =>
        readFileSync(join(WORKFLOWS, f), "utf8")
          .split("\n")
          .map((line, i) => ({ at: `${f}:${i + 1}`, line }))
          .filter(({ line }) => /\bgh\s+pr\s+edit\b/.test(line) && !/^\s*#/.test(line)),
      )
      .map(({ at, line }) => `${at}: ${line.trim()}`);
    expect(offenders).toEqual([]);
  });
});
