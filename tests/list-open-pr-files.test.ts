/**
 * Tests for scripts/list-open-pr-files.sh, run with bash against a stub `gh`.
 *
 * `gh pr list --json files` returns at most 100 files per PR, sorted by path.
 * PR #525 changed 157 files; the 100 listed held no rules/ path, so the ten
 * rule ids it added would have looked free to any lane allocating ids then.
 */
import { describe, it, expect, afterEach } from "vitest";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const SCRIPT = resolve(__dirname, "..", "scripts", "list-open-pr-files.sh");
const HAS_JQ = spawnSync("jq", ["--version"]).status === 0;

// `pr list` prints FAKE_GH_LIST; `api repos/{owner}/{repo}/pulls/N/files` prints
// FAKE_GH_API_<N> (gh applies --jq itself, so the stub prints filenames).
const STUB_GH = `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FAKE_GH_LOG"
if [ -n "\${FAKE_GH_FAIL:-}" ] && [ "$1" = "$FAKE_GH_FAIL" ]; then echo "gh: HTTP 502" >&2; exit 1; fi
if [ "$1 $2" = "pr list" ]; then cat "$FAKE_GH_LIST"; exit 0; fi
if [ "$1" = api ]; then
  n=$(sed -E 's#.*/pulls/([0-9]+)/files#\\1#' <<<"$3")
  var="FAKE_GH_API_$n"; cat "\${!var}"; exit 0
fi
echo "stub gh: unexpected call: $*" >&2; exit 1
`;

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function run(prs: unknown[], apiFiles: Record<number, string[]> = {}, fail?: "pr" | "api") {
  const root = mkdtempSync(join(tmpdir(), "open-pr-files-"));
  dirs.push(root);
  const bin = join(root, "bin");
  mkdirSync(bin);
  writeFileSync(join(bin, "gh"), STUB_GH);
  chmodSync(join(bin, "gh"), 0o755);
  writeFileSync(join(root, "list.json"), JSON.stringify(prs));
  const env: Record<string, string> = {
    PATH: `${bin}:${process.env.PATH ?? ""}`,
    FAKE_GH_LOG: join(root, "gh.log"),
    FAKE_GH_LIST: join(root, "list.json"),
    ...(fail ? { FAKE_GH_FAIL: fail } : {}),
  };
  for (const [n, files] of Object.entries(apiFiles)) {
    writeFileSync(join(root, `api-${n}.txt`), files.map((f) => `${f}\n`).join(""));
    env[`FAKE_GH_API_${n}`] = join(root, `api-${n}.txt`);
  }
  writeFileSync(env.FAKE_GH_LOG, "");
  const out = join(root, "open-pr-files.txt");
  const r = spawnSync("bash", [SCRIPT, out], { env, encoding: "utf8" });
  return {
    status: r.status,
    stderr: r.stderr,
    lines: existsSync(out) ? readFileSync(out, "utf8").split("\n").filter(Boolean) : null,
    calls: readFileSync(env.FAKE_GH_LOG, "utf8"),
  };
}

const pr = (number: number, paths: string[], changedFiles = paths.length) => ({
  number,
  changedFiles,
  files: paths.map((path) => ({ path })),
});

describe.skipIf(!HAS_JQ)("list-open-pr-files.sh", () => {
  it("writes every path of every open PR whose file list is complete, without calling the REST API", () => {
    const r = run([pr(639, ["rules/a/ATR-2026-02847-x.yaml", "stats.json"]), pr(638, ["rules/a/ATR-2026-02846-y.yaml"])]);
    expect(r.status, r.stderr).toBe(0);
    expect(r.lines).toEqual(["rules/a/ATR-2026-02847-x.yaml", "stats.json", "rules/a/ATR-2026-02846-y.yaml"]);
    expect(r.calls).not.toContain("api");
  });

  it("reads a PR that lists fewer files than it changed in full from the REST API", () => {
    const first100 = Array.from({ length: 100 }, (_, i) => `.scratch/${String(i).padStart(3, "0")}.md`);
    const all = [...first100, "rules/a/ATR-2026-02601-z.yaml", "rules/a/ATR-2026-02602-z.yaml"];
    const r = run([pr(525, first100, all.length), pr(639, ["rules/a/ATR-2026-02847-x.yaml"])], { 525: all });
    expect(r.status, r.stderr).toBe(0);
    expect(r.lines).toContain("rules/a/ATR-2026-02601-z.yaml");
    expect(r.lines).toContain("rules/a/ATR-2026-02602-z.yaml");
    expect(r.lines).toContain("rules/a/ATR-2026-02847-x.yaml");
    expect(r.calls).toContain("api --paginate repos/{owner}/{repo}/pulls/525/files --jq .[].filename");
  });

  it("writes an empty file when no PR is open", () => {
    const r = run([]);
    expect(r.status, r.stderr).toBe(0);
    expect(r.lines).toEqual([]);
  });

  it.each(["pr", "api"] as const)("fails, leaving no file, when the %s call fails", (which) => {
    const first100 = Array.from({ length: 100 }, (_, i) => `f${i}`);
    const r = run([pr(525, first100, 101)], { 525: [...first100, "rules/x.yaml"] }, which);
    expect(r.status).not.toBe(0);
    expect(r.lines).toBeNull();
  });
});
