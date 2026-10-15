/**
 * The only way a version of agent-threat-rules reaches npm is the staged path
 * in .github/workflows/publish.yml: a v* tag runs it, it stages the version
 * with `npm stage publish` through trusted publishing (OIDC), and a maintainer
 * approves the stage with 2FA.
 *
 * The package is declared dual-use (tests/package-dual-use.test.ts). npm's
 * Dual-Use Content Policy (https://docs.npmjs.com/policies/dual-use/) does not
 * permit a direct publish from CI, by trusted publishing or by a 2FA-bypass
 * token, and every attempt goes through npm's automated review: a blocked one
 * uses up its version number. Three workflows once published around
 * publish.yml (publish-current-version.yml, publish-on-rules-merge.yml, and
 * npm-stage.yml, which approved stages from CI with NPM_TOKEN). These tests
 * fail if any workflow regains that ability.
 */
import { describe, it, expect } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import yaml from "js-yaml";

const ROOT = resolve(__dirname, "..");
const WORKFLOWS = join(ROOT, ".github", "workflows");
const RELEASE_WORKFLOW = "publish.yml";

type Step = { run?: string; uses?: string; env?: Record<string, unknown> };
type Job = { steps?: Step[]; uses?: string; env?: Record<string, unknown> };
type Workflow = { on?: unknown; env?: Record<string, unknown>; jobs?: Record<string, Job> };

const files = readdirSync(WORKFLOWS).filter((f) => /\.ya?ml$/.test(f));
const raw = (file: string) => readFileSync(join(WORKFLOWS, file), "utf8");
const parse = (file: string) => yaml.load(raw(file)) as Workflow;

/** Shell lines that run something: comment lines and echo'd prose dropped. */
function commandLines(doc: Workflow): string[] {
  return Object.values(doc.jobs ?? {})
    .flatMap((job) => job.steps ?? [])
    .flatMap((step) => (step.run ?? "").split("\n"))
    .map((line) => line.trim())
    .filter((line) => line !== "" && !line.startsWith("#") && !/^(echo|printf)\b/.test(line));
}

/** Every command segment of a line that invokes npm/pnpm/yarn with `publish`. */
const PUBLISH = /\b(?:npm|pnpm|yarn)\b[^|;&\n]*?\bpublish\b/;
const DIRECT_NPM_PUBLISH = /\bnpm\b(?![^|;&\n]*\bstage\b)[^|;&\n]*?\bpublish\b/;
const STAGE_DECISION = /\bnpm\b[^|;&\n]*\bstage\s+(?:approve|reject)\b/;
const NPM_TOKEN = /secrets\s*(?:\.\s*NPM_TOKEN\b|\[\s*['"]NPM_TOKEN['"]\s*\])/;

function envKeys(doc: Workflow): string[] {
  const jobs = Object.values(doc.jobs ?? {});
  return [
    doc.env,
    ...jobs.map((j) => j.env),
    ...jobs.flatMap((j) => j.steps ?? []).map((s) => s.env),
  ].flatMap((env) => Object.keys(env ?? {}));
}

describe("npm release path", () => {
  it("finds the workflows, including publish.yml", () => {
    expect(files).toContain(RELEASE_WORKFLOW);
    expect(files.length).toBeGreaterThan(5);
  });

  it("no workflow other than publish.yml publishes, stages, or decides a stage", () => {
    const offenders = files
      .filter((f) => f !== RELEASE_WORKFLOW)
      .flatMap((f) => {
        const doc = parse(f);
        const lines = commandLines(doc).filter((l) => PUBLISH.test(l) || STAGE_DECISION.test(l));
        const actions = Object.values(doc.jobs ?? {})
          .flatMap((j) => j.steps ?? [])
          .map((s) => s.uses ?? "")
          .filter((u) => /npm-publish/i.test(u));
        return [...lines, ...actions].map((l) => `${f}: ${l}`);
      });
    expect(offenders).toEqual([]);
  });

  it("no workflow reads NPM_TOKEN or hands npm an auth token", () => {
    const offenders = files.flatMap((f) => [
      ...(NPM_TOKEN.test(raw(f)) ? [`${f}: secrets.NPM_TOKEN`] : []),
      ...envKeys(parse(f))
        .filter((k) => k === "NODE_AUTH_TOKEN" || k === "NPM_TOKEN")
        .map((k) => `${f}: env ${k}`),
    ]);
    expect(offenders).toEqual([]);
  });

  it("no workflow calls publish.yml, and publish.yml cannot be called", () => {
    const callers = files.filter((f) => /uses:\s*\.\/\.github\/workflows\/publish\.ya?ml/.test(raw(f)));
    expect(callers).toEqual([]);
    const on = parse(RELEASE_WORKFLOW).on as Record<string, unknown>;
    expect(Object.keys(on).sort()).toEqual(["push", "workflow_dispatch"]);
  });

  it("publish.yml runs on v* tags, never on a branch push", () => {
    const push = (parse(RELEASE_WORKFLOW).on as { push: Record<string, unknown> }).push;
    expect(push.tags).toEqual(["v*"]);
    expect(push.branches).toBeUndefined();
    expect(push["branches-ignore"]).toBeUndefined();
  });

  it("publish.yml stages and never publishes directly", () => {
    const lines = commandLines(parse(RELEASE_WORKFLOW));
    expect(lines.some((l) => /\bnpm stage publish\b/.test(l))).toBe(true);
    expect(lines.filter((l) => DIRECT_NPM_PUBLISH.test(l) || STAGE_DECISION.test(l))).toEqual([]);
  });

  it("scripts/release.sh leaves publishing to publish.yml", () => {
    const lines = readFileSync(join(ROOT, "scripts", "release.sh"), "utf8")
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l !== "" && !l.startsWith("#") && !/^(echo|printf)\b/.test(l));
    expect(lines.filter((l) => PUBLISH.test(l) || STAGE_DECISION.test(l))).toEqual([]);
  });

  it("the matchers catch what they are meant to", () => {
    expect(PUBLISH.test("npm publish --access public")).toBe(true);
    expect(PUBLISH.test("npm --workspace x publish")).toBe(true);
    expect(PUBLISH.test("npm stage publish --access public")).toBe(true);
    expect(PUBLISH.test("yarn npm publish")).toBe(true);
    expect(PUBLISH.test("npm ci && npm run build")).toBe(false);
    expect(DIRECT_NPM_PUBLISH.test("npm publish --access public")).toBe(true);
    expect(DIRECT_NPM_PUBLISH.test('npm stage publish --access public --tag "$TAG"')).toBe(false);
    expect(STAGE_DECISION.test('npm stage approve "$PKG@1.0.0"')).toBe(true);
    expect(STAGE_DECISION.test("npm stage reject x")).toBe(true);
    expect(STAGE_DECISION.test("npm stage list x")).toBe(false);
    expect(NPM_TOKEN.test("NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}")).toBe(true);
    expect(NPM_TOKEN.test("${{ secrets['NPM_TOKEN'] }}")).toBe(true);
  });
});
