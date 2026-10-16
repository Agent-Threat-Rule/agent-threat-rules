/**
 * Tests for .github/workflows/publish-python.yml — one pyatr release, one
 * upload.
 *
 * A manual dispatch bumps the version, tags it and pushes the tag with
 * ATR_REPO_TOKEN, a personal token. Unlike GITHUB_TOKEN, a push with a
 * personal token starts workflows, so that tag push started a second run of
 * this same workflow on the tag. Both runs built and uploaded: for pyatr 0.3.1
 * on 2026-10-15 the tag run uploaded first (run 38803975403) and the dispatch
 * run failed on PyPI's 400 for a file that already exists (run 38803927766).
 *
 * Now the dispatch run only bumps, tags and pushes; the tag run is the one
 * that tests, bundles, builds, uploads and creates the GitHub release. If the
 * personal token is missing, the tag push starts nothing, so the dispatch run
 * fails and says so instead of reporting a release that never happened.
 */
import { describe, it, expect } from "vitest";
import { resolve } from "node:path";
import { jobSteps, runBlock, type Step } from "./workflow-step-harness.js";

const WORKFLOW = resolve(__dirname, "..", ".github", "workflows", "publish-python.yml");
const JOB = "publish";
const ON_TAG = "${{ github.event_name == 'push' }}";
const ON_DISPATCH = "${{ github.event_name == 'workflow_dispatch' }}";

const steps = (): readonly Step[] => jobSteps(WORKFLOW, JOB);
const named = (name: string): Step => {
  const s = steps().find((x) => x.name === name);
  if (s === undefined) throw new Error(`no step named "${name}"`);
  return s;
};

describe("publish-python.yml", () => {
  it("uploads to PyPI and creates the GitHub release only in the tag-triggered run", () => {
    for (const name of [
      "Install pyATR deps + run tests",
      "Bundle rules into package",
      "Build sdist + wheel",
      "Verify built package",
      "Publish to PyPI",
      "Create GitHub release",
    ]) {
      expect(named(name).if, name).toBe(ON_TAG);
    }
  });

  it("has exactly one step that uploads to PyPI", () => {
    const uploads = steps().filter((s) => /twine\s+upload/.test(s.run ?? ""));
    expect(uploads.map((s) => s.name)).toEqual(["Publish to PyPI"]);
  });

  it("bumps and tags only on a manual dispatch", () => {
    expect(named("Bump version (manual dispatch only)").if).toBe(ON_DISPATCH);
  });

  it("fails a dispatch whose tag push cannot start the publishing run", () => {
    const guard = named("Hand off to the tag-triggered run");
    expect(guard.if).toBe(ON_DISPATCH);
    const script = runBlock(WORKFLOW, JOB, "Hand off to the tag-triggered run");
    expect(script).toMatch(/HAS_REPO_TOKEN/);
    expect(script).toMatch(/exit 1/);
  });
});
