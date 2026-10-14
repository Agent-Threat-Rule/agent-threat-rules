/**
 * Tests for .github/workflows/benign-corpus-harvest.yml — how a week's benign
 * samples reach main. Steps run verbatim against a throwaway origin, a
 * stand-in gh and a stand-in npx (see tests/workflow-step-harness.ts).
 *
 * - The response-action gate binds its evidence to a digest of the benign
 *   corpus. The harvest grew the corpus but never re-measured, so every
 *   harvest PR failed the gate with "the measurement was taken on a different
 *   corpus" (#652, 2026-10-11) and none could ever merge. The job now
 *   re-measures on the grown corpus and commits the evidence with the samples.
 * - A measurement that fails stops the job, so old evidence never ships next to
 *   new samples. An empty rule-id list is refused for the same reason: the
 *   measurement script answers it with "nothing to gate", exit 0, and no file.
 * - A gate that fails on the new evidence is a finding, not an error. The PR
 *   still opens and its body names the rules whose block actions the new
 *   samples no longer support; demoting them is a rule change, left to a
 *   separately reviewed PR.
 * - The step that runs the npm dependency tree for minutes has no token in its
 *   environment.
 */
import { describe, it, expect, afterEach } from "vitest";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  HAS_JQ,
  cleanSandboxes,
  ghCalls,
  git,
  jobSteps,
  put,
  runBlock,
  runStep,
  sandbox,
  type Sandbox,
} from "./workflow-step-harness.js";

const WORKFLOW = resolve(__dirname, "..", ".github", "workflows", "benign-corpus-harvest.yml");
const JOB = "harvest";
const HARVEST = "Harvest benign samples (arxiv / npm / pypi)";
const REMEASURE = "Re-measure the action evidence on the grown corpus";
const OPEN_PR = "Open review PR";

const CORPUS = "data/benign-corpus-extended/arxiv.jsonl";
const EVIDENCE = "data/benign-fp-measurement.json";
const OLD_EVIDENCE = '{"corpus_digest":"317283d8d33638c3836d18857b4a3009"}\n';
const NEW_EVIDENCE = '{"corpus_digest":"regenerated"}\n';
const ONE_SAMPLE = '{"text":"an abstract","source":"arxiv","source_id":"1"}\n';
const TWO_SAMPLES = ONE_SAMPLE + '{"text":"a package description","source":"npm","source_id":"2"}\n';

// Stands in for `npx tsx <script>`. The FP measurement copies the id list it was
// handed to seen-ids.txt and writes NEW_EVIDENCE; FAKE_FP_FAIL makes it crash.
// The action gate passes, or with FAKE_GATE_FAIL fails naming one rule.
const FAKE_NPX = `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$FAKE_NPX_LOG"
case "$*" in
  *gate-promotion-fp.ts*)
    if [ -n "\${FAKE_FP_FAIL:-}" ]; then echo "fp-gate crashed" >&2; exit 1; fi
    ids=""; out=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --ids) ids=$2; shift ;;
        --emit-measurement) out=$2; shift ;;
      esac
      shift
    done
    cp "$ids" "$RUNNER_TEMP/seen-ids.txt"
    printf '%s\\n' '{"corpus_digest":"regenerated"}' > "$out"
    ;;
  *gate-action-eligibility.ts*)
    if [ -n "\${FAKE_GATE_FAIL:-}" ]; then
      echo "[action-gate] FAIL — ATR-2026-00002 carries block_tool but false-positives on 3 benign samples" >&2
      exit 1
    fi
    echo "[action-gate] PASS — every response action is earned"
    ;;
  *) echo "fake npx: unexpected call: $*" >&2; exit 1 ;;
esac
`;

afterEach(cleanSandboxes);

function harvestSandbox(files: Readonly<Record<string, string>> = {}): Sandbox {
  const sb = sandbox("harvest-wf-", {
    "rules/prompt-injection/a.yaml": "id: ATR-2026-00001\ntitle: a\n",
    "rules/tool-poisoning/b.yaml": 'id: "ATR-2026-00002"\ntitle: b\n',
    [CORPUS]: ONE_SAMPLE,
    [EVIDENCE]: OLD_EVIDENCE,
    ...files,
  });
  const npx = join(sb.root, "bin", "npx");
  writeFileSync(npx, FAKE_NPX);
  chmodSync(npx, 0o755);
  writeFileSync(join(sb.root, "npx.log"), "");
  return sb;
}

/** What build-benign-corpus.ts --write leaves on disk in a week with new samples. */
const harvested = (sb: Sandbox) => put(sb.work, CORPUS, TWO_SAMPLES);

const npxEnv = (sb: Sandbox, extra: Record<string, string> = {}) => ({ FAKE_NPX_LOG: join(sb.root, "npx.log"), ...extra });
const npxCalls = (sb: Sandbox) => readFileSync(join(sb.root, "npx.log"), "utf8");
const githubOutput = (sb: Sandbox) => readFileSync(sb.env.GITHUB_OUTPUT, "utf8");
const evidence = (sb: Sandbox) => readFileSync(join(sb.work, EVIDENCE), "utf8");
const remeasure = (sb: Sandbox, extra: Record<string, string> = {}) =>
  runStep(sb, runBlock(WORKFLOW, JOB, REMEASURE), npxEnv(sb, extra));

describe("step layout", () => {
  it("re-measures after the harvest and before the PR, with no token in reach", () => {
    const steps = jobSteps(WORKFLOW, JOB);
    const names = steps.map((s) => s.name);
    const at = names.indexOf(REMEASURE);
    expect(at).toBeGreaterThan(names.indexOf(HARVEST));
    expect(at).toBeLessThan(names.indexOf(OPEN_PR));
    const step = steps[at] as { id?: string; env?: Record<string, string>; if?: string; run?: string };
    expect(step.id).toBe("remeasure");
    expect(step.if).toBe("inputs.dry_run != true");
    expect(step.env).toBeUndefined();
    expect(step.run).not.toMatch(/secrets\.|GH_TOKEN/);
    expect(steps[names.indexOf(OPEN_PR)].env?.GATE).toBe("${{ steps.remeasure.outputs.gate }}");
  });
});

describe("re-measuring the action evidence", () => {
  it("does nothing in a quiet week", () => {
    const sb = harvestSandbox();
    const res = remeasure(sb);
    expect(res.status, res.stderr).toBe(0);
    expect(npxCalls(sb)).toBe("");
    expect(evidence(sb)).toBe(OLD_EVIDENCE);
    expect(githubOutput(sb)).toBe("");
  });

  it("re-measures every rule on the grown corpus and records a passing gate", () => {
    const sb = harvestSandbox();
    harvested(sb);
    const res = remeasure(sb);
    expect(res.status, res.stderr).toBe(0);
    expect(evidence(sb)).toBe(NEW_EVIDENCE);
    const ids = readFileSync(join(sb.root, "seen-ids.txt"), "utf8").split("\n").filter(Boolean).sort();
    expect(ids).toEqual(["ATR-2026-00001", "ATR-2026-00002"]);
    expect(npxCalls(sb)).toMatch(/gate-promotion-fp\.ts .*--filter-mode .*--emit-measurement data\/benign-fp-measurement\.json/);
    expect(githubOutput(sb)).toBe("gate=pass\n");
  });

  it("treats a failing gate as a finding: exits 0 and keeps the gate's output", () => {
    const sb = harvestSandbox();
    harvested(sb);
    const res = remeasure(sb, { FAKE_GATE_FAIL: "1" });
    expect(res.status, res.stderr).toBe(0);
    expect(evidence(sb)).toBe(NEW_EVIDENCE);
    expect(githubOutput(sb)).toBe("gate=fail\n");
    expect(readFileSync(join(sb.root, "action-gate.txt"), "utf8")).toContain("ATR-2026-00002");
  });

  it("stops the job when the measurement fails, so the old evidence never ships", () => {
    const sb = harvestSandbox();
    harvested(sb);
    const res = remeasure(sb, { FAKE_FP_FAIL: "1" });
    expect(res.status).not.toBe(0);
    expect(evidence(sb)).toBe(OLD_EVIDENCE);
    expect(githubOutput(sb)).toBe("");
    expect(npxCalls(sb)).not.toContain("gate-action-eligibility");
  });

  it("refuses an empty rule-id list instead of letting the script skip the measurement", () => {
    const sb = harvestSandbox({ "rules/README.md": "no rules here\n" });
    git(sb, sb.work, "rm", "--quiet", "-r", "rules/prompt-injection", "rules/tool-poisoning");
    git(sb, sb.work, "commit", "--quiet", "-m", "drop rules");
    harvested(sb);
    const res = remeasure(sb);
    expect(res.status).not.toBe(0);
    expect(res.stdout + res.stderr).toContain("found no rule ids under rules/");
    expect(npxCalls(sb)).toBe("");
    expect(evidence(sb)).toBe(OLD_EVIDENCE);
  });
});

describe.skipIf(!HAS_JQ)("opening the review PR", () => {
  const body = (sb: Sandbox) => readFileSync(join(sb.root, "corpus-pr-body.md"), "utf8");
  const committed = (sb: Sandbox) => git(sb, sb.work, "show", "--name-only", "--format=", "HEAD").split("\n").sort();

  it("commits the evidence with the samples it describes and reports a passing gate", () => {
    const sb = harvestSandbox();
    harvested(sb);
    expect(remeasure(sb).status).toBe(0);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, OPEN_PR), { GATE: "pass" });
    expect(res.status, res.stderr).toBe(0);
    expect(committed(sb)).toEqual([CORPUS, EVIDENCE]);
    expect(ghCalls(sb)).toMatch(/pr create .*--body-file .*corpus-pr-body\.md/);
    expect(body(sb)).toContain("The response-action gate passes on it.");
  });

  it("names the rules whose actions the new samples no longer support when the gate fails", () => {
    const sb = harvestSandbox();
    harvested(sb);
    expect(remeasure(sb, { FAKE_GATE_FAIL: "1" }).status).toBe(0);
    const res = runStep(sb, runBlock(WORKFLOW, JOB, OPEN_PR), { GATE: "fail" });
    expect(res.status, res.stderr).toBe(0);
    expect(committed(sb)).toEqual([CORPUS, EVIDENCE]);
    expect(body(sb)).toContain("The response-action gate FAILS on it");
    expect(body(sb)).toContain("deliberately not done here");
    expect(body(sb)).toContain("    [action-gate] FAIL — ATR-2026-00002");
  });
});
