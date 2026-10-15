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
 * - The re-measure is the DELTA (scripts/remeasure-benign-fp.ts): rules whose
 *   detection is unchanged are measured on the new samples only. A full
 *   measurement takes hours, and in a job with no budget a slow week would end
 *   "cancelled" with no PR and nothing red. The step has a timeout of its own.
 * - The stand-in npx records the argv it was given, and the test feeds that
 *   argv through the scripts' OWN argument parsers, so a dropped or misspelled
 *   flag fails here rather than on the runner. The section the PR body carries
 *   is rendered by the real renderer, not a stand-in.
 * - A re-measure that refuses or fails stops the job, so old evidence never
 *   ships next to new samples.
 * - The gate's exit code is read, not guessed: 0 is a pass, 1 is a finding (the
 *   PR opens and names the new samples behind each failing rule), anything else
 *   is a pipeline error that fails the step and opens nothing.
 * - The PR step validates the verdict and its inputs before anything is pushed.
 *   A gate output too long for the body is cut with an explicit "… N more".
 * - An open rolling PR's description is refreshed through REST: `gh pr edit`
 *   fails with this PAT whenever the PR has a team review request.
 * - The step that runs the npm dependency tree has no PAT in its environment.
 *   (actions/checkout still leaves GITHUB_TOKEN in .git/config; the PAT that
 *   opens the PR is the one kept out of reach.)
 */
import { describe, it, expect, afterEach } from "vitest";
import { chmodSync, existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  HAS_JQ,
  cleanSandboxes,
  ghCalls,
  git,
  jobSteps,
  originSha,
  put,
  runBlock,
  runStep,
  sandbox,
  setPrs,
  type Sandbox,
} from "./workflow-step-harness.js";
import { parseRemeasureArgs } from "../scripts/remeasure-benign-fp.js";
import { parseRenderArgs } from "../scripts/render-fp-attribution.js";
import { ATTRIBUTION_SCHEMA, parseAttributionReport } from "../scripts/lib/fp-attribution.js";

const REPO_ROOT = resolve(__dirname, "..");
const WORKFLOW = resolve(REPO_ROOT, ".github", "workflows", "benign-corpus-harvest.yml");
const JOB = "harvest";
const HARVEST = "Harvest benign samples (arxiv / npm / pypi)";
const REMEASURE = "Re-measure the action evidence on the grown corpus";
const OPEN_PR = "Open review PR";
const BRANCH = "benign-corpus/rolling";

const CORPUS = "data/benign-corpus-extended/arxiv.jsonl";
const EVIDENCE = "data/benign-fp-measurement.json";
const OLD_EVIDENCE = '{"corpus_digest":"317283d8d33638c3836d18857b4a3009"}\n';
const NEW_EVIDENCE = '{"corpus_digest":"regenerated"}\n';
const ONE_SAMPLE = '{"text":"an abstract","source":"arxiv","source_id":"1"}\n';
const TWO_SAMPLES = ONE_SAMPLE + '{"text":"a package description","source":"npm","source_id":"2"}\n';

const FAILING_RULE = "ATR-2026-00002";
const GATE_FAIL_LINE = `[action-gate] FAIL — ${FAILING_RULE} carries block_tool but false-positives on 3 benign samples`;

// Stands in for `npx tsx <script>`. Each call's argv is logged one call per
// line, joined by \x1f, so the test can hand it to the script's own parser.
//   remeasure-benign-fp.ts: writes NEW_EVIDENCE and a report; FAKE_REMEASURE_EXIT refuses.
//   gate-action-eligibility.ts: prints FAKE_GATE_TEXT and exits FAKE_GATE_EXIT;
//     with --json prints FAKE_GATE_JSON and exits FAKE_GATE_JSON_EXIT (default: the same).
//   render-fp-attribution.ts: the REAL renderer, run with the real tsx.
const FAKE_NPX = `#!/usr/bin/env bash
set -euo pipefail
( IFS=$'\\x1f'; printf '%s\\n' "$*" ) >> "$FAKE_NPX_LOG"
[ "\${1:-}" = "tsx" ] || { echo "fake npx: expected tsx, got: $*" >&2; exit 1; }
script=\${2:-}
shift 2
case "$script" in
  scripts/remeasure-benign-fp.ts)
    if [ -n "\${FAKE_REMEASURE_EXIT:-}" ]; then
      echo "[remeasure] FULL MEASUREMENT REQUIRED (fake)" >&2
      exit "$FAKE_REMEASURE_EXIT"
    fi
    out=""; report=""
    while [ $# -gt 0 ]; do
      case "$1" in
        --emit-measurement) out=$2; shift ;;
        --report) report=$2; shift ;;
      esac
      shift
    done
    printf '%s\\n' '{"corpus_digest":"regenerated"}' > "$out"
    cp "$FAKE_REPORT" "$report"
    ;;
  scripts/gate-action-eligibility.ts)
    if [ "\${1:-}" = "--json" ]; then
      cat "$FAKE_GATE_JSON"
      exit "\${FAKE_GATE_JSON_EXIT:-\${FAKE_GATE_EXIT:-0}}"
    fi
    cat "$FAKE_GATE_TEXT"
    exit "\${FAKE_GATE_EXIT:-0}"
    ;;
  scripts/render-fp-attribution.ts)
    exec "$REAL_TSX" "$REAL_RENDERER" "$@"
    ;;
  *) echo "fake npx: unexpected call: $script $*" >&2; exit 1 ;;
esac
`;

// Wraps the harness's gh: `gh api` (REST) is recorded, with the body file it
// was handed; everything else goes to the harness stand-in, which refuses any
// call it does not know, `gh pr edit` included.
const FAKE_GH_API = `#!/usr/bin/env bash
set -euo pipefail
if [ "\${1:-}" = "api" ]; then
  printf '%s\\n' "$*" >> "$FAKE_GH_LOG"
  while [ $# -gt 0 ]; do
    case "$1" in
      -F|--field) case "$2" in body=@*) cp "\${2#body=@}" "$FAKE_GH_LOG.patch-body" ;; esac; shift ;;
    esac
    shift
  done
  exit 0
fi
exec "$(dirname "$0")/gh-harness" "$@"
`;

/** What the real delta script reports for this harvest: one rule fires on the npm sample. */
const REPORT = parseAttributionReport(
  JSON.stringify({
    schema: ATTRIBUTION_SCHEMA,
    base_ref: "HEAD",
    base_commit: "0".repeat(40),
    base_sample_count: 1,
    added_sample_count: 1,
    head_sample_count: 2,
    rules_total: 2,
    measured_on_added_only: 2,
    measured_in_full: [],
    rules: [
      {
        id: FAILING_RULE,
        measured: "delta",
        fp_count_before: 2,
        fp_count_after: 3,
        added_matches: 1,
        samples: [
          {
            excerpt: "a package description",
            occurrences: 1,
            locations: [{ file: CORPUS, line: 2, source: "npm", source_id: "2" }],
          },
        ],
      },
    ],
  }),
);

/** The shape `gate-action-eligibility.ts --json` prints for one violation. */
const GATE_JSON = JSON.stringify({
  checked: 2,
  violations: [
    {
      id: FAILING_RULE,
      file: "rules/tool-poisoning/b.yaml",
      unearned: ["block_tool"],
      maxTier: 0,
      decision: { maxTier: 0, fpRatePct: 2.5, reason: "benign FP 3/120 = 2.50% exceeds the 2% automatic-demotion line" },
    },
  ],
});

afterEach(cleanSandboxes);

function harvestSandbox(files: Readonly<Record<string, string>> = {}): Sandbox {
  const sb = sandbox("harvest-wf-", {
    "rules/prompt-injection/a.yaml": "id: ATR-2026-00001\ntitle: a\n",
    "rules/tool-poisoning/b.yaml": `id: ${FAILING_RULE}\ntitle: b\n`,
    [CORPUS]: ONE_SAMPLE,
    [EVIDENCE]: OLD_EVIDENCE,
    ...files,
  });
  const npx = join(sb.root, "bin", "npx");
  writeFileSync(npx, FAKE_NPX);
  chmodSync(npx, 0o755);
  renameSync(join(sb.root, "bin", "gh"), join(sb.root, "bin", "gh-harness"));
  writeFileSync(join(sb.root, "bin", "gh"), FAKE_GH_API);
  chmodSync(join(sb.root, "bin", "gh"), 0o755);
  writeFileSync(join(sb.root, "npx.log"), "");
  writeFileSync(join(sb.root, "fake-report.json"), JSON.stringify(REPORT));
  writeFileSync(join(sb.root, "fake-gate.json"), GATE_JSON);
  gateText(sb, "[action-gate] PASS — every live rule's response actions are within the tier\n");
  return sb;
}

function gateText(sb: Sandbox, text: string): void {
  writeFileSync(join(sb.root, "fake-gate.txt"), text);
}

/** What build-benign-corpus.ts --write leaves on disk in a week with new samples. */
const harvested = (sb: Sandbox) => put(sb.work, CORPUS, TWO_SAMPLES);

const npxEnv = (sb: Sandbox, extra: Record<string, string> = {}) => ({
  FAKE_NPX_LOG: join(sb.root, "npx.log"),
  FAKE_REPORT: join(sb.root, "fake-report.json"),
  FAKE_GATE_JSON: join(sb.root, "fake-gate.json"),
  FAKE_GATE_TEXT: join(sb.root, "fake-gate.txt"),
  REAL_TSX: join(REPO_ROOT, "node_modules", ".bin", "tsx"),
  REAL_RENDERER: join(REPO_ROOT, "scripts", "render-fp-attribution.ts"),
  ...extra,
});
const npxCalls = (sb: Sandbox): string[][] =>
  readFileSync(join(sb.root, "npx.log"), "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => l.split("\x1f"));
const callsTo = (sb: Sandbox, script: string) => npxCalls(sb).filter((c) => c[1] === script);
const githubOutput = (sb: Sandbox) => readFileSync(sb.env.GITHUB_OUTPUT, "utf8");
const evidence = (sb: Sandbox) => readFileSync(join(sb.work, EVIDENCE), "utf8");
const section = (sb: Sandbox) => readFileSync(join(sb.root, "fp-attribution.md"), "utf8");
const remeasure = (sb: Sandbox, extra: Record<string, string> = {}) =>
  runStep(sb, runBlock(WORKFLOW, JOB, REMEASURE), npxEnv(sb, extra));
const ghEnv = (gate: string) => ({
  GATE: gate,
  GITHUB_REPOSITORY: "Agent-Threat-Rule/agent-threat-rules",
  GITHUB_SERVER_URL: "https://github.com",
  GITHUB_RUN_ID: "4242",
});
const openPr = (sb: Sandbox, gate: string) => runStep(sb, runBlock(WORKFLOW, JOB, OPEN_PR), ghEnv(gate));

describe("step layout", () => {
  it("re-measures after the harvest and before the PR, with a time budget and no PAT in its environment", () => {
    const steps = jobSteps(WORKFLOW, JOB);
    const names = steps.map((s) => s.name);
    const at = names.indexOf(REMEASURE);
    expect(at).toBeGreaterThan(names.indexOf(HARVEST));
    expect(at).toBeLessThan(names.indexOf(OPEN_PR));
    const step = steps[at] as {
      id?: string;
      env?: Record<string, string>;
      if?: string;
      run?: string;
      "timeout-minutes"?: number;
    };
    expect(step.id).toBe("remeasure");
    expect(step.if).toBe("inputs.dry_run != true");
    expect(step.env).toBeUndefined();
    expect(step.run).not.toMatch(/secrets\.|GH_TOKEN/);
    expect(step["timeout-minutes"]).toBeGreaterThan(0);
    // Hours would mean a full measurement slipped through; the budget must stay far below that.
    expect(step["timeout-minutes"]).toBeLessThanOrEqual(60);
    expect(steps[names.indexOf(OPEN_PR)].env?.GATE).toBe("${{ steps.remeasure.outputs.gate }}");
  });
});

describe("re-measuring the action evidence", () => {
  it("does nothing in a quiet week", () => {
    const sb = harvestSandbox();
    const res = remeasure(sb);
    expect(res.status, res.stderr).toBe(0);
    expect(npxCalls(sb)).toEqual([]);
    expect(evidence(sb)).toBe(OLD_EVIDENCE);
    expect(githubOutput(sb)).toBe("");
  });

  it("runs the delta re-measure against HEAD with flags its own parser accepts", () => {
    const sb = harvestSandbox();
    harvested(sb);
    const res = remeasure(sb);
    expect(res.status, res.stderr).toBe(0);
    expect(evidence(sb)).toBe(NEW_EVIDENCE);
    const calls = callsTo(sb, "scripts/remeasure-benign-fp.ts");
    expect(calls).toHaveLength(1);
    expect(parseRemeasureArgs(calls[0]?.slice(2) ?? [])).toEqual({
      baseRef: "HEAD",
      emitMeasurement: EVIDENCE,
      report: join(sb.root, "fp-attribution.json"),
      maxFullRules: 100,
    });
    expect(callsTo(sb, "scripts/gate-promotion-fp.ts")).toEqual([]);
  });

  it("records a passing gate, echoes its output, and renders the section without a gate verdict file", () => {
    const sb = harvestSandbox();
    harvested(sb);
    const res = remeasure(sb);
    expect(res.status, res.stderr).toBe(0);
    expect(githubOutput(sb)).toBe("gate=pass\n");
    expect(res.stdout).toContain("[action-gate] PASS");
    expect(callsTo(sb, "scripts/gate-action-eligibility.ts")).toEqual([["tsx", "scripts/gate-action-eligibility.ts"]]);
    const render = callsTo(sb, "scripts/render-fp-attribution.ts");
    expect(render).toHaveLength(1);
    expect(parseRenderArgs(render[0]?.slice(2) ?? [])).toEqual({
      report: join(sb.root, "fp-attribution.json"),
      gateJson: null,
      out: join(sb.root, "fp-attribution.md"),
    });
    expect(section(sb)).toContain(FAILING_RULE);
  });

  it("treats exit 1 from the gate as a finding: exits 0, records the failure, names the samples", () => {
    const sb = harvestSandbox();
    harvested(sb);
    gateText(sb, `${GATE_FAIL_LINE}\n`);
    const res = remeasure(sb, { FAKE_GATE_EXIT: "1" });
    expect(res.status, res.stderr).toBe(0);
    expect(evidence(sb)).toBe(NEW_EVIDENCE);
    expect(githubOutput(sb)).toBe("gate=fail\n");
    expect(res.stdout).toContain(GATE_FAIL_LINE);
    expect(readFileSync(join(sb.root, "action-gate.txt"), "utf8")).toContain(FAILING_RULE);
    const render = callsTo(sb, "scripts/render-fp-attribution.ts");
    expect(parseRenderArgs(render[0]?.slice(2) ?? []).gateJson).toBe(join(sb.root, "action-gate.json"));
    expect(section(sb)).toContain("now fails");
    expect(section(sb)).toContain("npm 2  data/benign-corpus-extended/arxiv.jsonl:2");
    expect(section(sb)).toContain('"a package description"');
  });

  it("fails the step when the gate reaches no verdict (exit 2), and opens nothing", () => {
    const sb = harvestSandbox();
    harvested(sb);
    const res = remeasure(sb, { FAKE_GATE_EXIT: "2" });
    expect(res.status).not.toBe(0);
    expect(res.stdout + res.stderr).toContain("exited 2");
    expect(githubOutput(sb)).toBe("");
    expect(callsTo(sb, "scripts/render-fp-attribution.ts")).toEqual([]);
  });

  it("fails the step when the gate's --json run disagrees with its verdict", () => {
    const sb = harvestSandbox();
    harvested(sb);
    const res = remeasure(sb, { FAKE_GATE_EXIT: "1", FAKE_GATE_JSON_EXIT: "0" });
    expect(res.status).not.toBe(0);
    expect(githubOutput(sb)).toBe("");
  });

  it("stops the job when the delta re-measure refuses, so the old evidence never ships", () => {
    const sb = harvestSandbox();
    harvested(sb);
    const res = remeasure(sb, { FAKE_REMEASURE_EXIT: "4" });
    expect(res.status).not.toBe(0);
    expect(res.stdout + res.stderr).toContain("exited 4");
    expect(evidence(sb)).toBe(OLD_EVIDENCE);
    expect(githubOutput(sb)).toBe("");
    expect(callsTo(sb, "scripts/gate-action-eligibility.ts")).toEqual([]);
  });
});

describe.skipIf(!HAS_JQ)("opening the review PR", () => {
  const body = (sb: Sandbox) => readFileSync(join(sb.root, "corpus-pr-body.md"), "utf8");
  const committed = (sb: Sandbox) => git(sb, sb.work, "show", "--name-only", "--format=", "HEAD").split("\n").sort();

  it("commits the evidence with the samples it describes and reports a passing gate", () => {
    const sb = harvestSandbox();
    harvested(sb);
    expect(remeasure(sb).status).toBe(0);
    const res = openPr(sb, "pass");
    expect(res.status, res.stderr).toBe(0);
    expect(committed(sb)).toEqual([CORPUS, EVIDENCE]);
    expect(ghCalls(sb)).toMatch(/pr create .*--body-file .*corpus-pr-body\.md/);
    expect(body(sb)).toContain("The response-action gate passes on it.");
    expect(body(sb)).toContain(FAILING_RULE);
    expect(body(sb)).not.toContain("Gate output");
  });

  it("on a failing gate, names the triggering samples and asks whether they belong before any demotion", () => {
    const sb = harvestSandbox();
    harvested(sb);
    gateText(sb, `${GATE_FAIL_LINE}\n`);
    expect(remeasure(sb, { FAKE_GATE_EXIT: "1" }).status).toBe(0);
    const res = openPr(sb, "fail");
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toContain(GATE_FAIL_LINE);
    expect(committed(sb)).toEqual([CORPUS, EVIDENCE]);
    const text = body(sb);
    expect(text).toContain("The response-action gate FAILS on it");
    expect(text).toContain("First decide whether each sample belongs in the benign corpus");
    expect(text).toContain("deliberately not done here");
    expect(text).toContain("npm 2  data/benign-corpus-extended/arxiv.jsonl:2");
    expect(text).toContain('"a package description"');
    expect(text).toContain(`    ${GATE_FAIL_LINE}`);
    expect(text).toContain(
      "npx tsx scripts/remeasure-benign-fp.ts --base-ref origin/main --emit-measurement data/benign-fp-measurement.json",
    );
    expect(text).toContain("https://github.com/Agent-Threat-Rule/agent-threat-rules/actions/runs/4242");
  });

  it("the re-measure command it gives the reviewer is one the script accepts", () => {
    const sb = harvestSandbox();
    harvested(sb);
    expect(remeasure(sb).status).toBe(0);
    expect(openPr(sb, "pass").status).toBe(0);
    const line = body(sb)
      .split("\n")
      .find((l) => l.includes("npx tsx scripts/remeasure-benign-fp.ts"));
    const argv = (line ?? "").trim().split(/\s+/).slice(3);
    expect(parseRemeasureArgs(argv)).toMatchObject({ baseRef: "origin/main", emitMeasurement: EVIDENCE });
  });

  it("cuts a long gate output with an explicit marker instead of silently", () => {
    const sb = harvestSandbox();
    harvested(sb);
    const lines = Array.from({ length: 100 }, (_, i) => `gate line ${i + 1}`);
    gateText(sb, `${lines.join("\n")}\n`);
    expect(remeasure(sb, { FAKE_GATE_EXIT: "1" }).status).toBe(0);
    const res = openPr(sb, "fail");
    expect(res.status, res.stderr).toBe(0);
    const text = body(sb);
    expect(text).toContain("Gate output (first 40 of 100 lines)");
    expect(text).toContain("    gate line 40\n");
    expect(text).not.toContain("gate line 41\n");
    expect(text).toContain("… 60 more lines");
  });

  it.each(["", "maybe", "PASS"])("refuses gate=%j before anything is pushed", (gate) => {
    const sb = harvestSandbox();
    harvested(sb);
    expect(remeasure(sb).status).toBe(0);
    const res = openPr(sb, gate);
    expect(res.status).not.toBe(0);
    expect(res.stdout + res.stderr).toContain("not pass or fail");
    expect(originSha(sb, BRANCH)).toBe("");
    expect(ghCalls(sb)).toBe("");
  });

  it("refuses to push without the gate output and the evidence summary", () => {
    const sb = harvestSandbox();
    harvested(sb);
    const res = openPr(sb, "fail");
    expect(res.status).not.toBe(0);
    expect(originSha(sb, BRANCH)).toBe("");
    expect(ghCalls(sb)).toBe("");
    expect(existsSync(join(sb.root, "corpus-pr-body.md"))).toBe(false);
  });

  it("refreshes an open rolling PR's title and description through REST, never `gh pr edit`", () => {
    const sb = harvestSandbox();
    harvested(sb);
    setPrs(sb, [{ number: 652, state: "OPEN", isCrossRepository: false }]);
    expect(remeasure(sb, { FAKE_GATE_EXIT: "1" }).status).toBe(0);
    const res = openPr(sb, "fail");
    expect(res.status, res.stderr).toBe(0);
    const calls = ghCalls(sb);
    expect(calls).toMatch(/^api -X PATCH repos\/Agent-Threat-Rule\/agent-threat-rules\/pulls\/652 .*-F body=@/m);
    expect(calls).not.toMatch(/pr (edit|create)/);
    expect(readFileSync(`${sb.env.FAKE_GH_LOG}.patch-body`, "utf8")).toBe(body(sb));
    expect(originSha(sb, BRANCH)).not.toBe("");
  });
});
