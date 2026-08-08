/**
 * The test-case event builder is shared, and the validator reads every field.
 *
 * Two harnesses used to score the same rule differently. `pga test` built the
 * event with buildEventFromTestCase, which routes a payload into whichever
 * engine field the test case names. scripts/validate-rule-testcases.ts pulled
 * text with its own chain — tool_response ?? input ?? content ??
 * tool_description — reading none of tool_args, tool_name, user_input or
 * agent_output. 194 test cases across 27 rules name their payload under one of
 * those, so every one of them resolved to the empty string.
 *
 * Both directions of that were wrong, and the quiet one is worse:
 *
 *   - a true POSITIVE scored empty reports NOT triggered, which is
 *     indistinguishable from a broken rule and invites someone to "repair" a
 *     rule that detects perfectly well
 *   - a true NEGATIVE scored empty cannot trigger, so it PASSES — a rule's
 *     declared non-detections confirmed by a harness that never read them
 *
 * These assertions exist because a comment saying "keep these in sync" is what
 * failed here. Each was broken on purpose and confirmed red before landing.
 */
import { describe, it, expect } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { buildEventFromTestCase } from "../src/testcase-event.js";
import type { ATRRule } from "../src/types.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Engine field names a test case may carry its payload under. */
const FIELD_KEYS = [
  "tool_args",
  "tool_name",
  "user_input",
  "agent_output",
  "agent_message",
  "tool_response",
  "tool_description",
] as const;

function ruleFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const full = join(dir, e);
    if (statSync(full).isDirectory()) out.push(...ruleFiles(full));
    else if (e.endsWith(".yaml") || e.endsWith(".yml")) out.push(full);
  }
  return out;
}

describe("the test-case event builder has exactly one implementation", () => {
  it("lives in src/testcase-event.ts and has no module side effects", () => {
    const src = readFileSync(join(REPO_ROOT, "src/testcase-event.ts"), "utf-8");
    // Importing src/cli.ts runs its main(); that is why this module exists.
    // If it ever grows a top-level call, the validator starts executing the CLI
    // on import — which is exactly the failure that produced "Unknown command"
    // instead of a test result.
    expect(src).not.toMatch(/^\s*(?:void\s+)?main\s*\(/m);
    expect(src).toMatch(/export function buildEventFromTestCase/);
  });

  it("the validator imports it rather than routing fields itself", () => {
    const src = readFileSync(
      join(REPO_ROOT, "scripts/validate-rule-testcases.ts"),
      "utf-8",
    );
    expect(src).toMatch(/from "\.\.\/src\/testcase-event\.js"/);
    // The old chain, verbatim. It read four keys and missed five.
    expect(src).not.toMatch(
      /tool_response \?\? t\.input \?\? t\.content \?\? t\.tool_description/,
    );
  });

  it("the CLI re-exports the shared builder instead of keeping a copy", () => {
    const src = readFileSync(join(REPO_ROOT, "src/cli.ts"), "utf-8");
    expect(src).toMatch(/from "\.\/testcase-event\.js"/);
    expect(src).not.toMatch(/^function buildEventFromTestCase\(/m);
  });
});

describe("a payload under any engine field reaches the engine", () => {
  for (const key of FIELD_KEYS) {
    it(`${key} is routed, not dropped`, () => {
      const marker = "ZZQQ-ROUTING-PROBE-ZZQQ";
      const rule = { id: "PROBE", detection: {} } as unknown as ATRRule;
      const event = buildEventFromTestCase({ [key]: marker }, rule);
      // HONEST LIMIT, stated because a probe that cannot fail is worse than no
      // probe: `agent_message` is not independently guarded here. The builder
      // assigns it unconditionally from `content` (mirroring the canonical
      // corpus shape, which does the same — so detection and false positives
      // are charged on the same presentation). Deleting its dedicated route
      // therefore leaves this green. The other six were each broken on purpose
      // and confirmed red.
      //
      // The NAMED field, not merely somewhere in the event. An earlier version
      // of this assertion accepted the payload appearing anywhere, and passed
      // even with the tool_args routing deleted — because the text also lands
      // in `content`. A rule whose condition reads `field: tool_args` does not
      // read `content`, so "it is in there somewhere" is not the property that
      // matters. Found by breaking the routing and watching this stay green.
      const landed = (event.fields ?? {})[key];
      expect(
        typeof landed === "string" && landed.includes(marker),
        `a test case declaring "${key}" produced an event whose fields.${key} ` +
          `does not carry the payload (got ${JSON.stringify(landed)}). A rule ` +
          `keyed on that field cannot fire: scored as a true positive it reads ` +
          `as a broken rule, scored as a true negative it passes unread.`,
      ).toBe(true);
    });
  }
});

describe("every declared test case carries a payload the builder can find", () => {
  it("no live rule has a test case that resolves to nothing", () => {
    const empty: string[] = [];
    for (const file of ruleFiles(join(REPO_ROOT, "rules"))) {
      let doc: unknown;
      try {
        doc = yaml.load(readFileSync(file, "utf-8"));
      } catch {
        continue; // schema validation is validate-rules' job
      }
      const r = doc as {
        id?: string;
        status?: string;
        test_cases?: Record<string, unknown[]>;
      };
      if (typeof r?.id !== "string") continue;
      const status = String(r.status ?? "");
      if (status === "draft" || status === "deprecated") continue;
      for (const kind of ["true_positives", "true_negatives"] as const) {
        for (const [i, tc] of (r.test_cases?.[kind] ?? []).entries()) {
          if (tc === null || typeof tc !== "object") continue;
          const event = buildEventFromTestCase(
            tc as Record<string, unknown>,
            doc as ATRRule,
          );
          const carries =
            (event.content ?? "").length > 0 ||
            Object.values(event.fields ?? {}).some(
              (v) => typeof v === "string" && v.length > 0,
            ) ||
            event.trace !== undefined;
          if (!carries) empty.push(`${r.id} ${kind}[${i}]`);
        }
      }
    }
    expect(
      empty,
      "these test cases build an event with no payload in it. The engine cannot " +
        "fire on nothing, so a true positive here is a false failure and a true " +
        "negative here is a pass nobody earned.",
    ).toEqual([]);
  });
});
