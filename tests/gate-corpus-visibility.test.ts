/**
 * Tests for scripts/gate-corpus-visibility.ts — the ratchet that stops a rule
 * from reporting "0 false positives" on a corpus that could never have produced
 * one.
 *
 * WHAT IS BEING PROTECTED
 *   Five rules passed scripts/gate-promotion-fp.ts with a clean 0 over 5,352
 *   benign samples and were then overturned by hand-written benign samples that
 *   fired them at 20–57%. The corpus contained `torsocks` 0 times, `.onion` 0,
 *   "run each one" 0, `scp ` twice. Zero was never a measurement.
 *
 * Contracts pinned here:
 *   1. SOUNDNESS DIRECTION. The literal extractor may only ever UNDER-claim what
 *      a pattern requires. An over-claim reports a live rule as blind, which is
 *      the one error that makes the gate lie. Every construct it cannot read
 *      must degrade to "requires nothing".
 *   2. `\uDB40` consumes its payload. The first version stopped after `\u` and
 *      read `DB40` as required literal text, reporting a live Unicode-tag rule
 *      as blind. Found by --verify-blind on its first run.
 *   3. Rule visibility is the LEAST visible condition, for `any` as well as
 *      `all`. Taking the max reproduced the exact bug this gate exists to catch:
 *      the Tor rule scored 1786 because one broad condition drowned out the
 *      torsocks condition sitting at 1.
 *   4. A rule below the floor with no baseline entry fails; a baselined one at
 *      its recorded tier passes. That is the frozen debt.
 *   5. A baselined rule that got WORSE fails, and --write-baseline refuses to
 *      launder the regression into the record.
 *   6. --write-baseline can only shrink; --bootstrap-baseline refuses to run
 *      when a baseline already exists, so it cannot become a reset button.
 *   7. An unreadable rule file fails. "Cannot determine visibility" must never
 *      be reported as visible.
 *   8. The gate reads the same corpus paths as gate-promotion-fp.ts. Two lists
 *      would let the FP number and the visibility number describe different
 *      corpora.
 */
import { describe, it, expect } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  requirementOf,
  literalsOf,
  parsePattern,
} from "../scripts/lib/regex-literals.js";
import {
  buildLiteralIndex,
  documentFrequencies,
  frequencyMap,
} from "../scripts/lib/literal-index.js";
import {
  VISIBILITY_FLOOR,
  tierOf,
  scanRuleCorpus,
  measureVisibility,
  conditionVisibility,
  readRule,
  type ParsedRule,
} from "../scripts/lib/visibility-scan.js";
import {
  compareToBaseline,
  parseBaseline,
  tightenBaseline,
  EMPTY_BASELINE,
  VisibilityBaselineError,
  type VisibilityBaseline,
} from "../scripts/lib/visibility-baseline.js";
import { verifyBlindConditions } from "../scripts/lib/visibility-verify.js";
import { parseCliOptions, VisibilityGateUsageError } from "../scripts/gate-corpus-visibility.js";
import { MEASUREMENT_CORPORA } from "../scripts/lib/benign-corpus.js";
import { defaultDeps as fpGateDeps } from "../scripts/gate-promotion-fp.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function freqs(entries: Record<string, number>): ReadonlyMap<string, number> {
  return new Map(Object.entries(entries));
}

function measure(pattern: string, corpus: readonly string[]): number {
  const req = requirementOf(pattern);
  const index = buildLiteralIndex(literalsOf(req));
  const lowered = corpus.map((s) => s.toLowerCase());
  const map = frequencyMap(index, documentFrequencies(index, lowered));
  return conditionVisibility(req, map, corpus.length);
}

function ruleWith(
  combinator: string,
  patterns: readonly string[],
): ParsedRule {
  return {
    id: "ATR-TEST-0001",
    file: "rules/test/rule.yaml",
    status: "experimental",
    maturity: "test",
    severity: "high",
    combinator,
    conditions: patterns.map((p) => ({
      field: "content",
      operator: "regex",
      value: p,
      requirement: requirementOf(p),
      note: null,
    })),
  };
}

// ---------------------------------------------------------------------------
// 1. Soundness: the extractor may only under-claim
// ---------------------------------------------------------------------------

describe("required-literal extraction", () => {
  it("extracts a plain literal run", () => {
    expect(requirementOf("torsocks").alternatives).toEqual([["torsocks"]]);
  });

  it("splits alternation into independent alternatives", () => {
    const req = requirementOf("(?:torsocks|torify)");
    expect(req.alternatives.map((a) => [...a]).sort()).toEqual([["torify"], ["torsocks"]]);
  });

  it("ANDs across a bounded gap, so both sides are required", () => {
    const req = requirementOf("torsocks\\s+.{0,40}curl");
    expect(req.alternatives).toEqual([["curl", "torsocks"]]);
  });

  it("drops an optional trailing character rather than requiring it", () => {
    // `abc?` matches "ab". Requiring "abc" would be an over-claim.
    expect(requirementOf("abc?").alternatives).toEqual([["ab"]]);
    expect(requirementOf("abc*").alternatives).toEqual([["ab"]]);
    expect(requirementOf("abc+").alternatives).toEqual([["abc"]]);
    expect(requirementOf("abc{0,4}").alternatives).toEqual([["ab"]]);
  });

  it("requires nothing from character classes, dots, anchors and \\d\\w\\s", () => {
    for (const p of ["[a-z]+", ".*", "^$", "\\d{3}", "\\w+", "\\s"]) {
      expect(requirementOf(p).constrained, p).toBe(false);
    }
  });

  it("requires nothing from a lookaround, whose content is not guaranteed", () => {
    expect(requirementOf("(?=torsocks)").constrained).toBe(false);
    expect(requirementOf("(?!torsocks)").constrained).toBe(false);
  });

  it("treats an alternation with an empty branch as requiring nothing", () => {
    expect(requirementOf("(?:torsocks|)").constrained).toBe(false);
  });

  // Contract 2 — the regression that --verify-blind caught on its first run.
  it("consumes the payload of \\u, \\x, \\c, \\p so it is never read as text", () => {
    // `\uDB40` must not leave "DB40" behind as a required literal: no benign
    // sample contains "db40", so the rule would be reported blind while live.
    expect(requirementOf("(?:\\uDB40[\\uDC00-\\uDC7F]){3,}").constrained).toBe(false);
    expect(requirementOf("\\x41\\x42").constrained).toBe(false);
    expect(requirementOf("\\p{Script=Han}+").constrained).toBe(false);
    expect(requirementOf("\\u{1F600}").constrained).toBe(false);
    expect(literalsOf(requirementOf("\\uDB40"))).toEqual([]);
  });

  it("keeps escaped punctuation as literal text", () => {
    expect(requirementOf("\\.onion\\b").alternatives).toEqual([[".onion"]]);
  });

  it("lowercases, because every ATR condition compiles case-insensitive", () => {
    expect(requirementOf("TorSocks").alternatives).toEqual([["torsocks"]]);
  });

  it("never throws on a malformed pattern; it gives up instead", () => {
    for (const p of ["(unclosed", "[a-", "\\", "a{2,", "(?<"]) {
      expect(() => requirementOf(p), p).not.toThrow();
    }
  });

  it("parses without looping on input it cannot consume", () => {
    expect(() => parsePattern(")))")).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Visibility arithmetic
// ---------------------------------------------------------------------------

describe("condition visibility", () => {
  const corpus = [
    "run curl https://example.com to fetch the changelog",
    "the deploy script uses curl and jq",
    "scp build.tar.gz release@host:/srv/ during the cutover",
  ];

  it("is zero when a required literal is absent from the corpus", () => {
    expect(measure("torsocks\\s+curl", corpus)).toBe(0);
  });

  it("is bounded by the rarest literal in a conjunction", () => {
    // "curl" is in 2 samples, "changelog" in 1; both required.
    expect(measure("curl.{0,80}changelog", corpus)).toBe(1);
  });

  it("takes the best alternative of a disjunction", () => {
    expect(measure("(?:torsocks|curl)", corpus)).toBe(2);
  });

  it("reports the whole corpus when it cannot prove anything", () => {
    expect(measure("[a-z]+", corpus)).toBe(corpus.length);
  });

  it("counts documents, not occurrences", () => {
    expect(measure("curl", ["curl curl curl", "no match here"])).toBe(1);
  });

  it("scores a field no text corpus can fill as zero", () => {
    // Mirrors the NOT MEASURED report gate-promotion-fp.ts already prints.
    const rule: ParsedRule = {
      ...ruleWith("any", ["anything"]),
      conditions: [
        {
          field: "tool_name",
          operator: "regex",
          value: "anything",
          requirement: requirementOf("anything"),
          note: "no benign corpus of tool names exists",
        },
      ],
    };
    expect(measureVisibility(rule, freqs({ anything: 900 }), 5000).visibility).toBe(0);
  });
});

// Contract 3 — the design decision the first version got wrong.
describe("rule visibility is the least visible condition", () => {
  const map = freqs({ torsocks: 0, curl: 1786, exfiltrate: 40 });

  it("does not let a broad condition hide a blind one under `any`", () => {
    const rule = ruleWith("any", ["torsocks.{0,40}curl", "curl"]);
    const measured = measureVisibility(rule, map, 5352);
    expect(measured.widest).toBe(1786);
    expect(measured.visibility).toBe(0);
    expect(measured.tier).toBe("blind");
    expect(measured.blindConditions).toBe(1);
  });

  it("is also the minimum under `all`, where one blind conjunct kills the rule", () => {
    const rule = ruleWith("all", ["torsocks", "curl"]);
    expect(measureVisibility(rule, map, 5352).visibility).toBe(0);
  });

  it("tiers on the floor", () => {
    expect(tierOf(0)).toBe("blind");
    expect(tierOf(VISIBILITY_FLOOR - 1)).toBe("thin");
    expect(tierOf(VISIBILITY_FLOOR)).toBe("measured");
  });
});

// ---------------------------------------------------------------------------
// The gate's self-check
// ---------------------------------------------------------------------------

describe("--verify-blind self-check", () => {
  const corpus = ["a runbook that mentions curl and nothing else"];

  it("passes when a condition called blind really matches nothing", () => {
    const rule = measureVisibility(ruleWith("any", ["torsocks"]), freqs({ torsocks: 0 }), 1);
    const result = verifyBlindConditions([rule], corpus);
    expect(result.executed).toBe(1);
    expect(result.violations).toEqual([]);
  });

  it("fails when the extractor over-claimed and the pattern actually matches", () => {
    // Forced disagreement: the frequency map says "curl" is absent, the corpus
    // says otherwise. That is exactly the shape of an extractor over-claim.
    const rule = measureVisibility(ruleWith("any", ["curl"]), freqs({ curl: 0 }), 1);
    const result = verifyBlindConditions([rule], corpus);
    expect(result.violations).toHaveLength(1);
    expect(result.violations[0]?.pattern).toBe("curl");
  });
});

// ---------------------------------------------------------------------------
// Corpus scan
// ---------------------------------------------------------------------------

function fixtureRule(dir: string, name: string, body: string): void {
  mkdirSync(join(dir, "rules", "test"), { recursive: true });
  writeFileSync(join(dir, "rules", "test", name), body, "utf-8");
}

describe("rule corpus scan", () => {
  it("reports a rule with no readable detection instead of skipping it", () => {
    const root = mkdtempSync(join(tmpdir(), "atr-vis-"));
    fixtureRule(root, "a.yaml", "id: ATR-TEST-1\nstatus: experimental\n");
    fixtureRule(root, "b.yaml", "id: ATR-TEST-2\ndetection:\n  conditions: []\n");
    fixtureRule(root, "c.yaml", "id: ATR-TEST-3\ndetection: {conditions: [{field: content}]}\n");
    const scan = scanRuleCorpus(join(root, "rules"), root);
    expect(scan.rules).toHaveLength(0);
    expect(scan.unreadable).toHaveLength(3);
    expect(scan.unreadable.map((u) => u.reason).join(" ")).toContain("detection");
  });

  it("keeps the raw pattern so the self-check can execute the real thing", () => {
    const root = mkdtempSync(join(tmpdir(), "atr-vis-"));
    fixtureRule(
      root,
      "d.yaml",
      [
        "id: ATR-TEST-4",
        "status: experimental",
        "maturity: test",
        "detection:",
        "  condition: any",
        "  conditions:",
        "    - field: content",
        "      operator: regex",
        '      value: "torsocks"',
        "",
      ].join("\n"),
    );
    const rule = readRule(join(root, "rules", "test", "d.yaml"), root);
    expect("id" in rule && rule.conditions[0]?.value).toBe("torsocks");
  });
});

// ---------------------------------------------------------------------------
// Ratchet
// ---------------------------------------------------------------------------

const baselineWith = (entries: Record<string, "blind" | "thin">): VisibilityBaseline => ({
  ...EMPTY_BASELINE,
  knownUnmeasured: entries,
});

function scored(id: string, visibility: number, maturity = "test") {
  return measureVisibility(
    { ...ruleWith("any", ["tok"]), id, maturity },
    freqs({ tok: visibility }),
    5352,
  );
}

describe("baseline ratchet", () => {
  it("fails an un-baselined rule below the floor", () => {
    const cmp = compareToBaseline([scored("ATR-NEW", 0)], EMPTY_BASELINE);
    expect(cmp.newlyUnmeasured.map((r) => r.id)).toEqual(["ATR-NEW"]);
  });

  it("passes a baselined rule still at its recorded tier", () => {
    const cmp = compareToBaseline([scored("ATR-OLD", 0)], baselineWith({ "ATR-OLD": "blind" }));
    expect(cmp.newlyUnmeasured).toEqual([]);
    expect(cmp.grandfathered.map((r) => r.id)).toEqual(["ATR-OLD"]);
  });

  it("fails a baselined rule that got worse", () => {
    const cmp = compareToBaseline([scored("ATR-OLD", 0)], baselineWith({ "ATR-OLD": "thin" }));
    expect(cmp.regressed.map((r) => r.id)).toEqual(["ATR-OLD"]);
  });

  it("lists an improved rule for tightening", () => {
    const cmp = compareToBaseline([scored("ATR-OLD", 900)], baselineWith({ "ATR-OLD": "thin" }));
    expect(cmp.resolved).toEqual(["ATR-OLD"]);
  });

  it("names below-floor rules that auto-block in the enforce lane", () => {
    const cmp = compareToBaseline(
      [scored("ATR-ENF", 0, "stable"), scored("ATR-HUNT", 0, "test")],
      baselineWith({ "ATR-ENF": "blind", "ATR-HUNT": "blind" }),
    );
    expect(cmp.enforceLaneDebt.map((r) => r.id)).toEqual(["ATR-ENF"]);
  });

  it("--write-baseline records improvement but never regression", () => {
    const baseline = baselineWith({ "ATR-A": "blind", "ATR-B": "thin", "ATR-C": "thin" });
    const next = tightenBaseline(
      baseline,
      [scored("ATR-A", 4), scored("ATR-B", 0), scored("ATR-C", 900)],
      "now",
    );
    expect(next.knownUnmeasured["ATR-A"]).toBe("thin"); // blind -> thin, tightened
    expect(next.knownUnmeasured["ATR-B"]).toBe("thin"); // thin -> blind, NOT laundered
    expect(next.knownUnmeasured["ATR-C"]).toBeUndefined(); // cleared
  });

  it("--write-baseline never adds a new entry", () => {
    const next = tightenBaseline(EMPTY_BASELINE, [scored("ATR-NEW", 0)], "now");
    expect(Object.keys(next.knownUnmeasured)).toEqual([]);
  });

  it("refuses a corrupt baseline rather than reading it as empty or permissive", () => {
    expect(() => parseBaseline("{", "x")).toThrow(VisibilityBaselineError);
    expect(() => parseBaseline('{"knownUnmeasured": []}', "x")).toThrow(VisibilityBaselineError);
    expect(() => parseBaseline('{"knownUnmeasured": {"A": "measured"}}', "x")).toThrow(
      VisibilityBaselineError,
    );
  });
});

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

describe("cli", () => {
  it("rejects unknown flags", () => {
    expect(() => parseCliOptions(["--nope"])).toThrow(VisibilityGateUsageError);
  });

  it("refuses --write-baseline together with --bootstrap-baseline", () => {
    expect(() => parseCliOptions(["--write-baseline", "--bootstrap-baseline"])).toThrow(
      VisibilityGateUsageError,
    );
  });

  it("requires an id for --explain", () => {
    expect(() => parseCliOptions(["--explain"])).toThrow(VisibilityGateUsageError);
    expect(() => parseCliOptions(["--explain", "--json"])).toThrow(VisibilityGateUsageError);
  });
});

// ---------------------------------------------------------------------------
// Contract 8: one corpus definition, not two
// ---------------------------------------------------------------------------

describe("corpus agreement with the FP gate", () => {
  it("measures visibility over exactly the corpora the FP gate scores against", () => {
    const fpPaths = fpGateDeps().corpora.map((p) => p.replace(/^.*?\/(data\/.*)$/, "$1"));
    expect([...fpPaths].sort()).toEqual([...MEASUREMENT_CORPORA].sort());
  });

  it("ships a baseline, so the gate is not silently a no-op", () => {
    expect(existsSync(new URL("../data/corpus-visibility-baseline.json", import.meta.url)))
      .toBe(true);
  });
});
