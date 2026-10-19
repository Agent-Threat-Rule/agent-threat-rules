#!/usr/bin/env npx tsx
/**
 * scripts/vendor-suites/measure-vendor-suites.ts
 *
 * Measures ATR against the vendor guardrail test-suite corpus
 * (data/test-corpora/vendor-guardrail-suites/samples.jsonl, rebuilt from pinned upstream commits by
 * scripts/vendor-suites/fetch-vendor-suites.py) and writes one measurement file under
 * data/measurements/vendor-guardrail-suites/.
 *
 * What it records
 *   1. Full ruleset, per lane (hunt / alert / enforce): recall per vendor and per vendor x category on the
 *      attack samples, and flags on the vendors' own benign (negative) test cases, labelled as such.
 *   2. ATR-2026-00500..00505: which vendor test cases each rule matches, set against the vendor corpus and
 *      category the rule's description says it was generalised from.
 *   3. Whether each of those rules' own test_cases.true_positives is a vendor test case (exact text), or
 *      a sample of the 2026-05-12 corpora that the provenance audit could not find in the vendor repo.
 *   4. breakdown.in_sample_ablation: every lane again, per vendor, with the rules whose YAML names a vendor
 *      or the vendor-corpus-import tag removed (the ablation reference to cite beside the headline), and
 *      once more with every rule whose YAML shares a 40-character run with a vendor sample also removed.
 *   5. breakdown.overlaps: rules carrying vendor-sample text, and vendor samples that occur verbatim in the
 *      garak-full corpus, so the distance from out-of-sample is stated, not assumed.
 *   6. breakdown.precision_not_citable: the vendors ship 20 benign cases, too few for a precision or
 *      FP-rate claim; data/stats.json projects those fields as null.
 *
 * Detection predicate (identical for attacks and benign, identical across lanes)
 *   role=input  -> src/corpus-event.ts promptChannelShapes(): llm_input + tool_response, the predicate
 *                  every prompt-corpus runner uses (detectedOnPromptChannels).
 *   role=output -> one llm_output event (agent_output = text): the text is something the model emitted
 *                  and the vendor checks it on the output rail.
 *   A sample is detected when at least one rule matches on at least one of its events.
 *
 * Usage:
 *   npx tsx scripts/vendor-suites/measure-vendor-suites.ts            # measure + write measurement
 *   npx tsx scripts/vendor-suites/measure-vendor-suites.ts --dry-run  # measure, print, write nothing
 *   npx tsx scripts/vendor-suites/measure-vendor-suites.ts --force    # replace a same-day measurement file
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ATREngine } from '../../src/engine.js';
import { promptChannelShapes } from '../../src/corpus-event.js';
import { ENFORCE_LANE_NOTE, rulesInLane } from '../../src/measurement/enforce-lane.js';
import { writeMeasurement } from '../../src/measurement/write.js';
import type { AgentEvent, ATRRule } from '../../src/types.js';
import {
  SHINGLE_CHARS,
  VENDOR_NAMING_PATTERN,
  loadRuleTexts,
  ruleTextOverlaps,
  rulesDirWithout,
  rulesNaming,
  vendorSamplesInCorpus,
} from './in-sample.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const RULES_DIR = resolve(REPO_ROOT, 'rules');
const CORPUS_DIR = resolve(REPO_ROOT, 'data/test-corpora/vendor-guardrail-suites');
const SAMPLES_PATH = resolve(CORPUS_DIR, 'samples.jsonl');
const MANIFEST_PATH = resolve(CORPUS_DIR, 'manifest.json');
const LEGACY_AUDIT_PATH = resolve(CORPUS_DIR, 'legacy-corpora-provenance.json');
const GARAK_FULL_DIR = resolve(REPO_ROOT, 'data/test-corpora/garak-full');
const DRY_RUN = process.argv.includes('--dry-run');
const FORCE = process.argv.includes('--force');
const ABLATION_REFERENCE = 'without_rules_naming_source';

type Lane = 'hunt' | 'alert' | 'enforce';
const LANES: readonly Lane[] = ['hunt', 'alert', 'enforce'];

interface Sample {
  readonly id: string;
  readonly sha256: string;
  readonly vendor: string;
  readonly vendors: readonly string[];
  readonly label: 'attack' | 'benign';
  readonly category: string;
  readonly role: 'input' | 'output';
  readonly pins: readonly string[];
  readonly text: string;
}

/** The rules the red-team page entry names, and the corpus + category each says it was generalised from. */
const VENDOR_IMPORT_RULES: Readonly<Record<string, readonly { vendor: string; category: string }[]>> = {
  'ATR-2026-00500': [{ vendor: 'promptfoo', category: 'ssrf' }],
  'ATR-2026-00501': [{ vendor: 'promptfoo', category: 'data-exfil' }],
  'ATR-2026-00502': [{ vendor: 'promptfoo', category: 'divergent-repetition' }],
  'ATR-2026-00503': [{ vendor: 'llm-guard', category: 'prompt-injection' }],
  'ATR-2026-00504': [{ vendor: 'promptfoo', category: 'tool-discovery' }],
  'ATR-2026-00505': [
    { vendor: 'llm-guard', category: 'prompt-injection' },
    { vendor: 'promptfoo', category: 'prompt-extraction' },
  ],
};

// ------------------------------------------------------------------ loading

function loadSamples(): readonly Sample[] {
  if (!existsSync(SAMPLES_PATH)) {
    throw new Error(`${SAMPLES_PATH} missing — run python3 scripts/vendor-suites/fetch-vendor-suites.py first`);
  }
  const raw = readFileSync(SAMPLES_PATH, 'utf-8');
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf-8')) as { samples_sha256: string };
  const actual = createHash('sha256').update(raw, 'utf-8').digest('hex');
  if (actual !== manifest.samples_sha256) {
    throw new Error(`samples.jsonl sha256 ${actual} != manifest ${manifest.samples_sha256} — corpus edited by hand?`);
  }
  const samples = raw
    .split('\n')
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l) as Sample);
  if (samples.length === 0) throw new Error('samples.jsonl is empty');
  return samples;
}

function eventsFor(s: Sample): readonly AgentEvent[] {
  if (s.role === 'input') return promptChannelShapes(s.text).map((shape) => shape.event);
  return [
    Object.freeze({
      type: 'llm_output' as const,
      timestamp: new Date().toISOString(),
      content: s.text,
      fields: Object.freeze({ agent_output: s.text }),
    }),
  ];
}

function matchedRuleIds(engine: ATREngine, s: Sample): readonly string[] {
  const ids = new Set<string>();
  for (const ev of eventsFor(s)) for (const m of engine.evaluate(ev)) ids.add(m.rule.id);
  return [...ids].sort();
}

// ------------------------------------------------------------------ aggregation

interface Tally {
  attacks: number;
  detected: number;
  recall: number | null;
  benign: number;
  benign_flagged: number;
  benign_flag_rate: number | null;
}

function tally(samples: readonly Sample[], hits: ReadonlyMap<string, readonly string[]>): Tally {
  const attacks = samples.filter((s) => s.label === 'attack');
  const benign = samples.filter((s) => s.label === 'benign');
  const detected = attacks.filter((s) => (hits.get(s.id) ?? []).length > 0).length;
  const flagged = benign.filter((s) => (hits.get(s.id) ?? []).length > 0).length;
  return {
    attacks: attacks.length,
    detected,
    recall: attacks.length > 0 ? detected / attacks.length : null,
    benign: benign.length,
    benign_flagged: flagged,
    benign_flag_rate: benign.length > 0 ? flagged / benign.length : null,
  };
}

function groupBy<T>(xs: readonly T[], key: (x: T) => string): Map<string, T[]> {
  const out = new Map<string, T[]>();
  for (const x of xs) {
    const k = key(x);
    out.set(k, [...(out.get(k) ?? []), x]);
  }
  return out;
}

function laneReport(samples: readonly Sample[], hits: ReadonlyMap<string, readonly string[]>) {
  const byVendor: Record<string, Tally> = {};
  for (const [v, xs] of [...groupBy(samples, (s) => s.vendor)].sort()) byVendor[v] = tally(xs, hits);
  const byVendorCategory: Record<string, Record<string, Tally>> = {};
  for (const [v, xs] of [...groupBy(samples, (s) => s.vendor)].sort()) {
    byVendorCategory[v] = {};
    for (const [c, ys] of [...groupBy(xs, (s) => s.category)].sort()) byVendorCategory[v][c] = tally(ys, hits);
  }
  const byRole: Record<string, Tally> = {};
  for (const [r, xs] of [...groupBy(samples, (s) => s.role)].sort()) byRole[r] = tally(xs, hits);
  const missed = samples
    .filter((s) => s.label === 'attack' && (hits.get(s.id) ?? []).length === 0)
    .map((s) => ({ id: s.id, vendor: s.vendor, category: s.category, text_prefix: s.text.slice(0, 100) }));
  const benignFlagged = samples
    .filter((s) => s.label === 'benign' && (hits.get(s.id) ?? []).length > 0)
    .map((s) => ({ id: s.id, vendor: s.vendor, rules: hits.get(s.id), text_prefix: s.text.slice(0, 100) }));
  return { overall: tally(samples, hits), by_vendor: byVendor, by_vendor_category: byVendorCategory, by_role: byRole, missed_attacks: missed, benign_flagged: benignFlagged };
}

// ------------------------------------------------------------------ rule validation

const norm = (s: string): string =>
  s
    .replace(/[“”„]/g, '"')
    .replace(/[‘’]/g, "'")
    .replace(/\s+/g, ' ')
    .trim();

function tpText(tc: unknown): string | null {
  if (tc === null || typeof tc !== 'object') return null;
  const o = tc as Record<string, unknown>;
  for (const k of ['input', 'user_input', 'tool_response', 'content', 'agent_output', 'tool_args']) {
    if (typeof o[k] === 'string') return o[k] as string;
  }
  return null;
}

interface LegacyRow {
  sha256: string;
  status: string;
  claimed_source_file: string;
  text_prefix: string;
}

function loadLegacy(): { byNorm: Map<string, LegacyRow & { corpus: string }>; summary: Record<string, unknown> } {
  const byNorm = new Map<string, LegacyRow & { corpus: string }>();
  if (!existsSync(LEGACY_AUDIT_PATH)) return { byNorm, summary: { note: 'legacy-corpora-provenance.json absent' } };
  const audit = JSON.parse(readFileSync(LEGACY_AUDIT_PATH, 'utf-8')) as {
    corpora: Record<string, { corpus_file: string; samples: number; tally: Record<string, number>; checked_against: unknown }>;
  };
  const summary: Record<string, unknown> = {};
  for (const [vendor, c] of Object.entries(audit.corpora)) {
    summary[vendor] = { corpus_file: c.corpus_file, samples: c.samples, checked_against: c.checked_against, tally: c.tally };
    const corpus = JSON.parse(readFileSync(resolve(REPO_ROOT, c.corpus_file), 'utf-8')) as { attacks: { text: string }[] };
    const rows = (c as unknown as { samples_detail: LegacyRow[] }).samples_detail;
    corpus.attacks.forEach((a, i) => byNorm.set(norm(a.text), { ...rows[i], corpus: vendor }));
  }
  return { byNorm, summary };
}

function ruleValidation(
  rules: readonly ATRRule[],
  samples: readonly Sample[],
  laneHits: Readonly<Record<Lane, ReadonlyMap<string, readonly string[]>>>,
  laneRuleIds: Readonly<Record<Lane, ReadonlySet<string>>>,
) {
  const vendorByNorm = new Map(samples.map((s) => [norm(s.text), s] as const));
  const legacy = loadLegacy();
  const out: Record<string, unknown> = {};
  for (const [ruleId, cited] of Object.entries(VENDOR_IMPORT_RULES)) {
    const rule = rules.find((r) => r.id === ruleId);
    if (rule === undefined) {
      out[ruleId] = { error: 'rule not found in rules/' };
      continue;
    }
    const hunt = laneHits.hunt;
    const matchedAll = samples.filter((s) => (hunt.get(s.id) ?? []).includes(ruleId));
    const citedSamples = samples.filter((s) => s.label === 'attack' && cited.some((c) => c.vendor === s.vendor && c.category === s.category));
    const citedMatched = citedSamples.filter((s) => (hunt.get(s.id) ?? []).includes(ruleId));
    const tps = (rule.test_cases?.true_positives ?? []).map((tc) => tpText(tc)).filter((t): t is string => t !== null);
    const tpCorrespondence = tps.map((t) => {
      const nt = norm(t);
      const head = nt.replace(/[.\u2026 ]+$/, '').slice(0, 60);
      let relation: 'exact' | 'substring-of-vendor-case' | 'same-opening-as-vendor-case' | null = null;
      let v = vendorByNorm.get(nt);
      if (v) relation = 'exact';
      if (!v) {
        v = samples.find((s) => norm(s.text).includes(nt));
        if (v) relation = 'substring-of-vendor-case';
      }
      if (!v && head.length >= 40) {
        // several vendor cases can share an opening: take the one sharing the longest prefix with the TP
        const commonPrefix = (a: string, b: string): number => {
          let i = 0;
          while (i < a.length && i < b.length && a[i] === b[i]) i += 1;
          return i;
        };
        v = samples
          .filter((s) => norm(s.text).startsWith(head))
          .sort((a, b) => commonPrefix(norm(b.text), nt) - commonPrefix(norm(a.text), nt))[0];
        if (v) relation = 'same-opening-as-vendor-case';
      }
      const l = legacy.byNorm.get(nt);
      return {
        tp_prefix: t.slice(0, 90),
        relation_to_vendor_case: relation,
        vendor_test_case: v ? { id: v.id, vendor: v.vendor, category: v.category, pins: v.pins } : null,
        legacy_corpus_sample: l ? { corpus: l.corpus, claimed_source_file: l.claimed_source_file, provenance_status: l.status } : null,
      };
    });
    const sourceIds = [...new Set(tpCorrespondence.map((x) => x.vendor_test_case?.id).filter((x): x is string => x !== undefined))];
    const sourceMatched = sourceIds.filter((id) => (hunt.get(id) ?? []).includes(ruleId));
    out[ruleId] = {
      title: rule.title,
      status: rule.status,
      maturity: rule.maturity ?? null,
      loaded_in_lanes: LANES.filter((ln) => laneRuleIds[ln].has(ruleId)),
      cited_corpus: cited,
      cited_attack_cases: citedSamples.length,
      cited_attack_cases_matched_hunt: citedMatched.length,
      cited_matched_ids: citedMatched.map((s) => s.id),
      cited_unmatched: citedSamples
        .filter((s) => !citedMatched.includes(s))
        .map((s) => ({ id: s.id, vendor: s.vendor, category: s.category, text_prefix: s.text.slice(0, 100) })),
      all_vendor_matches_hunt: matchedAll.map((s) => ({ id: s.id, vendor: s.vendor, label: s.label, category: s.category, text_prefix: s.text.slice(0, 80) })),
      vendor_cases_behind_own_true_positives: sourceIds.length,
      vendor_cases_behind_own_true_positives_matched_hunt: sourceMatched.length,
      own_true_positives: tps.length,
      own_true_positives_that_are_vendor_cases: tpCorrespondence.filter((x) => x.relation_to_vendor_case === 'exact').length,
      own_true_positives_cut_or_edited_from_vendor_cases: tpCorrespondence.filter(
        (x) => x.relation_to_vendor_case !== null && x.relation_to_vendor_case !== 'exact',
      ).length,
      own_true_positives_detail: tpCorrespondence,
    };
  }
  return { rules: out, legacy_summary: legacy.summary };
}

// ------------------------------------------------------------------ in-sample checks

interface LaneRun {
  readonly hits: Map<string, readonly string[]>;
  readonly ruleIds: Set<string>;
  readonly ruleCount: number;
  readonly rules: readonly ATRRule[];
}

async function runLane(rulesDir: string, lane: Lane, samples: readonly Sample[]): Promise<LaneRun> {
  const engine = new ATREngine({ rulesDir, lane });
  const loaded = await engine.loadRules();
  if (loaded === 0) throw new Error(`${lane}: no rules loaded from ${rulesDir}`);
  if (engine.getLane() !== lane) throw new Error(`engine is in the ${engine.getLane()} lane, not ${lane}`);
  const rules = engine.getRules();
  return {
    hits: new Map(samples.map((s) => [s.id, matchedRuleIds(engine, s)] as const)),
    ruleIds: new Set(rules.filter((r) => rulesInLane([r], lane) === 1).map((r) => r.id)),
    ruleCount: rulesInLane(rules, lane),
    rules,
  };
}

/** One lane of an ablation, in the shape breakdown.lanes uses for the headline (detected / attacks / recall). */
function ablationLane(lane: Lane, run: LaneRun, samples: readonly Sample[]) {
  const t = tally(samples, run.hits);
  const byVendor: Record<string, Tally> = {};
  for (const [v, xs] of [...groupBy(samples, (s) => s.vendor)].sort()) byVendor[v] = tally(xs, run.hits);
  return {
    lane,
    detected: t.detected,
    attacks: t.attacks,
    recall: t.recall,
    rules_in_lane: run.ruleCount,
    benign: t.benign,
    benign_flagged: t.benign_flagged,
    by_vendor: byVendor,
  };
}

async function ablation(ids: readonly string[], description: string, samples: readonly Sample[]) {
  const { dir, removed } = rulesDirWithout(RULES_DIR, ids);
  const lanes: Record<string, ReturnType<typeof ablationLane>> = {};
  const runs = {} as Record<Lane, LaneRun>;
  for (const lane of LANES) {
    runs[lane] = await runLane(dir, lane, samples);
    lanes[lane] = ablationLane(lane, runs[lane], samples);
  }
  return { record: { description, removed_rule_ids: removed, lanes }, runs };
}

/** Rule-text and garak-full overlaps, and how many reference-ablation detections they account for. */
function overlaps(
  samples: readonly Sample[],
  namingIds: readonly string[],
  laneRuleIds: Readonly<Record<Lane, ReadonlySet<string>>>,
  reference: Readonly<Record<Lane, LaneRun>>,
) {
  const byId = new Map(samples.map((s) => [s.id, s] as const));
  const overlap = ruleTextOverlaps(loadRuleTexts(RULES_DIR), samples, SHINGLE_CHARS);
  const naming = new Set(namingIds);
  const rules = [...overlap].map(([ruleId, ids]) => ({
    rule_id: ruleId,
    names_a_vendor: naming.has(ruleId),
    loaded_in_lanes: LANES.filter((ln) => laneRuleIds[ln].has(ruleId)),
    attack_samples: ids.filter((id) => byId.get(id)?.label === 'attack'),
    benign_samples: ids.filter((id) => byId.get(id)?.label === 'benign'),
  }));
  const surviving = rules.filter((r) => !r.names_a_vendor);
  const attacksIn = (rs: typeof rules) => [...new Set(rs.flatMap((r) => r.attack_samples))].sort();
  const overlapOf = new Map(rules.map((r) => [r.rule_id, new Set([...r.attack_samples, ...r.benign_samples])] as const));
  const viaOverlap: Record<string, string[]> = {};
  for (const lane of LANES) {
    viaOverlap[lane] = samples
      .filter((s) => s.label === 'attack')
      .filter((s) => (reference[lane].hits.get(s.id) ?? []).some((r) => overlapOf.get(r)?.has(s.id) === true))
      .map((s) => s.id);
  }
  const garak = vendorSamplesInCorpus(
    samples.filter((s) => s.label === 'attack').map((s) => ({ id: s.id, text: s.text, vendor: s.vendor })),
    GARAK_FULL_DIR,
  );
  const garakIds = [...new Set(garak.map((g) => g.sample_id))].sort();
  const garakByVendor: Record<string, number> = {};
  for (const id of garakIds) {
    const v = byId.get(id)!.vendor;
    garakByVendor[v] = (garakByVendor[v] ?? 0) + 1;
  }
  const garakDetected: Record<string, number> = {};
  for (const lane of LANES) {
    garakDetected[lane] = garakIds.filter((id) => (reference[lane].hits.get(id) ?? []).length > 0).length;
  }
  return {
    method:
      `rule_text: every string in each rule's parsed YAML (test cases, patterns, descriptions) compared with every ` +
      `sample after folding whitespace and typographic quotes and lower-casing; a rule overlaps a sample when they ` +
      `share a run of ${SHINGLE_CHARS} characters. garak_full: for each vendor attack sample, the prompt of ` +
      `data/test-corpora/garak-full/*.json holding the largest share of the sample's distinct ${SHINGLE_CHARS}-character ` +
      'folded runs; listed when that share is at least 0.5 (contained = the whole sample occurs in the prompt; ' +
      'shared-template = a jailbreak template shared with the payload slot filled differently).',
    rule_text: {
      rules_overlapping: rules.length,
      rules_overlapping_not_naming_a_vendor: surviving.length,
      attack_samples_overlapped: attacksIn(rules).length,
      attack_samples_overlapped_by_rules_not_naming_a_vendor: attacksIn(surviving).length,
      reference_ablation_detections_by_an_overlapping_rule: Object.fromEntries(
        LANES.map((ln) => [ln, { count: viaOverlap[ln]!.length, sample_ids: viaOverlap[ln] }]),
      ),
      rules,
    },
    garak_full: {
      attack_samples_found: garakIds.length,
      by_vendor: garakByVendor,
      by_file: Object.fromEntries(
        [...new Set(garak.map((g) => g.file))].sort().map((f) => [f, garak.filter((g) => g.file === f).length]),
      ),
      reference_ablation_detections_among_them: garakDetected,
      occurrences: garak,
    },
  };
}

// ------------------------------------------------------------------ main

const pct = (x: number | null): string => (x === null ? 'n/a' : `${(x * 100).toFixed(1)}%`);

async function main(): Promise<void> {
  const samples = loadSamples();
  const attacks = samples.filter((s) => s.label === 'attack');
  const manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf-8')) as Record<string, unknown>;

  const laneHits = {} as Record<Lane, Map<string, readonly string[]>>;
  const laneRuleIds = {} as Record<Lane, Set<string>>;
  const laneRuleCount = {} as Record<Lane, number>;
  let huntRules: readonly ATRRule[] = [];
  for (const lane of LANES) {
    const run = await runLane(RULES_DIR, lane, samples);
    if (lane === 'hunt') huntRules = run.rules;
    laneRuleCount[lane] = run.ruleCount;
    laneRuleIds[lane] = run.ruleIds;
    laneHits[lane] = run.hits;
  }

  const namingIds = rulesNaming(RULES_DIR, VENDOR_NAMING_PATTERN);
  const reference = await ablation(
    namingIds,
    `every rule whose YAML text matches ${VENDOR_NAMING_PATTERN} (promptfoo, llm-guard, NeMo / NeMo Guardrails, ` +
      'the vendor-corpus-import author tag)',
    samples,
  );
  const overlapReport = overlaps(samples, namingIds, laneRuleIds, reference.runs);
  const sharingIds = overlapReport.rule_text.rules.map((r) => r.rule_id);
  const stricter = await ablation(
    [...new Set([...namingIds, ...sharingIds])].sort(),
    `the rules removed by ${ABLATION_REFERENCE}, and every rule whose YAML shares a ${SHINGLE_CHARS}-character ` +
      'run with a vendor sample (breakdown.overlaps.rule_text)',
    samples,
  );

  const lanes: Record<string, unknown> = {};
  for (const lane of LANES) lanes[lane] = { rules_in_lane: laneRuleCount[lane], ...laneReport(samples, laneHits[lane]) };

  const hunt = tally(samples, laneHits.hunt);
  const enforce = tally(samples, laneHits.enforce);
  const tp = hunt.detected;
  const fn = hunt.attacks - tp;
  const fp = hunt.benign_flagged;
  const tn = hunt.benign - fp;
  const recall = tp / hunt.attacks;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  const validation = ruleValidation(huntRules, samples, laneHits, laneRuleIds);

  console.log(`vendor-guardrail-suites: ${samples.length} samples (${attacks.length} attack / ${hunt.benign} benign)`);
  for (const lane of LANES) {
    const t = tally(samples, laneHits[lane]);
    console.log(`  ${lane.padEnd(7)} rules=${laneRuleCount[lane]}  recall ${t.detected}/${t.attacks} = ${pct(t.recall)}  benign flagged ${t.benign_flagged}/${t.benign}`);
    for (const [v, xs] of [...groupBy(samples, (s) => s.vendor)].sort()) {
      const tv = tally(xs, laneHits[lane]);
      console.log(`      ${v.padEnd(16)} ${tv.detected}/${tv.attacks} = ${pct(tv.recall)}   benign ${tv.benign_flagged}/${tv.benign}`);
    }
  }
  for (const [id, r] of Object.entries(validation.rules)) {
    const x = r as {
      cited_attack_cases: number;
      cited_attack_cases_matched_hunt: number;
      vendor_cases_behind_own_true_positives: number;
      vendor_cases_behind_own_true_positives_matched_hunt: number;
      own_true_positives: number;
      own_true_positives_that_are_vendor_cases: number;
      own_true_positives_cut_or_edited_from_vendor_cases: number;
      loaded_in_lanes: string[];
    };
    console.log(
      `  ${id}: cited-category vendor cases matched ${x.cited_attack_cases_matched_hunt}/${x.cited_attack_cases} (hunt); ` +
        `vendor cases behind its own TPs matched ${x.vendor_cases_behind_own_true_positives_matched_hunt}/${x.vendor_cases_behind_own_true_positives}; ` +
        `own TPs: ${x.own_true_positives_that_are_vendor_cases} exact vendor cases, ` +
        `${x.own_true_positives_cut_or_edited_from_vendor_cases} cut/edited from one, of ${x.own_true_positives}; lanes ${x.loaded_in_lanes.join(',')}`,
    );
  }
  for (const [name, a] of [[ABLATION_REFERENCE, reference.record], ['without_rules_naming_or_sharing_text', stricter.record]] as const) {
    console.log(`  ${name}: ${a.removed_rule_ids.length} rules removed`);
    for (const lane of LANES) {
      const x = a.lanes[lane]!;
      const per = Object.entries(x.by_vendor).map(([v, t]) => `${v} ${t.detected}/${t.attacks}`).join(', ');
      console.log(`      ${lane.padEnd(7)} ${x.detected}/${x.attacks} = ${pct(x.recall)}  (${per})  benign flagged ${x.benign_flagged}/${x.benign}`);
    }
  }
  const rt = overlapReport.rule_text;
  console.log(
    `  overlaps: ${rt.rules_overlapping} rules share ${SHINGLE_CHARS} chars with a sample ` +
      `(${rt.rules_overlapping_not_naming_a_vendor} do not name a vendor; ${rt.attack_samples_overlapped_by_rules_not_naming_a_vendor} attack samples); ` +
      `${overlapReport.garak_full.attack_samples_found} vendor attack samples occur in garak-full ${JSON.stringify(overlapReport.garak_full.by_vendor)}`,
  );
  if (DRY_RUN) return;

  const { measurementPath } = writeMeasurement(
    {
      source: 'vendor-guardrail-suites',
      source_version: 'pinned-2026-10-19',
      source_url: 'data/test-corpora/vendor-guardrail-suites/manifest.json',
      samples: samples.length,
      metrics: { recall, precision, f1, fp_rate: hunt.benign > 0 ? fp / hunt.benign : 0 },
      confusion: { tp, fp, tn, fn },
      breakdown: {
        enforce_lane: {
          lane: 'enforce',
          detected: enforce.detected,
          attacks: enforce.attacks,
          recall: enforce.detected / enforce.attacks,
          rules_in_lane: laneRuleCount.enforce,
          note: ENFORCE_LANE_NOTE,
        },
        corpus: {
          samples_file: 'data/test-corpora/vendor-guardrail-suites/samples.jsonl',
          samples_sha256: manifest.samples_sha256,
          attacks_by_vendor: manifest.attacks_by_vendor,
          benign_by_vendor: manifest.benign_by_vendor,
          by_vendor_category: manifest.by_vendor_category,
          pins: (manifest.sources as { vendor: string; repo: string; license: string; pins: unknown }[]).map((v) => ({
            vendor: v.vendor,
            repo: v.repo,
            license: v.license,
            pins: v.pins,
          })),
        },
        detection_predicate:
          'role=input: src/corpus-event.ts promptChannelShapes (llm_input + tool_response); role=output: one llm_output event ' +
          '(agent_output). Detected = at least one rule match on at least one event. Same predicate for attacks, benign and every lane.',
        lanes,
        in_sample_ablation: {
          note:
            'Ablation reference, not an out-of-sample result. Rules whose YAML names promptfoo, llm-guard or NeMo ' +
            `Guardrails, or carries the vendor-corpus-import author tag, were written from these suites. ${ABLATION_REFERENCE} ` +
            're-measures every lane without them; it is the figure to cite beside the headline. It approximates an ' +
            'out-of-sample figure without guaranteeing one: rules that do not name a vendor can still carry vendor text ' +
            '(breakdown.overlaps.rule_text), and some vendor samples also occur in garak-full, a corpus other rules were ' +
            'mined from (breakdown.overlaps.garak_full). without_rules_naming_or_sharing_text also removes every rule ' +
            `whose YAML shares a ${SHINGLE_CHARS}-character run with a vendor sample.`,
          reference: ABLATION_REFERENCE,
          [ABLATION_REFERENCE]: reference.record,
          without_rules_naming_or_sharing_text: stricter.record,
        },
        overlaps: overlapReport,
        precision_not_citable: {
          reason:
            'The vendors ship 20 benign test cases (llm-guard 16, NeMo Guardrails 4, promptfoo none). That is too few ' +
            'for a precision or false-positive-rate claim: metrics.precision and metrics.fp_rate are the bare ratios ' +
            'the schema requires, and data/stats.json projects them as null. Cite the counts instead.',
          benign_samples: hunt.benign,
          flagged_by_lane: Object.fromEntries(LANES.map((ln) => [ln, tally(samples, laneHits[ln]).benign_flagged])),
        },
        vendor_import_rules: validation.rules,
        legacy_2026_05_12_corpora_provenance: validation.legacy_summary,
      },
      notes:
        'Vendor guardrail test suites (protectai/llm-guard, NVIDIA-NeMo/Guardrails, promptfoo/promptfoo) extracted ' +
        'deterministically from pinned commits; see manifest.json. metrics/confusion are the hunt lane over all ' +
        `${samples.length} samples; fp_rate and precision use only the ${hunt.benign} benign test cases the vendors ` +
        'ship (llm-guard and NeMo; promptfoo ships none) and are too few to support a precision claim ' +
        '(breakdown.precision_not_citable; data/stats.json carries null). breakdown.lanes carries hunt, alert and ' +
        `enforce per vendor and per category. breakdown.in_sample_ablation.${ABLATION_REFERENCE} is the ablation ` +
        'reference to cite beside the headline; breakdown.overlaps states how far even that is from out-of-sample.',
    },
    { force: FORCE },
  );
  console.log(`Measurement: ${measurementPath}`);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
