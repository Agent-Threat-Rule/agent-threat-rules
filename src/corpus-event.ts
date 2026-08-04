/**
 * corpus-event.ts — the ONE way a text sample becomes engine events.
 *
 * WHY THIS FILE EXISTS
 *
 * An ATR rule condition names a field (`field: tool_args`). The engine resolves
 * that name against the event it is given (src/engine.ts resolveField). If the
 * harness that measures false positives builds an event that cannot resolve the
 * field, every condition on that field silently evaluates to false: the rule
 * cannot fire, cannot be counted as an FP, and the gate reports it CLEAN. That
 * is a zero-measurement PASS — indistinguishable, in the output, from a rule
 * that was measured and found innocent.
 *
 * That is exactly what happened. Five harnesses each carried a private copy of
 *
 *     { type: "mcp_exchange",
 *       fields: { tool_name, tool_input, tool_response, user_input } }
 *
 * which resolves NONE of tool_args / agent_output / agent_message /
 * tool_description. 40 rules declare `field: tool_args` (3 of them
 * maturity: stable, i.e. the enforce/auto-block lane) and their tool_args
 * conditions had never been measured against a single benign sample.
 *
 * THE RULE THIS FILE ENFORCES
 *
 * True positives and benign samples MUST be pushed through the IDENTICAL shape
 * set. Measuring TP on a wide shape and FP on a narrow one manufactures a 0-FP
 * result: the rule earns its detection credit on a shape that is never charged
 * for its false positives. Whatever shape a rule is allowed to fire on is the
 * shape it must also survive the benign corpus on. Import this module from both
 * sides of any measurement rather than hand-rolling an event.
 *
 * ENCODING FIDELITY
 *
 * Production does not hand the engine one flat string. src/hook-handler.ts
 * builds `tool_args: JSON.stringify(toolInput)` — a JSON-ENCODED string, where a
 * newline is the two characters `\` `n`, not U+000A. A pattern can match one
 * encoding and not the other (a real FP was found this way: a JSON-escaped `\n`
 * read as a shell line-continuation and joined two independent commands). So the
 * sample is presented in both the raw and the JSON-encoded form, and each field
 * receives the encoding production would actually put there — no more, no less.
 *
 * @module scripts/lib/corpus-event
 */
import type { AgentEvent } from "./types.js";

/**
 * Placeholder tool name — deliberately NOT the sample text.
 *
 * The corpus is a corpus of documents; it contains no tool names. In production
 * `tool_name` holds a short identifier ("Bash", "mcp__github__create_issue"),
 * and the rules that key on it match short verbs — `(?i)(exec|execute|shell|
 * bash|cmd|eval)`, `(?i)(delete|remove|drop|truncate)`, `(?i)(pay|payment|
 * transfer)`. Pouring a whole SKILL.md into that field would match nearly every
 * document and report a flood of false positives that cannot occur in
 * production, which is worse than not measuring: fabricated FPs push a
 * maintainer to weaken a rule that is correct.
 *
 * So tool_name is pinned to a constant. Conditions on it are therefore NOT
 * measured, and that is reported explicitly (see UNMEASURABLE_FIELDS) instead of
 * being passed off as clean. Frozen at the legacy value so the historical shape
 * is reproduced byte for byte and old FP counts stay comparable.
 */
export const CORPUS_TOOL_NAME = "corpus-sample";

/** Name of a shape, for reporting which presentation produced a match. */
export type CorpusShapeName =
  | "wide-raw"
  | "pre-tool-json-arg"
  | "pre-tool-json-both"
  | "post-tool-json"
  // Production prompt channels — see promptChannelShapes().
  | "llm-input"
  | "tool-response";

export interface CorpusShape {
  readonly name: CorpusShapeName;
  readonly event: AgentEvent;
}

/**
 * Every field name a sample's text is actually poured into by some shape.
 * A condition on any of these IS measured. Kept in sync with the shapes below
 * by tests/corpus-event-shapes.test.ts, which proves reachability through the
 * real engine rather than trusting this list.
 */
export const MEASURED_FIELDS: readonly string[] = Object.freeze([
  "content",
  "user_input",
  "agent_output",
  "agent_message",
  "tool_response",
  "tool_args",
  "tool_input",
  "tool_description",
]);

/**
 * Field names the engine can resolve but that a TEXT corpus cannot honestly
 * fill, with the reason. A rule whose conditions live here is UNMEASURED by
 * this harness — callers must say so out loud rather than report it clean.
 */
export const UNMEASURABLE_FIELDS: ReadonlyMap<string, string> = Object.freeze(
  new Map([
    [
      "tool_name",
      "production tool_name is a short identifier, not a document; pouring corpus " +
        "text in would fabricate FPs on rules that are correct in production",
    ],
    [
      "metric",
      "behavioral metric is a number over a time window, not text; the sync " +
        "evaluate() path cannot maintain the window at all",
    ],
  ]),
);

/** A trace-method rule needs event.trace (a span DAG), which text cannot supply. */
export const TRACE_FIELD_PREFIX = "trace.";
/** A behavioral condition needs a numeric metric window, which text cannot supply. */
export const BEHAVIORAL_FIELD_PREFIX = "behavioral.";

/** True when a condition field can be measured with a text corpus. */
export function isMeasurableField(field: string): boolean {
  if (field.startsWith(TRACE_FIELD_PREFIX)) return false;
  if (field.startsWith(BEHAVIORAL_FIELD_PREFIX)) return false;
  return MEASURED_FIELDS.includes(field);
}

/** Why a field cannot be measured — a sentence, or null when it can be. */
export function unmeasurableReason(field: string): string | null {
  if (isMeasurableField(field)) return null;
  if (field.startsWith(TRACE_FIELD_PREFIX)) {
    return "trace-method rule: needs an event.trace span DAG, which a text corpus cannot supply";
  }
  if (field.startsWith(BEHAVIORAL_FIELD_PREFIX)) {
    return "behavioral condition: needs a numeric metric window, which a text corpus cannot supply";
  }
  return (
    UNMEASURABLE_FIELDS.get(field) ??
    "unknown field name — the engine resolves it from event.metadata, which this " +
      "harness does not populate; no shape carries the sample into it"
  );
}

const now = (): string => new Date().toISOString();

/**
 * Shape 1 — WIDE, RAW. type `mcp_exchange` so the engine applies NO source-type
 * filtering (EVENT_TYPE_TO_SOURCE has no mcp_exchange entry), which means every
 * rule is evaluated regardless of its declared agent_source.type. Every
 * content-bearing field carries the raw sample.
 *
 * This is a strict superset of the legacy harness shape (same type, same
 * tool_name, same tool_input/tool_response/user_input), so no FP that the old
 * shape counted can disappear — the change can only reveal, never hide.
 */
function wideRaw(text: string): AgentEvent {
  return Object.freeze({
    type: "mcp_exchange" as const,
    timestamp: now(),
    content: text,
    fields: Object.freeze({
      tool_name: CORPUS_TOOL_NAME,
      tool_input: text,
      tool_response: text,
      user_input: text,
      agent_output: text,
      agent_message: text,
      tool_description: text,
      tool_args: text,
      content: text,
    }),
  });
}

/**
 * Shape 2 — PreToolUse where the payload IS a string tool argument
 * (`Write`, `Edit`, ...). src/hook-handler.ts:52-61 verbatim: `content` stays
 * raw because toolInput.content is a string, while `tool_args` is the
 * JSON-ENCODED whole argument object. This is the shape that exposes patterns
 * which only match escaped text.
 */
function preToolJsonArg(text: string): AgentEvent {
  const toolInput = { content: text };
  return Object.freeze({
    type: "tool_call" as const,
    timestamp: now(),
    content: toolInput.content,
    fields: Object.freeze({
      tool_name: CORPUS_TOOL_NAME,
      tool_args: JSON.stringify(toolInput),
      content: toolInput.content,
    }),
  });
}

/**
 * Shape 3 — PreToolUse where the payload is NOT under a `content` key
 * (`Bash` and most MCP tools). src/hook-handler.ts:53-55 then falls back to
 * JSON.stringify for `content` too, so BOTH content and tool_args are encoded.
 */
function preToolJsonBoth(text: string): AgentEvent {
  const toolInput = { command: text };
  const encoded = JSON.stringify(toolInput);
  return Object.freeze({
    type: "tool_call" as const,
    timestamp: now(),
    content: encoded,
    fields: Object.freeze({
      tool_name: CORPUS_TOOL_NAME,
      tool_args: encoded,
      content: encoded,
    }),
  });
}

/**
 * Shape 4 — PostToolUse. src/hook-handler.ts:64-69: the tool has already run,
 * its output lands in tool_response, and tool_args is still the JSON-encoded
 * argument object.
 *
 * This shape is NOT redundant with shapes 2-3, and the reason is the engine's
 * source-type filter. A `tool_call` event only evaluates rules whose
 * agent_source.type is tool_call or mcp_exchange. A `tool_response` event maps
 * to source mcp_exchange AND additionally admits llm_io rules (the engine's
 * indirect-prompt-injection route: poisoned tool output is the channel those
 * rules exist for). Four rules declare `field: tool_args` with
 * `agent_source.type: llm_io`; without this shape the JSON-encoded encoding of
 * tool_args would never be measured for them.
 */
function postToolJson(text: string): AgentEvent {
  const toolInput = { output: text };
  const encoded = JSON.stringify(toolInput);
  return Object.freeze({
    type: "tool_response" as const,
    timestamp: now(),
    content: encoded,
    fields: Object.freeze({
      tool_name: CORPUS_TOOL_NAME,
      tool_args: encoded,
      tool_response: text,
      content: encoded,
    }),
  });
}

/**
 * The canonical shape set. Callers must ALSO run engine.scanSkill(text) — the
 * SKILL.md path is a separate engine entry point, not an event shape.
 *
 * Two axes have to be covered, and missing either one hides false positives:
 *   - ENCODING: raw (shape 1) vs JSON-encoded (shapes 2-4), because a pattern
 *     can match one and not the other.
 *   - RULE ADMISSION: the engine filters rules by agent_source.type against the
 *     event type. mcp_exchange (shape 1) is filtered against nothing, so every
 *     rule runs; tool_call (2-3) admits tool_call + mcp_exchange rules;
 *     tool_response (4) admits mcp_exchange + llm_io rules.
 *
 * Deliberately omitted: `llm_input` / `llm_output` / `multi_agent_message`
 * events. Shape 1 already carries user_input / agent_output / agent_message
 * explicitly and is admitted for every rule, so those types can only narrow.
 */
export function corpusShapes(text: string): readonly CorpusShape[] {
  return Object.freeze([
    Object.freeze({ name: "wide-raw" as const, event: wideRaw(text) }),
    Object.freeze({ name: "pre-tool-json-arg" as const, event: preToolJsonArg(text) }),
    Object.freeze({ name: "pre-tool-json-both" as const, event: preToolJsonBoth(text) }),
    Object.freeze({ name: "post-tool-json" as const, event: postToolJson(text) }),
  ]);
}

/** Human-readable list of the shapes, for harness banners. */
export function shapeNames(): readonly string[] {
  return corpusShapes("").map((s) => s.name);
}

// ---------------------------------------------------------------------------
// A raw PROMPT corpus is not a document corpus
// ---------------------------------------------------------------------------

/**
 * The two channels a raw adversarial PROMPT (garak, PINT, academic jailbreak
 * corpora) can actually arrive through in production, as built by
 * src/hook-handler.ts:
 *
 *   - `llm_input`     — the human typed it. Maps to source `llm_io`, so only
 *                       llm_io rules are admitted.
 *   - `tool_response` — a tool / MCP / RAG result carried it in (indirect
 *                       injection). Maps to source `mcp_exchange`, and the
 *                       engine additionally admits llm_io rules on it.
 *
 * WHY THIS IS SEPARATE FROM `corpusShapes()`
 *
 * `corpusShapes()` exists for a DOCUMENT corpus measured for false positives,
 * and it is deliberately as wide as the engine allows — including
 * `engine.scanSkill()`, the SKILL.md entry point. Scoring a garak jailbreak
 * prompt through scanSkill() credits detections on a channel that prompt never
 * travels, which inflates recall on a corpus that can never pay a false
 * positive back (garak is 100% adversarial, so precision is 1 by construction
 * and nothing charges the wide shape for its FPs).
 *
 * So: FP measurement uses the widest honest shape set; a pure-recall prompt
 * corpus uses the production channels. Both live in this module so no harness
 * hand-rolls a third one — the mistake this file was written to end.
 *
 * WHAT THIS REPLACED
 *
 * Four eval scripts built `{ type: 'llm_io', ... }`. `llm_io` is a rule
 * SOURCE, not an `AgentEventType` (see src/types.ts). `EVENT_TYPE_TO_SOURCE`
 * has no entry for it, so `eventSourceType` came out `undefined` and
 * src/engine.ts skipped source-type filtering entirely — every rule of every
 * source ran against an event that carried only `user_input`. That is not the
 * narrow llm_input channel those scripts documented themselves as measuring.
 * `tsc` would have caught it on the first run; tsconfig.json never included
 * `scripts/`.
 */
export function promptChannelShapes(text: string): readonly CorpusShape[] {
  const ts = now();
  return Object.freeze([
    Object.freeze({
      name: "llm-input" as const,
      event: Object.freeze({
        type: "llm_input" as const,
        timestamp: ts,
        content: text,
        fields: Object.freeze({ user_input: text }),
      }),
    }),
    Object.freeze({
      name: "tool-response" as const,
      event: Object.freeze({
        type: "tool_response" as const,
        timestamp: ts,
        content: text,
        fields: Object.freeze({ tool_response: text }),
      }),
    }),
  ]) as readonly CorpusShape[];
}

/**
 * True when `text` trips at least one rule on either production prompt channel.
 * The one way a prompt-corpus harness decides "detected".
 */
export function detectedOnPromptChannels(engine: ScannableEngine, text: string): boolean {
  for (const shape of promptChannelShapes(text)) {
    if (engine.evaluate(shape.event).length > 0) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// The one way a harness turns a sample into matched rule ids
// ---------------------------------------------------------------------------

/**
 * The same event, re-typed so the engine's source-type filter admits every rule.
 *
 * src/engine.ts maps an event type to an ATR source type (EVENT_TYPE_TO_SOURCE)
 * and then skips every rule whose `agent_source.type` differs. `mcp_exchange`
 * has NO entry in that map, so an mcp_exchange event is filtered against
 * nothing — that is precisely why shape 1 above uses it.
 *
 * This helper isolates that single effect for a caller that already holds an
 * event and wants to know how much of a measurement gap is rule ADMISSION as
 * opposed to field POURING. It changes nothing else: same content, same fields,
 * so a rule that newly fires here fires on the caller's own presentation of the
 * sample, not on a fabricated one.
 *
 * Use it ALONGSIDE the original event, never instead of it. Re-typing drops the
 * type-specific aliases in resolveField (an llm_input event resolves
 * `user_input` from event.content; an mcp_exchange event does not), so the pair
 * {original, sourceAgnostic(original)} is a strict superset of the original and
 * the widening can only reveal matches, never hide them.
 */
export function sourceAgnosticEvent(event: AgentEvent): AgentEvent {
  return Object.freeze({ ...event, type: "mcp_exchange" as const });
}

/**
 * The slice of ATREngine a corpus scan needs. Structural on purpose: this module
 * stays free of a concrete engine import so the shape set can be reasoned about
 * (and unit-tested) without loading the engine.
 */
export interface ScannableEngine {
  evaluate(event: AgentEvent): readonly { readonly rule: { readonly id: string } }[];
  scanSkill(text: string): readonly { readonly rule: { readonly id: string } }[];
}

/**
 * Every rule id a sample matches: the canonical shape set PLUS scanSkill().
 *
 * Both halves are mandatory. scanSkill() is a separate engine entry point (the
 * `pga scan` path), not an event shape, and rules with `scan_target: skill`
 * reach production through it alone — a harness that only calls evaluate() would
 * score them clean without reading them.
 *
 * The converse is equally true and much less obvious: the scanSkill() half is a
 * no-op for most of the corpus. Its compound gate is unreachable for every
 * `condition: any` rule that is not `scan_target: skill|both`, so counting it
 * among the shapes does NOT mean a rule was measured on it. Ask
 * skillPathCoverage() which ones the skill path never asked about, and say so.
 *
 * Counted PER SAMPLE, not per shape: a document that trips a rule on three
 * shapes is one false positive, not three. Every harness that measures FP, TP or
 * coverage must go through this function, so a rule can never earn its detection
 * credit on a wider presentation than the one it pays its false positives on.
 */
export function matchedRuleIds(engine: ScannableEngine, text: string): ReadonlySet<string> {
  const matched = new Set<string>();
  for (const shape of corpusShapes(text)) {
    for (const m of engine.evaluate(shape.event)) matched.add(m.rule.id);
  }
  for (const m of engine.scanSkill(text)) matched.add(m.rule.id);
  return matched;
}

// ---------------------------------------------------------------------------
// Coverage: which of a rule's conditions this harness can actually measure
// ---------------------------------------------------------------------------

/** Minimal view of a rule — avoids importing the full ATRRule type surface. */
export interface RuleLike {
  readonly id: string;
  readonly status?: string;
  readonly maturity?: string;
  readonly tags?: { readonly scan_target?: unknown };
  readonly detection?: {
    readonly method?: string;
    readonly condition?: string;
    readonly conditions?: unknown;
    readonly semantic?: { readonly fallback_method?: unknown };
  };
}

/** Every field name a rule's conditions declare, in declaration order. */
export function conditionFields(rule: RuleLike): readonly string[] {
  const conds = rule.detection?.conditions;
  const list = Array.isArray(conds)
    ? conds
    : conds !== null && typeof conds === "object"
      ? Object.values(conds as Record<string, unknown>)
      : [];
  const out: string[] = [];
  for (const c of list) {
    if (c === null || typeof c !== "object") continue;
    const field = (c as { field?: unknown }).field;
    if (typeof field === "string" && !out.includes(field)) out.push(field);
  }
  return out;
}

export interface FieldCoverage {
  readonly ruleId: string;
  /** Declared fields this harness cannot pour the sample into. */
  readonly unmeasured: readonly string[];
  /**
   * True when NOTHING about this rule was measured — either no declared field is
   * measurable, or the rule ANDs its conditions so a single unmeasurable field
   * makes the whole rule unable to fire.
   */
  readonly zeroMeasurement: boolean;
}

/** Rules whose conditions this harness cannot fully measure. Clean rules omitted. */
export function fieldCoverage(rules: readonly RuleLike[]): readonly FieldCoverage[] {
  const out: FieldCoverage[] = [];
  for (const rule of rules) {
    const fields = conditionFields(rule);
    const unmeasured = fields.filter((f) => !isMeasurableField(f));
    const method = rule.detection?.method;
    const methodBlind = method === "trace" || method === "behavioral" || method === "signature";
    if (unmeasured.length === 0 && !methodBlind) continue;
    const expr = (rule.detection?.condition ?? "any").toLowerCase();
    const anyOf = expr === "any" || expr === "or";
    const measurable = fields.length - unmeasured.length;
    out.push(
      Object.freeze({
        ruleId: rule.id,
        unmeasured: Object.freeze(unmeasured),
        zeroMeasurement: methodBlind || measurable === 0 || (!anyOf && unmeasured.length > 0),
      }),
    );
  }
  return Object.freeze(out);
}

// ---------------------------------------------------------------------------
// Coverage, second axis: a rule the engine refuses to run at all
// ---------------------------------------------------------------------------

/**
 * Statuses src/engine.ts drops BEFORE the lane gate, on both evaluation paths:
 *
 *     if (rule.status === 'deprecated' || rule.status === 'draft') continue;
 *     if (!this.passesLane(rule)) continue;
 *
 * The order is the whole problem. `maturity` decides the lane; `status` decides
 * whether the rule exists at all. A rule can therefore carry `maturity: stable`
 * — the enforce lane, auto-block, no human in the loop — while `status: draft`
 * keeps the engine from ever evaluating it. Seven rules on main are in exactly
 * that state today.
 *
 * For an FP harness the consequence is the same disease fieldCoverage exists to
 * name: the rule cannot fire, so it cannot be counted as a false positive, so
 * the gate reports it CLEAN. Nothing in a field-based coverage check can see it,
 * because every field the rule declares is perfectly measurable — the sample
 * simply never reaches the rule.
 *
 * Kept honest by tests/corpus-event-shapes.test.ts, which parses the status
 * comparisons out of src/engine.ts rather than trusting this list.
 */
export const INERT_STATUSES: ReadonlySet<string> = Object.freeze(
  new Set(["draft", "deprecated"]),
);

/** Rule maturities that put a rule in the enforce (auto-block) lane. */
export const ENFORCE_LANE_MATURITIES: ReadonlySet<string> = Object.freeze(
  new Set(["stable", "production"]),
);

/** True when the engine skips this status outright, in every lane. */
export function isInertStatus(status: string | undefined): boolean {
  return status !== undefined && INERT_STATUSES.has(status.trim().toLowerCase());
}

/** Why a status makes a rule unmeasurable — a sentence, or null when it does not. */
export function inertStatusReason(status: string | undefined): string | null {
  if (!isInertStatus(status)) return null;
  const s = String(status).trim().toLowerCase();
  return (
    `status: ${s} — src/engine.ts skips this status on both evaluation paths, ` +
    `before the lane gate, so the rule cannot fire on any sample. Its 0 FP is ` +
    `the absence of a measurement, not the presence of precision.`
  );
}

export interface StatusGap {
  readonly ruleId: string;
  /** The normalised inert status that stopped the rule from being evaluated. */
  readonly status: string;
  /** The rule's declared maturity, so a caller can say how bad this is. */
  readonly maturity: string | null;
  /** True when the rule also claims the enforce (auto-block) lane. */
  readonly claimsEnforceLane: boolean;
  readonly reason: string;
}

/**
 * Rules the engine will not evaluate at all. Measurable rules are omitted.
 *
 * Unlike an unmeasurABLE field (no benign corpus can supply a tool_name; a text
 * corpus has no span DAG), this one has a remedy that is always available and is
 * one line long: flip the status, or drop the maturity out of the enforce lane.
 * That difference is why callers are expected to FAIL on this rather than merely
 * print it — see the exit-code note in scripts/gate-promotion-fp.ts.
 */
export function statusCoverage(rules: readonly RuleLike[]): readonly StatusGap[] {
  const out: StatusGap[] = [];
  for (const rule of rules) {
    if (!isInertStatus(rule.status)) continue;
    const status = String(rule.status).trim().toLowerCase();
    const maturity = typeof rule.maturity === "string" ? rule.maturity.trim().toLowerCase() : null;
    out.push(
      Object.freeze({
        ruleId: rule.id,
        status,
        maturity,
        claimsEnforceLane: maturity !== null && ENFORCE_LANE_MATURITIES.has(maturity),
        reason: inertStatusReason(status) ?? "",
      }),
    );
  }
  return Object.freeze(out);
}

// ---------------------------------------------------------------------------
// Coverage, third axis: the SKILL.md path evaluates almost no rules
// ---------------------------------------------------------------------------

/**
 * matchedRuleIds() runs four evaluate() shapes AND engine.scanSkill(), and the
 * gate prints `shapes = wide-raw, ..., skill`. That banner reads as "every rule
 * you are gating was offered to the skill path". For 645 of the 780 rules on
 * main that is false, and not by a little: they cannot produce a match on that
 * path for ANY input whatsoever.
 *
 * THE MECHANISM (src/engine.ts, evaluateRaw / evaluateAsync)
 *
 * scanSkill() builds an event with `scanContext: 'skill'`. In that context the
 * engine skips source-type filtering — every rule is evaluated — and then
 * applies a compound gate to any rule NOT declared for skill scanning:
 *
 *     if (isSkillContext && rule.tags.scan_target !== 'skill'
 *                        && rule.tags.scan_target !== 'both') {
 *       const totalConds = Number(rule.detection?.conditions?.length ?? 1);
 *       const minRequired = Math.max(2, Math.ceil(totalConds * 0.3));
 *       if ((matchResult.matchedConditions?.length ?? 0) < minRequired) continue;
 *     }
 *
 * The comment above it describes a graded threshold ("30%+ of conditions").
 * `matchedConditions` is produced by evaluateArrayConditions, which for
 * `condition: any` SHORT-CIRCUITS:
 *
 *     if (result) { matchedConditionIndices.push(i); if (isAny) break; }
 *
 * So for an any-mode rule `matchedConditions.length` is 1 whenever the rule
 * matches at all, and 0 otherwise. It is never 2. `minRequired` is never below
 * 2. 776 of the 780 rules on main declare `condition: any`. The threshold is
 * therefore not a threshold — it is an unconditional reject, and the effective
 * policy of the SKILL.md path is "only `scan_target: skill|both` rules run".
 *
 * That policy is defensible and it is load-bearing (measured 2026-08-05: making
 * the threshold reachable takes the 466-sample benign skill corpus from 1 flagged
 * sample to 265, while malicious recall stays 32/32 — the cost is real and the
 * benefit is unmeasurable on that corpus). What is NOT defensible is the gate
 * reporting a `skill` shape it never charged those rules on. This axis exists so
 * the gate says which rules the skill shape did not ask about, exactly as
 * fieldCoverage does for fields and statusCoverage does for inert rules.
 *
 * Like fieldCoverage — and unlike statusCoverage — this must NOT change an exit
 * code. An `scan_target: mcp` rule being unreachable on the SKILL.md path is the
 * intended behaviour, not a defect with a one-line remedy; failing on it would
 * block every promotion with nothing to fix.
 */
export const SKILL_NATIVE_SCAN_TARGETS: ReadonlySet<string> = Object.freeze(
  new Set(["skill", "both"]),
);

/** Why a rule can never fire on engine.scanSkill(). */
export type SkillPathBlocker =
  | "method-trace"
  | "method-behavioral"
  | "method-signature"
  | "method-semantic-no-pattern-fallback"
  | "no-conditions"
  | "compound-gate-unreachable";

export interface SkillPathGap {
  readonly ruleId: string;
  readonly blocker: SkillPathBlocker;
  /** scan_target as declared, or null when the rule declares none. */
  readonly scanTarget: string | null;
  readonly maturity: string | null;
  /** True when the rule also claims the enforce (auto-block) lane. */
  readonly claimsEnforceLane: boolean;
  /** Most matchedConditions the engine can ever hand the compound gate. */
  readonly maxAttainableConditions: number;
  /** What the compound gate demands. */
  readonly requiredConditions: number;
  readonly reason: string;
}

function normalise(v: unknown): string | null {
  return typeof v === "string" && v.trim() !== "" ? v.trim().toLowerCase() : null;
}

/**
 * The compound gate's own arithmetic, mirrored: `Number(conditions?.length ?? 1)`
 * — a named-map `conditions` has no `.length`, so it counts as 1 and the floor of
 * 2 applies.
 */
function requiredConditions(conditions: unknown): number {
  const total = Number(Array.isArray(conditions) ? conditions.length : 1);
  return Math.max(2, Math.ceil(total * 0.3));
}

/**
 * The largest `matchedConditions.length` the engine can ever produce for this
 * rule, given how each condition form accumulates matches:
 *   - array + any/or  -> 1  (evaluateArrayConditions breaks on the first match)
 *   - array + all     -> N  (a match requires every condition, so it is N or nothing)
 *   - named map       -> number of names (evaluateNamedConditions does not break)
 */
function maxAttainableConditions(rule: RuleLike): number {
  const conds = rule.detection?.conditions;
  const expr = normalise(rule.detection?.condition) ?? "any";
  if (Array.isArray(conds)) {
    if (conds.length === 0) return 0;
    return expr === "any" || expr === "or" ? 1 : conds.length;
  }
  if (conds !== null && typeof conds === "object") return Object.keys(conds as object).length;
  return 0;
}

/**
 * Why this rule can never match on the SKILL.md path — or null when it can.
 *
 * Inert (draft/deprecated) rules return null on purpose: they cannot fire on ANY
 * path, which is statusCoverage's finding, and reporting them twice would blur
 * "the skill path did not ask" into "the engine never loaded it".
 */
export function skillPathBlocker(rule: RuleLike): SkillPathGap | null {
  if (isInertStatus(rule.status)) return null;

  const scanTarget = normalise(rule.tags?.scan_target);
  const maturity = normalise(rule.maturity);
  const method = normalise(rule.detection?.method) ?? "pattern";
  const required = requiredConditions(rule.detection?.conditions);
  const attainable = maxAttainableConditions(rule);

  const gap = (blocker: SkillPathBlocker, reason: string): SkillPathGap =>
    Object.freeze({
      ruleId: rule.id,
      blocker,
      scanTarget,
      maturity,
      claimsEnforceLane: maturity !== null && ENFORCE_LANE_MATURITIES.has(maturity),
      maxAttainableConditions: attainable,
      requiredConditions: required,
      reason,
    });

  // Method dispatch happens before the compound gate and is independent of
  // scan_target: scanSkill() passes an event with no trace, no session window
  // and `fields: {}`, so these methods return null for every input.
  if (method === "trace") {
    return gap(
      "method-trace",
      "method: trace — scanSkill() builds an event with no `trace`, and " +
        "evaluateRule returns null when event.trace is undefined",
    );
  }
  if (method === "behavioral") {
    return gap(
      "method-behavioral",
      "method: behavioral — the synchronous evaluateRule returns null " +
        "unconditionally; a metric window needs a streaming path",
    );
  }
  if (method === "signature") {
    return gap(
      "method-signature",
      "method: signature — indicators are compared against event.fields, and " +
        "scanSkill() sets `fields: {}`, so no indicator can ever resolve",
    );
  }
  if (method === "semantic" && normalise(rule.detection?.semantic?.fallback_method) !== "pattern") {
    return gap(
      "method-semantic-no-pattern-fallback",
      "method: semantic without fallback_method: pattern — the synchronous " +
        "scanSkill() path has no judge and returns null",
    );
  }

  // scan_target skill/both is exempt from the compound gate entirely.
  if (scanTarget !== null && SKILL_NATIVE_SCAN_TARGETS.has(scanTarget)) return null;

  if (attainable === 0) {
    return gap("no-conditions", "the rule declares no conditions the engine can match");
  }
  if (attainable < required) {
    return gap(
      "compound-gate-unreachable",
      `scan_target: ${scanTarget ?? "(none)"} is not skill/both, so the skill compound ` +
        `gate demands ${required} matched conditions, but this rule can never report more ` +
        `than ${attainable}` +
        (attainable === 1 && Array.isArray(rule.detection?.conditions)
          ? ' — evaluateArrayConditions breaks on the first match for condition: "any"'
          : ""),
    );
  }
  return null;
}

/**
 * Rules engine.scanSkill() can never match. Reachable rules are omitted.
 *
 * The skill path is a genuine production entry point (`pga scan`), and it is one
 * of the two halves of matchedRuleIds(). A caller that prints "skill" among its
 * shapes owes the reader this list.
 */
export function skillPathCoverage(rules: readonly RuleLike[]): readonly SkillPathGap[] {
  const out: SkillPathGap[] = [];
  for (const rule of rules) {
    const gap = skillPathBlocker(rule);
    if (gap !== null) out.push(gap);
  }
  return Object.freeze(out);
}
