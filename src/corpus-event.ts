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
 * WHERE THIS FILE LIVES (moved 2026-08-05)
 *
 * It used to live at scripts/lib/corpus-event.ts. It now lives under src/ for
 * one reason: src/eval/eval-harness.ts — the harness behind `npm run eval` and
 * `npm run eval:pint`, i.e. the numbers that get published — is also an FP/TP
 * harness and was hand-rolling its own narrow event, exactly the defect this
 * module exists to abolish. tsconfig pins rootDir to ./src, so nothing under
 * src/ can import from scripts/ without breaking `npm run build`. Moving the
 * canonical module was therefore the only way to let the published harness use
 * it instead of a private copy. scripts/lib/corpus-event.ts remains as a
 * re-export so every existing importer (and the ratchet test that greps for
 * that import path) is untouched.
 *
 * @module agent-threat-rules/corpus-event
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
  | "post-tool-json";

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

// ---------------------------------------------------------------------------
// The one way a harness turns a sample into matched rule ids
// ---------------------------------------------------------------------------

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
  readonly detection?: {
    readonly method?: string;
    readonly condition?: string;
    readonly conditions?: unknown;
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
