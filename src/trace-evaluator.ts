/**
 * Trace-method rule evaluator.
 *
 * Implements the formal semantics in atr-method-v1.1.md §8 for the three
 * trace primitives: forbid, require, invariant. Operates on a Trace (DAG
 * of spans, OpenInference / OTel GenAI format).
 *
 * Capability: atr/method/trace (per atr-method-v1.1.md §9).
 *
 * Pure function; no I/O. Engine wires this in via evaluateRule dispatch
 * when detection.method === 'trace'.
 */

import type {
  ATRRule,
  ATRTrace,
  ATRSpan,
  ATRSpanShape,
  ATRTraceForbid,
  ATRTraceRequire,
  ATRTraceInvariant,
} from "./types.js";

/** Normalize a span's "kind" — accept either span.kind (OpenInference) or kind (OTel) */
function getSpanKind(span: ATRSpan): string | undefined {
  return span["span.kind"] ?? span.kind;
}

/** Resolve `${span.attributes.<path>}` placeholder against the candidate span */
function resolvePlaceholder(value: unknown, candidateSpan: ATRSpan): unknown {
  if (typeof value !== "string") return value;
  const m = value.match(/^\$\{span\.attributes\.(.+)\}$/);
  if (!m) return value;
  const path = m[1];
  return readAttributePath(candidateSpan.attributes ?? {}, path);
}

/** Read dotted-path attribute, e.g., "tool.args.target_conversation_id" */
function readAttributePath(attrs: Record<string, unknown>, path: string): unknown {
  // Fast path: exact literal key (covers "session.id" stored as a dotted literal key).
  if (path in attrs) return attrs[path];
  const parts = path.split(".");
  // Greedy: match the longest leading literal-key prefix, then descend into the
  // remainder. Handles span attributes that MIX literal dotted keys (e.g.
  // "tool.args") with nested objects (e.g. { target_conversation_id }), which a
  // plain part-by-part walk from the root cannot traverse.
  for (let n = parts.length; n >= 1; n--) {
    const prefix = parts.slice(0, n).join(".");
    if (prefix in attrs) {
      const head = attrs[prefix];
      const rest = parts.slice(n);
      if (rest.length === 0) return head;
      if (head !== null && typeof head === "object") {
        return readAttributePath(head as Record<string, unknown>, rest.join("."));
      }
      return undefined;
    }
  }
  // Fallback: plain nested walk from the root (fully-nested attribute objects).
  let cur: unknown = attrs;
  for (const part of parts) {
    if (cur === null || cur === undefined) return undefined;
    if (typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
    if (cur === undefined) return undefined;
  }
  return cur;
}

/** Evaluate a single attribute predicate against a value. Returns boolean. */
function evaluatePredicate(predicate: unknown, value: unknown): boolean {
  if (predicate === null || predicate === undefined) {
    return value === predicate;
  }
  // Literal equality
  if (typeof predicate !== "object") {
    return value === predicate;
  }
  const pred = predicate as Record<string, unknown>;
  // Compound predicate object: EVERY recognised operator present must hold (AND).
  // e.g. { exists: true, not_equals: X } means "the attribute exists AND differs
  // from X" (spec §8.3). Evaluating operators independently with first-match
  // early-return is a bug: { exists: true, not_equals: X } against an absent
  // attribute would wrongly pass on not_equals (undefined !== X) without ever
  // checking exists.
  let sawOperator = false;
  if ("in" in pred) {
    sawOperator = true;
    if (!Array.isArray(pred["in"]) || !(pred["in"] as unknown[]).includes(value)) return false;
  }
  if ("not_in" in pred) {
    sawOperator = true;
    if (!Array.isArray(pred["not_in"]) || (pred["not_in"] as unknown[]).includes(value)) return false;
  }
  if ("equals" in pred) {
    sawOperator = true;
    if (value !== pred["equals"]) return false;
  }
  if ("not_equals" in pred) {
    sawOperator = true;
    if (value === pred["not_equals"]) return false;
  }
  if ("exists" in pred) {
    sawOperator = true;
    const requiredExists = Boolean(pred["exists"]);
    if (requiredExists ? value === undefined : value !== undefined) return false;
  }
  if ("regex" in pred && typeof pred["regex"] === "string") {
    sawOperator = true;
    try {
      const re = new RegExp(pred["regex"] as string);
      if (!(typeof value === "string" && re.test(value))) return false;
    } catch {
      return false;
    }
  }
  if (!sawOperator) {
    // No recognised operator: empty object matches anything; otherwise strict-fail
    // rather than assume.
    return Object.keys(pred).length === 0;
  }
  return true;
}

/** Check if a span matches a shape. Handles literal values + predicate maps + placeholders. */
function spanMatchesShape(span: ATRSpan, shape: ATRSpanShape): boolean {
  if (shape["span.kind"] !== undefined) {
    const kind = getSpanKind(span);
    if (kind !== shape["span.kind"]) return false;
  }
  const attrPredicates = shape.attributes ?? {};
  for (const [path, predicate] of Object.entries(attrPredicates)) {
    const actual = readAttributePath(span.attributes ?? {}, path);
    const resolved = resolvePlaceholder(predicate, span);
    // Compound predicate map?
    if (
      resolved !== null &&
      typeof resolved === "object" &&
      !Array.isArray(resolved)
    ) {
      // Resolve ${...} inside compound predicates first
      const resolvedPred: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(resolved as Record<string, unknown>)) {
        resolvedPred[k] = resolvePlaceholder(v, span);
      }
      if (!evaluatePredicate(resolvedPred, actual)) return false;
    } else {
      // Literal value (after placeholder resolution if any)
      if (!evaluatePredicate(resolved, actual)) return false;
    }
  }
  return true;
}

/** Check the preceded_by clause; accepts single shape OR one_of_shapes disjunction. */
function checkPrecededBy(
  trace: ATRTrace,
  upToIndex: number,
  precededBy: ATRSpanShape | { one_of_shapes: ATRSpanShape[] },
): boolean {
  const shapes: ATRSpanShape[] =
    "one_of_shapes" in precededBy
      ? (precededBy as { one_of_shapes: ATRSpanShape[] }).one_of_shapes
      : [precededBy as ATRSpanShape];
  for (let i = 0; i < upToIndex; i++) {
    const s = trace.spans[i];
    for (const shape of shapes) {
      if (spanMatchesShape(s, shape)) return true;
    }
  }
  return false;
}

/** Evaluate a single forbid primitive. Returns array of violation descriptions. */
function evaluateForbid(trace: ATRTrace, forbid: ATRTraceForbid): string[] {
  const violations: string[] = [];
  for (let i = 0; i < trace.spans.length; i++) {
    const span = trace.spans[i];
    if (!spanMatchesShape(span, forbid.shape)) continue;
    if (forbid.preceded_by) {
      const hasPredecessor = checkPrecededBy(trace, i, forbid.preceded_by);
      if (hasPredecessor) {
        violations.push(`forbid: span ${span.id} matches shape AND predecessor present`);
      }
    } else {
      violations.push(`forbid: span ${span.id} matches forbidden shape`);
    }
  }
  return violations;
}

/** Evaluate a single require primitive. Returns array of violation descriptions
 *  (NB: violation = expected predecessor MISSING, per §8.3.2 inverse polarity). */
function evaluateRequire(trace: ATRTrace, req: ATRTraceRequire): string[] {
  const violations: string[] = [];
  for (let i = 0; i < trace.spans.length; i++) {
    const span = trace.spans[i];
    if (!spanMatchesShape(span, req.target_shape)) continue;
    const hasRequired = checkPrecededBy(trace, i, req.must_be_preceded_by);
    if (!hasRequired) {
      violations.push(`require: span ${span.id} matches target but predecessor missing`);
    }
  }
  return violations;
}

/** Group spans by the across-key value (chain id / session / conversation). */
function groupByAcross(trace: ATRTrace, across: ATRTraceInvariant["across"]): Map<string, ATRSpan[]> {
  const groups = new Map<string, ATRSpan[]>();
  for (const span of trace.spans) {
    let key: string | undefined;
    if (across === "trace") {
      key = trace.trace_id ?? "_trace_";
    } else if (across === "agent.delegation_chain") {
      key = readAttributePath(span.attributes ?? {}, "agent.delegation_chain") as
        | string
        | undefined;
    } else if (across === "session") {
      key = readAttributePath(span.attributes ?? {}, "session.id") as string | undefined;
    } else if (across === "conversation") {
      key =
        (readAttributePath(span.attributes ?? {}, "gen_ai.conversation.id") as string) ??
        (readAttributePath(span.attributes ?? {}, "conversation.id") as string);
    }
    if (key === undefined) continue;
    const list = groups.get(key) ?? [];
    list.push(span);
    groups.set(key, list);
  }
  return groups;
}

/** Evaluate a single invariant primitive. */
function evaluateInvariant(trace: ATRTrace, inv: ATRTraceInvariant): string[] {
  const violations: string[] = [];
  const groups = groupByAcross(trace, inv.across);
  for (const [key, spans] of groups.entries()) {
    if (spans.length < 2) continue;
    const firstVal = readAttributePath(spans[0].attributes ?? {}, inv.attribute);
    for (let i = 1; i < spans.length; i++) {
      const v = readAttributePath(spans[i].attributes ?? {}, inv.attribute);
      // If both undefined, no violation. If diverge, violation.
      if (firstVal === undefined && v === undefined) continue;
      if (firstVal !== v) {
        violations.push(
          `invariant: ${inv.attribute} drifts across ${inv.across}="${key}" (first=${JSON.stringify(firstVal)}, span ${spans[i].id}=${JSON.stringify(v)})`,
        );
        break; // one violation per group is sufficient
      }
    }
  }
  return violations;
}

export interface TraceEvaluationResult {
  matched: boolean;
  violations: string[];
  matchedPrimitives: ("forbid" | "require" | "invariant")[];
}

/** Top-level trace rule evaluator. Returns matched=true if ANY declared
 *  primitive evaluates to violation. */
export function evaluateTraceRule(rule: ATRRule, trace: ATRTrace): TraceEvaluationResult {
  const t = rule.detection.trace;
  if (!t) {
    return { matched: false, violations: [], matchedPrimitives: [] };
  }
  const allViolations: string[] = [];
  const matchedPrimitives: ("forbid" | "require" | "invariant")[] = [];

  for (const f of t.forbid ?? []) {
    const v = evaluateForbid(trace, f);
    if (v.length > 0) {
      allViolations.push(...v);
      matchedPrimitives.push("forbid");
    }
  }
  for (const r of t.require ?? []) {
    const v = evaluateRequire(trace, r);
    if (v.length > 0) {
      allViolations.push(...v);
      matchedPrimitives.push("require");
    }
  }
  for (const inv of t.invariant ?? []) {
    const v = evaluateInvariant(trace, inv);
    if (v.length > 0) {
      allViolations.push(...v);
      matchedPrimitives.push("invariant");
    }
  }

  return {
    matched: allViolations.length > 0,
    violations: allViolations,
    matchedPrimitives,
  };
}
