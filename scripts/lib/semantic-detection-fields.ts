/**
 * Field checks for a `detection.method: semantic` block, beyond the presence of
 * judge_model_class, prompt_template and threshold that tests/validate-rules.ts
 * already requires.
 *
 * WHY
 *
 * src/engine.ts evaluates a semantic rule's pattern fallback only when
 * `detection.semantic.fallback_method === 'pattern'`, compared exactly; the
 * judge runs only in evaluateAsync(). So on the synchronous path, which is the
 * path every benign-corpus measurement and the shipped `atr guard` hook take,
 * any other value means the rule never fires. spec/atr-schema.yaml allows
 * `pattern` or `none` and a threshold from 0 to 1. Nothing checked either, so
 * "Pattern", a threshold of 7, or a pattern fallback with no condition in it
 * all validated.
 */

const FALLBACK_METHODS: readonly string[] = Object.freeze(["pattern", "none"]);

/** A value as the author wrote it: NaN stays NaN, where JSON.stringify would print null. */
function shown(value: unknown): string {
  return typeof value === "number" || value === undefined ? String(value) : JSON.stringify(value);
}

/** True when `conditions` holds at least one entry, in the array or named-map form. */
function hasCondition(conditions: unknown): boolean {
  if (Array.isArray(conditions)) return conditions.length > 0;
  return conditions !== null && typeof conditions === "object" && Object.keys(conditions).length > 0;
}

/**
 * Problems with a semantic rule's `detection` block, one sentence each; empty
 * when there are none. A missing `semantic` block or a missing threshold is the
 * presence check's to report, not this one's.
 */
export function semanticDetectionErrors(detection: Readonly<Record<string, unknown>>): string[] {
  const semantic = detection["semantic"];
  if (semantic === null || typeof semantic !== "object") return [];
  const sem = semantic as Readonly<Record<string, unknown>>;
  const errors: string[] = [];

  if ("fallback_method" in sem) {
    const fallback = sem["fallback_method"];
    if (typeof fallback !== "string" || !FALLBACK_METHODS.includes(fallback)) {
      errors.push(
        `detection.semantic.fallback_method must be "pattern" or "none", not ${shown(fallback)}: ` +
          `the engine compares it exactly, and any other value runs no fallback`,
      );
    } else if (fallback === "pattern" && !hasCondition(detection["conditions"])) {
      errors.push(
        'detection.semantic.fallback_method is "pattern" but detection.conditions holds no condition: ' +
          "the fallback has nothing to match",
      );
    }
  }

  if ("threshold" in sem && sem["threshold"] !== undefined) {
    const threshold = sem["threshold"];
    if (typeof threshold !== "number" || !Number.isFinite(threshold) || threshold < 0 || threshold > 1) {
      errors.push(`detection.semantic.threshold must be a number from 0 to 1, not ${shown(threshold)}`);
    }
  }

  return errors;
}
