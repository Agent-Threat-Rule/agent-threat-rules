/**
 * ATR Rule Quality Contract — the single source of truth for what a rule's
 * maturity means, which detection lane it may fire in, and whether its
 * contract-level fields are valid.
 *
 * Every pipeline (the engine, the schema validators, rule producers, and the
 * promotion gate) imports from HERE instead of reimplementing its own notion of
 * "is this rule good / mature / allowed to block". Change the contract once and
 * every consumer stays consistent; a new pipeline inherits it by importing.
 *
 * This module is PURE (no engine / corpus / IO dependency) so it can be imported
 * everywhere without cycles. The precision/promotion GATES that need the engine +
 * corpus live in `./rule-gates.ts`.
 *
 * @module agent-threat-rules/quality/rule-contract
 */

/** Canonical maturity ladder. The ONLY allowed values; producers must emit one. */
export const MATURITIES = ['draft', 'experimental', 'test', 'stable', 'deprecated'] as const;
export type Maturity = (typeof MATURITIES)[number];

/** Detection lanes. enforce=auto-block, alert=analyst/correlation, hunt=advisory. */
export const LANES = ['enforce', 'alert', 'hunt'] as const;
export type Lane = (typeof LANES)[number];

/** Allowed values for a rule's `confirm` field (require a second-stage confirm). */
export const CONFIRM_METHODS = ['embedding'] as const;
export type ConfirmMethod = (typeof CONFIRM_METHODS)[number];

/**
 * Detection methods for which `confirm: embedding` is meaningful — content-matching
 * methods whose hit can be re-checked against attack-content similarity. `trace` and
 * `behavioral` are intentionally EXCLUDED: their signal is structural/temporal, not
 * content, so an embedding content-similarity confirm does not apply.
 */
export const CONFIRM_COMPATIBLE_METHODS = ['pattern', 'signature', 'semantic'] as const;

const MATURITY_SET: ReadonlySet<string> = new Set(MATURITIES);
const CONFIRM_SET: ReadonlySet<string> = new Set(CONFIRM_METHODS);
const CONFIRM_METHOD_SET: ReadonlySet<string> = new Set(CONFIRM_COMPATIBLE_METHODS);

/**
 * Normalize a possibly-missing/empty/odd maturity to the canonical set.
 * Safe-fail: anything unrecognized becomes 'experimental' (so a rule-authoring
 * typo is treated as not-production, never silently reaching the enforce lane).
 */
export function normalizeMaturity(m: unknown): Maturity {
  const s = String(m ?? '').trim();
  return MATURITY_SET.has(s) ? (s as Maturity) : 'experimental';
}

/**
 * Lane gate: may a rule of this maturity fire in this lane?
 *   enforce -> stable only        (lowest FP; the auto-block lane)
 *   alert   -> stable + test      (analyst / correlation lane)
 *   hunt    -> all (except deprecated)   (advisory / eval; default)
 * Self-contained: a `deprecated` maturity never fires in ANY lane (it is retired),
 * so a consumer that calls this without the engine's status-skip can't misroute it.
 */
export function laneAllows(maturity: unknown, lane: Lane): boolean {
  const m = normalizeMaturity(maturity);
  if (m === 'deprecated') return false; // retired — never fires, in any lane
  if (lane === 'hunt') return true;
  if (lane === 'enforce') return m === 'stable';
  return m === 'stable' || m === 'test'; // alert
}

/** Does a rule require embedding-confirmation before it may fire in enforce/alert? */
export function requiresConfirm(rule: { confirm?: unknown }): boolean {
  return String(rule.confirm ?? '') === 'embedding';
}

/**
 * Structural validation of the contract-level fields (maturity + confirm).
 * Returns a list of human-readable errors (empty = valid). Schema validators and
 * the loader call this so an invalid maturity (e.g. the legacy `needs-human-poc`)
 * or a bad `confirm` value can no longer pass silently.
 */
export function validateContract(rule: {
  maturity?: unknown;
  confirm?: unknown;
  detection?: { method?: string };
}): string[] {
  const errors: string[] = [];
  if (rule.maturity != null && !MATURITY_SET.has(String(rule.maturity).trim())) {
    errors.push(`invalid maturity "${String(rule.maturity)}" (allowed: ${MATURITIES.join(', ')})`);
  }
  if (rule.confirm != null) {
    if (!CONFIRM_SET.has(String(rule.confirm))) {
      errors.push(`invalid confirm "${String(rule.confirm)}" (allowed: ${CONFIRM_METHODS.join(', ')})`);
    }
    // embedding-confirm only makes sense for content-matching methods.
    const method = rule.detection?.method;
    if (method != null && !CONFIRM_METHOD_SET.has(String(method))) {
      errors.push(`confirm not supported for detection.method "${method}" (allowed: ${CONFIRM_COMPATIBLE_METHODS.join(', ')})`);
    }
    // Cross-field invariant: a rule that declares it needs confirmation must be
    // mature enough to reach an enforcing lane — confirm on draft/experimental is
    // incoherent (it would never actually be confirmed, since those don't fire in
    // enforce/alert).
    if (rule.maturity != null) {
      const m = normalizeMaturity(rule.maturity);
      if (m !== 'stable' && m !== 'test') {
        errors.push(`confirm requires maturity stable or test, got "${String(rule.maturity)}"`);
      }
    }
  }
  return errors;
}
