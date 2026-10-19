/**
 * The outcomes a fixture's expect.json may declare, per category (SUITE.md).
 * Shared by run-conformance.ts, which reports any other value as a broken
 * fixture (harness_error) rather than scoring it, and by the fixture tests.
 *
 * `handled` (edge only): match, no_match or graceful_error, within the runtime
 * budget, never engine_error. It is for payloads that are themselves detection
 * signals (zero-width, bidi-override and control characters), which a
 * faithful Engine running the published Corpus may legitimately match.
 */
export type Outcome = 'match' | 'no_match' | 'graceful_error' | 'graceful_error_or_no_match' | 'handled';

/** The suite and SPEC.md versions a report declares; report-schema.json lists them. */
export const SUITE_VERSION = 'v1.0.1';
export const SPEC_VERSION = '1.0.2';

export const ALLOWED_OUTCOMES: Readonly<Record<'tp' | 'tn' | 'edge', readonly Outcome[]>> = {
  tp: ['match'],
  tn: ['no_match'],
  edge: ['graceful_error', 'no_match', 'graceful_error_or_no_match', 'handled'],
};
