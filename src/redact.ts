/**
 * Match-value redaction utility.
 *
 * The engine's `ATRMatch.matchedPatterns` field can contain the raw text that
 * triggered a rule. Downstream integrations that include matched values in
 * log lines, error messages, or telemetry payloads risk re-exposing the very
 * secrets that the rule fired on (e.g., AWS access keys, OAuth tokens,
 * cookies, prompt-injection payloads containing user PII).
 *
 * Pass each entry of `match.matchedPatterns` through `redactMatchedValue()`
 * before logging or surfacing it externally. The function preserves enough
 * context for triage (rule shape, length, leading marker bytes) without
 * keeping the secret bytes themselves.
 *
 * @example
 *   import { redactMatchedValue } from "agent-threat-rules/redact";
 *   for (const match of engine.evaluate(event)) {
 *     logger.warn({
 *       rule: match.rule.id,
 *       redacted_patterns: match.matchedPatterns.map(redactMatchedValue),
 *     });
 *   }
 */

const SECRET_PREFIXES: ReadonlyArray<readonly [RegExp, string]> = [
  [/^AKIA[A-Z0-9]/, "aws_access_key_id"],
  [/^ASIA[A-Z0-9]/, "aws_session_credential"],
  [/^AGPA[A-Z0-9]/, "aws_user_identity"],
  [/^ghp_[A-Za-z0-9]/, "github_personal_token"],
  [/^gho_[A-Za-z0-9]/, "github_oauth_token"],
  [/^ghs_[A-Za-z0-9]/, "github_server_token"],
  [/^ghu_[A-Za-z0-9]/, "github_user_token"],
  [/^ghr_[A-Za-z0-9]/, "github_refresh_token"],
  [/^xox[abprs]-/, "slack_token"],
  [/^xoxe-/, "slack_external_token"],
  [/^sk-[A-Za-z0-9_]/, "openai_or_compatible_secret"],
  [/^sk-ant-[A-Za-z0-9_]/, "anthropic_secret"],
  [/^Bearer\s+/i, "bearer_credential"],
  [/^-----BEGIN [A-Z ]+PRIVATE KEY-----/, "pem_private_key"],
  [/^eyJ[A-Za-z0-9_-]/, "jwt_or_jose"],
];

const DEFAULT_HEAD_BYTES = 4;
const MAX_REDACTED_OUTPUT = 80;

/**
 * Options for `redactMatchedValue`.
 */
export interface RedactOptions {
  /**
   * Number of leading bytes to keep visible as a triage hint. Defaults to 4.
   * Set to 0 to keep no prefix at all.
   */
  headBytes?: number;
  /**
   * Maximum length of the returned redacted string. Defaults to 80.
   */
  maxLength?: number;
}

/**
 * Replace a raw matched value with a triage-safe summary.
 *
 * The output never contains more than `headBytes` (default 4) of the original
 * value. The remainder is replaced with a structured placeholder that records
 * the recognised secret class (when known), the original length, and an
 * elision marker. Whitespace and surrounding punctuation are preserved so the
 * summary still reads as a token in log lines.
 *
 * Returns a string of at most `maxLength` characters (default 80).
 */
export function redactMatchedValue(value: string, options: RedactOptions = {}): string {
  if (typeof value !== "string") return "[redacted:non-string]";
  if (value.length === 0) return "[redacted:empty]";

  const headBytes = Math.max(0, options.headBytes ?? DEFAULT_HEAD_BYTES);
  const maxLength = Math.max(8, options.maxLength ?? MAX_REDACTED_OUTPUT);

  // Strip leading / trailing whitespace for class detection, but keep the
  // visible head from the original (so context is preserved).
  const trimmed = value.trim();
  let secretClass: string | null = null;
  for (const [pattern, label] of SECRET_PREFIXES) {
    if (pattern.test(trimmed)) {
      secretClass = label;
      break;
    }
  }

  const head = value.slice(0, headBytes);
  const length = value.length;
  const summary =
    secretClass !== null
      ? `[redacted:${secretClass} head=${JSON.stringify(head)} len=${length}]`
      : `[redacted head=${JSON.stringify(head)} len=${length}]`;

  if (summary.length <= maxLength) return summary;
  return summary.slice(0, maxLength - 1) + "]";
}

/**
 * Convenience helper: apply `redactMatchedValue` to every entry of an array.
 */
export function redactMatchedValues(values: ReadonlyArray<string>, options?: RedactOptions): string[] {
  return values.map((v) => redactMatchedValue(v, options));
}
