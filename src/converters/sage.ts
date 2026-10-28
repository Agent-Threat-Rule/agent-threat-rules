/**
 * ATR → Sage (gendigitalinc/sage) Converter
 *
 * Converts ATR YAML rules into Sage's threat rule schema, suitable for
 * Sage's `threats/agent-layer.yaml`. Sage uses a single-pattern-per-rule
 * schema with `match_on` controlling the artifact channel; ATR uses
 * multi-condition rules with `field`-targeted regexes.
 *
 * Conversion strategy (per research memo):
 * - One ATR rule → one or more Sage rules, grouped by `field` target.
 *   Conditions on the same field combine via regex alternation.
 * - ATR `field` values (user_input, agent_output, content, tool_response,
 *   tool_args, tool_name, tool_description) collapse to Sage `match_on:
 *   content`. Sage's other channels (command, url, file_path, domain) are
 *   command-time matchers and do not have ATR equivalents in the current
 *   corpus.
 * - ATR `response.actions` (10 values) collapse to Sage `action` (3
 *   values: block / require_approval / log) by strongest-wins semantics.
 * - SPEC §6.4: every ATR regex condition matches case-insensitively, so the
 *   leading flag group is removed and every Sage rule sets
 *   `case_insensitive: true`. The Sage runtime compiles patterns as JavaScript
 *   `RegExp` with only the `i` flag, so a condition that depends on the `u`
 *   flag is skipped (sagePatternOf).
 * - ATR `detection_tier: semantic` rules are SKIPPED — they require LLM
 *   evaluation, not deterministic regex.
 * - License: ATR rules are MIT; Sage's `threats/*.yaml` are DRL 1.1. Per-rule
 *   comment in the output preserves upstream attribution per both licenses.
 *
 * Used by scripts/export-sage.ts, and by any downstream tool that consumes
 * ATR but wants Sage-flavoured output.
 *
 * @module agent-threat-rules/converters/sage
 */

import { regexConditionSpec } from '../regex-dialect.js';
import type {
	ATRRule,
	ATRAction,
	ATRSeverity,
	ATRArrayCondition,
} from '../types.js';

// ── Sage schema (mirror of gendigitalinc/sage packages/core/src/types.ts) ──

export type SageSeverity = 'critical' | 'high' | 'medium' | 'low';
export type SageAction = 'block' | 'require_approval' | 'log';
export type SageMatchOn = 'command' | 'url' | 'file_path' | 'content' | 'domain';

export interface SageRule {
	readonly id: string;
	readonly category: string;
	readonly severity: SageSeverity;
	readonly confidence: number;
	readonly action: SageAction;
	readonly pattern: string;
	readonly match_on: SageMatchOn | readonly SageMatchOn[];
	readonly title: string;
	readonly expires_at: string | null;
	readonly revoked: boolean;
	readonly case_insensitive?: boolean;
	/** Non-standard provenance fields preserved per the Sage loader's permissive parsing. */
	readonly upstream?: string;
	readonly upstream_url?: string;
	readonly upstream_license?: string;
	/** 1-2 sentence attack-scenario summary derived from ATR `description`, emitted as a `# Detects:` comment in YAML output. */
	readonly detects?: string;
}

export interface ConversionWarning {
	readonly ruleId: string;
	readonly kind:
		| 'semantic_tier_skipped'
		| 'unsupported_action_dropped'
		| 'regex_compat_issue'
		| 'split_by_length'
		| 'condition_without_field'
		| 'no_convertible_conditions'
		| 'deprecated_skipped'
		| 'draft_marked_revoked';
	readonly detail: string;
}

export interface ConvertResult {
	readonly rules: readonly SageRule[];
	readonly warnings: readonly ConversionWarning[];
}

// ── Mappings ───────────────────────────────────────────────────────────────

/**
 * ATR category strings (hyphenated) → Sage category strings (snake_case).
 * Sage's schema accepts any string; the agent-layer.yaml convention from
 * ATR PR #33 established snake_case category names.
 */
const CATEGORY_MAP: Readonly<Record<string, string>> = Object.freeze({
	'prompt-injection': 'prompt_injection',
	'tool-poisoning': 'mcp_poisoning',
	'context-exfiltration': 'context_exfiltration',
	'agent-manipulation': 'agent_manipulation',
	'privilege-escalation': 'privilege_escalation',
	'excessive-autonomy': 'excessive_autonomy',
	'data-poisoning': 'data_poisoning',
	'model-abuse': 'model_abuse',
	'skill-compromise': 'skill_compromise',
	'model-security': 'model_security',
});

/**
 * ATR severity → Sage severity. Sage has no `informational`; collapse to `low`.
 */
const SEVERITY_MAP: Readonly<Record<ATRSeverity, SageSeverity>> = Object.freeze({
	critical: 'critical',
	high: 'high',
	medium: 'medium',
	low: 'low',
	informational: 'low',
});

/**
 * ATR action strength ordering. Higher value = stronger action. When ATR rule
 * has multiple actions, we pick the strongest Sage-mappable action.
 */
const ACTION_STRENGTH: Readonly<Record<SageAction, number>> = Object.freeze({
	block: 3,
	require_approval: 2,
	log: 1,
});

/**
 * Map ATR action → Sage action. Returns null for ATR actions Sage does not
 * support (reset_context, reduce_permissions); the caller logs a warning.
 */
function mapAction(atr: ATRAction): SageAction | null {
	switch (atr) {
		case 'block_input':
		case 'block_output':
		case 'block_tool':
		case 'quarantine_session':
		case 'kill_agent':
			return 'block';
		case 'escalate':
			return 'require_approval';
		case 'alert':
		case 'snapshot':
		case 'shadow':
			return 'log';
		case 'reset_context':
		case 'reduce_permissions':
			return null;
		default: {
			// Exhaustiveness check — if a new ATRAction is added in the future
			// and not handled above, TypeScript will flag this assignment.
			const _exhaustive: never = atr;
			void _exhaustive;
			return null;
		}
	}
}

/**
 * Map ATR field name → Sage match_on. Most ATR field channels collapse to
 * Sage's `content`. URL-shaped fields could map to `url`, but the ATR corpus
 * does not currently use a distinct `url` field — URL matching happens via
 * regex content match.
 */
function mapField(atrField: string): SageMatchOn {
	switch (atrField) {
		case 'url':
			return 'url';
		case 'user_input':
		case 'agent_output':
		case 'content':
		case 'tool_response':
		case 'tool_args':
		case 'tool_name':
		case 'tool_description':
		case 'agent_message':
			return 'content';
		default:
			return 'content';
	}
}

/**
 * Map ATR category → Sage category. Unknown categories pass through unchanged
 * (Sage's loader accepts any string).
 */
function mapCategory(atrCategory: string): string {
	return CATEGORY_MAP[atrCategory] ?? atrCategory.replace(/-/g, '_');
}

// ── Regex compatibility ────────────────────────────────────────────────────

/**
 * A condition's regex for Sage, which compiles
 * `new RegExp(pattern, case_insensitive ? "i" : "")` and cannot set `u`.
 *
 * SPEC §6.4: the leading flag group is removed and every condition matches
 * case-insensitively, so every exported rule sets `case_insensitive: true`.
 * This used to follow the group instead: a condition without `(?i)` became a
 * case-sensitive Sage rule. `m`, `s` and `x` have no effect in ATR, so
 * dropping them changes nothing.
 *
 * The engine compiles a condition with `iu` when it contains `\u{...}`,
 * `\p{...}` or an astral character (needsUnicodeFlag). Without `u` an astral
 * character is two UTF-16 code units. As a plain literal it still matches the
 * same text, so such a condition is exported without `u`; the one difference
 * left is that `.` and a negated class consume one code unit, so a bounded
 * repeat such as `.{0,50}` counts an astral character of the input as two. A
 * condition that depends on `u` in any other way is skipped
 * (dependsOnUnicodeMode).
 */
function sagePatternOf(value: string): { pattern: string; needsUnicode: boolean } {
	const spec = regexConditionSpec(value);
	return {
		pattern: spec.source,
		needsUnicode: spec.flags === 'iu' && dependsOnUnicodeMode(spec.source),
	};
}

/**
 * Whether a pattern the engine compiles with `u` fails to compile, or means
 * something else, without it: `\u{...}`, `\p{...}` or `\P{...}`, or an
 * astral character inside a character class, before a quantifier, or with a
 * case mapping.
 */
function dependsOnUnicodeMode(source: string): boolean {
	if (/\\[pPu]\{/.test(source)) return true;
	try {
		new RegExp(source, 'i');
	} catch {
		return true;
	}
	const chars = [...source];
	let inClass = false;
	let escaped = false;
	for (let k = 0; k < chars.length; k++) {
		const ch = chars[k]!;
		if (escaped) {
			escaped = false;
			continue;
		}
		if (ch === '\\') {
			escaped = true;
			continue;
		}
		const astral = ch.codePointAt(0)! > 0xffff;
		if (inClass) {
			if (ch === ']') inClass = false;
			else if (astral) return true;
			continue;
		}
		if (ch === '[') {
			inClass = true;
			continue;
		}
		if (!astral) continue;
		if (ch.toLowerCase() !== ch || ch.toUpperCase() !== ch) return true;
		if (/^[*+?{]/.test(chars[k + 1] ?? '')) return true;
	}
	return false;
}

const NEEDS_UNICODE_DETAIL =
	'Regex depends on the u flag (\\u{...}, \\p{...}, or an astral character in a character class, ' +
	'before a quantifier or with a case mapping), which Sage cannot set; condition skipped';

/**
 * Validate a regex compiles the way Sage compiles an exported rule, with the
 * `i` flag. Returns the compile error message if it fails, or null if it
 * succeeds.
 */
function validateRegexCompiles(pattern: string): string | null {
	try {
		new RegExp(pattern, 'i');
		return null;
	} catch (e) {
		return e instanceof Error ? e.message : String(e);
	}
}

/**
 * Combine multiple regex patterns into a single regex using non-capturing
 * alternation. Each pattern is wrapped in a non-capturing group to preserve
 * its internal alternation semantics.
 */
function alternationCombine(patterns: readonly string[]): string {
	if (patterns.length === 1) return patterns[0]!;
	return patterns.map((p) => `(?:${p})`).join('|');
}

// ── Confidence ─────────────────────────────────────────────────────────────

/**
 * Pick a Sage confidence (0.0-1.0 number) from an ATR rule. ATR has both
 * `confidence` (numeric, 0-100) and `tags.confidence` (string enum). Prefer
 * numeric; fall back to enum; default to 0.8.
 */
function pickConfidence(atr: ATRRule): number {
	if (typeof atr.confidence === 'number') {
		// ATR uses 0-100; Sage uses 0.0-1.0
		const normalized = atr.confidence > 1 ? atr.confidence / 100 : atr.confidence;
		return Math.max(0, Math.min(1, Number(normalized.toFixed(2))));
	}
	const tag = atr.tags.confidence;
	if (tag === 'high') return 0.9;
	if (tag === 'medium') return 0.75;
	if (tag === 'low') return 0.6;
	return 0.8;
}

// ── Action picking ─────────────────────────────────────────────────────────

/**
 * From an ATR rule's `response.actions` array, pick the strongest Sage-mappable
 * action. Returns the action plus a list of dropped ATR actions (those that
 * have no Sage equivalent — reset_context, reduce_permissions).
 */
function pickAction(atrActions: readonly ATRAction[]): {
	action: SageAction;
	droppedActions: readonly ATRAction[];
} {
	const dropped: ATRAction[] = [];
	let best: SageAction = 'log';
	let bestStrength = 0;
	for (const a of atrActions) {
		const mapped = mapAction(a);
		if (mapped === null) {
			dropped.push(a);
			continue;
		}
		const strength = ACTION_STRENGTH[mapped];
		if (strength > bestStrength) {
			best = mapped;
			bestStrength = strength;
		}
	}
	return { action: best, droppedActions: dropped };
}

// ── Sage id generation ────────────────────────────────────────────────────

/**
 * Sage uses CLT-PREFIX-NNN ids. Map ATR category → Sage prefix.
 */
const SAGE_PREFIX_MAP: Readonly<Record<string, string>> = Object.freeze({
	prompt_injection: 'PI',
	mcp_poisoning: 'MCP',
	context_exfiltration: 'CTX',
	agent_manipulation: 'AGM',
	privilege_escalation: 'PRV',
	excessive_autonomy: 'EAU',
	data_poisoning: 'DPS',
	model_abuse: 'MAB',
	skill_compromise: 'SKL',
	model_security: 'MSC',
	supply_chain: 'SUP',
});

/**
 * Generate a Sage rule id matching Sage's existing 3-digit-suffix convention.
 * Format: CLT-<PREFIX>-<NNN> where PREFIX is the 2-3 letter category code.
 *
 * The id is generated sequentially by an IdAllocator passed in by the caller,
 * NOT derived from the ATR id. This matches Sage's convention (CLT-PI-001,
 * CLT-MCP-001, etc.) instead of producing weird-looking ids like CLT-PRV-0441.
 *
 * The ATR provenance survives in the `# Upstream: ATR-2026-NNNNN` comment.
 */
export class SageIdAllocator {
	private counters = new Map<string, number>();

	/**
	 * Construct with optional starting offsets per category. Pass
	 * `{prompt_injection: 8}` to start prompt_injection ids at 008 (after
	 * Sage's existing CLT-PI-001..007, for example).
	 */
	constructor(startingOffsets: Readonly<Record<string, number>> = {}) {
		for (const [cat, offset] of Object.entries(startingOffsets)) {
			this.counters.set(cat, offset);
		}
	}

	next(sageCategory: string, channelDisambiguator: string | null): string {
		const prefix = SAGE_PREFIX_MAP[sageCategory] ?? 'GEN';
		const counter = (this.counters.get(sageCategory) ?? 0) + 1;
		this.counters.set(sageCategory, counter);
		const numericPart = String(counter).padStart(3, '0');
		const suffix = channelDisambiguator ? `-${channelDisambiguator}` : '';
		return `CLT-${prefix}-${numericPart}${suffix}`;
	}
}

// ── Core conversion ────────────────────────────────────────────────────────

/**
 * Group ATR array-format conditions by the Sage match_on channel they map to,
 * NOT by their original ATR field name. This matters because all of ATR's
 * text-channel fields (user_input, agent_output, content, tool_response,
 * tool_args, tool_name, tool_description) collapse to Sage's single `content`
 * match_on — so an ATR rule with conditions across those fields should produce
 * one Sage rule with an alternation regex over all of them, not N separate
 * Sage rules.
 *
 * Conditions with no field or non-regex operators are excluded (with a warning
 * emitted by the caller).
 */
function groupConditionsBySageChannel(
	atrId: string,
	conditions: readonly ATRArrayCondition[],
	warnings: ConversionWarning[],
): Map<SageMatchOn, ATRArrayCondition[]> {
	const groups = new Map<SageMatchOn, ATRArrayCondition[]>();
	for (const cond of conditions) {
		if (!('field' in cond) || !cond.field) {
			warnings.push({
				ruleId: atrId,
				kind: 'condition_without_field',
				detail: 'Condition skipped — missing field target',
			});
			continue;
		}
		if (cond.operator !== 'regex') {
			warnings.push({
				ruleId: atrId,
				kind: 'regex_compat_issue',
				detail: `Operator ${cond.operator} not supported by Sage (only regex)`,
			});
			continue;
		}
		if (!cond.value) continue;
		const sageChannel = mapField(cond.field);
		const existing = groups.get(sageChannel) ?? [];
		existing.push(cond);
		groups.set(sageChannel, existing);
	}
	return groups;
}

/**
 * Process a single condition group (all conditions mapping to the same Sage
 * match_on channel) into a single Sage rule. Returns null if no valid regex
 * remains after compat filtering.
 */
function groupToSageRule(
	atr: ATRRule,
	sageChannel: SageMatchOn,
	conditions: readonly ATRArrayCondition[],
	channelDisambiguator: string | null,
	pickedAction: SageAction,
	idAllocator: SageIdAllocator,
	warnings: ConversionWarning[],
): SageRule | null {
	// Process each condition's regex (SPEC §6.4, see sagePatternOf) and
	// validate that it compiles.
	const processed: string[] = [];

	for (const cond of conditions) {
		const { pattern, needsUnicode } = sagePatternOf(cond.value);
		if (needsUnicode) {
			warnings.push({ ruleId: atr.id, kind: 'regex_compat_issue', detail: NEEDS_UNICODE_DETAIL });
			continue;
		}
		const compileError = validateRegexCompiles(pattern);
		if (compileError) {
			warnings.push({
				ruleId: atr.id,
				kind: 'regex_compat_issue',
				detail: `Regex does not compile under JS RegExp: ${compileError}`,
			});
			continue;
		}
		processed.push(pattern);
	}

	if (processed.length === 0) return null;

	const combinedRegex = alternationCombine(processed);

	// Validate the combined regex still compiles (alternation can occasionally
	// expose escape conflicts).
	const compileError = validateRegexCompiles(combinedRegex);
	if (compileError) {
		warnings.push({
			ruleId: atr.id,
			kind: 'regex_compat_issue',
			detail: `Combined regex (alternation) does not compile: ${compileError}`,
		});
		return null;
	}

	const sageCategory = mapCategory(atr.tags.category);
	const sageId = idAllocator.next(sageCategory, channelDisambiguator);
	const matchOn = sageChannel;
	const title = atr.title.length > 100 ? atr.title.slice(0, 97) + '...' : atr.title;

	const upstreamUrl = `https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/${atr.tags.category}/${atr.id}.yaml`;

	// Calibrate action vs confidence: Sage's convention is action=block ONLY
	// when confidence ≥0.85. Downgrade block→require_approval for lower-
	// confidence rules to avoid false-positive damage in production.
	const calibratedConfidence = pickConfidence(atr);
	const calibratedAction: SageAction =
		pickedAction === 'block' && calibratedConfidence < 0.85
			? 'require_approval'
			: pickedAction;

	return {
		id: sageId,
		category: sageCategory,
		severity: SEVERITY_MAP[atr.severity],
		confidence: calibratedConfidence,
		action: calibratedAction,
		pattern: combinedRegex,
		match_on: matchOn,
		title,
		expires_at: null,
		revoked: atr.status === 'draft',
		case_insensitive: true,
		upstream: atr.id,
		upstream_url: upstreamUrl,
		upstream_license: 'MIT',
		detects: extractDetectsSummary(atr.description),
	};
}

/**
 * Extract a 1-2 sentence summary from an ATR rule's `description` field,
 * for inclusion as a `# Detects:` comment above the Sage rule. Preserves the
 * attack-scenario context that Sage's schema does not have a field for.
 */
function extractDetectsSummary(description: string | undefined): string {
	if (!description) return '';
	// Take the first sentence (terminating at the first `.` or newline).
	const firstSentence = description
		.replace(/\s+/g, ' ')
		.trim()
		.match(/^(.{20,200}?[\.\?\!])(\s|$)/)?.[1];
	if (firstSentence) return firstSentence;
	// Fallback: first 150 chars
	const trimmed = description.replace(/\s+/g, ' ').trim().slice(0, 150);
	return trimmed.length === 150 ? trimmed + '...' : trimmed;
}

/**
 * Convert a single ATR rule to one or more Sage rules.
 *
 * Returns one Sage rule per unique `field` target in the ATR rule's detection
 * conditions. Most ATR rules in the current corpus target a single field
 * (user_input or tool_response or content), producing 1 Sage rule each.
 *
 * Lossy spots (documented in the bridge research memo):
 * - Conditions that depend on the `u` flag → skipped (sagePatternOf)
 * - `condition: all` semantics → ignored; alternation always treats as OR
 * - `response.actions` reduced to strongest single action
 * - All compliance/metadata fields (eu_ai_act, mitre_atlas, references, etc.)
 *   are dropped (not in Sage schema). They survive in the upstream_url link.
 */
export function atrToSage(
	atr: ATRRule,
	idAllocator: SageIdAllocator = new SageIdAllocator(),
): ConvertResult {
	const warnings: ConversionWarning[] = [];

	// Skip semantic-tier rules — they require LLM evaluation
	if (atr.detection_tier === 'semantic') {
		warnings.push({
			ruleId: atr.id,
			kind: 'semantic_tier_skipped',
			detail: 'Semantic-tier rules require LLM evaluation; Sage uses deterministic regex',
		});
		return { rules: [], warnings };
	}

	// Skip deprecated rules
	if (atr.status === 'deprecated') {
		warnings.push({
			ruleId: atr.id,
			kind: 'deprecated_skipped',
			detail: `Deprecated rule (replaced_by=${atr.replaced_by ?? 'none'})`,
		});
		return { rules: [], warnings };
	}

	// Pick action (strongest, with dropped actions logged)
	const { action: pickedAction, droppedActions } = pickAction(atr.response.actions);
	for (const dropped of droppedActions) {
		warnings.push({
			ruleId: atr.id,
			kind: 'unsupported_action_dropped',
			detail: `Action ${dropped} has no Sage equivalent`,
		});
	}

	// Process conditions
	const rawConditions = atr.detection.conditions;
	if (!Array.isArray(rawConditions)) {
		// Named-map format: extract pattern conditions only (skip behavioral/sequence)
		warnings.push({
			ruleId: atr.id,
			kind: 'no_convertible_conditions',
			detail: 'Named-map condition format not yet supported',
		});
		return { rules: [], warnings };
	}

	const groups = groupConditionsBySageChannel(atr.id, rawConditions, warnings);
	if (groups.size === 0) {
		warnings.push({
			ruleId: atr.id,
			kind: 'no_convertible_conditions',
			detail: 'No regex conditions with a field target found',
		});
		return { rules: [], warnings };
	}

	// Single-channel rules → no disambiguator. Multi-channel (rare; only when
	// an ATR rule has conditions on both content-channel fields AND url field)
	// → suffix with channel code.
	const channelEntries = Array.from(groups.entries());
	const isMultiChannel = channelEntries.length > 1;
	const sageRules: SageRule[] = [];
	const MAX_COMBINED_PATTERN_LEN = 500;
	for (const [sageChannel, conditions] of channelEntries) {
		const disambiguator = isMultiChannel ? channelCode(sageChannel) : null;

		// Build the combined regex once to check length. Conditions Sage cannot
		// express are skipped when the rule is built, so they do not count.
		const candidatePatterns = conditions
			.map((c) => sagePatternOf(c.value))
			.filter((p) => !p.needsUnicode && p.pattern.length > 0)
			.map((p) => p.pattern);
		const tentativeCombined = alternationCombine(candidatePatterns);

		if (tentativeCombined.length <= MAX_COMBINED_PATTERN_LEN || conditions.length === 1) {
			// Fits in one Sage rule — allocator advances once.
			const rule = groupToSageRule(
				atr,
				sageChannel,
				conditions,
				disambiguator,
				pickedAction,
				idAllocator,
				warnings,
			);
			if (rule) sageRules.push(rule);
		} else {
			// Combined regex too long — split into one Sage rule per ATR
			// condition. Share a single base id (allocator advances once) and
			// append letter suffixes so the related rules sort together:
			// CLT-PRV-001a, CLT-PRV-001b, etc.
			warnings.push({
				ruleId: atr.id,
				kind: 'split_by_length',
				detail: `Combined regex would be ${tentativeCombined.length} chars (>${MAX_COMBINED_PATTERN_LEN}); splitting into ${conditions.length} Sage rules with letter suffixes`,
			});
			const sageCategoryForSplit = mapCategory(atr.tags.category);
			const baseId = idAllocator.next(sageCategoryForSplit, disambiguator);
			conditions.forEach((cond, i) => {
				const letterSuffix = letterFromIndex(i);
				const subRule = buildSplitSubRule(
					atr,
					sageChannel,
					cond,
					`${baseId}${letterSuffix}`,
					pickedAction,
					warnings,
				);
				if (subRule) sageRules.push(subRule);
			});
		}
	}

	if (atr.status === 'draft') {
		warnings.push({
			ruleId: atr.id,
			kind: 'draft_marked_revoked',
			detail: 'ATR draft status → Sage revoked=true so the rule does not load',
		});
	}

	return { rules: sageRules, warnings };
}

/**
 * Build a single Sage rule from a single ATR condition. Used by the split
 * path when the combined regex exceeds the length cap. The caller provides
 * a pre-allocated id (which already includes the letter suffix) so split
 * sub-rules share the same numeric base.
 */
function buildSplitSubRule(
	atr: ATRRule,
	sageChannel: SageMatchOn,
	condition: ATRArrayCondition,
	id: string,
	pickedAction: SageAction,
	warnings: ConversionWarning[],
): SageRule | null {
	const { pattern, needsUnicode } = sagePatternOf(condition.value);
	if (needsUnicode) {
		warnings.push({ ruleId: atr.id, kind: 'regex_compat_issue', detail: NEEDS_UNICODE_DETAIL });
		return null;
	}
	const compileError = validateRegexCompiles(pattern);
	if (compileError) {
		warnings.push({
			ruleId: atr.id,
			kind: 'regex_compat_issue',
			detail: `Split sub-pattern does not compile: ${compileError}`,
		});
		return null;
	}

	const sageCategory = mapCategory(atr.tags.category);
	const title = atr.title.length > 100 ? atr.title.slice(0, 97) + '...' : atr.title;
	const upstreamUrl = `https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/rules/${atr.tags.category}/${atr.id}.yaml`;
	const calibratedConfidence = pickConfidence(atr);
	const calibratedAction: SageAction =
		pickedAction === 'block' && calibratedConfidence < 0.85
			? 'require_approval'
			: pickedAction;

	// Per-condition description from ATR (if present) takes precedence over
	// the rule-level description summary for split rules. This lets each sub-
	// rule explain its own role rather than repeating the rule-wide summary.
	const detectsSummary =
		(condition.description && condition.description.length > 10
			? condition.description
			: extractDetectsSummary(atr.description)) ?? '';

	return {
		id,
		category: sageCategory,
		severity: SEVERITY_MAP[atr.severity],
		confidence: calibratedConfidence,
		action: calibratedAction,
		pattern,
		match_on: sageChannel,
		title,
		expires_at: null,
		revoked: atr.status === 'draft',
		case_insensitive: true,
		upstream: atr.id,
		upstream_url: upstreamUrl,
		upstream_license: 'MIT',
		detects: detectsSummary,
	};
}

/**
 * Letter suffix for split rules. Used when an ATR rule's combined regex
 * exceeds the length cap and the converter splits each condition into a
 * separate Sage rule (CLT-PRV-001a, CLT-PRV-001b, ...).
 */
function letterFromIndex(i: number): string {
	if (i < 26) return String.fromCharCode(97 + i); // a..z
	// Beyond 26 conditions: aa, ab, ac, ...
	const first = Math.floor(i / 26) - 1;
	const second = i % 26;
	return String.fromCharCode(97 + first) + String.fromCharCode(97 + second);
}

/**
 * Short codes for Sage match_on channels, used as disambiguator suffixes when
 * a single ATR rule produces multiple Sage rules (one per Sage channel — rare
 * since most ATR rules target a single channel via text-field collapse).
 */
function channelCode(channel: SageMatchOn): string {
	switch (channel) {
		case 'content':
			return 'CT';
		case 'url':
			return 'URL';
		case 'command':
			return 'CMD';
		case 'file_path':
			return 'FP';
		case 'domain':
			return 'DOM';
	}
}

/**
 * Convert many ATR rules to Sage rules. Aggregates warnings and uses a shared
 * id allocator so that the resulting Sage rules have sequential 3-digit ids
 * (CLT-PRV-001, CLT-PRV-002, ...) within each category, matching Sage's
 * existing convention.
 *
 * @param atrRules the ATR rules to convert
 * @param startingOffsets optional starting offsets per Sage category — pass
 *   `{prompt_injection: 7}` if Sage's existing rules already use CLT-PI-001
 *   through CLT-PI-007 so the new rules start at CLT-PI-008.
 */
export function atrToSageBatch(
	atrRules: readonly ATRRule[],
	startingOffsets: Readonly<Record<string, number>> = {},
): ConvertResult {
	const allocator = new SageIdAllocator(startingOffsets);
	const rules: SageRule[] = [];
	const warnings: ConversionWarning[] = [];
	for (const atr of atrRules) {
		const result = atrToSage(atr, allocator);
		rules.push(...result.rules);
		warnings.push(...result.warnings);
	}
	return { rules, warnings };
}

// ── YAML serialization ─────────────────────────────────────────────────────

/**
 * Serialize a list of Sage rules to a YAML string suitable for inclusion in
 * `threats/agent-layer.yaml`. The output matches the style used in Sage's
 * existing agent-layer.yaml (no list indentation, double-quoted ids,
 * single-line regex pattern, upstream comment after each rule).
 *
 * Caller is responsible for prepending file-level comments (license,
 * generation timestamp, upstream version) before this output.
 */
export function sageRulesToYaml(rules: readonly SageRule[]): string {
	return rules.map(serializeRule).join('\n\n');
}

function serializeRule(rule: SageRule): string {
	const lines: string[] = [];
	// Detects summary first — gives the reader the attack-scenario context
	// before they read the regex.
	if (rule.detects) {
		lines.push(`  # Detects: ${rule.detects}`);
	}
	lines.push(`- id: "${rule.id}"`);
	lines.push(`  category: ${rule.category}`);
	lines.push(`  severity: ${rule.severity}`);
	lines.push(`  confidence: ${rule.confidence}`);
	lines.push(`  action: ${rule.action}`);
	lines.push(`  pattern: ${yamlString(rule.pattern)}`);
	if (Array.isArray(rule.match_on)) {
		lines.push(`  match_on: [${rule.match_on.join(', ')}]`);
	} else {
		lines.push(`  match_on: ${rule.match_on}`);
	}
	if (rule.case_insensitive) {
		lines.push(`  case_insensitive: true`);
	}
	lines.push(`  title: ${yamlString(rule.title)}`);
	lines.push(`  expires_at: null`);
	lines.push(`  revoked: ${rule.revoked}`);
	if (rule.upstream) {
		const license = rule.upstream_license ?? 'MIT';
		const url = rule.upstream_url ?? '';
		lines.push(`  # Upstream: ${rule.upstream} (${license}) ${url ? '— ' + url : ''}`.trimEnd());
	}
	return lines.join('\n');
}

/**
 * YAML double-quote a string with proper escaping. Used for pattern, title
 * (which can contain quotes / special characters). Falls back to single-quoted
 * form if pattern contains a literal backslash-quote sequence that double-
 * quoted YAML cannot represent without escape ambiguity.
 */
function yamlString(s: string): string {
	// If the string contains no special characters, plain string is fine, but
	// YAML's plain-string grammar is fragile around colons + spaces, leading
	// hyphens, leading question marks, etc. Safer: always wrap in double
	// quotes with JSON-style escaping (YAML accepts JSON as a subset).
	return JSON.stringify(s);
}
