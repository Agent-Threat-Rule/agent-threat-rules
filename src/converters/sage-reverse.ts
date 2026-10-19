/**
 * Sage → ATR Converter (reverse direction)
 *
 * Converts a Sage threat rule (from gendigitalinc/sage `threats/*.yaml`) into
 * an ATR YAML rule suitable for contribution back to the ATR corpus.
 *
 * This is the smaller half of the bidirectional bridge. The forward
 * direction (atrToSage) sees the heavy traffic; this reverse direction
 * exists so that Sage maintainers who write rules in Sage's format can
 * contribute them upstream to ATR without manual schema rewriting.
 *
 * Lossy spots:
 * - Sage has no description field; we emit a placeholder description that
 *   humans must fill in before merging into ATR.
 * - Sage has no test_cases; we emit a TODO block instructing humans to add
 *   true_positives + true_negatives (required for ATR PR acceptance).
 * - Sage has no compliance metadata (eu_ai_act, nist_ai_rmf, etc.); humans
 *   must add these if the rule maps to a regulatory framework.
 * - Sage has no references (mitre_atlas, owasp_llm, etc.); humans must add.
 * - Sage `match_on: command|url|file_path|content|domain` → ATR field name.
 *   The translation is heuristic since Sage's "command" channel doesn't have
 *   a perfect ATR equivalent (closest is tool_args at invocation time).
 *
 * @module agent-threat-rules/converters/sage-reverse
 */

import type {
	ATRRule,
	ATRSeverity,
	ATRAction,
	ATRCategory,
	ATRArrayCondition,
} from '../types.js';
import type { SageRule, SageSeverity, SageAction, SageMatchOn } from './sage.js';

export interface ReverseConvertResult {
	readonly rule: ATRRule;
	readonly warnings: readonly ReverseWarning[];
}

export interface ReverseWarning {
	readonly sageId: string;
	readonly kind:
		| 'missing_description'
		| 'missing_test_cases'
		| 'missing_compliance'
		| 'missing_references'
		| 'category_unknown'
		| 'match_on_ambiguous'
		| 'case_sensitivity_lost';
	readonly detail: string;
}

// ── Reverse mappings ───────────────────────────────────────────────────────

/**
 * Sage category → ATR category. Inverse of CATEGORY_MAP in sage.ts.
 * Unknown Sage categories pass through with a warning; humans should review.
 */
const CATEGORY_REVERSE_MAP: Readonly<Record<string, ATRCategory>> = Object.freeze({
	prompt_injection: 'prompt-injection',
	mcp_poisoning: 'tool-poisoning',
	context_exfiltration: 'context-exfiltration',
	agent_manipulation: 'agent-manipulation',
	privilege_escalation: 'privilege-escalation',
	excessive_autonomy: 'excessive-autonomy',
	data_poisoning: 'data-poisoning',
	model_abuse: 'model-abuse',
	skill_compromise: 'skill-compromise',
});

const SEVERITY_REVERSE_MAP: Readonly<Record<SageSeverity, ATRSeverity>> = Object.freeze({
	critical: 'critical',
	high: 'high',
	medium: 'medium',
	low: 'low',
});

/**
 * Sage action → ATR action list. Sage's `block` could mean block_input,
 * block_output, or block_tool depending on context; default to the most
 * conservative `block_input + alert` combination.
 */
function reverseAction(sage: SageAction): ATRAction[] {
	switch (sage) {
		case 'block':
			return ['block_input', 'alert'];
		case 'require_approval':
			return ['escalate', 'alert'];
		case 'log':
			return ['alert'];
	}
}

/**
 * Sage match_on → ATR field name. Sage's "command" is closest to ATR's
 * tool_args at invocation; "file_path" maps similarly. "domain" has no clean
 * ATR equivalent (no DNS-tier rules in current ATR corpus).
 */
function reverseMatchOn(sageMatchOn: SageMatchOn): string {
	switch (sageMatchOn) {
		case 'url':
			return 'url';
		case 'command':
			return 'tool_args';
		case 'file_path':
			return 'tool_args';
		case 'content':
			return 'content';
		case 'domain':
			return 'tool_args';
	}
}

// ── Confidence ─────────────────────────────────────────────────────────────

/**
 * Convert Sage's numeric confidence (0.0-1.0) to ATR's `tags.confidence`
 * string enum (high/medium/low).
 */
function sageConfidenceToAtrConfidence(c: number): 'high' | 'medium' | 'low' {
	if (c >= 0.85) return 'high';
	if (c >= 0.6) return 'medium';
	return 'low';
}

// ── Core reverse conversion ────────────────────────────────────────────────

/**
 * Generate an ATR id placeholder. Real production use should override this
 * with a maintainer-assigned final id at PR time.
 */
function placeholderAtrId(sageId: string): string {
	// e.g. CLT-PI-001 → ATR-2026-PI001 (placeholder, human reviews)
	const idPart = sageId.replace(/^CLT-/, '').replace(/-/g, '');
	const year = new Date().getFullYear();
	return `ATR-${year}-${idPart.padStart(5, '0').slice(0, 5)}`;
}

/**
 * Convert a single Sage rule to an ATR rule.
 *
 * The output rule has TODO markers in description and test_cases fields
 * that humans must fill in before merging. See module docstring for lossy
 * spots that require human enrichment.
 */
export function sageToAtr(sage: SageRule): ReverseConvertResult {
	const warnings: ReverseWarning[] = [];

	// Category map with warning on unknown
	const atrCategory = CATEGORY_REVERSE_MAP[sage.category];
	if (!atrCategory) {
		warnings.push({
			sageId: sage.id,
			kind: 'category_unknown',
			detail: `Sage category "${sage.category}" not in known reverse map; defaulting to skill-compromise (closest catch-all)`,
		});
	}

	// match_on can be single or array. For ATR, we emit one condition per
	// match_on field.
	const matchOnList: SageMatchOn[] = Array.isArray(sage.match_on)
		? [...sage.match_on]
		: [sage.match_on];

	if (matchOnList.length > 1) {
		warnings.push({
			sageId: sage.id,
			kind: 'match_on_ambiguous',
			detail: `Multi-channel match_on=${matchOnList.join(',')} expanded to ${matchOnList.length} ATR conditions`,
		});
	}

	// Build conditions. An ATR engine matches every regex condition
	// case-insensitively, whatever the pattern says (SPEC §6.4), so the
	// condition always gets (?i) and reads the way it behaves. A case-sensitive
	// Sage rule cannot keep that distinction in ATR; say so instead of
	// importing a pattern that only looks case-sensitive.
	const regexValue = sage.pattern.startsWith('(?i)') ? sage.pattern : `(?i)${sage.pattern}`;
	if (!sage.case_insensitive) {
		warnings.push({
			sageId: sage.id,
			kind: 'case_sensitivity_lost',
			detail:
				'Sage rule is case-sensitive; ATR matches every regex condition case-insensitively (SPEC §6.4), so the imported rule can match more inputs',
		});
	}

	const conditions: ATRArrayCondition[] = matchOnList.map((m) => ({
		field: reverseMatchOn(m),
		operator: 'regex',
		value: regexValue,
		description: `Imported from Sage rule ${sage.id}`,
	}));

	warnings.push({
		sageId: sage.id,
		kind: 'missing_description',
		detail: 'Description placeholder used — fill in attack details before merging',
	});
	warnings.push({
		sageId: sage.id,
		kind: 'missing_test_cases',
		detail: 'Sage rules ship without test cases — add true_positives + true_negatives before ATR PR',
	});
	warnings.push({
		sageId: sage.id,
		kind: 'missing_compliance',
		detail: 'Add compliance.eu_ai_act + nist_ai_rmf + iso_42001 if rule maps to regulatory frameworks',
	});
	warnings.push({
		sageId: sage.id,
		kind: 'missing_references',
		detail: 'Add references.mitre_atlas / mitre_attack / owasp_llm / cve where applicable',
	});

	const now = new Date();
	const dateStr = `${now.getUTCFullYear()}/${String(now.getUTCMonth() + 1).padStart(2, '0')}/${String(now.getUTCDate()).padStart(2, '0')}`;

	const rule: ATRRule = {
		title: sage.title,
		id: placeholderAtrId(sage.id),
		status: 'draft', // require human review before stable
		description:
			'TODO: replace this placeholder. Describe the attack pattern this rule detects, what it does NOT detect, ' +
			`and any known false-positive surface. Imported from Sage rule ${sage.id} ` +
			`(${sage.upstream_url ?? 'no upstream url'}).`,
		author: 'Sage (Gen Digital Inc.)',
		date: dateStr,
		schema_version: '0.1',
		detection_tier: 'pattern',
		maturity: 'experimental',
		severity: SEVERITY_REVERSE_MAP[sage.severity],
		tags: {
			category: atrCategory ?? 'skill-compromise',
			confidence: sageConfidenceToAtrConfidence(sage.confidence),
		},
		agent_source: {
			type: 'tool_call',
		},
		detection: {
			conditions,
			condition: 'any',
		},
		response: {
			actions: reverseAction(sage.action),
		},
		// Confidence: ATR's numeric scale is 0-100; multiply Sage's 0-1.
		confidence: Math.round(sage.confidence * 100),
	};

	return { rule, warnings };
}

/**
 * Reverse-convert many Sage rules.
 */
export function sageToAtrBatch(
	sageRules: readonly SageRule[],
): { readonly rules: readonly ATRRule[]; readonly warnings: readonly ReverseWarning[] } {
	const rules: ATRRule[] = [];
	const warnings: ReverseWarning[] = [];
	for (const sage of sageRules) {
		const result = sageToAtr(sage);
		rules.push(result.rule);
		warnings.push(...result.warnings);
	}
	return { rules, warnings };
}
