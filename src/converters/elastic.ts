/**
 * ATR-to-Elastic Query DSL Converter
 *
 * Converts ATR YAML rules into Elasticsearch Query DSL (JSON) that
 * a SOC analyst can use in Kibana or the Elasticsearch API.
 *
 * @module agent-threat-rules/converters/elastic
 */

import type { ATRRule, ATRArrayCondition } from '../types.js';
import { regexConditionSpec } from '../regex-dialect.js';

interface ElasticQuery {
  _meta: {
    rule_id: string;
    title: string;
    severity: string;
    category: string;
    source_type: string;
    condition_logic: string;
  };
  query: {
    bool: {
      should?: unknown[];
      must?: unknown[];
      minimum_should_match?: number;
    };
  };
}

/**
 * Convert a single ATR array condition to an Elastic Query DSL clause.
 */
function conditionToElastic(cond: ATRArrayCondition): unknown {
  const field = cond.field;
  const value = cond.value;

  switch (cond.operator) {
    case 'regex':
      // Lucene regular expressions have no inline flags, so a leading (?i)
      // group was never a flag there: Lucene reads it as literal characters
      // or rejects the query (not tested against a live cluster). Case-insensitivity
      // comes from case_insensitive below (SPEC §6.4: always), and m, s and x
      // have no effect in ATR.
      return {
        regexp: {
          [field]: {
            value: regexConditionSpec(value).source,
            flags: 'ALL',
            case_insensitive: true,
          },
        },
      };

    case 'contains':
      return {
        wildcard: {
          [field]: {
            value: `*${value}*`,
            case_insensitive: true,
          },
        },
      };

    case 'exact':
      return {
        term: {
          [field]: value,
        },
      };

    case 'starts_with':
      return {
        prefix: {
          [field]: {
            value: value,
            case_insensitive: true,
          },
        },
      };

    case 'gt':
      return { range: { [field]: { gt: Number(value) } } };

    case 'lt':
      return { range: { [field]: { lt: Number(value) } } };

    case 'gte':
      return { range: { [field]: { gte: Number(value) } } };

    case 'lte':
      return { range: { [field]: { lte: Number(value) } } };

    case 'eq':
      return { term: { [field]: Number(value) } };

    default:
      // Fallback: wildcard contains
      return {
        wildcard: {
          [field]: {
            value: `*${value}*`,
            case_insensitive: true,
          },
        },
      };
  }
}

/**
 * Convert an ATR rule to an Elasticsearch Query DSL object.
 *
 * Returns a JSON-serializable object with _meta and query fields.
 * - "any" condition logic -> bool.should with minimum_should_match=1
 * - "all" condition logic -> bool.must
 */
export function ruleToElastic(rule: ATRRule): ElasticQuery {
  const conditions = rule.detection.conditions;
  const logic = rule.detection.condition;

  const meta = {
    rule_id: rule.id,
    title: rule.title,
    severity: rule.severity,
    category: rule.tags.category,
    source_type: rule.agent_source.type,
    condition_logic: logic,
  };

  if (!Array.isArray(conditions)) {
    // Named-map format: return empty query with warning
    return {
      _meta: meta,
      query: {
        bool: {
          should: [],
          minimum_should_match: 0,
        },
      },
    };
  }

  const arrayConditions = conditions as ATRArrayCondition[];
  const clauses = arrayConditions.map(conditionToElastic);

  if (logic === 'all') {
    return {
      _meta: meta,
      query: {
        bool: {
          must: clauses,
        },
      },
    };
  }

  // Default: "any" -> should
  return {
    _meta: meta,
    query: {
      bool: {
        should: clauses,
        minimum_should_match: 1,
      },
    },
  };
}
