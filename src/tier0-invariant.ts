/**
 * Tier 0: Invariant Enforcement
 *
 * Hard boundaries that enforce what a skill is ALLOWED to do,
 * regardless of what its description says or how it phrases requests.
 *
 * This is NOT pattern matching. It is permission checking.
 * A skill declares capabilities in its manifest. Any action outside
 * the manifest is immediately denied with severity=critical.
 *
 * Inspired by Tesla's AEB (Automatic Emergency Braking):
 * it doesn't care what the neural network thinks -- it enforces physics.
 *
 * @module agent-threat-rules/tier0-invariant
 */

import { extractCapabilities } from './capability-extractor.js';
import type { AgentEvent, ATRMatch, ATRRule, ATRSeverity } from './types.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Simple glob match: supports * (any chars) and ** (any path segments) */
function simpleGlobMatch(value: string, pattern: string): boolean {
  if (pattern === '*' || pattern === '**') return true;
  if (pattern === value) return true;

  // Convert glob to regex: * → [^/]*, ** → .*, escape rest
  const regexStr = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*\*/g, '<<GLOBSTAR>>')
    .replace(/\*/g, '[^/]*')
    .replace(/<<GLOBSTAR>>/g, '.*');

  try {
    return new RegExp(`^${regexStr}$`).test(value);
  } catch {
    return value.startsWith(pattern.replace(/\*/g, ''));
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Skill capability manifest -- declares what a skill is allowed to do */
export interface SkillManifest {
  readonly skillId: string;
  readonly allowedPaths?: readonly string[];
  readonly allowedHosts?: readonly string[];
  readonly allowedEnvVars?: readonly string[];
  readonly allowedCommands?: readonly string[];
  readonly maxNetworkCalls?: number;
  readonly allowConfigModification?: boolean;
}

export type InvariantViolationType =
  | 'path_scope'
  | 'host_scope'
  | 'env_scope'
  | 'command_scope'
  | 'config_modification'
  | 'network_limit';

/** Result when an invariant is violated */
export interface InvariantViolation {
  readonly skillId: string;
  readonly violationType: InvariantViolationType;
  readonly description: string;
  readonly observedValue: string;
  readonly allowedValues: readonly string[];
}

// ---------------------------------------------------------------------------
// Invariant Checker
// ---------------------------------------------------------------------------

export class InvariantChecker {
  private readonly manifests: ReadonlyMap<string, SkillManifest>;

  constructor(manifests: ReadonlyMap<string, SkillManifest> | SkillManifest[]) {
    const map = new Map<string, SkillManifest>();
    if (Array.isArray(manifests)) {
      for (const m of manifests) {
        map.set(m.skillId, m);
      }
    } else {
      manifests.forEach((v, k) => map.set(k, v));
    }
    this.manifests = map;
  }

  /**
   * Check an event against the skill's manifest.
   * Returns empty array if no violations (or no manifest for the skill).
   */
  check(event: AgentEvent): readonly InvariantViolation[] {
    const skillId = this.resolveSkillId(event);
    if (!skillId) return [];

    const manifest = this.manifests.get(skillId);
    if (!manifest) return []; // No manifest = fail-open (unmanifested skills are not checked)

    const allText = [
      event.content ?? '',
      event.fields?.tool_args ?? '',
      event.fields?.tool_response ?? '',
    ].join(' ');

    const caps = extractCapabilities(allText);
    const violations: InvariantViolation[] = [];

    // Check filesystem paths
    if (manifest.allowedPaths && caps.filesystemPaths.length > 0) {
      for (const path of caps.filesystemPaths) {
        const allowed = manifest.allowedPaths.some((pattern) =>
          simpleGlobMatch(path, pattern)
        );
        if (!allowed) {
          violations.push({
            skillId,
            violationType: 'path_scope',
            description: `Skill "${skillId}" accessed path "${path}" outside allowed scope`,
            observedValue: path,
            allowedValues: manifest.allowedPaths,
          });
        }
      }
    }

    // Check network hosts
    if (manifest.allowedHosts && caps.networkTargets.length > 0) {
      for (const host of caps.networkTargets) {
        const allowed = manifest.allowedHosts.some(
          (pattern) => host === pattern || host.endsWith('.' + pattern) || pattern === '*'
        );
        if (!allowed) {
          violations.push({
            skillId,
            violationType: 'host_scope',
            description: `Skill "${skillId}" contacted host "${host}" outside allowed scope`,
            observedValue: host,
            allowedValues: manifest.allowedHosts,
          });
        }
      }
    }

    // Check environment variables
    if (manifest.allowedEnvVars && caps.envAccesses.length > 0) {
      for (const envVar of caps.envAccesses) {
        const allowed = manifest.allowedEnvVars.some(
          (pattern) => envVar === pattern || (pattern.endsWith('*') && envVar.startsWith(pattern.slice(0, -1)))
        );
        if (!allowed) {
          violations.push({
            skillId,
            violationType: 'env_scope',
            description: `Skill "${skillId}" accessed env var "${envVar}" outside allowed scope`,
            observedValue: envVar,
            allowedValues: manifest.allowedEnvVars,
          });
        }
      }
    }

    // Check command execution
    if (manifest.allowedCommands && caps.processExecs.length > 0) {
      for (const cmd of caps.processExecs) {
        const allowed = manifest.allowedCommands.some(
          (pattern) => cmd === pattern || cmd.startsWith(pattern + ' ')
        );
        if (!allowed) {
          violations.push({
            skillId,
            violationType: 'command_scope',
            description: `Skill "${skillId}" executed command "${cmd}" outside allowed scope`,
            observedValue: cmd,
            allowedValues: manifest.allowedCommands,
          });
        }
      }
    }

    // Check config modification
    if (manifest.allowConfigModification === false && caps.configModifications) {
      violations.push({
        skillId,
        violationType: 'config_modification',
        description: `Skill "${skillId}" attempted to modify agent configuration files`,
        observedValue: 'config file access detected',
        allowedValues: ['none'],
      });
    }

    return violations;
  }

  /** Build a synthetic ATRMatch from an invariant violation */
  buildDenyMatch(violation: InvariantViolation): ATRMatch {
    const syntheticRule: ATRRule = {
      title: `Invariant Violation: ${violation.violationType}`,
      id: `tier0-invariant-${violation.violationType}`,
      status: 'stable' as const,
      description: violation.description,
      author: 'atr-engine/tier0',
      date: new Date().toISOString().slice(0, 10),
      severity: 'critical' as ATRSeverity,
      tags: {
        category: 'privilege-escalation',
        subcategory: violation.violationType,
        confidence: 'high' as const,
      },
      agent_source: { type: 'skill_permission' as const },
      detection: { conditions: [], condition: 'tier0-invariant' },
      response: {
        actions: ['block_input' as const, 'alert' as const, 'snapshot' as const],
        message_template: violation.description,
      },
    };

    return {
      rule: syntheticRule,
      matchedConditions: [violation.violationType],
      matchedPatterns: [`${violation.observedValue} not in [${violation.allowedValues.join(', ')}]`],
      confidence: 1.0,
      timestamp: new Date().toISOString(),
      scan_context: 'native' as const,
      decidedBy: 'invariant' as const,
    };
  }

  /** Resolve skill ID from event metadata */
  private resolveSkillId(event: AgentEvent): string | undefined {
    const fromMetadata = event.metadata?.skillId;
    if (typeof fromMetadata === 'string') return fromMetadata;
    return event.fields?.skill_id ?? event.fields?.tool_name ?? undefined;
  }
}
