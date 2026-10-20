/**
 * Tier 1: Blacklist Provider
 *
 * Hash/name-based lookup for known-bad skills.
 * O(1) lookup, zero false positives, zero latency.
 *
 * Sources: Threat Cloud skill_blacklist, CVE advisories, community reports.
 *
 * @module agent-threat-rules/tier1-blacklist
 */

import type { ATRMatch, ATRRule, ATRSeverity } from './types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BlacklistEntry {
  readonly skillHash: string;
  readonly skillName: string;
  readonly reason: string;
  readonly reportCount: number;
  readonly severity: ATRSeverity;
}

export interface BlacklistProvider {
  /** Check if a skill is blacklisted. Returns entry if found. */
  lookup(skillId: string): BlacklistEntry | undefined;
  /** Refresh the blacklist from source */
  refresh(): Promise<void>;
  /** Total blacklist size */
  size(): number;
}

// ---------------------------------------------------------------------------
// In-Memory Implementation
// ---------------------------------------------------------------------------

export class InMemoryBlacklist implements BlacklistProvider {
  private byHash: Map<string, BlacklistEntry>;
  private byName: Map<string, BlacklistEntry>;

  constructor(entries?: readonly BlacklistEntry[]) {
    this.byHash = new Map();
    this.byName = new Map();
    if (entries) {
      for (const entry of entries) {
        this.byHash.set(entry.skillHash, entry);
        this.byName.set(entry.skillName.toLowerCase(), entry);
      }
    }
  }

  lookup(skillId: string): BlacklistEntry | undefined {
    // Try hash lookup first, then name lookup
    return this.byHash.get(skillId) ?? this.byName.get(skillId.toLowerCase());
  }

  async refresh(): Promise<void> {
    // No-op for static blacklist. Override for TC-backed implementations.
  }

  size(): number {
    return this.byHash.size;
  }

  /** Replace all entries (immutable update) */
  withEntries(entries: readonly BlacklistEntry[]): InMemoryBlacklist {
    return new InMemoryBlacklist(entries);
  }
}

// ---------------------------------------------------------------------------
// Match Builder
// ---------------------------------------------------------------------------

/** Build a synthetic ATRMatch from a blacklist hit */
export function buildBlacklistMatch(entry: BlacklistEntry): ATRMatch {
  const syntheticRule: ATRRule = {
    title: `Blacklisted Skill: ${entry.skillName}`,
    id: `tier1-blacklist-${entry.skillHash.slice(0, 8)}`,
    status: 'stable' as const,
    description: `Skill "${entry.skillName}" is on the community blacklist. ${entry.reason}. Reported by ${entry.reportCount} users.`,
    author: 'atr-engine/tier1-blacklist',
    date: new Date().toISOString().slice(0, 10),
    severity: entry.severity,
    tags: {
      category: 'skill-compromise',
      subcategory: 'blacklisted',
      confidence: 'high' as const,
    },
    agent_source: { type: 'skill_lifecycle' as const },
    detection: { conditions: [], condition: 'tier1-blacklist-match' },
    response: {
      actions: ['block_tool' as const, 'alert' as const],
      message_template: `Blocked: "${entry.skillName}" is a known malicious skill (${entry.reportCount} community reports)`,
    },
  };

  return {
    rule: syntheticRule,
    matchedConditions: ['blacklist_hash', 'blacklist_name'],
    matchedPatterns: [`hash:${entry.skillHash}`, `name:${entry.skillName}`],
    confidence: 1.0,
    timestamp: new Date().toISOString(),
    scan_context: 'native' as const,
    decidedBy: 'blacklist' as const,
  };
}

/**
 * Resolve skill identifier from event for blacklist lookup.
 * Prioritizes package-level identifiers (hash, package name) over
 * tool function names, since blacklists store package names.
 */
export function resolveSkillId(event: { fields?: Record<string, string>; metadata?: Record<string, unknown> }): string | undefined {
  return (
    (event.metadata?.skillHash as string) ??
    (event.metadata?.packageName as string) ??
    (event.metadata?.skillId as string) ??
    event.fields?.skill_hash ??
    event.fields?.package_name ??
    event.fields?.skill_name ??
    event.fields?.skill_id ??
    event.fields?.tool_name ??
    undefined
  );
}
