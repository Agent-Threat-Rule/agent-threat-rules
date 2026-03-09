/**
 * SessionTracker - Tracks per-session state for behavioral detection operators.
 *
 * Enables multi-turn injection detection, call frequency tracking,
 * and pattern repetition counting. All state is internal; public methods
 * return copies to preserve immutability.
 *
 * @module agent-threat-rules/session-tracker
 */

import type { AgentEvent } from './types.js';

/** Maximum number of events stored per session */
const MAX_EVENTS_PER_SESSION = 1000;

/** Maximum number of tracked sessions */
const MAX_SESSIONS = 10_000;

/** Internal record for a single tracked event */
interface TrackedEvent {
  readonly event: Readonly<AgentEvent>;
  readonly recordedAt: number;
  readonly toolName: string | undefined;
  readonly patterns: readonly string[];
}

/** Snapshot of session state returned to callers (immutable copy) */
export interface SessionStateSnapshot {
  readonly sessionId: string;
  readonly eventCount: number;
  readonly oldestEventTimestamp: number | undefined;
  readonly newestEventTimestamp: number | undefined;
}

/** Internal per-session state — never exposed directly */
interface SessionState {
  events: TrackedEvent[];
  callCounts: Map<string, number>;
  patternCounts: Map<string, number>;
  createdAt: number;
  lastActivityAt: number;
}

export class SessionTracker {
  private readonly sessions = new Map<string, SessionState>();

  /**
   * Record an agent event for the given session.
   * Extracts tool name and patterns from event fields/content.
   */
  recordEvent(sessionId: string, event: AgentEvent, patterns: readonly string[] = []): void {
    this.ensureCapacity();
    const state = this.getOrCreateSession(sessionId);
    const toolName = this.extractToolName(event);
    const now = Date.now();

    const tracked: TrackedEvent = {
      event: Object.freeze({ ...event }),
      recordedAt: now,
      toolName,
      patterns,
    };

    // Evict oldest if at capacity
    if (state.events.length >= MAX_EVENTS_PER_SESSION) {
      state.events = state.events.slice(1);
    }

    state.events = [...state.events, tracked];
    state.lastActivityAt = now;

    // Update call counts
    if (toolName) {
      const prev = state.callCounts.get(toolName) ?? 0;
      state.callCounts.set(toolName, prev + 1);
    }

    // Update pattern counts
    for (const p of patterns) {
      const prev = state.patternCounts.get(p) ?? 0;
      state.patternCounts.set(p, prev + 1);
    }
  }

  /**
   * Get the number of calls to a specific tool within a time window.
   */
  getCallFrequency(sessionId: string, toolName: string, windowMs: number): number {
    const state = this.sessions.get(sessionId);
    if (!state) return 0;

    const cutoff = Date.now() - windowMs;
    let count = 0;
    for (const tracked of state.events) {
      if (tracked.recordedAt >= cutoff && tracked.toolName === toolName) {
        count++;
      }
    }
    return count;
  }

  /**
   * Get the number of times a pattern has been observed within a time window.
   */
  getPatternFrequency(sessionId: string, pattern: string, windowMs: number): number {
    const state = this.sessions.get(sessionId);
    if (!state) return 0;

    const cutoff = Date.now() - windowMs;
    let count = 0;
    for (const tracked of state.events) {
      if (tracked.recordedAt >= cutoff && tracked.patterns.includes(pattern)) {
        count++;
      }
    }
    return count;
  }

  /**
   * Get total event count for a session, optionally within a time window.
   */
  getEventCount(sessionId: string, windowMs?: number): number {
    const state = this.sessions.get(sessionId);
    if (!state) return 0;

    if (windowMs === undefined) {
      return state.events.length;
    }

    const cutoff = Date.now() - windowMs;
    let count = 0;
    for (const tracked of state.events) {
      if (tracked.recordedAt >= cutoff) {
        count++;
      }
    }
    return count;
  }

  /**
   * Get an immutable snapshot of session state. Returns undefined if session does not exist.
   */
  getSessionSnapshot(sessionId: string): SessionStateSnapshot | undefined {
    const state = this.sessions.get(sessionId);
    if (!state) return undefined;

    const oldest = state.events.length > 0 ? state.events[0]!.recordedAt : undefined;
    const newest = state.events.length > 0 ? state.events[state.events.length - 1]!.recordedAt : undefined;

    return Object.freeze({
      sessionId,
      eventCount: state.events.length,
      oldestEventTimestamp: oldest,
      newestEventTimestamp: newest,
    });
  }

  /**
   * Evict sessions that have been inactive longer than maxAgeMs.
   * Returns the number of sessions evicted.
   */
  cleanup(maxAgeMs: number): number {
    const cutoff = Date.now() - maxAgeMs;
    let evicted = 0;

    for (const [id, state] of this.sessions) {
      if (state.lastActivityAt < cutoff) {
        this.sessions.delete(id);
        evicted++;
      }
    }

    return evicted;
  }

  /** Get the number of tracked sessions */
  getSessionCount(): number {
    return this.sessions.size;
  }

  /**
   * Ensure we don't exceed the maximum session count.
   * Evicts the oldest session if at capacity.
   */
  private ensureCapacity(): void {
    if (this.sessions.size < MAX_SESSIONS) return;

    let oldestId: string | undefined;
    let oldestTime = Infinity;

    for (const [id, state] of this.sessions) {
      if (state.lastActivityAt < oldestTime) {
        oldestTime = state.lastActivityAt;
        oldestId = id;
      }
    }

    if (oldestId) {
      this.sessions.delete(oldestId);
    }
  }

  private getOrCreateSession(sessionId: string): SessionState {
    const existing = this.sessions.get(sessionId);
    if (existing) return existing;

    const now = Date.now();
    const state: SessionState = {
      events: [],
      callCounts: new Map(),
      patternCounts: new Map(),
      createdAt: now,
      lastActivityAt: now,
    };
    this.sessions.set(sessionId, state);
    return state;
  }

  private extractToolName(event: AgentEvent): string | undefined {
    if (event.type === 'tool_call' || event.type === 'tool_response') {
      return event.fields?.['tool_name'] ?? event.content;
    }
    return undefined;
  }
}
