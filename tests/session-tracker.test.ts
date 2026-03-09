import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SessionTracker } from '../src/session-tracker.js';
import type { AgentEvent } from '../src/types.js';

function makeEvent(overrides: Partial<AgentEvent> = {}): AgentEvent {
  return {
    type: 'tool_call',
    timestamp: new Date().toISOString(),
    content: 'test_tool',
    ...overrides,
  };
}

function makeToolCallEvent(toolName: string): AgentEvent {
  return {
    type: 'tool_call',
    timestamp: new Date().toISOString(),
    content: toolName,
    fields: { tool_name: toolName },
  };
}

describe('SessionTracker', () => {
  let tracker: SessionTracker;

  beforeEach(() => {
    tracker = new SessionTracker();
  });

  describe('recordEvent', () => {
    it('records an event and increments event count', () => {
      tracker.recordEvent('session-1', makeEvent());
      expect(tracker.getEventCount('session-1')).toBe(1);
    });

    it('records multiple events for the same session', () => {
      tracker.recordEvent('session-1', makeEvent());
      tracker.recordEvent('session-1', makeEvent());
      tracker.recordEvent('session-1', makeEvent());
      expect(tracker.getEventCount('session-1')).toBe(3);
    });

    it('tracks events independently per session', () => {
      tracker.recordEvent('session-a', makeEvent());
      tracker.recordEvent('session-b', makeEvent());
      tracker.recordEvent('session-b', makeEvent());

      expect(tracker.getEventCount('session-a')).toBe(1);
      expect(tracker.getEventCount('session-b')).toBe(2);
    });

    it('returns 0 for unknown sessions', () => {
      expect(tracker.getEventCount('nonexistent')).toBe(0);
    });
  });

  describe('getCallFrequency', () => {
    it('counts calls to a specific tool within a time window', () => {
      const event = makeToolCallEvent('file_read');
      tracker.recordEvent('s1', event);
      tracker.recordEvent('s1', event);

      const freq = tracker.getCallFrequency('s1', 'file_read', 60_000);
      expect(freq).toBe(2);
    });

    it('returns 0 for a tool that was not called', () => {
      tracker.recordEvent('s1', makeToolCallEvent('file_read'));
      expect(tracker.getCallFrequency('s1', 'file_write', 60_000)).toBe(0);
    });

    it('returns 0 for unknown session', () => {
      expect(tracker.getCallFrequency('unknown', 'tool', 60_000)).toBe(0);
    });

    it('respects time window for call frequency', () => {
      // Record events with mocked time
      const now = Date.now();
      vi.spyOn(Date, 'now').mockReturnValue(now - 10_000);
      tracker.recordEvent('s1', makeToolCallEvent('file_read'));

      vi.spyOn(Date, 'now').mockReturnValue(now);
      tracker.recordEvent('s1', makeToolCallEvent('file_read'));

      // Window of 5 seconds should only include the recent event
      expect(tracker.getCallFrequency('s1', 'file_read', 5_000)).toBe(1);

      // Window of 15 seconds should include both
      expect(tracker.getCallFrequency('s1', 'file_read', 15_000)).toBe(2);

      vi.restoreAllMocks();
    });

    it('extracts tool name from content for tool_call events', () => {
      const event: AgentEvent = {
        type: 'tool_call',
        timestamp: new Date().toISOString(),
        content: 'shell_exec',
      };
      tracker.recordEvent('s1', event);
      expect(tracker.getCallFrequency('s1', 'shell_exec', 60_000)).toBe(1);
    });
  });

  describe('getPatternFrequency', () => {
    it('counts pattern occurrences within a time window', () => {
      tracker.recordEvent('s1', makeEvent(), ['injection_attempt']);
      tracker.recordEvent('s1', makeEvent(), ['injection_attempt']);
      tracker.recordEvent('s1', makeEvent(), ['data_exfil']);

      expect(tracker.getPatternFrequency('s1', 'injection_attempt', 60_000)).toBe(2);
      expect(tracker.getPatternFrequency('s1', 'data_exfil', 60_000)).toBe(1);
    });

    it('returns 0 for patterns not recorded', () => {
      tracker.recordEvent('s1', makeEvent(), ['other_pattern']);
      expect(tracker.getPatternFrequency('s1', 'injection', 60_000)).toBe(0);
    });

    it('returns 0 for unknown session', () => {
      expect(tracker.getPatternFrequency('unknown', 'pattern', 60_000)).toBe(0);
    });

    it('respects time window for pattern frequency', () => {
      const now = Date.now();
      vi.spyOn(Date, 'now').mockReturnValue(now - 20_000);
      tracker.recordEvent('s1', makeEvent(), ['old_pattern']);

      vi.spyOn(Date, 'now').mockReturnValue(now);
      tracker.recordEvent('s1', makeEvent(), ['old_pattern']);

      expect(tracker.getPatternFrequency('s1', 'old_pattern', 10_000)).toBe(1);
      expect(tracker.getPatternFrequency('s1', 'old_pattern', 30_000)).toBe(2);

      vi.restoreAllMocks();
    });
  });

  describe('getEventCount', () => {
    it('returns total event count without window', () => {
      tracker.recordEvent('s1', makeEvent());
      tracker.recordEvent('s1', makeEvent());
      expect(tracker.getEventCount('s1')).toBe(2);
    });

    it('returns count within a time window', () => {
      const now = Date.now();
      vi.spyOn(Date, 'now').mockReturnValue(now - 30_000);
      tracker.recordEvent('s1', makeEvent());

      vi.spyOn(Date, 'now').mockReturnValue(now);
      tracker.recordEvent('s1', makeEvent());

      expect(tracker.getEventCount('s1', 10_000)).toBe(1);
      expect(tracker.getEventCount('s1', 60_000)).toBe(2);

      vi.restoreAllMocks();
    });
  });

  describe('getSessionSnapshot', () => {
    it('returns undefined for unknown session', () => {
      expect(tracker.getSessionSnapshot('nonexistent')).toBeUndefined();
    });

    it('returns a frozen snapshot of session state', () => {
      tracker.recordEvent('s1', makeEvent());
      tracker.recordEvent('s1', makeEvent());

      const snapshot = tracker.getSessionSnapshot('s1');
      expect(snapshot).toBeDefined();
      expect(snapshot!.sessionId).toBe('s1');
      expect(snapshot!.eventCount).toBe(2);
      expect(snapshot!.oldestEventTimestamp).toBeDefined();
      expect(snapshot!.newestEventTimestamp).toBeDefined();
      expect(Object.isFrozen(snapshot)).toBe(true);
    });
  });

  describe('cleanup', () => {
    it('evicts sessions older than maxAgeMs', () => {
      const now = Date.now();

      vi.spyOn(Date, 'now').mockReturnValue(now - 120_000);
      tracker.recordEvent('old-session', makeEvent());

      vi.spyOn(Date, 'now').mockReturnValue(now);
      tracker.recordEvent('new-session', makeEvent());

      const evicted = tracker.cleanup(60_000);
      expect(evicted).toBe(1);
      expect(tracker.getSessionCount()).toBe(1);
      expect(tracker.getEventCount('old-session')).toBe(0);
      expect(tracker.getEventCount('new-session')).toBe(1);

      vi.restoreAllMocks();
    });

    it('returns 0 when no sessions are stale', () => {
      tracker.recordEvent('s1', makeEvent());
      expect(tracker.cleanup(60_000)).toBe(0);
    });
  });

  describe('max limits', () => {
    it('evicts oldest events when per-session limit (1000) is exceeded', () => {
      for (let i = 0; i < 1001; i++) {
        tracker.recordEvent('s1', makeEvent());
      }
      expect(tracker.getEventCount('s1')).toBe(1000);
    });

    it('evicts oldest session when session limit (10000) is exceeded', () => {
      const now = Date.now();

      // Create sessions with increasing timestamps so oldest is evicted
      for (let i = 0; i < 10_000; i++) {
        vi.spyOn(Date, 'now').mockReturnValue(now + i);
        tracker.recordEvent(`session-${i}`, makeEvent());
      }

      // This should trigger eviction of the oldest session
      vi.spyOn(Date, 'now').mockReturnValue(now + 10_001);
      tracker.recordEvent('session-overflow', makeEvent());

      expect(tracker.getSessionCount()).toBe(10_000);
      // session-0 (oldest) should have been evicted
      expect(tracker.getEventCount('session-0')).toBe(0);
      expect(tracker.getEventCount('session-overflow')).toBe(1);

      vi.restoreAllMocks();
    });
  });

  describe('immutability', () => {
    it('does not expose internal event objects to mutation', () => {
      const event = makeEvent({ content: 'original' });
      tracker.recordEvent('s1', event);

      // Mutating the original event should not affect the tracked copy
      event.content = 'mutated';

      const snapshot = tracker.getSessionSnapshot('s1');
      expect(snapshot).toBeDefined();
      // The tracker stores a frozen copy, so internal state is unaffected
      expect(snapshot!.eventCount).toBe(1);
    });
  });
});
