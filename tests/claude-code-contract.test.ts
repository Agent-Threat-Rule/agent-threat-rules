/**
 * Claude Code hook contract (finding #8 — silent non-enforcement).
 *
 * `atr init` installs `atr guard` as a Claude Code PreToolUse hook. Claude Code
 * only honors a block when it reads hookSpecificOutput.permissionDecision. The
 * guard used to emit the generic { decision } shape, which Claude Code silently
 * ignores — so the hook looked installed and never actually blocked. These
 * tests pin the exact contract the host requires WHEN BLOCKING IS ENABLED AND
 * THE VERDICT RESTRAINS.
 *
 * Blocking is opt-in and off by default, so these tests pass `{ blocking: true }`
 * explicitly. Two things are never emitted regardless: any decision at all while
 * advisory, and `permissionDecision: "allow"` in either mode — "allow" is an
 * affirmative approval that suppresses the host's own permission prompt, so ATR
 * emitting it would make the host less safe than having no hook. The full
 * matrix is pinned in tests/enforcement.test.ts.
 */
import { describe, it, expect } from 'vitest';
import { toClaudeCodePreToolUse, toClaudeCodePostToolUse } from '../src/hook-handler.js';
import type { HookOutput } from '../src/types.js';

const out = (o: Partial<HookOutput>): HookOutput =>
  Object.freeze({ decision: 'allow', reason: 'x', ...o }) as HookOutput;

describe('Claude Code PreToolUse contract', () => {
  it('emits hookSpecificOutput.permissionDecision that maps 1:1 from a restraining verdict', () => {
    // 'allow' is deliberately absent from this list — it is not a decision ATR
    // is willing to emit. See the next test.
    for (const decision of ['ask', 'deny'] as const) {
      const p = toClaudeCodePreToolUse(out({ decision, reason: `r-${decision}` }), { blocking: true });
      const hso = p['hookSpecificOutput'] as Record<string, unknown>;
      expect(hso['hookEventName']).toBe('PreToolUse');
      expect(hso['permissionDecision']).toBe(decision);
      expect(hso['permissionDecisionReason']).toBe(`r-${decision}`);
    }
  });

  it('emits NO decision for an allow verdict, even with blocking on', () => {
    const p = toClaudeCodePreToolUse(out({ decision: 'allow', reason: 'No rules matched.' }), {
      blocking: true,
    });
    expect(p['hookSpecificOutput']).toBeUndefined();
    expect(JSON.stringify(p)).not.toContain('permissionDecision');
    // The verdict is still reported — omission is silence on the permission
    // channel, not silence altogether.
    expect(p['atr_decision']).toBe('allow');
  });

  it('does NOT emit a top-level decision field Claude Code could misread', () => {
    const p = toClaudeCodePreToolUse(out({ decision: 'deny', reason: 'blocked' }), { blocking: true });
    expect(p['decision']).toBeUndefined();
    // ATR verdict is preserved under a non-colliding key for logs / other consumers
    expect(p['atr_decision']).toBe('deny');
  });

  it('carries matched_rules through when present', () => {
    const p = toClaudeCodePreToolUse(
      out({ decision: 'deny', matched_rules: Object.freeze(['ATR-2026-00001']) }),
      { blocking: true }
    );
    expect(p['matched_rules']).toEqual(['ATR-2026-00001']);
  });

  it('falls back to message when reason is absent', () => {
    const p = toClaudeCodePreToolUse(
      { decision: 'deny', message: 'Blocked: exfil' } as HookOutput,
      { blocking: true }
    );
    const hso = p['hookSpecificOutput'] as Record<string, unknown>;
    expect(hso['permissionDecisionReason']).toBe('Blocked: exfil');
  });
});

describe('Claude Code PostToolUse contract', () => {
  it('blocks (decision: block) on a deny verdict — the tool already ran', () => {
    const p = toClaudeCodePostToolUse(out({ decision: 'deny', reason: 'poisoned output' }), { blocking: true });
    expect(p['decision']).toBe('block');
    expect(p['reason']).toBe('poisoned output');
    expect(p['atr_decision']).toBe('deny');
  });

  it('blocks on ask too, and passes on allow', () => {
    expect(toClaudeCodePostToolUse(out({ decision: 'ask' }), { blocking: true })['decision']).toBe('block');
    expect(toClaudeCodePostToolUse(out({ decision: 'allow' }), { blocking: true })['decision']).toBeUndefined();
  });
});
