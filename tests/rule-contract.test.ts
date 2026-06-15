import { describe, it, expect } from 'vitest';
import {
  MATURITIES, normalizeMaturity, laneAllows, requiresConfirm, validateContract,
} from '../src/quality/rule-contract.js';

describe('rule-contract (single source of truth)', () => {
  describe('normalizeMaturity', () => {
    it('passes canonical values through', () => {
      for (const m of MATURITIES) expect(normalizeMaturity(m)).toBe(m);
    });
    it('safe-fails missing/empty/unknown to experimental', () => {
      expect(normalizeMaturity(undefined)).toBe('experimental');
      expect(normalizeMaturity('')).toBe('experimental');
      expect(normalizeMaturity('   ')).toBe('experimental');
      expect(normalizeMaturity('needs-human-poc')).toBe('experimental');
    });
    it('trims surrounding whitespace', () => {
      expect(normalizeMaturity(' stable ')).toBe('stable');
    });
  });

  describe('laneAllows', () => {
    it('hunt allows every maturity except deprecated', () => {
      for (const m of MATURITIES) expect(laneAllows(m, 'hunt')).toBe(m !== 'deprecated');
      expect(laneAllows('garbage', 'hunt')).toBe(true); // normalizes to experimental
    });
    it('enforce = stable only', () => {
      expect(laneAllows('stable', 'enforce')).toBe(true);
      expect(laneAllows('test', 'enforce')).toBe(false);
      expect(laneAllows('experimental', 'enforce')).toBe(false);
      expect(laneAllows(undefined, 'enforce')).toBe(false);
    });
    it('alert = stable + test', () => {
      expect(laneAllows('stable', 'alert')).toBe(true);
      expect(laneAllows('test', 'alert')).toBe(true);
      expect(laneAllows('experimental', 'alert')).toBe(false);
    });
    it('deprecated never fires in ANY lane (self-contained, retired)', () => {
      for (const lane of ['enforce', 'alert', 'hunt'] as const) {
        expect(laneAllows('deprecated', lane)).toBe(false);
      }
    });
    it('draft fires only in hunt', () => {
      expect(laneAllows('draft', 'hunt')).toBe(true);
      expect(laneAllows('draft', 'alert')).toBe(false);
      expect(laneAllows('draft', 'enforce')).toBe(false);
    });
  });

  describe('requiresConfirm', () => {
    it('true only for confirm: embedding', () => {
      expect(requiresConfirm({ confirm: 'embedding' })).toBe(true);
      expect(requiresConfirm({})).toBe(false);
      expect(requiresConfirm({ confirm: 'other' })).toBe(false);
    });
  });

  describe('validateContract', () => {
    it('accepts valid maturity + confirm on a pattern rule', () => {
      expect(validateContract({ maturity: 'stable', confirm: 'embedding', detection: { method: 'pattern' } })).toEqual([]);
    });
    it('accepts a rule carrying neither field', () => {
      expect(validateContract({})).toEqual([]);
    });
    it('rejects an invalid maturity (the legacy needs-human-poc)', () => {
      expect(validateContract({ maturity: 'needs-human-poc' })).toHaveLength(1);
    });
    it('rejects an invalid confirm value', () => {
      expect(validateContract({ confirm: 'llm' })).toHaveLength(1);
    });
    it('rejects confirm: embedding on an unsupported detection method', () => {
      expect(validateContract({ confirm: 'embedding', detection: { method: 'behavioral' } })).toHaveLength(1);
    });
    it('rejects confirm on draft/experimental maturity (cross-field invariant)', () => {
      expect(validateContract({ confirm: 'embedding', maturity: 'experimental', detection: { method: 'pattern' } }).length).toBeGreaterThan(0);
      expect(validateContract({ confirm: 'embedding', maturity: 'draft', detection: { method: 'pattern' } }).length).toBeGreaterThan(0);
    });
    it('accepts confirm on maturity:test (the ATR-2026-00442 case)', () => {
      expect(validateContract({ confirm: 'embedding', maturity: 'test', detection: { method: 'pattern' } })).toEqual([]);
    });
    it('allows a null/unspecified maturity (safe-fails to experimental at runtime, no error)', () => {
      expect(validateContract({ maturity: null })).toEqual([]);
    });
  });
});
