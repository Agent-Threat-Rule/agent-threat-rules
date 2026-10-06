import { describe, expect, it } from 'vitest';
import { reportNamesForYear } from '../scripts/sync-avid-db.js';

describe('reportNamesForYear', () => {
  it('returns every report when a year contains more than 1,000 files', () => {
    const reports = Array.from({ length: 1005 }, (_, index) => ({
      path: `reports/2026/AVID-2026-R${String(index + 1).padStart(4, '0')}.json`,
      type: 'blob',
    }));
    const tree = [
      ...reports,
      { path: 'reports/2025/AVID-2025-R0001.json', type: 'blob' },
      { path: 'reports/2026/README.md', type: 'blob' },
      { path: 'reports/2026/archive/old.json', type: 'blob' },
    ];

    const names = reportNamesForYear({ truncated: false, tree }, '2026');

    expect(names).toHaveLength(1005);
    expect(names[0]).toBe('AVID-2026-R0001.json');
    expect(names.at(-1)).toBe('AVID-2026-R1005.json');
  });

  it('rejects a truncated tree instead of silently missing reports', () => {
    expect(() => reportNamesForYear({ truncated: true, tree: [] }, '2026')).toThrow(
      'AVID Git tree response was truncated',
    );
  });
});
