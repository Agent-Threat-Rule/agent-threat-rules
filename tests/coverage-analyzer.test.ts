import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import yaml from 'js-yaml';
import { describe, expect, it } from 'vitest';
import { CoverageAnalyzer } from '../src/coverage-analyzer.js';

describe('CoverageAnalyzer', () => {
  it('uses the OWASP Agentic 2026 registry names', () => {
    const registry = JSON.parse(
      readFileSync(
        resolve(import.meta.dirname, '../data/compliance-frameworks/owasp_agentic.json'),
        'utf8',
      ),
    ) as { valids: Record<string, string> };
    const expected = Object.entries(registry.valids).map(([id, name]) => ({
      id: id.replace(':2026', ''),
      name,
    }));
    const report = new CoverageAnalyzer([]).analyze();
    const actual = report.gaps
      .filter((gap) => gap.framework === 'OWASP Agentic Top 10')
      .map((gap) => ({ id: gap.riskId, name: gap.riskName }));

    expect(actual).toEqual(expected);
  });

  it('includes every live rule category', () => {
    const expected = readdirSync(resolve(import.meta.dirname, '../rules'), {
      withFileTypes: true,
    })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();
    const actual = Object.keys(new CoverageAnalyzer([]).analyze().categoryDistribution).sort();
    const schema = yaml.load(
      readFileSync(resolve(import.meta.dirname, '../spec/atr-schema.yaml'), 'utf8'),
    ) as { properties: { tags: { properties: { category: { enum: string[] } } } } };

    expect(actual).toEqual(expected);
    expect(schema.properties.tags.properties.category.enum.sort()).toEqual(expected);
  });
});
