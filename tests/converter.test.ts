import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { convertRule, convertAllRules } from '../src/converters/index.js';
import { ruleToSPL } from '../src/converters/splunk.js';
import { ruleToElastic } from '../src/converters/elastic.js';
import { scanResultToSARIF } from '../src/converters/sarif.js';
import { loadRuleFile, loadRulesFromDirectory } from '../src/loader.js';
import type { ATRRule, ScanResult, ATRMatch } from '../src/types.js';

const RULES_DIR = join(__dirname, '..', 'rules');
const ATR_001_PATH = join(RULES_DIR, 'prompt-injection', 'ATR-2026-00001-direct-prompt-injection.yaml');

describe('SIEM Converter', () => {
  describe('Splunk SPL Conversion', () => {
    it('converts ATR-2026-00001 to valid SPL', () => {
      const rule = loadRuleFile(ATR_001_PATH);
      const spl = ruleToSPL(rule);

      // Should include rule metadata in comments
      expect(spl).toContain('ATR-2026-00001');
      expect(spl).toContain('Direct Prompt Injection');
      expect(spl).toContain('high');

      // Should include a base search
      expect(spl).toContain('index=ai_agent_logs');

      // Should include match() for regex conditions with OR logic
      expect(spl).toContain('match(');
      expect(spl).toContain('OR');

      // Should include a table command
      expect(spl).toContain('| table');
    });

    it('includes the field name from conditions', () => {
      const rule = loadRuleFile(ATR_001_PATH);
      const spl = ruleToSPL(rule);

      expect(spl).toContain('user_input');
    });

    it('handles convertRule wrapper for splunk', () => {
      const rule = loadRuleFile(ATR_001_PATH);
      const result = convertRule(rule, 'splunk');

      expect(result.ruleId).toBe('ATR-2026-00001');
      expect(result.title).toContain('Direct Prompt Injection');
      expect(result.severity).toBe('high');
      expect(result.format).toBe('splunk');
      expect(result.query).toContain('index=ai_agent_logs');
    });
  });

  describe('Elastic Query DSL Conversion', () => {
    it('converts ATR-2026-00001 to valid Elastic query', () => {
      const rule = loadRuleFile(ATR_001_PATH);
      const elastic = ruleToElastic(rule);

      // Check _meta
      expect(elastic._meta.rule_id).toBe('ATR-2026-00001');
      expect(elastic._meta.title).toContain('Direct Prompt Injection');
      expect(elastic._meta.severity).toBe('high');
      expect(elastic._meta.category).toBe('prompt-injection');

      // Should use bool.should for "any" logic
      expect(elastic.query.bool.should).toBeDefined();
      expect(elastic.query.bool.minimum_should_match).toBe(1);
      expect(elastic.query.bool.must).toBeUndefined();

      // Should have regexp clauses (all conditions in ATR-001 are regex)
      const shouldClauses = elastic.query.bool.should as unknown[];
      expect(shouldClauses.length).toBeGreaterThan(0);

      // Each clause should be a regexp query
      for (const clause of shouldClauses) {
        const c = clause as Record<string, unknown>;
        expect(c).toHaveProperty('regexp');
      }
    });

    it('handles convertRule wrapper for elastic', () => {
      const rule = loadRuleFile(ATR_001_PATH);
      const result = convertRule(rule, 'elastic');

      expect(result.ruleId).toBe('ATR-2026-00001');
      expect(result.format).toBe('elastic');

      // query should be valid JSON
      const parsed = JSON.parse(result.query);
      expect(parsed._meta.rule_id).toBe('ATR-2026-00001');
      expect(parsed.query.bool.should).toBeDefined();
    });
  });

  describe('Condition logic', () => {
    it('uses bool.should for "any" condition logic', () => {
      const rule = loadRuleFile(ATR_001_PATH);
      expect(rule.detection.condition).toBe('any');

      const elastic = ruleToElastic(rule);
      expect(elastic.query.bool.should).toBeDefined();
      expect(elastic.query.bool.must).toBeUndefined();
    });

    it('uses bool.must for "all" condition logic', () => {
      // Create a synthetic rule with "all" logic
      const rule = loadRuleFile(ATR_001_PATH);
      const allRule: ATRRule = {
        ...rule,
        detection: {
          ...rule.detection,
          condition: 'all',
          // Use only 2 conditions to keep the test small
          conditions: (rule.detection.conditions as unknown[]).slice(0, 2) as ATRRule['detection']['conditions'],
        },
      };

      const elastic = ruleToElastic(allRule);
      expect(elastic.query.bool.must).toBeDefined();
      expect(elastic.query.bool.should).toBeUndefined();
    });

    it('chains conditions sequentially for "all" in Splunk', () => {
      const rule = loadRuleFile(ATR_001_PATH);
      const allRule: ATRRule = {
        ...rule,
        detection: {
          ...rule.detection,
          condition: 'all',
          conditions: (rule.detection.conditions as unknown[]).slice(0, 2) as ATRRule['detection']['conditions'],
        },
      };

      const spl = ruleToSPL(allRule);

      // "all" logic should produce sequential | regex lines, not OR
      expect(spl).toContain('| regex user_input=');
      expect(spl).not.toContain('OR');
    });
  });

  describe('Bulk conversion', () => {
    it('converts all 61 rules to Splunk without error', () => {
      const results = convertAllRules(RULES_DIR, 'splunk');

      expect(results.length).toBeGreaterThanOrEqual(61);

      for (const result of results) {
        expect(result.ruleId).toMatch(/^ATR-\d{4}-\d{5}$/);
        expect(result.format).toBe('splunk');
        expect(result.query.length).toBeGreaterThan(0);
        expect(result.severity).toBeTruthy();
        expect(result.title).toBeTruthy();
      }
    });

    it('converts all 61 rules to Elastic without error', () => {
      const results = convertAllRules(RULES_DIR, 'elastic');

      expect(results.length).toBeGreaterThanOrEqual(61);

      for (const result of results) {
        expect(result.ruleId).toMatch(/^ATR-\d{4}-\d{5}$/);
        expect(result.format).toBe('elastic');

        // Each result query should be valid JSON
        const parsed = JSON.parse(result.query);
        expect(parsed._meta).toBeDefined();
        expect(parsed.query.bool).toBeDefined();
      }
    });
  });

  describe('Operator support', () => {
    it('converts contains operator to wildcard in Elastic', () => {
      const rule: ATRRule = {
        title: 'Test',
        id: 'ATR-2026-00999',
        status: 'experimental',
        description: 'test',
        author: 'test',
        date: '2026/01/01',
        severity: 'medium',
        tags: { category: 'prompt-injection' },
        agent_source: { type: 'llm_io' },
        detection: {
          conditions: [
            { field: 'user_input', operator: 'contains', value: 'malicious_string' },
          ],
          condition: 'any',
        },
        response: { actions: ['alert'] },
      };

      const elastic = ruleToElastic(rule);
      const clause = (elastic.query.bool.should as Record<string, unknown>[])[0];
      expect(clause).toHaveProperty('wildcard');

      const spl = ruleToSPL(rule);
      expect(spl).toContain('malicious_string');
    });

    it('converts numeric operators to range in Elastic', () => {
      const rule: ATRRule = {
        title: 'Test Numeric',
        id: 'ATR-2026-00998',
        status: 'experimental',
        description: 'test',
        author: 'test',
        date: '2026/01/01',
        severity: 'high',
        tags: { category: 'excessive-autonomy' },
        agent_source: { type: 'agent_behavior' },
        detection: {
          conditions: [
            { field: 'call_count', operator: 'gt', value: '100' },
            { field: 'duration', operator: 'lte', value: '5' },
          ],
          condition: 'all',
        },
        response: { actions: ['alert'] },
      };

      const elastic = ruleToElastic(rule);
      const mustClauses = elastic.query.bool.must as Record<string, unknown>[];
      expect(mustClauses).toHaveLength(2);

      const rangeClause1 = mustClauses[0] as { range: Record<string, unknown> };
      expect(rangeClause1.range.call_count).toEqual({ gt: 100 });

      const rangeClause2 = mustClauses[1] as { range: Record<string, unknown> };
      expect(rangeClause2.range.duration).toEqual({ lte: 5 });

      const spl = ruleToSPL(rule);
      expect(spl).toContain('| where call_count > 100');
      expect(spl).toContain('| where duration <= 5');
    });
  });
});

// ─── SARIF Converter Tests ───────────────────────────────────────────

describe('SARIF Converter', () => {
  const makeRule = (overrides: Partial<ATRRule> = {}): ATRRule => ({
    id: 'ATR-2026-00001',
    title: 'Direct Prompt Injection',
    description: 'Detects direct prompt injection attempts.',
    severity: 'high',
    status: 'active',
    schema_version: '0.1',
    author: 'test',
    date: '2026/01/01',
    tags: { category: 'prompt-injection', subcategory: 'direct', confidence: 'high' },
    detection: { conditions: [], condition: 'any' },
    response: { actions: ['alert'] },
    ...overrides,
  });

  const makeMatch = (overrides: Partial<ATRMatch> = {}): ATRMatch => ({
    rule: makeRule(),
    confidence: 0.95,
    matchedConditions: ['regex: ignore.*instructions'],
    scan_context: 'mcp',
    ...overrides,
  });

  const makeScanResult = (overrides: Partial<ScanResult> = {}): ScanResult => ({
    scan_type: 'mcp',
    content_hash: 'abc123',
    timestamp: '2026-01-01T00:00:00Z',
    rules_loaded: 100,
    matches: [makeMatch()],
    threat_count: 1,
    ...overrides,
  });

  it('produces valid SARIF v2.1.0 structure', () => {
    const sarif = scanResultToSARIF([makeScanResult()], '1.1.0') as Record<string, unknown>;

    expect(sarif['$schema']).toContain('sarif-schema-2.1.0');
    expect(sarif['version']).toBe('2.1.0');
    expect(sarif['runs']).toBeInstanceOf(Array);

    const runs = sarif['runs'] as Array<Record<string, unknown>>;
    expect(runs).toHaveLength(1);

    const run = runs[0]!;
    const tool = run['tool'] as Record<string, unknown>;
    const driver = tool['driver'] as Record<string, unknown>;
    expect(driver['name']).toBe('ATR (Agent Threat Rules)');
    expect(driver['version']).toBe('1.1.0');
    expect(driver['rules']).toBeInstanceOf(Array);
  });

  it('maps severity to SARIF levels correctly', () => {
    const criticalResult = makeScanResult({
      matches: [makeMatch({ rule: makeRule({ severity: 'critical' }) })],
    });
    const mediumResult = makeScanResult({
      matches: [makeMatch({ rule: makeRule({ severity: 'medium', id: 'ATR-2026-00002' }) })],
    });
    const lowResult = makeScanResult({
      matches: [makeMatch({ rule: makeRule({ severity: 'low', id: 'ATR-2026-00003' }) })],
    });

    const sarif = scanResultToSARIF(
      [criticalResult, mediumResult, lowResult], '1.0.0'
    ) as { runs: Array<{ results: Array<{ level: string }> }> };

    const results = sarif.runs[0]!.results;
    expect(results[0]!.level).toBe('error');    // critical → error
    expect(results[1]!.level).toBe('warning');  // medium → warning
    expect(results[2]!.level).toBe('note');     // low → note
  });

  it('maps severity to security-severity scores', () => {
    const sarif = scanResultToSARIF([makeScanResult()], '1.0.0') as {
      runs: Array<{ tool: { driver: { rules: Array<{ properties: { 'security-severity': string } }> } } }>;
    };
    const rules = sarif.runs[0]!.tool.driver.rules;
    // high severity → 8.0
    expect(rules[0]!.properties['security-severity']).toBe('8.0');
  });

  it('deduplicates rules across multiple results', () => {
    const result1 = makeScanResult();
    const result2 = makeScanResult({ content_hash: 'def456' });

    const sarif = scanResultToSARIF([result1, result2], '1.0.0') as {
      runs: Array<{ tool: { driver: { rules: object[] } }; results: object[] }>;
    };
    // Same rule ID in both results → only 1 rule definition
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(1);
    // But 2 result entries
    expect(sarif.runs[0]!.results).toHaveLength(2);
  });

  it('includes file locations when input_file is set', () => {
    const result = makeScanResult({ input_file: process.cwd() + '/skills/test/SKILL.md' });

    const sarif = scanResultToSARIF([result], '1.0.0') as {
      runs: Array<{ results: Array<{ locations?: Array<{ physicalLocation: { artifactLocation: { uri: string } } }> }> }>;
    };
    const loc = sarif.runs[0]!.results[0]!.locations;
    expect(loc).toBeDefined();
    expect(loc![0]!.physicalLocation.artifactLocation.uri).toBe('skills/test/SKILL.md');
  });

  it('omits locations when input_file is not set', () => {
    const result = makeScanResult();

    const sarif = scanResultToSARIF([result], '1.0.0') as {
      runs: Array<{ results: Array<{ locations?: unknown }> }>;
    };
    expect(sarif.runs[0]!.results[0]!.locations).toBeUndefined();
  });

  it('includes confidence and scan_context in result properties', () => {
    const sarif = scanResultToSARIF([makeScanResult()], '1.0.0') as {
      runs: Array<{ results: Array<{ properties: { confidence: number; scan_context: string } }> }>;
    };
    const props = sarif.runs[0]!.results[0]!.properties;
    expect(props.confidence).toBe(0.95);
    expect(props.scan_context).toBe('mcp');
  });

  it('handles empty results array', () => {
    const sarif = scanResultToSARIF([], '1.0.0') as {
      runs: Array<{ tool: { driver: { rules: object[] } }; results: object[] }>;
    };
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(0);
    expect(sarif.runs[0]!.results).toHaveLength(0);
  });

  it('handles results with no matches', () => {
    const result = makeScanResult({ matches: [], threat_count: 0 });
    const sarif = scanResultToSARIF([result], '1.0.0') as {
      runs: Array<{ results: object[] }>;
    };
    expect(sarif.runs[0]!.results).toHaveLength(0);
  });

  it('includes matched conditions in result message', () => {
    const sarif = scanResultToSARIF([makeScanResult()], '1.0.0') as {
      runs: Array<{ results: Array<{ message: { text: string } }> }>;
    };
    const msg = sarif.runs[0]!.results[0]!.message.text;
    expect(msg).toContain('Direct Prompt Injection');
    expect(msg).toContain('95%');
    expect(msg).toContain('regex: ignore.*instructions');
  });

  // ── Shared scan-report envelope: artifacts[] + index + layer ──

  it('emits run.artifacts[] with hashes["sha-256"] as the join key', () => {
    const result = makeScanResult({
      input_file: process.cwd() + '/skills/test/SKILL.md',
      content_hash: '64f9e18ef138e7238509134f660f1bdd9859ff9953f5e4cb9c884f0e0ec3395a',
    });
    const sarif = scanResultToSARIF([result], '1.0.0') as {
      runs: Array<{
        artifacts: Array<{ location: { uri: string; uriBaseId: string }; hashes: Record<string, string> }>;
      }>;
    };
    const artifacts = sarif.runs[0]!.artifacts;
    expect(artifacts).toHaveLength(1);
    expect(artifacts[0]!.location.uri).toBe('skills/test/SKILL.md');
    expect(artifacts[0]!.location.uriBaseId).toBe('%SRCROOT%');
    // The join key is the engine's existing content_hash, surfaced verbatim.
    expect(artifacts[0]!.hashes['sha-256']).toBe(
      '64f9e18ef138e7238509134f660f1bdd9859ff9953f5e4cb9c884f0e0ec3395a',
    );
  });

  it('points each result artifactLocation.index back at its artifact entry', () => {
    const result = makeScanResult({ input_file: process.cwd() + '/skills/test/SKILL.md' });
    const sarif = scanResultToSARIF([result], '1.0.0') as {
      runs: Array<{
        artifacts: Array<{ hashes: Record<string, string> }>;
        results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { uri: string; index: number } } }> }>;
      }>;
    };
    const artifactLoc = sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.artifactLocation;
    expect(artifactLoc.index).toBe(0);
    // index resolves to the artifact carrying the join key
    expect(sarif.runs[0]!.artifacts[artifactLoc.index]!.hashes['sha-256']).toBe('abc123');
  });

  it('sets properties.layer = "atr" on every result, keeping existing properties', () => {
    const result = makeScanResult({ input_file: process.cwd() + '/skills/test/SKILL.md' });
    const sarif = scanResultToSARIF([result], '1.0.0') as {
      runs: Array<{ results: Array<{ properties: Record<string, unknown> }> }>;
    };
    const props = sarif.runs[0]!.results[0]!.properties;
    expect(props['layer']).toBe('atr');
    // existing fields intact
    expect(props['confidence']).toBe(0.95);
    expect(props['scan_context']).toBe('mcp');
    expect(props['content_hash']).toBe('abc123');
  });

  it('deduplicates artifacts per scanned file (one entry per unique uri)', () => {
    const path = process.cwd() + '/skills/test/SKILL.md';
    // Two findings on the same file → one artifact entry, both results index 0.
    const result = makeScanResult({
      input_file: path,
      matches: [
        makeMatch(),
        makeMatch({ rule: makeRule({ id: 'ATR-2026-00002' }) }),
      ],
    });
    const sarif = scanResultToSARIF([result], '1.0.0') as {
      runs: Array<{
        artifacts: object[];
        results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { index: number } } }> }>;
      }>;
    };
    expect(sarif.runs[0]!.artifacts).toHaveLength(1);
    const results = sarif.runs[0]!.results;
    expect(results).toHaveLength(2);
    expect(results[0]!.locations[0]!.physicalLocation.artifactLocation.index).toBe(0);
    expect(results[1]!.locations[0]!.physicalLocation.artifactLocation.index).toBe(0);
  });

  it('emits an artifact per distinct file with the matching index', () => {
    const r1 = makeScanResult({ input_file: process.cwd() + '/skills/a/SKILL.md', content_hash: 'hashA' });
    const r2 = makeScanResult({
      input_file: process.cwd() + '/skills/b/SKILL.md',
      content_hash: 'hashB',
      matches: [makeMatch({ rule: makeRule({ id: 'ATR-2026-00009' }) })],
    });
    const sarif = scanResultToSARIF([r1, r2], '1.0.0') as {
      runs: Array<{
        artifacts: Array<{ location: { uri: string }; hashes: Record<string, string> }>;
        results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { uri: string; index: number } } }> }>;
      }>;
    };
    const artifacts = sarif.runs[0]!.artifacts;
    expect(artifacts).toHaveLength(2);
    expect(artifacts[0]!.hashes['sha-256']).toBe('hashA');
    expect(artifacts[1]!.hashes['sha-256']).toBe('hashB');
    const results = sarif.runs[0]!.results;
    // each result's index resolves to the artifact with its own uri + hash
    for (const res of results) {
      const loc = res.locations[0]!.physicalLocation.artifactLocation;
      expect(artifacts[loc.index]!.location.uri).toBe(loc.uri);
    }
  });

  it('keeps distinct files apart when their normalized URIs collide (basename clash)', () => {
    // Two distinct out-of-CWD files share a basename → both normalize to
    // 'SKILL.md', but each must get its own artifact carrying its own hash,
    // and each result must index back at the artifact for its own file.
    const r1 = makeScanResult({ input_file: '/mnt/scan-a/SKILL.md', content_hash: 'hashA' });
    const r2 = makeScanResult({
      input_file: '/mnt/scan-b/SKILL.md',
      content_hash: 'hashB',
      matches: [makeMatch({ rule: makeRule({ id: 'ATR-2026-00011' }) })],
    });
    const sarif = scanResultToSARIF([r1, r2], '1.0.0') as {
      runs: Array<{
        artifacts: Array<{ location: { uri: string }; hashes: Record<string, string> }>;
        results: Array<{ locations: Array<{ physicalLocation: { artifactLocation: { index: number } } }> }>;
      }>;
    };
    const artifacts = sarif.runs[0]!.artifacts;
    // distinct files → two artifacts even though both URIs are 'SKILL.md'
    expect(artifacts).toHaveLength(2);
    expect(artifacts[0]!.hashes['sha-256']).toBe('hashA');
    expect(artifacts[1]!.hashes['sha-256']).toBe('hashB');
    const results = sarif.runs[0]!.results;
    const idx0 = results[0]!.locations[0]!.physicalLocation.artifactLocation.index;
    const idx1 = results[1]!.locations[0]!.physicalLocation.artifactLocation.index;
    // each result resolves to the artifact with its own file's hash
    expect(artifacts[idx0]!.hashes['sha-256']).toBe('hashA');
    expect(artifacts[idx1]!.hashes['sha-256']).toBe('hashB');
  });

  it('emits empty artifacts[] and no index when no input_file is set', () => {
    const sarif = scanResultToSARIF([makeScanResult()], '1.0.0') as {
      runs: Array<{ artifacts: object[]; results: Array<{ locations?: unknown; properties: Record<string, unknown> }> }>;
    };
    expect(sarif.runs[0]!.artifacts).toHaveLength(0);
    // MCP runtime event: no location, but still tagged as the atr layer
    expect(sarif.runs[0]!.results[0]!.locations).toBeUndefined();
    expect(sarif.runs[0]!.results[0]!.properties['layer']).toBe('atr');
  });
});
