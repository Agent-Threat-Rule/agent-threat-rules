import { describe, it, expect, afterEach } from 'vitest';
import { join } from 'node:path';
import { writeFileSync, readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
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
  // The artifact digest is the file's raw octets, so the interop tests need a
  // real file on disk rather than a fake path + fake hash.
  const tempDirs: string[] = [];
  afterEach(() => {
    for (const d of tempDirs.splice(0)) rmSync(d, { recursive: true, force: true });
  });
  const writeTempSkill = (
    bytes: Buffer | string,
    name = 'SKILL.md',
  ): { path: string; rawDigest: string } => {
    const dir = mkdtempSync(join(tmpdir(), 'atr-sarif-'));
    tempDirs.push(dir);
    const path = join(dir, name);
    writeFileSync(path, bytes);
    const rawDigest = createHash('sha256').update(readFileSync(path)).digest('hex');
    return { path, rawDigest };
  };

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

  // The shared envelope profile (skil-lock#37 / SPEC 14.3) joins layers on the
  // artifact digest, so these four properties are an interop contract with the
  // drift and content layers rather than cosmetic output details.
  it('emits the shared envelope profile: artifacts[], raw-octet digest, index and layer', () => {
    const { path, rawDigest } = writeTempSkill('# demo skill\nsome content\n');
    const sarif = scanResultToSARIF(
      [makeScanResult({ input_file: path, content_hash: 'a'.repeat(64) })],
      '1.0.0',
    ) as {
      runs: Array<{
        artifacts?: Array<{
          location: { uri: string; uriBaseId: string };
          hashes?: Record<string, string>;
        }>;
        results: Array<{
          properties: Record<string, unknown>;
          locations: Array<{
            physicalLocation: { artifactLocation: { uri: string; index?: number } };
          }>;
        }>;
      }>;
    };

    const run = sarif.runs[0]!;
    expect(run.artifacts).toHaveLength(1);
    // Absolute path outside CWD is stripped to filename by toArtifactUri.
    expect(run.artifacts![0]!.location.uri).toBe('SKILL.md');
    expect(run.artifacts![0]!.location.uriBaseId).toBe('%SRCROOT%');
    // Join key is the raw-octet digest (== sha256sum of the file), NOT content_hash.
    expect(run.artifacts![0]!.hashes?.['sha-256']).toBe(rawDigest);

    const result = run.results[0]!;
    expect(result.properties['layer']).toBe('atr');
    // content_hash (UTF-8-decoded basis) stays for back-compat, distinct from the digest.
    expect(result.properties['content_hash']).toBe('a'.repeat(64));
    expect(result.locations[0]!.physicalLocation.artifactLocation.index).toBe(0);
  });

  it('indexes each scanned file separately and omits artifacts when no file is known', () => {
    const a = writeTempSkill('alpha\n', 'a.md');
    const b = writeTempSkill('beta\n', 'b.md');
    const twoFiles = scanResultToSARIF(
      [makeScanResult({ input_file: a.path }), makeScanResult({ input_file: b.path })],
      '1.0.0',
    ) as {
      runs: Array<{
        artifacts?: Array<{ hashes?: Record<string, string> }>;
        results: Array<{
          locations: Array<{ physicalLocation: { artifactLocation: { index?: number } } }>;
        }>;
      }>;
    };
    expect(twoFiles.runs[0]!.artifacts).toHaveLength(2);
    expect(
      twoFiles.runs[0]!.results.map(
        (r) => r.locations[0]!.physicalLocation.artifactLocation.index,
      ),
    ).toEqual([0, 1]);
    // Each artifact carries its own file's raw digest.
    expect(twoFiles.runs[0]!.artifacts![0]!.hashes?.['sha-256']).toBe(a.rawDigest);
    expect(twoFiles.runs[0]!.artifacts![1]!.hashes?.['sha-256']).toBe(b.rawDigest);

    // A non-file scan (e.g. a raw event stream) has nothing to hash.
    const noFile = scanResultToSARIF([makeScanResult()], '1.0.0') as {
      runs: Array<{ artifacts?: unknown[] }>;
    };
    expect(noFile.runs[0]!.artifacts).toBeUndefined();
  });

  // Regression for the digest basis: the join key must be raw octets, so it stays
  // correct on invalid UTF-8 / lone surrogates — where the UTF-8-decoded hash
  // (content_hash) would diverge and silently break the cross-layer join.
  // claude-code-skill-security-check#24 §2: "computed over the raw octets ...
  // before any character decoding ... MUST equal sha256sum of that file."
  it('digests raw octets, not the decoded string (invalid-UTF-8 regression)', () => {
    // A lone 0x80 plus a WTF-8-encoded lone surrogate U+D800 (ED A0 80).
    const bytes = Buffer.concat([
      Buffer.from('# skill\ncontent '),
      Buffer.from([0x80]),
      Buffer.from(' more '),
      Buffer.from([0xed, 0xa0, 0x80]),
      Buffer.from('\n'),
    ]);
    const { path, rawDigest } = writeTempSkill(bytes, 'weird.md');
    const decodedHash = createHash('sha256')
      .update(readFileSync(path).toString('utf8'), 'utf8')
      .digest('hex');
    // Precondition: this fixture actually discriminates the two hash bases.
    expect(rawDigest).not.toBe(decodedHash);

    const sarif = scanResultToSARIF(
      [makeScanResult({ input_file: path, content_hash: decodedHash })],
      '1.0.0',
    ) as { runs: Array<{ artifacts?: Array<{ hashes?: Record<string, string> }> }> };
    const emitted = sarif.runs[0]!.artifacts![0]!.hashes?.['sha-256'];
    // Envelope join key is raw octets (== sha256sum), never the decoded-string hash.
    expect(emitted).toBe(rawDigest);
    expect(emitted).not.toBe(decodedHash);
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
});
