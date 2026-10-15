/**
 * `atr tc pull` writes rules fetched from a Threat Cloud endpoint the user
 * names. That endpoint's response is untrusted input: it may be compromised,
 * hostile, or rewritten in transit over plain http. A rule's id becomes part of
 * a file name and its category becomes a directory, so both are checked before
 * anything is written, and the validator is started without a shell.
 *
 * The end-to-end case serves hostile rules from a local stand-in server and runs
 * the real CLI from source in a scratch directory, so a regression shows up as a
 * file the shell created, not as a mocked call.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import yaml from 'js-yaml';
import { planPulledRule, TC_PULL_CATEGORIES } from '../src/cli/tc-pipeline.js';

const ROOT = resolve(__dirname, '..');
const TSX_CLI = join(ROOT, 'node_modules', 'tsx', 'dist', 'cli.mjs');
const CLI_SRC = join(ROOT, 'src', 'cli.ts');
const execFileAsync = promisify(execFile);

function ruleYaml(id: string, category: string, extra = ''): string {
  return [
    `id: ${id}`,
    'title: Pulled rule fixture',
    extra,
    'tags:',
    `  category: ${category}`,
    '  subcategory: fixture',
  ].join('\n') + '\n';
}

function listFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    return statSync(full).isDirectory() ? listFiles(full) : [full];
  });
}

// Shell metacharacters in the id: command substitution, a closing quote
// followed by a separator, and backticks. Each would create a marker file in
// the working directory if the id reached a shell.
const HOSTILE_RULES = [
  ruleYaml('ATR-2026-$(touch${IFS}MARKER_SUBST)', 'prompt-injection'),
  ruleYaml('ATR-2026-00001";touch${IFS}MARKER_QUOTE;"', 'prompt-injection'),
  ruleYaml('ATR-2026-0000`touch${IFS}MARKER_TICK`', 'prompt-injection'),
  ruleYaml('ATR-2026-99001', '../../ESCAPED_DIR'),
  ruleYaml('../../ESCAPED_ID', 'prompt-injection'),
  // Quoted, so a text match on `id:` does not see it as the rule already in the
  // repo; the parsed id does, and it must not overwrite that file.
  ruleYaml('"ATR-2026-00042"', 'prompt-injection'),
];
const EXISTING_RULE = ruleYaml('ATR-2026-00042', 'prompt-injection');

describe('atr tc pull with a hostile Threat Cloud response', () => {
  let server: Server;
  let url = '';
  let work = '';
  let rulesDir = '';
  let existingFile = '';

  beforeAll(async () => {
    server = createServer((_req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        ok: true,
        data: HOSTILE_RULES.map((ruleContent, i) => ({ ruleId: `r${i}`, ruleContent, source: 'tc' })),
      }));
    });
    await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('stand-in server has no port');
    url = `http://127.0.0.1:${addr.port}`;

    work = mkdtempSync(join(tmpdir(), 'atr-tc-pull-'));
    // Nested so that a `../../` category resolves inside the scratch directory.
    rulesDir = join(work, 'a', 'b', 'rules');
    mkdirSync(join(rulesDir, 'prompt-injection'), { recursive: true });
    mkdirSync(join(work, 'data'), { recursive: true });
    existingFile = join(rulesDir, 'prompt-injection', 'ATR-2026-00042-fixture.yaml');
    writeFileSync(existingFile, EXISTING_RULE);
  });

  afterAll(async () => {
    await new Promise<void>((done) => server.close(() => done()));
    rmSync(work, { recursive: true, force: true });
  });

  it('runs no command from a rule id and writes or overwrites no rule file', async () => {
    const { stdout } = await execFileAsync(
      process.execPath,
      [TSX_CLI, CLI_SRC, 'tc', 'pull', '--tc-url', url, '--tc-key', 'test-key-not-real', '--rules', rulesDir],
      { cwd: work, encoding: 'utf-8', timeout: 120_000 },
    );

    for (const marker of ['MARKER_SUBST', 'MARKER_QUOTE', 'MARKER_TICK']) {
      expect(existsSync(join(work, marker)), `${marker} was created`).toBe(false);
    }
    expect(existsSync(join(work, 'a', 'ESCAPED_DIR'))).toBe(false);
    expect(listFiles(join(work, 'a')).filter((f) => !f.startsWith(rulesDir))).toEqual([]);
    expect(listFiles(rulesDir)).toEqual([existingFile]);
    expect(readFileSync(existingFile, 'utf-8')).toBe(EXISTING_RULE);
    // Rejected before the write, not written and then removed by the validator.
    expect(stdout.match(/rejected, not written/g) ?? []).toHaveLength(HOSTILE_RULES.length);
    expect(stdout).toMatch(/0 rules pulled/);
  });
});

describe('planPulledRule', () => {
  const rulesDir = join(tmpdir(), 'atr-plan-rules');

  it('takes the category from tags, not from an earlier compliance subcategory', () => {
    const content = ruleYaml(
      'ATR-2026-99997',
      'context-exfiltration',
      'compliance:\n  nist_ai_rmf:\n    - subcategory: MG.2.3\n      context: fixture',
    );
    const plan = planPulledRule(content, rulesDir);
    expect(plan).toEqual({
      ok: true,
      id: 'ATR-2026-99997',
      category: 'context-exfiltration',
      slug: 'fixture',
      filePath: join(rulesDir, 'context-exfiltration', 'ATR-2026-99997-fixture.yaml'),
    });
  });

  it('accepts flow-style tags', () => {
    const content = 'id: ATR-2026-99998\ntags: { category: tool-poisoning, subcategory: Flow.Style }\n';
    const plan = planPulledRule(content, rulesDir);
    expect(plan.ok && plan.filePath).toBe(join(rulesDir, 'tool-poisoning', 'ATR-2026-99998-flow-style.yaml'));
  });

  it.each([
    ['command substitution', 'ATR-2026-$(id)'],
    ['quote and separator', 'ATR-2026-00001";id;"'],
    ['backticks', 'ATR-2026-`id`'],
    ['path traversal', '../ATR-2026-00001'],
    ['trailing text', 'ATR-2026-00001-extra'],
    ['draft id', 'ATR-2026-DRAFT-abc'],
  ])('rejects an id with %s', (_label, id) => {
    expect(planPulledRule(ruleYaml(id, 'prompt-injection'), rulesDir).ok).toBe(false);
  });

  it.each([
    ['path traversal', '../../outside'],
    ['an absolute path', '/etc'],
    ['a compliance subcategory', 'MG.2.3'],
    ['a directory name that is not a schema category', 'model-security'],
  ])('rejects a category that is %s', (_label, category) => {
    expect(planPulledRule(ruleYaml('ATR-2026-99999', category), rulesDir).ok).toBe(false);
  });

  it('rejects a rule without an id, without tags, or that is not YAML', () => {
    expect(planPulledRule('title: no id\ntags:\n  category: prompt-injection\n', rulesDir).ok).toBe(false);
    expect(planPulledRule('id: ATR-2026-99999\n', rulesDir).ok).toBe(false);
    expect(planPulledRule('id: ATR-2026-99999\ntags: [unclosed\n', rulesDir).ok).toBe(false);
  });

  it('only ever plans a path inside the rules directory', () => {
    for (const category of TC_PULL_CATEGORIES) {
      const plan = planPulledRule(ruleYaml('ATR-2026-99999', category), rulesDir);
      expect(plan.ok).toBe(true);
      if (plan.ok) expect(relative(rulesDir, plan.filePath).startsWith('..')).toBe(false);
    }
  });

  it('allows exactly the categories the rule schema allows', () => {
    const schema = yaml.load(readFileSync(join(ROOT, 'spec', 'atr-schema.yaml'), 'utf-8')) as {
      properties: { tags: { properties: { category: { enum: string[] } } } };
    };
    expect([...TC_PULL_CATEGORIES].sort()).toEqual([...schema.properties.tags.properties.category.enum].sort());
  });
});
