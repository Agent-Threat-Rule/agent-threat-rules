#!/usr/bin/env tsx
/**
 * Generate the 20 edge-case fixtures required by SPEC.md §12 to verify
 * Engine robustness independent of rule correctness. Each fixture
 * exercises one class of input the Engine MUST handle gracefully:
 *
 *   - Catastrophic regex inputs (ReDoS triggers)
 *   - Malformed YAML / JSON
 *   - Oversized inputs
 *   - Deeply nested structures
 *   - Null and empty values
 *   - Exotic encodings and zero-width characters
 *   - Control character and null-byte injection
 *
 * For all of these, the Engine MUST return either no_match or a
 * graceful_error (per SPEC §13.2). Crash, hang, or unbounded resource
 * consumption is a conformance failure.
 *
 * Idempotent: re-running overwrites generated edge fixtures.
 */

import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');
const EDGE_DIR = join(REPO_ROOT, 'conformance', 'v1.0', 'fixtures', 'edge');

interface EdgeCase {
  id: string;
  title: string;
  scan_target: 'mcp' | 'skill' | 'runtime';
  input: string;
  rationale: string;
  max_runtime_ms?: number;
  error_kind_allowed?: string[];
  /**
   * Defaults to graceful_error_or_no_match. `handled` also accepts a match: for
   * a payload that is itself a detection signal, which a faithful Engine
   * running the published Corpus may legitimately match.
   */
  outcome?: 'handled';
}

const A_REPEAT = (n: number): string => 'a'.repeat(n);
const NULL_BYTES = '\x00'.repeat(50);
const ZERO_WIDTH = '​‌‍﻿'.repeat(40);
const RTL_OVERRIDE = '‮';
const CONTROL_CHARS = Array.from({ length: 32 }, (_, i) => String.fromCharCode(i)).join('');

const EDGES: readonly EdgeCase[] = [
  {
    id: 'edge-002-catastrophic-alternation',
    title: 'ReDoS via overlapping alternation',
    scan_target: 'skill',
    input: `${A_REPEAT(40)}X${A_REPEAT(40)}`,
    rationale: 'Inputs with long runs followed by a mismatch character are the classic ReDoS shape for `(a+)+$` style patterns. Engines MUST timeout per SPEC §13.2.',
    max_runtime_ms: 5000,
    error_kind_allowed: ['timeout', 'regex_timeout'],
  },
  {
    id: 'edge-003-nested-quantifier-backtrack',
    title: 'Nested quantifier backtracking',
    scan_target: 'skill',
    input: `(${A_REPEAT(60)})!`,
    rationale: 'Nested quantifier patterns like `(a+)*` over inputs that almost match drive exponential backtracking.',
    max_runtime_ms: 5000,
  },
  {
    id: 'edge-010-malformed-yaml-tab',
    title: 'YAML indentation by tab (invalid)',
    scan_target: 'skill',
    input: 'description:\n\tnested: value',
    rationale: 'YAML 1.2 forbids tabs in indentation. Engine that parses input as YAML MUST report graceful_error, not crash.',
    error_kind_allowed: ['parse_error', 'yaml_error'],
  },
  {
    id: 'edge-011-malformed-yaml-unterminated',
    title: 'Unterminated YAML quoted string',
    scan_target: 'skill',
    input: 'description: "unterminated string with no closing quote\nnext_field: value',
    rationale: 'Unterminated quoted string. Engine MUST not silently truncate input.',
    error_kind_allowed: ['parse_error', 'yaml_error'],
  },
  {
    id: 'edge-012-malformed-json-trailing-comma',
    title: 'JSON with trailing comma',
    scan_target: 'skill',
    input: '{"command": "test",}',
    rationale: 'Trailing comma is invalid JSON. Engine MUST surface the error.',
    error_kind_allowed: ['parse_error', 'json_error'],
  },
  {
    id: 'edge-013-malformed-json-unquoted-key',
    title: 'JSON with unquoted key',
    scan_target: 'skill',
    input: '{command: "echo hi"}',
    rationale: 'Unquoted key violates RFC 8259. Engine MUST surface the error.',
    error_kind_allowed: ['parse_error', 'json_error'],
  },
  {
    id: 'edge-020-oversized-input-1mb',
    title: 'Oversized input (1 MB)',
    scan_target: 'skill',
    input: A_REPEAT(1_000_000),
    rationale: 'A 1 MB benign blob. Engine MUST process within bounded memory and time per SPEC §13.2.',
    max_runtime_ms: 10_000,
  },
  {
    id: 'edge-021-many-lines',
    title: 'Many short lines (100,000 newlines)',
    scan_target: 'skill',
    input: 'line\n'.repeat(100_000),
    rationale: 'Pathological line-count input. Engines that line-buffer MUST not allocate unbounded memory.',
    max_runtime_ms: 10_000,
  },
  {
    id: 'edge-030-deep-nesting-json',
    title: 'Deeply nested JSON (1000 levels)',
    scan_target: 'skill',
    input: '['.repeat(1000) + 'null' + ']'.repeat(1000),
    rationale: 'Deeply nested JSON triggers stack overflow in naive recursive parsers.',
    error_kind_allowed: ['parse_error', 'stack_overflow', 'depth_limit'],
  },
  {
    id: 'edge-031-deep-nesting-yaml',
    title: 'Deeply nested YAML (500 levels)',
    scan_target: 'skill',
    input: Array.from({ length: 500 }, (_, i) => `${'  '.repeat(i)}- nest`).join('\n'),
    rationale: 'Deeply nested YAML, same stack-overflow class as edge-030.',
    error_kind_allowed: ['parse_error', 'stack_overflow', 'depth_limit'],
  },
  {
    id: 'edge-040-null-input',
    title: 'Explicit null input',
    scan_target: 'skill',
    input: '',
    rationale: 'Empty string input MUST not crash the engine; SHOULD evaluate to no_match across all rules.',
  },
  {
    id: 'edge-041-only-whitespace',
    title: 'Whitespace-only input',
    scan_target: 'skill',
    input: '   \n\t\n   \n',
    rationale: 'Whitespace-only input MUST evaluate to no_match without error.',
  },
  {
    id: 'edge-050-utf8-bom',
    title: 'UTF-8 BOM at start',
    scan_target: 'skill',
    input: '﻿description: legitimate skill description.',
    rationale: 'UTF-8 BOM at start of input MUST not break field matching.',
  },
  {
    id: 'edge-051-zero-width-injection',
    title: 'Zero-width characters interleaved with attack payload',
    scan_target: 'skill',
    input: `ignore${ZERO_WIDTH} previous${ZERO_WIDTH} instructions`,
    rationale: 'Zero-width characters between attack tokens. Engines MAY normalize before matching; behavior MUST be documented and consistent.',
    outcome: 'handled',
  },
  {
    id: 'edge-052-rtl-override',
    title: 'Right-to-left override character',
    scan_target: 'skill',
    input: `safe_command${RTL_OVERRIDE}rm -rf /`,
    rationale: 'RTL override is a known supply-chain attack vector. Engine MUST NOT execute or rewrite input semantics.',
    outcome: 'handled',
  },
  {
    id: 'edge-060-null-byte-injection',
    title: 'Null bytes in middle of input',
    scan_target: 'skill',
    input: `legitimate content${NULL_BYTES}attack payload after null`,
    rationale: 'Null bytes MUST NOT cause input truncation in the engine.',
    outcome: 'handled',
  },
  {
    id: 'edge-061-control-chars',
    title: 'All ASCII control characters',
    scan_target: 'skill',
    input: CONTROL_CHARS,
    rationale: 'Every C0 control character. Engine MUST handle without crash, regardless of how it treats them.',
    outcome: 'handled',
  },
  {
    id: 'edge-070-mixed-encoding',
    title: 'Mixed UTF-8 + Latin-1 sequences',
    scan_target: 'skill',
    input: 'normal text éè \xC0\xC1 mixed encoding',
    rationale: 'Real-world inputs often have mixed encoding. Engine MUST process without crash.',
  },
  {
    id: 'edge-080-extreme-regex-payload',
    title: 'Input full of regex metacharacters',
    scan_target: 'skill',
    input: '$^.*+?()[]{}|\\'.repeat(1000),
    rationale: 'Regex metacharacters as literal payload. Engine MUST escape or quote correctly when constructing internal patterns from input.',
  },
];

function write(edge: EdgeCase): void {
  const dir = join(EDGE_DIR, edge.id);
  mkdirSync(dir, { recursive: true });
  const inputDoc: Record<string, string> = {
    scan_target: edge.scan_target,
    input: edge.input,
  };
  if (edge.rationale) inputDoc.rationale = edge.rationale;
  writeFileSync(join(dir, 'input.yaml'), yaml.dump(inputDoc, { lineWidth: -1 }));
  const expect: Record<string, unknown> = {
    outcome: edge.outcome ?? 'graceful_error_or_no_match',
  };
  if (edge.max_runtime_ms) expect.max_runtime_ms = edge.max_runtime_ms;
  if (edge.error_kind_allowed) expect.error_kind_allowed = edge.error_kind_allowed;
  writeFileSync(join(dir, 'expect.json'), JSON.stringify(expect, null, 2) + '\n');
}

let written = 0;
let skipped = 0;
for (const edge of EDGES) {
  if (existsSync(join(EDGE_DIR, edge.id, 'input.yaml'))) {
    skipped++;
    continue;
  }
  write(edge);
  written++;
}
console.log(`[generate-edge] wrote ${written}, skipped ${skipped} (existing)`);
console.log(`[generate-edge] total edge fixtures should be 20 after this run`);
