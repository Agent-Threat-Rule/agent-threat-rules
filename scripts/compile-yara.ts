#!/usr/bin/env tsx
/**
 * ATR → YARA compiler.
 *
 * Implements the compilation contract from atr-method-v1.1.md §5.4. Reads
 * ATR rule YAML files with detection.method == "signature" and emits a
 * YARA rule per ATR rule.
 *
 * Usage:
 *   npx tsx scripts/compile-yara.ts <rule.yaml>           # single rule → stdout
 *   npx tsx scripts/compile-yara.ts --all rules/          # bulk, all signature rules → stdout
 *   npx tsx scripts/compile-yara.ts --all --out yara/     # bulk, write one .yar per rule
 *
 * Output capability: `atr/compiler/yara@1.0` per atr-method-v1.1.md §9.
 *
 * Non-signature rules are skipped silently with a stderr note (unless --verbose).
 * Rules with unknown indicator types fail loudly per §5.3.
 */

import { readFileSync, writeFileSync, readdirSync, statSync, mkdirSync, existsSync } from 'node:fs';
import { join, basename, extname } from 'node:path';
import yaml from 'js-yaml';
import { pathToFileURL } from 'node:url';

const COMPILER_VERSION = '1.0.0';

interface Indicator {
  type: 'sha256' | 'sha512' | 'blake2b-256' | 'package_name' | 'registry_url' | 'skill_id';
  value: string;
  target_field: string;
  provenance?: { first_observed?: string; source?: string; attribution?: string };
}

interface SignatureBlock {
  indicators: Indicator[];
  match_logic?: 'any' | 'all';
}

interface AtrRule {
  id: string;
  title: string;
  severity: string;
  status?: string;
  tags?: { category?: string };
  detection?: {
    method?: string;
    signature?: SignatureBlock;
  };
}

const KNOWN_INDICATOR_TYPES = new Set([
  'sha256', 'sha512', 'blake2b-256', 'package_name', 'registry_url', 'skill_id',
]);

function escapeYaraString(s: string): string {
  // YARA string literals: backslash-escape backslashes and double-quotes.
  return s.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function yaraRuleName(atrId: string): string {
  // YARA identifiers must match [a-zA-Z][_0-9a-zA-Z]{0,127}
  // ATR-YYYY-NNNNN → ATR_YYYY_NNNNN (valid YARA identifier)
  return atrId.replace(/-/g, '_');
}

function compileIndicator(indicator: Indicator, index: number): {
  imports: Set<string>;
  stringDecl: string | null;
  conditionRef: string;
} {
  const imports = new Set<string>();
  const stringName = `$ind${index}`;

  switch (indicator.type) {
    case 'sha256': {
      imports.add('hash');
      const h = indicator.value.toLowerCase();
      return {
        imports,
        stringDecl: null,
        conditionRef: `hash.sha256(0, filesize) == "${escapeYaraString(h)}"`,
      };
    }
    case 'sha512': {
      imports.add('hash');
      const h = indicator.value.toLowerCase();
      return {
        imports,
        stringDecl: null,
        conditionRef: `hash.sha512(0, filesize) == "${escapeYaraString(h)}"`,
      };
    }
    case 'blake2b-256': {
      // YARA's hash module does not natively support blake2b in upstream
      // releases. Emit a comment + fall back to a string-style sentinel
      // that conformant engines can post-process. Documented in §5.4.
      return {
        imports,
        stringDecl: null,
        conditionRef: `/* blake2b-256: ${escapeYaraString(indicator.value)} — requires engine post-processing */ false`,
      };
    }
    case 'package_name':
    case 'registry_url':
    case 'skill_id': {
      return {
        imports,
        stringDecl: `        ${stringName} = "${escapeYaraString(indicator.value)}"`,
        conditionRef: stringName,
      };
    }
    default: {
      const unknown = indicator as Indicator;
      throw new Error(
        `Unknown indicator type "${unknown.type}". atr-method-v1.1.md §5.3 requires engines to treat unknown types as graceful_error.`,
      );
    }
  }
}

export function compileRule(rule: AtrRule): string | null {
  if (rule.detection?.method !== 'signature') {
    return null;
  }
  const sig = rule.detection.signature;
  if (!sig || !Array.isArray(sig.indicators) || sig.indicators.length === 0) {
    throw new Error(
      `Rule ${rule.id}: method=signature requires non-empty detection.signature.indicators (atr-method-v1.1.md §5.2).`,
    );
  }

  const matchLogic = sig.match_logic ?? 'any';
  if (matchLogic !== 'any' && matchLogic !== 'all') {
    throw new Error(
      `Rule ${rule.id}: detection.signature.match_logic must be "any" or "all" (got "${matchLogic}").`,
    );
  }

  const ruleName = yaraRuleName(rule.id);
  const imports = new Set<string>();
  const stringDecls: string[] = [];
  const conditionRefs: string[] = [];

  sig.indicators.forEach((ind, idx) => {
    if (!KNOWN_INDICATOR_TYPES.has(ind.type)) {
      throw new Error(`Rule ${rule.id}: unknown indicator type "${ind.type}"`);
    }
    const compiled = compileIndicator(ind, idx);
    compiled.imports.forEach((i) => imports.add(i));
    if (compiled.stringDecl) stringDecls.push(compiled.stringDecl);
    conditionRefs.push(compiled.conditionRef);
  });

  const importLines = Array.from(imports).sort().map((i) => `import "${i}"`).join('\n');
  const stringsBlock = stringDecls.length > 0
    ? `    strings:\n${stringDecls.join('\n')}\n`
    : '';

  let conditionExpression: string;
  if (conditionRefs.length === 1) {
    conditionExpression = conditionRefs[0];
  } else {
    // YARA: prefer `all of them` / `any of them` only when ALL refs are
    // strings. If any refs are non-string predicates (e.g., hash module
    // calls), join with explicit `and`/`or`.
    const allStringRefs = conditionRefs.every((r) => r.startsWith('$'));
    if (allStringRefs) {
      conditionExpression = matchLogic === 'all' ? 'all of them' : 'any of them';
    } else {
      conditionExpression = conditionRefs.join(matchLogic === 'all' ? '\n            and ' : '\n            or ');
    }
  }

  const meta: string[] = [
    `        atr_id = "${escapeYaraString(rule.id)}"`,
    `        atr_title = "${escapeYaraString(rule.title)}"`,
    `        atr_severity = "${escapeYaraString(rule.severity)}"`,
  ];
  if (rule.status) meta.push(`        atr_status = "${escapeYaraString(rule.status)}"`);
  if (rule.tags?.category) meta.push(`        atr_category = "${escapeYaraString(rule.tags.category)}"`);
  meta.push(`        compiler = "atr-to-yara@${COMPILER_VERSION}"`);

  const header = importLines ? `${importLines}\n\n` : '';
  return `${header}rule ${ruleName}
{
    meta:
${meta.join('\n')}

${stringsBlock}    condition:
        ${conditionExpression}
}`;
}

function findRuleFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const s = statSync(p);
    if (s.isDirectory()) out.push(...findRuleFiles(p));
    else if (s.isFile() && (extname(entry) === '.yaml' || extname(entry) === '.yml')) out.push(p);
  }
  return out;
}

interface CliOptions {
  inputs: string[];
  all: boolean;
  outDir: string | null;
  verbose: boolean;
}

function parseArgs(argv: string[]): CliOptions {
  const opts: CliOptions = { inputs: [], all: false, outDir: null, verbose: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--all') opts.all = true;
    else if (a === '--out') opts.outDir = argv[++i];
    else if (a === '--verbose' || a === '-v') opts.verbose = true;
    else opts.inputs.push(a);
  }
  return opts;
}

function main(): void {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv.includes('--help') || argv.includes('-h')) {
    console.error(`atr-to-yara compiler v${COMPILER_VERSION}

Usage:
  npx tsx scripts/compile-yara.ts <rule.yaml>           Single rule → stdout
  npx tsx scripts/compile-yara.ts --all rules/          Bulk, signature rules only → stdout
  npx tsx scripts/compile-yara.ts --all rules/ --out yara/   Bulk, one .yar file per rule
  npx tsx scripts/compile-yara.ts --verbose <inputs>    Note skipped non-signature rules

Capability declaration: atr/compiler/yara@${COMPILER_VERSION} (atr-method-v1.1.md §9)`);
    process.exit(argv.length === 0 ? 2 : 0);
  }

  const opts = parseArgs(argv);

  let files: string[] = [];
  if (opts.all) {
    for (const root of opts.inputs.length ? opts.inputs : ['rules']) {
      const st = statSync(root);
      if (st.isDirectory()) files.push(...findRuleFiles(root));
      else files.push(root);
    }
  } else {
    files = opts.inputs;
  }

  if (files.length === 0) {
    console.error('No input files. Pass a YAML file or use --all <dir>.');
    process.exit(2);
  }

  if (opts.outDir && !existsSync(opts.outDir)) {
    mkdirSync(opts.outDir, { recursive: true });
  }

  let signatureCount = 0;
  let skippedCount = 0;
  let errorCount = 0;

  for (const file of files) {
    try {
      const rule = yaml.load(readFileSync(file, 'utf8')) as AtrRule;
      if (!rule || typeof rule !== 'object') {
        if (opts.verbose) console.error(`skip ${file}: not a YAML object`);
        skippedCount++;
        continue;
      }
      const compiled = compileRule(rule);
      if (compiled === null) {
        if (opts.verbose) console.error(`skip ${file}: detection.method != signature`);
        skippedCount++;
        continue;
      }
      signatureCount++;
      if (opts.outDir) {
        const outFile = join(opts.outDir, `${rule.id}.yar`);
        writeFileSync(outFile, compiled + '\n');
        console.error(`wrote ${outFile}`);
      } else {
        console.log(compiled);
        console.log('');
      }
    } catch (err) {
      errorCount++;
      console.error(`ERROR in ${file}: ${(err as Error).message}`);
    }
  }

  console.error(
    `\n[atr-to-yara] compiled ${signatureCount} signature rule(s); skipped ${skippedCount}; errors ${errorCount}.`,
  );
  if (errorCount > 0) process.exit(1);
}

// Run if invoked as a script (not when imported as a module for tests)
const isMainModule = import.meta.url === pathToFileURL(process.argv[1] ?? '').href;
if (isMainModule) main();
