#!/usr/bin/env npx tsx
/**
 * extract-ts-tools.ts — read MCP tool definitions out of TypeScript source, statically.
 *
 * Nothing in the source repository is imported, compiled or run. The files are parsed with the
 * TypeScript compiler API and a small evaluator folds the constant expressions a tool definition is
 * built from: string literals, template literals, `+` concatenation, `[...].join(sep)`, object and
 * array literals, `const` bindings (in the same file or imported from a relative / aliased path),
 * single-`return` helper functions (evaluated with their parameters bound), and zod builder chains
 * (`z.object({...})`, `z.string().describe(...)`, `.optional()`, `.default(...)`, `z.enum([...])`, ...).
 * A zod schema is then written out as the JSON Schema a tools/list response carries.
 *
 * Tool definitions it recognises (the shapes the pinned servers use):
 *   - `<x>.registerTool(name, { title, description, inputSchema, annotations }, handler)`
 *   - `<x>.tool(name, description?, shape?, annotations?, handler)`
 *   - any object literal with a string `name`, a `description` and an `inputSchema`
 *     (defineTool({...}), playwright's `schema: {...}`)
 *   - `key: someFactory({ description, parameters | inputSchema })` (a tool keyed by property name)
 *
 * Anything the evaluator cannot fold (a runtime value, a call into a library) becomes an
 * `{"$unresolved": "<source text>"}` marker; the tool is still emitted and the marker is listed in
 * `_extraction.unresolved`, so the caller decides whether the definition is faithful enough.
 *
 * Usage:
 *   npx tsx scripts/mcp-tools-list/extract-ts-tools.ts --root <checkout> --alias '@repo/x/=packages/x/' <file>...
 * Prints a JSON array of { name, title?, description, inputSchema, annotations?, _extraction } to stdout.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, relative, resolve } from 'node:path';
import ts from 'typescript';

type Json = null | boolean | number | string | Json[] | { [k: string]: Json };

interface Unresolved {
  readonly $unresolved: string;
}

interface ZodNode {
  readonly $zod: string;
  readonly args: readonly unknown[];
  readonly description?: string;
  readonly optional?: boolean;
  readonly nullable?: boolean;
  readonly hasDefault?: boolean;
  readonly defaultValue?: unknown;
  readonly checks?: Readonly<Record<string, unknown>>;
}

const isUnresolved = (v: unknown): v is Unresolved =>
  typeof v === 'object' && v !== null && '$unresolved' in v;
const isZod = (v: unknown): v is ZodNode => typeof v === 'object' && v !== null && '$zod' in v;
const isOpaque = (v: unknown): boolean => typeof v === 'object' && v !== null && ('$ns' in v || '$fn' in v);
const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && !isZod(v) && !isUnresolved(v) && !isOpaque(v);

// ------------------------------------------------------------------ module loading

interface Module {
  readonly path: string;
  readonly sf: ts.SourceFile;
  readonly decls: ReadonlyMap<string, ts.Node>;
  readonly deepDecls: ReadonlyMap<string, ts.Node>;
  readonly imports: ReadonlyMap<string, { from: string; name: string }>;
}

const ROOT = (() => {
  const i = process.argv.indexOf('--root');
  if (i < 0) throw new Error('--root <checkout> is required');
  return resolve(process.argv[i + 1]!);
})();

const ALIASES: ReadonlyArray<readonly [string, string]> = process.argv
  .flatMap((a, i) => (a === '--alias' ? [process.argv[i + 1]!] : []))
  .map((s) => s.split('=') as [string, string]);

const moduleCache = new Map<string, Module | null>();

function resolveModulePath(fromFile: string, spec: string): string | null {
  let base: string | null = null;
  if (spec.startsWith('.')) base = resolve(dirname(fromFile), spec);
  for (const [prefix, target] of ALIASES) {
    if (spec.startsWith(prefix)) base = resolve(ROOT, target + spec.slice(prefix.length));
  }
  if (base === null) return null;
  const stem = base.replace(/\.(js|mjs|cjs|ts)$/, '');
  for (const cand of [`${stem}.ts`, `${stem}.tsx`, `${stem}.mts`, `${stem}/index.ts`, base]) {
    if (existsSync(cand) && cand.startsWith(ROOT) && !cand.endsWith('/')) {
      try {
        readFileSync(cand);
        return cand;
      } catch {
        /* directory */
      }
    }
  }
  return null;
}

function loadModule(path: string): Module | null {
  if (moduleCache.has(path)) return moduleCache.get(path)!;
  moduleCache.set(path, null);
  const text = readFileSync(path, 'utf-8');
  const sf = ts.createSourceFile(path, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const decls = new Map<string, ts.Node>();
  const imports = new Map<string, { from: string; name: string }>();
  const visitTop = (node: ts.Node): void => {
    if (ts.isVariableStatement(node)) {
      for (const d of node.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.initializer) decls.set(d.name.text, d.initializer);
      }
    } else if (ts.isFunctionDeclaration(node) && node.name) {
      decls.set(node.name.text, node);
    } else if (ts.isEnumDeclaration(node)) {
      decls.set(node.name.text, node);
    } else if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const from = node.moduleSpecifier.text;
      const nb = node.importClause?.namedBindings;
      if (nb && ts.isNamedImports(nb)) {
        for (const el of nb.elements) {
          imports.set(el.name.text, { from, name: (el.propertyName ?? el.name).text });
        }
      } else if (nb && ts.isNamespaceImport(nb)) {
        imports.set(nb.name.text, { from, name: '*ns' }); // import * as X from './x'
      }
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      const from = node.moduleSpecifier.text;
      if (node.exportClause && ts.isNamedExports(node.exportClause)) {
        for (const el of node.exportClause.elements) {
          imports.set(el.name.text, { from, name: (el.propertyName ?? el.name).text });
        }
      } else {
        imports.set(`*${from}`, { from, name: '*' });
      }
    }
  };
  sf.statements.forEach(visitTop);
  // Function-scoped consts (tool files often declare schemas inside the register function); looked up
  // after top-level declarations and imports, so a local variable never shadows an imported name.
  const deepDecls = new Map<string, ts.Node>();
  const visitDeep = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      if (!decls.has(node.name.text) && !deepDecls.has(node.name.text)) deepDecls.set(node.name.text, node.initializer);
    }
    ts.forEachChild(node, visitDeep);
  };
  visitDeep(sf);
  const mod: Module = { path, sf, decls, deepDecls, imports };
  moduleCache.set(path, mod);
  return mod;
}

// ------------------------------------------------------------------ evaluator

type Scope = ReadonlyMap<string, unknown>;
const EMPTY_SCOPE: Scope = new Map();

function unresolved(node: ts.Node): Unresolved {
  const text = node.getText().replace(/\s+/g, ' ');
  return { $unresolved: text.length > 120 ? `${text.slice(0, 117)}...` : text };
}

function lookup(mod: Module, name: string, scope: Scope, depth: number): unknown {
  if (scope.has(name)) return scope.get(name);
  const decl = mod.decls.get(name) ?? (mod.imports.has(name) ? undefined : mod.deepDecls.get(name));
  if (decl) {
    if (ts.isFunctionDeclaration(decl)) return { $fn: decl, mod };
    if (ts.isEnumDeclaration(decl)) {
      const out: Record<string, unknown> = {};
      for (const m of decl.members) {
        const key = m.name.getText().replace(/^['"]|['"]$/g, '');
        out[key] = m.initializer ? evaluate(m.initializer, mod, EMPTY_SCOPE, depth + 1) : key;
      }
      return out;
    }
    if (ts.isArrowFunction(decl) || ts.isFunctionExpression(decl)) return { $fn: decl, mod };
    return evaluate(decl, mod, EMPTY_SCOPE, depth + 1);
  }
  const imp = mod.imports.get(name);
  if (imp) {
    const target = resolveModulePath(mod.path, imp.from);
    const tmod = target ? loadModule(target) : null;
    if (tmod && imp.name === '*ns') return { $ns: tmod };
    if (tmod) return lookup(tmod, imp.name, EMPTY_SCOPE, depth + 1);
  }
  for (const [key, star] of mod.imports) {
    if (!key.startsWith('*')) continue;
    const target = resolveModulePath(mod.path, star.from);
    const tmod = target ? loadModule(target) : null;
    if (tmod && (tmod.decls.has(name) || tmod.imports.has(name))) return lookup(tmod, name, EMPTY_SCOPE, depth + 1);
  }
  return undefined;
}

function zodWith(base: ZodNode, patch: Partial<ZodNode>): ZodNode {
  return { ...base, ...patch };
}

function applyZodMethod(base: ZodNode, method: string, args: readonly unknown[]): ZodNode {
  const checks = { ...(base.checks ?? {}) };
  switch (method) {
    case 'describe':
      return typeof args[0] === 'string' ? zodWith(base, { description: args[0] }) : base;
    case 'meta': {
      const m = args[0];
      if (isPlainObject(m) && typeof m['description'] === 'string') return zodWith(base, { description: m['description'] });
      return base;
    }
    case 'optional':
      return zodWith(base, { optional: true });
    case 'nullable':
      return zodWith(base, { nullable: true });
    case 'nullish':
      return zodWith(base, { optional: true, nullable: true });
    case 'default':
    case 'prefault':
      return zodWith(base, { hasDefault: true, defaultValue: args[0] });
    case 'array':
      return { $zod: 'array', args: [base] };
    case 'extend':
    case 'merge':
    case 'safeExtend': {
      const add = isZod(args[0]) && args[0].$zod === 'object' ? args[0].args[0] : args[0];
      if (base.$zod === 'object' && isPlainObject(base.args[0]) && isPlainObject(add)) {
        return zodWith(base, { args: [{ ...base.args[0], ...add }] });
      }
      return base;
    }
    case 'partial':
      if (base.$zod === 'object' && isPlainObject(base.args[0])) {
        const shape = Object.fromEntries(
          Object.entries(base.args[0]).map(([k, v]) => [k, isZod(v) ? zodWith(v, { optional: true }) : v]),
        );
        return zodWith(base, { args: [shape] });
      }
      return base;
    case 'pick':
    case 'omit':
      if (base.$zod === 'object' && isPlainObject(base.args[0]) && isPlainObject(args[0])) {
        const keys = new Set(Object.keys(args[0]));
        const shape = Object.fromEntries(
          Object.entries(base.args[0]).filter(([k]) => (method === 'pick' ? keys.has(k) : !keys.has(k))),
        );
        return zodWith(base, { args: [shape] });
      }
      return base;
    case 'or':
      return { $zod: 'union', args: [[base, args[0]]] };
    case 'min':
    case 'max':
    case 'length':
    case 'int':
    case 'positive':
    case 'nonnegative':
    case 'url':
    case 'email':
    case 'uuid':
    case 'datetime':
    case 'regex':
    case 'nonempty':
    case 'gte':
    case 'lte':
      checks[method] = args[0] ?? true;
      return zodWith(base, { checks });
    default:
      // refine, transform, strict, passthrough, catch, brand, trim, toLowerCase, ...: no schema text
      return base;
  }
}

function evalCall(node: ts.CallExpression, mod: Module, scope: Scope, depth: number): unknown {
  const callee = node.expression;
  const args = node.arguments.map((a) => evaluate(a, mod, scope, depth + 1));
  if (ts.isPropertyAccessExpression(callee)) {
    const method = callee.name.text;
    // z.<type>(...) — the zod namespace (z or zod)
    if (ts.isIdentifier(callee.expression) && /^(z|zod)$/.test(callee.expression.text)) {
      return { $zod: method, args } satisfies ZodNode;
    }
    // z.coerce.<type>(...) — same JSON Schema as z.<type>()
    if (ts.isPropertyAccessExpression(callee.expression) && ['coerce', 'iso', 'string_format'].includes(callee.expression.name.text) &&
        ts.isIdentifier(callee.expression.expression) && /^(z|zod)$/.test(callee.expression.expression.text)) {
      return { $zod: method, args } satisfies ZodNode;
    }
    // cloudflare/mcp-server-cloudflare packages/mcp-common/src/format.ts, mirrored line for line:
    // fmt.trim trims the string and every line; fmt.oneLine joins the non-empty trimmed lines with a space.
    if (ts.isIdentifier(callee.expression) && callee.expression.text === 'fmt' && typeof args[0] === 'string') {
      const lines = args[0].trim().split('\n').map((l) => l.trim());
      if (method === 'trim') return lines.join('\n');
      if (method === 'oneLine') return lines.filter((l) => l.length > 0).join(' ');
    }
    const target = evaluate(callee.expression, mod, scope, depth + 1);
    if (isZod(target)) return applyZodMethod(target, method, args);
    if (Array.isArray(target) && method === 'join') {
      const sep = typeof args[0] === 'string' ? args[0] : ',';
      return target.some((x) => typeof x !== 'string' && typeof x !== 'number')
        ? unresolved(node)
        : target.join(sep);
    }
    if (Array.isArray(target) && method === 'map') return unresolved(node);
    if (typeof target === 'string') {
      if (method === 'trim') return target.trim();
      if (method === 'replace' || method === 'replaceAll') return unresolved(node);
      if (method === 'concat') return [target, ...args].every((x) => typeof x === 'string') ? [target, ...args].join('') : unresolved(node);
    }
    if (ts.isIdentifier(callee.expression) && callee.expression.text === 'Object' && method === 'values' && isPlainObject(args[0])) {
      return Object.values(args[0]);
    }
    if (ts.isIdentifier(callee.expression) && callee.expression.text === 'Object' && method === 'keys' && isPlainObject(args[0])) {
      return Object.keys(args[0]);
    }
    return unresolved(node);
  }
  if (ts.isIdentifier(callee)) {
    const fn = lookup(mod, callee.text, scope, depth);
    if (typeof fn === 'object' && fn !== null && '$fn' in fn) {
      const { $fn, mod: fmod } = fn as { $fn: ts.SignatureDeclaration & { body?: ts.Node }; mod: Module };
      const body = $fn.body;
      let expr: ts.Expression | undefined;
      if (body && ts.isBlock(body)) {
        const ret = body.statements.filter(ts.isReturnStatement);
        if (body.statements.length === 1 && ret.length === 1) expr = ret[0]!.expression;
      } else if (body) {
        expr = body as ts.Expression;
      }
      if (expr) {
        const bound = new Map<string, unknown>(scope);
        $fn.parameters.forEach((p, i) => {
          if (ts.isIdentifier(p.name)) bound.set(p.name.text, args[i]);
          else if (ts.isObjectBindingPattern(p.name) && isPlainObject(args[i])) {
            for (const el of p.name.elements) {
              if (ts.isIdentifier(el.name)) {
                const key = el.propertyName ? el.propertyName.getText() : el.name.text;
                bound.set(el.name.text, (args[i] as Record<string, unknown>)[key]);
              }
            }
          }
        });
        return evaluate(expr, fmod, bound, depth + 1);
      }
    }
    // An unknown wrapper around one definition (defineTool({...}), injectableTool({...})): the argument.
    if (args.length >= 1 && (isPlainObject(args[0]) || isZod(args[0]))) return args[0];
    if (callee.text === 'String' && args.length === 1 && typeof args[0] !== 'object') return String(args[0]);
  }
  return unresolved(node);
}

function evaluate(node: ts.Node, mod: Module, scope: Scope, depth = 0): unknown {
  if (depth > 60) return unresolved(node);
  if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node) || ts.isSatisfiesExpression(node) ||
      ts.isNonNullExpression(node) || ts.isTypeAssertionExpression(node)) {
    return evaluate(node.expression, mod, scope, depth + 1);
  }
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isNumericLiteral(node)) return Number(node.text);
  if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.MinusToken && ts.isNumericLiteral(node.operand)) {
    return -Number(node.operand.text);
  }
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (node.kind === ts.SyntaxKind.NullKeyword) return null;
  if (ts.isIdentifier(node) && node.text === 'undefined') return undefined;
  if (ts.isTemplateExpression(node)) {
    let out = node.head.text;
    for (const span of node.templateSpans) {
      const v = evaluate(span.expression, mod, scope, depth + 1);
      if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') out += String(v);
      else if (Array.isArray(v) && v.every((x) => typeof x === 'string')) out += v.join(',');
      else return unresolved(node);
      out += span.literal.text;
    }
    return out;
  }
  if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const l = evaluate(node.left, mod, scope, depth + 1);
    const r = evaluate(node.right, mod, scope, depth + 1);
    if ((typeof l === 'string' || typeof l === 'number') && (typeof r === 'string' || typeof r === 'number')) {
      return (l as string) + (r as string);
    }
    return unresolved(node);
  }
  if (ts.isArrayLiteralExpression(node)) {
    const out: unknown[] = [];
    for (const el of node.elements) {
      if (ts.isSpreadElement(el)) {
        const v = evaluate(el.expression, mod, scope, depth + 1);
        if (Array.isArray(v)) out.push(...v);
        else out.push(unresolved(el));
      } else {
        out.push(evaluate(el, mod, scope, depth + 1));
      }
    }
    return out;
  }
  if (ts.isObjectLiteralExpression(node)) {
    const out: Record<string, unknown> = {};
    for (const p of node.properties) {
      if (ts.isPropertyAssignment(p)) {
        const key = ts.isComputedPropertyName(p.name)
          ? evaluate(p.name.expression, mod, scope, depth + 1)
          : p.name.getText().replace(/^['"`]|['"`]$/g, '');
        if (typeof key === 'string') out[key] = evaluate(p.initializer, mod, scope, depth + 1);
      } else if (ts.isShorthandPropertyAssignment(p)) {
        out[p.name.text] = lookup(mod, p.name.text, scope, depth) ?? unresolved(p);
      } else if (ts.isSpreadAssignment(p)) {
        const v = evaluate(p.expression, mod, scope, depth + 1);
        if (isPlainObject(v)) Object.assign(out, v);
        else out[`$spread:${p.expression.getText()}`] = unresolved(p);
      }
    }
    return out;
  }
  if (ts.isIdentifier(node)) {
    const v = lookup(mod, node.text, scope, depth);
    return v === undefined ? unresolved(node) : v;
  }
  if (ts.isPropertyAccessExpression(node)) {
    const target = evaluate(node.expression, mod, scope, depth + 1);
    const key = node.name.text;
    if (isZod(target) && key === 'shape' && target.$zod === 'object') return target.args[0];
    if (isZod(target) && key === 'element' && target.$zod === 'array') return target.args[0];
    if (typeof target === 'object' && target !== null && '$ns' in target) {
      const v = lookup((target as { $ns: Module }).$ns, key, EMPTY_SCOPE, depth + 1);
      return v === undefined ? unresolved(node) : v;
    }
    if (isPlainObject(target) && key in target) return target[key];
    if (typeof target === 'string' && key === 'length') return target.length;
    return unresolved(node);
  }
  if (ts.isElementAccessExpression(node)) {
    const target = evaluate(node.expression, mod, scope, depth + 1);
    const key = evaluate(node.argumentExpression, mod, scope, depth + 1);
    if (isPlainObject(target) && typeof key === 'string' && key in target) return target[key];
    if (Array.isArray(target) && typeof key === 'number') return target[key];
    return unresolved(node);
  }
  if (ts.isCallExpression(node)) return evalCall(node, mod, scope, depth);
  if (ts.isTaggedTemplateExpression(node) && ts.isIdentifier(node.tag)) {
    // common-tags / dedent style tags: codeBlock, stripIndent, dedent, oneLine
    const raw = evaluate(node.template, mod, scope, depth + 1);
    if (typeof raw !== 'string') return unresolved(node);
    const tag = node.tag.text;
    if (tag === 'oneLine') return raw.replace(/(?:\n(?:\s*))+/g, ' ').trim();
    if (['codeBlock', 'stripIndent', 'stripIndents', 'dedent', 'source', 'html'].includes(tag)) {
      if (tag === 'stripIndents') return raw.replace(/^[ \t]+/gm, '').trim();
      const lines = raw.split('\n');
      const indents = lines.filter((l) => l.trim() !== '').map((l) => /^[ \t]*/.exec(l)![0].length);
      const min = indents.length > 0 ? Math.min(...indents) : 0;
      return lines.map((l) => l.slice(Math.min(min, /^[ \t]*/.exec(l)![0].length))).join('\n').trim();
    }
    return unresolved(node);
  }
  if (ts.isConditionalExpression(node)) return unresolved(node);
  return unresolved(node);
}

// ------------------------------------------------------------------ zod -> JSON Schema

function collectUnresolved(v: unknown, acc: string[]): void {
  if (isOpaque(v)) acc.push('<function or module value>');
  else if (isUnresolved(v)) acc.push(v.$unresolved);
  else if (Array.isArray(v)) v.forEach((x) => collectUnresolved(x, acc));
  else if (typeof v === 'object' && v !== null) Object.values(v).forEach((x) => collectUnresolved(x, acc));
}

function jsonValue(v: unknown): Json {
  if (v === undefined) return null;
  if (isOpaque(v)) return { $unresolved: '<function or module value>' };
  if (isUnresolved(v)) return { $unresolved: v.$unresolved };
  if (Array.isArray(v)) return v.map(jsonValue);
  if (isZod(v)) return toJsonSchema(v);
  if (typeof v === 'object' && v !== null) {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, jsonValue(x)]));
  }
  return v as Json;
}

function objectSchema(shape: unknown): Record<string, Json> {
  if (!isPlainObject(shape)) return { type: 'object', $unresolved_shape: jsonValue(shape) };
  const properties: Record<string, Json> = {};
  const required: string[] = [];
  for (const [key, field] of Object.entries(shape)) {
    if (key.startsWith('$spread:')) {
      properties[key] = jsonValue(field);
      continue;
    }
    properties[key] = isZod(field) ? toJsonSchema(field) : jsonValue(field);
    if (isZod(field) && !field.optional && !field.hasDefault) required.push(key);
  }
  return {
    type: 'object',
    properties,
    ...(required.length > 0 ? { required } : {}),
    additionalProperties: false,
  };
}

function toJsonSchema(z: ZodNode): Record<string, Json> {
  let out: Record<string, Json>;
  const a0 = z.args[0];
  switch (z.$zod) {
    case 'string':
      out = { type: 'string' };
      break;
    case 'url':
      out = { type: 'string', format: 'uri' };
      break;
    case 'email':
      out = { type: 'string', format: 'email' };
      break;
    case 'uuid':
      out = { type: 'string', format: 'uuid' };
      break;
    case 'datetime':
      out = { type: 'string', format: 'date-time' };
      break;
    case 'date':
      out = { type: 'string', format: 'date' };
      break;
    case 'number':
      out = { type: 'number' };
      break;
    case 'int':
    case 'bigint':
      out = { type: 'integer' };
      break;
    case 'boolean':
      out = { type: 'boolean' };
      break;
    case 'null':
      out = { type: 'null' };
      break;
    case 'any':
    case 'unknown':
      out = {};
      break;
    case 'literal':
      out = { const: jsonValue(a0) };
      break;
    case 'enum':
      out = { type: 'string', enum: jsonValue(Array.isArray(a0) ? a0 : isPlainObject(a0) ? Object.values(a0) : a0) };
      break;
    case 'nativeEnum':
      out = { type: 'string', enum: jsonValue(isPlainObject(a0) ? Object.values(a0) : a0) };
      break;
    case 'array':
      out = { type: 'array', items: isZod(a0) ? toJsonSchema(a0) : jsonValue(a0) };
      break;
    case 'object':
    case 'strictObject':
    case 'looseObject':
      out = objectSchema(a0);
      break;
    case 'record':
      out = { type: 'object', additionalProperties: jsonValue(z.args[z.args.length - 1]) };
      break;
    case 'union':
    case 'discriminatedUnion': {
      const opts = z.$zod === 'union' ? a0 : z.args[1];
      out = { anyOf: Array.isArray(opts) ? opts.map(jsonValue) : jsonValue(opts) };
      break;
    }
    case 'tuple':
      out = { type: 'array', prefixItems: jsonValue(a0) };
      break;
    case 'coerce':
      out = {};
      break;
    default:
      out = { $unresolved_zod: z.$zod };
  }
  const c = z.checks ?? {};
  const isStr = out['type'] === 'string';
  const isArr = out['type'] === 'array';
  if (c['min'] !== undefined) out[isStr ? 'minLength' : isArr ? 'minItems' : 'minimum'] = jsonValue(c['min']);
  if (c['max'] !== undefined) out[isStr ? 'maxLength' : isArr ? 'maxItems' : 'maximum'] = jsonValue(c['max']);
  if (c['int'] !== undefined) out['type'] = 'integer';
  if (c['url'] !== undefined) out['format'] = 'uri';
  if (c['email'] !== undefined) out['format'] = 'email';
  if (c['nonempty'] !== undefined) out[isArr ? 'minItems' : 'minLength'] = 1;
  if (z.hasDefault) out['default'] = jsonValue(z.defaultValue);
  if (z.description !== undefined) out['description'] = z.description;
  if (z.nullable) out = { anyOf: [out, { type: 'null' }] };
  return out;
}

function schemaOf(v: unknown): Json {
  if (isZod(v)) return toJsonSchema(v);
  if (isPlainObject(v)) {
    // A raw shape ({ a: z.string() }) or an already-JSON schema ({ type: 'object', properties })
    const values = Object.values(v);
    if (values.length > 0 && values.some(isZod)) return objectSchema(v);
    if (values.length === 0 && !('type' in v)) return { type: 'object', properties: {} };
    return jsonValue(v);
  }
  if (v === undefined) return { type: 'object', properties: {} };
  return jsonValue(v);
}

// ------------------------------------------------------------------ tool discovery

interface ExtractedTool {
  name: string;
  title?: Json;
  description: Json;
  inputSchema: Json;
  annotations?: Json;
  _extraction: { path: string; line: number; shape: string; unresolved: string[] };
}

function emit(out: ExtractedTool[], mod: Module, node: ts.Node, shape: string, def: Record<string, unknown>): void {
  const name = def['name'];
  if (typeof name !== 'string' || name === '') return;
  const unres: string[] = [];
  const tool: ExtractedTool = {
    name,
    ...(def['title'] !== undefined ? { title: jsonValue(def['title']) } : {}),
    description: jsonValue(def['description']),
    inputSchema: schemaOf(def['inputSchema']),
    ...(def['annotations'] !== undefined ? { annotations: jsonValue(def['annotations']) } : {}),
    _extraction: {
      path: relative(ROOT, mod.path),
      line: mod.sf.getLineAndCharacterOfPosition(node.getStart()).line + 1,
      shape,
      unresolved: unres,
    },
  };
  collectUnresolved(tool.description, unres);
  collectUnresolved(tool.inputSchema, unres);
  collectUnresolved(tool.title, unres);
  out.push(tool);
}

function discover(mod: Module): ExtractedTool[] {
  const out: ExtractedTool[] = [];
  const claimed = new Set<ts.Node>();
  const visit = (node: ts.Node): void => {
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
      const m = node.expression.name.text;
      const args = node.arguments;
      if ((m === 'registerTool' || m === 'accountTool') && args.length >= 2) {
        const name = evaluate(args[0]!, mod, EMPTY_SCOPE);
        const cfg = evaluate(args[1]!, mod, EMPTY_SCOPE);
        if (typeof name === 'string' && isPlainObject(cfg)) {
          if (ts.isObjectLiteralExpression(args[1]!)) claimed.add(args[1]!);
          emit(out, mod, node, 'registerTool', { ...cfg, name });
        }
      } else if (m === 'tool' && args.length >= 2 && ts.isStringLiteralLike(args[0]!)) {
        const name = evaluate(args[0]!, mod, EMPTY_SCOPE);
        const rest = args.slice(1, -1).map((a) => evaluate(a, mod, EMPTY_SCOPE));
        const description = typeof rest[0] === 'string' || isUnresolved(rest[0]) ? rest.shift() : undefined;
        const shape = isPlainObject(rest[0]) && Object.values(rest[0]).some(isZod) ? rest.shift() : undefined;
        const annotations = isPlainObject(rest[0]) ? rest.shift() : undefined;
        emit(out, mod, node, 'server.tool', { name, description, inputSchema: shape ?? {}, annotations });
      }
    }
    if (ts.isObjectLiteralExpression(node) && !claimed.has(node)) {
      const keys = node.properties.map((p) => (p.name ? p.name.getText() : ''));
      const hasDesc = keys.includes('description');
      // inputSchema / parameters anywhere; schema / params only beside a literal name (cloudflare helpers)
      const named = keys.includes('name');
      const schemaKey = ['inputSchema', 'parameters', ...(named ? ['schema', 'params'] : [])].find((k) => keys.includes(k));
      if (hasDesc && schemaKey) {
        const def = evaluate(node, mod, EMPTY_SCOPE);
        if (isPlainObject(def)) {
          let name = def['name'];
          let shape = 'object-literal';
          if (typeof name !== 'string') {
            // key: factory({ description, parameters }) — the property key names the tool
            let p: ts.Node | undefined = node.parent;
            while (p && (ts.isCallExpression(p) || ts.isParenthesizedExpression(p) || ts.isAsExpression(p))) p = p.parent;
            if (p && ts.isPropertyAssignment(p)) {
              name = p.name.getText().replace(/^['"]|['"]$/g, '');
              shape = 'keyed-factory';
            }
          }
          emit(out, mod, node, shape, { ...def, name, inputSchema: def[schemaKey] });
          claimed.add(node);
        }
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(mod.sf);
  return out;
}

const files = process.argv.slice(2).filter((a, i, all) => !a.startsWith('--') && !['--root', '--alias'].includes(all[i - 1] ?? ''));
const tools = files.flatMap((f) => {
  const mod = loadModule(resolve(ROOT, f));
  return mod ? discover(mod) : [];
});
process.stdout.write(`${JSON.stringify(tools, null, 2)}\n`);
