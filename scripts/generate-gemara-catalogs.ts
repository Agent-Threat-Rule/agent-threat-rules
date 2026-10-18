#!/usr/bin/env tsx
/**
 * generate-gemara-catalogs — build the Gemara catalogs in
 * spec/category-registry/gemara/ from the category registry.
 *
 * WHY THIS EXISTS
 *
 * The Gemara vector catalog is a projection of spec/category-registry/v1.0.yaml:
 * one vector per registry category. When it was first written it was a
 * hand-copied file in another repository, so nothing stopped the copy and the
 * registry from drifting apart. It now sits beside the registry and is built
 * from it. Vector ids and descriptions come from the registry verbatim; only
 * what the registry does not say (vector titles and grouping, and the
 * capability, threat and control catalogs written against those vectors) comes
 * from spec/category-registry/gemara/src/editorial.yaml.
 *
 * The generator refuses to run when the two inputs disagree: a registry
 * category with no editorial entry, an editorial entry for a category the
 * registry does not have, a vector no threat reaches, or a reference to an id
 * that does not exist. tests/gemara-catalogs.test.ts fails CI when the
 * committed catalogs differ from what this script produces.
 *
 * The four catalogs form one OCI bundle. Its root is the control catalog; each
 * catalog lists what it uses from the others under `imports`, with a
 * mapping-reference whose url is a sibling file (file://./<name>), which is
 * what the Gemara bundle assembler walks to collect dependencies.
 *
 * Usage:
 *   npx tsx scripts/generate-gemara-catalogs.ts                  write the catalogs
 *   npx tsx scripts/generate-gemara-catalogs.ts --check          exit 1 when stale
 *   npx tsx scripts/generate-gemara-catalogs.ts --print-version  print the bundle version
 */
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import yaml from "js-yaml";

type Json = Record<string, unknown>;

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export const REGISTRY_PATH = join(REPO_ROOT, "spec", "category-registry", "v1.0.yaml");
export const CATALOG_DIR = join(REPO_ROOT, "spec", "category-registry", "gemara");
export const EDITORIAL_PATH = join(CATALOG_DIR, "src", "editorial.yaml");
const REPO_URL = "https://github.com/Agent-Threat-Rule/agent-threat-rules";
/** mapping-reference id for the category registry; generated, never declared in editorial.yaml. */
export const REGISTRY_REF_ID = "ATR";

const repoPath = (p: string): string => relative(REPO_ROOT, p).split(sep).join("/");

export class CatalogError extends Error {}

function fail(message: string): never {
  throw new CatalogError(message);
}

// ---------------------------------------------------------------- reading --

function mapping(value: unknown, where: string): Json {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${where}: expected a mapping`);
  return value as Json;
}

function entries(value: unknown, where: string): Json[] {
  if (!Array.isArray(value) || value.length === 0) fail(`${where}: expected a non-empty list`);
  return value.map((item, i) => mapping(item, `${where}[${i}]`));
}

function text(value: unknown, where: string): string {
  if (typeof value !== "string" || value.trim() === "") fail(`${where}: expected a non-empty string`);
  return value;
}

function assertUnique(ids: readonly string[], where: string): void {
  const seen = new Set<string>();
  for (const id of ids) {
    if (seen.has(id)) fail(`${where}: duplicate id "${id}"`);
    seen.add(id);
  }
}

/** Folded YAML scalars end in a newline; drop it so output does not depend on how the source was folded. */
function trimStrings(value: unknown): unknown {
  if (typeof value === "string") return value.trimEnd();
  if (Array.isArray(value)) return value.map(trimStrings);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, trimStrings(v)]));
  }
  return value;
}

// --------------------------------------------------------------- registry --

interface Category {
  readonly id: string;
  readonly description: string;
}

interface Registry {
  readonly version: string;
  readonly status: string;
  readonly categories: readonly Category[];
}

/**
 * The registry's description, whitespace-normalized. Its descriptions are folded
 * scalars, and a hyphenated word wrapped at the hyphen ("cross-" / "agent")
 * folds to "cross- agent"; that fold is undone. Nothing else is changed.
 */
function registryDescription(value: unknown, where: string): string {
  return text(value, where)
    .replace(/\s+/g, " ")
    .trim()
    .replace(/(\w)- (?=\w)/g, "$1-");
}

function parseRegistry(raw: unknown): Registry {
  const r = mapping(raw, "registry");
  const version = String(r.version ?? "");
  if (!/^\d+\.\d+$/.test(version)) fail(`registry: version must be MAJOR.MINOR, got "${version}"`);
  const categories = entries(r.categories, "registry.categories").map((c, i) => ({
    id: text(c.id, `registry.categories[${i}].id`),
    description: registryDescription(c.description, `registry.categories[${i}].description`),
  }));
  assertUnique(
    categories.map((c) => c.id),
    "registry.categories",
  );
  return { version, status: text(r.status, "registry.status"), categories };
}

function registryReference(registry: Registry): Json {
  return {
    id: REGISTRY_REF_ID,
    title: "Agent Threat Rules category registry",
    version: registry.version,
    url: `${REPO_URL}/blob/main/${repoPath(REGISTRY_PATH)}`,
    description:
      "Detection categories of Agent Threat Rules (ATR). Each entry id is a category id " +
      "in this registry and names the directory under rules/ that holds that category's rules.",
  };
}

// --------------------------------------------------------------- editorial --

interface Bundle {
  readonly version: string;
  readonly gemaraVersion: string;
  readonly author: Json;
  readonly draft: boolean;
}

interface CatalogSource {
  readonly key: string;
  readonly file: string;
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly body: Json;
}

function parseBundle(editorial: Json, registry: Registry): Bundle {
  const b = mapping(editorial.bundle, "bundle");
  const version = text(b.version, "bundle.version");
  const semver = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!semver) fail(`bundle.version must be MAJOR.MINOR.PATCH, got "${version}"`);
  if (`${semver[1]}.${semver[2]}` !== registry.version) {
    fail(`bundle.version ${version}: MAJOR.MINOR must equal the registry version ${registry.version}`);
  }
  return {
    version,
    gemaraVersion: text(b["gemara-version"], "bundle.gemara-version"),
    author: mapping(b.author, "bundle.author"),
    // The registry is the thing being projected; while it is a draft, so is every catalog built from it.
    draft: registry.status === "draft",
  };
}

function catalogSource(editorial: Json, key: string): CatalogSource {
  const body = mapping(editorial[key], key);
  const file = text(body.file, `${key}.file`);
  if (!/^[a-z0-9-]+\.yaml$/.test(file)) fail(`${key}.file: expected a bare lower-case .yaml file name, got "${file}"`);
  return {
    key,
    file,
    id: text(body.id, `${key}.id`),
    title: text(body.title, `${key}.title`),
    description: text(body.description, `${key}.description`),
    body,
  };
}

function externalReferences(editorial: Json): ReadonlyMap<string, Json> {
  const refs = entries(editorial["external-references"], "external-references");
  const byId = new Map<string, Json>();
  for (const [i, ref] of refs.entries()) {
    const id = text(ref.id, `external-references[${i}].id`);
    if (id === REGISTRY_REF_ID) fail(`external-references: "${id}" is generated from the registry; do not declare it`);
    if (byId.has(id)) fail(`external-references: duplicate id "${id}"`);
    byId.set(id, ref);
  }
  return byId;
}

// ------------------------------------------------------------- validation --

function checkGroups(items: readonly Json[], groups: readonly Json[], where: string): void {
  const ids = new Set(groups.map((g, i) => text(g.id, `${where}.groups[${i}].id`)));
  assertUnique(
    groups.map((g) => String(g.id)),
    `${where}.groups`,
  );
  for (const [i, item] of items.entries()) {
    const group = text(item.group, `${where}[${i}].group`);
    if (!ids.has(group)) fail(`${where}[${i}] (${String(item.id)}): group "${group}" is not defined`);
  }
}

/** Allowed entry ids per reference-id; null means an external document whose ids are not checked here. */
type Allowed = ReadonlyMap<string, ReadonlySet<string> | null>;

/**
 * Walk the MultiEntryMapping list under `field` on every item, fail on any
 * reference-id or entry id that does not resolve, and record what was used.
 */
function collectReferences(items: readonly Json[], field: string, where: string, allowed: Allowed, used: Map<string, Set<string>>): void {
  for (const [i, item] of items.entries()) {
    const refs = item[field];
    if (refs === undefined) continue;
    for (const [j, ref] of entries(refs, `${where}[${i}].${field}`).entries()) {
      const refId = text(ref["reference-id"], `${where}[${i}].${field}[${j}].reference-id`);
      if (!allowed.has(refId)) fail(`${where}[${i}] (${String(item.id)}): ${field} reference "${refId}" is not allowed here`);
      const valid = allowed.get(refId) ?? null;
      const seen = used.get(refId) ?? new Set<string>();
      for (const [k, entry] of entries(ref.entries, `${where}[${i}].${field}[${j}].entries`).entries()) {
        const id = text(entry["reference-id"], `${where}[${i}].${field}[${j}].entries[${k}]`);
        if (valid !== null && !valid.has(id)) fail(`${where}[${i}] (${String(item.id)}): "${id}" is not an entry of ${refId}`);
        seen.add(id);
      }
      used.set(refId, seen);
    }
  }
}

function referenceDescriptions(source: CatalogSource, usedRefIds: readonly string[]): ReadonlyMap<string, string> {
  const raw = mapping(source.body["reference-descriptions"], `${source.key}.reference-descriptions`);
  for (const key of Object.keys(raw)) {
    if (!usedRefIds.includes(key)) fail(`${source.key}.reference-descriptions.${key}: no reference to that catalog is used`);
  }
  return new Map(usedRefIds.map((id) => [id, text(raw[id], `${source.key}.reference-descriptions.${id}`)]));
}

// ---------------------------------------------------------------- building --

function metadata(source: CatalogSource, type: string, bundle: Bundle, refs: readonly Json[], extra: Json = {}): Json {
  return {
    id: source.id,
    type,
    "gemara-version": bundle.gemaraVersion,
    version: bundle.version,
    description: source.description,
    author: bundle.author,
    ...(refs.length > 0 ? { "mapping-references": refs } : {}),
    ...extra,
    ...(bundle.draft ? { draft: true } : {}),
  };
}

/** A reference to another catalog in the bundle, resolvable by the assembler as a sibling file. */
function bundleReference(target: CatalogSource, bundle: Bundle, description: string): Json {
  return { id: target.id, title: target.title, version: bundle.version, url: `file://./${target.file}`, description };
}

/** `imports` entry listing the ids used from `target`, in the target's own order. */
function importOf(target: CatalogSource, order: readonly string[], used: ReadonlySet<string>): Json {
  return {
    "reference-id": target.id,
    entries: order.filter((id) => used.has(id)).map((id) => ({ "reference-id": id })),
  };
}

function buildVectorCatalog(source: CatalogSource, registry: Registry, bundle: Bundle): Json {
  const groups = entries(source.body.groups, `${source.key}.groups`);
  const editorial = mapping(source.body.vectors, `${source.key}.vectors`);
  const known = new Set(registry.categories.map((c) => c.id));
  for (const id of Object.keys(editorial)) {
    if (!known.has(id)) fail(`${source.key}.vectors.${id}: "${id}" is not a category in the registry`);
  }
  const vectors = registry.categories.map((category) => {
    if (editorial[category.id] === undefined) {
      fail(`registry category "${category.id}" has no entry under ${source.key}.vectors (title and group)`);
    }
    const v = mapping(editorial[category.id], `${source.key}.vectors.${category.id}`);
    const title = text(v.title, `${source.key}.vectors.${category.id}.title`);
    return { id: category.id, title, description: category.description, group: v.group };
  });
  checkGroups(vectors, groups, `${source.key}.vectors`);
  return {
    metadata: metadata(source, "VectorCatalog", bundle, [registryReference(registry)]),
    title: source.title,
    groups,
    vectors,
  };
}

function buildCapabilityCatalog(source: CatalogSource, bundle: Bundle): Json {
  const groups = entries(source.body.groups, `${source.key}.groups`);
  const capabilities = entries(source.body.capabilities, `${source.key}.capabilities`);
  assertUnique(
    capabilities.map((c, i) => text(c.id, `${source.key}.capabilities[${i}].id`)),
    `${source.key}.capabilities`,
  );
  checkGroups(capabilities, groups, `${source.key}.capabilities`);
  return { metadata: metadata(source, "CapabilityCatalog", bundle, []), title: source.title, groups, capabilities };
}

interface ThreatInputs {
  readonly source: CatalogSource;
  readonly capabilities: CatalogSource;
  readonly capabilityIds: readonly string[];
  readonly vectors: CatalogSource;
  readonly registry: Registry;
  readonly bundle: Bundle;
}

function buildThreatCatalog(t: ThreatInputs): Json {
  const where = `${t.source.key}.threats`;
  const threats = entries(t.source.body.threats, where);
  assertUnique(
    threats.map((x, i) => text(x.id, `${where}[${i}].id`)),
    where,
  );
  checkGroups(threats, entries(t.source.body.groups, `${t.source.key}.groups`), where);
  const vectorIds = t.registry.categories.map((c) => c.id);
  const used = new Map<string, Set<string>>();
  for (const [i, threat] of threats.entries()) entries(threat.capabilities, `${where}[${i}].capabilities`);
  collectReferences(threats, "capabilities", where, new Map([[t.capabilities.id, new Set(t.capabilityIds)]]), used);
  collectReferences(threats, "vectors", where, new Map([[t.vectors.id, new Set(vectorIds)]]), used);
  const reached = used.get(t.vectors.id) ?? new Set<string>();
  for (const id of vectorIds) {
    if (!reached.has(id)) fail(`registry category "${id}" is not reached by any threat in ${t.source.key}`);
  }
  const usedCaps = used.get(t.capabilities.id) ?? new Set<string>();
  const descriptions = referenceDescriptions(t.source, [t.capabilities.id, t.vectors.id]);
  const refs = [t.capabilities, t.vectors].map((c) => bundleReference(c, t.bundle, descriptions.get(c.id) ?? ""));
  return {
    metadata: metadata(t.source, "ThreatCatalog", t.bundle, refs),
    title: t.source.title,
    imports: [importOf(t.capabilities, t.capabilityIds, usedCaps), importOf(t.vectors, vectorIds, reached)],
    groups: t.source.body.groups,
    threats,
  };
}

function checkApplicability(controls: readonly Json[], groups: readonly Json[], where: string): void {
  const ids = new Set(groups.map((g, i) => text(g.id, `${where}.applicability-groups[${i}].id`)));
  for (const [i, control] of controls.entries()) {
    for (const [j, ar] of entries(control["assessment-requirements"], `${where}[${i}].assessment-requirements`).entries()) {
      const applicability = ar.applicability;
      if (!Array.isArray(applicability) || applicability.length === 0) fail(`${where}[${i}].assessment-requirements[${j}]: applicability is required`);
      for (const a of applicability) {
        if (!ids.has(String(a))) fail(`${where}[${i}].assessment-requirements[${j}]: applicability "${String(a)}" is not defined`);
      }
    }
  }
}

interface ControlInputs {
  readonly source: CatalogSource;
  readonly threats: CatalogSource;
  readonly threatIds: readonly string[];
  readonly registry: Registry;
  readonly externals: ReadonlyMap<string, Json>;
  readonly bundle: Bundle;
}

function buildControlCatalog(c: ControlInputs): Json {
  const where = `${c.source.key}.controls`;
  const controls = entries(c.source.body.controls, where);
  assertUnique(
    controls.map((x, i) => text(x.id, `${where}[${i}].id`)),
    where,
  );
  checkGroups(controls, entries(c.source.body.groups, `${c.source.key}.groups`), where);
  const applicabilityGroups = entries(c.source.body["applicability-groups"], `${c.source.key}.applicability-groups`);
  checkApplicability(controls, applicabilityGroups, where);
  const used = new Map<string, Set<string>>();
  collectReferences(controls, "threats", where, new Map([[c.threats.id, new Set(c.threatIds)]]), used);
  const guidelineTargets = new Map<string, ReadonlySet<string> | null>([
    [REGISTRY_REF_ID, new Set(c.registry.categories.map((x) => x.id))],
    ...[...c.externals.keys()].map((id): [string, null] => [id, null]),
  ]);
  collectReferences(controls, "guidelines", where, guidelineTargets, used);
  for (const id of c.externals.keys()) {
    if (!used.has(id)) fail(`external-references: "${id}" is declared but no catalog uses it`);
  }
  const descriptions = referenceDescriptions(c.source, [c.threats.id]);
  const refs = [
    bundleReference(c.threats, c.bundle, descriptions.get(c.threats.id) ?? ""),
    ...(used.has(REGISTRY_REF_ID) ? [registryReference(c.registry)] : []),
    ...[...c.externals.entries()].filter(([id]) => used.has(id)).map(([, ref]) => ref),
  ];
  return {
    metadata: metadata(c.source, "ControlCatalog", c.bundle, refs, { "applicability-groups": applicabilityGroups }),
    title: c.source.title,
    imports: [importOf(c.threats, c.threatIds, used.get(c.threats.id) ?? new Set())],
    groups: c.source.body.groups,
    controls,
  };
}

// --------------------------------------------------------------- rendering --

function header(): string {
  return [
    "# GENERATED by scripts/generate-gemara-catalogs.ts. Do not edit by hand.",
    `# Inputs: ${repoPath(REGISTRY_PATH)} (the category registry) and`,
    `#         ${repoPath(EDITORIAL_PATH)}`,
    "# Regenerate: npx tsx scripts/generate-gemara-catalogs.ts",
    "# License: MIT",
    "",
  ].join("\n");
}

function render(doc: Json): string {
  return header() + yaml.dump(doc, { lineWidth: 80, noRefs: true, noCompatMode: true, quotingType: '"' });
}

export interface GeneratedFile {
  readonly file: string;
  readonly content: string;
}

export interface Generated {
  /** Bundle version: metadata.version on every catalog, and the OCI tag. */
  readonly version: string;
  /** File name of the root artifact the bundle is assembled from. */
  readonly root: string;
  /** Root first. */
  readonly files: readonly GeneratedFile[];
}

/** Pure: build every catalog from the parsed registry and editorial documents. */
export function generate(registryRaw: unknown, editorialRaw: unknown): Generated {
  const registry = parseRegistry(registryRaw);
  const editorial = mapping(trimStrings(editorialRaw), "editorial");
  const bundle = parseBundle(editorial, registry);
  const [vectors, capabilities, threats, controls] = ["vector-catalog", "capability-catalog", "threat-catalog", "control-catalog"].map(
    (key) => catalogSource(editorial, key),
  );
  assertUnique(
    [vectors, capabilities, threats, controls].map((s) => s.file),
    "catalog files",
  );
  // The projection first: a registry/editorial mismatch is reported as such,
  // not as whatever downstream reference it happens to break.
  const vectorDoc = buildVectorCatalog(vectors, registry, bundle);
  const capabilityDoc = buildCapabilityCatalog(capabilities, bundle);
  const capabilityIds = (capabilityDoc.capabilities as Json[]).map((c) => String(c.id));
  const threatDoc = buildThreatCatalog({ source: threats, capabilities, capabilityIds, vectors, registry, bundle });
  const threatIds = (threatDoc.threats as Json[]).map((t) => String(t.id));
  const controlDoc = buildControlCatalog({ source: controls, threats, threatIds, registry, externals: externalReferences(editorial), bundle });
  const files = [
    { file: controls.file, content: render(controlDoc) },
    { file: threats.file, content: render(threatDoc) },
    { file: capabilities.file, content: render(capabilityDoc) },
    { file: vectors.file, content: render(vectorDoc) },
  ];
  return { version: bundle.version, root: controls.file, files };
}

export function loadInputs(registryPath = REGISTRY_PATH, editorialPath = EDITORIAL_PATH): readonly [unknown, unknown] {
  return [yaml.load(readFileSync(registryPath, "utf8")), yaml.load(readFileSync(editorialPath, "utf8"))];
}

/** What differs between `dir` and the generator output; empty when the committed catalogs are current. */
export function staleFiles(generated: Generated, dir = CATALOG_DIR): string[] {
  const problems: string[] = [];
  for (const { file, content } of generated.files) {
    const path = join(dir, file);
    if (!existsSync(path)) problems.push(`${file}: missing`);
    else if (readFileSync(path, "utf8") !== content) problems.push(`${file}: differs from the generator output`);
  }
  const expected = new Set(generated.files.map((f) => f.file));
  for (const name of readdirSync(dir)) {
    if (/\.ya?ml$/.test(name) && !expected.has(name)) {
      problems.push(`${name}: not produced by the generator, but sits in the bundle directory`);
    }
  }
  return problems;
}

function main(args: readonly string[]): number {
  const generated = generate(...loadInputs());
  if (args.includes("--print-version")) {
    console.log(generated.version);
    return 0;
  }
  if (args.includes("--check")) {
    const problems = staleFiles(generated);
    if (problems.length === 0) {
      console.log(`Gemara catalogs are current (bundle ${generated.version}).`);
      return 0;
    }
    console.error(["Gemara catalogs are stale. Run: npx tsx scripts/generate-gemara-catalogs.ts", ...problems.map((p) => `  ${p}`)].join("\n"));
    return 1;
  }
  for (const { file, content } of generated.files) writeFileSync(join(CATALOG_DIR, file), content);
  console.log(`Wrote ${generated.files.length} catalogs to ${repoPath(CATALOG_DIR)} (bundle ${generated.version}, root ${generated.root}).`);
  return 0;
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(resolve(invokedPath)).href) {
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    if (!(error instanceof CatalogError)) throw error;
    console.error(`generate-gemara-catalogs: ${error.message}`);
    process.exitCode = 1;
  }
}
