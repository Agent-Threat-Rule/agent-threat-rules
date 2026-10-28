import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { load } from "js-yaml";
import { emitYaml, type YamlValue } from "./yaml-emit.js";
import type { CiscoSignature, SignatureFile } from "./transform.js";

/**
 * The bundled-pack schema Cisco Skill Scanner validates at startup since its
 * scanner modernisation (schema_version 2) and taxonomy mapping. The scanner
 * rejects any manifest field outside its allowlist -- `signature_files`,
 * `maturity`, `atr_id`, `atr_url` and `file` included -- and every rule must
 * name a Cisco AI taxonomy code or inherit one from `taxonomy_defaults` for
 * its category.
 *
 * The categories and taxonomy codes are the scanner maintainers' choices, not
 * ATR's: they map ATR's ten categories onto the scanner's threat categories
 * and pick a code per rule. A refresh therefore reads them from the pack
 * already vendored downstream and carries them forward unchanged. A rule new
 * to the pack takes the scanner category its ATR category already maps to
 * and inherits that category's default code, unless --taxonomy names one.
 */

export interface DownstreamRule {
  readonly category: string;
  readonly taxonomy?: string;
}

export interface DownstreamPack {
  /** Leading comment block of the vendored pack.yaml, kept verbatim. */
  readonly headerComments: string;
  readonly taxonomyDefaults: Readonly<Record<string, string>>;
  /** Keyed by signature id, e.g. ATR_2026_00030. */
  readonly rules: ReadonlyMap<string, DownstreamRule>;
  /** ATR signature category (e.g. agent_manipulation) -> scanner category. */
  readonly categoryMap: ReadonlyMap<string, string>;
}

interface RawManifest {
  readonly schema_version?: unknown;
  readonly taxonomy_defaults?: Record<string, unknown>;
  readonly rules?: Record<string, { category?: unknown; taxonomy?: unknown }>;
}

function leadingComments(text: string): string {
  const lines = text.split("\n");
  const end = lines.findIndex(
    (line) => line.trim() !== "" && !line.startsWith("#"),
  );
  return lines.slice(0, end === -1 ? lines.length : end).join("\n");
}

/** "atr_agent_manipulation.yaml" -> "agent_manipulation". */
function atrCategoryOfFile(fileName: string): string {
  return fileName.replace(/^atr_/, "").replace(/\.yaml$/, "");
}

function signatureIdsByAtrCategory(packDir: string): Map<string, string[]> {
  const dir = join(packDir, "signatures");
  const byCategory = new Map<string, string[]>();
  for (const fileName of readdirSync(dir)
    .filter((f) => f.endsWith(".yaml"))
    .sort()) {
    const doc = load(readFileSync(join(dir, fileName), "utf8")) as {
      signatures?: { id?: unknown }[];
    };
    const ids = (doc.signatures ?? []).map((s) => String(s.id));
    byCategory.set(atrCategoryOfFile(fileName), ids);
  }
  return byCategory;
}

/**
 * Derive ATR category -> scanner category from the vendored pack. Every rule
 * of one ATR category must map to the same scanner category; if the
 * maintainers ever split one, a new rule's category is a choice this script
 * must not guess, so it stops instead.
 */
function deriveCategoryMap(
  rules: ReadonlyMap<string, DownstreamRule>,
  idsByAtrCategory: ReadonlyMap<string, readonly string[]>,
): Map<string, string> {
  const map = new Map<string, string>();
  for (const [atrCategory, ids] of idsByAtrCategory) {
    const scannerCategories = new Set(
      ids.map((id) => rules.get(id)?.category).filter(Boolean),
    );
    if (scannerCategories.size !== 1) {
      throw new Error(
        `downstream maps ATR category ${atrCategory} to ${scannerCategories.size} scanner categories ` +
          `(${[...scannerCategories].join(", ") || "none"}); expected exactly one`,
      );
    }
    map.set(atrCategory, [...scannerCategories][0] as string);
  }
  return map;
}

export function readDownstreamPack(packDir: string): DownstreamPack {
  const manifestPath = join(packDir, "pack.yaml");
  if (!existsSync(manifestPath)) throw new Error(`no pack.yaml in ${packDir}`);
  const text = readFileSync(manifestPath, "utf8");
  const raw = load(text) as RawManifest;
  if (raw.schema_version !== 2) {
    throw new Error(
      `downstream pack.yaml has schema_version ${String(raw.schema_version)}, expected 2`,
    );
  }
  const rules = new Map<string, DownstreamRule>();
  for (const [id, entry] of Object.entries(raw.rules ?? {})) {
    rules.set(id, {
      category: String(entry.category),
      ...(entry.taxonomy === undefined
        ? {}
        : { taxonomy: String(entry.taxonomy) }),
    });
  }
  const taxonomyDefaults = Object.fromEntries(
    Object.entries(raw.taxonomy_defaults ?? {}).map(([k, v]) => [k, String(v)]),
  );
  return {
    headerComments: leadingComments(text),
    taxonomyDefaults,
    rules,
    categoryMap: deriveCategoryMap(rules, signatureIdsByAtrCategory(packDir)),
  };
}

export interface V2Rule {
  readonly category: string;
  readonly taxonomy?: string;
}

/**
 * Scanner category and taxonomy selection for every emitted signature.
 * `overrides` is keyed by ATR id (ATR-2026-02662) and wins over both the
 * vendored selection and the category default.
 */
export function resolveV2Rules(
  files: readonly SignatureFile[],
  downstream: DownstreamPack,
  overrides: ReadonlyMap<string, string>,
): Map<string, V2Rule> {
  const resolved = new Map<string, V2Rule>();
  const unmapped: string[] = [];
  for (const file of files) {
    for (const signature of file.signatures) {
      const vendored = downstream.rules.get(signature.id);
      const category =
        vendored?.category ?? downstream.categoryMap.get(signature.category);
      if (!category)
        throw new Error(
          `no scanner category for ATR category ${signature.category}`,
        );
      const taxonomy = overrides.get(signature.atr_id) ?? vendored?.taxonomy;
      if (
        taxonomy === undefined &&
        downstream.taxonomyDefaults[category] === undefined
      ) {
        unmapped.push(`${signature.atr_id} (${category})`);
      }
      resolved.set(signature.id, {
        category,
        ...(taxonomy === undefined ? {} : { taxonomy }),
      });
    }
  }
  if (unmapped.length > 0) {
    throw new Error(
      `these rules have no taxonomy and their scanner category has no default; ` +
        `pass --taxonomy <ATR id>=<code> for each: ${unmapped.join(", ")}`,
    );
  }
  return resolved;
}

/** Signatures with the scanner's category and without the fields it rejects. */
export function toV2SignatureFiles(
  files: readonly SignatureFile[],
  resolved: ReadonlyMap<string, V2Rule>,
): SignatureFile[] {
  return files.map((file) => ({
    ...file,
    signatures: file.signatures.map((signature): CiscoSignature => {
      const { maturity: _maturity, ...rest } = signature;
      return {
        ...rest,
        category: resolved.get(signature.id)?.category ?? signature.category,
      };
    }),
  }));
}

export function packDescriptionV2(total: number, categories: number): string {
  return (
    "Open-source AI agent security detection rules from the Agent Threat Rules (ATR) project. " +
    `${total} supported static rules across ${categories} attack categories: prompt injection, ` +
    "agent manipulation, skill compromise, context exfiltration, tool poisoning, privilege " +
    "escalation, model abuse, excessive autonomy, data poisoning, and model security. " +
    "Benchmark results are published upstream in the ATR benchmark table, version-pinned per " +
    "measurement; see the pack README for the figures that apply to this ruleset and their " +
    "caveats. MIT license."
  );
}

export function renderPackManifestV2(
  files: readonly SignatureFile[],
  resolved: ReadonlyMap<string, V2Rule>,
  downstream: DownstreamPack,
  version: string,
): string {
  const total = files.reduce((sum, file) => sum + file.signatures.length, 0);
  const rules: Record<string, YamlValue> = {};
  for (const file of files) {
    for (const signature of file.signatures) {
      const rule = resolved.get(signature.id);
      if (!rule) throw new Error(`no resolved category for ${signature.id}`);
      rules[signature.id] = {
        source: "signature",
        category: rule.category,
        ...(rule.taxonomy === undefined ? {} : { taxonomy: rule.taxonomy }),
        severity: signature.severity,
        knobs: { enabled: true },
        description: signature.description,
      };
    }
  }
  const header = downstream.headerComments.trimEnd();
  return (
    (header ? `${header}\n` : "") +
    emitYaml({
      schema_version: 2,
      name: "atr",
      version,
      description: packDescriptionV2(total, files.length),
      taxonomy_defaults: { ...downstream.taxonomyDefaults },
      rules,
    })
  );
}

/** "ATR-2026-02662=AISubtech-6.1.1" -> ["ATR-2026-02662", "AISubtech-6.1.1"]. */
export function parseTaxonomyOverride(value: string): [string, string] {
  const match = /^(ATR-\d{4}-\d{5})=(\S+)$/.exec(value);
  if (!match)
    throw new Error(`--taxonomy expects <ATR id>=<code>, got ${value}`);
  return [match[1] as string, match[2] as string];
}
