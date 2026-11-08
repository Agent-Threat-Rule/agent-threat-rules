/**
 * Tests for the schema_version 2 output of the Cisco Skill Scanner pack
 * exporter (scripts/cisco-pack/downstream-v2.ts).
 *
 * The scanner's maintainers map ATR's categories onto their own threat
 * categories and pick a Cisco AI taxonomy code per rule. These tests pin the
 * contract that a refresh carries those choices forward unchanged, maps a new
 * rule only through a mapping the vendored pack already makes, and stops
 * rather than guessing when it cannot.
 */

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import yaml from "js-yaml";
import { describe, expect, it } from "vitest";
import {
  parseTaxonomyOverride,
  readDownstreamPack,
  renderPackManifestV2,
  resolveV2Rules,
  toV2SignatureFiles,
} from "../scripts/cisco-pack/downstream-v2.js";
import type {
  CiscoSignature,
  SignatureFile,
} from "../scripts/cisco-pack/transform.js";

const MANIFEST = `# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

schema_version: 2
name: atr
version: 3.5.6
description: old
taxonomy_defaults:
  social_engineering: AISubtech-1.1.5
rules:
  ATR_2026_00030:
    source: signature
    category: social_engineering
    taxonomy: AISubtech-1.1.3
    severity: CRITICAL
    knobs:
      enabled: true
    description: kept
  ATR_2026_00031:
    source: signature
    category: social_engineering
    severity: HIGH
    knobs:
      enabled: true
    description: inherits
  ATR_2026_00072:
    source: signature
    category: policy_violation
    taxonomy: AISubtech-10.1.1
    severity: CRITICAL
    knobs:
      enabled: true
    description: no default for this category
`;

function downstreamDir(manifest = MANIFEST): string {
  const dir = mkdtempSync(join(tmpdir(), "cisco-v2-"));
  mkdirSync(join(dir, "signatures"));
  writeFileSync(join(dir, "pack.yaml"), manifest);
  writeFileSync(
    join(dir, "signatures", "atr_agent_manipulation.yaml"),
    "signatures:\n  - id: ATR_2026_00030\n  - id: ATR_2026_00031\n",
  );
  writeFileSync(
    join(dir, "signatures", "atr_model_security.yaml"),
    "signatures:\n  - id: ATR_2026_00072\n",
  );
  return dir;
}

function signature(atrId: string, category: string): CiscoSignature {
  return {
    id: atrId.replace(/-/g, "_"),
    atr_id: atrId,
    atr_url: `https://example.test/${atrId}.yaml`,
    category,
    severity: "HIGH",
    maturity: "test",
    patterns: ["(?i)abc"],
    file_types: ["markdown"],
    description: `description of ${atrId}`,
    remediation: "",
  };
}

function file(category: string, ids: readonly string[]): SignatureFile {
  return {
    category: category.replace(/_/g, "-"),
    path: `signatures/atr_${category}.yaml`,
    signatures: ids.map((id) => signature(id, category)),
  };
}

describe("readDownstreamPack", () => {
  it("derives the ATR -> scanner category map from the vendored signature files", () => {
    const pack = readDownstreamPack(downstreamDir());
    expect(Object.fromEntries(pack.categoryMap)).toEqual({
      agent_manipulation: "social_engineering",
      model_security: "policy_violation",
    });
    expect(pack.headerComments).toContain("Copyright 2026 Cisco Systems, Inc.");
  });

  it("refuses a pack that is not schema_version 2", () => {
    expect(() =>
      readDownstreamPack(
        downstreamDir(
          MANIFEST.replace("schema_version: 2", "schema_version: 1"),
        ),
      ),
    ).toThrow(/schema_version 1, expected 2/);
  });

  it("refuses to guess when one ATR category maps to two scanner categories", () => {
    const split = MANIFEST.replace(
      "category: social_engineering\n    severity: HIGH",
      "category: prompt_injection\n    severity: HIGH",
    );
    expect(() => readDownstreamPack(downstreamDir(split))).toThrow(
      /agent_manipulation to 2 scanner categories/,
    );
  });
});

describe("resolveV2Rules", () => {
  const pack = readDownstreamPack(downstreamDir());

  it("carries vendored categories and taxonomy codes forward and lets a new rule inherit the default", () => {
    const resolved = resolveV2Rules(
      [
        file("agent_manipulation", [
          "ATR-2026-00030",
          "ATR-2026-00031",
          "ATR-2026-09999",
        ]),
      ],
      pack,
      new Map(),
    );
    expect(resolved.get("ATR_2026_00030")).toEqual({
      category: "social_engineering",
      taxonomy: "AISubtech-1.1.3",
    });
    expect(resolved.get("ATR_2026_00031")).toEqual({
      category: "social_engineering",
    });
    expect(resolved.get("ATR_2026_09999")).toEqual({
      category: "social_engineering",
    });
  });

  it("stops on a new rule whose scanner category has no default code", () => {
    expect(() =>
      resolveV2Rules(
        [file("model_security", ["ATR-2026-02662"])],
        pack,
        new Map(),
      ),
    ).toThrow(/ATR-2026-02662 \(policy_violation\)/);
  });

  it("accepts an explicit --taxonomy for that rule", () => {
    const resolved = resolveV2Rules(
      [file("model_security", ["ATR-2026-02662"])],
      pack,
      new Map([parseTaxonomyOverride("ATR-2026-02662=AISubtech-9.1.1")]),
    );
    expect(resolved.get("ATR_2026_02662")).toEqual({
      category: "policy_violation",
      taxonomy: "AISubtech-9.1.1",
    });
  });
});

describe("schema_version 2 output", () => {
  const pack = readDownstreamPack(downstreamDir());
  const atrFiles = [
    file("agent_manipulation", ["ATR-2026-00030", "ATR-2026-09999"]),
  ];
  const resolved = resolveV2Rules(atrFiles, pack, new Map());
  const files = toV2SignatureFiles(atrFiles, resolved);

  it("writes only the manifest fields the scanner accepts", () => {
    const manifest = yaml.load(
      renderPackManifestV2(files, resolved, pack, "4.2.2"),
    ) as Record<string, unknown>;
    expect(Object.keys(manifest)).toEqual([
      "schema_version",
      "name",
      "version",
      "description",
      "taxonomy_defaults",
      "rules",
    ]);
    expect(manifest.schema_version).toBe(2);
    const rules = manifest.rules as Record<string, Record<string, unknown>>;
    expect(Object.keys(rules.ATR_2026_00030 ?? {})).toEqual([
      "source",
      "category",
      "taxonomy",
      "severity",
      "knobs",
      "description",
    ]);
    expect(Object.keys(rules.ATR_2026_09999 ?? {})).toEqual([
      "source",
      "category",
      "severity",
      "knobs",
      "description",
    ]);
  });

  it("keeps the vendored header and states no benchmark figure in the description", () => {
    const text = renderPackManifestV2(files, resolved, pack, "4.2.2");
    expect(text.startsWith("# Copyright 2026 Cisco Systems, Inc.")).toBe(true);
    const description = String(
      (yaml.load(text) as { description: string }).description,
    );
    expect(description).toContain("2 supported static rules");
    expect(description).not.toMatch(/\d+(?:\.\d+)?%/);
  });

  it("gives signatures the scanner category and drops maturity without mutating the input", () => {
    const [converted] = files[0]?.signatures ?? [];
    expect(converted?.category).toBe("social_engineering");
    expect(converted).not.toHaveProperty("maturity");
    expect(atrFiles[0]?.signatures[0]?.category).toBe("agent_manipulation");
    expect(atrFiles[0]?.signatures[0]?.maturity).toBe("test");
  });

  it("rejects a malformed --taxonomy value", () => {
    expect(() => parseTaxonomyOverride("ATR-2026-02662")).toThrow(
      /expects <ATR id>=<code>/,
    );
  });
});
