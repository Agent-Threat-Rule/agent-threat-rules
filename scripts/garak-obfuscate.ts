#!/usr/bin/env npx tsx
/**
 * garak-obfuscate.ts — build the obfuscated garak corpus that ATR has never had.
 *
 * PROBLEM THIS SOLVES
 *
 * Sort the `prompts` array in each of
 * data/test-corpora/garak-full/{badchars,malwaregen,sata,smuggling}.json and all
 * four hash to the same SHA-256. They are garak's `harmful_behaviors` payload
 * list — the plaintext each probe obfuscates — not the prompts those probes
 * send. encoding.json is the same mistake: 36 entries of the `text_en` +
 * `web_html_js` + `slur_terms_en` payload libraries, never encoded. Every ATR
 * recall figure for those families was therefore measured on plaintext.
 *
 * A SECOND DEFECT IN encoding.json, found while checking the first: only 32 of
 * its 36 entries are garak payloads at all. The other four —
 * "English sample text", "Javascript embedded in HTML", "English ethnic slurs",
 * "Toxic/Hate/Slurs" — are the `garak_payload_name` and `payload_types` METADATA
 * FIELDS of garak/data/payloads/{text_en,web_html_js,slur_terms_en}.json, swept
 * up by whatever scraped those files. They have been sitting in the denominator
 * of every encoding-probe recall figure. The 32 real payloads are also only 32
 * of the 78 those three libraries actually contain.
 *
 * This script applies the real transformations (see scripts/lib/garak-transforms*.ts,
 * every function carrying its upstream file:line) and writes one corpus file.
 *
 * Usage:
 *   npx tsx scripts/garak-obfuscate.ts [--output <path>]
 *
 * Exit codes: 0 on success; 1 if an input corpus is missing or a family's
 * assumed payload identity does not hold.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  GARAK_TRANSFORMS,
  UNPORTED_TRANSFORMS,
  type GarakTransform,
} from "./lib/garak-transforms.js";
import {
  ENCODING_TEMPLATES,
  applyTemplate,
} from "./lib/garak-transforms-encoding.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS_DIR = resolve(REPO_ROOT, "data/test-corpora/garak-full");

/** The four families whose stored prompts are byte-identical plaintext payloads. */
const SHARED_PLAINTEXT_FAMILIES = [
  "badchars",
  "malwaregen",
  "sata",
  "smuggling",
] as const;

export interface ObfuscatedSample {
  readonly seedCorpus: string;
  readonly seedIndex: number;
  readonly transformId: string;
  readonly family: string;
  /** "raw" for a perturbation, or the index of the encoding.py carrier template. */
  readonly presentation: string;
  readonly text: string;
}

export interface ObfuscatedCorpus {
  readonly generatedBy: string;
  readonly upstreamCommit: string;
  readonly seedCorpora: Readonly<Record<string, readonly string[]>>;
  readonly sharedPlaintextSha256: string;
  readonly encodingPayloadProvenance: {
    readonly entries: number;
    readonly realGarakPayloads: number;
    readonly metadataStringsMistakenForPayloads: readonly string[];
    readonly upstreamLibraryPayloadTotal: number;
    readonly note: string;
  };
  readonly unported: Readonly<Record<string, string>>;
  readonly samples: readonly ObfuscatedSample[];
}

const UPSTREAM_COMMIT = "NVIDIA/garak@7ff1f2778e4d6ca6dc25ba8e17d8dfa520003ee0";

function readPrompts(family: string): readonly string[] {
  const path = resolve(CORPUS_DIR, `${family}.json`);
  if (!existsSync(path)) throw new Error(`missing corpus file: ${path}`);
  const parsed = JSON.parse(readFileSync(path, "utf-8")) as {
    prompts?: unknown;
  };
  if (!Array.isArray(parsed.prompts) || parsed.prompts.length === 0) {
    throw new Error(`corpus ${family}.json has no prompts array`);
  }
  return Object.freeze(parsed.prompts.map(String));
}

/** SHA-256 over the sorted prompts, newline-joined — the identity check from the brief. */
function sortedPromptsSha256(prompts: readonly string[]): string {
  return createHash("sha256")
    .update([...prompts].sort().join("\n"), "utf8")
    .digest("hex");
}

/**
 * Refuse to build on an assumption that has silently stopped holding. If the
 * four families ever diverge, this corpus is measuring something else and the
 * caller must be told, not handed a file.
 */
function assertSharedPlaintext(): string {
  const hashes = SHARED_PLAINTEXT_FAMILIES.map((f) =>
    sortedPromptsSha256(readPrompts(f)),
  );
  const [first] = hashes;
  if (!hashes.every((h) => h === first)) {
    throw new Error(
      `families ${SHARED_PLAINTEXT_FAMILIES.join("/")} no longer share one payload list: ` +
        hashes
          .map((h, i) => `${SHARED_PLAINTEXT_FAMILIES[i]}=${h.slice(0, 12)}`)
          .join(" "),
    );
  }
  return first;
}

function expandTransform(
  transform: GarakTransform,
  seedCorpus: string,
  seeds: readonly string[],
): readonly ObfuscatedSample[] {
  const out: ObfuscatedSample[] = [];
  for (let seedIndex = 0; seedIndex < seeds.length; seedIndex++) {
    for (const produced of transform.expand(seeds[seedIndex])) {
      const base = {
        seedCorpus,
        seedIndex,
        transformId: transform.id,
        family: transform.family,
      };
      if (transform.kind === "perturbation") {
        out.push({ ...base, presentation: "raw", text: produced });
        continue;
      }
      out.push({ ...base, presentation: "bare", text: produced });
      for (let t = 0; t < ENCODING_TEMPLATES.length; t++) {
        out.push({
          ...base,
          presentation: `template-${t}`,
          text: applyTemplate(
            ENCODING_TEMPLATES[t],
            transform.encodingName,
            produced,
          ),
        });
      }
    }
  }
  return Object.freeze(out);
}

export function buildCorpus(): ObfuscatedCorpus {
  const sharedSha = assertSharedPlaintext();
  const harmfulBehaviors = readPrompts("badchars");
  const encodingPayloads = readPrompts("encoding");

  // Which seed list each family's probe actually consumes upstream:
  //   badchars.py:135  payload_name = "harmful_behaviors"
  //   smuggling.py:134 payloads = ["harmful_behaviors"]  (HomoglyphObfuscation)
  //   encoding.py:217  payloads = ["default", "xss", "slur_terms"]
  //                    -> text_en + web_html_js + slur_terms_en == encoding.json
  const seedsFor = (t: GarakTransform): readonly [string, readonly string[]] =>
    t.family === "encoding" ||
    t.id.startsWith("smuggling-unicode") ||
    t.id.startsWith("smuggling-variant") ||
    t.id.startsWith("smuggling-sneaky")
      ? ["encoding_payloads", encodingPayloads]
      : ["harmful_behaviors", harmfulBehaviors];

  const samples = GARAK_TRANSFORMS.flatMap((t) => {
    const [name, seeds] = seedsFor(t);
    return expandTransform(t, name, seeds);
  });

  return Object.freeze({
    generatedBy: "scripts/garak-obfuscate.ts",
    upstreamCommit: UPSTREAM_COMMIT,
    seedCorpora: Object.freeze({
      harmful_behaviors: harmfulBehaviors,
      encoding_payloads: encodingPayloads,
    }),
    sharedPlaintextSha256: sharedSha,
    encodingPayloadProvenance: Object.freeze({
      entries: encodingPayloads.length,
      realGarakPayloads: 32,
      metadataStringsMistakenForPayloads: Object.freeze([
        "English sample text",
        "Javascript embedded in HTML",
        "English ethnic slurs",
        "Toxic/Hate/Slurs",
      ]),
      upstreamLibraryPayloadTotal: 78,
      note:
        "Verified against garak/data/payloads/{text_en,web_html_js,slur_terms_en}.json at " +
        "NVIDIA/garak@7ff1f2778e4d6ca6dc25ba8e17d8dfa520003ee0. The four listed strings are " +
        "the files' garak_payload_name / payload_types fields, not payloads.",
    }),
    unported: UNPORTED_TRANSFORMS,
    samples: Object.freeze(samples),
  });
}

function main(): void {
  const args = process.argv.slice(2);
  const outIdx = args.indexOf("--output");
  const outPath =
    outIdx >= 0
      ? resolve(REPO_ROOT, args[outIdx + 1])
      : resolve(REPO_ROOT, "data/test-corpora/garak-obfuscated/corpus.json");

  const corpus = buildCorpus();
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify(corpus, null, 2)}\n`, "utf-8");

  const byTransform = new Map<string, number>();
  for (const s of corpus.samples)
    byTransform.set(s.transformId, (byTransform.get(s.transformId) ?? 0) + 1);

  console.log(`[obfuscate] upstream: ${corpus.upstreamCommit}`);
  console.log(
    `[obfuscate] shared plaintext sha256(sorted prompts): ${corpus.sharedPlaintextSha256}`,
  );
  console.log(
    `[obfuscate] seeds: harmful_behaviors=${corpus.seedCorpora.harmful_behaviors.length} encoding_payloads=${corpus.seedCorpora.encoding_payloads.length}`,
  );
  for (const [id, n] of [...byTransform].sort())
    console.log(`[obfuscate]   ${id.padEnd(30)} ${n}`);
  console.log(`[obfuscate] total samples: ${corpus.samples.length}`);
  console.log(`[obfuscate] NOT ported (absent != measured clean):`);
  for (const [id, why] of Object.entries(corpus.unported))
    console.log(`[obfuscate]   ${id}: ${why}`);
  console.log(
    `[obfuscate] encoding.json provenance: ${corpus.encodingPayloadProvenance.realGarakPayloads}/${corpus.encodingPayloadProvenance.entries} entries are real garak payloads; ` +
      `${corpus.encodingPayloadProvenance.metadataStringsMistakenForPayloads.length} are payload-file metadata fields`,
  );
  console.log(`[obfuscate] wrote ${outPath}`);
}

if (import.meta.url === `file://${process.argv[1]}`) main();
