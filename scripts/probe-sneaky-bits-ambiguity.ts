#!/usr/bin/env npx tsx
/**
 * probe-sneaky-bits-ambiguity.ts — evidence for the one claim in
 * scripts/lib/carrier-decode.ts that cannot be read off the source: garak's
 * sneaky-bits encoding does not have a unique decoding.
 *
 * `sneaky_bits_smuggling` (garak/resources/smuggling/smuggle_ascii.py:50-72)
 * writes `bin(ord(ch)).removeprefix("0b")`, which is 6 bits for U+0020-U+003F
 * and 7 bits for U+0040-U+007E, with no separator and no length prefix. The
 * resulting stream can be read as several different printable-ASCII strings.
 *
 * This prints how many, per seed, so "we do not decode it because we cannot
 * know which reading is the payload" is a measurement rather than an opinion.
 *
 * Usage: npx tsx scripts/probe-sneaky-bits-ambiguity.ts
 * Exit codes: 0 always (diagnostic).
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { smuggleSneakyBits } from "./lib/garak-transforms-encoding.js";
import { sneakyBitsParseCount } from "./lib/carrier-decode.js";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CORPUS = resolve(REPO_ROOT, "data/test-corpora/garak-full");

const load = (file: string): readonly string[] =>
  JSON.parse(readFileSync(resolve(CORPUS, file), "utf-8")).prompts as string[];

const seeds: readonly { readonly corpus: string; readonly text: string }[] = [
  ...load("badchars.json").map((text) => ({
    corpus: "harmful_behaviors",
    text,
  })),
  ...load("encoding.json").map((text) => ({
    corpus: "encoding_payloads",
    text,
  })),
];

let unique = 0;
let ambiguous = 0;
let worst = { text: "", parses: 0 };

for (const seed of seeds) {
  const parses = sneakyBitsParseCount(smuggleSneakyBits(seed.text));
  if (parses === 1) unique++;
  else ambiguous++;
  if (parses > worst.parses) worst = { text: seed.text, parses };
}

console.log(`[sneaky] seeds measured: ${seeds.length}`);
console.log(`[sneaky] uniquely decodable: ${unique}`);
console.log(
  `[sneaky] ambiguous (>1 valid printable-ASCII reading): ${ambiguous}`,
);
console.log(
  `[sneaky] worst: ${worst.parses} readings (capped at 1000 per segment) for ${JSON.stringify(worst.text.slice(0, 60))}`,
);
console.log(
  "[sneaky] conclusion: a normalization decode cannot reverse this carrier without guessing; " +
    "detection has to key on the carrier code points U+2062 / U+2064 instead.",
);
