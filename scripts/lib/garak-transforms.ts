/**
 * Registry of the garak obfuscations ATR has never actually been measured on.
 *
 * WHY THIS EXISTS
 *
 * data/test-corpora/garak-full/{badchars,malwaregen,sata,smuggling}.json are the
 * same 16 strings: sort the `prompts` array of each and every one hashes to
 * sha256 457c4b462d3a8d1e27161c9d... . Those 16 strings are garak's
 * `harmful_behaviors` PAYLOAD list — the input each probe obfuscates — not the
 * prompts any of those probes sends. `encoding.json` has the same problem: its
 * 36 entries are the `text_en` + `web_html_js` + `slur_terms_en` payload
 * libraries, never passed through an encoder. So every garak recall number ATR
 * has ever published for these four families was measured on plaintext.
 *
 * This module applies the transformations the probes actually perform, ported
 * from upstream with per-function line citations. See
 * garak-transforms-badchars.ts and garak-transforms-encoding.ts.
 *
 * DETERMINISM: every transform here is a pure function of its input. The two
 * places upstream uses `random` are documented as deviations at their
 * definitions (leetspeak's coin flip, the smuggling probe's per-character
 * choice); both are resolved to fixed branches so a measurement is repeatable.
 */
import {
  deletionVariants,
  homoglyphVariants,
  invisibleVariants,
  reorderingVariants,
} from "./garak-transforms-badchars.js";
import * as Enc from "./garak-transforms-encoding.js";

export type TransformFamily = "badchars" | "encoding" | "smuggling";

/**
 * `encoding` transforms produce one ciphertext that garak then wraps in each of
 * the five carrier templates (encoding.py:41-47). `perturbation` transforms
 * produce many variants that garak sends verbatim.
 */
export type TransformKind = "encoding" | "perturbation";

export interface GarakTransform {
  readonly id: string;
  readonly family: TransformFamily;
  readonly kind: TransformKind;
  /** `{encoding_name}` as garak substitutes it; empty for perturbations. */
  readonly encodingName: string;
  /** Upstream file and line range this reproduces. */
  readonly citation: string;
  readonly expand: (seed: string) => readonly string[];
}

const one =
  (fn: (s: string) => string) =>
  (seed: string): readonly string[] =>
    Object.freeze([fn(seed)]);

export const GARAK_TRANSFORMS: readonly GarakTransform[] = Object.freeze([
  // ---- badchars: imperceptible perturbation ------------------------------
  {
    id: "badchars-invisible",
    family: "badchars",
    kind: "perturbation",
    encodingName: "",
    citation: "garak/probes/badchars.py:22,244-258,323-330",
    expand: (seed) => invisibleVariants(seed),
  },
  {
    id: "badchars-homoglyph",
    family: "badchars",
    kind: "perturbation",
    encodingName: "",
    citation:
      "garak/probes/badchars.py:77-108,260-284 (UTS#39 intentional.txt)",
    expand: (seed) => homoglyphVariants(seed),
  },
  {
    id: "badchars-reordering",
    family: "badchars",
    kind: "perturbation",
    encodingName: "",
    citation: "garak/probes/badchars.py:23-30,41-74,286-301,332-344",
    expand: (seed) => reorderingVariants(seed),
  },
  {
    id: "badchars-deletion",
    family: "badchars",
    kind: "perturbation",
    encodingName: "",
    citation: "garak/probes/badchars.py:303-321,382-388",
    expand: (seed) => deletionVariants(seed),
  },

  // ---- encoding: ciphertext + carrier template ---------------------------
  {
    id: "encoding-base64",
    family: "encoding",
    kind: "encoding",
    encodingName: "BASE64",
    citation: "garak/probes/encoding.py:296-302",
    expand: one(Enc.injectBase64),
  },
  {
    id: "encoding-base64url",
    family: "encoding",
    kind: "encoding",
    encodingName: "BASE64",
    citation: "garak/probes/encoding.py:298",
    expand: one(Enc.injectBase64Url),
  },
  {
    id: "encoding-base16",
    family: "encoding",
    kind: "encoding",
    encodingName: "BASE16",
    citation: "garak/probes/encoding.py:310-318",
    expand: one(Enc.injectBase16),
  },
  {
    id: "encoding-base32",
    family: "encoding",
    kind: "encoding",
    encodingName: "BASE32",
    citation: "garak/probes/encoding.py:325-333",
    expand: one(Enc.injectBase32),
  },
  {
    id: "encoding-ascii85",
    family: "encoding",
    kind: "encoding",
    encodingName: "ASCII85",
    citation: "garak/probes/encoding.py:340-348",
    expand: one(Enc.injectAscii85),
  },
  {
    id: "encoding-hex",
    family: "encoding",
    kind: "encoding",
    encodingName: "hex",
    citation: "garak/probes/encoding.py:355-363",
    expand: one(Enc.injectHex),
  },
  {
    id: "encoding-uu",
    family: "encoding",
    kind: "encoding",
    encodingName: "UUencode",
    citation: "garak/probes/encoding.py:387-408",
    expand: one(Enc.injectUU),
  },
  {
    id: "encoding-rot13",
    family: "encoding",
    kind: "encoding",
    encodingName: "ROT13",
    citation: "garak/probes/encoding.py:50-57,428-441",
    expand: one(Enc.injectRot13),
  },
  {
    id: "encoding-atbash",
    family: "encoding",
    kind: "encoding",
    encodingName: "Atbash",
    citation: "garak/probes/encoding.py:477-508",
    expand: one(Enc.injectAtbash),
  },
  {
    id: "encoding-morse",
    family: "encoding",
    kind: "encoding",
    encodingName: "Morse",
    citation: "garak/probes/encoding.py:141-189,511-524",
    expand: one(Enc.injectMorse),
  },
  {
    id: "encoding-nato",
    family: "encoding",
    kind: "encoding",
    encodingName: "Nato",
    citation: "garak/probes/encoding.py:527-577",
    expand: one(Enc.injectNato),
  },
  {
    id: "encoding-braille",
    family: "encoding",
    kind: "encoding",
    encodingName: "Braille",
    citation: "garak/probes/encoding.py:60-138,461-474",
    expand: one(Enc.injectBraille),
  },
  {
    id: "encoding-leetspeak",
    family: "encoding",
    kind: "encoding",
    encodingName: "Leetspeak",
    citation: "garak/resources/encodings.py:12-22 via encoding.py:635-652",
    expand: one(Enc.injectLeet),
  },

  // ---- smuggling: invisible carriers -------------------------------------
  {
    id: "smuggling-unicode-tags",
    family: "smuggling",
    kind: "encoding",
    encodingName: "ASCII in Unicode Tags",
    citation:
      "garak/resources/smuggling/smuggle_ascii.py:15-30 via encoding.py:655-682",
    expand: one((s) => Enc.smuggleUnicodeTags(s)),
  },
  {
    id: "smuggling-variant-selectors",
    family: "smuggling",
    kind: "encoding",
    encodingName: "ASCII in Unicode Variant Selector",
    citation:
      "garak/resources/smuggling/smuggle_ascii.py:33-47 via encoding.py:685-704",
    expand: one(Enc.smuggleVariantSelectors),
  },
  {
    id: "smuggling-sneaky-bits",
    family: "smuggling",
    kind: "encoding",
    encodingName: "ASCII in hidden unicode binary encoding",
    citation:
      "garak/resources/smuggling/smuggle_ascii.py:50-72 via encoding.py:707-728",
    expand: one(Enc.smuggleSneakyBits),
  },
  {
    id: "smuggling-homoglyph",
    family: "smuggling",
    kind: "perturbation",
    encodingName: "",
    citation: "garak/probes/smuggling.py:29-67,98-160",
    expand: (seed) => Enc.smuggleHomoglyphVariants(seed),
  },
]);

/** Lookup by id; throws rather than returning undefined so callers cannot skip silently. */
export function transformById(id: string): GarakTransform {
  const found = GARAK_TRANSFORMS.find((t) => t.id === id);
  if (!found) throw new Error(`unknown garak transform: ${id}`);
  return found;
}

/**
 * Transformations upstream ships that this port does NOT implement, and why.
 * Reported by the CLI so a reader never mistakes "absent" for "measured clean".
 */
export const UNPORTED_TRANSFORMS: Readonly<Record<string, string>> =
  Object.freeze({
    "encoding-base2048":
      "encoding.py:444-458 requires the third-party `base2048` package; no pure-TS equivalent vendored",
    "encoding-ecoji":
      "encoding.py:580-606 requires the third-party `ecoji` package",
    "encoding-zalgo":
      "encoding.py:609-632 requires `zalgolib`, and its output is randomised per call",
    "encoding-base85":
      "encoding.py:346 lists base64.b85encode alongside a85encode; only a85 is ported (same family, different alphabet)",
    "encoding-qp-mime":
      "encoding.py:370-384 and :411-425 are marked active = False upstream — quoted-printable passes ASCII straight through",
  });
