/**
 * Homoglyph map used by garak's BadCharacters probe.
 *
 * PROVENANCE — this is not invented. garak/probes/badchars.py:77-108
 * (`_load_homoglyph_map`) parses `garak/data/badchars/intentional.txt`, which is
 * a verbatim copy of the Unicode Consortium's UTS #39 confusable-intentional
 * table (https://www.unicode.org/Public/security/latest/intentional.txt,
 * version 17.0.0, dated 2025-07-22). The parser reads `SOURCE ; TARGET…` lines,
 * skips comments, and drops entries where source === target.
 *
 * The table below is that parse applied to the copy vendored in garak at commit
 * 7ff1f2778e4d6ca6dc25ba8e17d8dfa520003ee0 — 76 source code points. Keys are
 * source characters; values are the replacement candidates, sorted, exactly as
 * `_load_homoglyph_map` returns them.
 *
 * Regenerate with scripts/lib/garak-homoglyphs.regen.md.
 */
export const GARAK_HOMOGLYPH_MAP: Readonly<Record<string, readonly string[]>> =
  Object.freeze({
    "!": ["ǃ"],
    A: ["Α"],
    B: ["Β"],
    C: ["С"],
    E: ["Ε"],
    H: ["Η"],
    I: ["Ι"],
    J: ["Ј"],
    K: ["Κ"],
    M: ["Μ"],
    N: ["Ν"],
    O: ["Ο"],
    P: ["Ρ"],
    S: ["Ѕ"],
    T: ["Τ"],
    X: ["Χ"],
    Y: ["Υ"],
    Z: ["Ζ"],
    a: ["а"],
    c: ["с"],
    d: ["ԁ"],
    e: ["е"],
    h: ["һ"],
    i: ["і"],
    j: ["ϳ"],
    o: ["ο"],
    p: ["р"],
    s: ["ѕ"],
    x: ["х"],
    y: ["у"],
    Æ: ["Ӕ"],
    Ð: ["Đ"],
    æ: ["ӕ"],
    ĸ: ["к"],
    Ƃ: ["Б"],
    Ə: ["Ә"],
    Ɵ: ["Ө"],
    Ʃ: ["Σ"],
    ǝ: ["ə"],
    Ʌ: ["Λ"],
    ə: ["ә"],
    ɛ: ["ε"],
    ɩ: ["ι"],
    ɵ: ["ө"],
    ʒ: ["ӡ"],
    ʙ: ["в"],
    ʜ: ["н"],
    Γ: ["Г"],
    Π: ["П"],
    α: ["⍺"],
    ι: ["⍳"],
    ρ: ["⍴"],
    ω: ["⍵"],
    г: ["ᴦ"],
    л: ["ᴫ"],
    п: ["ᴨ"],
    ဝ: ["၀"],
    អ: ["ឣ"],
    ᠵ: ["ᡕ"],
    ᦞ: ["᧐"],
    ᦱ: ["᧑"],
    ᩅ: ["᪀", "᪐"],
    ᬍ: ["᭒"],
    ᬑ: ["᭓"],
    ᬨ: ["᭘"],
    "᭐": ["᭜"],
    ᴍ: ["м"],
    ᴘ: ["ᴩ"],
    ᴛ: ["т"],
    Ⱨ: ["Ң"],
    Ⱪ: ["Қ"],
    "꧐": ["꧆"],
    "\u{10382}": ["\u{103D1}"],
    "\u{10393}": ["\u{103D3}"],
    "\u{1039A}": ["\u{12038}"],
    "\u{10486}": ["\u{104A0}"],
  });

/**
 * The much narrower Latin→Cyrillic map used by garak's token-smuggling probe,
 * `garak/probes/smuggling.py:29-50` (`DEFAULT_HOMOGLYPH_MAP`). Copied verbatim,
 * including the two options for lowercase `i`.
 *
 * Kept separate from GARAK_HOMOGLYPH_MAP on purpose: the two probes disagree
 * about which glyphs are worth swapping, and collapsing them would hide that.
 */
export const GARAK_SMUGGLING_HOMOGLYPH_MAP: Readonly<
  Record<string, readonly string[]>
> = Object.freeze({
  a: ["а"],
  c: ["с"],
  e: ["е"],
  i: ["і", "ı"],
  o: ["о"],
  p: ["р"],
  s: ["ѕ"],
  x: ["х"],
  y: ["у"],
  A: ["А"],
  B: ["В"],
  C: ["С"],
  E: ["Е"],
  H: ["Н"],
  K: ["К"],
  M: ["М"],
  O: ["О"],
  P: ["Р"],
  T: ["Т"],
  X: ["Х"],
});
