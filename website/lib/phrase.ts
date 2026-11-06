// Chinese line breaking.
//
// Browsers may break Chinese text between any two characters, so a narrow
// column splits words: 開放標準 becomes 開放標 / 準. We split each run of text
// into words with the ICU word segmenter at build time and only allow line
// breaks between words. The rules below fix what the segmenter alone gets
// wrong for reading:
//   - closing punctuation stays on the word before it, opening punctuation
//     and one-character words that lead a phrase (這, 每, 都, 把...) stay on
//     the word after it;
//   - the last short clause of a block stays on one line, so a paragraph does
//     not end on one or two lone characters;
//   - a run of ASCII with no space inside (INC., 66.0%, an email address, a
//     date such as 2026-04-13) stays whole, up to MAX_ASCII_RUN characters.
// Run this on the server only: browser ICU versions may segment differently,
// and the client would then disagree with the server-rendered HTML.

const CJK = /[\u3400-\u9fff\uf900-\ufaff]/;
const CLOSE = /^[，。、：；！？」』）》〉…—]+$/;
const OPEN = /^[「『（《〈]+$/;
const PREFIX = /^[這那每各逐第該本此都也就才還又再被把讓給]$/;
const CLAUSE_END = /[，。、：；！？·]$/;
const MAX_TAIL = 10;
const MIN_TAIL = 4;
const MAX_ASCII_RUN = 40;
const ASCII_TAIL = /[\x21-\x7e]+$/;
const ASCII_HEAD = /^[\x21-\x7e]+/;
const PUNCT_OR_SPACE = /[\s，。、：；！？「」『』（）《》〈〉…—·]/g;

let segmenter: Intl.Segmenter | null = null;

function words(text: string): string[] {
  segmenter ??= new Intl.Segmenter("zh-Hant", { granularity: "word" });
  const out: string[] = [];
  let carry = "";
  for (const { segment } of segmenter.segment(text)) {
    if (OPEN.test(segment) || PREFIX.test(segment)) {
      carry += segment;
    } else if (CLOSE.test(segment) && out.length > 0 && !carry) {
      out[out.length - 1] += segment;
    } else {
      out.push(carry + segment);
      carry = "";
    }
  }
  return joinAscii(carry ? [...out, carry] : out);
}

// The segmenter splits ASCII at every symbol (INC | . , 2026 | - | 04), and a
// line may break at each of those cuts. Join pieces that meet between two
// non-space ASCII characters while the joined run stays short.
function joinAscii(ws: string[]): string[] {
  return ws.reduce<string[]>((acc, w) => {
    const prev = acc[acc.length - 1];
    const tail = prev?.match(ASCII_TAIL)?.[0].length ?? 0;
    const head = w.match(ASCII_HEAD)?.[0].length ?? 0;
    if (tail > 0 && head > 0 && tail + head <= MAX_ASCII_RUN) {
      return [...acc.slice(0, -1), prev + w];
    }
    return [...acc, w];
  }, []);
}

export function hasChinese(text: string): boolean {
  return CJK.test(text);
}

/**
 * Splits text into the pieces a line may break between. The last piece is
 * the final clause (or the last two words) and must not break inside.
 */
export function phrases(text: string): string[] {
  const ws = words(text);
  // Word indices that are not plain spaces: the tail counts these only.
  const real = ws.flatMap((w, i) => (w.trim() ? [i] : []));
  if (real.length <= 3) return [ws.join("")];
  const lastTwo = real[real.length - 2];
  let cut = lastTwo;
  for (let k = real.length - 2; k > 0; k--) {
    if (CLAUSE_END.test(ws[real[k]].trim())) {
      cut = real[k] + 1;
      break;
    }
  }
  if (ws.slice(cut).join("").trim().length > MAX_TAIL) cut = lastTwo;
  // The segmenter sometimes splits a word into single characters (載 / 入),
  // so also make sure the tail carries at least MIN_TAIL characters.
  const letters = (from: number) => ws.slice(from).join("").replace(PUNCT_OR_SPACE, "").length;
  for (let k = real.indexOf(cut); k > 1 && letters(cut) < MIN_TAIL; k--) cut = real[k - 1];
  return [...ws.slice(0, cut), ws.slice(cut).join("")];
}

const RAW_TAGS = /^<\/?(code|pre|kbd|samp|script|style)\b/i;
const ENTITY = /&#?[a-zA-Z0-9]+;/g;
const PLACEHOLDER_BASE = 0xe000;

/**
 * The same line breaking for prose that a page injects as an HTML string.
 * Only text between tags changes; text inside code, pre, kbd, samp, script
 * and style is left alone, and HTML entities (&lt; &amp; ...) stay whole.
 */
export function phraseHtml(html: string): string {
  let raw = 0;
  return html
    .split(/(<[^>]+>)/)
    .map((part) => {
      if (part.startsWith("<")) {
        if (RAW_TAGS.test(part)) raw += part.startsWith("</") ? -1 : 1;
        return part;
      }
      if (raw > 0 || !hasChinese(part)) return part;
      const entities: string[] = [];
      const masked = part.replace(ENTITY, (e) => String.fromCharCode(PLACEHOLDER_BASE + entities.push(e) - 1));
      const restore = (s: string) => s.replace(/[-]/g, (c) => entities[c.charCodeAt(0) - PLACEHOLDER_BASE] ?? c);
      const pieces = phrases(masked).map(restore);
      const last = pieces.length - 1;
      const body = pieces
        .map((p, i) => (i === last && i > 0 && p.trim().length <= 14 ? `<span class="whitespace-nowrap">${p}</span>` : p))
        .join("<wbr>");
      return `<span class="phr">${body}</span>`;
    })
    .join("");
}
