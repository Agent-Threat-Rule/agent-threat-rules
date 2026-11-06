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
//     not end on one or two lone characters.
// Run this on the server only: browser ICU versions may segment differently,
// and the client would then disagree with the server-rendered HTML.

const CJK = /[\u3400-\u9fff\uf900-\ufaff]/;
const CLOSE = /^[，。、：；！？」』）》〉…—]+$/;
const OPEN = /^[「『（《〈]+$/;
const PREFIX = /^[這那每各逐第該本此都也就才還又再被把讓給]$/;
const CLAUSE_END = /[，。、：；！？]$/;
const MAX_TAIL = 10;

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
  return carry ? [...out, carry] : out;
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
  if (ws.length <= 3) return [ws.join("")];
  let cut = ws.length - 2;
  for (let i = ws.length - 2; i > 0; i--) {
    if (CLAUSE_END.test(ws[i])) {
      cut = i + 1;
      break;
    }
  }
  if (ws.slice(cut).join("").length > MAX_TAIL) cut = ws.length - 2;
  return [...ws.slice(0, cut), ws.slice(cut).join("")];
}
