/**
 * adopters-evidence.mjs — the links in an ADOPTERS.md Evidence field, read
 * the same way by every script that reads them (scripts/verify-adopters.mjs,
 * which checks them, and scripts/lib/status-claims.mjs, which exempts what it
 * checks). Standard library only.
 */

/** First canonical URL out of an Evidence value (mirrors website/lib/adopters.ts). */
export function firstUrl(evidence) {
  const angle = evidence.match(/<(https?:\/\/[^>\s]+)>/);
  if (angle) return angle[1];
  const link = evidence.match(/^\[.*?\]\((.+?)\)/);
  if (link) return link[1];
  const bare = evidence.match(/https?:\/\/[^\s>)]+/);
  return bare ? bare[0] : undefined;
}

/** Every URL in an Evidence value, in order, once: <angle> links, [markdown](links) and bare URLs. */
export function evidenceUrls(evidence) {
  const found = [...evidence.matchAll(/<(https?:\/\/[^>\s]+)>|\]\((https?:\/\/[^)\s]+)\)|(https?:\/\/[^\s>)\]]+)/g)]
    .map((m) => (m[1] ?? m[2] ?? m[3]).replace(/[.,;:]+$/, ''));
  return [...new Set(found)];
}
