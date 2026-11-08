#!/usr/bin/env node
// Post-build check of the static export in out/: every /en and /zh page must
// carry a canonical URL that is its own address, hreflang alternates that
// point at the same page in each locale (English as x-default), an og:url
// equal to the canonical, and a title that does not repeat the site suffix.
//
// Run after `npm run build`:  node scripts/check-seo.mjs [outDir]
// Exits 1 and lists the pages that fail.

import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

const SITE_URL = "https://agentthreatrule.org";
const LOCALES = { en: "en", zh: "zh-Hant" };
const OUT_DIR = process.argv[2] ?? join(process.cwd(), "out");

function htmlFiles(dir) {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) return htmlFiles(full);
    return entry.endsWith(".html") ? [full] : [];
  });
}

function decode(s) {
  return s
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;|&#39;/g, "'");
}

function attrs(tag) {
  const out = {};
  for (const m of tag.matchAll(/([a-zA-Z:-]+)="([^"]*)"/g)) out[m[1].toLowerCase()] = decode(m[2]);
  return out;
}

/** Head metadata of one exported page. */
function readHead(html) {
  const links = [...html.matchAll(/<link\b[^>]*>/g)].map((m) => attrs(m[0]));
  const metas = [...html.matchAll(/<meta\b[^>]*>/g)].map((m) => attrs(m[0]));
  const title = decode(/<title>([^<]*)<\/title>/.exec(html)?.[1] ?? "");
  return {
    canonicals: links.filter((l) => l.rel === "canonical").map((l) => l.href),
    alternates: links.filter((l) => l.rel === "alternate" && l.hreflang),
    ogUrl: metas.find((m) => m.property === "og:url")?.content,
    title,
  };
}

/** "/en/spec" for out/en/spec.html, "/en" for out/en.html. */
function pagePath(file) {
  return "/" + relative(OUT_DIR, file).split(sep).join("/").replace(/\.html$/, "");
}

/** Path that an absolute site URL points at inside out/, or null when it is off-site. */
function exportedFile(url) {
  if (!url.startsWith(SITE_URL + "/")) return null;
  return join(OUT_DIR, url.slice(SITE_URL.length + 1) + ".html");
}

// The site name repeated at the end, e.g. "Specification | ATR | ATR" or "About — ATR | ATR".
const REPEATED_SUFFIX = /[|—–-]\s*ATR\s*\|\s*ATR\s*$/;

function checkPage(file) {
  const path = pagePath(file);
  const [, locale, ...rest] = path.split("/");
  const below = rest.length ? "/" + rest.join("/") : "";
  const expected = `${SITE_URL}${path}`;
  const head = readHead(readFileSync(file, "utf-8"));
  const problems = [];

  if (head.canonicals.length !== 1) problems.push(`${head.canonicals.length} canonical links`);
  else if (head.canonicals[0] !== expected) problems.push(`canonical is ${head.canonicals[0]}`);

  const wanted = {
    ...Object.fromEntries(Object.entries(LOCALES).map(([l, tag]) => [tag, `${SITE_URL}/${l}${below}`])),
    "x-default": `${SITE_URL}/en${below}`,
  };
  for (const [hreflang, href] of Object.entries(wanted)) {
    const found = head.alternates.filter((a) => a.hreflang === hreflang);
    if (found.length !== 1) problems.push(`${found.length} hreflang="${hreflang}" links`);
    else if (found[0].href !== href) problems.push(`hreflang="${hreflang}" is ${found[0].href}`);
    else if (!existsSync(exportedFile(href))) problems.push(`hreflang="${hreflang}" target ${href} is not exported`);
  }
  const extra = head.alternates.filter((a) => !(a.hreflang in wanted));
  if (extra.length) problems.push(`unexpected hreflang ${extra.map((a) => a.hreflang).join(", ")}`);

  if (head.ogUrl !== expected) problems.push(`og:url is ${head.ogUrl ?? "missing"}`);
  if (!head.title) problems.push("no <title>");
  else if (REPEATED_SUFFIX.test(head.title)) problems.push(`title repeats the site name: "${head.title}"`);

  return { path, locale, problems };
}

function main() {
  if (!existsSync(OUT_DIR)) {
    console.error(`check-seo: ${OUT_DIR} does not exist; run the build first.`);
    process.exit(2);
  }
  const pages = Object.keys(LOCALES).flatMap((l) => {
    const dir = join(OUT_DIR, l);
    const home = join(OUT_DIR, `${l}.html`);
    return [...(existsSync(home) ? [home] : []), ...(existsSync(dir) ? htmlFiles(dir) : [])];
  });
  const results = pages.map(checkPage);
  const failures = results.filter((r) => r.problems.length > 0);
  const nonRule = results.filter((r) => !/^\/(en|zh)\/rules\/ATR-/.test(r.path)).length;

  console.log(`check-seo: ${results.length} pages checked (${nonRule} outside /rules/ATR-*), ${failures.length} failing`);
  for (const f of failures.slice(0, 40)) console.log(`  ${f.path}: ${f.problems.join("; ")}`);
  if (failures.length > 40) console.log(`  ... and ${failures.length - 40} more`);
  process.exit(failures.length ? 1 : 0);
}

main();
