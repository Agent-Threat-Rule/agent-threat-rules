// The root layout cannot see the [locale] segment, so every exported page
// starts as <html lang="en"> and only the browser switches it (HtmlLang.tsx).
// Screen readers and crawlers that read the static HTML then hear Chinese
// pages as English. After export, set lang="zh-Hant" on out/zh.html (the
// Chinese home page) and every page under out/zh.
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const out = join(process.cwd(), "out");
const root = join(out, "zh");
const walk = (dir) =>
  readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : path.endsWith(".html") ? [path] : [];
  });

let changed = 0;
for (const file of [join(out, "zh.html"), ...walk(root)]) {
  const html = readFileSync(file, "utf8");
  const next = html.replace(/<html lang="en"/, '<html lang="zh-Hant"');
  if (next !== html) {
    writeFileSync(file, next);
    changed++;
  }
}
console.log(`set-html-lang: ${changed} Chinese pages set to zh-Hant`);
