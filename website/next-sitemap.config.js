const SITE_URL = "https://agentthreatrule.org";

/** @type {import('next-sitemap').IConfig} */
module.exports = {
  siteUrl: SITE_URL,
  generateRobotsTxt: true,
  outDir: "./out",
  generateIndexSitemap: false,
  // Privacy and Terms stay out of the sitemap while they are drafts (lib/legal.ts).
  exclude: ["/icon.svg", "/favicon.ico", "/llms.txt", "/rules/index.json", "/rules/index.csv", "/en/privacy", "/zh/privacy", "/en/terms", "/zh/terms", "/en/community/membership", "/zh/community/membership", "/en/community/join", "/zh/community/join"],
  robotsTxtOptions: {
    policies: [
      { userAgent: "*", allow: "/" },
      { userAgent: "GPTBot", allow: "/" },
      { userAgent: "ChatGPT-User", allow: "/" },
      { userAgent: "Google-Extended", allow: "/" },
      { userAgent: "PerplexityBot", allow: "/" },
      { userAgent: "ClaudeBot", allow: "/" },
    ],
  },
  transform: async (_config, path) => {
    const priorities = {
      "/en": 1.0,
      "/zh": 1.0,
      "/en/rules": 0.9,
      "/zh/rules": 0.9,
      "/en/integrate": 0.9,
      "/zh/integrate": 0.9,
      "/en/ecosystem": 0.8,
      "/zh/ecosystem": 0.8,
      "/en/coverage": 0.8,
      "/zh/coverage": 0.8,
      "/en/research": 0.8,
      "/zh/research": 0.8,
      "/en/wall": 0.7,
      "/zh/wall": 0.7,
      "/en/contribute": 0.7,
      "/zh/contribute": 0.7,
    };

    // Individual rule pages get 0.6 priority
    const isRulePage = /^\/(en|zh)\/rules\/ATR-/.test(path);

    // hreflang: the same page in each locale, English as x-default (the
    // <link rel="alternate"> tags on each page say the same; see lib/seo.ts).
    const localized = /^\/(en|zh)(\/.*)?$/.exec(path);
    const below = localized ? localized[2] ?? "" : "";
    const alternateRefs = localized
      ? [
          { href: `${SITE_URL}/en${below}`, hreflang: "en", hrefIsAbsolute: true },
          { href: `${SITE_URL}/zh${below}`, hreflang: "zh-Hant", hrefIsAbsolute: true },
          { href: `${SITE_URL}/en${below}`, hreflang: "x-default", hrefIsAbsolute: true },
        ]
      : [];

    return {
      loc: path,
      alternateRefs,
      changefreq: isRulePage ? "weekly" : path.includes("rules") ? "weekly" : "monthly",
      priority: priorities[path] ?? (isRulePage ? 0.6 : 0.5),
      lastmod: new Date().toISOString(),
    };
  },
};
