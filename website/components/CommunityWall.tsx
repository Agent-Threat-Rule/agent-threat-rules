"use client";

import { motion, useInView } from "motion/react";
import { useRef } from "react";

interface Contributor {
  github: string;
  country: string;
  role: "maintainer" | "contributor" | "reporter";
  contributions: string[];
}

interface CountryStats {
  code: string;
  flag: string;
  count: number;
  contributions: number;
}

interface Integration {
  name: string;
  type: "merged" | "open" | "using";
  detail: string;
  url?: string;
  logo?: string;
}

const EASE: [number, number, number, number] = [0.25, 0.1, 0.25, 1];

const COUNTRY_NAMES: Record<string, { en: string; zh: string }> = {
  TW: { en: "Taiwan", zh: "台灣" },
  US: { en: "United States", zh: "美國" },
  DE: { en: "Germany", zh: "德國" },
  JP: { en: "Japan", zh: "日本" },
  IN: { en: "India", zh: "印度" },
  GB: { en: "United Kingdom", zh: "英國" },
  FR: { en: "France", zh: "法國" },
  KR: { en: "South Korea", zh: "韓國" },
  BR: { en: "Brazil", zh: "巴西" },
  CA: { en: "Canada", zh: "加拿大" },
  AU: { en: "Australia", zh: "澳洲" },
  SG: { en: "Singapore", zh: "新加坡" },
  IL: { en: "Israel", zh: "以色列" },
  CN: { en: "China", zh: "中國" },
  SE: { en: "Sweden", zh: "瑞典" },
  NL: { en: "Netherlands", zh: "荷蘭" },
};

export function CommunityWall({
  contributors,
  countries,
  integrations,
  locale = "en",
}: {
  contributors: Contributor[];
  countries: CountryStats[];
  integrations: Integration[];
  locale?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: true, margin: "-60px" });
  const zh = locale === "zh";

  const merged = integrations.filter((i) => i.type === "merged");
  const open = integrations.filter((i) => i.type === "open");
  const maxContributions = Math.max(...countries.map((c) => c.contributions), 1);

  return (
    <div ref={ref}>
      {/* Country rows — each country is a horizontal bar */}
      <div className="border border-fog divide-y divide-fog">
        {countries.map((country, i) => {
          const name = COUNTRY_NAMES[country.code]?.[zh ? "zh" : "en"] ?? country.code;
          const barWidth = Math.max((country.contributions / maxContributions) * 100, 8);
          const countryContributors = contributors.filter((c) => c.country === country.code);

          return (
            <motion.div
              key={country.code}
              initial={{ opacity: 0, x: -20 }}
              animate={isInView ? { opacity: 1, x: 0 } : { opacity: 0, x: -20 }}
              transition={{ duration: 0.5, delay: i * 0.1, ease: EASE }}
              className="flex items-center gap-4 md:gap-6 px-5 md:px-6 py-4 md:py-5"
            >
              {/* Flag */}
              <span className="text-3xl md:text-4xl leading-none shrink-0">{country.flag}</span>

              {/* Info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-baseline gap-3 mb-1.5">
                  <span className="font-display text-sm font-semibold text-ink">{name}</span>
                  <span className="font-data text-xs text-mist">
                    {country.count} {zh ? "人" : (country.count === 1 ? "contributor" : "contributors")}
                  </span>
                </div>

                {/* Contribution bar */}
                <div className="h-2 bg-ash  overflow-hidden mb-2">
                  <motion.div
                    className="h-full bg-ink "
                    initial={{ width: 0 }}
                    animate={isInView ? { width: `${barWidth}%` } : { width: 0 }}
                    transition={{ duration: 0.8, delay: 0.2 + i * 0.1, ease: EASE }}
                  />
                </div>

                {/* Contributor avatars inline */}
                <div className="flex items-center gap-1.5">
                  {countryContributors.map((c) => (
                    <a
                      key={c.github}
                      href={`https://github.com/${c.github}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="group flex items-center gap-1.5"
                    >
                      <img
                        src={`https://github.com/${c.github}.png?size=32`}
                        alt={c.github}
                        width={20}
                        height={20}
                        className="ring-1 ring-fog group-hover:ring-blue transition-all"
                      />
                      <span className="font-data text-xs text-stone group-hover:text-ink transition-colors">
                        @{c.github}
                      </span>
                    </a>
                  ))}
                </div>
              </div>

              {/* Contribution count */}
              <div className="text-right shrink-0">
                <div className="font-data text-xl md:text-2xl font-bold text-ink">{country.contributions}</div>
                <div className="font-data text-xs text-mist">{zh ? "次貢獻" : "contributions"}</div>
              </div>
            </motion.div>
          );
        })}
      </div>

      {/* Ecosystem integrations */}
      <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-px bg-fog">
        {merged.map((item, i) => (
          <motion.a
            key={item.name}
            href={item.url}
            target="_blank"
            rel="noopener noreferrer"
            initial={{ opacity: 0, y: 12 }}
            animate={isInView ? { opacity: 1, y: 0 } : { opacity: 0, y: 12 }}
            transition={{ duration: 0.4, delay: 0.4 + i * 0.1, ease: EASE }}
            className="bg-paper px-5 py-4 flex items-center gap-3 hover:bg-ash/50 transition-colors"
          >
            {item.logo && (
              <img src={item.logo} alt="" width={28} height={28} className="ring-1 ring-fog" />
            )}
            <div className="min-w-0">
              <div className="font-display text-sm font-semibold text-ink truncate">{item.name}</div>
              <div className="text-xs text-stone truncate">{item.detail}</div>
            </div>
          </motion.a>
        ))}
      </div>

      {/* Open PRs */}
      {open.length > 0 && (
        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          <span className="font-data text-xs text-mist tracking-[1px] uppercase mr-1">
            {zh ? "審查中" : "In review"}
          </span>
          {open.map((item) => (
            <a
              key={item.name}
              href={item.url}
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs text-stone hover:text-ink transition-colors"
            >
              {item.name}{item !== open[open.length - 1] ? " ·" : ""}
            </a>
          ))}
        </div>
      )}

      {/* CTA */}
      <div className="mt-6 flex items-center gap-4">
        <a
          href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=add-contributor.md&title=Add+contributor:+MY_GITHUB_USERNAME"
          target="_blank"
          rel="noopener noreferrer"
          className="font-data text-xs text-blue hover:underline"
        >
          {zh ? "把自己加上來 →" : "Add yourself to the wall →"}
        </a>
        <span className="font-data text-xs text-mist">
          {contributors.length} {zh ? "位貢獻者" : "contributors"} · {countries.length} {zh ? "個國家" : "countries"} · {merged.length} {zh ? "個已合併的整合" : "merged integrations"}
        </span>
      </div>
    </div>
  );
}
