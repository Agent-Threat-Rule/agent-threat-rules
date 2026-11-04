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

const EASE: [number, number, number, number] = [0.25, 0.1, 0.25, 1];

/** Map total contributions to a flag font size (rem). More contributions = bigger flag. */
function flagSize(contributions: number, maxContributions: number): number {
  const min = 1.5;
  const max = 4;
  const ratio = Math.min(contributions / Math.max(maxContributions, 1), 1);
  // Ease the ratio so small contributors aren't invisible
  const eased = Math.pow(ratio, 0.5);
  return min + (max - min) * eased;
}

export function ContributorWall({
  contributors,
  countries,
  locale = "en",
}: {
  contributors: Contributor[];
  countries: CountryStats[];
  locale?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: true, margin: "-60px" });
  const zh = locale === "zh";
  const maxContributions = Math.max(...countries.map((c) => c.contributions), 1);
  const countryCount = countries.length;

  return (
    <div ref={ref}>
      {/* Flag cloud — size = contribution volume */}
      <div className="flex flex-wrap items-end justify-center gap-3 md:gap-5 mb-8">
        {countries.map((country, i) => {
          const size = flagSize(country.contributions, maxContributions);
          return (
            <motion.div
              key={country.code}
              initial={{ opacity: 0, scale: 0.5 }}
              animate={
                isInView
                  ? { opacity: 1, scale: 1 }
                  : { opacity: 0, scale: 0.5 }
              }
              transition={{
                duration: 0.5,
                delay: i * 0.1,
                ease: EASE,
              }}
              className="flex flex-col items-center"
              title={`${country.code}: ${country.count} contributor${country.count > 1 ? "s" : ""}, ${country.contributions} contributions`}
            >
              <span style={{ fontSize: `${size}rem`, lineHeight: 1 }}>
                {country.flag}
              </span>
              <span className="font-data text-xs text-mist mt-1">
                {country.contributions}
              </span>
            </motion.div>
          );
        })}
      </div>

      {/* Contributor avatars */}
      <div className="flex flex-wrap justify-center gap-3">
        {contributors.map((c, i) => (
          <motion.a
            key={c.github}
            href={`https://github.com/${c.github}`}
            target="_blank"
            rel="noopener noreferrer"
            initial={{ opacity: 0, y: 12 }}
            animate={
              isInView ? { opacity: 1, y: 0 } : { opacity: 0, y: 12 }
            }
            transition={{
              duration: 0.4,
              delay: 0.3 + i * 0.08,
              ease: EASE,
            }}
            className="group relative"
            title={`@${c.github} (${c.role})`}
          >
            <img
              src={`https://github.com/${c.github}.png?size=64`}
              alt={c.github}
              width={48}
              height={48}
              className={` ${
                c.role === "maintainer"
                  ? "ring-2 ring-blue"
                  : "ring-1 ring-fog"
              } group-hover:ring-ink transition-all`}
            />
            {/* Country flag badge */}
            <span className="absolute -bottom-1 -right-1 text-sm leading-none">
              {countries.find((co) => co.code === c.country)?.flag}
            </span>
          </motion.a>
        ))}
      </div>

      {/* Stats line */}
      <div className="text-center mt-6">
        <span className="font-data text-xs text-stone tracking-[1px]">
          {contributors.length} {zh ? "位貢獻者" : "contributors"} · {countryCount}{" "}
          {zh ? "個國家" : (countryCount === 1 ? "country" : "countries")}
        </span>
      </div>

      {/* CTA */}
      <div className="text-center mt-4">
        <a
          href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=add-contributor.md&title=Add+contributor:+MY_GITHUB_USERNAME"
          target="_blank"
          rel="noopener noreferrer"
          className="font-data text-xs text-blue hover:underline tracking-wide"
        >
          {zh ? "把自己加進來 →" : "Add yourself →"}
        </a>
      </div>
    </div>
  );
}
