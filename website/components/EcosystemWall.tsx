"use client";

import { motion, useInView } from "motion/react";
import { useRef } from "react";

interface Integration {
  name: string;
  type: "merged" | "open" | "using";
  detail: string;
  url?: string;
  logo?: string;
}

const EASE: [number, number, number, number] = [0.25, 0.1, 0.25, 1];

export function EcosystemWall({
  integrations,
  locale = "en",
}: {
  integrations: Integration[];
  locale?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const isInView = useInView(ref, { once: true, margin: "-60px" });
  const zh = locale === "zh";

  const merged = integrations.filter((i) => i.type === "merged");
  const open = integrations.filter((i) => i.type === "open");

  return (
    <div ref={ref}>
      {/* Merged — logo wall */}
      <div className="text-[13px] text-stone mb-4">
        {zh ? "已合併" : "Merged"}
      </div>
      <div className="flex flex-wrap gap-4 mb-8">
        {merged.map((item, i) => (
          <motion.a
            key={item.name}
            href={item.url}
            target="_blank"
            rel="noopener noreferrer"
            initial={{ opacity: 0, y: 12 }}
            animate={isInView ? { opacity: 1, y: 0 } : { opacity: 0, y: 12 }}
            transition={{ duration: 0.4, delay: i * 0.1, ease: EASE }}
            className="group flex items-center gap-3 border border-fog px-4 py-3 hover:border-stone transition-colors"
          >
            {item.logo && (
              <img
                src={item.logo}
                alt={item.name}
                width={32}
                height={32}
                className=""
              />
            )}
            <div>
              <div className="font-display text-sm font-semibold text-ink group-hover:text-blue transition-colors">
                {item.name}
              </div>
              <div className="text-xs text-stone">{item.detail}</div>
            </div>
          </motion.a>
        ))}
      </div>

      {/* Open PRs — compact list */}
      <div className="text-[13px] text-stone mb-3">
        {zh ? "審查中" : "In review"} ({open.length})
      </div>
      <div className="flex flex-wrap gap-2">
        {open.map((item, i) => (
          <motion.a
            key={item.name}
            href={item.url}
            target="_blank"
            rel="noopener noreferrer"
            initial={{ opacity: 0 }}
            animate={isInView ? { opacity: 1 } : { opacity: 0 }}
            transition={{ duration: 0.3, delay: 0.4 + i * 0.05, ease: EASE }}
            className="font-data text-xs text-stone border border-fog px-3 py-1.5 hover:border-stone hover:text-ink transition-colors"
          >
            {item.name}
          </motion.a>
        ))}
      </div>
    </div>
  );
}
