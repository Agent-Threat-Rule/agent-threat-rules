"use client";

import { useState, useMemo } from "react";
import type { RuleSummary } from "@/lib/rules";
import { categoryDisplayName } from "@/lib/categories";
import { t, type Locale } from "@/lib/i18n";
import { LANES, normalizeMaturity, rulesLanes, type Lane } from "@/lib/lanes";

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };
const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-ink font-semibold",
  high: "text-ink",
  medium: "text-graphite",
  low: "text-stone",
  informational: "text-stone",
};

/** Lane filter value: a lane, or "inert" for files no lane loads. */
type LaneFilter = Lane | "inert";

interface Props {
  rules: RuleSummary[];
  categories: { name: string; count: number }[];
  locale: Locale;
}

export function RuleExplorer({ rules, categories, locale }: Props) {
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
  const [selectedLane, setSelectedLane] = useState<LaneFilter | null>(null);
  const zh = locale === "zh";

  const lanesById = useMemo(() => new Map(rules.map((r) => [r.id, rulesLanes(r)])), [rules]);
  const laneOptions = useMemo(
    () => [
      ...LANES.map((lane) => ({ value: lane as LaneFilter, count: rules.filter((r) => lanesById.get(r.id)?.includes(lane)).length })),
      { value: "inert" as LaneFilter, count: rules.filter((r) => (lanesById.get(r.id) ?? []).length === 0).length },
    ],
    [rules, lanesById],
  );
  const [expandedRule, setExpandedRule] = useState<string | null>(null);

  const filtered = useMemo(() => {
    let result = rules;

    if (selectedCategory) {
      result = result.filter((r) => r.category === selectedCategory);
    }

    if (selectedSeverity) {
      result = result.filter((r) => r.severity === selectedSeverity);
    }

    if (selectedLane) {
      result = result.filter((r) => {
        const lanes = lanesById.get(r.id) ?? [];
        return selectedLane === "inert" ? lanes.length === 0 : lanes.includes(selectedLane);
      });
    }

    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (r) =>
          r.title.toLowerCase().includes(q) ||
          r.id.toLowerCase().includes(q) ||
          r.description.toLowerCase().includes(q) ||
          r.cves.some((c) => c.toLowerCase().includes(q))
      );
    }

    return [...result].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5));
  }, [rules, search, selectedCategory, selectedSeverity, selectedLane, lanesById]);

  const laneLabel = (value: LaneFilter): string => {
    const labels: Record<LaneFilter, { en: string; zh: string }> = {
      enforce: { en: "enforce lane (maturity stable)", zh: "enforce 車道（成熟度 stable）" },
      alert: { en: "alert lane (stable + test)", zh: "alert 車道（stable + test）" },
      hunt: { en: "hunt lane (default)", zh: "hunt 車道（預設）" },
      inert: { en: "inert (no lane loads it)", zh: "inert（任何車道都不載入）" },
    };
    return zh ? labels[value].zh : labels[value].en;
  };
  const clearAll = () => { setSearch(""); setSelectedCategory(null); setSelectedSeverity(null); setSelectedLane(null); };

  const severities = useMemo(() => {
    const map = new Map<string, number>();
    for (const r of rules) {
      map.set(r.severity, (map.get(r.severity) ?? 0) + 1);
    }
    return Array.from(map.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => (SEVERITY_ORDER[a.name] ?? 5) - (SEVERITY_ORDER[b.name] ?? 5));
  }, [rules]);

  return (
    <div>
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-3 mb-6">
        <input
          type="text"
          placeholder={t(locale, "rules.search")}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 min-w-[240px] bg-white border border-fog px-4 py-2.5 font-data text-sm text-ink placeholder:text-mist focus:outline-none focus:border-stone"
        />
        <select
          value={selectedCategory ?? ""}
          onChange={(e) => setSelectedCategory(e.target.value || null)}
          className="bg-white border border-fog px-4 py-2.5 text-sm text-stone font-data appearance-none cursor-pointer focus:outline-none"
        >
          <option value="">{t(locale, "rules.all_categories")}</option>
          {categories.map((c) => (
            <option key={c.name} value={c.name}>
              {categoryDisplayName(c.name, locale)} ({c.count})
            </option>
          ))}
        </select>
        <select
          value={selectedSeverity ?? ""}
          onChange={(e) => setSelectedSeverity(e.target.value || null)}
          className="bg-white border border-fog px-4 py-2.5 text-sm text-stone font-data appearance-none cursor-pointer focus:outline-none"
        >
          <option value="">{t(locale, "rules.all_severities")}</option>
          {severities.map((s) => (
            <option key={s.name} value={s.name}>
              {s.name} ({s.count})
            </option>
          ))}
        </select>
        <select
          value={selectedLane ?? ""}
          onChange={(e) => setSelectedLane((e.target.value || null) as LaneFilter | null)}
          aria-label={zh ? "依車道篩選" : "Filter by lane"}
          className="bg-white border border-fog px-4 py-2.5 text-sm text-stone font-data appearance-none cursor-pointer focus:outline-none"
        >
          <option value="">{zh ? "所有車道與 inert" : "All lanes and inert"}</option>
          {laneOptions.map((o) => (
            <option key={o.value} value={o.value}>
              {laneLabel(o.value)} ({o.count})
            </option>
          ))}
        </select>
      </div>

      {/* Stats bar */}
      <div className="font-data text-xs text-stone mb-4 tracking-wide">
        {t(locale, "rules.showing", { filtered: String(filtered.length), total: String(rules.length) })}
        {selectedCategory && <span className="ml-2">| {locale === "zh" ? "類別" : "category"}: {categoryDisplayName(selectedCategory, locale)}</span>}
        {selectedSeverity && <span className="ml-2">| severity: {selectedSeverity}</span>}
        {selectedLane && <span className="ml-2">| {laneLabel(selectedLane)}</span>}
        {search && <span className="ml-2">| search: &quot;{search}&quot;</span>}
        {(selectedCategory || selectedSeverity || selectedLane || search) && (
          <button
            onClick={clearAll}
            className="ml-3 text-blue hover:underline"
          >
            {t(locale, "rules.clear")}
          </button>
        )}
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="py-16 text-center">
          <p className="text-stone text-base">{t(locale, "rules.no_match")}</p>
          <button
            onClick={clearAll}
            className="mt-3 text-blue text-sm hover:underline"
          >
            {t(locale, "rules.clear")}
          </button>
        </div>
      ) : (
        <div className="border-t border-ink">
          {/* Header */}
          <div className="hidden lg:grid grid-cols-[150px_1fr_130px_90px_100px_110px_120px] border-b border-ink">
            <div className="px-4 py-3 font-data text-xs text-stone uppercase tracking-wider font-semibold">{t(locale, "rules.col.id")}</div>
            <div className="px-4 py-3 font-data text-xs text-stone uppercase tracking-wider font-semibold">{t(locale, "rules.col.name")}</div>
            <div className="px-4 py-3 font-data text-xs text-stone uppercase tracking-wider font-semibold">{t(locale, "rules.col.category")}</div>
            <div className="px-4 py-3 font-data text-xs text-stone uppercase tracking-wider font-semibold">{t(locale, "rules.col.severity")}</div>
            <div className="px-4 py-3 font-data text-xs text-stone uppercase tracking-wider font-semibold">{zh ? "成熟度" : "Maturity"}</div>
            <div className="px-4 py-3 font-data text-xs text-stone uppercase tracking-wider font-semibold">{zh ? "掃描目標" : "Scan target"}</div>
            <div className="px-4 py-3 font-data text-xs text-stone uppercase tracking-wider font-semibold">{t(locale, "rules.col.cves")}</div>
          </div>

          {/* Rows */}
          {filtered.map((rule) => (
            <div key={rule.id}>
              <button
                onClick={() => setExpandedRule(expandedRule === rule.id ? null : rule.id)}
                className="w-full text-left grid grid-cols-1 lg:grid-cols-[150px_1fr_130px_90px_100px_110px_120px] border-b border-fog hover:bg-ash/60 transition-colors"
              >
                <div className="px-4 py-3 font-data text-sm text-blue">{rule.id}</div>
                <div className="px-4 py-3 text-sm text-ink">{rule.title}</div>
                <div className="px-4 py-3 font-data text-xs text-stone">{categoryDisplayName(rule.category, locale)}</div>
                <div className="px-4 py-3">
                  <span className={`font-data text-xs uppercase tracking-wide ${SEVERITY_COLORS[rule.severity] ?? "text-stone"}`}>
                    {rule.severity}
                  </span>
                </div>
                <div className="px-4 py-3 font-data text-xs text-stone">
                  <span className="lg:hidden text-mist">maturity: </span>
                  {normalizeMaturity(rule.maturity)}
                  {(lanesById.get(rule.id) ?? []).length === 0 && <span className="ml-1 text-high">(inert)</span>}
                </div>
                <div className="px-4 py-3 font-data text-xs text-stone">
                  <span className="lg:hidden text-mist">{zh ? "掃描目標：" : "scan target: "}</span>
                  {rule.scanTarget ?? "--"}
                </div>
                <div className="px-4 py-3 font-data text-xs text-stone">
                  {rule.cves.length > 0 ? `${rule.cves[0]}${rule.cves.length > 1 ? ` +${rule.cves.length - 1}` : ""}` : "--"}
                </div>
              </button>

              {/* Expanded detail panel */}
              {expandedRule === rule.id && (
                <div className="bg-ash border-b border-fog px-6 py-5">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <div className="font-data text-xs text-stone uppercase tracking-wider mb-1">{t(locale, "rules.col.desc")}</div>
                      <p className="text-sm text-graphite leading-relaxed">{rule.description}</p>
                    </div>
                    <div className="space-y-4">
                      <div>
                        <div className="font-data text-xs text-stone uppercase tracking-wider mb-1">{zh ? "載入此規則的車道" : "Lanes that load this rule"}</div>
                        <div className="font-data text-xs text-ink">
                          {(lanesById.get(rule.id) ?? []).length > 0
                            ? (lanesById.get(rule.id) ?? []).join(", ")
                            : zh ? `無（status ${rule.status ?? "?"}，inert）` : `none (status ${rule.status ?? "?"}, inert)`}
                        </div>
                      </div>
                      {rule.owaspAgentic.length > 0 && (
                        <div>
                          <div className="font-data text-xs text-stone uppercase tracking-wider mb-1">OWASP Agentic</div>
                          <div className="font-data text-xs text-ink">{rule.owaspAgentic.join(", ")}</div>
                        </div>
                      )}
                      {rule.mitreAtlas.length > 0 && (
                        <div>
                          <div className="font-data text-xs text-stone uppercase tracking-wider mb-1">MITRE ATLAS</div>
                          <div className="font-data text-xs text-ink">{rule.mitreAtlas.join(", ")}</div>
                        </div>
                      )}
                      {rule.cves.length > 0 && (
                        <div>
                          <div className="font-data text-xs text-stone uppercase tracking-wider mb-1">CVEs</div>
                          <div className="font-data text-xs text-ink">{rule.cves.join(", ")}</div>
                        </div>
                      )}
                      <div>
                        <a
                          href={`https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/${rule.filePath}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-data text-xs text-blue hover:underline"
                        >
                          {t(locale, "rules.view_yaml")} &rarr;
                        </a>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
