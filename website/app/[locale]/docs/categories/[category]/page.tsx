import Link from "next/link";
import type { Metadata } from "next";
import { notFound } from "next/navigation";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { loadAllRules, categoryDisplayName } from "@/lib/rules";
import { normalizeMaturity, rulesLanes } from "@/lib/lanes";
import { CATEGORY_DESC } from "@/lib/category-desc";
import { CATEGORY_ORDER, categoryLetter } from "@/lib/docs-nav";
import { DocsShell, GlanceTable } from "@/components/DocsShell";
import Phrased from "@/components/Phrased";

export function generateStaticParams() {
  return locales.flatMap((locale) => CATEGORY_ORDER.map((category) => ({ locale, category })));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string; category: string }> }): Promise<Metadata> {
  const { locale, category } = await params;
  if (!CATEGORY_DESC[category]) return { title: "Category not found" };
  const name = categoryDisplayName(category, locale);
  return pageMetadata({
    locale,
    path: `/docs/categories/${category}`,
    title: `${categoryLetter(category)}. ${name}`,
    description: locale === "zh" ? CATEGORY_DESC[category].zh : CATEGORY_DESC[category].en,
  });
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };

/** The most frequent references across a category's rules, for the crosswalk summary. */
function topRefs(refs: string[][], limit = 6): { ref: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const list of refs) for (const ref of new Set(list)) counts.set(ref, (counts.get(ref) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit).map(([ref, count]) => ({ ref, count }));
}

export default async function CategoryPage({ params }: { params: Promise<{ locale: string; category: string }> }) {
  const { locale: raw, category } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  if (!CATEGORY_DESC[category]) notFound();
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const versions = await loadVersionLabels();
  const rules = loadAllRules()
    .filter((r) => r.category === category)
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) || a.id.localeCompare(b.id));
  const effective = rules.filter((r) => rulesLanes(r).length > 0);
  const enforce = rules.filter((r) => rulesLanes(r).includes("enforce"));
  const atlas = topRefs(rules.map((r) => r.mitreAtlas));
  const agentic = topRefs(rules.map((r) => r.owaspAgentic));
  const letter = categoryLetter(category);

  return (
    <Phrased>
    <DocsShell
      locale={locale}
      path={`/docs/categories/${category}`}
      eyebrow={zh ? `II. 威脅類別 · ${letter}` : `II. Threat categories · ${letter}`}
      title={`${letter}. ${categoryDisplayName(category, locale)}`}
      lead={zh ? CATEGORY_DESC[category].zh : CATEGORY_DESC[category].en}
      generatedAt={versions.generatedAt}
    >
      <GlanceTable
        rows={[
          { label: zh ? "規則檔" : "Rule files", value: `${rules.length}` },
          { label: zh ? "生效" : "Effective", value: zh ? `${effective.length} 條，至少一個 lane 會載入` : `${effective.length}, loaded by at least one lane` },
          { label: zh ? "enforce lane" : "Enforce lane", value: zh ? `${enforce.length} 條，只收 stable` : `${enforce.length}, stable only` },
          { label: zh ? "下載" : "Download", value: <a href="/rules/index.csv" className="text-blue hover:underline underline-offset-4">rules/index.csv</a> },
        ]}
      />

      {(atlas.length > 0 || agentic.length > 0) && (
        <section className="mt-12">
          <h2 className="text-[20px] text-ink">{zh ? "最常見的框架對照" : "Most frequent crosswalks"}</h2>
          <p className="mt-2 text-[13px] text-stone">{zh ? "括號裡的數字，是這一類有幾條規則帶這一項。這些對應是 ATR 自己做的，框架方沒有審查或背書。" : "The number in brackets is how many rules in this category carry that item. ATR wrote these mappings; the framework owners have not reviewed or endorsed them."}</p>
          <div className="mt-5 grid md:grid-cols-2 gap-8">
            {[{ name: "MITRE ATLAS", list: atlas }, { name: "OWASP Agentic Top 10", list: agentic }].filter((x) => x.list.length > 0).map((fw) => (
              <div key={fw.name}>
                <div className="text-[13px] text-ink mb-2">{fw.name}</div>
                <ul className="border-t border-fog">
                  {fw.list.map((x) => (
                    <li key={x.ref} className="flex justify-between gap-4 py-2 border-b border-fog text-[12.5px] text-graphite">
                      <span>{x.ref}</span>
                      <span className="font-data text-stone tabular-nums">({x.count})</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </section>
      )}

      <section className="mt-12">
        <h2 className="text-[20px] text-ink">{zh ? "規則" : "Rules"}</h2>
        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-left border-t border-fog min-w-[640px]">
            <thead>
              <tr className="border-b border-fog font-data text-[10px] uppercase tracking-[0.08em] text-mist">
                <th className="py-2.5 pr-4 font-normal">ID</th>
                <th className="py-2.5 pr-4 font-normal">{zh ? "名稱" : "Title"}</th>
                <th className="py-2.5 pr-4 font-normal">{zh ? "嚴重度" : "Severity"}</th>
                <th className="py-2.5 pr-4 font-normal">Maturity</th>
                <th className="py-2.5 font-normal">{zh ? "載入的 lane" : "Lanes"}</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => {
                const lanes = rulesLanes(r);
                return (
                  <tr key={r.id} className="border-b border-fog align-top">
                    <td className="py-2.5 pr-4 font-data text-[11.5px] whitespace-nowrap">
                      <Link href={`${prefix}/rules/${r.id}`} className="text-blue hover:underline underline-offset-4">{r.id}</Link>
                    </td>
                    <td className="py-2.5 pr-4 text-[13px] text-ink">{r.title}</td>
                    <td className={`py-2.5 pr-4 text-[12.5px] ${r.severity === "critical" ? "text-critical" : r.severity === "high" ? "text-high" : "text-graphite"}`}>{r.severity}</td>
                    <td className="py-2.5 pr-4 text-[12.5px] text-graphite">{normalizeMaturity(r.maturity)}</td>
                    <td className="py-2.5 text-[12.5px] text-graphite whitespace-nowrap">
                      {lanes.length > 0 ? lanes.join(" · ") : <span className="text-high">{zh ? "無，不生效" : "none, inert"}</span>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    </DocsShell>
    </Phrased>
  );
}
