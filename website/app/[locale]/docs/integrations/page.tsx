import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { COMPONENTS, LAYERS, loadMatrix } from "@/lib/integration-matrix";
import { DocsShell, Callout } from "@/components/DocsShell";

const REPO = "https://github.com/Agent-Threat-Rule/agent-threat-rules";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({ params }: { params: Promise<{ locale: string }> }): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/docs/integrations",
    title: locale === "zh" ? "整合對照表" : "Integrations matrix",
    description:
      locale === "zh"
        ? "每一筆公開採用，對應到它使用的 ATR 元件與它運作的層級，附公開證據。"
        : "Every public adoption mapped to the ATR component it consumes and the layer it runs in, with public evidence.",
  });
}

export default async function IntegrationsMatrixPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const pick = (t: { en: string; zh: string }) => (zh ? t.zh : t.en);
  const versions = await loadVersionLabels();
  const rows = loadMatrix();
  const byComponent = COMPONENTS.map((c) => ({ c, rows: rows.filter((r) => r.component === c.key) })).filter((g) => g.rows.length > 0);

  return (
    <DocsShell
      locale={locale}
      path="/docs/integrations"
      eyebrow={zh ? "IV. 實作" : "IV. Implement"}
      title={zh ? "整合對照表" : "Integrations matrix"}
      lead={
        zh
          ? "每一筆公開採用使用了 ATR 的哪個元件、在哪一層運作。分類只根據 ADOPTERS.md 該筆自己的描述；描述沒寫的，標為「未說明」，不猜。"
          : "Which ATR component each public adoption consumes, and the layer it runs in. The classification reads only that entry's own sentence in ADOPTERS.md; where the sentence names no component, it says so instead of guessing."
      }
      generatedAt={versions.generatedAt}
    >
      <Callout label={zh ? "中立" : "Neutral"}>
        {zh
          ? "這張表依同一套規則列出所有採用者，不排名、不推薦。合併過的 pull request 證明曾經整合，不代表今天仍在使用。要更正某一筆，請改 ADOPTERS.md。"
          : "Every adopter is listed by the same rules, with no ranking or recommendation. A merged pull request shows an integration happened; it does not prove it is still in use. To correct an entry, edit ADOPTERS.md."}
      </Callout>

      <section className="mt-12">
        <h2 className="text-[20px] text-ink">{zh ? "依元件" : "By component"}</h2>
        <div className="mt-5 grid sm:grid-cols-2 lg:grid-cols-3 border-t border-l border-fog">
          {byComponent.map(({ c, rows: rs }) => (
            <a key={c.key} href={`#${c.key}`} className="p-5 border-r border-b border-fog bg-white/40 hover:bg-white transition-colors">
              <div className="flex items-baseline justify-between gap-3">
                <span className="text-[14px] text-ink">{pick(c.label)}</span>
                <span className="font-data text-[18px] text-ink tabular-nums">{rs.length}</span>
              </div>
              <p className="mt-2 text-[12.5px] leading-[1.55] text-stone">{pick(c.note)}</p>
              {c.repoPath && <div className="mt-3 font-data text-[10.5px] text-mist">{c.repoPath}/</div>}
            </a>
          ))}
        </div>
      </section>

      {byComponent.map(({ c, rows: rs }) => (
        <section key={c.key} id={c.key} className="mt-14 scroll-mt-32">
          <div className="flex items-baseline justify-between gap-4 flex-wrap">
            <h2 className="text-[20px] text-ink">{pick(c.label)}</h2>
            {c.repoPath && (
              <a href={`${REPO}/tree/main/${c.repoPath}`} className="font-data text-[11px] text-blue hover:underline underline-offset-4" target="_blank" rel="noopener noreferrer">
                {c.repoPath}/ ↗
              </a>
            )}
          </div>
          <div className="mt-4 overflow-x-auto">
            <table className="w-full text-left border-t border-fog min-w-[640px]">
              <thead>
                <tr className="border-b border-fog font-data text-[10px] uppercase tracking-[0.08em] text-mist">
                  <th className="py-2.5 pr-4 font-normal">{zh ? "專案" : "Project"}</th>
                  <th className="py-2.5 pr-4 font-normal">{zh ? "層級" : "Layer"}</th>
                  <th className="py-2.5 pr-4 font-normal">{zh ? "整合內容（ADOPTERS.md 原文）" : "Integration (from ADOPTERS.md)"}</th>
                  <th className="py-2.5 font-normal text-right">{zh ? "證據" : "Evidence"}</th>
                </tr>
              </thead>
              <tbody>
                {rs.map((r) => (
                  <tr key={r.name + r.evidence} className="border-b border-fog align-top">
                    <td className="py-3 pr-4">
                      <div className="text-[13.5px] text-ink">{r.name}</div>
                      <div className="font-data text-[10.5px] text-stone mt-0.5">
                        tier {r.tier}{r.status === "in-review" ? (zh ? " · 審查中" : " · in review") : ""}
                      </div>
                    </td>
                    <td className="py-3 pr-4 text-[12.5px] text-graphite whitespace-nowrap">{pick(LAYERS[r.layer] ?? LAYERS.other)}</td>
                    <td className="py-3 pr-4 text-[12.5px] leading-[1.55] text-graphite">{r.integration}</td>
                    <td className="py-3 text-right">
                      <a href={r.evidence} target="_blank" rel="noopener noreferrer" className="font-data text-[11px] text-blue hover:underline underline-offset-4">↗</a>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </DocsShell>
  );
}
