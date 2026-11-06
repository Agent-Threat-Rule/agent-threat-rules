import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { pageMetadata } from "@/lib/seo";
import { loadVersionLabels } from "@/lib/versions";
import { COMPONENTS, LAYERS, loadMatrix } from "@/lib/integration-matrix";
import { DocsShell, Callout } from "@/components/DocsShell";
import Phrased from "@/components/Phrased";

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
        ? "每一筆公開採用用了 ATR 哪個元件、跑在哪一層，都附公開證據。"
        : "Each public adoption, mapped to the ATR component it uses and the layer it runs in, with public evidence.",
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
    <Phrased>
    <DocsShell
      locale={locale}
      path="/docs/integrations"
      eyebrow={zh ? "IV. 實作" : "IV. Implement"}
      title={zh ? "整合對照表" : "Integrations matrix"}
      lead={
        zh
          ? "每一筆公開採用，用的是 ATR 哪個元件，在哪一層跑。分類只看 ADOPTERS.md 裡那一筆自己怎麼寫。沒寫的，就標「未說明」，不用猜的。"
          : "Which ATR component each public adoption uses, and the layer it runs in. The classification reads only that entry's own sentence in ADOPTERS.md. If the sentence names no component, the table says so rather than guess."
      }
      generatedAt={versions.generatedAt}
    >
      <Callout label={zh ? "中立" : "Neutral"}>
        {zh
          ? "所有採用者都照同一套規則列出，不排名，也不推薦。PR 合併過，證明當時整合過，不代表今天還在用。哪一筆寫錯了，直接改 ADOPTERS.md。"
          : "Every adopter is listed by the same rules. No ranking, no recommendation. A merged pull request shows an integration happened. It does not prove the integration is still in use. To correct an entry, edit ADOPTERS.md."}
      </Callout>

      <section className="mt-12">
        <h2 className="text-[20px] text-ink">{zh ? "按元件看" : "By component"}</h2>
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
    </Phrased>
  );
}
