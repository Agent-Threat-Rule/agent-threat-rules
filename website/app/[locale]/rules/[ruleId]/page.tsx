import { loadAllRules, findRuleById, getRelatedRules, loadRuleDetail, categoryDisplayName, type RuleSummary } from "@/lib/rules";
import { locales, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import { SheetRow } from "@/components/Sheet";
import { normalizeMaturity, rulesLanes } from "@/lib/lanes";
import Link from "next/link";
import { notFound } from "next/navigation";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-critical/10 text-critical",
  high: "bg-high/10 text-high",
  medium: "bg-medium/10 text-medium",
  low: "bg-green/10 text-green",
  informational: "bg-blue/10 text-blue",
};

/** First sentence of a rule description, for the lead line under the title. */
function leadSentence(text: string): string {
  // Descriptions are YAML block scalars with hard line breaks; flatten first.
  const flat = text.replace(/\s+/g, " ").trim();
  const m = /^(.{40,}?[.。])(\s|$)/.exec(flat);
  return m ? m[1] : flat;
}

interface Crosswalk {
  name: string;
  help: string;
  items: { text: string; href?: string }[];
}

function buildCrosswalks(rule: RuleSummary, zh: boolean): Crosswalk[] {
  const atlasId = (ref: string) => /AML\.T\d{4}(?:\.\d{3})?/.exec(ref)?.[0];
  const all: Crosswalk[] = [
    {
      name: "MITRE ATLAS",
      help: zh ? "MITRE 的 AI 攻擊技術知識庫；這裡列 technique 層級的 ID" : "MITRE's knowledge base of attacks on AI systems; technique-level IDs",
      items: rule.mitreAtlas.map((ref) => {
        const id = atlasId(ref);
        return { text: ref, href: id ? `https://atlas.mitre.org/techniques/${id}` : undefined };
      }),
    },
    {
      name: "OWASP Agentic Top 10",
      help: zh ? "OWASP 針對 AI 代理應用的十大風險" : "OWASP's top ten risks for agentic AI applications",
      items: rule.owaspAgentic.map((text) => ({ text })),
    },
    {
      name: "OWASP LLM Top 10",
      help: zh ? "OWASP 針對大型語言模型應用的十大風險" : "OWASP's top ten risks for LLM applications",
      items: rule.owaspLlm.map((text) => ({ text })),
    },
    {
      name: "CVE",
      help: zh ? "這條規則偵測的已公開漏洞，連到 NVD" : "Published vulnerabilities this rule detects, linked to NVD",
      items: rule.cves.map((cve) => ({ text: cve, href: `https://nvd.nist.gov/vuln/detail/${cve}` })),
    },
  ];
  return all.filter((c) => c.items.length > 0);
}

export function generateStaticParams() {
  const rules = loadAllRules();
  const params: { locale: string; ruleId: string }[] = [];
  for (const locale of locales) {
    for (const rule of rules) {
      params.push({ locale, ruleId: rule.id });
    }
  }
  return params;
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string; ruleId: string }>;
}): Promise<Metadata> {
  const { locale, ruleId } = await params;
  const rules = loadAllRules();
  const rule = findRuleById(rules, ruleId);

  if (!rule) return { title: "Rule Not Found" };

  const categoryDisplay = categoryDisplayName(rule.category, locale);

  return {
    ...pageMetadata({
      locale,
      path: `/rules/${rule.id}`,
      title: `${rule.id}: ${rule.title}`,
      description: rule.description.slice(0, 160),
      openGraph: {
        description: `${rule.severity.toUpperCase()} severity ${categoryDisplay} detection rule. ${rule.description.slice(0, 120)}`,
      },
    }),
    other: {
      "article:section": categoryDisplay,
      "article:tag": [rule.category, rule.severity, ...rule.cves].join(","),
    },
  };
}

export default async function RuleDetailPage({
  params,
}: {
  params: Promise<{ locale: string; ruleId: string }>;
}) {
  const { locale: rawLocale, ruleId } = await params;
  const locale = (locales.includes(rawLocale as Locale) ? rawLocale : "en") as Locale;
  const zh = locale === "zh";
  const prefix = `/${locale}`;
  const rules = loadAllRules();
  const rule = findRuleById(rules, ruleId);

  if (!rule) notFound();

  const detail = loadRuleDetail(ruleId);
  const related = getRelatedRules(rules, rule);
  const categoryDisplay = categoryDisplayName(rule.category, locale);
  const severityClass = SEVERITY_COLORS[rule.severity] ?? "bg-ash text-stone";
  const lanes = rulesLanes(rule);
  const keywords = [rule.subcategory, rule.detectionTier, rule.confidence && `confidence: ${rule.confidence}`]
    .filter((k): k is string => typeof k === "string" && k.trim() !== "")
    .map((k) => k.replace(/[-_]/g, " "));
  const crosswalks = buildCrosswalks(rule, zh);

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "TechArticle",
    name: `${rule.id}: ${rule.title}`,
    description: rule.description,
    author: { "@type": "Organization", name: "ATR Community" },
    datePublished: rule.date ? rule.date.replace(/\//g, "-") : undefined,
    url: `https://agentthreatrule.org/${locale}/rules/${rule.id}`,
    isPartOf: {
      "@type": "WebSite",
      name: "ATR - Agent Threat Rules",
      url: "https://agentthreatrule.org",
    },
    keywords: [rule.category, rule.severity, "AI agent security", "detection rule", ...rule.cves],
  };

  return (
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/<\/script>/gi, "<\\/script>") }}
      />

      <div className="sheet">
      <SheetRow>
      <div className="pt-16 pb-24 px-8 md:px-12 max-w-[900px] mx-auto">
        {/* Breadcrumb */}
        <nav className="font-data text-xs text-stone mb-6 flex items-center gap-2">
          <Link href={prefix} className="hover:text-ink transition-colors">ATR</Link>
          <span className="text-fog">/</span>
          <Link href={`${prefix}/rules`} className="hover:text-ink transition-colors">
            {zh ? "規則" : "Rules"}
          </Link>
          <span className="text-fog">/</span>
          <span className="text-ink">{rule.id}</span>
        </nav>

        {/* Header — one template for every rule: identity, one-sentence
            statement, keywords, attribute row, crosswalk grid. */}
        <div className="font-data text-[11px] uppercase tracking-[0.1em] text-stone mb-4">
          {categoryDisplay} <span className="text-mist">· {rule.id}</span>
        </div>
        <h1 className="text-[30px] md:text-[36px] leading-[1.15] tracking-[-0.02em] font-medium text-ink text-balance">
          {rule.title}
        </h1>
        <p className="mt-4 text-[17px] leading-[1.6] text-graphite text-pretty">{leadSentence(rule.description)}</p>

        {keywords.length > 0 && (
          <div className="mt-6 flex flex-wrap gap-2">
            {keywords.map((k) => (
              <span key={k} className="font-data text-[11px] text-graphite bg-ash border border-fog px-2 py-0.5 rounded-[2px]">{k}</span>
            ))}
          </div>
        )}

        <dl className="mt-8 grid grid-cols-2 md:grid-cols-5 border-t border-b border-fog">
          {[
            { label: zh ? "嚴重度" : "Severity", value: rule.severity, tone: rule.severity === "critical" ? "text-critical" : rule.severity === "high" ? "text-high" : "text-ink" },
            { label: "Maturity", value: normalizeMaturity(rule.maturity), tone: "text-ink" },
            { label: zh ? "載入的 lane" : "Lanes", value: lanes.length > 0 ? lanes.join(" · ") : zh ? "無（inert）" : "none (inert)", tone: lanes.length > 0 ? "text-ink" : "text-high" },
            { label: zh ? "掃描目標" : "Scan target", value: rule.scanTarget ?? "—", tone: "text-ink" },
            { label: "Status", value: rule.status ?? "—", tone: "text-ink" },
          ].map((cell) => (
            <div key={cell.label} className="py-4 pr-4 md:border-r border-fog last:border-r-0 [&:not(:first-child)]:md:pl-4">
              <dt className="font-data text-[10px] uppercase tracking-[0.08em] text-mist">{cell.label}</dt>
              <dd className={`mt-1.5 text-[14px] ${cell.tone}`}>{cell.value}</dd>
            </div>
          ))}
        </dl>

        {crosswalks.length > 0 && (
          <section className="mt-10" aria-labelledby="crosswalks-heading">
            <h2 id="crosswalks-heading" className="font-data text-[11px] uppercase tracking-[0.1em] text-stone mb-4">
              {zh ? "框架對照" : "Crosswalks"}
            </h2>
            <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-6">
              {crosswalks.map((cw) => (
                <div key={cw.name}>
                  <div className="text-[13px] text-ink mb-2 flex items-center gap-1.5">
                    {cw.name}
                    <span title={cw.help} className="font-data text-[10px] text-mist border border-fog rounded-full w-4 h-4 inline-flex items-center justify-center cursor-help" aria-label={cw.help}>?</span>
                  </div>
                  <ul className="flex flex-col gap-1">
                    {cw.items.map((item) => (
                      <li key={item.text} className="text-[13px] leading-snug">
                        {item.href ? (
                          <a href={item.href} target="_blank" rel="noopener noreferrer" className="text-blue hover:underline underline-offset-4">{item.text}</a>
                        ) : (
                          <span className="text-graphite">{item.text}</span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </section>
        )}

        <section className="mt-10 pt-8 border-t border-fog">
          <h2 className="font-data text-[11px] uppercase tracking-[0.1em] text-stone mb-3">{zh ? "說明" : "Description"}</h2>
          <p className="text-[15px] text-graphite leading-[1.8]">{rule.description}</p>
          {rule.responseActions && rule.responseActions.length > 0 && (
            <div className="mt-6 flex flex-wrap items-center gap-2">
              <span className="font-data text-[10px] uppercase tracking-[0.08em] text-mist mr-1">{zh ? "建議回應" : "Suggested response"}</span>
              {rule.responseActions.map((action) => (
                <span key={action} className="font-data text-[11px] text-ink border border-fog px-2 py-0.5 rounded-[2px]">
                  {action.replace(/_/g, " ")}
                </span>
              ))}
            </div>
          )}
          <div className="mt-6 font-data text-[11px] text-stone">
            {zh ? "作者" : "Author"}: {rule.author}
            {rule.date && <> · {zh ? "建立" : "Created"} {rule.date.replace(/\//g, "-")}</>}
            {detail?.lastModified && <> · {zh ? "最後修改" : "Last modified"} {detail.lastModified}</>}
          </div>
        </section>

        <div className="mb-8" />
        {/* Validation stats — wild scan results */}
        {detail?.wildSamples !== undefined && (
          <div className="mb-8">
            <h2 className="font-display text-sm font-semibold text-ink mb-3">
              {zh ? "實地驗證" : "Wild Validation"}
            </h2>
            <div className="flex flex-wrap gap-px bg-fog border border-fog">
              {detail.wildValidated && (
                <div className="bg-paper p-4 flex-1 min-w-[160px]">
                  <div className="font-data text-xs text-stone mb-1">
                    {zh ? "驗證日期" : "Validated"}
                  </div>
                  <div className="font-data text-sm text-ink">
                    {detail.wildValidated.replace(/\//g, "-")}
                  </div>
                </div>
              )}
              <div className="bg-paper p-4 flex-1 min-w-[160px]">
                <div className="font-data text-xs text-stone mb-1">
                  {zh ? "樣本數" : "Samples"}
                </div>
                <div className="font-data text-sm text-ink">
                  {detail.wildSamples.toLocaleString()}
                </div>
              </div>
              {detail.wildFpRate !== undefined && (
                <div className="bg-paper p-4 flex-1 min-w-[160px]">
                  <div className="font-data text-xs text-stone mb-1">
                    {zh ? "誤報率（實地語料）" : "False Positive Rate (in-the-wild)"}
                  </div>
                  <div className="font-data text-sm text-ink">{detail.wildFpRate}%</div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Detection conditions */}
        {detail && detail.detectionConditions.length > 0 && (
          <div className="mb-8">
            <div className="flex items-baseline justify-between gap-2 flex-wrap mb-3">
              <h2 className="font-display text-sm font-semibold text-ink">
                {zh ? "偵測條件" : "Detection Conditions"}
              </h2>
              {detail.detectionCombinator && (
                <span className="font-data text-[10px] text-mist uppercase tracking-wide">
                  {zh ? "組合方式" : "Combinator"}: {detail.detectionCombinator}
                </span>
              )}
            </div>
            <ol className="space-y-2">
              {detail.detectionConditions.map((c, i) => (
                <li key={i} className="bg-paper border border-fog p-3 md:p-4">
                  <div className="flex items-start gap-3">
                    <span className="font-data text-[11px] text-mist shrink-0 mt-0.5">
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    <div className="min-w-0 flex-1">
                      {c.description && (
                        <div className="text-sm text-ink leading-[1.6] mb-1.5">{c.description}</div>
                      )}
                      <div className="font-data text-[10px] md:text-[11px] text-stone flex flex-wrap gap-x-3 gap-y-1">
                        {c.field && <span>{zh ? "欄位" : "field"}: {c.field}</span>}
                        {c.operator && <span>{zh ? "運算子" : "op"}: {c.operator}</span>}
                      </div>
                    </div>
                  </div>
                </li>
              ))}
            </ol>
          </div>
        )}

        {/* Attack examples — test cases that trigger the rule */}
        {detail && detail.truePositives.length > 0 && (
          <div className="mb-8">
            <h2 className="font-display text-sm font-semibold text-ink mb-3">
              {zh ? "攻擊範例（規則會觸發）" : "Attack Examples (Rule Triggers)"}
            </h2>
            <ol className="space-y-3">
              {detail.truePositives.map((tc, i) => (
                <li key={i} className="bg-critical/[0.03] border-l-2 border-critical p-3 md:p-4">
                  {tc.matched_condition && (
                    <div className="font-data text-[10px] text-critical uppercase tracking-wide mb-2">
                      {zh ? "觸發條件" : "Matches"}: {tc.matched_condition}
                    </div>
                  )}
                  <pre className="font-data text-xs text-graphite whitespace-pre-wrap break-all leading-[1.7]">
                    {tc.input}
                  </pre>
                </li>
              ))}
            </ol>
            <p className="text-xs text-mist mt-3 leading-[1.7]">
              {zh
                ? "以上為真實攻擊 payload 的脫敏版本，與規則一同版本化，作為 regression test——確保未來的修訂不會悄悄漏掉它們。"
                : "Real-world attack payloads, sanitized and versioned alongside the rule as regression tests — so a future revision can't silently stop catching them."}
            </p>
          </div>
        )}

        {/* Negative examples — should NOT trigger */}
        {detail && detail.trueNegatives.length > 0 && (
          <div className="mb-8">
            <h2 className="font-display text-sm font-semibold text-ink mb-3">
              {zh ? "正常樣本（規則不會觸發）" : "Benign Examples (Rule Doesn't Trigger)"}
            </h2>
            <ol className="space-y-3">
              {detail.trueNegatives.map((tc, i) => (
                <li key={i} className="bg-green/[0.05] border-l-2 border-green p-3 md:p-4">
                  {tc.description && (
                    <div className="font-data text-[10px] text-green uppercase tracking-wide mb-2">
                      {tc.description}
                    </div>
                  )}
                  <pre className="font-data text-xs text-graphite whitespace-pre-wrap break-all leading-[1.7]">
                    {tc.input}
                  </pre>
                </li>
              ))}
            </ol>
          </div>
        )}

        {/* False positives — documented known-FP contexts */}
        {detail && detail.falsePositives.length > 0 && (
          <div className="mb-8">
            <h2 className="font-display text-sm font-semibold text-ink mb-3">
              {zh ? "已知誤報情境" : "Known False Positive Contexts"}
            </h2>
            <ul className="space-y-2">
              {detail.falsePositives.map((fp, i) => (
                <li key={i} className="text-sm text-graphite leading-[1.7] flex items-start gap-2">
                  <span className="text-fog shrink-0 mt-1">▸</span>
                  <span>{fp}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Evasion techniques — documented bypasses */}
        {detail && detail.evasionTests.length > 0 && (
          <div className="mb-8">
            <h2 className="font-display text-sm font-semibold text-ink mb-3">
              {zh ? "已記錄的規避手法" : "Documented Evasion Techniques"}
            </h2>
            <ol className="space-y-3">
              {detail.evasionTests.map((ev, i) => (
                <li key={i} className="bg-high/[0.05] border-l-2 border-high p-3 md:p-4">
                  {ev.bypass_technique && (
                    <div className="font-data text-[10px] text-high uppercase tracking-wide mb-2">
                      {zh ? "手法" : "Technique"}: {ev.bypass_technique.replace(/_/g, " ")}
                    </div>
                  )}
                  <pre className="font-data text-xs text-graphite whitespace-pre-wrap break-all leading-[1.7] mb-2">
                    {ev.input}
                  </pre>
                  {ev.notes && (
                    <div className="text-xs text-stone leading-[1.7]">{ev.notes}</div>
                  )}
                </li>
              ))}
            </ol>
            <p className="text-xs text-mist mt-3 leading-[1.7]">
              {zh
                ? "這些是公開記錄的繞過手法。一個標準的可信度，取決於它願不願意公開自己最差的數字——所以已知限制寫在規則裡，而不是藏起來。"
                : "Publicly documented bypasses. A standard earns trust by publishing its worst figures, not hiding them — so known limitations ship inside the rule, not in a footnote."}
            </p>
          </div>
        )}

        {/* Full YAML preview */}
        {detail && (
          <div className="mb-8">
            <div className="flex items-baseline justify-between gap-2 flex-wrap mb-3">
              <h2 className="font-display text-sm font-semibold text-ink">
                {zh ? "完整 YAML 定義" : "Full YAML Definition"}
              </h2>
              <a
                href={`https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/${rule.filePath}`}
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline"
              >
                {zh ? "在 GitHub 編輯 →" : "Edit on GitHub →"}
              </a>
            </div>
            <pre className="bg-ash border border-fog p-4 md:p-5 font-data text-[11px] md:text-xs text-graphite leading-[1.7] overflow-x-auto max-h-[480px] overflow-y-auto">
              {detail.rawYaml}
            </pre>
          </div>
        )}

        {/* Revision history */}
        <div className="mb-10 border-t border-fog pt-6">
          <h2 className="font-display text-sm font-semibold text-ink mb-3">
            {zh ? "修訂歷史" : "Revision History"}
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-px bg-fog">
            {rule.date && (
              <div className="bg-paper p-4">
                <div className="font-data text-xs text-stone mb-1">
                  {zh ? "建立於" : "Created"}
                </div>
                <div className="font-data text-sm text-ink">{rule.date.replace(/\//g, "-")}</div>
              </div>
            )}
            {detail?.lastModified && (
              <div className="bg-paper p-4">
                <div className="font-data text-xs text-stone mb-1">
                  {zh ? "最後修改" : "Last modified"}
                </div>
                <div className="font-data text-sm text-ink">{detail.lastModified}</div>
              </div>
            )}
          </div>
          <a
            href={`https://github.com/Agent-Threat-Rule/agent-threat-rules/commits/main/${rule.filePath}`}
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline inline-block mt-3"
          >
            {zh ? "在 GitHub 查看完整 commit 歷史 →" : "View full commit history on GitHub →"}
          </a>
        </div>

        {/* Related rules */}
        {related.length > 0 && (
          <div className="border-t border-fog pt-8">
            <h2 className="font-display text-sm font-semibold text-ink mb-4">
              {zh ? `更多 ${categoryDisplay} 規則` : `More ${categoryDisplay} Rules`}
            </h2>
            <div className="grid grid-cols-1 gap-px bg-fog">
              {related.map((r) => (
                <Link
                  key={r.id}
                  href={`${prefix}/rules/${r.id}`}
                  className="bg-paper p-4 hover:bg-ash/50 transition-colors flex items-center gap-4"
                >
                  <span className="font-data text-xs text-mist shrink-0 w-28">{r.id}</span>
                  <span className={`font-data text-xs px-1.5 py-0.5 rounded-sm uppercase shrink-0 ${SEVERITY_COLORS[r.severity] ?? "bg-ash text-stone"}`}>
                    {r.severity}
                  </span>
                  <span className="text-sm text-ink truncate">{r.title}</span>
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
      </SheetRow>
      </div>
    </>
  );
}
