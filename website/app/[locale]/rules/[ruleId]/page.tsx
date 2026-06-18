import { loadAllRules, findRuleById, getRelatedRules, loadRuleDetail, categoryDisplayName } from "@/lib/rules";
import { locales, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-critical/10 text-critical",
  high: "bg-high/10 text-high",
  medium: "bg-medium/10 text-medium",
  low: "bg-green/10 text-green",
  informational: "bg-blue/10 text-blue",
};

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
    title: `${rule.id}: ${rule.title}`,
    description: rule.description.slice(0, 160),
    alternates: {
      canonical: `https://agentthreatrule.org/${locale}/rules/${rule.id}`,
      languages: {
        en: `https://agentthreatrule.org/en/rules/${rule.id}`,
        zh: `https://agentthreatrule.org/zh/rules/${rule.id}`,
      },
    },
    openGraph: {
      title: `${rule.id}: ${rule.title} | ATR`,
      description: `${rule.severity.toUpperCase()} severity ${categoryDisplay} detection rule. ${rule.description.slice(0, 120)}`,
    },
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

      <div className="pt-20 pb-16 px-5 md:px-6 max-w-[860px] mx-auto">
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

        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-3 flex-wrap">
            <span className="font-data text-xs text-mist">{rule.id}</span>
            <span className={`font-data text-xs px-2 py-0.5 rounded-sm uppercase ${severityClass}`}>
              {rule.severity}
            </span>
            <span className="font-data text-xs text-stone bg-ash px-2 py-0.5 rounded-sm">
              {categoryDisplay}
            </span>
            {rule.status && (
              <span className="font-data text-xs text-mist bg-ash px-2 py-0.5 rounded-sm">
                {rule.status}
              </span>
            )}
          </div>
          <h1 className="font-display text-[clamp(22px,3.5vw,36px)] font-extrabold tracking-[-1px] leading-[1.3] text-ink">
            {rule.title}
          </h1>
        </div>

        {/* Description */}
        <div className="mb-8">
          <p className="text-sm md:text-base text-graphite leading-[1.8]">
            {rule.description}
          </p>
        </div>

        {/* Metadata grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-fog mb-8">
          <div className="bg-paper p-4">
            <div className="font-data text-xs text-stone mb-1">{zh ? "嚴重度" : "Severity"}</div>
            <div className={`font-data text-sm font-semibold uppercase ${rule.severity === "critical" ? "text-critical" : rule.severity === "high" ? "text-high" : "text-medium"}`}>
              {rule.severity}
            </div>
          </div>
          <div className="bg-paper p-4">
            <div className="font-data text-xs text-stone mb-1">{zh ? "類別" : "Category"}</div>
            <div className="font-data text-sm text-ink">{categoryDisplay}</div>
          </div>
          <div className="bg-paper p-4">
            <div className="font-data text-xs text-stone mb-1">{zh ? "掃描目標" : "Scan Target"}</div>
            <div className="font-data text-sm text-ink">{rule.scanTarget ?? "mcp"}</div>
          </div>
          <div className="bg-paper p-4">
            <div className="font-data text-xs text-stone mb-1">{zh ? "作者" : "Author"}</div>
            <div className="font-data text-sm text-ink">{rule.author}</div>
          </div>
        </div>

        {/* Response actions */}
        {rule.responseActions && rule.responseActions.length > 0 && (
          <div className="mb-8">
            <h2 className="font-display text-sm font-semibold text-ink mb-3">
              {zh ? "建議回應" : "Response Actions"}
            </h2>
            <div className="flex flex-wrap gap-2">
              {rule.responseActions.map((action) => (
                <span key={action} className="font-data text-xs bg-ash text-ink px-3 py-1.5 rounded-sm">
                  {action.replace(/_/g, " ")}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* References */}
        {(rule.cves.length > 0 || rule.owaspAgentic.length > 0 || rule.owaspLlm.length > 0 || rule.mitreAtlas.length > 0) && (
          <div className="mb-8">
            <h2 className="font-display text-sm font-semibold text-ink mb-3">
              {zh ? "參考資料" : "References"}
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog">
              {rule.cves.length > 0 && (
                <div className="bg-paper p-4">
                  <div className="font-data text-xs text-stone mb-2">CVE</div>
                  <div className="flex flex-wrap gap-2">
                    {rule.cves.map((cve) => (
                      <a
                        key={cve}
                        href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-data text-xs text-blue hover:underline"
                      >
                        {cve}
                      </a>
                    ))}
                  </div>
                </div>
              )}
              {rule.owaspAgentic.length > 0 && (
                <div className="bg-paper p-4">
                  <div className="font-data text-xs text-stone mb-2">OWASP Agentic</div>
                  <div className="flex flex-col gap-1">
                    {rule.owaspAgentic.map((ref) => (
                      <span key={ref} className="font-data text-xs text-ink">{ref}</span>
                    ))}
                  </div>
                </div>
              )}
              {rule.owaspLlm.length > 0 && (
                <div className="bg-paper p-4">
                  <div className="font-data text-xs text-stone mb-2">OWASP LLM</div>
                  <div className="flex flex-col gap-1">
                    {rule.owaspLlm.map((ref) => (
                      <span key={ref} className="font-data text-xs text-ink">{ref}</span>
                    ))}
                  </div>
                </div>
              )}
              {rule.mitreAtlas.length > 0 && (
                <div className="bg-paper p-4">
                  <div className="font-data text-xs text-stone mb-2">MITRE ATLAS</div>
                  <div className="flex flex-col gap-1">
                    {rule.mitreAtlas.map((ref) => (
                      <span key={ref} className="font-data text-xs text-ink">{ref}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Validation stats — wild scan results */}
        {detail?.wildSamples !== undefined && (
          <div className="mb-8">
            <h2 className="font-display text-sm font-semibold text-ink mb-3">
              {zh ? "實地驗證" : "Wild Validation"}
            </h2>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-px bg-fog">
              {detail.wildValidated && (
                <div className="bg-paper p-4">
                  <div className="font-data text-xs text-stone mb-1">
                    {zh ? "驗證日期" : "Validated"}
                  </div>
                  <div className="font-data text-sm text-ink">
                    {detail.wildValidated.replace(/\//g, "-")}
                  </div>
                </div>
              )}
              <div className="bg-paper p-4">
                <div className="font-data text-xs text-stone mb-1">
                  {zh ? "樣本數" : "Samples"}
                </div>
                <div className="font-data text-sm text-ink">
                  {detail.wildSamples.toLocaleString()}
                </div>
              </div>
              {detail.wildFpRate !== undefined && (
                <div className="bg-paper p-4">
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
    </>
  );
}
