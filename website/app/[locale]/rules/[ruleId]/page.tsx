import { loadAllRules, findRuleById, getRelatedRules, loadRuleDetail, categoryDisplayName, type RuleSummary } from "@/lib/rules";
import { locales, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import { SheetRow } from "@/components/Sheet";
import { normalizeMaturity, rulesLanes } from "@/lib/lanes";
import Link from "next/link";
import { notFound } from "next/navigation";
import Phrased from "@/components/Phrased";
import { Sign } from "@/components/Sign";
import { ScrollX } from "@/components/ScrollX";
import { categoryLetter } from "@/lib/docs-nav";

/** YAML longer than this shows its head, with the rest behind "show all". */
const YAML_HEAD_LINES = 40;

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
      help: zh ? "MITRE 整理的 AI 攻擊知識庫，這裡列到 technique 層級" : "MITRE's catalog of attacks on AI systems, listed at technique level",
      items: rule.mitreAtlas.map((ref) => {
        const id = atlasId(ref);
        return { text: ref, href: id ? `https://atlas.mitre.org/techniques/${id}` : undefined };
      }),
    },
    {
      name: "OWASP Agentic Top 10",
      help: zh ? "OWASP 列出的 agent 應用十大風險" : "OWASP's top ten risks for agentic AI applications",
      items: rule.owaspAgentic.map((text) => ({ text })),
    },
    {
      name: "OWASP LLM Top 10",
      help: zh ? "OWASP 列出的大型語言模型應用十大風險" : "OWASP's top ten risks for LLM applications",
      items: rule.owaspLlm.map((text) => ({ text })),
    },
    {
      name: "CVE",
      help: zh ? "這條規則偵測的公開漏洞，連到 NVD" : "Published vulnerabilities this rule detects, linked to NVD",
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
  const lanes = rulesLanes(rule);
  const maturity = normalizeMaturity(rule.maturity);
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
    <Phrased>
    <>
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/<\/script>/gi, "<\\/script>") }}
      />

      <>
      <SheetRow>
      <div className="pt-16 pb-24 px-6 md:px-14 max-w-[1012px]">
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
        <div className="mb-10 border-y border-ink py-7 md:py-9 text-center">
          <div className="text-[12px] tracking-[0.18em] text-stone"><span className="font-spec text-[15px] tracking-normal text-ink mr-2">{categoryLetter(rule.category)}</span>{categoryDisplay}</div>
          <div className="font-title mt-3 text-[30px] sm:text-[40px] md:text-[48px] leading-none tracking-[0.1em] text-ink">{rule.id}</div>
          <div className="mt-4 text-[12px] text-stone">
            {[
              rule.date && `${zh ? "收錄於" : "Recorded"} ${rule.date.replace(/\//g, "-")}`,
              rule.author && `${zh ? "作者" : "Author"} ${rule.author}`,
            ]
              .filter(Boolean)
              .join("  ·  ")}
          </div>
        </div>
        <h1 className="text-[28px] md:text-[34px] leading-[1.2] text-ink text-balance">
          {rule.title}
        </h1>
        <p className="mt-4 text-[17px] leading-[1.6] text-graphite text-pretty">{leadSentence(rule.description)}</p>

        {keywords.length > 0 && (
          <p className="mt-5 font-data text-[11.5px] text-stone">{keywords.join("  ·  ")}</p>
        )}

        {/* Attributes as a record, one per line. Signs from components/Sign.tsx:
            obelos = the rule marks and reports, enforce = it may block,
            stigme = not yet stable, asteriskos = the same thing in another framework. */}
        <dl className="mt-8 border-t border-fog">
          {[
            { sign: null, label: zh ? "嚴重度" : "Severity", value: rule.severity, note: null },
            {
              sign: lanes.includes("enforce") ? ("enforce" as const) : lanes.length > 0 ? ("obelos" as const) : null,
              label: zh ? "車道" : "Lanes",
              value: lanes.length > 0 ? lanes.join(" · ") : zh ? "無（inert）" : "none (inert)",
              note: lanes.includes("enforce") ? (zh ? "可以用來攔截" : "can be used to block") : lanes.length > 0 ? (zh ? "比對到就標出、回報" : "marks and reports a match") : null,
            },
            { sign: maturity !== "stable" ? ("stigme" as const) : null, label: zh ? "成熟度" : "Maturity", value: maturity, note: maturity !== "stable" ? (zh ? "還沒定論" : "not yet settled") : null },
            { sign: null, label: zh ? "掃描目標" : "Scan target", value: rule.scanTarget ?? "—", note: null },
            { sign: null, label: zh ? "狀態" : "Status", value: rule.status ?? "—", note: null },
          ].map((row) => (
            <div key={row.label} className="grid grid-cols-[20px_96px_1fr] sm:grid-cols-[24px_140px_1fr] gap-x-2 items-baseline py-3 border-b border-fog">
              <span className="self-center text-ink">{row.sign && <Sign name={row.sign} size={14} />}</span>
              <dt className="text-[13px] text-stone">{row.label}</dt>
              <dd className={`text-[14px] ${lanes.length === 0 && row.label === (zh ? "車道" : "Lanes") ? "text-stone" : "text-ink"}`}>
                {row.value}
                {row.note && <span className="ml-3 text-[13px] text-stone">{row.note}</span>}
              </dd>
            </div>
          ))}
        </dl>

        {crosswalks.length > 0 && (
          <section className="mt-10" aria-labelledby="crosswalks-heading">
            <h2 id="crosswalks-heading" className="font-body text-[13px] text-stone mb-2">
              {zh ? "框架對照" : "Framework mappings"}
            </h2>
            <dl className="border-t border-fog">
              {crosswalks.map((cw) => (
                <div key={cw.name} className="grid grid-cols-[20px_1fr] sm:grid-cols-[24px_200px_1fr] gap-x-2 gap-y-1 items-baseline py-3 border-b border-fog">
                  <span className="self-center text-ink"><Sign name="asteriskos" size={16} /></span>
                  <dt className="text-[13px] text-ink" title={cw.help}>{cw.name}</dt>
                  <dd className="col-start-2 sm:col-start-3">
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
                  </dd>
                </div>
              ))}
            </dl>
            <p className="mt-3 text-[12px] text-stone">
              {zh ? "這些對應是 ATR 自己做的，框架方沒有審查或背書。" : "ATR wrote these mappings. The framework owners have not reviewed or endorsed them."}
            </p>
          </section>
        )}

        <section className="mt-10 pt-8 border-t border-fog">
          <h2 className="font-body text-[13px] text-stone mb-3">{zh ? "說明" : "Description"}</h2>
          <p className="text-[15px] text-graphite leading-[1.8]">{rule.description}</p>
          {rule.responseActions && rule.responseActions.length > 0 && (
            <div className="mt-6 flex flex-wrap items-baseline gap-x-4 gap-y-1">
              <span className="text-[13px] text-stone">{zh ? "建議回應" : "Suggested response"}</span>
              {rule.responseActions.map((action) => (
                <span key={action} className="font-data text-[12px] text-ink">
                  {action.replace(/_/g, " ")}
                </span>
              ))}
            </div>
          )}
          <div className="mt-6 font-data text-[11px] text-stone">
            {zh ? "作者：" : "Author: "}{rule.author}
            {rule.date && <> · {zh ? "建立" : "Created"} {rule.date.replace(/\//g, "-")}</>}
            {detail?.lastModified && <> · {zh ? "最後修改" : "Last modified"} {detail.lastModified}</>}
          </div>
        </section>

        <div className="mb-8" />
        {/* Validation stats — wild scan results */}
        {detail?.wildSamples !== undefined && (
          <div className="mb-8">
            <h2 className="font-display text-sm font-semibold text-ink mb-3">
              {zh ? "野外驗證" : "Tested in the wild"}
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
                    {zh ? "誤報率，野外樣本" : "False positive rate, wild samples"}
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
                {zh ? "偵測條件" : "Detection conditions"}
              </h2>
              {detail.detectionCombinator && (
                <span className="text-[13px] text-stone">
                  {zh ? "組合方式：" : "Combinator: "}{detail.detectionCombinator}
                </span>
              )}
            </div>
            <ol className="border-b border-fog">
              {detail.detectionConditions.map((c, i) => (
                <li key={i} className="border-t border-fog py-3 md:py-4">
                  <div className="flex items-start gap-3">
                    <span className="font-data text-[11px] text-mist shrink-0 mt-0.5">
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    <div className="min-w-0 flex-1">
                      {c.description && (
                        <div className="text-sm text-ink leading-[1.6] mb-1.5">{c.description}</div>
                      )}
                      <div className="font-data text-[10px] md:text-[11px] text-stone flex flex-wrap gap-x-3 gap-y-1">
                        {c.field && <span>{zh ? "欄位：" : "field: "}{c.field}</span>}
                        {c.operator && <span>{zh ? "運算子：" : "op: "}{c.operator}</span>}
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
              {zh ? "會觸發的攻擊範例" : "Attacks it catches"}
            </h2>
            <ol className="space-y-3">
              {detail.truePositives.map((tc, i) => (
                <li key={i} className="border-l-2 border-alert pl-4 py-2">
                  {tc.matched_condition && (
                    <div className="text-[13px] text-stone mb-2">
                      {zh ? "觸發條件：" : "Matches: "}{tc.matched_condition}
                    </div>
                  )}
                  <pre className="font-data text-xs text-alert-ink whitespace-pre-wrap [overflow-wrap:anywhere] leading-[1.7]">
                    {tc.input}
                  </pre>
                </li>
              ))}
            </ol>
            <p className="text-xs text-mist mt-3 leading-[1.7]">
              {zh
                ? "規則必須抓到的攻擊範例，很多是照公開回報的攻擊改寫的，有些是照攻擊的形狀寫出來的。範例跟規則一起版本化，當作回歸測試。之後改規則時，如果其中一個範例不再命中，一定看得出來。"
                : "Attack examples the rule must catch, many based on reported attacks and some written to match their shape. They are versioned with the rule as regression tests. If a later revision stops catching one, it shows."}
            </p>
          </div>
        )}

        {/* Negative examples — should NOT trigger */}
        {detail && detail.trueNegatives.length > 0 && (
          <div className="mb-8">
            <h2 className="font-display text-sm font-semibold text-ink mb-3">
              {zh ? "不會觸發的正常樣本" : "Benign inputs it leaves alone"}
            </h2>
            <ol className="space-y-3">
              {detail.trueNegatives.map((tc, i) => (
                <li key={i} className="border-l-2 border-fog pl-4 py-2">
                  {tc.description && (
                    <div className="text-[13px] text-stone mb-2">
                      {tc.description}
                    </div>
                  )}
                  <pre className="font-data text-xs text-graphite whitespace-pre-wrap [overflow-wrap:anywhere] leading-[1.7]">
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
              {zh ? "已知的誤報情境" : "Known false positives"}
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
              {zh ? "已記錄的繞過手法" : "Documented bypasses"}
            </h2>
            <ol className="space-y-3">
              {detail.evasionTests.map((ev, i) => (
                <li key={i} className="border-l-2 border-alert pl-4 py-2">
                  {ev.bypass_technique && (
                    <div className="text-[13px] text-stone mb-2">
                      {zh ? "手法：" : "Technique: "}{ev.bypass_technique.replace(/_/g, " ")}
                    </div>
                  )}
                  <pre className="font-data text-xs text-alert-ink whitespace-pre-wrap [overflow-wrap:anywhere] leading-[1.7] mb-2">
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
                ? "這些繞過手法都有公開紀錄。已知的限制就寫在規則本身。"
                : "These bypasses are documented in public. The rule itself lists its known limits."}
            </p>
          </div>
        )}

        {/* Full YAML preview */}
        {detail && (
          <div className="mb-8">
            <div className="flex items-baseline justify-between gap-2 flex-wrap mb-3">
              <h2 className="font-display text-sm font-semibold text-ink">
                {zh ? "完整 YAML" : "Full YAML"}
              </h2>
              <a
                href={`https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/${rule.filePath}`}
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline"
              >
                {zh ? "在 GitHub 編輯" : "Edit on GitHub"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
              </a>
            </div>
            <YamlBlock yaml={detail.rawYaml} zh={zh} />
          </div>
        )}

        {/* Revision history */}
        <div className="mb-10 border-t border-fog pt-6">
          <h2 className="font-display text-sm font-semibold text-ink mb-3">
            {zh ? "修訂紀錄" : "Revision history"}
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 border-t border-fog">
            {rule.date && (
              <div className="py-3 border-b border-fog">
                <div className="font-data text-xs text-stone mb-1">
                  {zh ? "建立於" : "Created"}
                </div>
                <div className="font-data text-sm text-ink">{rule.date.replace(/\//g, "-")}</div>
              </div>
            )}
            {detail?.lastModified && (
              <div className="py-3 border-b border-fog">
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
            {zh ? "到 GitHub 看完整的 commit 紀錄" : "Full commit history on GitHub"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
          </a>
        </div>

        {/* Related rules */}
        {related.length > 0 && (
          <div className="border-t border-fog pt-8">
            <h2 className="font-display text-sm font-semibold text-ink mb-4">
              {zh ? `更多${categoryDisplay}規則` : `More ${categoryDisplay} rules`}
            </h2>
            <div className="border-t border-fog">
              {related.map((r) => (
                <Link
                  key={r.id}
                  href={`${prefix}/rules/${r.id}`}
                  className="group py-3 border-b border-fog flex items-baseline gap-4"
                >
                  <span className="font-data text-xs text-mist shrink-0 w-28">{r.id}</span>
                  <span className="font-data text-xs text-stone shrink-0 w-20">{r.severity}</span>
                  <span className="text-sm text-ink truncate group-hover:underline underline-offset-4">{r.title}</span>
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
      </SheetRow>
      </>
    </>
    </Phrased>
  );
}

/** The rule file as published. Long files show their head first, and the rest
 *  opens in place under a "show all" control, so nothing is cut off silently. */
function YamlBlock({ yaml, zh }: { yaml: string; zh: boolean }) {
  const lines = yaml.replace(/\n+$/, "").split("\n");
  const PRE = "font-data text-[11px] md:text-xs text-graphite leading-[1.7] w-max min-w-full";
  if (lines.length <= YAML_HEAD_LINES + 10) {
    return (
      <div className="border-t border-ink pt-4">
        <ScrollX zh={zh}>
          <pre className={PRE}>{lines.join("\n")}</pre>
        </ScrollX>
      </div>
    );
  }
  const rest = lines.length - YAML_HEAD_LINES;
  return (
    <div className="border-t border-ink pt-4">
      <ScrollX zh={zh}>
        <pre className={PRE}>{lines.slice(0, YAML_HEAD_LINES).join("\n")}</pre>
      </ScrollX>
      <details className="group mt-2">
        <summary className="cursor-pointer list-none text-[13px] text-blue hover:underline underline-offset-4 [&::-webkit-details-marker]:hidden">
          <span className="group-open:hidden">{zh ? `顯示全部（還有 ${rest} 行）` : `Show all (${rest} more lines)`}</span>
          <span className="hidden group-open:inline">{zh ? "收起" : "Show less"}</span>
        </summary>
        <ScrollX zh={zh}>
          <pre className={PRE}>{lines.slice(YAML_HEAD_LINES).join("\n")}</pre>
        </ScrollX>
      </details>
    </div>
  );
}
