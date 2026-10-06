import { loadCoverageData } from "@/lib/coverage";
import { loadSiteStats } from "@/lib/stats";
import { Reveal } from "@/components/Reveal";
import { CountUp } from "@/components/CountUp";
import { StatsHydrator } from "@/components/StatsHydrator";
import { locales, t, type Locale } from "@/lib/i18n";
import Link from "next/link";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Coverage - ATR",
  description: "ATR coverage of OWASP Agentic Top 10, OWASP AST10, SAFE-MCP, and MITRE ATLAS frameworks.",
};

const STATUS_COLORS: Record<string, string> = {
  STRONG: "bg-green/10 text-green",
  MODERATE: "bg-blue/10 text-blue",
  PARTIAL: "bg-medium/10 text-medium",
  GAP: "bg-stone/10 text-stone",
};

export default async function CoveragePage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const coverage = loadCoverageData();
  const stats = loadSiteStats();

  return (
    <div className="pt-20 pb-16 px-6 max-w-[1120px] mx-auto">
      <StatsHydrator />
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">{t(locale, "coverage.label")}</div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="font-display text-[clamp(28px,4vw,44px)] font-extrabold tracking-[-2px] mb-2">
          {t(locale, "coverage.heading")}
        </h1>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-base text-stone font-light mb-10">
          {t(locale, "coverage.sub")}
        </p>
      </Reveal>

      {/* How to read this */}
      <Reveal delay={0.25}>
        <div className="bg-ash border border-fog p-5 md:p-6 mb-8">
          <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
            {locale === "zh" ? "如何解讀這些數字" : "How to read this"}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-graphite leading-[1.7]">
            {[
              {
                name: "PINT-format (850 samples)",
                verdict: locale === "zh"
                  ? "ATR 在 850 個 PINT 格式對抗性樣本上達到 65.4% 召回率，並在該語料的 399 個良性樣本上 0 誤報（ATR 3.5.12，量測於 2026-08-15）。這是自建語料（deepset + Lakera Gandalf），不是 Lakera 官方私有 PINT benchmark；只有一小部分規則會在這份語料上開火，請讀成 prompt injection 家族的分數，不是整體覆蓋率。"
                  : "ATR reaches 65.4% recall on 850 PINT-format adversarial samples, with zero false positives on that corpus's 399 benign samples (ATR 3.5.12, measured 2026-08-15). This is a self-built corpus (deepset + Lakera Gandalf), not Lakera's official private PINT benchmark; only a small subset of rules fire on it, so read it as a prompt-injection-family score rather than overall coverage.",
              },
              {
                name: "HackAPrompt (4,780 samples)",
                verdict: locale === "zh"
                  ? "ATR 在 4,780 個 HackAPrompt 競賽樣本上達到 69.6% 召回率（ATR 3.5.0，量測於 2026-06-16）。這份語料 100% 對抗性、沒有良性樣本，所以它算不出 precision 或誤報率——別把它當精準度證據。"
                  : "ATR catches 69.6% of the 4,780 HackAPrompt competition samples (ATR 3.5.0, measured 2026-06-16). The corpus is 100% adversarial with no benign population, so it cannot yield a precision or false-positive figure — do not read it as precision evidence.",
              },
              {
                name: "Self-test (341 samples)",
                verdict: locale === "zh"
                  ? "ATR 在 341 個內部自測樣本上達到 96.6% 召回率、0 誤報（ATR 3.5.12，量測於 2026-08-15）——這是與 SKILL.md benchmark 分開的獨立語料，且是自家語料,不能當成樣本外證據。"
                  : "ATR reaches 96.6% recall with zero false positives on 341 internal self-test samples (ATR 3.5.12, measured 2026-08-15) — a separate corpus from the SKILL.md benchmark, and an in-house one, so it is not out-of-sample evidence.",
              },
              {
                name: "garak (650 in-the-wild / 3,475 full)",
                verdict: locale === "zh"
                  ? "ATR 對 garak in-the-wild jailbreak 集（650 個 prompt）達到 92.3% 召回率；對完整 23-probe garak 套件（3,475 個 prompt）為 57.2%（皆為 ATR 3.5.12，量測於 2026-08-15）。"
                  : "ATR reaches 92.3% recall on garak's in-the-wild jailbreak set (650 prompts), and 57.2% on the full 23-probe garak suite (3,475 prompts) — both at ATR 3.5.12, measured 2026-08-15.",
              },
            ].map((item) => (
              <div key={item.name}>
                <div className="font-data text-xs text-blue font-semibold mb-1">{item.name}</div>
                <p>{item.verdict}</p>
              </div>
            ))}
          </div>
        </div>
      </Reveal>

      {/* Summary cards */}
      <Reveal delay={0.3}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-fog mb-12">
          <div className="bg-paper p-6 text-center">
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">OWASP Agentic</div>
            <div className="font-data text-3xl font-bold text-ink">{stats.owaspAgentic}</div>
          </div>
          <div className="bg-paper p-6 text-center">
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">SAFE-MCP</div>
            <div className="font-data text-3xl font-bold text-ink">{stats.safeMcp}</div>
          </div>
          <div className="bg-paper p-6 text-center">
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">OWASP AST10</div>
            <div className="font-data text-3xl font-bold text-ink">{stats.owaspAst10}</div>
          </div>
          <div className="bg-paper p-6 text-center">
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">PINT F1</div>
            <div className="font-data text-3xl font-bold text-ink"><CountUp target={stats.pintF1} liveKey="pintF1" /></div>
          </div>
        </div>
      </Reveal>

      {/* OWASP Agentic Top 10 */}
      <Reveal>
        <h2 className="font-display text-2xl font-extrabold tracking-[-1px] mb-1 mt-12">OWASP Agentic Top 10</h2>
        <p className="text-sm text-stone mb-6">{coverage.owaspAgenticCovered}/10 {locale === "zh" ? "個類別都有開火的規則——不是打勾，是偵測。" : "categories, each backed by rules that fire — not a checklist, detections."}</p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog">
          <div className="hidden md:grid grid-cols-[100px_1fr_100px_100px] bg-ash border-b border-fog">
            <div className="px-4 py-2.5 font-data text-xs text-stone uppercase tracking-wider font-semibold">ID</div>
            <div className="px-4 py-2.5 font-data text-xs text-stone uppercase tracking-wider font-semibold">{locale === "zh" ? "類別" : "Category"}</div>
            <div className="px-4 py-2.5 font-data text-xs text-stone uppercase tracking-wider font-semibold">{locale === "zh" ? "規則數" : "Rules"}</div>
            <div className="px-4 py-2.5 font-data text-xs text-stone uppercase tracking-wider font-semibold">{locale === "zh" ? "狀態" : "Status"}</div>
          </div>
          {coverage.owaspAgentic.map((m) => (
            <div key={m.id} className="grid grid-cols-1 md:grid-cols-[100px_1fr_100px_100px] border-b border-fog last:border-b-0 hover:bg-ash/50 transition-colors">
              <div className="px-4 py-3 font-data text-sm text-blue">{m.id}</div>
              <div className="px-4 py-3 text-sm text-ink">{m.category}</div>
              <div className="px-4 py-3 font-data text-sm text-ink">{m.ruleCount}</div>
              <div className="px-4 py-3">
                <span className={`font-data text-xs font-semibold uppercase tracking-wide px-2.5 py-1 rounded-sm ${STATUS_COLORS[m.status] ?? ""}`}>
                  {m.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </Reveal>

      {/* OWASP AST10 */}
      <Reveal>
        <h2 className="font-display text-2xl font-extrabold tracking-[-1px] mb-1 mt-12">OWASP Agentic Skills Top 10 (AST10)</h2>
        <p className="text-sm text-stone mb-6">{coverage.ast10Covered}/10 {locale === "zh" ? "個類別有規則覆蓋。3 個類別屬於流程/元層級（無法用模式偵測）。" : "categories with rule coverage. 3 categories are process/meta-level (not pattern-detectable)."}</p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog">
          <div className="hidden md:grid grid-cols-[100px_1fr_100px_100px] bg-ash border-b border-fog">
            <div className="px-4 py-2.5 font-data text-xs text-stone uppercase tracking-wider font-semibold">ID</div>
            <div className="px-4 py-2.5 font-data text-xs text-stone uppercase tracking-wider font-semibold">{locale === "zh" ? "類別" : "Category"}</div>
            <div className="px-4 py-2.5 font-data text-xs text-stone uppercase tracking-wider font-semibold">{locale === "zh" ? "規則數" : "Rules"}</div>
            <div className="px-4 py-2.5 font-data text-xs text-stone uppercase tracking-wider font-semibold">{locale === "zh" ? "狀態" : "Status"}</div>
          </div>
          {coverage.owaspAst10.map((m) => (
            <div key={m.id} className="grid grid-cols-1 md:grid-cols-[100px_1fr_100px_100px] border-b border-fog last:border-b-0 hover:bg-ash/50 transition-colors">
              <div className="px-4 py-3 font-data text-sm text-blue">{m.id}</div>
              <div className="px-4 py-3 text-sm text-ink">{m.category}</div>
              <div className="px-4 py-3 font-data text-sm text-ink">{m.ruleCount}</div>
              <div className="px-4 py-3">
                <span className={`font-data text-xs font-semibold uppercase tracking-wide px-2.5 py-1 rounded-sm ${STATUS_COLORS[m.status] ?? ""}`}>
                  {m.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </Reveal>

      {/* SAFE-MCP */}
      <Reveal>
        <h2 className="font-display text-2xl font-extrabold tracking-[-1px] mb-1 mt-12">SAFE-MCP</h2>
        <p className="text-sm text-stone mb-4">{locale === "zh" ? "85 項 MCP 攻擊技術中，78 項有對應的偵測規則（91.8%）——其餘 7 項是已知缺口，未補的我們直說。對應表正隨類別重整持續校訂。" : "78 of 85 MCP attack techniques are backed by a detection rule (91.8%) — the remaining 7 are known gaps, stated plainly rather than papered over. Mapping is revised continuously as categories are reconciled."}</p>
        <a
          href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/SAFE-MCP-MAPPING.md"
          target="_blank"
          rel="noopener noreferrer"
          className="font-data text-sm text-blue hover:underline"
        >
          {locale === "zh" ? "在 GitHub 查看完整 SAFE-MCP 對應表" : "View full SAFE-MCP mapping on GitHub"} &rarr;
        </a>
      </Reveal>

      {/* MITRE ATLAS */}
      <Reveal>
        <h2 className="font-display text-2xl font-extrabold tracking-[-1px] mb-1 mt-12">MITRE ATLAS</h2>
        <p className="text-sm text-stone mb-4">{locale === "zh" ? "每條規則的 YAML 都帶有 MITRE ATLAS 參照——這是 ATR 對六個框架（ATLAS、OWASP Agentic、OWASP LLM、EU AI Act、NIST AI RMF、ISO 42001）逐條對應的一部分。沒有對應的規則進不了 main，由 CI 強制。在規則瀏覽器中依戰術分組。" : "Every rule's YAML carries a MITRE ATLAS reference — part of ATR's per-rule mapping into six frameworks (ATLAS, OWASP Agentic, OWASP LLM, EU AI Act, NIST AI RMF, ISO 42001). A rule with no mapping does not reach main; CI enforces it. Grouped by tactic in the rule explorer."}</p>
        <Link
          href={`/${locale}/rules`}
          className="font-data text-sm text-blue hover:underline"
        >
          {locale === "zh" ? "瀏覽含 MITRE 對應的規則" : "Browse rules with MITRE mappings"} &rarr;
        </Link>
      </Reveal>
    </div>
  );
}
