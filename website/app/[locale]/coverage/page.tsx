import { loadCoverageData } from "@/lib/coverage";
import { loadSiteStats, type SiteStats } from "@/lib/stats";
import {
  GARAK_BOTH_CLOSED_BOOK,
  LANES_EXPLAINED,
  NO_ENFORCE_RECORD,
  commonStamp,
  count,
  findBenchmark,
  measuredStamp,
  recallLanes,
} from "@/lib/recall";
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
  const pint = findBenchmark(stats, "pint");

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
          <p className="text-sm text-graphite leading-[1.7] mb-4">
            {locale === "zh"
              ? `每個召回率都列兩個 lane,先 hunt 後 enforce。${LANES_EXPLAINED.zh}誤報數字只在 hunt lane 量測。`
              : `Every recall below names two lanes, hunt first. ${LANES_EXPLAINED.en} False-positive figures are measured in the hunt lane only.`}
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-graphite leading-[1.7]">
            {readingNotes(stats, locale === "zh").map((item) => (
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
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-2">PINT F1 · hunt</div>
            {pint && <div className="font-data text-3xl font-bold text-ink"><CountUp target={Math.round(pint.f1 * 1000) / 10} /></div>}
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

type Note = { name: string; verdict: string };

function pintNote(stats: SiteStats, zh: boolean): Note | null {
  const pint = findBenchmark(stats, "pint");
  if (!pint || pint.attacks === null || pint.benign === null) return null;
  const fp = count(pint.falsePositives ?? 0);
  return {
    name: `PINT-format (${count(pint.samples)} samples)`,
    verdict: zh
      ? `ATR 在 PINT 格式語料(${count(pint.samples)} 個樣本,其中 ${count(pint.attacks)} 個是攻擊)上的召回率是 ${recallLanes(pint)};hunt lane 在 ${count(pint.benign)} 個良性樣本上誤報 ${fp} 次(${measuredStamp(pint, true)})。這是自建語料(deepset + Lakera Gandalf),不是 Lakera 官方私有 PINT benchmark;只有一小部分規則會在這份語料上開火,請讀成 prompt injection 家族的分數,不是整體覆蓋率。`
      : `Recall on the PINT-format corpus (${count(pint.samples)} samples, ${count(pint.attacks)} of them attacks) is ${recallLanes(pint)}, with ${fp} false positives on its ${count(pint.benign)} benign samples in the hunt lane (${measuredStamp(pint, false)}). This is a self-built corpus (deepset + Lakera Gandalf), not Lakera's official private PINT benchmark; only a small subset of rules fire on it, so read it as a prompt-injection-family score rather than overall coverage.`,
  };
}

function hackapromptNote(stats: SiteStats, zh: boolean): Note | null {
  const hack = findBenchmark(stats, "hackaprompt");
  if (!hack) return null;
  const none = hack.enforce === null;
  return {
    name: `HackAPrompt (${count(hack.samples)} samples)`,
    verdict: zh
      ? `ATR 在 ${count(hack.samples)} 個 HackAPrompt 競賽樣本上的召回率是 ${recallLanes(hack)}(${measuredStamp(hack, true)})${none ? `;${NO_ENFORCE_RECORD.zh}` : ""}。這份語料 100% 對抗性、沒有良性樣本,所以它算不出 precision 或誤報率——別把它當精準度證據。`
      : `Recall on the ${count(hack.samples)} HackAPrompt competition samples is ${recallLanes(hack)} (${measuredStamp(hack, false)})${none ? `; ${NO_ENFORCE_RECORD.en}` : ""}. The corpus is 100% adversarial with no benign population, so it cannot yield a precision or false-positive figure — do not read it as precision evidence.`,
  };
}

function selfTestNote(stats: SiteStats, zh: boolean): Note | null {
  const self = findBenchmark(stats, "atr-self-test");
  if (!self) return null;
  const fp = count(self.falsePositives ?? 0);
  return {
    name: `Self-test (${count(self.samples)} samples)`,
    verdict: zh
      ? `ATR 在 ${count(self.samples)} 個內部自測樣本上的召回率是 ${recallLanes(self)},hunt lane 誤報 ${fp} 次(${measuredStamp(self, true)})——這是與 SKILL.md benchmark 分開的獨立語料,且是自家語料,不能當成樣本外證據。`
      : `Recall on the ${count(self.samples)} internal self-test samples is ${recallLanes(self)}, with ${fp} false positives in the hunt lane (${measuredStamp(self, false)}) — a separate corpus from the SKILL.md benchmark, and an in-house one, so it is not out-of-sample evidence.`,
  };
}

function garakNote(stats: SiteStats, zh: boolean): Note | null {
  const garak = findBenchmark(stats, "garak");
  const full = findBenchmark(stats, "garak-full");
  if (!garak || !full) return null;
  return {
    name: `garak (${count(garak.samples)} in-the-wild / ${count(full.samples)} full)`,
    verdict: zh
      ? `ATR 在 garak in-the-wild 越獄集(${count(garak.samples)} 個 prompt)上的召回率是 ${recallLanes(garak)};在完整 garak probe 套件(${count(full.samples)} 個 prompt)上是 ${recallLanes(full)}(${commonStamp([garak, full], true)})。${GARAK_BOTH_CLOSED_BOOK.zh}`
      : `Recall on garak's in-the-wild jailbreak set (${count(garak.samples)} prompts) is ${recallLanes(garak)}, and on the full garak probe suite (${count(full.samples)} prompts) ${recallLanes(full)} (${commonStamp([garak, full], false)}). ${GARAK_BOTH_CLOSED_BOOK.en}`,
  };
}

/**
 * The "How to read this" notes, each figure from its measurement file with its
 * lane. A corpus with no measurement gets no note rather than a typed number.
 */
function readingNotes(stats: SiteStats, zh: boolean): Note[] {
  return [pintNote, hackapromptNote, selfTestNote, garakNote].flatMap((note) => note(stats, zh) ?? []);
}
