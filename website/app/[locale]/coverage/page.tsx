import { loadCoverageData } from "@/lib/coverage";
import { loadSiteStats, type SiteStats } from "@/lib/stats";
import {
  GARAK_BOTH_CLOSED_BOOK,
  HACKAPROMPT_CLOSED_BOOK,
  LANES_EXPLAINED,
  NO_ENFORCE_RECORD,
  PINT_CLOSED_BOOK,
  commonStamp,
  toFullWidth,
  count,
  findBenchmark,
  measuredStamp,
  recallLanes,
} from "@/lib/recall";
import { ABLATION_EXPLAINED, ablationLanes } from "@/lib/ablation";
import { Reveal } from "@/components/Reveal";
import { CountUp } from "@/components/CountUp";
import { StatsHydrator } from "@/components/StatsHydrator";
import { locales, t, type Locale } from "@/lib/i18n";
import Link from "next/link";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import Phrased from "@/components/Phrased";
import { Sign } from "@/components/Sign";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/coverage",
    title: "Coverage",
    description: "How ATR rules cover OWASP Agentic Top 10, OWASP AST10, SAFE-MCP and MITRE ATLAS.",
  });
}

const STATUS_COLORS: Record<string, string> = {
  STRONG: "bg-green/10 text-green",
  MODERATE: "bg-ink/10 text-blue",
  PARTIAL: "bg-medium/10 text-medium",
  GAP: "bg-stone/10 text-stone",
};

/** The mapping writes some statuses with a note, as "GAP (meta-concern)"; the colour keys on the first word. */
function statusColor(status: string): string {
  return STATUS_COLORS[status.split(" ")[0]] ?? "";
}

/** AST10 rows with no rule, and the ones the mapping marks as process or meta-level concerns. */
function ast10Gaps(rows: ReadonlyArray<{ id: string; ruleCount: number; status: string }>) {
  const none = rows.filter((m) => m.ruleCount === 0);
  return {
    none: none.map((m) => m.id),
    notPattern: none.filter((m) => /meta|process/i.test(m.status)).map((m) => m.id),
  };
}

export default async function CoveragePage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const coverage = loadCoverageData();
  const stats = loadSiteStats();
  const pint = findBenchmark(stats, "pint");
  const gaps = ast10Gaps(coverage.owaspAst10);

  return (
    <Phrased>
    <div className="pt-20 pb-16 px-6 md:px-14">
      <StatsHydrator />
      <Reveal>
        <div className="text-[13px] text-stone mb-3">{t(locale, "coverage.label")}</div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="text-[32px] md:text-[48px] leading-[1.12] tracking-[-0.01em] font-medium mb-2">
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
        <div className="border-t border-ink pt-5 mb-8">
          <div className="text-[13px] text-stone mb-3">
            {locale === "zh" ? "這些數字怎麼讀" : "How to read this"}
          </div>
          <p className="text-sm text-graphite leading-[1.7] mb-4">
            {locale === "zh"
              ? `下面每個召回率都標了車道。先列 hunt，量測有記錄 enforce 的，再接著列 enforce。${toFullWidth(LANES_EXPLAINED.zh)}誤報數字只在 hunt 車道量過。`
              : `Every recall below names its lane. Hunt comes first, then enforce wherever the measurement recorded it. ${LANES_EXPLAINED.en} False-positive figures were measured in the hunt lane only.`}
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
            <div className="text-[13px] text-stone mb-2">OWASP Agentic</div>
            <div className="font-data text-3xl font-bold text-ink">{stats.owaspAgentic}</div>
          </div>
          <div className="bg-paper p-6 text-center">
            <div className="text-[13px] text-stone mb-2">{locale === "zh" ? "SAF-MCP（候選）" : "SAF-MCP (candidate)"}</div>
            <div className="font-data text-3xl font-bold text-ink">{stats.safeMcp}</div>
          </div>
          <div className="bg-paper p-6 text-center">
            <div className="text-[13px] text-stone mb-2">OWASP AST10</div>
            <div className="font-data text-3xl font-bold text-ink">{stats.owaspAst10}</div>
          </div>
          {pint && (
            <div className="bg-paper p-6 text-center">
              <div className="text-[13px] text-stone mb-2">PINT F1 · hunt</div>
              <div className="font-data text-3xl font-bold text-ink"><CountUp target={Math.round(pint.f1 * 1000) / 10} /></div>
            </div>
          )}
        </div>
      </Reveal>

      {/* OWASP Agentic Top 10 */}
      <Reveal>
        <h2 className="font-display text-2xl font-medium tracking-[-1px] mb-1 mt-12">OWASP Agentic Top 10</h2>
        <p className="text-sm text-stone mb-6">{stats.owaspAgentic} {locale === "zh" ? "個類別，每一類都有實際會觸發的規則。不是打勾，是偵測。" : "categories, each backed by rules that fire. Detections, not a checklist."}</p>
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
                <span className={`font-data text-xs font-semibold uppercase tracking-wide px-2.5 py-1  ${statusColor(m.status)}`}>
                  {m.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </Reveal>

      {/* OWASP AST10 */}
      <Reveal>
        <h2 className="font-display text-2xl font-medium tracking-[-1px] mb-1 mt-12">OWASP Agentic Skills Top 10 (AST10)</h2>
        <p className="text-sm text-stone mb-6">
          {stats.owaspAst10} {locale === "zh" ? "個類別有規則覆蓋。" : "categories with rule coverage."}
          {gaps.none.length > 0 && (locale === "zh" ? `${gaps.none.join("、")} 沒有規則。` : ` ${gaps.none.join(" and ")} have no rule.`)}
          {gaps.notPattern.length > 0 && (locale === "zh" ? `對應表把 ${gaps.notPattern.join("、")} 列為流程或後設層面的問題，沒辦法用 pattern 偵測。` : ` The mapping lists ${gaps.notPattern.join(" and ")} as process or meta-level concerns, which pattern matching cannot detect.`)}
        </p>
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
                <span className={`font-data text-xs font-semibold uppercase tracking-wide px-2.5 py-1  ${statusColor(m.status)}`}>
                  {m.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </Reveal>

      {/* SAFE-MCP */}
      <Reveal>
        <h2 className="font-display text-2xl font-medium tracking-[-1px] mb-1 mt-12">SAF-MCP</h2>
        <p className="text-sm text-stone mb-4">{locale === "zh" ? `SAF Framework Model v2 的有效技術裡，有 ${stats.safeMcp} 項至少對到一條審查過的 ATR 規則，對應程度是 partial 或 adjacent。每一組對應都是看規則實際的 pattern 提出來的，兩位獨立審查者都同意才留下。這些是候選對照，SAF 沒有驗證過，也不代表偵測成效。adjacent 只補充旁邊的脈絡，光靠它偵測不到這項技術。沒有對應規則的技術，列在對應表最後面。` : `${stats.safeMcp} active SAF Framework Model v2 techniques have at least one reviewed ATR rule mapped to them, as partial or adjacent. Each pair was proposed from the rule's actual patterns and kept only when two independent reviewers agreed. These are candidate mappings. SAF has not validated them, and they make no claim about detection effectiveness. An adjacent rule adds supporting context. On its own it does not detect the technique. Techniques with no mapped rule are listed at the end of the mapping.`}</p>
        <a
          href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/SAFE-MCP-MAPPING.md"
          target="_blank"
          rel="noopener noreferrer"
          className="font-data text-sm text-blue hover:underline"
        >
          {locale === "zh" ? "到 GitHub 看完整的 SAFE-MCP 對應表" : "Full SAFE-MCP mapping on GitHub"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
        </a>
      </Reveal>

      {/* MITRE ATLAS */}
      <Reveal>
        <h2 className="font-display text-2xl font-medium tracking-[-1px] mb-1 mt-12">MITRE ATLAS</h2>
        <p className="text-sm text-stone mb-4">{locale === "zh" ? "每條規則的 YAML 都帶 MITRE ATLAS 參照。ATR 逐條把規則對到六個框架：ATLAS、OWASP Agentic、OWASP LLM、EU AI Act、NIST AI RMF、ISO 42001，這是其中一環。沒有對應的規則進不了 main，由 CI 把關。規則瀏覽器裡按戰術分組。" : "Every rule's YAML carries a MITRE ATLAS reference. It is part of how ATR maps each rule into six frameworks: ATLAS, OWASP Agentic, OWASP LLM, EU AI Act, NIST AI RMF and ISO 42001. A rule with no mapping does not reach main. CI enforces that. The rule explorer groups them by tactic."}</p>
        <Link
          href={`/${locale}/rules`}
          className="font-data text-sm text-blue hover:underline"
        >
          {locale === "zh" ? "看有 MITRE 對應的規則" : "Browse rules with MITRE mappings"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
        </Link>
      </Reveal>
      <p className="text-xs text-stone mt-12 max-w-2xl">
        {locale === "zh"
          ? "利益揭露：維護者創辦並控制 PANGUARD AI, INC.，這家公司販售以 ATR 為基礎的 agent 資安產品。"
          : "Interests: the maintainer founded and controls PANGUARD AI, INC., which sells AI agent security products built on ATR."}
      </p>
    </div>
    </Phrased>
  );
}

type Note = { name: string; verdict: string };

function pintNote(stats: SiteStats, zh: boolean): Note | null {
  const pint = findBenchmark(stats, "pint");
  if (!pint || pint.attacks === null || pint.benign === null || pint.falsePositives === null) return null;
  const fp = `${count(pint.falsePositives)} of ${count(pint.benign)}`;
  return {
    name: zh ? `PINT 格式（${count(pint.samples)} 個樣本）` : `PINT-format (${count(pint.samples)} samples)`,
    verdict: zh
      ? `ATR 在 PINT 格式語料上的召回率是 ${recallLanes(pint)}。語料共 ${count(pint.samples)} 個樣本，其中 ${count(pint.attacks)} 個是攻擊。hunt 車道 在 ${count(pint.benign)} 個良性樣本裡誤報 ${count(pint.falsePositives)} 次（${measuredStamp(pint, true, true)}）。${toFullWidth(PINT_CLOSED_BOOK.zh)}這份語料是 ATR 自己用 deepset 和 Lakera Gandalf 的資料組的，不是 Lakera 官方那份不公開的 PINT benchmark。只有一小部分規則會在上面觸發，請把它看成 prompt injection 這一家的分數，不是整體覆蓋率。`
      : `Recall on the PINT-format corpus is ${recallLanes(pint)}. The corpus has ${count(pint.samples)} samples, ${count(pint.attacks)} of them attacks. The hunt lane flagged ${fp} benign samples (${measuredStamp(pint, false)}). ${PINT_CLOSED_BOOK.en} ATR built this corpus itself from deepset and Lakera Gandalf data. It is not Lakera's official private PINT benchmark. Only a small subset of rules fire on it, so read it as a score for the prompt-injection family, not overall coverage.`,
  };
}

function hackapromptNote(stats: SiteStats, zh: boolean): Note | null {
  const hack = findBenchmark(stats, "hackaprompt");
  if (!hack) return null;
  const none = hack.enforce === null;
  const ablation = ablationLanes(hack);
  if (ablation !== null && hack.ablation !== null && hack.population !== null) {
    const n = hack.ablation.rulesRemoved;
    return {
      name: zh ? `HackAPrompt（${count(hack.samples)} 個樣本）` : `HackAPrompt (${count(hack.samples)} samples)`,
      verdict: zh
        ? `HackAPrompt 競賽有 ${count(hack.population)} 個 prompt，用固定種子從中抽出 ${count(hack.samples)} 個樣本，ATR 的召回率是 ${recallLanes(hack)}（${measuredStamp(hack, true, true)}）${none ? `；${toFullWidth(NO_ENFORCE_RECORD.zh)}` : ""}。這份子集有一部分屬於樣本內。有 ${n} 條規則在 YAML 裡註明出自 HackAPrompt，其中幾條就是從這份子集挖出來的。拿掉這 ${n} 條，同一批樣本的召回率是 ${ablation}，${toFullWidth(ABLATION_EXPLAINED.zh)}。這份語料 100% 是攻擊，沒有良性樣本，算不出 precision 或誤報率。別把它當成準確度的證據。`
        : `Recall on a seeded subset of ${count(hack.samples)} of the ${count(hack.population)} HackAPrompt competition prompts is ${recallLanes(hack)} (${measuredStamp(hack, false)})${none ? `; ${NO_ENFORCE_RECORD.en}` : ""}. The subset is partly in-sample. ${n} rules name HackAPrompt in their YAML, and several were mined from this subset. Without those ${n} rules the same samples score ${ablation}: ${ABLATION_EXPLAINED.en}. The corpus is 100% adversarial with no benign samples, so it cannot give a precision or false-positive figure. Do not read it as evidence of precision.`,
    };
  }
  return {
    name: zh ? `HackAPrompt（${count(hack.samples)} 個樣本）` : `HackAPrompt (${count(hack.samples)} samples)`,
    verdict: zh
      ? `ATR 在 ${count(hack.samples)} 個 HackAPrompt 競賽樣本上的召回率是 ${recallLanes(hack)}（${measuredStamp(hack, true, true)}）${none ? `；${toFullWidth(NO_ENFORCE_RECORD.zh)}` : ""}。${toFullWidth(HACKAPROMPT_CLOSED_BOOK.zh)}這份語料 100% 是攻擊，沒有良性樣本，算不出 precision 或誤報率。別把它當成準確度的證據。`
      : `Recall on the ${count(hack.samples)} HackAPrompt competition samples is ${recallLanes(hack)} (${measuredStamp(hack, false)})${none ? `; ${NO_ENFORCE_RECORD.en}` : ""}. ${HACKAPROMPT_CLOSED_BOOK.en} The corpus is 100% adversarial with no benign samples, so it cannot give a precision or false-positive figure. Do not read it as evidence of precision.`,
  };
}

function selfTestNote(stats: SiteStats, zh: boolean): Note | null {
  const self = findBenchmark(stats, "atr-self-test");
  if (!self || self.benign === null || self.falsePositives === null) return null;
  return {
    name: zh ? `自測（${count(self.samples)} 個樣本）` : `Self-test (${count(self.samples)} samples)`,
    verdict: zh
      ? `ATR 在 ${count(self.samples)} 個內部自測樣本上的召回率是 ${recallLanes(self)}。hunt 車道 在 ${count(self.benign)} 個良性樣本上誤報 ${count(self.falsePositives)} 次（${measuredStamp(self, true, true)}）。這份語料跟 SKILL.md benchmark 是分開的，而且是 ATR 自己做的，不能當成樣本外的證據。`
      : `Recall on the ${count(self.samples)} internal self-test samples is ${recallLanes(self)}. The hunt lane flagged ${count(self.falsePositives)} of ${count(self.benign)} benign samples (${measuredStamp(self, false)}). This corpus is separate from the SKILL.md benchmark. It is also in-house, so it is not out-of-sample evidence.`,
  };
}

function garakNote(stats: SiteStats, zh: boolean): Note | null {
  const garak = findBenchmark(stats, "garak");
  const full = findBenchmark(stats, "garak-full");
  if (!garak || !full) return null;
  return {
    name: zh ? `garak（in-the-wild ${count(garak.samples)} / 完整 ${count(full.samples)}）` : `garak (${count(garak.samples)} in-the-wild / ${count(full.samples)} full)`,
    verdict: zh
      ? `ATR 在 garak 的 in-the-wild 越獄集上，召回率是 ${recallLanes(garak)}，共 ${count(garak.samples)} 個 prompt。在完整的 garak probe 套件上是 ${recallLanes(full)}，共 ${count(full.samples)} 個 prompt（${commonStamp([garak, full], true, true)}）。${toFullWidth(GARAK_BOTH_CLOSED_BOOK.zh)}`
      : `Recall on garak's in-the-wild jailbreak set of ${count(garak.samples)} prompts is ${recallLanes(garak)}. On the full garak probe suite of ${count(full.samples)} prompts it is ${recallLanes(full)} (${commonStamp([garak, full], false)}). ${GARAK_BOTH_CLOSED_BOOK.en}`,
  };
}

/**
 * The "How to read this" notes, each figure from its measurement file with its
 * lane. A corpus with no measurement gets no note rather than a typed number.
 */
function readingNotes(stats: SiteStats, zh: boolean): Note[] {
  return [pintNote, hackapromptNote, selfTestNote, garakNote].flatMap((note) => note(stats, zh) ?? []);
}
