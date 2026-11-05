import { Reveal } from "@/components/Reveal";
import { CountUp } from "@/components/CountUp";
import { StatsHydrator } from "@/components/StatsHydrator";
import { loadSiteStats, type BenchmarkMeasurement } from "@/lib/stats";
import { PINT_CLOSED_BOOK, count, findBenchmark, measuredStamp, pct, pctHunt, toFullWidth } from "@/lib/recall";
import { MetricCell, RecallCell } from "@/components/LaneFigures";
import { loadVersionLabels, npmReleaseText } from "@/lib/versions";
import { locales, t, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";

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
    path: "/research",
    title: "Research",
    description: "Papers, benchmark results, ecosystem scan data and known limits for ATR.",
  });
}

export default async function ResearchPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const stats = loadSiteStats();
  const versions = await loadVersionLabels();
  const zh = locale === "zh";
  const pintRun = findBenchmark(stats, "pint");
  const selfTestRun = findBenchmark(stats, "atr-self-test");
  const skillRun = findBenchmark(stats, "skill-benchmark");

  return (
    <div className="pt-20 pb-16 px-6 max-w-[1120px] mx-auto">
      <StatsHydrator />
      <Reveal>
        <div className="text-[13px] text-stone mb-3">{t(locale, "research.label")}</div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="text-[32px] md:text-[44px] leading-[1.12] tracking-[-0.03em] font-medium mb-2">
          {t(locale, "research.heading")}
        </h1>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-base text-stone font-light mb-10">
          {t(locale, "research.sub")}
        </p>
      </Reveal>

      {/* Papers */}
      <Reveal>
        <div className="grid grid-cols-1 gap-px bg-fog mb-8 border border-fog">
          {/* Main paper */}
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-center gap-2 mb-2">
              <span className="font-data text-xs text-mist">{zh ? "2026 年 4 月 · 25 頁 · 67 篇參考文獻" : "April 2026 · 25 pages · 67 references"}</span>
            </div>
            <div className="font-display text-base font-semibold text-ink mb-1">
              {locale === "zh"
                ? "信任的崩塌：自主 AI Agent 時代的安全架構"
                : "The Collapse of Trust: Security Architecture for the Age of Autonomous AI Agents"}
            </div>
            <p className="text-sm text-stone mb-3">
              {locale === "zh"
                ? `ATR 為什麼要存在，這篇從頭講。agent 一旦能自己動手，信任就不能再預設，偵測得變成一層標準，任何人都能查核，由社群維護、發版。內容包括 RFC-001 品質規範、野外生態系掃描，以及讓標準持續更新、不停在一次快照的做法。論文裡的掃描數字已經過時。現在能引用的是：掃描 ${stats.megaScanTotal.toLocaleString()} 個項目，標記 ${stats.megaScanFlagged.toLocaleString()} 個（engine v2.0.0，${stats.megaScanDate}）。`
                : `Why ATR exists, argued from the start. Once agents act on their own, trust can't be assumed, and detection has to become a standard layer that anyone can audit and the community versions and maintains. It covers the RFC-001 quality specification, the in-the-wild ecosystem scan, and how the standard keeps updating instead of stopping at one snapshot. The scan figures in the paper are out of date. The ones to cite are ${stats.megaScanTotal.toLocaleString()} items scanned and ${stats.megaScanFlagged.toLocaleString()} flagged (engine v2.0.0, ${stats.megaScanDate}).`}
            </p>
            <div className="flex flex-wrap gap-3">
              <a href="https://doi.org/10.5281/zenodo.19178002" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">Zenodo (DOI)</a>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/paper/ATR-Paper.pdf" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">PDF (GitHub)</a>
              <span className="font-data text-xs text-stone">SSRN: 6457179</span>
            </div>
          </div>

          {/* Malware campaign research report */}
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-center gap-2 mb-2">
              <span className="font-data text-xs bg-critical/10 text-critical px-2 py-0.5 ">{locale === "zh" ? "新" : "NEW"}</span>
              <span className="font-data text-xs text-mist">{zh ? "2026 年 4 月" : "April 2026"}</span>
            </div>
            <div className="font-display text-base font-semibold text-ink mb-1">
              {locale === "zh"
                ? "OpenClaw registry 的協同惡意軟體行動：三個大量發布的攻擊帳號"
                : "A Coordinated Malware Campaign in the OpenClaw Registry: Three Mass-Publishing Threat Accounts"}
            </div>
            <p className="text-sm text-stone mb-3">
              {locale === "zh"
                ? `野外掃描標記了 ${stats.megaScanFlagged.toLocaleString()} 個項目，集中在三個大量發布的帳號：hightower6eu 發了 354 個 skill，sakaen736jih 212 個，52yuanchangxing 137 個。payload 有加密 zip、base64 包起來的 shell 指令，還有 C2 callback。已經通報 NousResearch，也列進公開黑名單。報告是以發布者為單位下判定，套用到整個帳號，不是一個檔一個檔判讀。報告裡的總數已經過時，請以本頁的數字為準。`
                : `The wild scan flagged ${stats.megaScanFlagged.toLocaleString()} items, clustered in three accounts that published in bulk: hightower6eu (354 skills), sakaen736jih (212) and 52yuanchangxing (137). Payloads include encrypted zips, base64 shell commands and C2 callbacks. They were reported to NousResearch and added to a public blacklist. The verdicts are made per publisher and applied to the whole account, not file by file. The report's totals are out of date; use the figures on this page.`}
            </p>
            <div className="flex flex-wrap gap-3">
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/research/openclaw-malware-campaign-2026-04.md" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">{locale === "zh" ? "完整報告（英文）" : "Full report (English)"}</a>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/research/openclaw-malware-campaign-2026-04-zh.md" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">{locale === "zh" ? "完整報告（中文）" : "Full report (Chinese)"}</a>
            </div>
          </div>

          {/* Mega scan paper */}
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-center gap-2 mb-2">
              <span className="font-data text-xs text-mist">{zh ? "2026 年 4 月 · 7 頁 · 32 篇參考文獻" : "April 2026 · 7 pages · 32 references"}</span>
            </div>
            <div className="font-display text-base font-semibold text-ink mb-1">
              A Large-Scale Security Audit of the AI Agent Ecosystem
            </div>
            <p className="text-sm text-stone mb-3">
              {locale === "zh"
                ? `在五個公開 registry 上，大規模掃描 agent skill 和 MCP 定義。找到三個協同攻擊的帳號。光是一條規則 ATR-2026-00121（透過工具描述竊取憑證），就佔了被標記 skill 的 53%。論文裡的總數已經過時，現在能引用的是：掃描 ${stats.megaScanTotal.toLocaleString()} 個項目，標記 ${stats.megaScanFlagged.toLocaleString()} 個（engine v2.0.0，${stats.megaScanDate}）。`
                : `A large scan of agent skills and MCP definitions across five public registries. It found three coordinated threat accounts. One rule, ATR-2026-00121 (credential access through tool descriptions), accounts for 53% of flagged skills. The paper's totals are out of date. The ones to cite are ${stats.megaScanTotal.toLocaleString()} items scanned and ${stats.megaScanFlagged.toLocaleString()} flagged (engine v2.0.0, ${stats.megaScanDate}).`}
            </p>
            <div className="flex flex-wrap gap-3">
              <a href="https://doi.org/10.5281/zenodo.19476480" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">Zenodo (DOI)</a>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/paper/ATR-MegaScan-2026.pdf" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">PDF (GitHub)</a>
            </div>
          </div>

          {/* MCP attack surface paper */}
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-center gap-2 mb-2">
              <span className="font-data text-xs bg-critical/10 text-critical px-2 py-0.5 ">{locale === "zh" ? "新" : "NEW"}</span>
              <span className="font-data text-xs text-mist">{zh ? "2026 年 4 月 · 18 頁 · 30 篇參考文獻" : "April 2026 · 18 pages · 30 references"}</span>
            </div>
            <div className="font-display text-base font-semibold text-ink mb-1">
              30 CVEs in 60 Days: The Model Context Protocol Attack Surface
            </div>
            <p className="text-sm text-stone mb-3">
              {locale === "zh"
                ? "用實際資料拆解 MCP 的攻擊面。60 天出了 30 個 CVE，38% 完全沒有認證。論文把攻擊分成 7 類，另外掃了 53K 個生態系項目。這個速度，是 Docker 頭兩年的 15 倍。"
                : "The MCP attack surface, measured. 30 CVEs in 60 days, and 38% with no authentication at all. The paper sorts attacks into 7 classes and scans 53K ecosystem items. That pace is 15x faster than Docker's first two years."}
            </p>
            <div className="flex flex-wrap gap-3">
              <a href="https://doi.org/10.5281/zenodo.19476482" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">Zenodo (DOI)</a>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/paper/MCP-Attack-Surface-2026.pdf" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">PDF (GitHub)</a>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Benchmarks */}
      <Reveal>
        <h2 className="font-display text-2xl font-medium tracking-[-1px] mb-1 mt-10">{t(locale, "research.benchmarks")}</h2>
        <p className="text-sm text-stone mb-6">{t(locale, "research.benchmarks.sub")}</p>
      </Reveal>
      {pintRun && selfTestRun && (
        <Reveal delay={0.1}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog mb-8">
            {/* PINT */}
            <div className="bg-paper p-6">
              <div className="text-[13px] text-stone mb-4">{t(locale, "research.pint")}</div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <MetricCell value={pintRun.precision} label={`${t(locale, "research.precision")} · hunt`} />
                <RecallCell m={pintRun} label={t(locale, "research.recall")} zh={zh} />
                <MetricCell value={pintRun.f1} label="F1 · hunt" plain />
              </div>
              <div className="font-data text-xs text-stone mt-3">
                {count(pintRun.samples)} {zh ? "個樣本" : "samples"} · {measuredStamp(pintRun, zh)}
              </div>
              <p className="text-xs text-mist mt-2 leading-[1.7]">
                {zh
                  ? `這不是 Lakera 官方的 PINT benchmark。官方語料不公開，規模大約是這份的 5 倍。這份是照 PINT 格式自己組的，共 ${count(pintRun.samples)} 個樣本，來自 deepset/prompt-injections（660）和 Lakera/gandalf_ignore_instructions（190）。會在上面觸發的規則只有一小部分，大部分偵測又來自同一條規則。所以請把它當成 prompt injection 這一類的分數，不是 ATR 的整體覆蓋率。${toFullWidth(PINT_CLOSED_BOOK.zh)}`
                  : `This is not Lakera's official PINT benchmark. That corpus is private and about 5x larger. This one is self-built in PINT's format: ${count(pintRun.samples)} samples from deepset/prompt-injections (660) and Lakera/gandalf_ignore_instructions (190). Only a small subset of rules fire on it, and one rule accounts for most detections. Read it as a score for the prompt-injection family, not for ATR's overall coverage. ${PINT_CLOSED_BOOK.en}`}
              </p>
            </div>
            {/* Self-test */}
            <div className="bg-paper p-6">
              <div className="text-[13px] text-stone mb-4">{zh ? "回歸檢查：ATR 自己的測試案例" : "Regression check on ATR's own test cases"}</div>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <MetricCell value={selfTestRun.precision} label="Precision · hunt" />
                <RecallCell m={selfTestRun} label="Recall" zh={zh} />
                <div>
                  <div className="font-data text-2xl font-bold text-ink">{count(selfTestRun.samples)}</div>
                  <div className="text-xs text-stone">{zh ? "樣本數" : "Samples"}</div>
                </div>
              </div>
              <div className="font-data text-xs text-stone mt-3">{measuredStamp(selfTestRun, zh)}</div>
              <p className="text-xs text-mist mt-2 leading-[1.7]">
                {zh
                  ? "這份語料有一部分就是規則自己的 true positive，分數高是應該的。它檢查的是規則還抓不抓得到當初要抓的東西。它不是基準測試，不要拿來跟左邊比。"
                  : "This corpus is built partly from the rules' own true positives, so a high score is expected. It checks that the rules still catch what they were written to catch. It is not a benchmark and does not compare with the corpus on the left."}
              </p>
            </div>
          </div>
        </Reveal>
      )}
      {pintRun && (
        <Reveal delay={0.2}>
          <p className="text-sm text-stone mb-8">
            {pintRun.enforce
              ? t(locale, "research.gap_note", {
                  precision: pct(pintRun.precision),
                  recall: pctHunt(pintRun.recall),
                  enforce: pct(pintRun.enforce.recall),
                })
              : t(locale, "research.gap_note_hunt_only", { precision: pct(pintRun.precision), recall: pctHunt(pintRun.recall) })}
          </p>
        </Reveal>
      )}

      {/* SKILL.md Benchmark */}
      {skillRun && <SkillBenchmark run={skillRun} zh={zh} />}

      {/* Ecosystem Scan Data */}
      <Reveal>
        <h2 className="font-display text-2xl font-medium tracking-[-1px] mb-1 mt-10">{t(locale, "research.scan")}</h2>
        <p className="text-sm text-stone mb-6">{t(locale, "research.scan.sub")}</p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog mb-8">
          <div className="bg-paper p-6">
            <div className="text-[13px] text-stone mb-3">{locale === "zh" ? "野外生態系掃描（5 個來源）" : "Wild ecosystem scan (5 sources)"}</div>
            <div className="font-data text-3xl font-bold text-ink mb-1"><CountUp target={stats.megaScanTotal} useComma liveKey="megaScanTotal" /></div>
            <div className="text-sm text-stone mb-3">{locale === "zh" ? "個 skill 掃過" : "skills scanned"}</div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-center">
              <div>
                <div className="font-data text-lg font-bold text-critical"><CountUp target={stats.megaScanCritical} useComma liveKey="megaScanCritical" /></div>
                <div className="text-xs text-stone">CRITICAL</div>
              </div>
              <div>
                <div className="font-data text-lg font-bold text-high"><CountUp target={stats.megaScanHigh} useComma liveKey="megaScanHigh" /></div>
                <div className="text-xs text-stone">HIGH</div>
              </div>
              <div>
                <div className="font-data text-lg font-bold text-ink"><CountUp target={stats.megaScanFlagged} useComma liveKey="megaScanFlagged" /></div>
                <div className="text-xs text-stone">{locale === "zh" ? "總標記數" : "Total flagged"}</div>
              </div>
            </div>
          </div>
          <div className="bg-paper p-6">
            <div className="text-[13px] text-stone mb-3">{zh ? "ClawHub registry 掃描" : "ClawHub registry scan"}</div>
            <div className="font-data text-3xl font-bold text-ink mb-1"><CountUp target={stats.clawHubCrawled} useComma /></div>
            <div className="text-sm text-stone mb-3">{locale === "zh" ? "個 skill 爬下來" : "skills crawled"}</div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-center">
              <div>
                <div className="font-data text-lg font-bold text-critical"><CountUp target={stats.clawHubCritical} /></div>
                <div className="text-xs text-stone">CRITICAL</div>
              </div>
              <div>
                <div className="font-data text-lg font-bold text-high"><CountUp target={stats.clawHubHigh} useComma /></div>
                <div className="text-xs text-stone">HIGH</div>
              </div>
              <div>
                <div className="font-data text-lg font-bold text-ink"><CountUp target={stats.clawHubScanned} useComma /></div>
                <div className="text-xs text-stone">{locale === "zh" ? "含原始碼" : "With source code"}</div>
              </div>
            </div>
          </div>
        </div>
      </Reveal>
      <Reveal delay={0.15}>
        <p className="text-sm text-graphite leading-[1.7] mb-6 max-w-[760px]">
          {locale === "zh"
            ? `上面的野外掃描是 ${stats.megaScanDate} 跑的。規則的來源還有 CVE 與安全公告的掃描、benchmark 漏抓的樣本，以及貢獻者。規則從 462 條長到現在 main 上的 ${stats.ruleCount} 條生效規則，另有 ${stats.ruleInertCount} 條 inert（${npmReleaseText(versions, true)}，頁面產生於 ${versions.generatedAt}）。`
            : `The wild scan above ran on ${stats.megaScanDate}. Rules also come from CVE and advisory sweeps, from benchmark misses and from contributors. The ruleset has grown from 462 to the ${stats.ruleCount} effective rules on main today, plus ${stats.ruleInertCount} inert (${npmReleaseText(versions, false)}, as of ${versions.generatedAt}).`}
        </p>
      </Reveal>
      <Reveal delay={0.2}>
        <div className="flex gap-4 mb-8">
          <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/data/clawhub-scan/ecosystem-report.csv" target="_blank" rel="noopener noreferrer" className="font-data text-sm text-blue hover:underline">
            {t(locale, "research.download.csv")} &rarr;
          </a>
          <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/data/clawhub-scan/ecosystem-stats.json" target="_blank" rel="noopener noreferrer" className="font-data text-sm text-blue hover:underline">
            {t(locale, "research.download.json")} &rarr;
          </a>
        </div>
      </Reveal>

      {/* Methodology */}
      <Reveal>
        <h2 className="font-display text-2xl font-medium tracking-[-1px] mb-1 mt-10">
          {locale === "zh" ? "數字怎麼來的" : "How the numbers are made"}
        </h2>
        <p className="text-sm text-stone mb-6">
          {locale === "zh"
            ? "數字要別人重跑得出來，才算數。這裡的研究都能重跑。資料集、掃描腳本、評估腳本都用 MIT 授權公開，拿同一版 ATR 跑一遍，你會得到一樣的數字，不然就是證明它錯了。"
            : "A number only counts if someone else can reproduce it. Everything here can be rerun. The datasets, scan scripts and evaluation scripts are open source under the MIT license. Run them on the same ATR version and you get these figures, or you show they're wrong."}
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="space-y-4 mb-8">
          <div className="border-l-2 border-fog pl-4">
            <div className="font-display text-sm font-semibold text-ink mb-1">
              {locale === "zh" ? "掃描範圍" : "Scan coverage"}
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? `五個來源，一共 ${stats.megaScanTotal.toLocaleString()} 個項目（engine v2.0.0，${stats.megaScanDate}）。最大的三個是 OpenClaw ${stats.megaScanSources.openclaw.toLocaleString()}、ClawHub ${stats.clawHubCrawled.toLocaleString()}、Skills.sh ${stats.megaScanSources.skillsSh.toLocaleString()}，另外兩個是 Hermes Agent 和一個 MCP registry 索引。各來源的數字取自各自的爬蟲報告，跟總數不是同一個時間點拍的，所以加起來不會剛好等於總數。每個來源都是透過公開的 HTTP API 或 git repo 爬下來的。`
                : `Five sources, ${stats.megaScanTotal.toLocaleString()} items in total (engine v2.0.0, ${stats.megaScanDate}). The largest are OpenClaw ${stats.megaScanSources.openclaw.toLocaleString()}, ClawHub ${stats.clawHubCrawled.toLocaleString()} and Skills.sh ${stats.megaScanSources.skillsSh.toLocaleString()}. The other two are Hermes Agent and an MCP registry index. Each per-source count comes from that crawler's own report, taken at a different time from the total, so they won't add up to it. Every source is crawled through a public HTTP API or git repository.`}
            </p>
          </div>
          <div className="border-l-2 border-fog pl-4">
            <div className="font-display text-sm font-semibold text-ink mb-1">
              {locale === "zh" ? "偵測引擎" : "Detection engine"}
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? `偵測核心是確定性的。規則用 regex 和 AST 比對，不靠 LLM 推論，同一個輸入在哪裡跑結果都一樣，預設開著的就是這一層。v3.1.0 起另有一個選用的實驗性語意 judge，專門補抓 pattern 漏掉的改寫式攻擊。它預設關閉，要自己打開，也不會動到確定性核心。新規則合併前要過一道安全閘：拿一批良性 skill 語料去跑，不能有任何誤報。`
                : `The detection core is deterministic. Rules run regex and AST matching with no LLM inference, so the same input gives the same result anywhere. That core is what ships on by default. Since v3.1.0 there is also an optional, experimental semantic judge stage for paraphrased attacks the patterns miss. You have to turn it on, and it never changes the deterministic core. Before a new rule merges, it has to pass a safety gate: zero false positives on a corpus of benign skills.`}
            </p>
          </div>
          <div className="border-l-2 border-fog pl-4">
            <div className="font-display text-sm font-semibold text-ink mb-1">
              {locale === "zh" ? "基準測試" : "Benchmarking"}
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? `precision 和 recall 跑在一份照 PINT 格式自建的語料上。recall 兩個 lane 都列，precision 只量 hunt lane。樣本來自外部公開資料集（deepset/prompt-injections、Lakera/gandalf_ignore_instructions），但後來有幾條 hunt lane 規則，是從這份語料自己漏抓的樣本挖出來的，所以 hunt 的數字有一部分屬於 closed-book。這份語料是 ATR 自己組的，不是 Lakera 官方的 PINT benchmark。另外還有一組內部的 SKILL.md benchmark，用的是標註過的檔案，其中一部分惡意樣本是專門為它手寫的。`
                : `Precision and recall run on a self-built corpus in PINT's format. Recall is reported for both lanes, precision for the hunt lane only. The samples come from public datasets (deepset/prompt-injections, Lakera/gandalf_ignore_instructions). Some hunt-lane rules were later mined from this corpus's own misses, though, so the hunt figure is partly closed-book. The corpus is ATR's own, not Lakera's official PINT benchmark. A separate internal SKILL.md benchmark uses labelled files, and some of its malicious files were written for that benchmark.`}
            </p>
          </div>
          <div className="border-l-2 border-fog pl-4">
            <div className="font-display text-sm font-semibold text-ink mb-1">
              {locale === "zh" ? "誤報量測" : "False positive measurement"}
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? "誤報率拿真實的良性樣本來量，也就是經過人工或社群審查的正常 skill：被誤判的良性樣本數，除以掃過的良性樣本總數。數字按 lane 分開列，不合成一個好看的數字。enforce lane 只跑最成熟的規則，預設的 hunt lane 則把全部規則當成提醒訊號來跑。之前在這裡公布的各 lane 誤報率已經撤回，等重新量測。原因是當時用的良性語料裡，後來發現混進了真的越獄樣本，基準站不住。重測完成之前，這裡不放數字。每一個已記錄的誤報情境，還是會寫進規則 YAML 的 false_positives 欄位，並顯示在規則頁上。"
                : "False positive rate is measured on real benign samples, meaning skills that passed manual or community review: the benign samples flagged, divided by all benign samples scanned. It is reported per lane, not as one flattering number. The enforce lane runs only the most mature rules. The default hunt lane runs every rule as an advisory signal. The per-lane figures once published here are withdrawn until they are re-measured: the benign corpus behind them turned out to contain real jailbreak samples, so the baseline didn't hold. No figure appears here until the re-measurement is done. Every documented FP context still goes into the rule YAML's false_positives field and shows on the rule page."}
            </p>
          </div>
          <div className="border-l-2 border-fog pl-4">
            <div className="font-display text-sm font-semibold text-ink mb-1">
              {locale === "zh" ? "重現性" : "Reproducibility"}
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh" ? (
                <>掃描 checkpoint、測試集和評估腳本，都公開放在 <code className="font-data text-xs bg-ash px-1.5 py-0.5">data/</code> 和 <code className="font-data text-xs bg-ash px-1.5 py-0.5">tests/</code> 底下。用同一版 ATR 重跑掃描，結果會一模一樣。</>
              ) : (
                <>Scan checkpoints, test sets and evaluation scripts are public under <code className="font-data text-xs bg-ash px-1.5 py-0.5">data/</code> and <code className="font-data text-xs bg-ash px-1.5 py-0.5">tests/</code>. Rerun the scan with the same ATR version and you get identical results.</>
              )}
            </p>
          </div>
        </div>
      </Reveal>

      {/* External Citations */}
      <Reveal>
        <h2 className="font-display text-2xl font-medium tracking-[-1px] mb-1 mt-10">
          {locale === "zh" ? "外部引用" : "External citations"}
        </h2>
        <p className="text-sm text-stone mb-6">
          {locale === "zh"
            ? "ATR 本來就是要讓人引用、嵌進去、拿來當基礎的。外部引用記在這裡，還沒有的也照實寫。"
            : "ATR is meant to be cited, embedded and built on. External citations are recorded here, and so is the fact when there are none."}
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="bg-paper border border-fog p-5 md:p-6 mb-8">
          <p className="text-sm text-graphite leading-[1.7]">
            {locale === "zh" ? (
              <>目前還沒有公開的引用紀錄。如果你的論文、技術報告或產品文件引用了 ATR，請開一個 <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">GitHub issue</a> 告訴維護者。</>
            ) : (
              <>No external citations recorded yet. If your paper, technical report or product docs cite ATR, open a <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">GitHub issue</a> to tell the maintainer.</>
            )}
          </p>
          <div className="mt-4 pt-4 border-t border-fog space-y-3">
            <div>
              <div className="text-[13px] text-stone mb-1">
                {locale === "zh" ? "引用這個標準" : "Cite the standard"}
              </div>
              <p className="text-xs text-mist leading-[1.7]">
                {locale === "zh"
                  ? "Cite as: Agent Threat Rules (ATR) Project (2026). Agent Threat Rules: An open detection standard for AI agent threats. DOI: 10.5281/zenodo.19178002"
                  : "Cite as: Agent Threat Rules (ATR) Project (2026). Agent Threat Rules: An open detection standard for AI agent threats. DOI: 10.5281/zenodo.19178002"}
              </p>
            </div>
            <div>
              <div className="text-[13px] text-stone mb-1">
                {locale === "zh" ? "原始論文" : "Originating paper"}
              </div>
              <p className="text-xs text-mist leading-[1.7]">
                {locale === "zh"
                  ? "Cite as: Lin, Kuan-Hsin (2026). The Collapse of Trust. DOI: 10.5281/zenodo.19178002"
                  : "Cite as: Lin, Kuan-Hsin (2026). The Collapse of Trust. DOI: 10.5281/zenodo.19178002"}
              </p>
            </div>
            <div className="flex flex-wrap gap-3 pt-1">
              <a href={`/${locale}/citations`} className="font-data text-xs text-blue hover:underline">
                {locale === "zh" ? "BibTeX / 引用格式" : "BibTeX / citation formats"} &rarr;
              </a>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/CITATION.cff" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">
                {locale === "zh" ? "機器可讀的引用檔（CITATION.cff）" : "Machine-readable citation (CITATION.cff)"}
              </a>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Upcoming Research */}
      <Reveal>
        <h2 className="font-display text-2xl font-medium tracking-[-1px] mb-1 mt-10">
          {locale === "zh" ? "接下來的研究" : "What's next"}
        </h2>
        <p className="text-sm text-stone mb-6">
          {locale === "zh"
            ? "下一步，偵測不只看靜態 pattern，也要看 runtime 的行為和語意。難判定的案例，最後再寫回確定性規則。每一步都會出現在 GitHub release 和論文更新裡，外面的人追得到進度。"
            : "Next, detection looks at runtime behavior and meaning, not only static patterns, and the hard cases get written back into deterministic rules. Each step shows up in GitHub releases and paper updates, so anyone outside can follow the progress."}
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="grid grid-cols-1 gap-px bg-fog mb-8">
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-baseline justify-between gap-2 flex-wrap mb-1.5">
              <div className="font-display text-sm md:text-base font-semibold text-ink">
                {locale === "zh" ? "Tier 3 行為評估層" : "Tier 3 Behavioral Evaluator"}
              </div>
              <span className="font-data text-[10px] text-blue bg-ink/10 px-2 py-0.5  uppercase tracking-wide">
                {locale === "zh" ? "進行中" : "In progress"}
              </span>
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? "偵測從靜態 regex 延伸到 runtime 的行為訊號。第一批規則看的是：讀了環境變數又接著連網、工具呼叫頻率不正常、跑出預期外的 shell。"
                : "Takes detection past static regex to runtime behavior. The first rules look for env variable reads followed by network calls, odd tool-call rates, and shell access nobody expected."}
            </p>
          </div>
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-baseline justify-between gap-2 flex-wrap mb-1.5">
              <div className="font-display text-sm md:text-base font-semibold text-ink">
                {locale === "zh" ? "Tier 4 語意評估 + 結晶 pipeline" : "Tier 4 Semantic Evaluator + Crystallization Pipeline"}
              </div>
              <span className="font-data text-[10px] text-stone bg-stone/10 px-2 py-0.5  uppercase tracking-wide">
                {locale === "zh" ? "設計中" : "Design"}
              </span>
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? "Tier 3 判不出來的樣本，交給 LLM-as-judge 做語意分析。LLM 找到的東西，再寫成 Tier 2 的 regex 規則放回 ATR。"
                : "Cases Tier 3 can't decide go to an LLM-as-judge for semantic analysis. What the LLM finds is written back into ATR as Tier 2 regex rules."}
            </p>
          </div>
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-baseline justify-between gap-2 flex-wrap mb-1.5">
              <div className="font-display text-sm md:text-base font-semibold text-ink">
                {locale === "zh" ? "轉成 Sigma / YARA" : "Sigma / YARA output"}
              </div>
              <span className="font-data text-[10px] text-stone bg-stone/10 px-2 py-0.5  uppercase tracking-wide">
                {locale === "zh" ? "規劃中" : "Planned"}
              </span>
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? "把 ATR 規則編譯成 SIEM 用的 Sigma 和掃檔案用的 YARA。agent 的威脅偵測就能直接放進現有的資安管線，不用重建。"
                : "Compile ATR rules to Sigma for the SIEM and YARA for files. Agent threat detection then runs in the security pipelines people already have, with nothing rebuilt."}
            </p>
          </div>
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-baseline justify-between gap-2 flex-wrap mb-1.5">
              <div className="font-display text-sm md:text-base font-semibold text-ink">
                {locale === "zh" ? "訓練期和 runtime 之間的斷層" : "The gap between training and runtime"}
              </div>
              <span className="font-data text-[10px] text-stone bg-stone/10 px-2 py-0.5  uppercase tracking-wide">
                {locale === "zh" ? "開放問題" : "Open problem"}
              </span>
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? "ATR 只偵測 runtime 的攻擊。訓練時就埋進模型的後門，到了推論階段，從架構上就看不到。要補上這個斷層，得有新技術，把供應鏈來源（model card、訓練資料稽核）和 runtime 的行為指紋接起來。"
                : "ATR detects runtime attacks. A backdoor planted in a model during training is invisible, by design, at inference time. Closing that gap needs new techniques that tie supply-chain provenance (model cards, training data audits) to runtime behavioral fingerprints."}
            </p>
          </div>
        </div>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-xs text-mist leading-[1.7] mb-8">
          {locale === "zh" ? (
            <>出處：<a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ATR-FRAMEWORK-SPEC.md" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">ATR-FRAMEWORK-SPEC.md</a> 的 Phase 2-4 路線圖，以及<a href="https://doi.org/10.5281/zenodo.19178002" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">主論文</a>的未來工作章節。</>
          ) : (
            <>Sources: <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ATR-FRAMEWORK-SPEC.md" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">ATR-FRAMEWORK-SPEC.md</a> Phase 2-4 roadmap and the <a href="https://doi.org/10.5281/zenodo.19178002" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">main paper</a>&apos;s future work section.</>
          )}
        </p>
      </Reveal>

      {/* Limitations */}
      <Reveal>
        <h2 className="font-display text-2xl font-medium tracking-[-1px] mb-1 mt-10">{t(locale, "research.limits")}</h2>
        <p className="text-sm text-stone mb-6">{t(locale, "research.limits.sub")}</p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="space-y-4">
          {(["paraphrase", "multilang", "context", "protocol", "multiturn", "novel"] as const).map((key) => (
            { title: t(locale, `research.limit.${key}`), desc: t(locale, `research.limit.${key}.desc`) }
          )).map((limitation) => (
            <div key={limitation.title} className="border-b border-fog pb-4">
              <div className="font-display text-sm font-semibold mb-1">{limitation.title}</div>
              <p className="text-sm text-stone leading-[1.6]">{limitation.desc}</p>
            </div>
          ))}
        </div>
      </Reveal>
      <Reveal>
        <div className="mt-6">
          <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/LIMITATIONS.md" target="_blank" rel="noopener noreferrer" className="font-data text-sm text-blue hover:underline">
            {t(locale, "research.limits.full")} &rarr;
          </a>
        </div>
      </Reveal>
    </div>
  );
}

/** As src/eval/skill-benchmark.ts defines them. */
const LAYERS: Readonly<Record<string, { en: string; zh: string }>> = {
  a: { en: "Obvious payloads", zh: "明顯的惡意 payload" },
  b: { en: "Obfuscated attacks", zh: "混淆攻擊" },
  c: { en: "Semantic attacks", zh: "語意型攻擊" },
};

/**
 * The SKILL.md benchmark, from its measurement file. Every recall names its
 * lane: hunt detects every attack sample here, and the enforce lane, which
 * loads only stable rules, detects what the measurement records beside it.
 */
function SkillBenchmark({ run, zh }: { run: BenchmarkMeasurement; zh: boolean }) {
  return (
    <>
      <Reveal>
        <h2 className="font-display text-2xl font-medium tracking-[-1px] mb-1 mt-10">
          {zh ? "SKILL.md 偵測基準" : "SKILL.md detection benchmark"}
        </h2>
        <p className="text-sm text-stone mb-6">
          {skillCorpusLine(run, zh)}
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog mb-8">
          <SkillOverall run={run} zh={zh} />
          <SkillLayers run={run} zh={zh} />
        </div>
      </Reveal>
    </>
  );
}

function SkillOverall({ run, zh }: { run: BenchmarkMeasurement; zh: boolean }) {
  return (
    <div className="bg-paper p-6">
      <div className="text-[13px] text-stone mb-4">
        {zh ? "整體" : "Overall"}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <RecallCell m={run} label="Recall" zh={zh} />
        <MetricCell value={run.precision} label="Precision · hunt" />
        <MetricCell value={run.f1} label="F1 · hunt" plain />
      </div>
      <div className="grid grid-cols-2 gap-4 mt-4 pt-4 border-t border-fog">
        <div>
          <div className="font-data text-lg font-bold text-green">{pct(run.fp_rate, 2)}</div>
          <div className="text-xs text-stone">{zh ? "誤報率 · hunt" : "False positive rate · hunt"}</div>
        </div>
        <div>
          <div className="font-data text-lg font-bold text-ink">{count(run.samples)}</div>
          <div className="text-xs text-stone">{zh ? "已標註樣本" : "Labelled samples"}</div>
        </div>
      </div>
    </div>
  );
}

function SkillLayers({ run, zh }: { run: BenchmarkMeasurement; zh: boolean }) {
  const layers = Object.entries(run.layers ?? {}).filter(([, l]) => l.total > 0);
  const fp = run.falsePositives === null ? null : count(run.falsePositives);
  return (
    <div className="bg-paper p-6">
      <div className="text-[13px] text-stone mb-4">
        {zh ? "依攻擊層 · hunt lane" : "By attack layer · hunt lane"}
      </div>
      <div className="space-y-4">
        {layers.map(([key, l]) => (
          <LayerBar
            key={key}
            name={`Layer ${key.toUpperCase()}`}
            value={pctHunt(l.detected / l.total)}
            desc={zh
              ? `${(LAYERS[key] ?? { en: key, zh: key }).zh}：偵測到 ${l.detected}/${l.total}`
              : `${(LAYERS[key] ?? { en: key, zh: key }).en}: ${l.detected}/${l.total} detected`}
            width={(l.detected / l.total) * 100}
          />
        ))}
        {run.benign !== null && fp !== null && (
          <LayerBar
            name={zh ? "正常樣本" : "Benign"}
            value={`${fp} FP`}
            desc={zh
              ? `${count(run.benign)} 個正常 SKILL.md，誤報 ${fp} 個（${pct(run.fp_rate, 2)}）`
              : `${count(run.benign)} benign SKILL.md files, ${fp} false positive${run.falsePositives === 1 ? "" : "s"} (${pct(run.fp_rate, 2)})`}
            width={100}
            benign
          />
        )}
      </div>
      <p className="text-xs text-stone mt-4 leading-[1.6]">{skillEnforceNote(run, zh)}</p>
    </div>
  );
}

/** The corpus line: what the benchmark is, from its measurement; the layer names follow the harness. */
function skillCorpusLine(run: BenchmarkMeasurement, zh: boolean): string {
  const split = run.attacks !== null && run.benign !== null
    ? (zh ? `${count(run.attacks)} 個惡意 + ${count(run.benign)} 個正常；` : `${count(run.attacks)} malicious + ${count(run.benign)} benign; `)
    : "";
  const noB = (run.layers?.b?.total ?? 0) === 0;
  return zh
    ? `一份內部、標註過的 SKILL.md 語料，共 ${count(run.samples)} 個檔案（${split}${measuredStamp(run, true, true)}）。其中一部分惡意樣本是專門為這個 benchmark 手寫的。Layer A 是明顯的惡意 payload，像 curl | bash、base64 執行、reverse shell。Layer C 是語意型攻擊，像用自然語言下指令、社交工程。${noB ? "這份語料沒有 Layer B（混淆）的樣本。" : ""}`
    : `An internal, labelled SKILL.md corpus of ${count(run.samples)} files (${split}${measuredStamp(run, false)}). Some of the malicious files were written for this benchmark. Layer A is obvious payloads: curl | bash, base64 exec, reverse shell. Layer C is semantic attacks: natural-language instructions, social engineering.${noB ? " The corpus has no Layer B (obfuscated) samples." : ""}`;
}

function skillEnforceNote(run: BenchmarkMeasurement, zh: boolean): string {
  const e = run.enforce;
  if (e === null) return zh ? "這次量測沒有記錄 enforce lane 的數字。" : "This measurement records no enforce-lane figure.";
  return zh
    ? `enforce lane 只載入 stable 規則，要開封鎖就用這一條。它在 ${count(e.attacks)} 個惡意樣本中偵測到 ${count(e.detected)} 個（${pct(e.recall)}）。這次量測沒有逐層的 enforce 數字。`
    : `The enforce lane loads stable rules only, and it's the one to run with blocking on. It detects ${count(e.detected)} of the ${count(e.attacks)} malicious samples (${pct(e.recall)}). The measurement has no per-layer enforce split.`;
}

function LayerBar({ name, value, desc, width, benign = false }: { name: string; value: string; desc: string; width: number; benign?: boolean }) {
  return (
    <div>
      <div className="flex items-baseline justify-between mb-1">
        <span className="font-data text-sm font-semibold">{name}</span>
        <span className={`font-data text-sm font-bold ${benign ? "text-green" : "text-ink"}`}>{value}</span>
      </div>
      <div className="text-xs text-stone">{desc}</div>
      <div className="mt-1.5 h-1.5 bg-fog"><div className={`h-full ${benign ? "bg-green" : "bg-ink"}`} style={{ width: `${width}%` }} /></div>
    </div>
  );
}
