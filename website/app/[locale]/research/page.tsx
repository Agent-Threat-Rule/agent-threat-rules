import { Reveal } from "@/components/Reveal";
import { CountUp } from "@/components/CountUp";
import { StatsHydrator } from "@/components/StatsHydrator";
import { loadSiteStats } from "@/lib/stats";
import { getSpecMeta } from "@/lib/spec-meta";
import { locales, t, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Research - ATR",
  description: "ATR research: academic paper, benchmark results, limitations, and ecosystem scan data.",
};

export default async function ResearchPage({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const stats = loadSiteStats();

  return (
    <div className="pt-20 pb-16 px-6 max-w-[1120px] mx-auto">
      <StatsHydrator />
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">{t(locale, "research.label")}</div>
      </Reveal>
      <Reveal delay={0.1}>
        <h1 className="font-display text-[clamp(28px,4vw,44px)] font-extrabold tracking-[-2px] mb-2">
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
              <span className="font-data text-xs text-mist">April 2026 · 25 pages · 67 references</span>
            </div>
            <div className="font-display text-base font-semibold text-ink mb-1">
              {locale === "zh"
                ? "信任的崩塌：自主 AI Agent 時代的安全架構"
                : "The Collapse of Trust: Security Architecture for the Age of Autonomous AI Agents"}
            </div>
            <p className="text-sm text-stone mb-3">
              {locale === "zh"
                ? `ATR 標準為何存在的完整論述：當 agent 能自主行動，信任不再能假設，偵測必須變成一個任何人都能查核、版本化、社群維護的標準層。涵蓋 RFC-001 品質規範、96,096 個 skill 的生態系掃描（1,302 個被標記、經人工複審確認 552 個惡意），以及把標準從一次性快照變成活飛輪的機制。`
                : `The full argument for why ATR exists: once agents act on their own, trust can no longer be assumed, and detection has to become a standard layer anyone can audit, version, and maintain. Covers the RFC-001 quality specification, a 96,096-skill ecosystem scan (1,302 flagged, 552 confirmed malware after manual review), and the mechanism that turns the standard from a one-time snapshot into a living one.`}
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
              <span className="font-data text-xs bg-critical/10 text-critical px-2 py-0.5 rounded-sm">{locale === "zh" ? "新" : "NEW"}</span>
              <span className="font-data text-xs text-mist">April 2026</span>
            </div>
            <div className="font-display text-base font-semibold text-ink mb-1">
              {locale === "zh"
                ? "552 個確認惡意的 AI Agent Skill：史上最大規模的 AI Agent 惡意軟體行動"
                : "552 Confirmed Malicious AI Agent Skills: The Largest AI Agent Malware Campaign Ever Documented"}
            </div>
            <p className="text-sm text-stone mb-3">
              {locale === "zh"
                ? "掃描 96,096 個 skill、標記 1,302 個風險項，人工複審後確認 552 個惡意軟體。發現三個協同攻擊者（hightower6eu 354、sakaen736jih 212、52yuanchangxing 137）。已通報 NousResearch 並全數加入黑名單。"
                : "1,302 flagged across 96,096 skills scanned in six registries; 552 confirmed malware after manual review. Three coordinated threat actors (hightower6eu 354, sakaen736jih 212, 52yuanchangxing 137). Reported to NousResearch and blacklisted."}
            </p>
            <div className="flex flex-wrap gap-3">
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/research/openclaw-malware-campaign-2026-04.md" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">{locale === "zh" ? "完整報告 (EN)" : "Full Report (EN)"}</a>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/research/openclaw-malware-campaign-2026-04-zh.md" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">{locale === "zh" ? "完整報告 (ZH)" : "Full Report (ZH)"}</a>
            </div>
          </div>

          {/* Mega scan paper */}
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-center gap-2 mb-2">
              <span className="font-data text-xs text-mist">April 2026 · 7 pages · 32 references</span>
            </div>
            <div className="font-display text-base font-semibold text-ink mb-1">
              96,096 Skills, 552 Confirmed Malware: A Large-Scale Security Audit of the AI Agent Ecosystem
            </div>
            <p className="text-sm text-stone mb-3">
              {locale === "zh"
                ? "史上最大規模 AI agent 安全掃描。96,096 個 skill、1,302 個有風險、人工複審後 552 個確認惡意軟體。三個協同攻擊者。工具描述下毒佔偵測的 53%。"
                : "The largest AI agent security scan to date. 96,096 skills across 6 registries, 1,302 flagged, 552 confirmed malware after manual review. Three coordinated threat actors. Credential access via tool descriptions accounts for 53% of detections."}
            </p>
            <div className="flex flex-wrap gap-3">
              <a href="https://doi.org/10.5281/zenodo.19476480" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">Zenodo (DOI)</a>
              <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/docs/paper/ATR-MegaScan-2026.pdf" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline">PDF (GitHub)</a>
            </div>
          </div>

          {/* MCP attack surface paper */}
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-center gap-2 mb-2">
              <span className="font-data text-xs bg-critical/10 text-critical px-2 py-0.5 rounded-sm">{locale === "zh" ? "新" : "NEW"}</span>
              <span className="font-data text-xs text-mist">April 2026 · 18 pages · 30 references</span>
            </div>
            <div className="font-display text-base font-semibold text-ink mb-1">
              30 CVEs in 60 Days: The Model Context Protocol Attack Surface
            </div>
            <p className="text-sm text-stone mb-3">
              {locale === "zh"
                ? "MCP 攻擊面實證分析。60 天 30 個 CVE、38% 零認證、7 類攻擊分類學、53K 生態系掃描。比 Docker 前兩年快 15 倍。"
                : "Empirical analysis of the MCP attack surface. 30 CVEs in 60 days, 38% zero authentication, 7-class attack taxonomy, 53K ecosystem scan. 15x faster than Docker's first two years."}
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
        <h2 className="font-display text-2xl font-extrabold tracking-[-1px] mb-1 mt-10">{t(locale, "research.benchmarks")}</h2>
        <p className="text-sm text-stone mb-6">{t(locale, "research.benchmarks.sub")}</p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog mb-8">
          {/* PINT */}
          <div className="bg-paper p-6">
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-4">{t(locale, "research.pint")}</div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <div className="font-data text-2xl font-bold text-ink"><CountUp target={stats.pintPrecision} suffix="%" liveKey="pintPrecision" /></div>
                <div className="text-xs text-stone">{t(locale, "research.precision")}</div>
              </div>
              <div>
                <div className="font-data text-2xl font-bold text-ink"><CountUp target={stats.pintRecall} suffix="%" liveKey="pintRecall" /></div>
                <div className="text-xs text-stone">{t(locale, "research.recall")}</div>
              </div>
              <div>
                <div className="font-data text-2xl font-bold text-ink"><CountUp target={stats.pintF1} liveKey="pintF1" /></div>
                <div className="text-xs text-stone">F1</div>
              </div>
            </div>
            <div className="font-data text-xs text-stone mt-3">{stats.pintSamples} {locale === "zh" ? "個樣本" : "samples"}</div>
          </div>
          {/* Self-test */}
          <div className="bg-paper p-6">
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-4">{t(locale, "research.self")}</div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <div className="font-data text-2xl font-bold text-ink"><CountUp target={stats.selfTestPrecision} suffix="%" liveKey="selfTestPrecision" /></div>
                <div className="text-xs text-stone">Precision</div>
              </div>
              <div>
                <div className="font-data text-2xl font-bold text-ink"><CountUp target={stats.selfTestRecall} suffix="%" liveKey="selfTestRecall" /></div>
                <div className="text-xs text-stone">Recall</div>
              </div>
              <div>
                <div className="font-data text-2xl font-bold text-ink">{stats.selfTestSamples}</div>
                <div className="text-xs text-stone">{locale === "zh" ? "樣本數" : "Samples"}</div>
              </div>
            </div>
          </div>
        </div>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-sm text-stone mb-8">
          {t(locale, "research.gap_note", { precision: String(stats.pintPrecision), recall: String(stats.pintRecall) })}
        </p>
      </Reveal>

      {/* SKILL.md Benchmark */}
      <Reveal>
        <h2 className="font-display text-2xl font-extrabold tracking-[-1px] mb-1 mt-10">
          {locale === "zh" ? "SKILL.md 偵測基準" : "SKILL.md Detection Benchmark"}
        </h2>
        <p className="text-sm text-stone mb-6">
          {locale === "zh"
            ? "使用 498 個真實世界的 OpenClaw SKILL.md 檔案測試（32 個惡意 + 466 個正常）。Layer A = 明確惡意指令，Layer C = 混淆/隱藏攻擊。"
            : "Tested against 498 real-world OpenClaw SKILL.md files (32 malicious + 466 benign). Layer A = explicit malicious instructions. Layer C = obfuscated / hidden attacks."}
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog mb-8">
          <div className="bg-paper p-6">
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-4">
              {locale === "zh" ? "整體表現" : "Overall Performance"}
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <div className="font-data text-2xl font-bold text-ink"><CountUp target={stats.skillBenchRecall} suffix="%" /></div>
                <div className="text-xs text-stone">Recall</div>
              </div>
              <div>
                <div className="font-data text-2xl font-bold text-ink"><CountUp target={stats.skillBenchPrecision} suffix="%" /></div>
                <div className="text-xs text-stone">Precision</div>
              </div>
              <div>
                <div className="font-data text-2xl font-bold text-ink"><CountUp target={stats.skillBenchF1} /></div>
                <div className="text-xs text-stone">F1</div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4 mt-4 pt-4 border-t border-fog">
              <div>
                <div className="font-data text-lg font-bold text-green"><CountUp target={stats.skillBenchFpRate} suffix="%" /></div>
                <div className="text-xs text-stone">{locale === "zh" ? "誤報率" : "False positive rate"}</div>
              </div>
              <div>
                <div className="font-data text-lg font-bold text-ink">{stats.skillBenchSamples}</div>
                <div className="text-xs text-stone">{locale === "zh" ? "真實樣本" : "Real-world samples"}</div>
              </div>
            </div>
          </div>
          <div className="bg-paper p-6">
            {/* SKILL.md benchmark snapshot (v2.0.0, 498 samples): Layer A 24 + Layer C 8 = 32 malicious, both 100% detected. Pinned numbers — re-sync if the benchmark is re-run. */}
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-4">
              {locale === "zh" ? "按攻擊層分析" : "By Attack Layer"}
            </div>
            <div className="space-y-4">
              <div>
                <div className="flex items-baseline justify-between mb-1">
                  <span className="font-data text-sm font-semibold">Layer A</span>
                  <span className="font-data text-sm font-bold text-ink">100%</span>
                </div>
                <div className="text-xs text-stone">
                  {locale === "zh" ? "明確惡意指令 — 24/24 全部偵測" : "Explicit malicious instructions — 24/24 detected"}
                </div>
                <div className="mt-1.5 h-1.5 bg-fog"><div className="h-full bg-blue" style={{ width: "100%" }} /></div>
              </div>
              <div>
                <div className="flex items-baseline justify-between mb-1">
                  <span className="font-data text-sm font-semibold">Layer C</span>
                  <span className="font-data text-sm font-bold text-ink">100%</span>
                </div>
                <div className="text-xs text-stone">
                  {locale === "zh" ? "混淆/隱藏攻擊 — 8/8 全部偵測" : "Obfuscated attacks — 8/8 detected"}
                </div>
                <div className="mt-1.5 h-1.5 bg-fog"><div className="h-full bg-blue" style={{ width: "100%" }} /></div>
              </div>
              <div>
                <div className="flex items-baseline justify-between mb-1">
                  <span className="font-data text-sm font-semibold">{locale === "zh" ? "正常樣本" : "Benign"}</span>
                  <span className="font-data text-sm font-bold text-green">1 FP</span>
                </div>
                <div className="text-xs text-stone">
                  {locale === "zh" ? "466 個正常 SKILL.md — 1 個誤報（0.20%）" : "466 benign SKILL.md files — 1 false positive (0.20%)"}
                </div>
                <div className="mt-1.5 h-1.5 bg-fog"><div className="h-full bg-green" style={{ width: "100%" }} /></div>
              </div>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Ecosystem Scan Data */}
      <Reveal>
        <h2 className="font-display text-2xl font-extrabold tracking-[-1px] mb-1 mt-10">{t(locale, "research.scan")}</h2>
        <p className="text-sm text-stone mb-6">{t(locale, "research.scan.sub")}</p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog mb-8">
          <div className="bg-paper p-6">
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">{locale === "zh" ? "生態系掃描（6 個 Registry）" : "Ecosystem Scan (6 Registries)"}</div>
            <div className="font-data text-3xl font-bold text-ink mb-1"><CountUp target={stats.megaScanTotal} useComma liveKey="megaScanTotal" /></div>
            <div className="text-sm text-stone mb-3">{locale === "zh" ? "個 skill 已掃描" : "skills scanned"}</div>
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
            <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">ClawHub Registry Scan</div>
            <div className="font-data text-3xl font-bold text-ink mb-1"><CountUp target={stats.clawHubCrawled} useComma /></div>
            <div className="text-sm text-stone mb-3">{locale === "zh" ? "個 skill 已爬取" : "skills crawled"}</div>
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
            ? `這個掃描不是一份報告，是一條每天運轉的迴圈。新攻擊出現 → 結晶成偵測規則 → 回流標準：紅隊巨量掃描與 CVE 攝取兩條飛輪各自跑完整輪後轉為每日更新，把規則集從 462 條推進到目前的 ${stats.ruleCount} 條（新增 ${stats.ruleCount - 462} 條，npm agent-threat-rules@${getSpecMeta().version}）。這就是「標準活著」的意思——不是一次性的快照，而是與威脅同速演化的層。`
            : `This scan is not a report — it is a loop that runs every day. New attack appears → crystallizes into a detection rule → flows back into the standard. A red-team mega-scan flywheel and a CVE-ingestion flywheel each completed a full sweep, then moved to daily updates, taking the ruleset from 462 to the current ${stats.ruleCount} (${stats.ruleCount - 462} new rules, npm agent-threat-rules@${getSpecMeta().version}). This is what it means for a standard to be alive: not a one-time snapshot, but a layer that evolves at the speed of the threats it covers.`}
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
        <h2 className="font-display text-2xl font-extrabold tracking-[-1px] mb-1 mt-10">
          {locale === "zh" ? "研究方法論" : "Research Methodology"}
        </h2>
        <p className="text-sm text-stone mb-6">
          {locale === "zh"
            ? "一個標準的數字只有在別人能複驗時才算數。所有研究都可重現——資料集、掃描腳本、評估腳本全部以 MIT license 開源，任何人都能拿同一版 ATR 重跑，自己得出這些數字，或證明它們是錯的。"
            : "A standard's numbers only count if someone else can reproduce them. All research here is reproducible — datasets, scan scripts, and evaluation scripts are open-source under MIT license, so anyone can rerun them on the same ATR version and arrive at these figures, or prove them wrong."}
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
                ? `六個 registry 共 ${stats.megaScanTotal.toLocaleString()} 個 skill。最大子集：OpenClaw ${stats.megaScanSources.openclaw.toLocaleString()}、ClawHub ${stats.clawHubCrawled.toLocaleString()}、Skills.sh ${stats.megaScanSources.skillsSh.toLocaleString()}，加上三個額外 MCP / skill index。每個 registry 透過公開 HTTP API 或 git 倉儲爬取。`
                : `Six registries totaling ${stats.megaScanTotal.toLocaleString()} skills. Largest subsets: OpenClaw ${stats.megaScanSources.openclaw.toLocaleString()}, ClawHub ${stats.clawHubCrawled.toLocaleString()}, Skills.sh ${stats.megaScanSources.skillsSh.toLocaleString()}, plus three additional MCP / skill indexes. Each registry is crawled via public HTTP API or git repository.`}
            </p>
          </div>
          <div className="border-l-2 border-fog pl-4">
            <div className="font-display text-sm font-semibold text-ink mb-1">
              {locale === "zh" ? "偵測引擎" : "Detection engine"}
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? `偵測核心是確定性的：規則以 regex / AST 比對執行、無 LLM 推論，同一個輸入在任何環境都得到一致的結果——可重現性是前提，也是預設啟用的部分。v3.1.0 起另有一個選用、實驗性的語意 judge 階段，用來補抓 pattern 漏掉的改寫式攻擊；它需手動開啟、預設關閉，不更動確定性核心。每條規則在發布前都會對 ${stats.clawHubCrawled.toLocaleString()} 個 ClawHub skill 的 wild 樣本驗證。`
                : `The detection core is deterministic: rules execute regex / AST matching with no LLM inference, so the same input produces the same result in every environment — reproducibility is a prerequisite, and it is what ships on by default. Since v3.1.0 an optional, experimental semantic judge stage recovers paraphrased attacks the patterns miss; it is opt-in, off by default, and never alters the deterministic core. Every rule is wild-validated against ${stats.clawHubCrawled.toLocaleString()} ClawHub skills before publication.`}
            </p>
          </div>
          <div className="border-l-2 border-fog pl-4">
            <div className="font-display text-sm font-semibold text-ink mb-1">
              {locale === "zh" ? "基準測試" : "Benchmarking"}
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? `Precision / recall 採用外部 PINT dataset（${stats.pintSamples} 樣本），而非自產測試集——避免 overfit 到自家 test cases。另一組 SKILL.md benchmark 從真實 OpenClaw 抓 ${stats.skillBenchSamples} 個檔案，其中惡意樣本透過人工標記後作為 ground truth。`
                : `Precision / recall uses the external PINT dataset (${stats.pintSamples} samples) rather than self-generated tests — this avoids overfitting to our own test cases. A separate SKILL.md benchmark uses ${stats.skillBenchSamples} real-world OpenClaw files, with malicious samples hand-labeled as ground truth.`}
            </p>
          </div>
          <div className="border-l-2 border-fog pl-4">
            <div className="font-display text-sm font-semibold text-ink mb-1">
              {locale === "zh" ? "誤報量測" : "False positive measurement"}
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? "誤報率以真實 benign 樣本（通過人工或社群審查的正常 skill）除以總偵測數量測，並逐車道揭露、不用單一數字概括：enforce 車道只跑最成熟的規則（在一個約 65,000 筆的良性語料上約 0.24% 誤報），預設的 hunt 車道把全部規則當建議性訊號跑（約 9%）。一個標準的可信度，取決於它願不願意公開自己最差的數字——所以這裡兩個都列。每條已記錄的誤報情境會寫入 YAML 的 false_positives 欄位，並在規則頁面公開。"
                : "False positive rate is measured against real benign samples (skills vetted by manual or community review), divided by total detections, and reported lane by lane rather than as one flattering number: the enforce lane runs only the most mature rules (~0.24% on a ~65,000-sample benign corpus), while the default hunt lane runs everything as an advisory signal (~9%). A standard earns trust by publishing its worst figure, not hiding it — so both are stated here. Every documented FP context is written into the rule YAML's false_positives field and surfaced on the rule page."}
            </p>
          </div>
          <div className="border-l-2 border-fog pl-4">
            <div className="font-display text-sm font-semibold text-ink mb-1">
              {locale === "zh" ? "重現性" : "Reproducibility"}
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh" ? (
                <>掃描 checkpoint、測試集、評估腳本全部在 <code className="font-data text-xs bg-ash px-1.5 py-0.5">data/</code> 和 <code className="font-data text-xs bg-ash px-1.5 py-0.5">tests/</code> 下公開。任何研究者可以用相同的 ATR 版本重跑掃描並取得一致的結果。</>
              ) : (
                <>Scan checkpoints, test sets, and evaluation scripts are public under <code className="font-data text-xs bg-ash px-1.5 py-0.5">data/</code> and <code className="font-data text-xs bg-ash px-1.5 py-0.5">tests/</code>. Any researcher can rerun the scan with the same ATR version and obtain identical results.</>
              )}
            </p>
          </div>
        </div>
      </Reveal>

      {/* External Citations */}
      <Reveal>
        <h2 className="font-display text-2xl font-extrabold tracking-[-1px] mb-1 mt-10">
          {locale === "zh" ? "外部引用" : "External Citations"}
        </h2>
        <p className="text-sm text-stone mb-6">
          {locale === "zh"
            ? "ATR 的設計目標就是被引用、被內嵌、被別人的工作所依賴。這裡誠實記錄外部引用——包括目前還沒有的部分。"
            : "ATR is built to be cited, embedded, and depended on by other people's work. This section records external citations honestly — including where there are none yet."}
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="bg-paper border border-fog p-5 md:p-6 mb-8">
          <p className="text-sm text-graphite leading-[1.7]">
            {locale === "zh" ? (
              <>目前尚未有公開引用紀錄。如果你的論文、技術報告或產品文件引用了 ATR，請透過 <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">GitHub issue</a> 通知我們。</>
            ) : (
              <>No external citations recorded yet. If your paper, technical report, or product documentation cites ATR, please let us know via <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">GitHub issue</a>.</>
            )}
          </p>
          <div className="mt-4 pt-4 border-t border-fog space-y-3">
            <div>
              <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-1">
                {locale === "zh" ? "引用此標準" : "Cite the standard"}
              </div>
              <p className="text-xs text-mist leading-[1.7]">
                {locale === "zh"
                  ? "Cite as: Agent Threat Rules (ATR) Project (2026). Agent Threat Rules: An open detection standard for AI agent threats. DOI: 10.5281/zenodo.19178002"
                  : "Cite as: Agent Threat Rules (ATR) Project (2026). Agent Threat Rules: An open detection standard for AI agent threats. DOI: 10.5281/zenodo.19178002"}
              </p>
            </div>
            <div>
              <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-1">
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
                {locale === "zh" ? "機器可讀引用 (CITATION.cff)" : "Machine-readable citation (CITATION.cff)"}
              </a>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Upcoming Research */}
      <Reveal>
        <h2 className="font-display text-2xl font-extrabold tracking-[-1px] mb-1 mt-10">
          {locale === "zh" ? "進行中的研究" : "Upcoming Research"}
        </h2>
        <p className="text-sm text-stone mb-6">
          {locale === "zh"
            ? "飛輪的下一段：把偵測從靜態 pattern 推向 runtime 行為與語意，再讓難判定的案例結晶回確定性規則。每一步都公開在 GitHub release 與 paper 更新，進度可被外部追蹤。"
            : "The next turns of the flywheel: pushing detection from static patterns toward runtime behavior and semantics, then crystallizing the hard cases back into deterministic rules. Each step ships in GitHub releases and paper updates, so the progress is auditable from the outside."}
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="grid grid-cols-1 gap-px bg-fog mb-8">
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-baseline justify-between gap-2 flex-wrap mb-1.5">
              <div className="font-display text-sm md:text-base font-semibold text-ink">
                {locale === "zh" ? "Tier 3 行為評估層" : "Tier 3 Behavioral Evaluator"}
              </div>
              <span className="font-data text-[10px] text-blue bg-blue/10 px-2 py-0.5 rounded-sm uppercase tracking-wide">
                {locale === "zh" ? "進行中" : "In progress"}
              </span>
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? "從靜態 regex 擴展到 runtime 行為偵測。初始規則：env 變數存取 + 網路呼叫的組合、工具呼叫頻率異常、非預期 shell 存取。"
                : "Extends detection from static regex to runtime behavioral signals. Initial rules: env variable access combined with network calls, tool-call rate anomalies, unexpected shell access."}
            </p>
          </div>
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-baseline justify-between gap-2 flex-wrap mb-1.5">
              <div className="font-display text-sm md:text-base font-semibold text-ink">
                {locale === "zh" ? "Tier 4 語意評估 + 結晶 pipeline" : "Tier 4 Semantic Evaluator + Crystallization Pipeline"}
              </div>
              <span className="font-data text-[10px] text-stone bg-stone/10 px-2 py-0.5 rounded-sm uppercase tracking-wide">
                {locale === "zh" ? "設計中" : "Design"}
              </span>
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? "Tier 3 難以判定的樣本升級給 LLM-as-judge 語意分析；LLM 的發現會結晶成 Tier 2 regex 規則回流到 ATR，完成「適應性免疫 → 先天免疫」的轉換。"
                : "Cases Tier 3 cannot decide escalate to LLM-as-judge semantic analysis. LLM findings crystallize into Tier 2 regex rules and flow back into ATR — the adaptive-to-innate immunity transition."}
            </p>
          </div>
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-baseline justify-between gap-2 flex-wrap mb-1.5">
              <div className="font-display text-sm md:text-base font-semibold text-ink">
                {locale === "zh" ? "Sigma / YARA 跨格式相容" : "Sigma / YARA Cross-format Compatibility"}
              </div>
              <span className="font-data text-[10px] text-stone bg-stone/10 px-2 py-0.5 rounded-sm uppercase tracking-wide">
                {locale === "zh" ? "規劃中" : "Planned"}
              </span>
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? "將 ATR 規則編譯為 Sigma（SIEM 端）與 YARA（檔案端）格式，讓 agent 威脅偵測融入現有資安偵測管線，不需要重建 pipeline。"
                : "Compile ATR rules into Sigma (SIEM-side) and YARA (file-side) formats so agent threat detection plugs into existing security pipelines without rebuilding infrastructure."}
            </p>
          </div>
          <div className="bg-paper p-5 md:p-6">
            <div className="flex items-baseline justify-between gap-2 flex-wrap mb-1.5">
              <div className="font-display text-sm md:text-base font-semibold text-ink">
                {locale === "zh" ? "訓練 ↔ runtime 偵測邊界" : "Training ↔ Runtime Detection Boundary"}
              </div>
              <span className="font-data text-[10px] text-stone bg-stone/10 px-2 py-0.5 rounded-sm uppercase tracking-wide">
                {locale === "zh" ? "開放問題" : "Open problem"}
              </span>
            </div>
            <p className="text-sm text-graphite leading-[1.7]">
              {locale === "zh"
                ? "ATR 只偵測 runtime 攻擊。訓練階段植入的模型後門在推論時架構上不可見。要橋接這個斷層，需要結合 supply-chain provenance（model card、訓練資料稽核）與 runtime 行為指紋的新技術。"
                : "ATR detects runtime attacks. Model backdoors planted during training are architecturally invisible at inference time. Bridging this gap requires new techniques combining supply-chain provenance (model cards, training data audits) with runtime behavioral fingerprinting."}
            </p>
          </div>
        </div>
      </Reveal>
      <Reveal delay={0.2}>
        <p className="text-xs text-mist leading-[1.7] mb-8">
          {locale === "zh" ? (
            <>素材來源：<a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ATR-FRAMEWORK-SPEC.md" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">ATR-FRAMEWORK-SPEC.md</a> Phase 2-4 路線圖與 <a href="https://doi.org/10.5281/zenodo.19178002" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">主論文</a>未來工作章節。</>
          ) : (
            <>Sources: <a href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/ATR-FRAMEWORK-SPEC.md" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">ATR-FRAMEWORK-SPEC.md</a> Phase 2-4 roadmap and the <a href="https://doi.org/10.5281/zenodo.19178002" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">main paper</a>&apos;s future work section.</>
          )}
        </p>
      </Reveal>

      {/* Limitations */}
      <Reveal>
        <h2 className="font-display text-2xl font-extrabold tracking-[-1px] mb-1 mt-10">{t(locale, "research.limits")}</h2>
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
