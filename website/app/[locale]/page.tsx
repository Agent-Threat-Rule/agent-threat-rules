/* ATR Homepage — 8-scene narrative per DESIGN.md */
import { HeroEntrance } from "@/components/HeroEntrance";
import { CountUp } from "@/components/CountUp";
import { SpeedLines } from "@/components/SpeedLines";
import { Reveal } from "@/components/Reveal";
import { StatsHydrator } from "@/components/StatsHydrator";
import { NumberScramble } from "@/components/NumberScramble";
import { Flywheel } from "@/components/Flywheel";
import { HeroGrid } from "@/components/DotGrid";
import { loadSiteStats } from "@/lib/stats";
import { loadAllRules, getCategories, categoryDisplayName } from "@/lib/rules";
import { locales, type Locale } from "@/lib/i18n";
import Link from "next/link";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

const CATEGORY_DESC: Record<string, { en: string; zh: string }> = {
  "prompt-injection": {
    en: "Hijacking agent behavior through crafted inputs",
    zh: "透過精心構造的輸入劫持 agent 行為",
  },
  "skill-compromise": {
    en: "Malicious or vulnerable MCP skills and SKILL.md",
    zh: "惡意或有漏洞的 MCP skill 和 SKILL.md",
  },
  "context-exfiltration": {
    en: "Stealing conversation context and sensitive data",
    zh: "竊取對話上下文和敏感資料",
  },
  "agent-manipulation": {
    en: "Social engineering and behavioral manipulation of agents",
    zh: "對 agent 的社交工程和行為操控",
  },
  "tool-poisoning": {
    en: "Poisoned tool descriptions and malicious tool responses",
    zh: "被下毒的工具描述和惡意工具回應",
  },
  "privilege-escalation": {
    en: "Unauthorized elevation of agent capabilities",
    zh: "未授權提升 agent 權限",
  },
  "excessive-autonomy": {
    en: "Agents exceeding intended operational boundaries",
    zh: "Agent 超越預期的操作邊界",
  },
  "model-level-attacks": {
    en: "Attacks on the LLM itself — behavior extraction, adversarial fine-tuning, poisoned training data",
    zh: "針對 LLM 模型本身的攻擊——行為提取、對抗式 fine-tuning、污染訓練資料",
  },
};

export default async function Home({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: rawLocale } = await params;
  const locale = (locales.includes(rawLocale as Locale) ? rawLocale : "en") as Locale;
  const prefix = `/${locale}`;
  const stats = loadSiteStats();
  const zh = locale === "zh";
  const rules = loadAllRules();
  const categories = getCategories(rules);
  const mergedCount = stats.ecosystemIntegrations.filter(e => e.type === "merged").length;

  return (
    <>
      <StatsHydrator />

      {/* ── Scene 1: The Shift (Hero) ── */}
      <section className="bg-paper min-h-screen flex flex-col items-center justify-center text-center px-5 md:px-6 relative overflow-hidden">
        <HeroGrid />

        <div className="relative z-10 max-w-[900px]">
          {/* Logo — full ATR lockup */}
          <HeroEntrance delay={0.5}>
            <img src="/atr-logo-black.png" alt="ATR" className="h-12 md:h-16 mx-auto mb-8 md:mb-10" />
          </HeroEntrance>

          {/* Standards-lineage eyebrow — peer-format framing */}
          <HeroEntrance delay={0.8}>
            <p className="font-display text-[28px] md:text-[clamp(40px,5.5vw,72px)] font-black leading-[1.1] tracking-[-1.5px] md:tracking-[-3px] text-stone">
              {zh ? "Sigma 寫給 SIEM。YARA 寫給 malware。" : "Sigma is for SIEM. YARA is for malware."}
            </p>
          </HeroEntrance>

          {/* H1 — ATR's position in the lineage */}
          <HeroEntrance delay={1.1}>
            <h1 className="font-display text-[36px] md:text-[clamp(52px,6.5vw,80px)] font-black leading-[1.05] tracking-[-2px] md:tracking-[-3px] text-ink mt-2 md:mt-3">
              {zh ? "ATR 寫給 AI agent。" : "ATR is for AI agents."}
            </h1>
          </HeroEntrance>

          {/* Subtitle — definitional, not outcome */}
          <HeroEntrance delay={1.3}>
            <p className="text-base md:text-lg text-stone font-light mt-5 md:mt-6 max-w-[640px] mx-auto leading-relaxed">
              {zh
                ? "AI agent 安全威脅的公共偵測規則格式。版本化、可機器讀取、廠商中立。任何符合規範的引擎都能評估。社群維護,MIT 永久授權。"
                : "An open, versioned, machine-readable detection rule format for AI agent security threats. Any conforming engine can evaluate it. Community-maintained, MIT licensed."}
            </p>
          </HeroEntrance>

          {/* Three monospace stats — emphasize garak recall (more impressive than PINT precision) */}
          <HeroEntrance delay={1.5}>
            <div className="flex flex-wrap items-center justify-center gap-x-6 gap-y-2 mt-8 md:mt-10 font-data text-sm md:text-base tracking-wide">
              <span><span className="font-data font-bold text-ink">{stats.ruleCount}</span> <span className="text-stone">{zh ? "條規則" : "rules"}</span></span>
              <span className="text-fog">·</span>
              <span><span className="font-data font-bold text-ink">{stats.categoryCount}</span> <span className="text-stone">{zh ? "個類別" : "categories"}</span></span>
              <span className="text-fog">·</span>
              <span><span className="font-data font-bold text-ink">97.1%</span> <span className="text-stone">{zh ? "garak 抓得到" : "garak recall"}</span></span>
            </div>
          </HeroEntrance>

          {/* CTAs — procedural, standards-form */}
          <HeroEntrance delay={1.7}>
            <div className="flex gap-3 justify-center flex-wrap mt-7 md:mt-8">
              <Link
                href={`${prefix}/quality-standard`}
                className="bg-blue text-white px-8 md:px-10 py-3.5 md:py-4 rounded-[2px] text-sm font-semibold hover:bg-blue-hover transition-colors"
              >
                {zh ? "讀規範" : "Read the spec"}
              </Link>
              <Link
                href={`${prefix}/rules`}
                className="text-ink px-8 md:px-10 py-3.5 md:py-4 text-sm font-medium border border-fog hover:border-stone transition-colors rounded-[2px]"
              >
                {zh ? "瀏覽規則" : "Browse rules"}
              </Link>
              <Link
                href={`${prefix}/contribute`}
                className="text-ink px-8 md:px-10 py-3.5 md:py-4 text-sm font-medium border border-fog hover:border-stone transition-colors rounded-[2px]"
              >
                {zh ? "投規則" : "Submit a rule"}
              </Link>
            </div>
          </HeroEntrance>

          {/* Trust bar — three rows, standards bodies first, text-only (no logos until vendor brand approval) */}
          <HeroEntrance delay={1.9}>
            <div className="mt-8 md:mt-10 font-data text-[11px] md:text-xs text-stone tracking-wide space-y-1.5">
              {/* Row 1 — peer standards bodies (most important trust signal for a standard) */}
              <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1">
                <span>{zh ? "標準同儕:" : "Standards bodies:"}</span>
                <span className="text-ink">MISP / CIRCL</span>
                <span className="text-fog">·</span>
                <span className="text-ink">OWASP A-S-R-H</span>
                <span className="text-fog">·</span>
                <span className="text-ink">NIST AI RMF (OSCAL)</span>
                <span className="text-fog">·</span>
                <span className="text-ink">OpenTelemetry</span>
              </div>
              {/* Row 2 — production deployments */}
              <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1">
                <span>{zh ? "已上線:" : "In production:"}</span>
                <span className="font-bold text-ink">Cisco AI Defense</span>
                <span className="text-fog">·</span>
                <span className="font-bold text-ink">Microsoft AGT</span>
                <span className="text-fog">·</span>
                <span className="font-bold text-ink">Gen Digital Sage</span>
              </div>
              {/* Row 3 — license + lineage */}
              <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1 pt-1">
                <span>MIT License · {zh ? "ATR 社群維護" : "Maintained by ATR Community"} · {zh ? "規範 v1.0 穩定版" : "Spec v1.0 stable"}</span>
              </div>
            </div>
          </HeroEntrance>
        </div>
      </section>

      <SpeedLines />

      {/* ── Scene 1.5: The Gap (why ATR exists) ── */}
      <section className="py-14 md:py-[100px] px-5 md:px-6 bg-ash">
        <div className="max-w-[980px] mx-auto">
          <Reveal>
            <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-5 md:mb-6">
              {zh ? "為什麼要做新的" : "Why a new standard"}
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="font-display text-[26px] md:text-[clamp(34px,4.5vw,52px)] font-extrabold tracking-[-1px] md:tracking-[-2px] leading-[1.15] text-ink max-w-[820px]">
              {zh
                ? <>舊的偵測規則<br/>抓不到 AI agent 在搞什麼。</>
                : <>Endpoint detection standards<br/>cannot see AI agent behavior.</>}
            </h2>
          </Reveal>
          <Reveal delay={0.2}>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog mt-8 md:mt-12">
              <div className="bg-paper p-6 md:p-8">
                <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">{zh ? "舊時代" : "Old era"}</div>
                <div className="font-display text-xl md:text-2xl font-bold text-ink mb-3">Sigma · YARA · CVE</div>
                <p className="text-sm text-graphite leading-[1.7]">
                  {zh
                    ? "看 log、看檔案、編漏洞編號——盯著程式碼,看不到意圖。"
                    : "Built for endpoint event logs, file binaries, and software vulnerability IDs. They watch code, not intent."}
                </p>
              </div>
              <div className="bg-paper p-6 md:p-8">
                <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">{zh ? "新攻擊面" : "New surface"}</div>
                <div className="font-display text-xl md:text-2xl font-bold text-ink mb-3">{zh ? "AI Agent 的行為" : "AI Agent behavior"}</div>
                <p className="text-sm text-graphite leading-[1.7]">
                  {zh
                    ? "Prompt 注入、工具下毒、skill 被汙染、context 外洩——攻擊發生在 prompt 跟 tool call 層,不在程式檔案層。"
                    : "Prompt injection, tool poisoning, skill compromise, context exfiltration — attacks live at the prompt / tool call / skill layer, not at process / file / network."}
                </p>
              </div>
              <div className="bg-paper p-6 md:p-8 border-l-2 border-blue">
                <div className="font-data text-xs text-blue tracking-[2px] uppercase mb-3">{zh ? "新標準" : "New standard"}</div>
                <div className="font-display text-xl md:text-2xl font-bold text-ink mb-3">ATR</div>
                <p className="text-sm text-graphite leading-[1.7]">
                  {zh
                    ? "不綁特定協議的行為偵測規則。看 agent 在做什麼,不是看它在跑什麼。MIT 永久,社群治理。"
                    : "Protocol-agnostic behavioral detection rules. Watches what an agent does, not just what it runs. MIT forever. Community governed."}
                </p>
              </div>
            </div>
          </Reveal>
          <Reveal delay={0.3}>
            <p className="text-sm md:text-base text-graphite mt-8 max-w-[820px] leading-[1.8]">
              {zh
                ? <>2017 年 Sigma 成為 SIEM 偵測的開放標準之前,每家 SOC 各寫各的規則。1999 年 CVE 出現之前,每家廠商各編各的漏洞編號。<strong>AI Agent 的偵測層,現在就站在那個位置——還沒被任何人標準化。</strong>ATR 把這格填上。</>
                : <>Before Sigma became the open standard for SIEM detection in 2017, every SOC wrote its own rules. Before CVE in 1999, every vendor numbered its own vulnerabilities. <strong>The detection layer for the AI agent era sits in the same position right now — not yet standardized.</strong> ATR fills the gap.</>}
            </p>
          </Reveal>
        </div>
      </section>

      <SpeedLines />

      {/* ── Scene 2: The Threat ── */}
      <section className="py-14 md:py-[120px] px-5 md:px-6">
        <div className="max-w-[1120px] mx-auto">
          <Reveal>
            <div className="font-data text-[clamp(64px,14vw,180px)] font-bold text-critical/[0.12] leading-[0.85] mb-2 md:mb-3">
              <NumberScramble target={stats.megaScanTotal.toLocaleString()} duration={2000} liveKey="megaScanTotal" />
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-4 md:mb-5 leading-[1.8]">
              {zh
                ? "skills 已掃描 — 史上最大規模的 AI agent 安全掃描"
                : "skills scanned — the largest AI agent security scan ever conducted"}
            </div>
          </Reveal>
          <Reveal delay={0.15}>
            <div className="font-data text-[clamp(48px,10vw,120px)] font-bold text-critical/[0.18] leading-[0.9] mb-3 md:mb-4">
              751
            </div>
          </Reveal>
          <Reveal delay={0.2}>
            <h2 className="font-display text-[20px] md:text-[clamp(22px,3vw,32px)] font-extrabold tracking-[-1px] leading-[1.35] mb-3 md:mb-4 max-w-[620px]">
              {zh
                ? <>惡意 AI agent skill。<br />三個協同攻擊者。<br />史上最大的 AI agent 惡意軟體行動。</>
                : <>malicious AI agent skills.<br />Three coordinated threat actors.<br />The largest AI agent malware campaign ever documented.</>}
            </h2>
          </Reveal>
          <Reveal delay={0.25}>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-px bg-fog max-w-[700px]">
              {[
                { actor: "hightower6eu", count: 354, desc: zh ? "Solana / Google Workspace 偽裝" : "Solana / Google Workspace disguise" },
                { actor: "sakaen736jih", count: 212, desc: zh ? "C2 伺服器 91.92.242.30" : "C2 server at 91.92.242.30" },
                { actor: "52yuanchangxing", count: 137, desc: zh ? "偽冒開發工具 + npm typosquat" : "Fake dev tools + npm typosquatting" },
              ].map((a) => (
                <div key={a.actor} className="bg-paper p-4 md:p-5">
                  <div className="font-data text-xs text-stone mb-1">{a.actor}</div>
                  <div className="font-data text-2xl font-bold text-critical">{a.count}</div>
                  <div className="text-xs text-mist mt-1">{a.desc}</div>
                </div>
              ))}
            </div>
          </Reveal>
          <Reveal delay={0.3}>
            <p className="text-sm md:text-base text-graphite max-w-[520px] mt-5 leading-[1.8]">
              {zh
                ? "ATR 掃描 ClawHub、OpenClaw、Skills.sh 等六個 registry，共 96,096 個 skill 時發現了這些攻擊者。751 個惡意 skill 全數加入黑名單，並已通報 NousResearch。"
                : "ATR found these threat actors scanning 96,096 skills across six registries — ClawHub, OpenClaw, Skills.sh, and three others. All 751 blacklisted and reported to NousResearch."}
            </p>
          </Reveal>
          <Reveal delay={0.35}>
            <Link href={`${prefix}/research`} className="font-data text-xs md:text-sm text-blue hover:underline inline-block mt-4">
              {zh ? "閱讀完整研究報告 →" : "Read the full research report →"}
            </Link>
          </Reveal>
        </div>
      </section>

      <SpeedLines />

      {/* ── Scene 2.5: Adopted By ── */}
      <section className="py-14 md:py-[100px] px-5 md:px-6">
        <div className="max-w-[1120px] mx-auto text-center">
          <Reveal>
            <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-8 md:mb-10">
              {zh ? "已被採用" : "Adopted by"}
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog max-w-[900px] mx-auto">
              <div className="bg-paper p-8 md:p-10 text-center">
                <h3 className="font-display text-[24px] md:text-[clamp(28px,3.5vw,40px)] font-extrabold tracking-[-1px] md:tracking-[-2px] leading-[1.1] text-ink">
                  Cisco AI Defense
                </h3>
                <p className="text-sm text-graphite mt-4 leading-[1.7]">
                  {zh ? "PR #79 + #99 已合併 · 330 條完整規則集進入 skill-scanner 生產環境"
                      : "PR #79 + #99 merged · full 330-rule pack in skill-scanner production"}
                </p>
                <a
                  href="https://github.com/cisco-ai-defense/skill-scanner/pull/99"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-data text-xs text-blue hover:underline inline-block mt-3"
                >
                  {zh ? "查看 PR #99 →" : "View PR #99 →"}
                </a>
              </div>
              <div className="bg-paper p-8 md:p-10 text-center">
                <h3 className="font-display text-[24px] md:text-[clamp(28px,3.5vw,40px)] font-extrabold tracking-[-1px] md:tracking-[-2px] leading-[1.1] text-ink">
                  Microsoft AGT
                </h3>
                <p className="text-sm text-graphite mt-4 leading-[1.7]">
                  {zh ? "PR #908 + #1277 已合併 · 287 條規則 + 每週自動同步 workflow"
                      : "PR #908 + #1277 merged · 287 rules + weekly auto-sync workflow"}
                </p>
                <a
                  href="https://github.com/microsoft/agent-governance-toolkit/pull/1277"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-data text-xs text-blue hover:underline inline-block mt-3"
                >
                  {zh ? "查看 PR #1277 →" : "View PR #1277 →"}
                </a>
              </div>
            </div>
          </Reveal>
          <Reveal delay={0.25}>
            <p className="font-data text-xs text-mist mt-8 md:mt-10">
              {zh ? "整合進行中:" : "Integrations in active review:"}{" "}
              <a href="https://github.com/NVIDIA/garak/pull/1676" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">NVIDIA garak #1676</a>
              {" · "}
              <a href="https://github.com/gendigitalinc/sage/pull/33" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">Gen Digital Sage #33</a>
              {" · "}
              <a href="https://github.com/IBM/mcp-context-forge/pull/4109" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">IBM mcp-context-forge #4109</a>
              {" · "}
              <a href="https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/pull/814" target="_blank" rel="noopener noreferrer" className="text-blue hover:underline">OWASP LLM Top 10 #814</a>
            </p>
          </Reveal>
        </div>
      </section>

      {/* ── Scene 3: The Numbers ── */}
      <section className="py-14 md:py-[120px] px-5 md:px-6 bg-ash">
        <div className="max-w-[1120px] mx-auto">
          <Reveal>
            <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-5 md:mb-6">
              {zh ? "數據一覽" : "The Numbers"}
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-[2px] bg-paper mb-[2px]">
              {/* Row 1: quality + scale stats */}
              {[
                { value: stats.ruleCount, suffix: "", label: zh ? "條偵測規則" : "detection rules", desc: zh ? `${stats.categoryCount} 個威脅類別` : `${stats.categoryCount} threat categories`, liveKey: undefined },
                { label: zh ? "HackAPrompt 召回率" : "HackAPrompt recall", rawValue: "66.2%", desc: zh ? "4,780 個對抗性樣本" : "4,780 adversarial samples" },
                { value: stats.pintPrecision, suffix: "%", label: zh ? "PINT 精準度 (0.25% FP)" : "PINT precision (0.25% FP)", desc: zh ? `850 個樣本` : `850 samples`, liveKey: "pintPrecision" },
                { label: "npm", rawValue: "23K", desc: zh ? "月下載量 (30d)" : "monthly downloads (30d)" },
              ].map((item, i) => (
                <Reveal key={i} delay={0.1 + i * 0.05}>
                  <div className="bg-ash p-5 md:p-10">
                    <div className="font-data text-[clamp(28px,5vw,56px)] font-bold text-ink leading-none">
                      {"rawValue" in item ? item.rawValue : <CountUp target={(item as {value: number; suffix: string; liveKey?: string}).value} suffix={(item as {value: number; suffix: string; liveKey?: string}).suffix} liveKey={(item as {value: number; suffix: string; liveKey?: string}).liveKey} />}
                    </div>
                    <div className="font-data text-sm text-stone mt-2 md:mt-3">{item.label}</div>
                    <div className="text-xs text-mist mt-1 leading-relaxed">{item.desc}</div>
                  </div>
                </Reveal>
              ))}
            </div>
            {/* Row 2: integration tiers — split clearly */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-[2px] bg-paper">
              <Reveal delay={0.3}>
                <div className="bg-ash p-5 md:p-8">
                  <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">
                    {zh ? "已在生產環境" : "In production"}
                  </div>
                  <div className="font-data text-[clamp(28px,4vw,48px)] font-bold text-ink leading-none mb-2">2</div>
                  <div className="text-sm text-graphite leading-[1.7]">
                    {zh
                      ? "Microsoft Agent Governance Toolkit · Cisco AI Defense"
                      : "Microsoft Agent Governance Toolkit · Cisco AI Defense"}
                  </div>
                  <div className="text-xs text-mist mt-2">
                    {zh ? "已合併 PR，已進入生產部署" : "Merged PRs, deployed in production"}
                  </div>
                </div>
              </Reveal>
              <Reveal delay={0.35}>
                <div className="bg-ash p-5 md:p-8">
                  <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">
                    {zh ? "正在整合" : "Integrating"}
                  </div>
                  <div className="font-data text-[clamp(28px,4vw,48px)] font-bold text-ink leading-none mb-2">5</div>
                  <div className="text-sm text-graphite leading-[1.7]">
                    {zh
                      ? "NVIDIA garak · MISP taxonomies + galaxy · OWASP A-S-R-H · NIST OSCAL Path 1"
                      : "NVIDIA garak · MISP taxonomies + galaxy · OWASP A-S-R-H · NIST OSCAL Path 1"}
                  </div>
                  <div className="text-xs text-mist mt-2">
                    {zh ? "審查中或已接受" : "Under review or accepted"}
                  </div>
                </div>
              </Reveal>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ── Scene 3.3: Microsoft Copilot Loop Case Study ── */}
      <section className="py-14 md:py-[100px] px-5 md:px-6">
        <div className="max-w-[980px] mx-auto">
          <Reveal>
            <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-5 md:mb-6">
              {zh ? "生產環境閉環案例" : "Production loop — case study"}
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="font-display text-[24px] md:text-[clamp(28px,4vw,48px)] font-extrabold tracking-[-1.5px] md:tracking-[-2px] leading-[1.1] text-ink max-w-[820px] mb-6">
              {zh
                ? <>Microsoft 自己的 AI 工程師把 ATR 當成內建的。</>
                : <>Microsoft&apos;s own autonomous AI engineer treats ATR as built-in.</>}
            </h2>
          </Reveal>
          <Reveal delay={0.15}>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog mb-8">
              {[
                {
                  time: zh ? "2026-05-07" : "2026-05-07",
                  label: zh ? "CVE 公開" : "CVE disclosed",
                  desc: zh
                    ? "MSRC 發布 Semantic Kernel CVE-2026-26030 + CVE-2026-25592"
                    : "MSRC publishes Semantic Kernel CVE-2026-26030 + CVE-2026-25592",
                },
                {
                  time: zh ? "2026-05-11 06:07 UTC" : "2026-05-11 06:07 UTC",
                  label: zh ? "Microsoft Copilot 開 PR" : "Microsoft Copilot opens PR",
                  desc: zh
                    ? "Microsoft Copilot SWE Agent 開 AGT#1981，regression-test fixtures 預設 ATR 偵測已存在"
                    : "Microsoft Copilot SWE Agent opens AGT#1981 with regression-test fixtures presuming ATR detection coverage",
                },
                {
                  time: zh ? "2026-05-11 08:24 UTC" : "2026-05-11 08:24 UTC",
                  label: zh ? "ATR v2.1.2 發布" : "ATR v2.1.2 ships",
                  desc: zh
                    ? "ATR-2026-00440 + ATR-2026-00441 發布到 npm。CVE 公開到規則發布：2 小時 16 分鐘"
                    : "ATR-2026-00440 + ATR-2026-00441 published on npm. CVE disclosure to rule publish: 2h 16m",
                },
              ].map((item) => (
                <div key={item.time} className="bg-paper p-6 md:p-8">
                  <div className="font-data text-[10px] text-stone tracking-[2px] uppercase mb-2">{item.time}</div>
                  <div className="font-display text-sm font-bold text-ink mb-2">{item.label}</div>
                  <p className="text-sm text-graphite leading-[1.7]">{item.desc}</p>
                </div>
              ))}
            </div>
          </Reveal>
          <Reveal delay={0.2}>
            <div className="bg-ash border-l-2 border-blue p-5 md:p-6 max-w-[820px]">
              <p className="text-sm md:text-base text-graphite leading-[1.8]">
                {zh
                  ? "這不是人工安排的整合。Microsoft 的自主 AI 工程師在開 PR 時預設 ATR 已覆蓋——這個假設正確。規則在 2 小時 16 分鐘內驗證並發布。"
                  : "This was not a manually arranged integration. Microsoft's autonomous AI engineer opened the PR assuming ATR coverage existed — and the assumption was correct. Rules were validated and published within 2h 16m."}
              </p>
              <a
                href="https://github.com/microsoft/agent-governance-toolkit/issues/1981"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs text-blue hover:underline inline-block mt-3"
              >
                {zh ? "查看 AGT#1981 →" : "View AGT#1981 →"}
              </a>
            </div>
          </Reveal>
        </div>
      </section>

      {/* ── Scene 3.5: Open Call to Democratic Governments ── */}
      <section className="py-14 md:py-[120px] px-5 md:px-6 bg-paper relative overflow-hidden">
        <HeroGrid />
        <div className="max-w-[980px] mx-auto relative z-10">
          <Reveal>
            <div className="font-data text-[11px] md:text-xs font-medium text-blue tracking-[1.5px] md:tracking-[3px] uppercase mb-5 md:mb-6">
              {zh ? "致民主國家的公開邀請" : "An open invitation"}
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="font-display text-[28px] md:text-[clamp(36px,5vw,60px)] font-extrabold tracking-[-1.5px] md:tracking-[-2.5px] leading-[1.1] text-ink max-w-[860px]">
              {zh
                ? <>每個民主國家都在做主權 AI。<br/><span className="text-stone">沒人在做主權 AI 的防禦層。</span></>
                : <>Every democratic nation is building sovereign AI.<br/><span className="text-stone">None are building sovereign AI defense.</span></>}
            </h2>
          </Reveal>
          <Reveal delay={0.2}>
            <p className="text-base md:text-lg text-graphite mt-8 md:mt-10 max-w-[760px] leading-[1.8]">
              {zh
                ? <>印度、日本、英國、法國、韓國、UAE、台灣——大家都在做自己的主權 AI 模型跟算力。<strong>但沒有任何一個合約包含對應的防禦層。</strong>這個缺口如果沒被開放標準填上,就會被閉源方案、地緣政治綁定的私下協議、或被對岸先補上。</>
                : <>India, Japan, UK, France, Korea, UAE, and Taiwan are all shipping sovereign AI models and compute. <strong>None of these deployments include a corresponding defense layer.</strong> If this gap is not filled by an open standard, it will be filled by closed solutions, geopolitically-tied private agreements, or by adversaries first.</>}
            </p>
          </Reveal>
          <Reveal delay={0.3}>
            <div className="mt-10 md:mt-12 p-6 md:p-8 border-l-2 border-blue bg-ash">
              <p className="font-display text-lg md:text-xl font-bold text-ink leading-[1.5]">
                {zh
                  ? "我們邀請各國的數位部會、AI 安全機構、與標準制定組織,評估 ATR 作為您主權 AI 防禦層的開放基底。"
                  : "We invite digital ministries, AI safety institutes, and standards bodies to evaluate ATR as the open foundation for your sovereign AI defense layer."}
              </p>
              <p className="text-sm md:text-base text-graphite mt-4 leading-[1.7]">
                {zh
                  ? "不被任何廠商綁住。不帶地緣政治條件。可以分叉、可以替換、可以問責。第一個 reference deployment 已在對話中。歡迎任何民主國家加入。"
                  : "No vendor lock-in. No geopolitical strings. Forkable, replaceable, accountable. First reference deployment in discussion. We are seeking conversation partners across democracies."}
              </p>
              <div className="flex flex-wrap gap-x-6 gap-y-3 mt-6 font-data text-xs md:text-sm">
                <a href="mailto:adam@agentthreatrule.org" className="text-blue hover:underline">
                  adam@agentthreatrule.org
                </a>
                <span className="text-fog">·</span>
                <Link href={`${prefix}/sovereign-ai-defense`} className="text-blue hover:underline">
                  {zh ? "閱讀完整公開信 →" : "Read the full manifesto →"}
                </Link>
              </div>
            </div>
          </Reveal>
        </div>
      </section>

      <SpeedLines />

      {/* ── Scene 4: The Categories ── */}
      <section className="py-14 md:py-[120px] px-5 md:px-6">
        <div className="max-w-[1120px] mx-auto">
          <Reveal>
            <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-3 md:mb-4">
              {zh ? "ATR 偵測什麼" : "What ATR Detects"}
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="font-display text-[20px] md:text-[clamp(24px,3.5vw,40px)] font-extrabold tracking-[-1px] md:tracking-[-2px] leading-[1.3] mb-6 md:mb-8 max-w-[700px]">
              {zh
                ? <>{stats.categoryCount} 個威脅類別。<br className="sm:hidden" />{stats.ruleCount} 條規則。真實 CVE。</>
                : <>{stats.categoryCount} threat categories.<br className="sm:hidden" /> {stats.ruleCount} rules. Real CVEs.</>}
            </h2>
          </Reveal>
          <Reveal delay={0.2}>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-px bg-fog">
              {categories.map((cat) => {
                const desc = CATEGORY_DESC[cat.name];
                const displayName = categoryDisplayName(cat.name, locale);
                return (
                  <div key={cat.name} className="bg-paper p-5 md:p-6 hover:bg-ash/50 transition-colors">
                    <div className="font-display text-sm font-semibold text-ink">{displayName}</div>
                    <div className="font-data text-xs text-blue mt-1.5">{cat.count} {zh ? "條規則" : "rules"}</div>
                    <p className="text-sm text-stone mt-2">
                      {desc ? (zh ? desc.zh : desc.en) : cat.name}
                    </p>
                  </div>
                );
              })}
            </div>
          </Reveal>
          <Reveal delay={0.3}>
            <div className="mt-5 md:mt-6">
              <Link href={`${prefix}/rules`} className="font-data text-xs md:text-sm text-blue hover:underline">
                {zh ? "瀏覽所有規則 + YAML 詳情 →" : "Browse all rules + YAML details →"}
              </Link>
            </div>
          </Reveal>
        </div>
      </section>

      <SpeedLines />

      {/* ── Scene 5: The Proof ── */}
      <section className="py-14 md:py-[120px] px-5 md:px-6">
        <div className="max-w-[1120px] mx-auto">
          <Reveal>
            <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-3 md:mb-4">
              {zh ? "已在生產環境運行" : "Already in Production"}
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="font-display text-[20px] md:text-[clamp(24px,3.5vw,48px)] font-extrabold tracking-[-1px] md:tracking-[-2px] leading-[1.35] max-w-[800px]">
              <span className="text-blue">Cisco AI Defense</span>
              {zh
                ? <><br className="md:hidden" />將 34 條 ATR 規則<br className="sm:hidden" />作為上游依賴。</>
                : <><br className="md:hidden" /> ships 34 ATR rules<br className="sm:hidden" /> as upstream.</>}
            </h2>
          </Reveal>
          <Reveal delay={0.2}>
            <p className="text-sm md:text-base text-graphite max-w-[560px] mt-3 md:mt-4 leading-[1.7]">
              {zh
                ? "他們的工程師提了 PR，我們審查完 3 天合併，1,272 行新增。然後他們專門建了 CLI 來消費 ATR 規則。"
                : "Their engineer submitted a PR. We reviewed it. Merged in 3 days. 1,272 additions. Then they built a CLI specifically to consume ATR rules."}
            </p>
          </Reveal>
          <Reveal delay={0.3}>
            <a
              href="https://github.com/cisco-ai-defense/skill-scanner/pull/79"
              target="_blank"
              rel="noopener noreferrer"
              className="font-data text-xs md:text-sm text-blue hover:underline inline-block mt-3 md:mt-4"
            >
              {zh ? "在 GitHub 查看 PR #79 →" : "View PR #79 on GitHub →"}
            </a>
          </Reveal>

          <Reveal delay={0.35}>
            <div className="mt-8 md:mt-10 border-t border-fog pt-6 md:pt-8 max-w-[560px]">
              <h3 className="font-display text-lg md:text-xl font-semibold text-ink tracking-[-0.5px] leading-[1.3]">
                <span className="text-blue">Microsoft AGT</span>
                {zh ? " 合併了 15 條 ATR 規則。" : " merged 15 ATR rules."}
              </h3>
              <p className="text-sm md:text-base text-graphite mt-2 md:mt-3 leading-[1.7]">
                {zh
                  ? "改寫為 AGT 的 PolicyDocument 格式，554 行新增。"
                  : "Adapted as PolicyDocument, AGT's native policy format. 554 additions."}
              </p>
              <a
                href="https://github.com/microsoft/agent-governance-toolkit/pull/908"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-xs md:text-sm text-blue hover:underline inline-block mt-3"
              >
                {zh ? "在 GitHub 查看 PR #908 →" : "View PR #908 on GitHub →"}
              </a>
            </div>
          </Reveal>

          <Reveal delay={0.4}>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-fog mt-10 md:mt-12">
              {[
                { num: "34", label: zh ? "條規則已合併" : "rules merged", sub: "Cisco AI Defense" },
                { num: String(stats.ruleCount), label: zh ? "條偵測規則" : "detection rules", sub: zh ? `跨 ${stats.categoryCount} 個類別` : `across ${stats.categoryCount} categories` },
                { num: stats.megaScanTotal.toLocaleString(), label: zh ? "skills 已掃描" : "skills scanned", sub: zh ? "跨多個 registry" : "across registries" },
                { num: `${mergedCount}/${stats.ecosystemIntegrations.length}`, label: zh ? "生態系 PR" : "ecosystem PRs", sub: zh ? "已合併" : "merged" },
              ].map((item) => (
                <div key={item.label} className="bg-paper p-5 md:p-6">
                  <div className="font-data text-2xl sm:text-[clamp(24px,4vw,36px)] font-bold text-ink leading-none">{item.num}</div>
                  <div className="font-data text-xs text-stone mt-2">{item.label}</div>
                  <div className="text-xs text-mist mt-1">{item.sub}</div>
                </div>
              ))}
            </div>
          </Reveal>
        </div>
      </section>

      {/* ── Scene 6: The Standards ── */}
      <section className="py-14 md:py-[100px] px-5 md:px-6 bg-ash">
        <div className="max-w-[1120px] mx-auto">
          <Reveal>
            <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-5 md:mb-6">
              {zh ? "標準覆蓋" : "Standards Coverage"}
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-paper">
              {[
                { name: "OWASP Agentic", score: "10/10", desc: zh ? "完整覆蓋" : "Full coverage" },
                { name: "SAFE-MCP", score: "91.8%", desc: zh ? "78/85 技術" : "78/85 techniques" },
                { name: "OWASP AST10", score: "7/10", desc: zh ? "3 個是流程層級" : "3 are process-level" },
                { name: "PINT F1", score: "76.7", desc: zh ? "850 個樣本" : "850 samples" },
              ].map((s) => (
                <div key={s.name} className="bg-ash p-6 md:p-8 text-center">
                  <div className="font-data text-[10px] md:text-xs font-medium text-stone tracking-[2px] uppercase mb-2 md:mb-3">{s.name}</div>
                  <div className="font-data text-[clamp(28px,4vw,48px)] font-bold text-ink leading-none">{s.score}</div>
                  <div className="text-xs text-mist mt-2">{s.desc}</div>
                </div>
              ))}
            </div>
          </Reveal>
          <Reveal delay={0.2}>
            <p className="text-sm text-graphite max-w-[520px] mt-5 leading-[1.8]">
              {zh
                ? "框架告訴你威脅存在，ATR 告訴你怎麼偵測。ATR 對 MITRE ATLAS 的關係，就像 Sigma 規則對 ATT&CK 的關係。"
                : "Frameworks tell you threats exist. ATR tells you how to detect them. ATR is to MITRE ATLAS what Sigma rules are to ATT&CK."}
            </p>
          </Reveal>
          <Reveal delay={0.25}>
            <Link href={`${prefix}/coverage`} className="font-data text-xs md:text-sm text-blue hover:underline inline-block mt-3">
              {zh ? "查看完整覆蓋對照表 →" : "View full coverage mapping →"}
            </Link>
          </Reveal>
        </div>
      </section>

      {/* ── Scene 7: Threat Crystallization ── */}
      <section className="py-14 md:py-[120px] px-5 md:px-6">
        <div className="max-w-[1120px] mx-auto">
          <Reveal>
            <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-3 md:mb-4">
              {zh ? "威脅結晶化" : "THREAT CRYSTALLIZATION"}
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="font-display text-[20px] md:text-[clamp(24px,3.5vw,48px)] font-extrabold tracking-[-1px] md:tracking-[-2px] leading-[1.35] max-w-[700px] mb-3">
              {zh
                ? <>每一次攻擊，都讓所有人更安全。</>
                : <>Every attack makes everyone safer.</>}
            </h2>
          </Reveal>
          <Reveal delay={0.15}>
            <p className="text-sm md:text-base text-graphite font-light max-w-[600px] mb-4 leading-[1.8]">
              {zh
                ? <>Threat Cloud 的運作原理就像免疫系統。LLM 語義分析（適應性免疫）抓到新型攻擊後，把偵測邏輯「結晶」成 regex 規則（先天免疫）——從每次 500ms 的推理成本，變成 5ms 的 pattern match。926 份威脅報告產生了 42 條結晶規則，4.5% 的結晶率代表剩下的 95.5% 已被現有規則覆蓋。</>
                : <>Threat Cloud works like an immune system. When the LLM semantic layer (adaptive immunity) catches a novel attack, it crystallizes the detection logic into a regex rule (innate immunity) &mdash; turning a $0.001 / 500ms inference into a $0 / 5ms pattern match. 926 threat reports produced 42 crystallized rules. The 4.5% crystallization rate means 95.5% of threats are already covered by existing rules.</>}
            </p>
          </Reveal>
          <Reveal delay={0.18}>
            <p className="text-sm text-stone font-light max-w-[600px] mb-6 md:mb-8 leading-[1.8]">
              {zh
                ? <>這個飛輪已經在運轉。96,096 次掃描發現 751 個惡意 skill，觸發結晶流程，新規則再回頭掃描——一個不斷自我強化的循環。</>
                : <>The flywheel is already turning. The 96,096-skill scan discovered 751 malware, triggered crystallization, and new rules re-scanned the ecosystem &mdash; a self-reinforcing loop.</>}
            </p>
          </Reveal>

          <Reveal delay={0.2}>
            <Flywheel locale={locale} />
          </Reveal>

          {/* Validated flywheel data */}
          <Reveal delay={0.25}>
            <div className="mt-8 md:mt-10 grid grid-cols-2 sm:grid-cols-4 gap-px bg-fog max-w-[620px]">
              {[
                { num: "926", label: zh ? "威脅報告" : "threat reports" },
                { num: "42", label: zh ? "結晶規則" : "crystallized rules" },
                { num: "4.5%", label: zh ? "結晶率" : "crystallization rate" },
                { num: "<48h", label: zh ? "偵測到部署" : "detect to deploy" },
              ].map((item) => (
                <div key={item.label} className="bg-paper p-4 md:p-5 text-center">
                  <div className="font-data text-xl md:text-2xl font-bold text-ink">{item.num}</div>
                  <div className="text-xs text-stone mt-1">{item.label}</div>
                </div>
              ))}
            </div>
          </Reveal>
          <Reveal delay={0.3}>
            <div className="mt-4 max-w-[620px] md:flex md:items-center md:gap-2">
              <div className="h-px flex-1 bg-fog hidden md:block" />
              <span className="font-data text-[10px] text-mist tracking-[1px] block text-center">
                {zh ? "更多端點 = 更多資料 = 更強規則" : "More endpoints = more data = stronger rules"}
              </span>
              <div className="h-px flex-1 bg-fog hidden md:block" />
            </div>
          </Reveal>
        </div>
      </section>

      <SpeedLines />

      {/* ── Scene 8: Integrate — per DESIGN.md §9 ── */}
      <section className="py-14 md:py-[120px] px-5 md:px-6 bg-ash">
        <div className="max-w-[1120px] mx-auto text-center">
          <Reveal>
            <h2 className="font-display text-[24px] md:text-[clamp(28px,4vw,56px)] font-black tracking-[-1.5px] md:tracking-[-2px] mb-6 md:mb-8 text-ink">
              {zh ? "開始整合 ATR。" : "Integrate ATR."}
            </h2>
          </Reveal>

          {/* Terminal demo — moved here from hero */}
          <Reveal delay={0.1}>
            <div className="bg-paper border border-fog rounded-[2px] overflow-hidden max-w-[520px] mx-auto text-left">
              <div className="flex items-center gap-2 px-3 py-2 border-b border-fog">
                <span className="font-data text-xs text-mist">{zh ? "一行指令。即時結果。" : "One command. Instant results."}</span>
              </div>
              <div className="p-3 md:p-4 font-data text-[11px] md:text-sm leading-[1.8]">
                <div className="text-stone">$ <span className="text-ink">npx agent-threat-rules scan .</span></div>
                <div className="text-mist mt-2"># {zh ? "結果" : "results"}</div>
                <div className="text-green">{zh ? "  3 個 SKILL.md 已掃描" : "  3 SKILL.md scanned"}</div>
                <div className="text-green">{zh ? "  12 個工具描述已檢查" : "  12 tool descriptions checked"}</div>
                <div className="text-critical mt-1">{zh ? "  1 CRITICAL: 工具描述中的憑證竊取" : "  1 CRITICAL: credential theft"}</div>
                <div className="text-critical">{zh ? "    ATR-2026-00121" : "    rule ATR-2026-00121"}</div>
                <div className="text-stone mt-2">{zh ? "47ms 完成。" : "Done in 47ms."}</div>
              </div>
            </div>
          </Reveal>

          <Reveal delay={0.2}>
            <p className="text-sm md:text-base text-stone font-light max-w-[480px] mx-auto mb-7 md:mb-8 mt-6 md:mt-8 leading-[1.8]">
              {zh
                ? "TypeScript、Python、Raw YAML、SIEM 轉換器——四種整合路徑。"
                : "TypeScript, Python, Raw YAML, SIEM converters. Four integration paths."}
            </p>
          </Reveal>
          <Reveal delay={0.3}>
            <div className="flex gap-3 justify-center flex-wrap">
              <Link
                href={`${prefix}/integrate`}
                className="bg-blue text-white px-8 md:px-10 py-3.5 md:py-4 rounded-[2px] text-sm font-semibold hover:bg-blue-hover transition-colors"
              >
                {zh ? "整合指南" : "Integration Guide"}
              </Link>
              <Link
                href={`${prefix}/threats`}
                className="text-ink px-8 md:px-10 py-3.5 md:py-4 text-sm font-medium border border-fog hover:border-stone transition-colors rounded-[2px]"
              >
                {zh ? "查看威脅清單" : "View Threat Feed"}
              </Link>
            </div>
          </Reveal>
        </div>
      </section>
    </>
  );
}
