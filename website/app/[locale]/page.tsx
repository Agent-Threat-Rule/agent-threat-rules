/* ATR Homepage — 7-scene narrative (redesigned: deduped credibility, restrained name-drops) */
import { HeroEntrance } from "@/components/HeroEntrance";
import { CountUp } from "@/components/CountUp";
import { SpeedLines } from "@/components/SpeedLines";
import { Reveal } from "@/components/Reveal";
import { StatsHydrator } from "@/components/StatsHydrator";
import { NumberScramble } from "@/components/NumberScramble";
import { Flywheel } from "@/components/Flywheel";
import { HeroGrid } from "@/components/DotGrid";
import { EcosystemWall } from "@/components/EcosystemWall";
import { loadSiteStats } from "@/lib/stats";
import { getSpecMeta } from "@/lib/spec-meta";
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
  "data-poisoning": {
    en: "Corrupting training data, memory, or retrieval sources to bias agent behavior",
    zh: "污染訓練資料、記憶體或檢索來源以扭曲 agent 行為",
  },
  "model-abuse": {
    en: "Misusing model capabilities — jailbreaks, harmful generation, resource abuse",
    zh: "濫用模型能力——越獄、有害內容生成、資源濫用",
  },
  "model-security": {
    en: "Attacks on the model itself — extraction, inversion, adversarial inputs",
    zh: "針對模型本身的攻擊——模型提取、逆向還原、對抗式輸入",
  },
};

export default async function Home({ params }: { params: Promise<{ locale: string }> }) {
  const { locale: rawLocale } = await params;
  const locale = (locales.includes(rawLocale as Locale) ? rawLocale : "en") as Locale;
  const prefix = `/${locale}`;
  const stats = loadSiteStats();
  const zh = locale === "zh";
  const rules = loadAllRules();
  // Display the full defined taxonomy (10 categories) — consistent with the
  // spec, stats.json, and every other ATR material. The live rule set currently
  // populates 8; sort populated categories first so the grid still leads with
  // substance.
  const categoryCounts = new Map(getCategories(rules).map((c) => [c.name, c.count]));
  const taxonomy = Object.keys(CATEGORY_DESC).sort(
    (a, b) => (categoryCounts.get(b) ?? 0) - (categoryCounts.get(a) ?? 0)
  );
  const categoryCount = taxonomy.length;
  const mergedCount = stats.ecosystemIntegrations.filter(e => e.type === "merged").length;
  const specVersion = getSpecMeta().version;
  // Tier 1 in ADOPTERS.md = shipped in a publicly-available product.
  const productionCount = stats.ecosystemIntegrations.filter(
    (e) => e.tier === "1" && e.type === "merged",
  ).length;
  // The home logo wall shows standards bodies, production deployments, and
  // tooling/SDK integrations (tiers S/1/2). Catalogue and documentation
  // references (tier 3) are summarised as a count with a pointer to /ecosystem.
  const wallIntegrations = stats.ecosystemIntegrations.filter(
    (e) => e.tier === "S" || e.tier === "1" || e.tier === "2",
  );
  const tier3Merged = stats.ecosystemIntegrations.filter(
    (e) => e.tier === "3" && e.type === "merged",
  ).length;
  // Pull garak recall from the version-pinned measurement (data/measurements/garak/latest.json)
  // rather than hardcoding — keeps the hero stat honest as the corpus is re-run.
  const garakMeasurement = stats.benchmarks.find((b) => b.source === "garak");
  const garakRecall = garakMeasurement
    ? (Math.round(garakMeasurement.recall * 1000) / 10).toFixed(1)
    : "97.2";

  return (
    <>
      <StatsHydrator />

      {/* ── Scene 1: The Shift (Hero) ── */}
      <section className="bg-paper min-h-screen flex flex-col items-center justify-center text-center px-5 md:px-6 pt-32 pb-24 md:pt-40 md:pb-32 relative overflow-hidden">
        <HeroGrid />

        <div className="relative z-10 max-w-[820px]">
          {/* Standards-lineage eyebrow — peer-format framing.
              (Hero logo removed: the nav already carries the ATR lockup, and a
              second oversized logo here collided with the sticky nav on load.) */}
          <HeroEntrance delay={0.6}>
            <p className="font-display text-[18px] md:text-[clamp(22px,2.6vw,32px)] font-semibold leading-[1.35] tracking-[-0.3px] text-mist text-balance">
              {zh ? "Sigma 寫給 SIEM。YARA 寫給 malware。" : "Sigma is for SIEM. YARA is for malware."}
            </p>
          </HeroEntrance>

          {/* H1 — ATR's position in the lineage */}
          <HeroEntrance delay={0.9}>
            <h1 className="font-display text-[40px] md:text-[clamp(48px,5.6vw,72px)] font-black leading-[1.04] tracking-[-1.5px] md:tracking-[-2.5px] text-ink mt-3 md:mt-4 text-balance">
              {zh ? "ATR 寫給 AI agent。" : "ATR is for AI agents."}
            </h1>
          </HeroEntrance>

          {/* Mission tagline — short, italic, between H1 and subtitle. */}
          <HeroEntrance delay={1.0}>
            <p className="mt-7 md:mt-9 text-sm md:text-base italic text-stone font-light max-w-[580px] mx-auto leading-[1.7] text-pretty">
              {zh
                ? "一條在台北寫的規則,能擋下西雅圖首次通報的攻擊——規則格式不必有人重新發明。"
                : "Built so a rule written in Taipei catches an attack first reported in Seattle — without anyone reinventing the rule format."}
            </p>
          </HeroEntrance>

          {/* Subtitle — definitional, not outcome */}
          <HeroEntrance delay={1.1}>
            <p className="text-base md:text-lg text-stone font-light mt-5 md:mt-7 max-w-[600px] mx-auto leading-[1.75] text-pretty">
              {zh
                ? "AI agent 安全威脅的公共偵測規則格式。版本化、可機器讀取、廠商中立,任何符合規範的引擎都能評估。社群維護,MIT 永久授權。"
                : "An open, versioned, machine-readable detection rule format for AI agent security threats. Any conforming engine can evaluate it. Community-maintained, MIT licensed."}
            </p>
          </HeroEntrance>

          {/* Three monospace stats */}
          <HeroEntrance delay={1.3}>
            <div className="flex flex-wrap items-center justify-center gap-x-8 gap-y-2 mt-11 md:mt-14 font-data text-sm md:text-base tracking-wide">
              <span><span className="font-data font-bold text-ink">{stats.ruleCount}</span> <span className="text-stone">{zh ? "條規則" : "rules"}</span></span>
              <span className="text-fog">·</span>
              <span><span className="font-data font-bold text-ink">{categoryCount}</span> <span className="text-stone">{zh ? "個類別" : "categories"}</span></span>
              <span className="text-fog">·</span>
              <span><span className="font-data font-bold text-ink">{garakRecall}%</span> <span className="text-stone">{zh ? "garak 抓得到" : "garak recall"}</span></span>
            </div>
          </HeroEntrance>

          {/* Document Status strip — W3C-style version + status + canonical URL. */}
          <HeroEntrance delay={1.4}>
            <Link
              href={`${prefix}/spec`}
              className="mt-5 inline-flex flex-wrap items-center justify-center gap-x-2 gap-y-1 font-data text-[10px] md:text-[11px] tracking-[0.08em] uppercase text-stone hover:text-ink transition-colors px-3 py-1.5 border border-fog rounded-[2px] group"
              aria-label={zh ? `規格 Working Draft v${specVersion}` : `Specification Working Draft v${specVersion}`}
            >
              <span className="text-ink font-semibold">Working Draft</span>
              <span className="text-fog">·</span>
              <span>v{specVersion}</span>
              {stats.lastRegenerated && (
                <>
                  <span className="text-fog">·</span>
                  <span>{zh ? `最新發布 ${stats.lastRegenerated}` : `latest release ${stats.lastRegenerated}`}</span>
                </>
              )}
              <span className="text-fog">·</span>
              <span>{zh ? "正式網址" : "canonical"} <span className="text-ink group-hover:underline">/spec</span></span>
            </Link>
          </HeroEntrance>

          {/* CTAs — procedural, standards-form */}
          <HeroEntrance delay={1.5}>
            <div className="flex gap-3 justify-center flex-wrap mt-9 md:mt-11">
              <Link
                href={`${prefix}/spec`}
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

          {/* Secondary text link — keeps RFC-001 discoverable */}
          <HeroEntrance delay={1.6}>
            <div className="mt-3 text-xs text-stone">
              <Link
                href={`${prefix}/quality-standard`}
                className="hover:text-ink underline-offset-4 hover:underline transition-colors"
              >
                {zh ? "規則晉升標準 (RFC-001) →" : "Quality standard (RFC-001) →"}
              </Link>
            </div>
          </HeroEntrance>

          {/* Trust bar — two restrained rows. Detailed adoption lives in the
              consolidated section below; here it is a single touch each. */}
          <HeroEntrance delay={1.7}>
            <div className="mt-16 md:mt-24 pt-8 md:pt-10 border-t border-fog/60 font-data text-[11px] md:text-xs text-mist tracking-wide space-y-2">
              <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1">
                <span>{zh ? "標準同儕:" : "Standards bodies:"}</span>
                <span className="text-ink">MISP / CIRCL</span>
                <span className="text-fog">·</span>
                <span className="text-ink">OWASP</span>
                <span className="text-fog">·</span>
                <span className="text-ink">NIST AI RMF (OSCAL)</span>
                <span className="text-fog">·</span>
                <span className="text-ink">OpenTelemetry</span>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1">
                <span>{zh ? "已上線:" : "In production:"}</span>
                <span className="font-semibold text-ink">Microsoft AGT</span>
                <span className="text-fog">·</span>
                <span className="font-semibold text-ink">Cisco AI Defense</span>
                <span className="text-fog">·</span>
                <span className="font-semibold text-ink">Gen Digital Sage</span>
              </div>
            </div>
          </HeroEntrance>
        </div>
      </section>

      <SpeedLines />

      {/* ── Scene 2: The Gap (why ATR exists) ── */}
      <section className="py-14 md:py-[100px] px-5 md:px-6 bg-ash">
        <div className="max-w-[980px] mx-auto">
          <Reveal>
            <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-5 md:mb-6">
              {zh ? "為什麼要做新的" : "Why a new standard"}
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="font-display text-[26px] md:text-[clamp(34px,4.5vw,52px)] font-extrabold tracking-[-1px] md:tracking-[-2px] leading-[1.15] text-ink max-w-[820px] text-balance">
              {zh
                ? <>舊的偵測標準,<br className="hidden md:block"/>看不到 AI agent 的行為。</>
                : <>Endpoint detection standards<br className="hidden md:block"/> cannot see AI agent behavior.</>}
            </h2>
          </Reveal>
          <Reveal delay={0.2}>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog mt-8 md:mt-12">
              <div className="bg-paper p-6 md:p-8">
                <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">{zh ? "舊時代" : "Old era"}</div>
                <div className="font-display text-xl md:text-2xl font-bold text-ink mb-3">Sigma · YARA · CVE</div>
                <p className="text-sm text-graphite leading-[1.7] text-pretty">
                  {zh
                    ? "看 log、看檔案、編漏洞編號——盯著程式碼,看不到意圖。"
                    : "Built for endpoint event logs, file binaries, and software vulnerability IDs. They watch code, not intent."}
                </p>
              </div>
              <div className="bg-paper p-6 md:p-8">
                <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-3">{zh ? "新攻擊面" : "New surface"}</div>
                <div className="font-display text-xl md:text-2xl font-bold text-ink mb-3">{zh ? "AI Agent 的行為" : "AI Agent behavior"}</div>
                <p className="text-sm text-graphite leading-[1.7] text-pretty">
                  {zh
                    ? "Prompt 注入、工具下毒、skill 被汙染、context 外洩——攻擊發生在 prompt 跟 tool call 層,不在程式檔案層。"
                    : "Prompt injection, tool poisoning, skill compromise, context exfiltration — attacks live at the prompt / tool call / skill layer, not at process / file / network."}
                </p>
              </div>
              <div className="bg-paper p-6 md:p-8 border-l-2 border-blue">
                <div className="font-data text-xs text-blue tracking-[2px] uppercase mb-3">{zh ? "新標準" : "New standard"}</div>
                <div className="font-display text-xl md:text-2xl font-bold text-ink mb-3">ATR</div>
                <p className="text-sm text-graphite leading-[1.7] text-pretty">
                  {zh
                    ? "廠商中立、機器可讀的行為偵測規則。看 agent 在做什麼,不是看它在跑什麼。任何符合規範的引擎都能評估。MIT 永久,社群治理。"
                    : "Vendor-neutral, machine-readable behavioral detection rules. Watches what an agent does, not just what it runs. Any conforming engine can evaluate it. MIT forever. Community governed."}
                </p>
              </div>
            </div>
          </Reveal>
          <Reveal delay={0.3}>
            <p className="text-sm md:text-base text-graphite mt-8 max-w-[820px] leading-[1.8] text-pretty">
              {zh
                ? <>2017 年 Sigma 成為 SIEM 偵測的開放標準之前,每家 SOC 各寫各的規則。1999 年 CVE 出現之前,每家廠商各編各的漏洞編號。<strong>AI Agent 的偵測層,現在就站在那個位置——還沒被任何人標準化。</strong>ATR 把這格填上。</>
                : <>Before Sigma became the open standard for SIEM detection in 2017, every SOC wrote its own rules. Before CVE in 1999, every vendor numbered its own vulnerabilities. <strong>The detection layer for the AI agent era sits in the same position right now — not yet standardized.</strong> ATR fills the gap.</>}
            </p>
          </Reveal>
        </div>
      </section>

      <SpeedLines />

      {/* ── Scene 3: The Threat (mega-scan) ── */}
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
              1,302
            </div>
          </Reveal>
          <Reveal delay={0.2}>
            <h2 className="font-display text-[20px] md:text-[clamp(22px,3vw,32px)] font-extrabold tracking-[-1px] leading-[1.35] mb-3 md:mb-4 max-w-[620px] text-balance">
              {zh
                ? <>個 skill 被標記,552 個經人工複審確認為惡意。三個協同攻擊者。史上最大的 AI agent 惡意軟體行動。</>
                : <>skills flagged, 552 confirmed malware after manual review. Three coordinated threat actors. The largest AI agent malware campaign ever documented.</>}
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
            <p className="text-sm md:text-base text-graphite max-w-[520px] mt-5 leading-[1.8] text-pretty">
              {zh
                ? "ATR 掃描 ClawHub、OpenClaw、Skills.sh 等六個 registry,共 96,096 個 skill 時發現了這些攻擊者。1,302 個 skill 被標記,經人工複審後確認 552 個為惡意,全數加入黑名單並已通報 NousResearch。"
                : "ATR found these threat actors scanning 96,096 skills across six registries — ClawHub, OpenClaw, Skills.sh, and three others. 1,302 were flagged; 552 confirmed malware after manual review, all blacklisted and reported to NousResearch."}
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

      {/* ── Scene 4: What ATR Detects (categories) ── */}
      <section className="py-14 md:py-[120px] px-5 md:px-6">
        <div className="max-w-[1120px] mx-auto">
          <Reveal>
            <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-3 md:mb-4">
              {zh ? "ATR 偵測什麼" : "What ATR Detects"}
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="font-display text-[20px] md:text-[clamp(24px,3.5vw,40px)] font-extrabold tracking-[-1px] md:tracking-[-2px] leading-[1.3] mb-6 md:mb-8 max-w-[700px] text-balance">
              {zh
                ? <>{categoryCount} 個威脅類別。{stats.ruleCount} 條規則。真實 CVE。</>
                : <>{categoryCount} threat categories. {stats.ruleCount} rules. Real CVEs.</>}
            </h2>
          </Reveal>
          <Reveal delay={0.2}>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-px bg-fog">
              {taxonomy.map((name) => {
                const desc = CATEGORY_DESC[name];
                const count = categoryCounts.get(name) ?? 0;
                const displayName = categoryDisplayName(name, locale);
                return (
                  <div key={name} className="bg-paper p-5 md:p-6 hover:bg-ash/50 transition-colors">
                    <div className="font-display text-sm font-semibold text-ink">{displayName}</div>
                    <div className="font-data text-xs text-blue mt-1.5">{count} {zh ? "條規則" : "rules"}</div>
                    <p className="text-sm text-stone mt-2 text-pretty">
                      {desc ? (zh ? desc.zh : desc.en) : name}
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

      {/* ── Scene 5: Adoption + Integration (consolidated) ──
          One section replaces the former Adopted-By / Numbers / Copilot-Loop /
          Proof scenes. Restrained name-drops: each adopter appears once in the
          row; the Microsoft Copilot loop is the single highlighted proof. */}
      <section className="py-14 md:py-[120px] px-5 md:px-6 bg-ash">
        <div className="max-w-[1120px] mx-auto">
          <Reveal>
            <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-3 md:mb-4">
              {zh ? "已被採用" : "Adopted by"}
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="font-display text-[24px] md:text-[clamp(28px,4vw,48px)] font-extrabold tracking-[-1.5px] md:tracking-[-2px] leading-[1.15] text-ink max-w-[820px] text-balance">
              {zh
                ? "已在生產環境運行的安全平台,把 ATR 當成上游規則來源。"
                : "Security platforms run ATR in production as an upstream rule source."}
            </h2>
          </Reveal>

          {/* Production adopters — one row, one mention each, PR-linked */}
          <Reveal delay={0.2}>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-px bg-fog mt-8 md:mt-10">
              {[
                {
                  name: "Microsoft AGT",
                  detail: zh ? "PR #908 + #1277 已合併 · 287 條規則(合併當時)+ 每週自動同步" : "PR #908 + #1277 merged · 287 rules (at PR time) + weekly auto-sync",
                  href: "https://github.com/microsoft/agent-governance-toolkit/pull/1277",
                },
                {
                  name: "Cisco AI Defense",
                  detail: zh ? "PR #79 + #99 已合併 · 完整規則集進入 skill-scanner 生產環境" : "PR #79 + #99 merged · full rule pack in skill-scanner production",
                  href: "https://github.com/cisco-ai-defense/skill-scanner/pull/99",
                },
                {
                  name: "Gen Digital Sage",
                  detail: zh ? "PR #33 已合併 · Norton / Avast / LifeLock 母集團的 agentic-AI 風險評分層" : "PR #33 merged · agentic-AI risk-scoring layer at the Norton / Avast / LifeLock parent",
                  href: "https://github.com/gendigitalinc/sage/pull/33",
                },
              ].map((a) => (
                <div key={a.name} className="bg-paper p-6 md:p-8">
                  <h3 className="font-display text-lg md:text-xl font-bold text-ink tracking-[-0.5px]">{a.name}</h3>
                  <p className="text-sm text-graphite mt-3 leading-[1.7] text-pretty">{a.detail}</p>
                  <a href={a.href} target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline inline-block mt-3">
                    {zh ? "查看 PR →" : "View PR →"}
                  </a>
                </div>
              ))}
            </div>
          </Reveal>

          {/* Single highlighted proof: the autonomous-integration loop */}
          <Reveal delay={0.25}>
            <div className="mt-6 md:mt-8 bg-paper border-l-2 border-blue p-5 md:p-7 max-w-[860px]">
              <div className="font-data text-[10px] md:text-xs text-stone tracking-[2px] uppercase mb-3">
                {zh ? "生產環境閉環 · 2 小時 16 分" : "Production loop · 2h 16m"}
              </div>
              <p className="font-display text-base md:text-lg font-semibold text-ink leading-[1.5] text-balance">
                {zh
                  ? "Microsoft 的自主 AI 工程師開 PR 時,預設 ATR 已覆蓋——而這個假設是對的。"
                  : "Microsoft's autonomous AI engineer opened a PR assuming ATR coverage existed — and the assumption was correct."}
              </p>
              <p className="text-sm md:text-base text-graphite mt-3 leading-[1.8] text-pretty">
                {zh
                  ? "2026-05-11,Copilot SWE Agent 為兩個 Semantic Kernel CVE 開了 AGT#1981,regression fixtures 預設 ATR 偵測存在。規則在 2 小時 16 分鐘內驗證並發布到 npm。不是人工安排的整合。"
                  : "On 2026-05-11, the Copilot SWE Agent opened AGT#1981 for two Semantic Kernel CVEs with regression fixtures presuming ATR detection. Rules were validated and published to npm within 2h 16m. Not a manually arranged integration."}
              </p>
              <a href="https://github.com/microsoft/agent-governance-toolkit/issues/1981" target="_blank" rel="noopener noreferrer" className="font-data text-xs text-blue hover:underline inline-block mt-3">
                {zh ? "查看 AGT#1981 →" : "View AGT#1981 →"}
              </a>
            </div>
          </Reveal>

          {/* Ecosystem wall — standards bodies, production deployments, and
              tooling integrations, derived from ADOPTERS.md (single source of
              truth) with the merging org's logo on every shipped entry. */}
          <Reveal delay={0.3}>
            <div className="mt-8 md:mt-10">
              <div className="font-data text-[11px] md:text-xs text-stone tracking-[1.5px] md:tracking-[2px] uppercase mb-4">
                {zh ? "誰在出貨這個標準" : "Who ships the standard"}
              </div>
              <EcosystemWall integrations={wallIntegrations} locale={locale} />
              <p className="font-data text-xs text-stone mt-5">
                {zh
                  ? `另有 ${tier3Merged} 個公開目錄與文件索引收錄 ATR — `
                  : `Plus ${tier3Merged} public catalogues and documentation indices listing ATR — `}
                <Link href={`${prefix}/ecosystem`} className="text-blue hover:underline">
                  {zh ? "完整採用清單" : "full adopter list"}
                </Link>
              </p>
            </div>
          </Reveal>

          {/* Compact stats row */}
          <Reveal delay={0.35}>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-fog mt-8 md:mt-10">
              {[
                { num: String(productionCount), label: zh ? "已在生產環境" : "in production", sub: zh ? "Microsoft · Cisco · Gen Digital" : "Microsoft, Cisco, Gen Digital" },
                { num: String(stats.ruleCount), label: zh ? "條偵測規則" : "detection rules", sub: zh ? `跨 ${categoryCount} 個類別` : `across ${categoryCount} categories` },
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

          {/* Pointers out: full ecosystem + sovereign invitation */}
          <Reveal delay={0.4}>
            <div className="mt-6 flex flex-wrap gap-x-6 gap-y-2 font-data text-xs md:text-sm">
              <Link href={`${prefix}/ecosystem`} className="text-blue hover:underline">
                {zh ? "完整生態系與整合清單 →" : "Full ecosystem + integrations →"}
              </Link>
              <Link href={`${prefix}/sovereign-ai-defense`} className="text-blue hover:underline">
                {zh ? "致民主國家:主權 AI 防禦層 →" : "For democracies: sovereign AI defense →"}
              </Link>
            </div>
          </Reveal>
        </div>
      </section>

      <SpeedLines />

      {/* ── Scene 6: Living standard (coverage + flywheel merged) ── */}
      <section className="py-14 md:py-[120px] px-5 md:px-6">
        <div className="max-w-[1120px] mx-auto">
          <Reveal>
            <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-3 md:mb-4">
              {zh ? "一個活的標準" : "A living standard"}
            </div>
          </Reveal>
          <Reveal delay={0.1}>
            <h2 className="font-display text-[20px] md:text-[clamp(24px,3.5vw,48px)] font-extrabold tracking-[-1px] md:tracking-[-2px] leading-[1.35] max-w-[700px] mb-3 text-balance">
              {zh ? "每一次攻擊,都讓所有人更安全。" : "Every attack makes everyone safer."}
            </h2>
          </Reveal>
          <Reveal delay={0.15}>
            <p className="text-sm md:text-base text-graphite font-light max-w-[640px] mb-6 md:mb-8 leading-[1.8] text-pretty">
              {zh
                ? <>紅隊大掃描與 CVE 匯入兩條管線每天運轉:新攻擊被語義層抓到後,「結晶」成 regex 規則回流標準——從每次 500ms 的推理,變成 5ms 的 pattern match。自動結晶化把標準從 462 條長到 {stats.ruleCount} 條,全部隨 npm <span className="font-data text-graphite">agent-threat-rules@{specVersion}</span> 發布。</>
                : <>A red-team mega-scan pipeline and a CVE-ingestion pipeline run daily: when the semantic layer catches a novel attack, it crystallizes into a regex rule and flows back into the standard — turning a 500ms inference into a 5ms pattern match. Auto-crystallization grew the standard from 462 to {stats.ruleCount} rules, all shipped in npm <span className="font-data text-graphite">agent-threat-rules@{specVersion}</span>.</>}
            </p>
          </Reveal>
          <Reveal delay={0.18}>
            <p className="text-sm md:text-base text-graphite font-light max-w-[640px] mb-6 md:mb-8 leading-[1.8] text-pretty">
              {zh
                ? <>但成長從不是目的——對精確度誠實才是。v3.5.0 引入偵測車道:每條規則標明成熟度,使用者自己決定要信任到哪。enforce 車道只放最成熟的規則開火(在 65,000 筆良性語料上約 0.24% 誤報);預設的 hunt 車道把全部規則當建議性訊號跑(約 9%)。誤報率逐車道揭露,而不是用一個好看的數字一概而論。<strong>一個標準的可信度,取決於它願不願意公開自己最差的數字。</strong></>
                : <>But growth was never the point — honesty about precision is. v3.5.0 introduced detection lanes: every rule declares a maturity, and the consumer decides how far to trust it. The enforce lane fires only the most mature rules (~0.24% false positives on a 65,000-sample benign corpus); the default hunt lane runs everything as advisory (~9%). False-positive rates are reported lane by lane, never as a single flattering number. <strong>A standard earns trust by publishing its worst figure, not hiding it.</strong></>}
            </p>
          </Reveal>

          {/* Standard heartbeat — version-pinned, dated cadence so the flywheel
              reads as a live, moving standard rather than a frozen catalog. Every
              token here is verifiable (npm tag, rule count, daily CI, stats.json regen date). */}
          <Reveal delay={0.19}>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 font-data text-[11px] md:text-xs text-stone mb-8 md:mb-10">
              <span className="inline-flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-green inline-block" aria-hidden="true" />
                <span className="text-ink font-semibold">agent-threat-rules@{specVersion}</span>
              </span>
              <span className="text-fog">·</span>
              <span><span className="text-ink font-semibold">{stats.ruleCount}</span> {zh ? "條規則" : "rules"}</span>
              <span className="text-fog">·</span>
              <span>{zh ? "CVE 匯入 + 結晶管線每天運轉" : "CVE-ingest + crystallize pipelines run daily"}</span>
              {stats.lastRegenerated && (
                <>
                  <span className="text-fog">·</span>
                  <span>{zh ? `標準最後重生 ${stats.lastRegenerated}` : `standard regenerated ${stats.lastRegenerated}`}</span>
                </>
              )}
            </div>
          </Reveal>

          <Reveal delay={0.2}>
            <Flywheel locale={locale} />
          </Reveal>

          {/* Coverage scores — framework mapping */}
          <Reveal delay={0.25}>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-fog mt-10 md:mt-12">
              {[
                { name: "OWASP Agentic", score: "10/10", desc: zh ? "完整覆蓋" : "Full coverage" },
                { name: "SAFE-MCP", score: "91.8%", desc: zh ? "78/85 技術" : "78/85 techniques" },
                { name: "OWASP AST10", score: "7/10", desc: zh ? "3 個是流程層級" : "3 are process-level" },
                { name: "PINT F1", score: String(stats.pintF1), desc: zh ? "850 個樣本" : "850 samples" },
              ].map((s) => (
                <div key={s.name} className="bg-paper p-6 md:p-8 text-center">
                  <div className="font-data text-[10px] md:text-xs font-medium text-stone tracking-[2px] uppercase mb-2 md:mb-3">{s.name}</div>
                  <div className="font-data text-[clamp(28px,4vw,48px)] font-bold text-ink leading-none">{s.score}</div>
                  <div className="text-xs text-mist mt-2">{s.desc}</div>
                </div>
              ))}
            </div>
          </Reveal>
          <Reveal delay={0.3}>
            <p className="text-sm text-graphite max-w-[560px] mt-5 leading-[1.8] text-pretty">
              {zh
                ? "框架告訴你威脅存在,ATR 告訴你怎麼偵測。ATR 對 MITRE ATLAS 的關係,就像 Sigma 規則對 ATT&CK 的關係——目前對映官方 ATLAS v5.6.0 的 34/101 個技法。覆蓋集中在 agent 原生的攻擊面,不是硬充版面。"
                : "Frameworks tell you threats exist. ATR tells you how to detect them. ATR is to MITRE ATLAS what Sigma rules are to ATT&CK — today mapping 34 of 101 official ATLAS techniques (v5.6.0), concentrated on the agent-native surface rather than padded for breadth."}
            </p>
          </Reveal>
          <Reveal delay={0.35}>
            <Link href={`${prefix}/coverage`} className="font-data text-xs md:text-sm text-blue hover:underline inline-block mt-3">
              {zh ? "查看完整覆蓋對照表 →" : "View full coverage mapping →"}
            </Link>
            <Link href={`${prefix}/atd`} className="font-data text-xs md:text-sm text-blue hover:underline inline-block mt-3 md:ml-6">
              {zh ? "ATD:可執行的 agent 威脅技法目錄 →" : "ATD: the executable agent-threat technique catalog →"}
            </Link>
          </Reveal>
        </div>
      </section>

      <SpeedLines />

      {/* ── Scene 7: Integrate (CTA) ── */}
      <section className="py-14 md:py-[120px] px-5 md:px-6 bg-ash">
        <div className="max-w-[1120px] mx-auto text-center">
          <Reveal>
            <h2 className="font-display text-[24px] md:text-[clamp(28px,4vw,56px)] font-black tracking-[-1.5px] md:tracking-[-2px] mb-6 md:mb-8 text-ink">
              {zh ? "開始整合 ATR。" : "Integrate ATR."}
            </h2>
          </Reveal>

          {/* Terminal demo */}
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
            <p className="text-sm md:text-base text-stone font-light max-w-[480px] mx-auto mb-7 md:mb-8 mt-6 md:mt-8 leading-[1.8] text-pretty">
              {zh
                ? "TypeScript、Python、Raw YAML、SIEM 轉換器——四種整合路徑,同一份規則。MIT 永久,沒有授權鎖,任何符合規範的引擎都能評估。"
                : "TypeScript, Python, Raw YAML, SIEM converters — four integration paths, one ruleset. MIT forever, no license to negotiate, evaluated by any conforming engine."}
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
