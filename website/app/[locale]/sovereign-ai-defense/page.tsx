import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { loadSiteStats } from "@/lib/stats";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  const zh = locale === "zh";
  return {
    title: zh
      ? "Sovereign AI Defense — 主權 AI 時代的缺口"
      : "Sovereign AI Defense — The Missing Layer",
    description: zh
      ? "每個國家都在建 Sovereign AI，沒有一個國家在建 Sovereign AI Defense。一份開放倡議。"
      : "Every country is building Sovereign AI. None are building Sovereign AI Defense. An open call.",
  };
}

const ENCODED_SLOGAN_ZH = encodeURIComponent(
  '"Sovereign AI without Sovereign Defense is just Sovereign Risk."\n\n呼籲全球民主陣營共建開放 AI Agent 防禦標準'
);
const ENCODED_SLOGAN_EN = encodeURIComponent(
  '"Sovereign AI without Sovereign Defense is just Sovereign Risk."\n\nAn open call for a democratic AI agent defense standard.'
);
const ENCODED_URL_ZH = encodeURIComponent(
  "https://agentthreatrule.org/zh/sovereign-ai-defense"
);
const ENCODED_URL_EN = encodeURIComponent(
  "https://agentthreatrule.org/en/sovereign-ai-defense"
);

export default async function SovereignAIDefensePage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: rawLocale } = await params;
  const locale = (locales.includes(rawLocale as Locale) ? rawLocale : "en") as Locale;
  const zh = locale === "zh";
  const ENC_SLOGAN = zh ? ENCODED_SLOGAN_ZH : ENCODED_SLOGAN_EN;
  const ENC_URL = zh ? ENCODED_URL_ZH : ENCODED_URL_EN;
  const stats = loadSiteStats();
  const ruleCount = stats.ruleCount;

  return (
    <div className="pt-20 pb-20 px-5 md:px-6 max-w-[880px] mx-auto">
      {/* Header eyebrow */}
      <Reveal>
        <div className="font-data text-[11px] md:text-xs font-medium text-blue tracking-[1.5px] md:tracking-[3px] uppercase mb-5">
          Sovereign AI Defense · {zh ? "公開倡議" : "An Open Call"} · May 2026
        </div>
      </Reveal>

      {/* Slogan callout */}
      <Reveal delay={0.03}>
        <div className="mb-7 md:mb-8 px-7 py-6 bg-ink rounded">
          <p className="font-display text-[18px] md:text-[22px] font-medium italic leading-[1.4] tracking-[-0.01em] text-paper">
            &ldquo;Sovereign AI without Sovereign Defense is just Sovereign Risk.&rdquo;
          </p>
        </div>
      </Reveal>

      {/* H1 */}
      <Reveal delay={0.08}>
        <h1 className="font-display text-[clamp(32px,5vw,52px)] font-extrabold tracking-[-2px] md:tracking-[-3px] leading-[1.08] text-ink">
          {zh ? "每個國家都在建 Sovereign AI。" : "Every country is building Sovereign AI."}
          <br />
          {zh ? "沒有一個國家在建 Sovereign AI Defense。" : "None are building Sovereign AI Defense."}
          <br />
          <span className="text-blue">{zh ? "直到現在。" : "Until now."}</span>
        </h1>
      </Reveal>

      {/* Speed line */}
      <Reveal delay={0.12}>
        <div className="h-[2px] bg-blue w-20 my-8" />
      </Reveal>

      {/* Declarative opening */}
      <Reveal delay={0.15}>
        <p className="text-[18px] md:text-[21px] font-medium text-ink leading-[1.5] max-w-[720px]">
          {zh ? (
            <>
              過去 18 個月，民主國家投入超過 <strong>USD 10B</strong> 打造 Sovereign AI。
              卻沒有一個國家為這些自主 Agent 準備好 defense layer。
            </>
          ) : (
            <>
              Over the last 18 months, democracies have committed over <strong>USD 10B</strong> to build Sovereign AI.
              None have prepared a defense layer for the autonomous agents they&rsquo;re building.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.55] max-w-[720px] mt-3">
          {zh ? (
            <>
              這不是疏忽,這是<strong className="text-ink">系統性漏洞</strong>。
              今天,這個缺口有了第一個開放、可運作、由社群治理的答案——
              MIT License、{ruleCount} 條行為規則、已在 Microsoft AGT、Cisco AI Defense 生產環境運作(外加 Gen Digital Sage PR 已合併),並被 MISP、OWASP 引用。
            </>
          ) : (
            <>
              This is not an oversight. It is a <strong className="text-ink">structural vulnerability</strong>.
              Today, that gap has its first open, operational, community-governed answer —
              MIT-licensed, {ruleCount} behavioral rules, in production at Microsoft AGT and Cisco AI Defense (plus Gen Digital Sage, PR merged), and referenced by MISP and OWASP.
            </>
          )}
        </p>
      </Reveal>

      {/* Stats bar */}
      <Reveal delay={0.2}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-[2px] bg-fog border border-fog mt-9">
          <StatCell
            label="SHIPPING"
            value={String(ruleCount)}
            unit={zh ? " 條" : ""}
            note={zh ? "完整 ATR 規則集於 Cisco AI Defense" : "full ATR rule pack in Cisco AI Defense"}
          />
          <StatCell
            label="GARAK RECALL"
            value="98.0"
            unit="%"
            note={zh ? "650 in-the-wild · 全 3,475 樣本 38.5%" : "650 in-the-wild · 38.5% on full 3,475"}
          />
          <StatCell
            label="FALSE POSITIVE"
            value="0.20"
            unit="%"
            note={zh ? "498 真實 SKILL.md 樣本" : "498 benign samples"}
          />
          <StatCell
            label="GARAK MAPPING"
            value="32"
            unit="/32"
            note={zh ? "ATR 側對應覆蓋 · garak PR #1676 審查中" : "ATR-side mapping coverage · garak PR #1676 open"}
          />
        </div>
      </Reveal>

      {/* 01 · The moment */}
      <Section label="01 · THE MOMENT" delay={0.05}>
        <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-ink mb-5">
          {zh
            ? "Sovereign AI 為什麼是這個時代的國家命題"
            : "Why Sovereign AI became a national imperative"}
        </h2>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh ? (
            <>
              AI 不再只是「工具」，而是<strong className="text-ink">下一個時代的國家競爭力核心</strong>——
              誰控制 AI，就控制未來的經濟、軍事、外交與文化話語權。
              過去 18 個月，民主陣營已簽下超過 USD 10B 的 Sovereign AI 合約：
            </>
          ) : (
            <>
              AI is no longer a tool. It is the <strong className="text-ink">core of next-era national competitiveness</strong> —
              whoever controls AI controls the future of economic, military, diplomatic, and cultural voice.
              Over the last 18 months, democratic allies have signed over USD 10B in Sovereign AI commitments:
            </>
          )}
        </p>
        <div className="border-t border-fog mt-6">
          <DealRow
            country="India"
            desc={zh ? "Tata + Reliance · 印地語 / 馬拉地語 LLMs" : "Tata + Reliance · Hindi / Marathi LLMs"}
            scale="$ multi-billion"
          />
          <DealRow
            country="Japan"
            desc={zh ? "SoftBank + KDDI · 日語 LLMs · 災害韌性 AI" : "SoftBank + KDDI · Japanese LLMs · disaster resilience AI"}
            scale="$ multi-billion"
          />
          <DealRow
            country="United Kingdom"
            desc={zh ? "NVIDIA AI 基礎設施合約" : "NVIDIA AI infrastructure commitment"}
            scale="£1B (≈ $1.3B)"
          />
          <DealRow
            country="France"
            desc={zh ? "Mistral AI + 18,000 顆 Grace Blackwell" : "Mistral AI + 18,000 Grace Blackwell"}
            scale="$ multi-billion"
          />
          <DealRow
            country="Saudi / UAE / Korea"
            desc={zh ? "2025 US-Saudi Investment Forum 等" : "2025 US-Saudi Investment Forum and others"}
            scale="$ multi-billion"
          />
          <DealRow
            country="Taiwan"
            desc={zh ? "Foxconn + TSMC + 政府 AI 超級電腦 · Constellation HQ" : "Foxconn + TSMC + gov AI supercomputer · Constellation HQ"}
            scale="NT$ 40B+"
          />
        </div>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-7">
          {zh
            ? "驅動力是主權焦慮——各國不希望關鍵資料與智慧跑到美國雲端，也不願在關鍵時刻被外國平台關閉或審查。"
            : "The driver is sovereignty anxiety — no country wants its critical data and intelligence running in US clouds, nor wants to be shut off or censored by foreign platforms at critical moments."}
        </p>
        <Callout borderColor="blue">
          {zh ? (
            <>
              「每個國家都需要擁有自己的智慧生產線。第一件事，就是把你文化的語言、資料，
              編碼到你自己的大型語言模型裡。」
            </>
          ) : (
            <>
              &ldquo;Every country needs to own the production of their own intelligence. The first thing I would do is
              codify the language, the data of your culture into your own large language model.&rdquo;
            </>
          )}
          <span className="block font-data text-[10px] tracking-[0.1em] text-stone mt-3 uppercase">
            Jensen Huang · World Governments Summit · {zh ? "杜拜 2024" : "Dubai 2024"}
          </span>
        </Callout>
      </Section>

      {/* 02 · The gap */}
      <Section label="02 · THE FATAL GAP" delay={0.05}>
        <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-ink mb-5">
          {zh
            ? "每個國家都有了自己的 AI，卻沒有一個國家有自己的 AI Defense"
            : "Every country now owns its AI. None owns its AI Defense."}
        </h2>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh ? (
            <>
              這些國家都有了自己的模型、自己的算力。
              但當這些 AI 變成 <strong className="text-ink">Agent</strong>——會自主行動、調度工具、串接 MCP、執行交易——
              <strong className="text-ink">沒有一套被廣泛接受的安全檢測標準</strong>。
            </>
          ) : (
            <>
              These countries have their own models and their own compute.
              But when those AI systems become <strong className="text-ink">agents</strong> — autonomous actors, tool users, MCP clients,
              transaction executors — <strong className="text-ink">no widely accepted agent security detection standard exists</strong>.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? (
            <>
              目前的現實是：Sovereign AI 客戶的安全層，多由美國私企供應（閉源規則庫、黑盒模型）。
              這製造了 Sovereign AI 本來要消除的依賴。
              <strong className="text-ink">你可以擁有自己的 AI，但得跟外國私企買防禦的「知識」——這是不完整的主權。</strong>
            </>
          ) : (
            <>
              The current reality: sovereign AI customers source their security layer from US-private vendors
              running proprietary rule sets and black-box models. This reproduces exactly the dependency that
              Sovereign AI was created to escape.
              <strong className="text-ink"> You can own your AI, but still have to rent the knowledge that defends it — that is incomplete sovereignty.</strong>
            </>
          )}
        </p>
        <Callout borderColor="critical">
          &ldquo;Conventional cybersecurity approaches do not translate cleanly to autonomous agent deployments.&rdquo;
          <span className="block font-data text-[10px] tracking-[0.1em] text-stone mt-3 uppercase">
            NIST CAISI · {zh ? "2026 年 1 月 · 官方承認 AI Agent 防禦標準空白" : "January 2026 · Official acknowledgment of the standards gap"}
          </span>
        </Callout>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-[2px] bg-fog border border-fog mt-7">
          <StatCell
            label={zh ? "擔憂" : "CONCERNED"}
            value="87"
            unit="%"
            note={zh ? "組織擔憂 AI Agent 安全 · 但只有 11% 已準備" : "but only 11% report being prepared · CSA 2026"}
            valueColor="critical"
          />
          <StatCell
            label={zh ? "現有合約" : "DEPLOYMENTS"}
            value="0"
            unit=""
            note={zh ? "Sovereign AI 合約含對應 Defense 層" : "Sovereign AI deals include a defense layer"}
            valueColor="blue"
          />
          <StatCell
            label="MYTHOS"
            value="83.1"
            unit="%"
            note={zh ? "自動漏洞挖掘成功率 · 前代 ≈ 0%" : "CyberGym reproduction · previous generation ≈ 0%"}
            valueColor="critical"
          />
        </div>
      </Section>

      {/* 03 · The proposal */}
      <Section label="03 · THE PROPOSAL" delay={0.05}>
        <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-ink mb-5">
          {zh
            ? "ATR — 讓 Sovereign AI 有對應 Defense 的開放標準"
            : "ATR — the open standard that fills the missing layer"}
        </h2>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh
            ? `MIT License · ${ruleCount} 條行為規則 · Protocol-agnostic · Behavioral-based。從真實攻擊情資產生,對應 NVIDIA garak、OWASP Agentic、MITRE ATLAS 三大標準 taxonomy。任何國家可採用,任何組織可貢獻,沒有地緣政治風險,沒有 vendor lock-in。`
            : `MIT License · ${ruleCount} behavioral rules · protocol-agnostic · behavior-based. Derived from real attack corpora, classified to NVIDIA garak / OWASP Agentic / MITRE ATLAS taxonomies. Adoptable by any country, contributable by any organization. No geopolitical risk. No vendor lock-in.`}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? (
            <>
              ATR 抓的是<strong className="text-ink">攻擊的行為意圖</strong>，不是字串特徵。
              攻擊者改 prompt、改 payload、改包裝都無法繞過，因為偵測的是<strong className="text-ink">因果結構</strong>。
              每次攻擊都必須重新設計整條攻擊鏈，成本指數級上升。
            </>
          ) : (
            <>
              ATR detects <strong className="text-ink">behavioral intent</strong>, not string signatures.
              Attackers who rephrase prompts, repackage payloads, or restructure attack chains cannot evade it,
              because the detection target is the <strong className="text-ink">causal structure of the attack</strong>.
              Each attack has to be redesigned — cost rises exponentially.
            </>
          )}
        </p>
      </Section>

      {/* 03b · Carrying SOC detection IP forward */}
      <Section label="03B · CARRYING DETECTION IP FORWARD" delay={0.05}>
        <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-ink mb-5">
          {zh ? "20 年的偵測知識不會消失，它換了個外殼" : "Twenty years of detection knowledge doesn't disappear — it takes a new form"}
        </h2>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh ? (
            <>
              任何銀行、醫院或半導體廠的資安中心，都累積了一整套
              <strong className="text-ink">用多年攻防實戰養出來的偵測 IP</strong>
              ——Sigma、YARA、Snort、Splunk SPL、Elastic EQL。每一條規則背後，都有一場真實事件。
            </>
          ) : (
            <>
              Every bank, hospital, and semiconductor fab&rsquo;s security operations center has accumulated
              <strong className="text-ink"> detection IP built over years of real combat</strong>
              {" "}— Sigma, YARA, Snort, Splunk SPL, Elastic EQL. Behind every rule sits a real incident.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? (
            <>
              AI Agent 時代來臨後，SQL injection 沒有消失——它跑進了 reasoning chain。Command injection 跑進了 tool calls。SSRF 跑進了 MCP 連線。
              <strong className="text-ink">攻擊面變了，攻擊的本質沒變。</strong>
            </>
          ) : (
            <>
              In the AI agent era, SQL injection didn&rsquo;t disappear — it moved into reasoning chains. Command injection lives in tool calls. SSRF lives in MCP connections.
              <strong className="text-ink"> The attack surface changed; the nature of attack didn&rsquo;t.</strong>
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-5">
          {zh ? (
            <>
              ATR 提供一個開放的參考 CLI <strong className="text-ink">atr migrate</strong>，把既有的偵測規則轉成 ATR 格式的草稿規則，讓累積的偵測知識能銜接到 AI Agent 時代，不用打掉重練。每條輸出都對 benign 樣本語料做誤報檢查，沒過關就拒收。
            </>
          ) : (
            <>
              ATR ships an open reference CLI, <strong className="text-ink">atr migrate</strong>, that translates existing detection rules into draft ATR rules — so accumulated detection knowledge carries forward into the AI agent era without rewriting from scratch. Each emitted rule is checked against a benign corpus for false positives; rules that don&rsquo;t pass are rejected.
            </>
          )}
        </p>
        <pre className="mt-7 bg-ink text-paper rounded-md p-5 text-[12.5px] md:text-[13px] leading-[1.7] overflow-x-auto font-data whitespace-pre">
          <code>{`# Open reference CLI (MIT)
atr migrate --source snort --input ./rules.snort --output ./atr-out`}</code>
        </pre>
      </Section>

      {/* 04 · Ecosystem */}
      <Section label="04 · ECOSYSTEM" delay={0.05}>
        <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-ink mb-5">
          {zh ? "已在全球主要資安堆疊落地" : "Already shipping across the major democratic security stacks"}
        </h2>
        <div className="border-t border-fog">
          <TractionRow
            org="Cisco AI Defense"
            status={zh ? "已出貨" : "Shipping"}
            statusClass="bg-green/10 text-green"
            desc={zh ? "PR #99 已合併 · 完整 ATR 規則集於 skill-scanner 生產環境（2026-04-22）" : "PR #99 merged · Full ATR rule pack shipping in skill-scanner (2026-04-22)"}
          />
          <TractionRow
            org="Microsoft"
            status={zh ? "PR 已合併" : "PR Merged"}
            statusClass="bg-blue/10 text-blue"
            desc={zh ? "agent-governance-toolkit · PR #1277 · 287 條規則（PR 當時）+ 每週自動同步 ATR 上游釋出" : "agent-governance-toolkit · PR #1277 · 287 rules at time of PR + weekly auto-sync of ATR upstream releases"}
          />
          <TractionRow
            org="NVIDIA garak"
            status={zh ? "整合中" : "Integrating"}
            statusClass="bg-medium/10 text-medium"
            desc={zh ? "PR #1676 · 完整 ATR 規則集 · 兩輪 review 通過,等待 maintainer 終審" : "PR #1676 · Full ATR rule pack · Two review rounds passed, awaiting maintainer final review"}
          />
          <TractionRow
            org="Gen Digital Sage"
            status={zh ? "已合併" : "Merged"}
            statusClass="bg-green/10 text-green"
            desc={zh ? "PR #33 已合併（2026-05-11）· 完整 ATR 規則集於 Norton/Avast/LifeLock 母集團的 Sage 風險評分層" : "PR #33 merged (2026-05-11) · Full ATR rule pack in the Sage risk-scoring layer under the Norton/Avast/LifeLock parent"}
          />
          <TractionRow
            org="OWASP"
            status={zh ? "Review 中" : "Under Review"}
            statusClass="bg-ash text-stone"
            desc={zh ? "LLM Top 10 專案 PR · 審查中" : "PR to the LLM Top 10 project · under review"}
          />
        </div>
        <p className="text-xs md:text-sm text-stone mt-5">
          {zh
            ? `0 → ${ruleCount} 條規則 · 2 個生產環境（Microsoft、Cisco）外加 Gen Digital Sage（已合併）· 標準同儕引用 · 完整採用者清單見 ADOPTERS.md · MIT 永久授權 · `
            : `0 → ${ruleCount} rules · 2 in production (Microsoft, Cisco) plus Gen Digital Sage (merged) · peer-standard references · full adopter list in ADOPTERS.md · MIT licensed · `}
          <a href="https://doi.org/10.5281/zenodo.19178002" className="text-blue hover:underline">
            DOI 10.5281/zenodo.19178002
          </a>
        </p>
      </Section>

      {/* 05 · Community-governed */}
      <Section label="05 · COMMUNITY-GOVERNED" delay={0.05}>
        <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-ink mb-5">
          {zh ? "一個由社群治理的開放標準" : "An open standard, governed by its contributors"}
        </h2>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh ? (
            <>
              ATR 不是單一實驗室或單一廠商的作品。每條規則都經過一條公開、可稽核的流程：
              <strong className="text-ink"> pull request → 自動化 safety gate → 社群審核 → 合併 → npm publish</strong>。
              治理規則寫在 GOVERNANCE.md；每條規則都有 provenance metadata；
              任何貢獻者都可以挑戰、修正、或擴充 taxonomy。
            </>
          ) : (
            <>
              ATR is not a single lab&rsquo;s or vendor&rsquo;s deliverable. Every rule passes through a
              public, auditable pipeline:
              <strong className="text-ink"> pull request → automated safety gate → community review → merge → npm publish</strong>.
              Governance rules are codified in GOVERNANCE.md; every rule carries provenance metadata;
              any contributor can challenge, correct, or extend the taxonomy.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? "如果這份倡議對你的組織有共鳴，有三個層次可以參與：" : "If this proposal resonates with your organization, there are three levels of participation:"}
        </p>
        <ul className="mt-3 space-y-2">
          <ContribItem
            strong={zh ? "貢獻規則：" : "Contribute rules:"}
            text={zh ? "把你見過的 AI agent 攻擊樣本，轉成 ATR 格式的 YAML rule 提 PR" : "translate AI agent attack samples you've observed into ATR YAML rule PRs"}
          />
          <ContribItem
            strong={zh ? "貢獻 probe：" : "Contribute probes:"}
            text={zh ? "定義新的攻擊類別，讓規則產出可以系統化覆蓋" : "define new attack classes so rule generation can be systematically mapped"}
          />
          <ContribItem
            strong={zh ? "貢獻驗證：" : "Contribute validation:"}
            text={zh ? "用真實攻擊 corpus 測 FP/Recall，找出規則盲點" : "test FP/Recall against real attack corpora, surface detection gaps"}
          />
        </ul>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-5">
          {zh ? (
            <>
              開放治理本身就是 Sovereign AI Defense 必要的制度基礎——
              <strong className="text-ink">攻擊不是由單一實驗室定義、防禦也不應該由單一廠商決定</strong>。
            </>
          ) : (
            <>
              Open governance is itself a structural requirement for Sovereign AI Defense —
              <strong className="text-ink"> attacks are not defined by a single lab, and defense should not be defined by a single vendor</strong>.
            </>
          )}
        </p>
      </Section>

      {/* 06 · First reference */}
      <Section label="06 · FIRST REFERENCE" delay={0.05}>
        <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-ink mb-5">
          {zh ? "第一個國家級 reference deployment 需要什麼" : "What a first national reference deployment requires"}
        </h2>
        <p className="text-[17px] md:text-lg text-graphite leading-[1.55] mb-7">
          {zh ? (
            <>
              <strong className="text-ink">沒有任何國家會「擁有」這個標準，只會率先採用它</strong>——
              像第一個採用 Linux 的銀行、第一個採用 OpenSSL 的政府。以下是讓一個民主國家適合成為第一個 reference deployment 的條件。
            </>
          ) : (
            <>
              <strong className="text-ink">No country will own this standard; the first adopter simply deploys it first</strong> —
              like the first bank to run Linux, or the first government to adopt OpenSSL. These are the conditions that make a democracy a strong candidate to be the first reference deployment.
            </>
          )}
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <ConditionCard
            num="CONDITION 01"
            head={zh ? "密集的真實國家級攻擊環境" : "A dense, real nation-state attack environment"}
            body={zh
              ? "醫療、電信、半導體供應鏈、政府系統都是已確認目標——真實攻擊壓力讓行為偵測規則能被實戰驗證，而非只在實驗室。"
              : "Healthcare, telecom, semiconductor supply chains, and government systems are confirmed targets — real attack pressure that validates behavioral rules in production, not only in a lab."}
          />
          <ConditionCard
            num="CONDITION 02"
            head={zh ? "靠近的 AI 算力與生態" : "Proximity to AI compute and ecosystem"}
            body={zh
              ? "鄰近大型 AI 基礎設施投資與供應鏈，讓 Sovereign AI 與其對應的 Defense 層能在同一個生態裡一起落地。"
              : "Closeness to large AI infrastructure investment and supply chains, so Sovereign AI and its defense layer can land together inside the same ecosystem."}
          />
          <ConditionCard
            num="CONDITION 03"
            head={zh ? "成熟的開放治理文化" : "A mature open-governance culture"}
            body={zh
              ? "具備「開放標準 × 政府協作」長期實戰經驗的民主社會，最能把社群治理的開放標準接到公部門。"
              : "A democracy with proven experience running open standards × government collaboration is best placed to connect a community-governed standard into the public sector."}
          />
          <ConditionCard
            num="CONDITION 04"
            head={zh ? "短的決策鏈" : "A short decision chain"}
            body={zh
              ? "從技術社群到行政部門距離短——提案可以在數個月內啟動，而不是數年。"
              : "A short distance from technical community to executive agencies — a proposal can launch in months rather than years."}
          />
        </div>
      </Section>

      {/* 07 · Open call */}
      <Reveal delay={0.05}>
        <section className="mt-12 md:mt-16">
          <div className="bg-ink text-paper rounded-md p-10 md:p-12">
            <div className="font-data text-[11px] md:text-xs font-medium text-mist tracking-[1.5px] md:tracking-[3px] uppercase mb-3">
              07 · OPEN CALL
            </div>
            <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-paper mb-4">
              {zh ? "我們在找的合作者" : "Who we're looking for"}
            </h2>
            <p className="text-sm md:text-base text-[#D8D8D3] leading-[1.6] mb-5">
              {zh
                ? "ATR 是 MIT License，這份倡議沒有排他性。以下任何一類組織或個人，如果你相信 Sovereign AI 時代需要一個對應的 Defense 開放標準，請直接聯繫："
                : "ATR is MIT-licensed. This proposal has no exclusivity. If you believe the Sovereign AI era needs a corresponding open Defense standard, we invite the following groups to make contact:"}
            </p>
            <ul className="mt-5">
              <CallItem
                strong={zh ? "政府 / 公部門 / 國家資安機構" : "Governments · public sector · national cybersecurity agencies"}
                desc={zh
                  ? "願意採用 ATR 作為 AI Agent 安全參考框架、或提供去識別化攻擊樣本的任何國家單位。"
                  : "Any jurisdiction willing to adopt ATR as an AI agent security reference framework, or to provide anonymized attack samples for rule development."}
              />
              <CallItem
                strong={zh ? "企業資安團隊 / CISO" : "Enterprise security teams · CISOs"}
                desc={zh
                  ? "金融、電信、醫療、關鍵基礎設施——想在 Mythos 等級威脅到來前，先把 ATR 落地到自己的 agent runtime 的團隊。"
                  : "Finance, telecom, healthcare, critical infrastructure — teams that want to deploy ATR into their agent runtime before Mythos-class threats arrive."}
              />
              <CallItem
                strong={zh ? "研究機構 / 學術實驗室" : "Research institutions · academic labs"}
                desc={zh
                  ? "有 AI agent 攻擊 / 紅隊 / 威脅情資相關研究，願意以 ATR 作為 benchmark 或貢獻規則。"
                  : "Groups working on AI agent attacks, red-teaming, or threat intelligence who want to use ATR as a benchmark or contribute rules."}
              />
              <CallItem
                strong={zh ? "開源社群 / 標準組織" : "Open-source communities · standards bodies"}
                desc={zh
                  ? "OpenSSF、OWASP、MITRE、CSA、Linux Foundation、ROOST——任何想把 ATR 納入現有資安標準生態的夥伴。"
                  : "OpenSSF, OWASP, MITRE, CSA, Linux Foundation, ROOST — any partner willing to help integrate ATR into the existing security standards ecosystem."}
              />
              <CallItem
                strong={zh ? "資安廠商 / 工具開發者" : "Security vendors · tool builders"}
                desc={zh
                  ? "把 ATR 規則整合進你們既有產品（SIEM / SOC / agent runtime / MCP gateway）。"
                  : "Teams willing to integrate ATR rules into existing products (SIEM, SOC, agent runtime, MCP gateways)."}
              />
              <CallItem
                strong={zh ? "記者 / 分析師 / 政策研究者" : "Journalists · analysts · policy researchers"}
                desc={zh
                  ? "如果你在報導或研究 Sovereign AI、agent 安全、或全球 AI 治理，這份倡議歡迎直接引用、質疑、挑戰。"
                  : "If you're reporting on or researching Sovereign AI, agent security, or global AI governance, this proposal is open to citation, scrutiny, and challenge."}
              />
            </ul>
          </div>
        </section>
      </Reveal>

      {/* Share */}
      <Section label="SHARE" delay={0.05}>
        <h2 className="font-display text-xl md:text-2xl font-bold tracking-[-0.02em] text-ink mb-3">
          {zh ? "讓這個缺口被更多人看見" : "Help this gap become visible"}
        </h2>
        <p className="text-sm text-stone mb-5">
          {zh
            ? "這份宣言的傳播，會直接決定下一個民主國家多快採納。轉發 = 縮短時間窗口。"
            : "The distribution of this manifesto directly shortens the timeline to adoption. A share is a vote that this layer should exist."}
        </p>
        <div className="flex flex-wrap gap-3">
          <a
            href={`https://twitter.com/intent/tweet?text=${ENC_SLOGAN}&url=${ENC_URL}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-block px-5 py-2.5 bg-ink text-paper no-underline rounded-[3px] font-display font-semibold text-sm"
          >
            {zh ? "轉到 X / Twitter" : "Share on X"}
          </a>
          <a
            href={`https://www.linkedin.com/sharing/share-offsite/?url=${ENC_URL}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-block px-5 py-2.5 bg-paper text-ink border border-ink no-underline rounded-[3px] font-display font-semibold text-sm"
          >
            {zh ? "轉到 LinkedIn" : "Share on LinkedIn"}
          </a>
          <a
            href={`mailto:?subject=Sovereign%20AI%20Defense%20%E2%80%94%20Open%20Call&body=${ENC_SLOGAN}%0A%0A${ENC_URL}`}
            className="inline-block px-5 py-2.5 bg-paper text-ink border border-ink no-underline rounded-[3px] font-display font-semibold text-sm"
          >
            {zh ? "用 Email 轉寄" : "Forward by Email"}
          </a>
        </div>
      </Section>

      {/* Footer */}
      <Reveal delay={0.05}>
        <div className="mt-14 pt-9 border-t border-fog flex flex-col md:flex-row justify-between gap-5 text-xs text-stone">
          <div>
            <div className="font-display text-base font-semibold text-ink mb-1.5">Adam Lin</div>
            <div>{zh ? "ATR 發起人" : "ATR Initiator"}</div>
            <div className="mt-2">
              <a href="mailto:adam@agentthreatrule.org" className="text-blue hover:underline">
                adam@agentthreatrule.org
              </a>
            </div>
            <div className="font-data text-[11px] text-mist tracking-[1px] uppercase mt-3">
              MIT License · Open Standard
            </div>
          </div>
          <div className="md:text-right">
            <a href="https://agentthreatrule.org" className="font-display font-semibold text-sm text-blue hover:underline">
              agentthreatrule.org
            </a>
            <div className="font-data text-[11px] text-mist tracking-[1px] uppercase mt-3">
              {ruleCount} Rules · NIST AI RMF mappings · Spec 3.0.0-alpha.1 (Working Draft)
            </div>
          </div>
        </div>
      </Reveal>
    </div>
  );
}

// ───── Helper components ─────

function Section({
  label,
  children,
  delay = 0,
}: {
  label: string;
  children: React.ReactNode;
  delay?: number;
}) {
  return (
    <Reveal delay={delay}>
      <section className="mt-12 md:mt-16">
        <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-4 md:mb-5">
          {label}
        </div>
        {children}
      </section>
    </Reveal>
  );
}

function StatCell({
  label,
  value,
  unit,
  note,
  valueColor = "ink",
}: {
  label: string;
  value: string;
  unit: string;
  note: string;
  valueColor?: "ink" | "blue" | "critical";
}) {
  const colorMap = {
    ink: "text-ink",
    blue: "text-blue",
    critical: "text-critical",
  };
  return (
    <div className="bg-paper p-5">
      <div className="font-data text-[10px] text-blue tracking-[1.2px] uppercase mb-2">
        {label}
      </div>
      <div className={`font-display text-2xl md:text-[26px] font-bold leading-[1.1] tracking-[-0.02em] ${colorMap[valueColor]}`}>
        {value}
        <span className="text-[15px] md:text-lg">{unit}</span>
      </div>
      <div className="text-[11.5px] text-stone mt-1.5 leading-[1.4]">{note}</div>
    </div>
  );
}

function DealRow({ country, desc, scale }: { country: string; desc: string; scale: string }) {
  return (
    <div className="grid grid-cols-[140px_1fr_140px] gap-5 py-3 border-b border-fog text-sm items-baseline max-md:grid-cols-1 max-md:gap-1">
      <div className="font-display font-semibold text-ink">{country}</div>
      <div className="text-graphite text-[13px]">{desc}</div>
      <div className="font-data text-xs text-blue md:text-right">{scale}</div>
    </div>
  );
}

function Callout({
  children,
  borderColor = "blue",
}: {
  children: React.ReactNode;
  borderColor?: "blue" | "critical";
}) {
  const colorMap = {
    blue: "border-blue",
    critical: "border-critical",
  };
  return (
    <div className={`bg-ash border-l-[3px] ${colorMap[borderColor]} px-7 py-6 my-6 text-ink leading-[1.55]`}>
      {children}
    </div>
  );
}

function TractionRow({
  org,
  status,
  statusClass,
  desc,
}: {
  org: string;
  status: string;
  statusClass: string;
  desc: string;
}) {
  return (
    <div className="grid grid-cols-[160px_140px_1fr] gap-4 py-4 border-b border-fog items-center max-md:grid-cols-1 max-md:gap-1.5">
      <div className="font-display font-semibold text-ink">{org}</div>
      <div className={`font-data text-[10px] tracking-[1.2px] uppercase px-2.5 py-1 rounded-[3px] text-center font-semibold ${statusClass}`}>
        {status}
      </div>
      <div className="text-graphite text-sm leading-[1.5]">{desc}</div>
    </div>
  );
}

function ConditionCard({ num, head, body }: { num: string; head: string; body: string }) {
  return (
    <div className="p-6 border border-fog rounded-md bg-paper">
      <div className="font-data text-[11px] text-blue tracking-[1.2px] uppercase mb-2">{num}</div>
      <div className="font-display text-[17px] font-bold text-ink mb-2">{head}</div>
      <div className="text-[13.5px] text-graphite leading-[1.55]">{body}</div>
    </div>
  );
}

function ContribItem({ strong, text }: { strong: string; text: string }) {
  return (
    <li className="relative pl-5 text-sm text-graphite leading-[1.55]">
      <span className="absolute left-0 font-data text-blue">→</span>
      <strong className="text-ink">{strong}</strong> {text}
    </li>
  );
}

function CallItem({ strong, desc }: { strong: string; desc: string }) {
  return (
    <li className="py-4 border-t border-paper/15 text-[#D8D8D3] leading-[1.6] first:border-t-0 first:pt-2">
      <strong className="block text-paper font-display font-semibold text-base mb-1">{strong}</strong>
      <span className="text-sm">{desc}</span>
    </li>
  );
}
