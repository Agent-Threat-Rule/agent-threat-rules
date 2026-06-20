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
      ? "主權 AI 與中立偵測標準"
      : "Sovereign AI and a Neutral Detection Standard",
    description: zh
      ? "主權 AI 需要一個廠商中立、不受任何國家或公司控制的開放偵測標準。ATR 在主權 AI 語境裡的角色說明。"
      : "Sovereign AI needs a vendor-neutral detection standard controlled by no single country or company. ATR's role in the sovereign-AI context.",
  };
}

const ENCODED_SLOGAN_ZH = encodeURIComponent(
  '"Sovereign AI without Sovereign Defense is just Sovereign Risk."\n\n主權 AI 需要一個廠商中立的開放 agent 偵測標準。'
);
const ENCODED_SLOGAN_EN = encodeURIComponent(
  '"Sovereign AI without Sovereign Defense is just Sovereign Risk."\n\nSovereign AI needs a vendor-neutral open standard for agent threat detection.'
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
{zh ? "主權 AI · 中立標準" : "Sovereign AI · A Neutral Standard"}
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
          {zh ? "每個國家都在建主權 AI。" : "Every country is building sovereign AI."}
          <br />
          {zh ? "保護它的偵測知識,不該屬於任何單一廠商。" : "The detection knowledge that defends it should belong to no single vendor."}
          <br />
          <span className="text-blue">{zh ? "標準層必須是中立的。" : "That layer has to be neutral."}</span>
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
              各國正大規模投資自主可控的主權 AI。但保護這些 agent 的偵測規則,
              至今多半來自單一國家的私有廠商——這正是主權 AI 本來要消除的依賴。
            </>
          ) : (
            <>
              Countries are investing heavily in sovereign AI they can control and audit. Yet the detection rules
              that defend those agents still come mostly from private vendors in a single country —
              the very dependency sovereign AI was meant to remove.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.55] max-w-[720px] mt-3">
          {zh ? (
            <>
              ATR 是這個語境裡的<strong className="text-ink">中立基礎建設</strong>:MIT 授權、{ruleCount} 條機器可讀的偵測規則、
              社群維護,任何國家或組織都能採用、稽核、擴充、或 fork——不依賴任何單一廠商。
              目前的外部採用已包含 Microsoft AGT、Cisco AI Defense 與 Gen Digital Sage 的已合併規則集,以及 MISP、OWASP 的引用。
            </>
          ) : (
            <>
              ATR is the <strong className="text-ink">neutral infrastructure</strong> for that context: MIT-licensed,
              {" "}{ruleCount} machine-readable detection rules, community-maintained — adoptable, auditable, extensible, or forkable
              by any country or organization, dependent on no single vendor.
              Adoption to date includes merged rule packs in Microsoft AGT, Cisco AI Defense, and Gen Digital Sage, plus references from MISP and OWASP.
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
            value="0.24"
            unit="%"
            note={zh ? "enforce 車道 · 65,000 筆良性語料 · 逐車道揭露" : "enforce lane · 65k benign corpus · reported per lane"}
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
              許多國家已把 AI 視為<strong className="text-ink">必須自主掌握的國家能力</strong>,
              並大規模投資於自己語言、自己資料、自己算力上的模型,以避免關鍵系統依賴外國平台。
              這股投資橫跨多個地區:
            </>
          ) : (
            <>
              Many countries now treat AI as a <strong className="text-ink">national capability they must control themselves</strong>,
              investing heavily in models built on their own language, data, and compute so that critical systems
              do not depend on foreign platforms. That investment spans many regions:
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
            ? "驅動力是主權焦慮——各國不希望關鍵資料與智慧跑到美國雲端,也不願在關鍵時刻被外國平台關閉或審查。光是亞太的主權 AI 基礎建設市場,2026 年估計就有 90–140 億美元,並預計在 2030 年達到 230–470 億美元。"
            : "The driver is sovereignty anxiety — no country wants its critical data and intelligence running in US clouds, nor wants to be shut off or censored by foreign platforms at critical moments. The Asia-Pacific sovereign-AI infrastructure market alone is estimated at $9–14B in 2026, projected to reach $23–47B by 2030."}
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
      <Section label="02 · THE NEUTRALITY PROBLEM" delay={0.05}>
        <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-ink mb-5">
          {zh
            ? "自主掌握模型容易,自主掌握防禦它的偵測知識難"
            : "Owning the model is one thing. Owning the detection knowledge that defends it is another."}
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
              監管者自己也清楚。EU AI Act 是在 agentic AI 出現之前談定的——它的風險分級假設的是
              「輔助人類決策」的系統,而不是自己決策、自己行動的系統。NIST 的 AI Agent Standards
              Initiative 在 2026 年 2 月啟動,正是為了補上這個缺口。框架正在追趕;它們底下仍然缺的,
              是一個<strong className="text-ink">可執行的偵測層</strong>。
            </>
          ) : (
            <>
              The regulators know it. The EU AI Act was negotiated before agentic AI arrived — its risk tiers
              assume systems that <strong className="text-ink">assist</strong> a human decision, not systems that decide and act on their
              own. NIST&rsquo;s AI Agent Standards Initiative opened in February 2026 precisely to close that gap.
              The frameworks are catching up; what they still need underneath them is an
              {" "}<strong className="text-ink">executable detection layer</strong>.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? (
            <>
              目前多數可用的偵測規則庫是閉源的,且集中在少數國家的私有廠商手裡。
              一個國家可以自主掌握模型,卻仍得透過閉源、無法稽核的規則庫去防禦它。
              <strong className="text-ink">無法被開啟、檢視、fork 的防禦知識,是不完整的主權。</strong>
            </>
          ) : (
            <>
              Most available detection rule sets are closed-source and concentrated in private vendors within a few countries.
              In a 2026 survey, 94% of IT leaders said they fear AI vendor lock-in — and for detection knowledge the lock-in is sharper:
              a country can control its model yet still defend it through proprietary, unauditable rule sets it cannot inspect.
              <strong className="text-ink"> Defense knowledge that cannot be opened, inspected, or forked is incomplete sovereignty.</strong>
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
            label={zh ? "開放標準" : "OPEN STANDARDS"}
            value="0"
            unit=""
            note={zh ? "agent 偵測層此前沒有廠商中立的開放標準" : "vendor-neutral open standards for the agent detection layer, before ATR"}
            valueColor="blue"
          />
          <StatCell
            label="MYTHOS"
            value="83.1"
            unit="%"
            note={zh ? "自動漏洞挖掘成功率 · 攻擊能力快速演進,簽章式偵測難跟上" : "automated vuln discovery · attack capability evolving faster than signature detection"}
            valueColor="critical"
          />
        </div>
      </Section>

      {/* 03 · Why a neutral standard fits */}
      <Section label="03 · WHY A NEUTRAL STANDARD" delay={0.05}>
        <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-ink mb-5">
          {zh
            ? "為什麼這個語境需要的是開放標準,而不是另一個產品"
            : "Why this context calls for an open standard, not another product"}
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

      {/* 03b · Interoperable with existing SOC tooling */}
      <Section label="03B · INTEROPERABLE WITH EXISTING TOOLING" delay={0.05}>
        <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-ink mb-5">
          {zh ? "不必丟掉現有的 SOC 工具鏈" : "No need to replace your existing SOC tooling"}
        </h2>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh ? (
            <>
              任何銀行、醫院或半導體廠的資安中心,都已經跑在某套既有的偵測堆疊上——
              Splunk、Elastic、各種 SIEM。一個中立標準如果要求大家換掉這些,就沒人會採用。
            </>
          ) : (
            <>
              Every bank, hospital, and semiconductor fab&rsquo;s security operations center already runs on
              an existing detection stack — Splunk, Elastic, one SIEM or another. A neutral standard nobody can
              use without ripping those out is a standard nobody adopts.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? (
            <>
              所以 ATR 規則設計成<strong className="text-ink">可匯出</strong>:同一條機器可讀的規則,
              可以轉成 Splunk SPL、Elastic 查詢、或通用 regex,直接餵進既有的偵測管線。
              標準存在於規則本身,不綁定任何一家廠商的執行引擎。
            </>
          ) : (
            <>
              So ATR rules are designed to be <strong className="text-ink">exportable</strong>: the same machine-readable
              rule can be emitted as Splunk SPL, an Elastic query, or generic regex, and fed straight into an existing
              detection pipeline. The standard lives in the rule itself, bound to no single vendor&rsquo;s execution engine.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-5">
          {zh ? (
            <>
              這個轉換器是 ATR 開放參考實作的一部分(MIT)。攻擊面變了——SQL injection 跑進了 reasoning chain、command injection 跑進了 tool call、SSRF 跑進了 MCP 連線——但既有的偵測基礎建設不必跟著歸零。
            </>
          ) : (
            <>
              The converter is part of ATR&rsquo;s open reference implementation (MIT). The attack surface moved — SQL injection into reasoning chains, command injection into tool calls, SSRF into MCP connections — but existing detection infrastructure does not have to reset to zero to keep up.
            </>
          )}
        </p>
        <pre className="mt-7 bg-ink text-paper rounded-md p-5 text-[12.5px] md:text-[13px] leading-[1.7] overflow-x-auto font-data whitespace-pre">
          <code>{`# Open reference CLI (MIT) — export ATR rules into existing tooling
atr convert splunk --output ./atr-rules.spl`}</code>
        </pre>
      </Section>

      {/* 04 · Ecosystem */}
      <Section label="04 · ECOSYSTEM" delay={0.05}>
        <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-ink mb-5">
          {zh ? "已被多個主要資安堆疊採用" : "Already adopted across major security stacks"}
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
          {zh ? "參與這個標準有三個層次:" : "There are three levels of participation in the standard:"}
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
              對主權 AI 來說,開放治理本身就是必要的制度基礎——
              <strong className="text-ink">攻擊不是由單一實驗室定義,防禦也不該由單一廠商決定</strong>。
            </>
          ) : (
            <>
              For sovereign AI, open governance is itself a structural requirement —
              <strong className="text-ink"> attacks are not defined by a single lab, and defense should not be defined by a single vendor</strong>.
            </>
          )}
        </p>
      </Section>

      {/* 06 · How any country adopts it */}
      <Section label="06 · HOW ANY COUNTRY ADOPTS IT" delay={0.05}>
        <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-ink mb-5">
          {zh ? "任何國家如何採用一個公共財標準" : "How any country adopts a public-good standard"}
        </h2>
        <p className="text-[17px] md:text-lg text-graphite leading-[1.55] mb-7">
          {zh ? (
            <>
              <strong className="text-ink">沒有任何國家會「擁有」這個標準,任何國家都能採用它</strong>——
              就像採用 Linux、OpenSSL、Sigma 一樣:下載、稽核、在自己的環境裡跑、把缺的規則貢獻回上游。
              因為是 MIT 公共財,採用不需要任何人的許可,也不附帶地緣政治條件。
            </>
          ) : (
            <>
              <strong className="text-ink">No country owns this standard; any country can adopt it</strong> —
              the same way one adopts Linux, OpenSSL, or Sigma: download it, audit it, run it in your own environment,
              contribute the rules you&rsquo;re missing back upstream. Because it is an MIT public good, adoption needs no one&rsquo;s
              permission and carries no geopolitical strings.
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-5">
          {zh ? (
            <>
              這也是國際局勢重要的原因。AI Safety Institutes 國際網絡——2024 年於舊金山啟動、創始十國,
              如今跨司法管轄區協調——正朝「各國之間可比的安全評估」推進。可比的前提,是一套共享的、
              機器可讀的偵測格式。一個中立標準,正是讓一國的發現對另一國仍然可讀的東西——
              就像東京登記的一筆 CVE,在柏林意義相同。
            </>
          ) : (
            <>
              This is also why the international picture matters. The AI Safety Institutes network — launched in
              San Francisco in 2024 with ten founding members and now coordinating across jurisdictions — is working
              toward safety evaluations that are comparable from one country to the next. Comparability needs a shared,
              machine-readable detection format. A neutral standard is what keeps one country&rsquo;s findings legible to
              another&rsquo;s — the way a CVE filed in Tokyo means the same thing in Berlin.
            </>
          )}
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <ConditionCard
            num="PROPERTY 01"
            head={zh ? "可稽核" : "Auditable"}
            body={zh
              ? "每條規則都是公開的 YAML,帶 provenance metadata。採用者可以逐條檢視偵測邏輯,不用信任任何黑盒。"
              : "Every rule is public YAML with provenance metadata. Adopters can inspect the detection logic rule by rule, with no black box to trust."}
          />
          <ConditionCard
            num="PROPERTY 02"
            head={zh ? "可在地化" : "Localizable"}
            body={zh
              ? "規則可 fork、可擴充。任何國家都能加入自己環境裡見到的攻擊樣本,而不必依賴外部廠商的更新節奏。"
              : "Rules are forkable and extensible. Any country can add attack samples it observes in its own environment, without depending on an external vendor's release cadence."}
          />
          <ConditionCard
            num="PROPERTY 03"
            head={zh ? "可貢獻回上游" : "Upstream-contributable"}
            body={zh
              ? "改進透過公開 PR 回流,經自動化 safety gate 與社群審核。一個國家修好的盲點,所有採用者都受益。"
              : "Improvements flow back via public pull requests through an automated safety gate and community review. A gap one country fixes benefits every adopter."}
          />
          <ConditionCard
            num="PROPERTY 04"
            head={zh ? "ID 永久穩定" : "Stable identifiers"}
            body={zh
              ? "規則用 CVE 風格 ID(ATR-YYYY-NNNNN),發布後永不變更——政府文件、稽核報告、CI 腳本都能安全長期引用。"
              : "Rules use CVE-style IDs (ATR-YYYY-NNNNN) that never change after publication — safe for government documents, audit reports, and CI scripts to cite long-term."}
          />
        </div>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-7">
          {zh
            ? "採用不是一份提案,是三行指令。沒有授權窗口、沒有採購流程、沒有人需要先點頭:"
            : "Adoption is not a proposal — it is three commands. No license desk, no procurement cycle, no one's permission required:"}
        </p>
        <pre className="mt-4 bg-ink text-paper rounded-md p-5 text-[12.5px] md:text-[13px] leading-[1.7] overflow-x-auto font-data whitespace-pre">
          <code>{`# Adopt the open standard — MIT, no fee, no geopolitical strings
npm install -g agent-threat-rules
atr scan ./agent-config.json     # audit your own agents against ${ruleCount} rules
atr convert splunk               # or export into the SOC you already run`}</code>
        </pre>
      </Section>

      {/* 07 · Open call */}
      <Reveal delay={0.05}>
        <section className="mt-12 md:mt-16">
          <div className="bg-ink text-paper rounded-md p-10 md:p-12">
            <div className="font-data text-[11px] md:text-xs font-medium text-mist tracking-[1.5px] md:tracking-[3px] uppercase mb-3">
              07 · OPEN CALL
            </div>
            <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-paper mb-4">
              {zh ? "誰能參與這個標準" : "Who can take part"}
            </h2>
            <p className="text-sm md:text-base text-[#D8D8D3] leading-[1.6] mb-5">
              {zh
                ? "ATR 是 MIT 授權的開放標準,沒有排他性,也不屬於任何單一廠商。如果你相信主權 AI 語境需要一個廠商中立、可稽核的偵測標準,以下任何一類都能直接參與:"
                : "ATR is an MIT-licensed open standard — non-exclusive, owned by no single vendor. If you believe the sovereign-AI context needs a vendor-neutral, auditable detection standard, any of the following can take part directly:"}
            </p>
            <ul className="mt-5">
              <CallItem
                strong={zh ? "政府 / 公部門 / 國家資安機構" : "Governments · public sector · national cybersecurity agencies"}
                desc={zh
                  ? "可把 ATR 當作 AI agent 安全的中立參考標準來評估、稽核、在地化,或貢獻去識別化的攻擊樣本回上游。"
                  : "Can evaluate, audit, or localize ATR as a neutral reference standard for AI agent security, or contribute anonymized attack samples upstream."}
              />
              <CallItem
                strong={zh ? "企業資安團隊 / CISO" : "Enterprise security teams · CISOs"}
                desc={zh
                  ? "金融、電信、醫療、關鍵基礎設施——把開放規則整合進自己的 agent runtime,並把實戰見到的偵測盲點貢獻回標準。"
                  : "Finance, telecom, healthcare, critical infrastructure — integrate the open rules into their agent runtime and contribute detection gaps they hit back to the standard."}
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
                  ? "如果你在報導或研究主權 AI、agent 安全、或全球 AI 治理,這個標準的規則、數據、方法都公開可引用、可質疑、可挑戰。"
                  : "If you're reporting on or researching sovereign AI, agent security, or global AI governance, the standard's rules, data, and methodology are open to citation, scrutiny, and challenge."}
              />
            </ul>
          </div>
        </section>
      </Reveal>

      {/* Share */}
      <Section label="SHARE" delay={0.05}>
        <h2 className="font-display text-xl md:text-2xl font-bold tracking-[-0.02em] text-ink mb-3">
          {zh ? "把這個討論帶給更多人" : "Pass this on"}
        </h2>
        <p className="text-sm text-stone mb-5">
          {zh
            ? "標準靠被更多人知道、檢視、採用而成立。如果這個觀點對你的同行有用,歡迎轉給他們。"
            : "A standard works by being seen, scrutinized, and adopted widely. If this framing is useful to your peers, pass it along."}
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
              {ruleCount} Rules · NIST AI RMF mappings · Spec 3.5.0 (Working Draft)
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
