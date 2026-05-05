import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
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
              這不是疏忽，這是<strong className="text-ink">系統性漏洞</strong>。
              今天，這個缺口有了第一個開放、可運作、由社群治理的答案——
              MIT License、314 條行為規則、已在 Cisco、Microsoft、NVIDIA、Meta、IBM 的資安堆疊中運作。
            </>
          ) : (
            <>
              This is not an oversight. It is a <strong className="text-ink">structural vulnerability</strong>.
              Today, that gap has its first open, operational, community-governed answer —
              MIT-licensed, 314 behavioral rules, already shipping in Cisco, Microsoft, NVIDIA, Meta, and IBM security stacks.
            </>
          )}
        </p>
      </Reveal>

      {/* Stats bar */}
      <Reveal delay={0.2}>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-[2px] bg-fog border border-fog mt-9">
          <StatCell
            label="SHIPPING"
            value="314"
            unit={zh ? " 條" : ""}
            note={zh ? "在 Cisco AI Defense 生產環境" : "rules in Cisco AI Defense"}
          />
          <StatCell
            label="RECALL"
            value="97.1"
            unit="%"
            note={zh ? "666 真實 jailbreaks" : "666 real-world jailbreaks"}
          />
          <StatCell
            label="FALSE POSITIVE"
            value="0.20"
            unit="%"
            note={zh ? "498 真實 SKILL.md 樣本" : "498 benign samples"}
          />
          <StatCell
            label="GARAK COVERAGE"
            value="32"
            unit="/32"
            note={zh ? "NVIDIA 紅隊 probe 模組" : "NVIDIA probe modules"}
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
            ? "MIT License · 314 條行為規則 · Protocol-agnostic · Behavioral-based。從真實攻擊情資產生，對應 NVIDIA garak、OWASP Agentic、MITRE ATLAS 三大標準 taxonomy。任何國家可採用，任何組織可貢獻，沒有地緣政治風險，沒有 vendor lock-in。"
            : "MIT License · 314 behavioral rules · protocol-agnostic · behavior-based. Derived from real attack corpora, classified to NVIDIA garak / OWASP Agentic / MITRE ATLAS taxonomies. Adoptable by any country, contributable by any organization. No geopolitical risk. No vendor lock-in."}
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

      {/* 03b · Migration + Compliance Layer */}
      <Section label="03B · MIGRATION + COMPLIANCE LAYER" delay={0.05}>
        <h2 className="font-display text-2xl md:text-[28px] font-bold tracking-[-0.02em] text-ink mb-5">
          {zh
            ? "把全人類的偵測知識帶進 AI Agent 時代"
            : "Bringing humanity's detection knowledge into the AI agent era"}
        </h2>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh ? (
            <>
              ATR 還必須回答 CISO 一定會問的問題：「我們公司過去 15 年寫的所有 Sigma / YARA / Snort / CodeQL / Splunk SPL / Elastic EQL / CVE / KEV / Semgrep——都白花錢了嗎？」答案：
              <strong className="text-ink"> 沒有。它們是這時代攻擊的祖宗。</strong>
            </>
          ) : (
            <>
              ATR must answer the question every CISO will ask: &ldquo;Are the 15 years we spent writing Sigma, YARA, Snort, CodeQL, Splunk SPL, Elastic EQL — and curating CVE, KEV, Semgrep policies — wasted?&rdquo;
              <strong className="text-ink"> No. They are the ancestors of this era&rsquo;s attacks.</strong>
            </>
          )}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? (
            <>
              <strong className="text-ink">ATR Migrator v0.1.0</strong> 已 ship 15-format 遷移層，覆蓋你既有資安堆疊的全部知識來源：
            </>
          ) : (
            <>
              <strong className="text-ink">ATR Migrator v0.1.0</strong> ships a 15-format migration layer covering every knowledge source in any existing security stack:
            </>
          )}
        </p>
        <div className="border-t border-fog mt-5">
          <FormatRow category={zh ? "漏洞情資" : "Vulnerability intel"} formats="CVE-NVD · GHSA · OSV · CISA KEV" />
          <FormatRow category={zh ? "AI Red Teaming" : "AI red teaming"} formats="NVIDIA garak · Microsoft PyRIT · promptfoo" />
          <FormatRow category={zh ? "程式碼掃描" : "Code scanning"} formats="Semgrep · CodeQL" />
          <FormatRow category={zh ? "網路偵測" : "Network detection"} formats="Snort" />
          <FormatRow category={zh ? "Runtime 安全" : "Runtime security"} formats="Falco" />
          <FormatRow category={zh ? "SIEM 查詢語言" : "SIEM queries"} formats="Splunk SPL · Elastic EQL" />
          <FormatRow category={zh ? "早期 SIEM / 樣本" : "Legacy SIEM / malware"} formats="Sigma · YARA" />
        </div>
        <pre className="mt-7 bg-ink text-paper rounded-md p-5 text-[12.5px] md:text-[13px] leading-[1.7] overflow-x-auto font-data whitespace-pre">
          <code>{`# Commercial CLI (production)
panguard migrate-pro --source garak --input ./probes.json   --strict
panguard migrate-pro --source nvd   --input ./cve-feed.json --strict

# Open reference CLI
atr migrate --source snort --input ./rules.snort --output ./atr-out`}</code>
        </pre>
        <h3 className="font-display text-[19px] md:text-[21px] font-bold text-ink mt-9 mb-3">
          {zh ? "不是 grep/sed，是工業級品質流水線" : "Not grep/sed — an industrial quality pipeline"}
        </h3>
        <pre className="bg-ash text-ink rounded-md p-5 text-[12.5px] leading-[1.7] overflow-x-auto font-data border border-fog whitespace-pre">
          <code>{zh
            ? `1. Parse        → 來源規則 → NormalizedRule IR
2. Variant gen  → 自動推導同源攻擊變體
3. FP sampler   → 432 benign corpus 找出潛在誤報
4. Regex tighten → 多條件強化弱 pattern
5. Self-test    → strict 逐條件驗證 + 失敗即拒絕`
            : `1. Parse         → Source rules → NormalizedRule IR
2. Variant gen   → Sibling attack variants derived automatically
3. FP sampler    → False positives surfaced via 432-sample benign corpus
4. Regex tighten → Weak patterns strengthened with multi-condition logic
5. Self-test     → Strict per-condition validation; fail-closed`}</code>
        </pre>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh ? (
            <>
              每條輸出規則於 <strong className="text-ink">garak inthewild (666 prompts) + Lakera PINT (850 prompts)</strong> 對抗樣本集上自動驗證。
            </>
          ) : (
            <>
              Every emitted rule is auto-validated against <strong className="text-ink">garak inthewild (666 prompts) + Lakera PINT (850 prompts)</strong> adversarial corpora.
            </>
          )}
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-[2px] bg-fog border border-fog mt-7">
          <StatCell
            label={zh ? "誤報率" : "FALSE POSITIVES"}
            value="0"
            unit=""
            note={zh ? "於 432 benign 樣本" : "on 432 benign samples"}
            valueColor="blue"
          />
          <StatCell
            label={zh ? "測試通過" : "TESTS PASSING"}
            value="313"
            unit="/313"
            note={zh ? "TypeScript strict mode" : "TypeScript strict mode"}
          />
          <StatCell
            label={zh ? "Adapter" : "ADAPTERS"}
            value="15"
            unit=""
            note={zh ? "格式全綠 · 0 FP" : "formats green · 0 FP"}
          />
        </div>
        <h3 className="font-display text-[19px] md:text-[21px] font-bold text-ink mt-9 mb-3">
          {zh ? "自動合規證據鏈（不需要人工標註）" : "Automatic compliance evidence (zero manual labeling)"}
        </h3>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh ? (
            <>
              Migrator 的 <code className="font-data text-[13px] text-blue">compliance-mapper.ts</code> 在轉換時即自動寫入：
            </>
          ) : (
            <>
              Migrator&rsquo;s <code className="font-data text-[13px] text-blue">compliance-mapper.ts</code> writes, at conversion time:
            </>
          )}
        </p>
        <ul className="mt-3 space-y-2">
          <ContribItem
            strong={zh ? "EU AI Act：" : "EU AI Act:"}
            text={zh ? "Article 9 (Risk Management) / Article 15 (Cybersecurity) tag" : "Article 9 (Risk Management) / Article 15 (Cybersecurity) tags"}
          />
          <ContribItem
            strong={zh ? "NIST AI RMF：" : "NIST AI RMF:"}
            text={zh ? "Manage / Measure / Govern function 對應" : "Manage / Measure / Govern function mappings"}
          />
          <ContribItem
            strong={zh ? "ISO/IEC 42001：" : "ISO/IEC 42001:"}
            text={zh ? "AI Management System 條文對應" : "AI Management System clause mappings"}
          />
        </ul>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-5">
          {zh ? (
            <>
              受 EU AI Act 管制的銀行、健保、能源公司——把現有 Sigma 規則餵進 Migrator——
              <strong className="text-ink">直接得到帶合規 metadata 的 AI Agent 偵測規則</strong>。Article 15 cybersecurity-by-design 證據自動產生。
            </>
          ) : (
            <>
              Banks, healthcare systems, and energy companies subject to EU AI Act feed in their existing Sigma rules — and
              <strong className="text-ink"> get back AI agent detection rules pre-tagged with compliance metadata</strong>. Article 15 cybersecurity-by-design evidence is generated automatically.
            </>
          )}
        </p>
        <h3 className="font-display text-[19px] md:text-[21px] font-bold text-ink mt-9 mb-3">
          {zh ? "為什麼這對 Sovereign AI 是必要的" : "Why this is necessary for Sovereign AI"}
        </h3>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mb-4">
          {zh ? "Sovereign AI 不能只是「擁有自己的模型」。它必須有：" : "Sovereign AI cannot just mean owning your own model. It must include:"}
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <ConditionCard
            num="LAYER 01"
            head={zh ? "開放標準" : "Open Standard"}
            body={zh ? "ATR · MIT License — 任何國家可採用、可審核、可叉。" : "ATR · MIT License — adoptable, auditable, forkable by any nation."}
          />
          <ConditionCard
            num="LAYER 02"
            head={zh ? "遷移層" : "Migration Layer"}
            body={zh ? "ATR Migrator — 把 SOC 過去 20 年的 detection IP 帶進 AI Agent 時代。" : "ATR Migrator — bringing the SOC's 20 years of detection IP into the AI agent era."}
          />
          <ConditionCard
            num="LAYER 03"
            head={zh ? "合規層" : "Compliance Layer"}
            body={zh ? "Compliance metadata — 自動產生該國 AI 法規所需證據。" : "Compliance metadata — auto-producing evidence that satisfies each nation's AI regulations."}
          />
        </div>
        <Callout borderColor="blue">
          <strong className="text-ink">
            {zh
              ? "能保留歷史投資、能產出合規證據、能脫離 vendor lock-in——三者皆備才叫 Sovereign AI Defense。"
              : "Preserves historical investment. Produces compliance evidence. Escapes vendor lock-in. Only with all three is it Sovereign AI Defense."}
          </strong>
        </Callout>
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
            desc={zh ? "PR #99 已合併 · 314 條完整規則集於 skill-scanner 生產環境（2026-04-22）" : "PR #99 merged · Full 314-rule library shipping in skill-scanner (2026-04-22)"}
          />
          <TractionRow
            org="Microsoft"
            status={zh ? "PR 已合併" : "PR Merged"}
            statusClass="bg-blue/10 text-blue"
            desc={zh ? "agent-governance-toolkit · 314 條規則自動同步" : "agent-governance-toolkit · 314-rule auto-sync"}
          />
          <TractionRow
            org="NVIDIA garak"
            status={zh ? "整合中" : "Integrating"}
            statusClass="bg-medium/10 text-medium"
            desc={zh ? "PR #1676 · v2.0.17 · 已通過兩輪 review" : "PR #1676 · v2.0.17 · 2 review rounds passed"}
          />
          <TractionRow
            org="Meta PurpleLlama"
            status="Open PR"
            statusClass="bg-ash text-stone"
            desc={zh ? "20 條 regex pattern 合併入 DEFAULT_REGEX_PATTERNS" : "20 regex patterns merged into DEFAULT_REGEX_PATTERNS"}
          />
          <TractionRow
            org="IBM"
            status="Open PR"
            statusClass="bg-ash text-stone"
            desc={zh ? "mcp-context-forge · IBM MCP runtime ATR plugin" : "mcp-context-forge · ATR plugin for IBM MCP runtime"}
          />
          <TractionRow
            org="OWASP"
            status={zh ? "Review 中" : "Under Review"}
            statusClass="bg-ash text-stone"
            desc={zh ? "LLM Top 10 官方專案 PR · 標準引用路徑" : "LLM Top 10 official project PR · standards-track reference"}
          />
        </div>
        <p className="text-xs md:text-sm text-stone mt-5">
          {zh
            ? "43 天 solo · 0 → 314 條規則 · 6 個 ecosystem integrations · 30+ PRs 進行中 · Apache 2.0 學術版 · "
            : "43 days solo · 0 → 314 rules · 6 ecosystem integrations · 30+ PRs in flight · Apache 2.0 academic edition · "}
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
          {zh ? "為什麼台灣適合成為第一個 reference deployment" : "Why Taiwan is positioned to be the first reference deployment"}
        </h2>
        <p className="text-[17px] md:text-lg text-graphite leading-[1.55] mb-7">
          {zh ? (
            <>
              <strong className="text-ink">台灣不會擁有這個標準，台灣只是率先採用它</strong>——
              像第一個採用 Linux 的銀行、第一個採用 OpenSSL 的政府。
            </>
          ) : (
            <>
              <strong className="text-ink">Taiwan will not own this standard. Taiwan will be the first to adopt it</strong> —
              like the first bank to deploy Linux, or the first government to adopt OpenSSL.
            </>
          )}
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <ConditionCard
            num="CONDITION 01"
            head={zh ? "最密集的真實國家級攻擊" : "Densest real nation-state attack environment"}
            body={zh
              ? "2025 年每日 263 萬次攻擊（NSB 官方，較 2023 年 +113%）。醫療、電信、半導體供應鏈、政府系統皆為已確認目標。"
              : "2.63 million daily attacks in 2025 (NSB official, +113% vs 2023). Healthcare, telecom, semiconductor supply chain, and government systems are all confirmed targets."}
          />
          <ConditionCard
            num="CONDITION 02"
            head={zh ? "最靠近的 NVIDIA 生態" : "Closest NVIDIA ecosystem"}
            body={zh
              ? 'NVIDIA Taipei HQ 「Constellation」NT$40B+ 投資、2026/6 動工。Jensen Huang 公開表達："Without Taiwan, NVIDIA could not achieve what it has today."'
              : 'NVIDIA Taipei HQ "Constellation" — NT$40B+ investment, groundbreaking June 2026. Jensen Huang: "Without Taiwan, NVIDIA could not achieve what it has today."'}
          />
          <ConditionCard
            num="CONDITION 03"
            head={zh ? "最成熟的開放治理文化" : "Most mature open-governance culture"}
            body={zh
              ? "g0v、vTaiwan、Pol.is、Plurality——台灣是全球少數擁有「開放標準 × 政府協作」長期實戰經驗的民主社會。"
              : "g0v, vTaiwan, Pol.is, Plurality — Taiwan is one of the few democracies with long-term proven experience running open standards × government collaboration in production."}
          />
          <ConditionCard
            num="CONDITION 04"
            head={zh ? "最短的決策鏈" : "Shortest decision chain"}
            body={zh
              ? "從技術社群到行政部門的距離遠小於歐美——同樣的提案在 D.C. 需要 18 個月，在台北可以 3 個月啟動。"
              : "The distance from technical community to executive agencies is far shorter than in the EU or US. The same proposal that needs 18 months in D.C. can launch in 3 months in Taipei."}
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
            <div>{zh ? "PanGuard AI · ATR 發起人" : "Founder · PanGuard AI · ATR Initiator"}</div>
            <div className="mt-2">
              <a href="mailto:adam@agentthreatrule.org" className="text-blue hover:underline">
                adam@agentthreatrule.org
              </a>
            </div>
            <div className="font-data text-[11px] text-mist tracking-[1px] uppercase mt-3">
              MIT License · Open Standard · Day 43
            </div>
          </div>
          <div className="md:text-right">
            <a href="https://agentthreatrule.org" className="font-display font-semibold text-sm text-blue hover:underline">
              agentthreatrule.org
            </a>
            <div className="font-data text-[11px] text-mist tracking-[1px] uppercase mt-3">
              v2.0.17 · 314 Rules · 1,600+ Patterns
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

function FormatRow({ category, formats }: { category: string; formats: string }) {
  return (
    <div className="grid grid-cols-[180px_1fr] gap-5 py-3 border-b border-fog text-sm items-baseline max-md:grid-cols-1 max-md:gap-1">
      <div className="font-display font-semibold text-ink">{category}</div>
      <div className="font-data text-[12.5px] text-graphite tracking-[0.3px]">{formats}</div>
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
