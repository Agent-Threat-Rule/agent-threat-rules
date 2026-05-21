import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
import Link from "next/link";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Responsible Use — ATR",
  description:
    "ATR responsible-use policy: intended use for defensive detection, what constitutes misuse, dual-use disclosure, and abuse reporting contact.",
};

export default async function ResponsibleUsePage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";

  return (
    <div className="pt-20 pb-20 px-5 md:px-6 max-w-[860px] mx-auto">
      <Reveal>
        <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-3">
          {zh ? "負責任使用" : "Responsible Use"}
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <h1 className="font-display text-[clamp(28px,4vw,48px)] font-extrabold tracking-[-2px] leading-[1.08] text-ink mb-4">
          {zh ? "ATR 設計給誰，以及不設計給誰。" : "What ATR is built for — and what it is not."}
        </h1>
      </Reveal>
      <Reveal delay={0.1}>
        <p className="text-base text-stone font-light max-w-[640px] leading-[1.8] mb-12">
          {zh
            ? "ATR 的 421 條規則描述 AI agent 攻擊模式，用途是偵測。相同的描述可以被誤用來生成攻擊。本頁說明我們的設計意圖、已知的雙重用途風險、以及回報濫用的管道。"
            : "ATR's 421 rules describe AI agent attack patterns for the purpose of detection. The same descriptions can be misused to generate attacks. This page explains our design intent, known dual-use risks, and how to report misuse."}
        </p>
      </Reveal>

      {/* Intended use */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "設計用途" : "Intended use"}
        </div>
        <h2 className="font-display text-xl font-extrabold tracking-[-0.5px] mb-4">
          {zh ? "ATR 是防禦偵測工具。" : "ATR is a defensive detection tool."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="space-y-px bg-fog mb-12">
          {[
            {
              title: zh ? "整合到安全掃描器" : "Integrate into security scanners",
              desc: zh
                ? "在 CI/CD pipeline、agent runtime、或 MCP server 中執行 ATR 規則，偵測已知攻擊模式。Cisco AI Defense 和 Microsoft AGT 是生產環境的實際案例。"
                : "Run ATR rules in CI/CD pipelines, agent runtimes, or MCP server middleware to detect known attack patterns. Cisco AI Defense and Microsoft AGT are production examples.",
            },
            {
              title: zh ? "紅隊測試的基準線" : "Red-team baseline",
              desc: zh
                ? "用 ATR 規則衡量你的紅隊工具找到的攻擊有多少已有偵測覆蓋，以及有多少是尚未有規則的新型態。這是 NVIDIA garak 整合的設計意圖。"
                : "Use ATR rules to measure what fraction of attacks your red-team tool discovers already have detection coverage, and what fraction are novel. This is the design intent of the NVIDIA garak integration.",
            },
            {
              title: zh ? "標準映射與合規文件" : "Standards mapping and compliance documentation",
              desc: zh
                ? "ATR 規則映射到 OWASP、MITRE ATLAS、NIST AI RMF、EU AI Act、ISO 42001。用於生成合規證據包，或向採購委員會說明框架覆蓋。"
                : "ATR rules map to OWASP, MITRE ATLAS, NIST AI RMF, EU AI Act, and ISO 42001. Use these mappings to generate compliance evidence packages or explain framework coverage to procurement.",
            },
            {
              title: zh ? "研究與學術引用" : "Research and academic citation",
              desc: zh
                ? "引用特定 rule ID（例如 ATR-2026-00440）作為攻擊偵測的可執行基準。規則 ID 永久穩定，適合論文引用。"
                : "Cite specific rule IDs (e.g. ATR-2026-00440) as executable detection baselines for attack research. Rule IDs are permanent, suitable for academic citation.",
            },
          ].map((item) => (
            <div key={item.title} className="bg-paper p-5 md:p-6">
              <div className="font-display text-sm font-semibold text-ink mb-2">{item.title}</div>
              <p className="text-sm text-graphite leading-[1.7]">{item.desc}</p>
            </div>
          ))}
        </div>
      </Reveal>

      {/* What constitutes misuse */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "濫用定義" : "What constitutes misuse"}
        </div>
        <h2 className="font-display text-xl font-extrabold tracking-[-0.5px] mb-4">
          {zh ? "ATR 規則不應當作攻擊生成器使用。" : "ATR rules should not be used as attack generators."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="bg-paper border border-fog p-6 md:p-8 mb-6">
          <p className="text-sm text-graphite leading-[1.7] mb-4">
            {zh
              ? "ATR 的每條規則都包含攻擊模式的 regex 描述和 test cases（包含 true_positives）。這些 test_cases 的目的是驗證規則偵測能力，不是提供現成的攻擊 payload。"
              : "Each ATR rule contains a regex description of an attack pattern and test cases that include true_positives. Those test_cases exist to validate detection capability — not to provide ready-made attack payloads."}
          </p>
          <p className="text-sm text-graphite leading-[1.7] mb-4">
            {zh
              ? "以下使用方式構成濫用："
              : "The following uses constitute misuse:"}
          </p>
          <ul className="space-y-2 text-sm text-graphite leading-[1.7]">
            {[
              zh
                ? "將 true_positive test cases 直接作為對生產 AI agent 系統的攻擊 payload 使用。"
                : "Using true_positive test cases directly as attack payloads against production AI agent systems without authorization.",
              zh
                ? "將 ATR 規則的 regex 反向工程成繞過偵測的攻擊變體，並在未授權的環境中使用。"
                : "Reverse-engineering ATR rule regexes into evasion variants and deploying them against unauthorized targets.",
              zh
                ? "基於 ATR 規則庫建立攻擊自動化工具，目的是突破已部署 ATR 規則的系統。"
                : "Building attack automation tools grounded in the ATR rule corpus with the intent of breaching systems that have deployed ATR rules.",
              zh
                ? "使用 ATR 資料訓練攻擊模型，目的是生成能逃過 ATR 偵測的對抗性輸入。"
                : "Using ATR data to train attack models aimed at generating adversarial inputs that evade ATR detection.",
            ].map((item, i) => (
              <li key={i} className="flex items-start gap-3">
                <span className="text-fog shrink-0 mt-1">▸</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <p className="text-sm text-stone leading-[1.7] max-w-[640px] mb-12">
          {zh
            ? "MIT 授權允許任何使用，包括商業和分叉使用。本頁的濫用定義不是法律限制，而是清晰說明設計意圖，讓採用者在評估風險時有明確的參照。"
            : "The MIT license permits any use, including commercial and forked use. This misuse definition is not a legal restriction — it is a clear statement of design intent, so adopters have a clear reference when evaluating risk."}
        </p>
      </Reveal>

      {/* Dual-use disclosure */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "雙重用途揭露" : "Dual-use disclosure"}
        </div>
        <h2 className="font-display text-xl font-extrabold tracking-[-0.5px] mb-4">
          {zh ? "我們知道這個標準是雙重用途的。" : "We acknowledge this standard has dual-use properties."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="bg-ash p-6 md:p-8 mb-12 text-sm text-graphite leading-[1.7]">
          <p className="mb-4">
            {zh
              ? "ATR 規則描述 AI agent 攻擊的行為特徵。描述攻擊模式的任何系統——無論是 CVE 資料庫、Sigma 規則、YARA 簽名、或 MITRE ATT&CK——都具有類似的雙重性質。公開攻擊模式的防禦效益是：讓防守方比攻擊方更快知道哪些技術已被記錄。"
              : "ATR rules describe behavioral signatures of AI agent attacks. Any system that describes attack patterns — CVE databases, Sigma rules, YARA signatures, MITRE ATT&CK — has a similar dual nature. The defensive rationale for public disclosure is that defenders see documented techniques faster than attackers benefit from the documentation."}
          </p>
          <p className="mb-4">
            {zh
              ? "我們對此設計了兩個緩解措施："
              : "We have designed two mitigations:"}
          </p>
          <ul className="space-y-2">
            <li className="flex items-start gap-3">
              <span className="text-blue shrink-0 mt-0.5">1.</span>
              <span>
                {zh
                  ? "規則中的 true_positive test cases 是最小化的模式範例，不是完整的攻擊鏈。它們足以驗證偵測，但需要額外的攻擊工程才能作為真實 exploit 使用。"
                  : "The true_positive test cases in rules are minimal pattern exemplars, not complete attack chains. They are sufficient to validate detection but require additional attack engineering to function as a real exploit."}
              </span>
            </li>
            <li className="flex items-start gap-3">
              <span className="text-blue shrink-0 mt-0.5">2.</span>
              <span>
                {zh
                  ? "特別危險的規則（高 CVSS、已在野外主動利用）在送 PR 前，我們遵循負責任揭露流程，確保受影響廠商有修補時間。ATR-2026-00440 和 ATR-2026-00441（Microsoft Semantic Kernel CVE）是一個案例：規則在 MSRC 公開揭露後才發布。"
                  : "For particularly dangerous rules (high CVSS, actively exploited in the wild), we follow responsible-disclosure timelines and confirm affected vendors have had patch time before filing the PR. ATR-2026-00440 and ATR-2026-00441 (Microsoft Semantic Kernel CVEs) are an example: rules were published after MSRC's public disclosure."}
              </span>
            </li>
          </ul>
          <p className="mt-4">
            {zh
              ? "我們沒有導入 PyRIT 的 Pliny L1B3RT4S 資料集，因為 Anthropic 的使用政策不允許我們的 subagent 消費它。AdvBench、HarmBench、JailbreakBench 被重新分類為測試語料庫（data/test-corpora/），而非規則來源——這些資料集描述目標行為，而非包裝好的攻擊 payload。"
              : "We did not import PyRIT's Pliny L1B3RT4S dataset because Anthropic's usage policy prevented our subagents from consuming it. AdvBench, HarmBench, and JailbreakBench were reclassified as test corpora (data/test-corpora/) rather than rule sources — those datasets describe target behaviors, not wrapped attack payloads."}
          </p>
        </div>
      </Reveal>

      {/* Abuse reporting */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "濫用回報" : "Abuse reporting"}
        </div>
        <h2 className="font-display text-xl font-extrabold tracking-[-0.5px] mb-4">
          {zh ? "如果你看到 ATR 被濫用。" : "If you observe ATR being misused."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog p-6 md:p-8 mb-12">
          <p className="text-sm text-graphite leading-[1.7] mb-6">
            {zh
              ? "我們沒有能力阻止濫用——MIT 授權不允許我們這樣做，也不是正確的工程做法。但我們確實想了解濫用案例，以便在文件和規則設計中做出回應。"
              : "We cannot technically prevent misuse — the MIT license does not allow it and it would not be the right engineering approach. We do want to know about misuse cases in order to respond in documentation and rule design."}
          </p>
          <div className="flex flex-col gap-3">
            <div>
              <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-1">
                {zh ? "濫用回報" : "Abuse reports"}
              </div>
              <a
                href="mailto:security@agentthreatrule.org"
                className="font-data text-sm text-blue hover:underline"
              >
                security@agentthreatrule.org
              </a>
            </div>
            <div>
              <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-1">
                {zh ? "一般問題" : "General questions"}
              </div>
              <a
                href="mailto:contact@agentthreatrule.org"
                className="font-data text-sm text-blue hover:underline"
              >
                contact@agentthreatrule.org
              </a>
            </div>
            <div>
              <div className="font-data text-xs text-stone tracking-[2px] uppercase mb-1">
                {zh ? "安全漏洞回報（ATR 本身）" : "Security vulnerability reports (ATR itself)"}
              </div>
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/SECURITY.md"
                target="_blank"
                rel="noopener noreferrer"
                className="font-data text-sm text-blue hover:underline"
              >
                {zh ? "依照 SECURITY.md 的流程" : "Follow the SECURITY.md process"} &rarr;
              </a>
            </div>
          </div>
        </div>
      </Reveal>

      {/* Links */}
      <Reveal>
        <div className="flex flex-wrap gap-4">
          <Link href={`/${locale}/governance`} className="font-data text-xs text-blue hover:underline">
            {zh ? "治理結構" : "Governance"} &rarr;
          </Link>
          <span className="text-fog">|</span>
          <Link href={`/${locale}/quality-standard`} className="font-data text-xs text-blue hover:underline">
            {zh ? "品質標準" : "Quality Standard"} &rarr;
          </Link>
          <span className="text-fog">|</span>
          <Link href={`/${locale}/red-team`} className="font-data text-xs text-blue hover:underline">
            {zh ? "紅隊整合" : "Red Team"} &rarr;
          </Link>
        </div>
      </Reveal>
    </div>
  );
}
