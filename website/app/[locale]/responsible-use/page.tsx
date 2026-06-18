import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { loadSiteStats } from "@/lib/stats";
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
  const stats = loadSiteStats();

  return (
    <div className="pt-20 pb-20 px-5 md:px-6 max-w-[860px] mx-auto">
      <Reveal>
        <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-3">
          {zh ? "負責任使用" : "Responsible Use"}
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <h1 className="font-display text-[clamp(28px,4vw,48px)] font-extrabold tracking-[-2px] leading-[1.08] text-ink mb-4">
          {zh ? "一個公開的攻擊偵測標準，必須面對雙重用途。" : "A public attack-detection standard must answer for dual use."}
        </h1>
      </Reveal>
      <Reveal delay={0.1}>
        <p className="text-base text-stone font-light max-w-[640px] leading-[1.8] mb-12">
          {zh
            ? `ATR 的 ${stats.ruleCount} 條規則描述 AI agent 的攻擊模式，目的是偵測。一個描述攻擊的標準，同樣可以被誤讀為攻擊的配方——CVE、Sigma、YARA、ATT&CK 都帶著這道張力。ATR 選擇透明：規則公開、可審查，並在這裡寫清楚邊界，而不是靠隱晦求安全。本頁說明設計意圖、已知的雙重用途風險、ATR 抓不到什麼，以及回報濫用的管道。`
            : `ATR's ${stats.ruleCount} rules describe AI agent attack patterns for the purpose of detection. A standard that documents attacks can also be misread as a recipe for them — CVE, Sigma, YARA, and ATT&CK all carry the same tension. ATR's answer is transparency: the rules are public and reviewable, and the boundaries are written down here rather than relying on obscurity. This page states the design intent, the known dual-use risks, what ATR does not catch, and how to report misuse.`}
        </p>
      </Reveal>

      {/* Intended use */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "設計用途" : "Intended use"}
        </div>
        <h2 className="font-display text-xl font-extrabold tracking-[-0.5px] mb-4">
          {zh ? "ATR 是防禦端的偵測標準。" : "ATR is a defensive detection standard."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="space-y-px bg-fog mb-12">
          {[
            {
              title: zh ? "整合進安全掃描器" : "Integrate into security scanners",
              desc: zh
                ? "在 CI/CD pipeline、agent runtime、或 MCP server middleware 中執行 ATR 規則，偵測 SKILL.md、tool 描述、agent config 上的已知攻擊模式。Cisco AI Defense 與 Microsoft AGT 是生產環境的實際案例。"
                : "Run ATR rules in CI/CD pipelines, agent runtimes, or MCP server middleware to detect known attack patterns in SKILL.md files, tool descriptions, and agent configs. Cisco AI Defense and Microsoft AGT are production examples.",
            },
            {
              title: zh ? "紅隊測試的基準線" : "Red-team baseline",
              desc: zh
                ? "在授權範圍內，用 ATR 規則衡量你的紅隊工具找到的攻擊有多少已被偵測覆蓋，有多少是尚無規則的新型態——新型態正是下一條規則的來源。這是進行中的 NVIDIA garak 整合的設計意圖。"
                : "Within an authorized scope, use ATR rules to measure what fraction of the attacks your red-team tool discovers already have detection coverage, and what fraction are novel — the novel fraction is where the next rule comes from. This is the design intent of the in-review NVIDIA garak integration.",
            },
            {
              title: zh ? "標準映射與合規文件" : "Standards mapping and compliance documentation",
              desc: zh
                ? "每條 ATR 規則都對映到 OWASP、MITRE ATLAS、NIST AI RMF、EU AI Act、ISO 42001 的條目。把這些映射當作可執行的覆蓋證據，向稽核或採購說明哪些框架要求已有對應的偵測。"
                : "Every ATR rule carries crosswalks to OWASP, MITRE ATLAS, NIST AI RMF, EU AI Act, and ISO 42001. Use those mappings as executable coverage evidence — showing auditors or procurement which framework requirements have a corresponding detection.",
            },
            {
              title: zh ? "研究與學術引用" : "Research and academic citation",
              desc: zh
                ? "引用特定 rule ID（例如 ATR-2026-00440）作為攻擊偵測的可執行基準。規則 ID 以 CVE/CWE 風格編號，一經發布永不改動——論文、CI 腳本、外部文件都能安全長期引用。"
                : "Cite specific rule IDs (e.g. ATR-2026-00440) as executable detection baselines for attack research. IDs follow CVE/CWE-style numbering and never change after publication — safe for papers, CI scripts, and external documentation to reference for the long term.",
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
              ? "每條 ATR 規則都包含攻擊模式的 regex 描述，以及涵蓋 true_positives 與 true_negatives 的 test cases。這些 test_cases 的存在是為了證明規則確實能偵測、且不會誤判良性輸入——它們是規範可被驗證的依據，不是現成的攻擊 payload。"
              : "Each ATR rule contains a regex description of an attack pattern and test cases covering both true_positives and true_negatives. Those test_cases exist to prove the rule detects what it claims and does not fire on benign input — they are how the standard stays conformance-testable, not a supply of ready-made attack payloads."}
          </p>
          <p className="text-sm text-graphite leading-[1.7] mb-4">
            {zh
              ? "以下使用方式構成濫用："
              : "The following uses constitute misuse:"}
          </p>
          <ul className="space-y-2 text-sm text-graphite leading-[1.7]">
            {[
              zh
                ? "未經授權,將 true_positive test cases 直接作為對生產 AI agent 系統的攻擊 payload 使用。"
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
            ? "MIT 授權允許任何使用，包括商業與 fork。這份濫用定義不是法律限制——標準層管不了它被怎麼用，也不該假裝管得了。它是一份對設計意圖的明確聲明，讓採用者在評估風險時有一個可引用的參照。"
            : "The MIT license permits any use, including commercial and forked use. This misuse definition is not a legal restriction — a standard cannot control how it is used, and should not pretend to. It is a clear statement of design intent, giving adopters a reference they can cite when evaluating risk."}
        </p>
      </Reveal>

      {/* Dual-use disclosure */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "雙重用途揭露" : "Dual-use disclosure"}
        </div>
        <h2 className="font-display text-xl font-extrabold tracking-[-0.5px] mb-4">
          {zh ? "這個標準是雙重用途的，我們把它寫在明處。" : "This standard is dual-use, and we say so in the open."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="bg-ash p-6 md:p-8 mb-12 text-sm text-graphite leading-[1.7]">
          <p className="mb-4">
            {zh
              ? "ATR 規則描述 AI agent 攻擊的行為特徵。任何描述攻擊的系統——CVE 資料庫、Sigma 規則、YARA 簽名、MITRE ATT&CK——都帶著同一道張力。資安界長年的共識是：把攻擊技術寫在明處，防守方獲得的領先，大於攻擊方從文件得到的便利。隱晦只能拖延，公開才能讓所有防守方同時補上。ATR 站在透明這一邊，因為偵測標準的價值正建立在它能被審查。"
              : "ATR rules describe behavioral signatures of AI agent attacks. Any system that documents attacks — CVE databases, Sigma rules, YARA signatures, MITRE ATT&CK — carries the same tension. The field's long-standing consensus is that writing techniques down in the open gives defenders a lead larger than the convenience attackers draw from the documentation. Obscurity only delays; disclosure lets every defender close the gap at once. ATR sits on the side of transparency because a detection standard is only worth as much as it can be reviewed."}
          </p>
          <p className="mb-4">
            {zh
              ? "兩個刻意的設計約束，把這道張力收窄："
              : "Two deliberate design constraints narrow that tension:"}
          </p>
          <ul className="space-y-2">
            <li className="flex items-start gap-3">
              <span className="text-blue shrink-0 mt-0.5">1.</span>
              <span>
                {zh
                  ? "規則中的 true_positive test case 是最小化的模式範例，不是完整的攻擊鏈。它們足以驗證偵測，卻仍需要額外的攻擊工程才能變成可用的 exploit——偵測規範需要的特徵面，遠小於武器化需要的工作量。"
                  : "The true_positive test cases are minimal pattern exemplars, not complete attack chains. They are sufficient to validate detection, yet still require additional attack engineering to become a working exploit — the signal a detection standard needs is a small fraction of the work weaponization takes."}
              </span>
            </li>
            <li className="flex items-start gap-3">
              <span className="text-blue shrink-0 mt-0.5">2.</span>
              <span>
                {zh
                  ? "特別危險的規則（高 CVSS、已在野外主動利用）在送 PR 前，遵循負責任揭露的時程，確認受影響廠商已有修補時間。ATR-2026-00440 與 ATR-2026-00441 對應 Microsoft Semantic Kernel 的兩個 critical CVE（CVE-2026-26030、CVE-2026-25592），是這條原則的實例：規則在 MSRC 公開揭露之後才發布。"
                  : "Rules for the most dangerous cases (high CVSS, actively exploited in the wild) follow responsible-disclosure timelines, confirming affected vendors have had patch time before the PR is filed. ATR-2026-00440 and ATR-2026-00441 — covering two critical Microsoft Semantic Kernel CVEs (CVE-2026-26030 and CVE-2026-25592) — are an instance of this: the rules were published only after MSRC's public disclosure."}
              </span>
            </li>
          </ul>
          <p className="mt-4">
            {zh
              ? "資料來源同樣有界線。PyRIT 的 Pliny L1B3RT4S 資料集未被導入——Anthropic 的使用政策不允許 subagent 消費它。AdvBench、HarmBench、JailbreakBench 被歸類為測試語料庫（data/test-corpora/），而非規則來源：這些資料集描述目標行為，不是包裝好的攻擊 payload。"
              : "Source provenance is bounded too. PyRIT's Pliny L1B3RT4S dataset was not imported — Anthropic's usage policy does not allow our subagents to consume it. AdvBench, HarmBench, and JailbreakBench are classified as test corpora (data/test-corpora/) rather than rule sources: those datasets describe target behaviors, not wrapped attack payloads."}
          </p>
          <p className="mt-4">
            {zh
              ? "最後，誠實的揭露也意味著說清楚 ATR 抓不到什麼。規則以 pattern 為基礎，對換句話說的改寫、語意等價的重述、非英語的注入、跨多輪逐步升級、以及傳輸層協定攻擊本質上是盲的——任何讀過公開規則的攻擊者，都能避開特定的動詞、名詞與句構。ATR 公開維護 64 條已知繞過技法（每條規則的 evasion_tests 欄位）與一份完整的 LIMITATIONS.md，把這些邊界寫成可被引用的文件，而不是行銷話術裡的空白。一個偵測標準的可信度，取決於它願不願意公開自己最差的數字。"
              : "Finally, honest disclosure means stating what ATR cannot catch. The rules are pattern-based, and are blind by construction to paraphrase, semantic equivalence, non-English injection, gradual multi-turn escalation, and transport-layer protocol attacks — any attacker who reads the published rules can route around the specific verbs, nouns, and syntax. ATR publishes 64 known evasion techniques (in each rule's evasion_tests field) and a full LIMITATIONS.md, writing these boundaries down as a citable document rather than leaving them as a blank in the marketing. A detection standard earns trust by publishing its worst figure, not hiding it."}
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
              ? "標準層阻止不了濫用，也不應該假裝做得到——這不是 MIT 授權允許的事，也不是好的工程設計。但濫用的案例值得被了解：它會回饋到文件與規則設計，讓下一版更清楚也更難被反向利用。看到 ATR 被濫用，請告訴我們。"
              : "A standard layer cannot prevent misuse, and should not pretend to — that is not what the MIT license permits, nor good engineering. But misuse cases are worth knowing about: they feed back into documentation and rule design, making the next revision clearer and harder to turn around. If you see ATR being misused, tell us."}
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
