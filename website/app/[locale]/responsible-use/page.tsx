import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import { loadSiteStats } from "@/lib/stats";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import Link from "next/link";

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
    path: "/responsible-use",
    title: "Responsible Use",
    description:
      "ATR's responsible-use policy: what the rules are for, what counts as misuse, why the standard is dual-use, and where to report abuse.",
  });
}

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
    <div className="pt-20 pb-20 px-6 md:px-14 max-w-[972px]">
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "負責任使用" : "Responsible use"}
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <h1 className="text-[32px] md:text-[48px] leading-[1.12] tracking-[-0.01em] font-medium text-ink mb-4">
          {zh ? "公開的攻擊偵測標準，必須回答雙重用途的問題。" : "A public attack-detection standard must answer for dual use."}
        </h1>
      </Reveal>
      <Reveal delay={0.1}>
        <p className="text-base text-stone font-light max-w-[640px] leading-[1.8] mb-12">
          {zh
            ? `ATR 的 ${stats.ruleCount} 條規則描述 AI agent 的攻擊模式，目的是偵測。描述攻擊的標準，也可能被誤讀成攻擊的配方。CVE、Sigma、YARA、ATT&CK 都有這個張力。ATR 選擇透明：規則公開、可以審查，邊界寫在這一頁，不靠藏起來求安全。下面講設計意圖、已知的雙重用途風險、ATR 抓不到什麼，還有回報濫用的管道。`
            : `ATR's ${stats.ruleCount} rules describe attack patterns against AI agents so that they can be detected. A standard that documents attacks can also be misread as a recipe for them. CVE, Sigma, YARA and ATT&CK all carry the same tension. ATR's answer is transparency: the rules are public and reviewable, and the boundaries are written down here instead of relying on obscurity. This page covers the design intent, the known dual-use risks, what ATR does not catch, and how to report misuse.`}
        </p>
      </Reveal>

      {/* Intended use */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "設計用途" : "Intended use"}
        </div>
        <h2 className="font-display text-xl font-medium tracking-[-0.5px] mb-4">
          {zh ? "ATR 是防禦端的偵測標準。" : "ATR is a defensive detection standard."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="space-y-px bg-fog mb-12">
          {[
            {
              title: zh ? "整合進資安掃描器" : "Integrate into security scanners",
              desc: zh
                ? "在 CI/CD pipeline、agent runtime 或 MCP server 的中介層裡執行 ATR 規則，偵測 SKILL.md、工具描述、agent 設定檔裡的已知攻擊模式。Cisco AI Defense 的開源 skill-scanner 已經合併 ATR 規則集，Microsoft AGT 也有已合併的 ATR 範例目錄，兩者都是可以照著看的實例。"
                : "Run ATR rules in CI/CD pipelines, agent runtimes or MCP server middleware to detect known attack patterns in SKILL.md files, tool descriptions and agent configs. Cisco AI Defense's open-source skill-scanner has merged the ATR rule pack, and Microsoft AGT carries merged ATR example directories. Both are worked examples you can read.",
            },
            {
              title: zh ? "紅隊測試的基準線" : "Red-team baseline",
              desc: zh
                ? "在授權範圍內，用 ATR 規則量出你的紅隊工具找到的攻擊裡，有多少已經有偵測，有多少是還沒有規則的新型態。新型態，就是下一條規則的來源。"
                : "Within an authorized scope, use ATR rules to measure how much of what your red-team tool finds already has detection coverage, and how much is new. The new part is where the next rule comes from.",
            },
            {
              title: zh ? "標準映射與合規文件" : "Standards mapping and compliance documentation",
              desc: zh
                ? "每條 ATR 規則都對應到 OWASP、MITRE ATLAS、NIST AI RMF、EU AI Act、ISO 42001 的條目。這些對應可以當成可執行的覆蓋證據，向稽核或採購說明，哪些框架要求已經有對應的偵測。"
                : "Every ATR rule carries crosswalks to OWASP, MITRE ATLAS, NIST AI RMF, EU AI Act and ISO 42001. Use those mappings as executable coverage evidence, to show auditors or procurement which framework requirements have a matching detection.",
            },
            {
              title: zh ? "研究與學術引用" : "Research and academic citation",
              desc: zh
                ? "引用特定的規則編號（例如 ATR-2026-00440），當作攻擊偵測的可執行基準。編號照 CVE/CWE 的方式編，發布之後永遠不改，論文、CI 腳本、外部文件都能長期放心引用。"
                : "Cite specific rule IDs (e.g. ATR-2026-00440) as executable detection baselines in attack research. IDs follow CVE/CWE-style numbering and never change after publication, so papers, CI scripts and external docs can safely cite them for the long term.",
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
        <div className="text-[13px] text-stone mb-3">
          {zh ? "什麼算濫用" : "What constitutes misuse"}
        </div>
        <h2 className="font-display text-xl font-medium tracking-[-0.5px] mb-4">
          {zh ? "ATR 規則不該被當成攻擊產生器。" : "ATR rules should not be used as attack generators."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border-t border-ink pt-6 mb-6">
          <p className="text-sm text-graphite leading-[1.7] mb-4">
            {zh
              ? "每條 ATR 規則都有一段描述攻擊模式的 regex，以及涵蓋 true_positives 和 true_negatives 的 test case。這些 test_cases 是用來證明規則真的抓得到，也不會誤判良性輸入。它們讓這個標準可以被驗證，不是現成的攻擊 payload。"
              : "Each ATR rule contains a regex describing an attack pattern, plus test cases covering both true_positives and true_negatives. Those test_cases exist to prove the rule detects what it claims and does not fire on benign input. They are how the standard stays conformance-testable. They are not a supply of ready-made attack payloads."}
          </p>
          <p className="text-sm text-graphite leading-[1.7] mb-4">
            {zh
              ? "下面這些用法，算是濫用："
              : "The following uses constitute misuse:"}
          </p>
          <ul className="space-y-2 text-sm text-graphite leading-[1.7]">
            {[
              zh
                ? "未經授權，把 true_positive test case 直接當成攻擊 payload，拿去打正式環境的 AI agent 系統。"
                : "Using true_positive test cases directly as attack payloads against production AI agent systems without authorization.",
              zh
                ? "把 ATR 規則的 regex 反推成能繞過偵測的攻擊變體，拿到未經授權的目標上使用。"
                : "Reverse-engineering ATR rule regexes into evasion variants and deploying them against unauthorized targets.",
              zh
                ? "以 ATR 規則庫為基礎做攻擊自動化工具，目的是攻破已經部署 ATR 規則的系統。"
                : "Building attack automation tools grounded in the ATR rule corpus with the intent of breaching systems that have deployed ATR rules.",
              zh
                ? "用 ATR 的資料訓練攻擊模型，目的是產生能躲過 ATR 偵測的對抗性輸入。"
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
            ? "MIT 授權允許任何用途，包括商業使用和 fork。這份濫用定義不是法律限制。標準管不了自己被怎麼用，也不該假裝管得了。它是對設計意圖的明確聲明，讓採用者評估風險時，有一份可以引用的依據。"
            : "The MIT license permits any use, including commercial use and forks. This definition of misuse is not a legal restriction. A standard cannot control how it is used, and should not pretend to. It is a clear statement of design intent that adopters can cite when they evaluate risk."}
        </p>
      </Reveal>

      {/* Dual-use disclosure */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "雙重用途揭露" : "Dual-use disclosure"}
        </div>
        <h2 className="font-display text-xl font-medium tracking-[-0.5px] mb-4">
          {zh ? "這個標準有雙重用途，這件事攤開來講。" : "This standard is dual-use, and this page says so in the open."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="bg-ash p-6 md:p-8 mb-12 text-sm text-graphite leading-[1.7]">
          <p className="mb-4">
            {zh
              ? "ATR 規則描述的是 AI agent 攻擊的行為特徵。任何記錄攻擊的系統都有同樣的張力，CVE 資料庫、Sigma 規則、YARA 簽章、MITRE ATT&CK 都是。資安界長年的共識是：把攻擊技術公開寫下來，防守方得到的領先，大過攻擊方從文件得到的方便。藏起來只能拖時間，公開才能讓所有防守方同時補上。ATR 站在透明這一邊，因為偵測標準的價值，就建立在它能被審查。"
              : "ATR rules describe the behavioral signatures of attacks on AI agents. Every system that documents attacks carries the same tension: CVE databases, Sigma rules, YARA signatures, MITRE ATT&CK. The field's long-standing consensus is that writing techniques down in the open gives defenders a bigger lead than the convenience attackers draw from the documentation. Obscurity only delays. Disclosure lets every defender close the gap at once. ATR sits on the side of transparency, because a detection standard is only worth as much as it can be reviewed."}
          </p>
          <p className="mb-4">
            {zh
              ? "有兩個刻意的設計限制，把這個張力收窄："
              : "Two deliberate design constraints narrow that tension:"}
          </p>
          <ul className="space-y-2">
            <li className="flex items-start gap-3">
              <span className="text-blue shrink-0 mt-0.5">1.</span>
              <span>
                {zh
                  ? "規則裡的 true_positive test case 是最小化的模式範例，不是完整的攻擊鏈。拿來驗證偵測已經足夠，但要變成能用的 exploit，還得再做額外的攻擊工程。偵測標準需要的特徵，遠小於武器化需要的工作量。"
                  : "The true_positive test cases are minimal pattern examples, not complete attack chains. They are enough to validate detection, but turning one into a working exploit still takes additional attack engineering. The signal a detection standard needs is a small fraction of the work weaponization takes."}
              </span>
            </li>
            <li className="flex items-start gap-3">
              <span className="text-blue shrink-0 mt-0.5">2.</span>
              <span>
                {zh
                  ? "特別危險的規則（高 CVSS、已在野外被主動利用），送 PR 之前會照負責任揭露的時程走，先確認受影響的廠商已經有時間修補。ATR-2026-00440 與 ATR-2026-00441 對應 Microsoft Semantic Kernel 的兩個 critical CVE（CVE-2026-26030、CVE-2026-25592），就是這樣做的：規則在 MSRC 公開揭露之後才發布。"
                  : "Rules for the most dangerous cases (high CVSS, actively exploited in the wild) follow responsible-disclosure timelines. Before the PR is filed, the affected vendor is confirmed to have had time to patch. ATR-2026-00440 and ATR-2026-00441 cover two critical Microsoft Semantic Kernel CVEs (CVE-2026-26030 and CVE-2026-25592), and they followed this rule: they were published only after MSRC's public disclosure."}
              </span>
            </li>
          </ul>
          <p className="mt-4">
            {zh
              ? "資料來源也有界線。PyRIT 的 Pliny L1B3RT4S 資料集沒有導入，因為 Anthropic 的使用政策不允許 subagent 讀取它。AdvBench、HarmBench、JailbreakBench 歸在測試語料（data/test-corpora/），不當規則來源。這些資料集描述的是目標行為，不是包裝好的攻擊 payload。"
              : "The data sources have limits too. PyRIT's Pliny L1B3RT4S dataset was not imported, because Anthropic's usage policy does not allow the subagents used in this work to consume it. AdvBench, HarmBench and JailbreakBench are classified as test corpora (data/test-corpora/), not rule sources. Those datasets describe target behaviors, not wrapped attack payloads."}
          </p>
          <p className="mt-4">
            {zh
              ? "最後，誠實揭露也代表要講清楚 ATR 抓不到什麼。規則以 pattern 為基礎，天生看不見換句話說的改寫、語意相同的重述、非英語的注入、跨多輪的逐步升級，還有傳輸層的協定攻擊。任何讀過公開規則的攻擊者，都能避開特定的動詞、名詞和句構。ATR 把已知的繞過手法公開寫在規則的 evasion_tests 欄位裡（目前不到一半的規則有），也維護一份完整的 LIMITATIONS.md，把這些邊界寫成可以引用的文件，不留成行銷話術裡的空白。"
              : "Finally, honest disclosure means stating what ATR cannot catch. The rules are pattern-based. By construction they are blind to paraphrase, semantic equivalence, non-English injection, gradual multi-turn escalation and transport-layer protocol attacks. Any attacker who reads the published rules can route around the specific verbs, nouns and syntax. ATR publishes known evasions in its rules' evasion_tests fields (fewer than half of the rules have them) and keeps a full LIMITATIONS.md, so these boundaries are a document you can cite instead of a blank in the marketing. "}
          </p>
        </div>
      </Reveal>

      {/* Abuse reporting */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "濫用回報" : "Abuse reporting"}
        </div>
        <h2 className="font-display text-xl font-medium tracking-[-0.5px] mb-4">
          {zh ? "如果你看到 ATR 被濫用。" : "If you observe ATR being misused."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border-t border-ink pt-6 mb-12">
          <p className="text-sm text-graphite leading-[1.7] mb-6">
            {zh
              ? "標準本身擋不住濫用，也不該假裝擋得住。MIT 授權沒有限制用途的空間，硬要擋也不是好的工程設計。但濫用的案例值得知道。它們會回饋到文件和規則設計，讓下一版寫得更清楚，也更難被反過來利用。看到 ATR 被濫用，請告訴維護者。"
              : "A standard cannot prevent misuse, and should not pretend to. The MIT license leaves no room to restrict use, and trying would not be good engineering. Misuse cases are still worth knowing about. They feed back into the documentation and the rule design, so the next revision is clearer and harder to turn around. If you see ATR being misused, tell the maintainer."}
          </p>
          <div className="flex flex-col gap-3">
            <div>
              <div className="text-[13px] text-stone mb-1">
                {zh ? "濫用回報" : "Abuse reports"}
              </div>
              <a
                href="mailto:adam@agentthreatrule.org"
                className="font-data text-sm text-blue hover:underline"
              >
                adam@agentthreatrule.org
              </a>
            </div>
            <div>
              <div className="text-[13px] text-stone mb-1">
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
              <div className="text-[13px] text-stone mb-1">
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
            {zh ? "品質標準" : "Quality standard"} &rarr;
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
