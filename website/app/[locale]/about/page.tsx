import { Reveal } from "@/components/Reveal";
import { loadSiteStats } from "@/lib/stats";
import { locales, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import Link from "next/link";
import Phrased from "@/components/Phrased";
import { Sign } from "@/components/Sign";

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
    path: "/about",
    title: "About",
    description:
      "ATR is the open detection standard for AI agent threats. Where it came from, how it is run, and who maintains it.",
  });
}

type Bilingual = { en: string; zh: string };

interface Milestone {
  date: string;
  title: Bilingual;
  detail: Bilingual;
}

const MILESTONES: Milestone[] = [
  {
    date: "2026-03-09",
    title: {
      en: "ATR founded · v0.1.0 released",
      zh: "ATR 啟動 · v0.1.0 發布",
    },
    detail: {
      en: "29 rules in 9 threat categories, a TypeScript engine, and 325 tests, all passing.",
      zh: "29 條規則，9 個威脅類別，一個 TypeScript 偵測引擎，325 個測試全部通過。",
    },
  },
  {
    date: "2026-04-03",
    title: {
      en: "Cisco AI Defense merges 34 rules (PR #79)",
      zh: "Cisco AI Defense 合併 34 條規則（PR #79）",
    },
    detail: {
      en: "First enterprise adoption. 1,272 lines added, merged the day after it was submitted.",
      zh: "第一個企業採用。新增 1,272 行，送出隔天就合併。",
    },
  },
  {
    date: "2026-04-06",
    title: {
      en: "v1.0.0 released",
      zh: "v1.0.0 發布",
    },
    detail: {
      en: "OWASP Agentic coverage reached 10/10. PINT F1: 76.7.",
      zh: "OWASP Agentic 覆蓋到 10/10。PINT F1 為 76.7。",
    },
  },
  {
    date: "2026-04-13",
    title: {
      en: "Microsoft AGT merges a 15-rule ATR example (PR #908)",
      zh: "Microsoft AGT 合併 15 條規則的 ATR 範例（PR #908）",
    },
    detail: {
      en: "Merged as an example directory, 554 lines added, adapted to the PolicyDocument format. The rule YAML is no longer in the AGT repository.",
      zh: "以範例目錄的形式合併，新增 554 行，改寫成 PolicyDocument 格式。這些規則 YAML 現在已經不在 AGT 的 repo 裡。",
    },
  },
  {
    date: "2026-04-14",
    title: {
      en: "Research on a mass malware campaign published",
      zh: "發表大規模惡意軟體行動的研究",
    },
    detail: {
      en: "101,280 agent skills and MCP definitions scanned across five registries, and 1,434 flagged (engine v2.0.0, data as of 2026-04-13). The research documented malicious skills from three coordinated threat accounts and notified NousResearch in issue #9809.",
      zh: "在五個 registry 掃描了 101,280 個 agent skill 與 MCP 定義，1,434 個被標記（engine v2.0.0，資料截至 2026-04-13）。研究記錄了來自三個協同帳號的惡意 skill，並在 issue #9809 通報 NousResearch。",
    },
  },
  {
    date: "2026-04-15",
    title: {
      en: "v2.0.0 released",
      zh: "v2.0.0 發布",
    },
    detail: {
      en: "113 detection rules in 8 categories, with full coverage mappings to MITRE ATLAS, OWASP Agentic, OWASP LLM and OWASP AST.",
      zh: "113 條偵測規則，分成 8 個類別。對 MITRE ATLAS、OWASP Agentic、OWASP LLM、OWASP AST 都有完整對照。",
    },
  },
  {
    date: "2026-04-21",
    title: {
      en: "v2.0.11 · NVIDIA garak coverage",
      zh: "v2.0.11 · 涵蓋 NVIDIA garak",
    },
    detail: {
      en: "193 new rules, many written from the NVIDIA garak probe corpus, for 311 in total. Recall on garak's in-the-wild jailbreak subset was 97.1% (647/666) at the time, with every rule loaded. Detection lanes came later; that setup is what today's hunt lane loads. Many of these rules were written from that same corpus, so the figure is partly closed-book. It is not an out-of-sample result.",
      zh: "新增 193 條規則，不少是照著 NVIDIA garak 的 probe 語料寫的，總數來到 311 條。當時在 garak in-the-wild 越獄子集上的召回率是 97.1%（647/666），載入的是全部規則。那時還沒有偵測車道，這個設定等於今天的 hunt 車道。因為不少規則正是從同一份語料寫出來的，這個數字有一部分是開卷考，不是樣本外的成績。",
    },
  },
  {
    date: "2026-04-22",
    title: {
      en: "ATR rule pack merged into cisco-ai-defense/skill-scanner (PR #99)",
      zh: "ATR 規則集合併進 cisco-ai-defense/skill-scanner（PR #99）",
    },
    detail: {
      en: "A follow-up to the 34-rule PoC. It lands the ATR rule pack in skill-scanner, the Cisco AI Defense team's open-source repository, which consumes it two ways: through the rule-packs CLI and through skill-scanner itself. This is a merged pull request in a public repository. It is not a statement about Cisco's commercial product.",
      zh: "34 條 PoC 之後的後續 PR，把 ATR 規則集放進 Cisco AI Defense 團隊的開源 skill-scanner repo。這個 repo 有兩條使用路徑：rule-packs CLI 和 skill-scanner。這是公開 repo 裡一個已合併的 PR，講的不是 Cisco 的商業產品。",
    },
  },
  {
    date: "2026-04-26",
    title: {
      en: "Microsoft AGT example grows to 287 rules, plus a weekly sync workflow (PR #1277)",
      zh: "Microsoft AGT 範例擴充到 287 條規則，加上每週同步 workflow（PR #1277）",
    },
    detail: {
      en: "Builds on PR #908's 15-rule example with 272 more rules (287 in total) and a weekly sync workflow. The rule YAML has since left the AGT repository, and the workflow is pinned to an old ATR release.",
      zh: "接續 PR #908 的 15 條範例，再加 272 條（合計 287 條）和一個每週同步的 workflow。之後規則 YAML 已經不在 AGT repo 裡，workflow 也還釘在舊版 ATR。",
    },
  },
  {
    date: "2026-05-10",
    title: {
      en: "MISP / CIRCL taxonomy and galaxy merged",
      zh: "MISP / CIRCL 合併 taxonomy 與 galaxy",
    },
    detail: {
      en: "Alexandre Dulaunoy (CIRCL) merged the ATR rule-ID taxonomy (misp-taxonomies #323) and a threat-intel galaxy (misp-galaxy #1207) into MISP's taxonomy and galaxy repositories. The ATR maintainer opened both pull requests.",
      zh: "CIRCL 的 Alexandre Dulaunoy 把 ATR 的規則編號 taxonomy（misp-taxonomies #323）和威脅情資 galaxy（misp-galaxy #1207）合進 MISP 的 taxonomy 與 galaxy 兩個 repo。兩個 PR 都是 ATR 維護者開的。",
    },
  },
  {
    date: "2026-05-11",
    title: {
      en: "OWASP Agent Security Regression Harness (#74) and Gen Digital Sage (#33) merged on the same day",
      zh: "OWASP Agent Security Regression Harness（#74）與 Gen Digital Sage（#33）同一天合併",
    },
    detail: {
      en: "The OWASP Agent Security Regression Harness project merged four regression scenarios derived from ATR rules (PR #74, merged by Mert Satilmaz). The scenario files do not mention ATR. The same day, Gen Digital, the parent of Norton, Avast and LifeLock, merged the full ATR rule pack into the Sage agentic-AI risk-scoring layer (PR #33).",
      zh: "OWASP 的 Agent Security Regression Harness 專案合併了四個從 ATR 規則改寫的回歸情境（PR #74，由 Mert Satilmaz 合併），情境檔裡沒有提到 ATR。同一天，Norton、Avast、LifeLock 的母集團 Gen Digital，把完整的 ATR 規則集合進 Sage 的 agentic AI 風險評分層（PR #33）。",
    },
  },
  {
    date: "2026-05-22",
    title: {
      en: "ATR website rewritten in standards form",
      zh: "ATR 官網改寫成標準文件的體裁",
    },
    detail: {
      en: "The hero, footer and information architecture were rewritten to read like peer standards such as Sigma, YARA, ATT&CK and NIST AI RMF. An intake pipeline for integrations shipped with it: a structured issue form, an auto-triage workflow, and ADOPTERS.md as the machine-readable source of truth.",
      zh: "首頁主視覺、頁尾和資訊架構全部改寫，向 Sigma、YARA、ATT&CK、NIST AI RMF 這類標準的寫法看齊。整合申請流程同時上線：結構化的 issue 表單、自動分流的 workflow，以及作為機器可讀來源的 ADOPTERS.md。",
    },
  },
  {
    date: "2026-06",
    title: {
      en: "v3.5.0 · detection lanes ship",
      zh: "v3.5.0 · 偵測車道上線",
    },
    detail: {
      en: "v3.5.0 (652 rules at release) introduced detection lanes: enforce, alert and hunt. Precision follows rule maturity, and false-positive rates are reported per lane instead of as a single figure.",
      zh: "v3.5.0（發布時 652 條規則）加入偵測車道：enforce、alert、hunt。精確度跟著規則成熟度走，誤報率逐車道公布，不用單一數字概括。",
    },
  },
  {
    date: "2026-07",
    title: {
      en: "Adoption re-verified · auto-publish flywheel",
      zh: "採用紀錄全部重驗 · 自動發布飛輪",
    },
    detail: {
      en: "Every adopter PR was re-checked against GitHub, and newly shipped integrations were recorded, among them FINOS, SigmaHQ, rulezet/CIRCL, AMD GAIA and AG2. The crystallization flywheel now publishes new rules to npm automatically when they merge. The rule count, spec version and adopter wall on this site are all rebuilt from the repository at deploy time.",
      zh: "每個採用者 PR 的狀態都對 GitHub 重新驗過一次，新上線的整合也一併記錄，包括 FINOS、SigmaHQ、rulezet/CIRCL、AMD GAIA、AG2。結晶飛輪現在會在規則合併時自動發布到 npm。本站的規則數、規格版本和採用者牆，都在部署時從 repo 重新產生。",
    },
  },
];

export default async function AboutPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: rawLocale } = await params;
  const locale = (locales.includes(rawLocale as Locale) ? rawLocale : "en") as Locale;
  const zh = locale === "zh";
  const ruleCount = loadSiteStats().ruleCount;

  return (
    <Phrased>
    <div className="pt-20 pb-20 px-6 md:px-14 max-w-[972px]">
      {/* Header */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "關於 ATR" : "About ATR"}
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <h1 className="text-[32px] md:text-[48px] leading-[1.06] tracking-[-0.01em] font-medium text-ink">
          {zh ? "一個開放標準。" : "An open standard."}
          <br />
          {zh ? "從一位維護者開始。" : "Started by one maintainer."}
        </h1>
      </Reveal>
      <Reveal delay={0.1}>
        <p className="text-sm md:text-base text-graphite max-w-[640px] mt-5 md:mt-6 leading-[1.8]">
          {zh
            ? "ATR 是一套開放標準，用來偵測 AI agent 面對的資安威脅。這一頁說明它為什麼出現、怎麼運作，以及目前由誰維護。"
            : "ATR is the open detection standard for AI agent security threats. This page covers why it exists, how it works and who maintains it."}
        </p>
      </Reveal>

      {/* Mission */}
      <Section label={zh ? "它做什麼" : "What it does"} delay={0.15}>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh
            ? "ATR 寫的是能直接執行的偵測規則。MITRE ATLAS、OWASP Agentic、NIST AI RMF 這些框架，負責把威脅分類、定義風險管理的流程。ATR 的規則則直接跑在 agent 真正用到的檔案上：SKILL.md、MCP 工具描述、agent 設定檔。ATR 之於 MITRE ATLAS，就像 Sigma 規則之於 ATT&CK。"
            : "ATR is a set of detection rules you can run. Frameworks such as MITRE ATLAS, OWASP Agentic and NIST AI RMF sort threats into categories and define how to manage risk. ATR's rules run on the files an agent actually uses: SKILL.md files, MCP tool descriptions, agent configs. ATR is to MITRE ATLAS what Sigma rules are to ATT&CK."}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh
            ? "規則用 MIT 授權公開，以 YAML 格式放在 GitHub 上。誰都可以整合、修改，或把改動送回上游。沒有付費功能，也沒有廠商鎖定。利益揭露：維護者創辦並控制 PANGUARD AI, INC.，這家公司販售以 ATR 為基礎的 agent 資安產品。"
            : "The rules are YAML files on GitHub under the MIT license. Anyone may integrate them, change them, or send changes back upstream. Nothing is paid, and nothing locks you to a vendor. Interests: the maintainer founded and controls PANGUARD AI, INC., which sells AI agent security products built on ATR."}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh
            ? <>標準由社群推動。六月到現在，規則從 462 條增加到 {ruleCount} 條。來源有 CVE 與安全公告的掃描、從 benchmark 漏報裡挖出來的攻擊，還有貢獻者送來的規則。每一條都是透過維護者合併的 pull request 進到 main。</>
            : <>The standard is community-driven. Since June the ruleset has grown from 462 to {ruleCount} rules. They come from sweeps of CVEs and advisories, from attacks the benchmark missed, and from contributors. Each one reaches main through a pull request that a maintainer merges.</>}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh
            ? "比規則數量更要緊的，是把精確度老實交代清楚。v3.5.0 加入了偵測車道：每條規則都標明成熟度，用的人自己決定要信到什麼程度。enforce 車道只讓最成熟的規則觸發。預設的 hunt 車道會跑全部規則，結果只當建議。ATR 的誤報率一條車道一條車道公布，從不拿一個好看的數字概括。目前各車道的誤報率已經撤回，等重新量測。原因是後來發現，量測用的良性語料裡混進了真實的越獄樣本。"
            : "The rule count matters less than being honest about precision. The v3.5.0 release introduced detection lanes: every rule declares a maturity, and whoever runs the rules decides how far to trust them. The enforce lane fires only the most mature rules. The default hunt lane runs everything, as advisory. ATR reports false-positive rates lane by lane, never as one flattering number. The current per-lane figures are withdrawn pending re-measurement, because the benign corpus they were measured on turned out to contain real jailbreak samples."}
        </p>
      </Section>

      {/* History Timeline */}
      <Section label={zh ? "歷程" : "History"} delay={0.2}>
        <ol className="space-y-0">
          {MILESTONES.map((m, i) => (
            <li key={i} className="flex gap-4 md:gap-6 relative pl-1">
              <div className="font-data text-xs text-stone w-[92px] shrink-0 pt-1.5">
                {m.date}
              </div>
              <div className="flex flex-col items-center shrink-0 pt-2.5">
                <div className="w-2 h-2 rounded-full bg-ink" />
                {i < MILESTONES.length - 1 && (
                  <div className="w-px flex-1 bg-fog mt-1 min-h-[48px]" />
                )}
              </div>
              <div className="pb-7 flex-1 min-w-0">
                <div className="font-display text-sm md:text-base font-semibold text-ink leading-[1.4]">
                  {zh ? m.title.zh : m.title.en}
                </div>
                <p className="text-sm text-graphite mt-1.5 leading-[1.7]">
                  {zh ? m.detail.zh : m.detail.en}
                </p>
              </div>
            </li>
          ))}
        </ol>
      </Section>

      {/* Governance */}
      <Section label={zh ? "治理" : "Governance"} delay={0.25}>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh
            ? "每一個規則變更，都以公開的 GitHub pull request 提交和審查。收規則的條件包括：描述清楚、附上真陽性和假陽性的 test case、符合 schema，而且不跟現有規則衝突。"
            : "Every rule change is proposed and reviewed in a public GitHub pull request. The acceptance criteria include a clear description, test cases covering true and false positives, schema compliance, and no conflict with existing rules."}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh
            ? "規則編號照 CVE/CWE 的方式編（ATR-YYYY-NNNNN），發布之後永遠不改。規則內容可以修訂（rule_version++），編號不變。外部文件、論文、CI 腳本都可以放心引用。"
            : "Rule IDs follow the CVE/CWE style (ATR-YYYY-NNNNN) and never change after publication. A rule can be revised (rule_version++) while its ID stays the same, so external docs, papers and CI scripts can cite it safely."}
        </p>
        <div className="mt-5">
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/GOVERNANCE.md"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs md:text-sm text-blue hover:underline"
          >
            {zh ? "完整治理文件（GOVERNANCE.md）" : "Read the full governance document (GOVERNANCE.md)"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
          </a>
        </div>
      </Section>

      {/* Maintainers */}
      <Section label={zh ? "維護者" : "Maintainers"} delay={0.3}>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh
            ? "ATR 由林冠辛發起，現在也主要由他維護。專案是一個人開始的。1991 年的 Linux 是 Linus Torvalds 一個人起頭，Sigma 是 Florian Roth 起頭。要看的是社群能不能真的貢獻進來。"
            : "Kuan-Hsin Lin started ATR and is still its main maintainer. One person started it, the way Linus Torvalds started Linux in 1991 and Florian Roth started Sigma. What matters is whether the community can make real contributions."}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh
            ? "到目前為止的外部採用：三個已合併的上游整合，每一個都有公開 repo 裡已合併的 PR 為憑。分別是 Cisco AI Defense 開源 skill-scanner 裡的 ATR 規則集、Microsoft AGT 的 ATR 範例目錄，以及 Gen Digital 已合併的 Sage 規則包。MISP 收下了 ATR 的 taxonomy（#323）和 galaxy（#1207），由 CIRCL 的維護者合併。OWASP Agent Security Regression Harness 合併了四個從 ATR 改寫的回歸情境（#74），檔案裡沒有標註 ATR。另有兩個提案還開著，尚未合併。一個是送到 NIST OSCAL 內容庫的 usnistgov/oscal-content#338，提供 AI RMF profile 範例，正在等 NIST 審查，不是 NIST 背書。另一個是 OpenTelemetry GenAI SIG 的 PR #165，定義 agent.threat.detection.* 語意慣例。這些整合都是用 pull request 進來的，沒有私下 fork。"
            : "External adoption so far: three merged upstream integrations, each backed by a merged pull request in a public repository. They are the ATR rule pack in Cisco AI Defense's open-source skill-scanner, ATR example directories in Microsoft AGT, and Gen Digital's merged Sage pack. MISP took in an ATR taxonomy (#323) and galaxy (#1207), merged by a CIRCL maintainer. The OWASP Agent Security Regression Harness merged four regression scenarios derived from ATR (#74); the files do not credit ATR. Two proposals are still open and unmerged. One is usnistgov/oscal-content#338, which offers AI RMF profile examples to NIST's OSCAL content repository and is awaiting NIST review; it is not a NIST endorsement. The other is PR #165 in OpenTelemetry's GenAI SIG, for the agent.threat.detection.* semantic conventions. These enterprises integrated through pull requests, not private forks. That is the kind of adoption ATR is built for."}
        </p>
        <div className="mt-5 flex flex-wrap gap-x-5 gap-y-2">
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/CONTRIBUTORS.md"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs md:text-sm text-blue hover:underline"
          >
            {zh ? "貢獻者名單" : "Contributors list"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
          </a>
          <Link
            href={`/${locale}/contribute`}
            className="font-data text-xs md:text-sm text-blue hover:underline"
          >
            {zh ? "如何貢獻" : "How to contribute"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
          </Link>
        </div>
      </Section>

      {/* Independence notice */}
      <Section label={zh ? "獨立聲明" : "Independence"} delay={0.35}>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh
            ? "ATR 不屬於任何商業公司，不是哪個資安產品的功能。規則是公共財。誰都可以採用、擴充或 fork，競爭廠商也一樣。"
            : "No commercial entity owns ATR. It is not a feature of any security product. The rules are a public good. Anyone may adopt, extend or fork them, competing vendors included."}
        </p>
      </Section>
    </div>
    </Phrased>
  );
}

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
        <div className="text-[13px] text-stone mb-4 md:mb-5">
          {label}
        </div>
        {children}
      </section>
    </Reveal>
  );
}
