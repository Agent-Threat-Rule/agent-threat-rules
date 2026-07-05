import { Reveal } from "@/components/Reveal";
import { loadSiteStats } from "@/lib/stats";
import { locales, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
import Link from "next/link";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "About — ATR",
  description:
    "ATR is the open detection standard for AI agent threats. Mission, history, governance, and maintainers.",
};

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
      en: "29 rules across 9 threat categories, TypeScript engine, 325 passing tests.",
      zh: "29 條規則，9 個威脅類別，TypeScript 偵測引擎，325 個測試全通過。",
    },
  },
  {
    date: "2026-04-03",
    title: {
      en: "Cisco AI Defense merges 34 rules (PR #79)",
      zh: "Cisco AI Defense 合併 34 條規則（PR #79）",
    },
    detail: {
      en: "First enterprise adoption. 1,272 additions, merged one day after submission.",
      zh: "首個企業級採用。新增 1,272 行，送出後隔日合併。",
    },
  },
  {
    date: "2026-04-06",
    title: {
      en: "v1.0.0 released",
      zh: "v1.0.0 發布",
    },
    detail: {
      en: "Coverage milestone: OWASP Agentic 10/10, SAFE-MCP 91.8%, PINT F1 76.7.",
      zh: "覆蓋里程碑：OWASP Agentic 10/10、SAFE-MCP 91.8%、PINT F1 76.7。",
    },
  },
  {
    date: "2026-04-13",
    title: {
      en: "Microsoft AGT merges 15 rules (PR #908)",
      zh: "Microsoft AGT 合併 15 條規則（PR #908）",
    },
    detail: {
      en: "Second enterprise adoption. 554 additions, adapted as PolicyDocument.",
      zh: "第二個企業級採用。新增 554 行，改寫為 PolicyDocument 格式。",
    },
  },
  {
    date: "2026-04-14",
    title: {
      en: "Mass malware campaign research published",
      zh: "大規模惡意軟體行動研究發布",
    },
    detail: {
      en: "Scanned 96,096 skills across five registries. Documented malicious skills from three coordinated threat actors (552 confirmed on the live blacklist). Notified NousResearch via issue #9809.",
      zh: "跨五個 registry 掃描 96,096 個 skill，記錄三個協同行為者的惡意 skill（即時黑名單已確認 552 個），透過 issue #9809 通報 NousResearch。",
    },
  },
  {
    date: "2026-04-15",
    title: {
      en: "v2.0.0 released",
      zh: "v2.0.0 發布",
    },
    detail: {
      en: "113 detection rules across 8 categories. Full coverage mapping to MITRE ATLAS, OWASP Agentic, OWASP LLM, and OWASP AST.",
      zh: "113 條偵測規則，跨 8 個類別。完整對照 MITRE ATLAS、OWASP Agentic、OWASP LLM、OWASP AST。",
    },
  },
  {
    date: "2026-04-21",
    title: {
      en: "v2.0.11 · NVIDIA garak coverage",
      zh: "v2.0.11 · NVIDIA garak 覆蓋",
    },
    detail: {
      en: "193 new rules covering the full NVIDIA garak probe corpus (311 total). garak in-the-wild jailbreak subset recall: 97.1% (646/666) at the time.",
      zh: "新增 193 條規則，涵蓋完整 NVIDIA garak probe corpus（總計 311 條）。garak in-the-wild jailbreak 子集召回率（當時）：97.1%（646/666）。",
    },
  },
  {
    date: "2026-04-22",
    title: {
      en: "Cisco AI Defense production rollout (PR #99)",
      zh: "Cisco AI Defense production 上線 (PR #99)",
    },
    detail: {
      en: "Follow-up production PR after the 34-rule PoC. Lands the full ATR rule pack inside Cisco AI Defense's skill-scanner. ATR now ships in two Cisco production paths: rule-packs CLI and skill-scanner.",
      zh: "34 條 PoC 之後的 production 跟進 PR,把完整 ATR 規則集送進 Cisco AI Defense 的 skill-scanner。ATR 同時走兩條 Cisco production 路徑:rule-packs CLI + skill-scanner。",
    },
  },
  {
    date: "2026-04-26",
    title: {
      en: "Microsoft AGT 287-rule expansion + weekly auto-sync (PR #1277)",
      zh: "Microsoft AGT 287 條規則擴張 + 每週自動同步 (PR #1277)",
    },
    detail: {
      en: "Follow-up to PR #908's 15-rule PoC. Adds 272 more rules (287 total) and a workflow that auto-syncs ATR upstream releases every week. First standards-grade auto-sync pipeline.",
      zh: "PR #908 (15 條 PoC) 的 production 跟進。新增 272 條規則 (合計 287 條),並加上每週自動同步 ATR 上游釋出版本的 workflow。第一條標準級自動同步管線。",
    },
  },
  {
    date: "2026-05-10",
    title: {
      en: "MISP / CIRCL taxonomy + galaxy merged",
      zh: "MISP / CIRCL taxonomy + galaxy 合併",
    },
    detail: {
      en: "Alexandre Dulaunoy (CIRCL) merged ATR rule-ID taxonomy (misp-taxonomies #323) and threat-intel galaxy (misp-galaxy #1207) into MISP's core distribution. First neutral standards-body adoption.",
      zh: "Alexandre Dulaunoy (CIRCL) 把 ATR rule-ID taxonomy (misp-taxonomies #323) 跟 threat-intel galaxy (misp-galaxy #1207) 合進 MISP 主分發。第一個中立標準機構採用。",
    },
  },
  {
    date: "2026-05-11",
    title: {
      en: "OWASP Agent Security Regression Harness (#74) + Gen Digital Sage (#33) both merged",
      zh: "OWASP Agent Security Regression Harness (#74) 與 Gen Digital Sage (#33) 同日合併",
    },
    detail: {
      en: "OWASP Foundation's regression-harness project references ATR as its canonical agent-threat detection ruleset (PR #74, merged by Mert Satilmaz). On the same day, Gen Digital (Norton / Avast / LifeLock parent) merged the full ATR rule pack into the Sage agentic-AI risk-scoring layer (PR #33).",
      zh: "OWASP Foundation 的 regression-harness 專案把 ATR 列為標準 agent-threat 偵測 ruleset (PR #74, Mert Satilmaz 合併)。同一天,Gen Digital (Norton / Avast / LifeLock 母集團) 把完整 ATR 規則集合進 Sage agentic-AI 風險評分層 (PR #33)。",
    },
  },
  {
    date: "2026-05-22",
    title: {
      en: "ATR website standards-form rewrite",
      zh: "ATR 官網標準體裁重寫",
    },
    detail: {
      en: "Hero, footer, and information architecture rewritten to match peer-format positioning (Sigma / YARA / ATT&CK / NIST AI RMF). Integration intake pipeline shipped: structured issue form, auto-triage workflow, ADOPTERS.md as machine-readable source of truth.",
      zh: "Hero、footer、資訊架構全面改寫為標準體裁,與 Sigma / YARA / ATT&CK / NIST AI RMF 對齊。Integration intake 管線上線:結構化 issue form、自動 triage workflow、ADOPTERS.md 作為機器可讀來源。",
    },
  },
  {
    date: "2026-06",
    title: {
      en: "v3.5.0 · detection lanes ship",
      zh: "v3.5.0 · 偵測車道上線",
    },
    detail: {
      en: "v3.5.0 (652 rules at release) introduced detection lanes (enforce / alert / hunt) — maturity-driven precision, with false-positive rates reported per lane rather than as a single figure.",
      zh: "v3.5.0（發布時 652 條規則）引入偵測車道(enforce / alert / hunt)——以成熟度驅動精確度,誤報率逐車道揭露,而非用單一數字概括。",
    },
  },
  {
    date: "2026-07",
    title: {
      en: "Adoption re-verified · auto-publish flywheel",
      zh: "採用全面現驗 · 自動發布飛輪",
    },
    detail: {
      en: "Every adopter PR state re-verified against GitHub — new shipped integrations recorded across FINOS, SigmaHQ, rulezet/CIRCL, AMD GAIA, and AG2. The crystallization flywheel now auto-publishes new rules to npm on merge; rule count, spec version, and the adopter wall on this site are all rebuilt from repo state at deploy time.",
      zh: "所有採用者 PR 狀態對 GitHub 全面現驗——FINOS、SigmaHQ、rulezet/CIRCL、AMD GAIA、AG2 等新出貨整合入列。結晶飛輪已在 merge 時自動發布新規則到 npm;本站的規則數、規範版本、採用者牆全部在部署時從 repo 狀態重建。",
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
    <div className="pt-20 pb-20 px-5 md:px-6 max-w-[860px] mx-auto">
      {/* Header */}
      <Reveal>
        <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-3">
          {zh ? "關於 ATR" : "About ATR"}
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <h1 className="font-display text-[clamp(32px,5vw,56px)] font-extrabold tracking-[-2px] md:tracking-[-3px] leading-[1.05] text-ink">
          {zh ? "一個開放標準。" : "An open standard."}
          <br />
          {zh ? "一位維護者開始。" : "Started by one maintainer."}
        </h1>
      </Reveal>
      <Reveal delay={0.1}>
        <p className="text-sm md:text-base text-graphite max-w-[640px] mt-5 md:mt-6 leading-[1.8]">
          {zh
            ? "ATR 是 AI agent 安全威脅的開放式偵測標準。本頁說明它為何存在、如何運作、誰在維護。"
            : "ATR is the open detection standard for AI agent security threats. This page explains why it exists, how it works, and who maintains it."}
        </p>
      </Reveal>

      {/* Mission */}
      <Section label={zh ? "使命" : "Mission"} delay={0.15}>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh
            ? "ATR 為 AI agent 提供可執行的偵測規則。其他框架（MITRE ATLAS、OWASP Agentic、NIST AI RMF）分類威脅並定義風險管理流程；ATR 提供能在真實 agent 成品——SKILL.md、MCP tool 描述、agent config——上運作的偵測規則。ATR 之於 MITRE ATLAS，等同於 Sigma 規則之於 ATT&CK。"
            : "ATR provides executable detection rules for AI agents. Other frameworks — MITRE ATLAS, OWASP Agentic, NIST AI RMF — categorize threats and define risk management processes. ATR provides the detection rules that operate on real agent artifacts: SKILL.md files, MCP tool descriptions, agent configs. ATR is to MITRE ATLAS what Sigma rules are to ATT&CK."}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh
            ? "規則以 MIT 授權公開，YAML 格式儲存於 GitHub。任何人都可以整合、修改、或貢獻回上游。沒有付費功能，沒有廠商鎖定。"
            : "Rules are published under MIT license in YAML format on GitHub. Anyone may integrate, modify, or contribute upstream. There are no paid features. There is no vendor lock-in."}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh
            ? <>標準由社群驅動，並透過每日自動結晶飛輪持續擴張——紅隊大掃描與 CVE 攝取兩條管線各自跑完完整 sweep，把規則集從 462 條長到 {ruleCount} 條。</>
            : <>The standard is community-driven and grows through daily auto-crystallization flywheels — a red-team mega-scan pipeline and a CVE-ingestion pipeline each ran full sweeps, expanding the ruleset from 462 to {ruleCount} rules.</>}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh
            ? "但成長從不是目的——對精確度誠實才是。v3.5.0 引入偵測車道:每條規則標明成熟度,使用者自己決定要信任到什麼程度。enforce 車道只讓最成熟的規則開火(在 65,000 筆良性語料上約 0.24% 誤報);預設的 hunt 車道把全部規則當建議性訊號跑(約 9%)。ATR 逐車道揭露誤報率,從不用單一個好看的數字一概而論。一個標準的可信度,取決於它願不願意公開自己最差的數字。"
            : "But growth was never the point — honesty about precision is. The v3.5.0 release introduced detection lanes: every rule declares a maturity, and the consumer decides how far to trust it. The enforce lane fires only the most mature rules (~0.24% false positives on a 65,000-sample benign corpus); the default hunt lane runs everything as advisory (~9%). ATR reports false-positive rates lane by lane, never as a single flattering number. A standard earns trust by publishing its worst figure, not hiding it."}
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
            ? "所有規則變更都透過公開的 GitHub Pull Request 提交與審查。規則採納標準包括：描述清楚、有 test cases（真/假陽性範例）、遵守 schema 規範、不與現有規則衝突。"
            : "All rule changes are submitted and reviewed via public GitHub pull requests. Adoption criteria include: clear description, test cases covering true and false positives, schema compliance, and no conflict with existing rules."}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh
            ? "規則嚴格按 CVE/CWE 風格編號（ATR-YYYY-NNNNN），一經發布永不改 ID。規則可以修訂（rule_version++），但 ID 穩定——外部文件、論文、CI 腳本都可以安全引用。"
            : "Rules use CVE/CWE-style identifiers (ATR-YYYY-NNNNN). IDs never change after publication. Rules may be revised (rule_version++), but the ID remains stable — safe for external documentation, academic citations, and CI scripts to reference."}
        </p>
        <div className="mt-5">
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/GOVERNANCE.md"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs md:text-sm text-blue hover:underline"
          >
            {zh ? "閱讀完整治理文件 (GOVERNANCE.md) →" : "Read full governance document (GOVERNANCE.md) →"}
          </a>
        </div>
      </Section>

      {/* Maintainers */}
      <Section label={zh ? "維護者" : "Maintainers"} delay={0.3}>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh
            ? "ATR 由 林冠辛 發起並主要維護。這是一個單人啟動的專案——就像 Linus Torvalds 1991 年的 Linux、Florian Roth 的 Sigma。重點是社群能不能實質貢獻，而不是 founders 名單有多長。"
            : "ATR was founded and is primarily maintained by Kuan-Hsin Lin. This is a project started by one person — the same way Linus Torvalds started Linux in 1991, or Florian Roth started Sigma. What matters is whether the community can contribute substantively, not how long the founders list is."}
        </p>
        <p className="text-sm md:text-base text-graphite leading-[1.8] mt-4">
          {zh
            ? "目前的外部採用包含兩條生產環境部署(Cisco AI Defense 完整規則集進 skill-scanner、Microsoft AGT 287 條規則加每週自動同步),外加 Gen Digital Sage 已合併的規則包,兩個標準機構已合併(MISP/CIRCL 的 taxonomies #323 + galaxy #1207、OWASP A-S-R-H #74),以及兩條送審中的 standards-body 提案(NIST AI RMF 社群 OSCAL catalog 已自 publish · usnistgov/oscal-content#338 協作分支審查中,非 NIST 背書;OpenTelemetry GenAI SIG 的 agent.threat.detection.* PR #165 review 中)——這種「企業把鞋帶綁緊就提 PR」的採用模式,是 ATR 想要的治理質感。"
            : "External adoption to date includes two in production (Cisco AI Defense's full rule pack in skill-scanner, Microsoft AGT's 287 rules plus weekly auto-sync) plus Gen Digital's merged Sage pack; two standards-body integrations actually merged (MISP / CIRCL taxonomies #323 + galaxy #1207, and OWASP A-S-R-H #74); and two standards-body submissions in review (a community-authored OSCAL catalog for NIST AI RMF self-published by the ATR maintainers, with usnistgov/oscal-content#338 collaboration branch in review — not a NIST endorsement; and the agent.threat.detection.* semantic-conventions PR #165 in OpenTelemetry GenAI SIG review). This pattern — enterprises integrating via pull request instead of private forks — is the governance texture ATR is built for."}
        </p>
        <div className="mt-5 flex flex-wrap gap-x-5 gap-y-2">
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/CONTRIBUTORS.md"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs md:text-sm text-blue hover:underline"
          >
            {zh ? "貢獻者名單 →" : "Contributors list →"}
          </a>
          <Link
            href={`/${locale}/contribute`}
            className="font-data text-xs md:text-sm text-blue hover:underline"
          >
            {zh ? "如何貢獻 →" : "How to contribute →"}
          </Link>
        </div>
      </Section>

      {/* Independence notice */}
      <Section label={zh ? "獨立聲明" : "Independence"} delay={0.35}>
        <p className="text-sm md:text-base text-graphite leading-[1.8]">
          {zh
            ? "ATR 不屬於任何商業公司。不是任何安全產品的一部分，也不被任何廠商控制。規則是公共財，任何人（包括競爭廠商）都可以採用、擴充、或 fork。"
            : "ATR is not owned by any commercial entity. It is not a feature of any security product and is not controlled by any vendor. The rules are a public good — anyone, including competing vendors, may adopt, extend, or fork them."}
        </p>
      </Section>
    </div>
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
        <div className="font-data text-[11px] md:text-xs font-medium text-stone tracking-[1.5px] md:tracking-[3px] uppercase mb-4 md:mb-5">
          {label}
        </div>
        {children}
      </section>
    </Reveal>
  );
}
