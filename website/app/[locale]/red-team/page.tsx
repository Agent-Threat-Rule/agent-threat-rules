import { Reveal } from "@/components/Reveal";
import { loadSiteStats, type SiteStats } from "@/lib/stats";
import { loadAdopters } from "@/lib/adopters";
import { NO_ENFORCE_RECORD, REPO_BLOB_URL, commonStamp, count, currentRecallSentence, figureMeasurements, findBenchmark, measuredStamp, recallLanes, toFullWidth } from "@/lib/recall";
import { locales, type Locale } from "@/lib/i18n";
import { RED_TEAM_TOOLS, type RedTeamTool } from "@/lib/red-team-tools";
import { ablationLanes } from "@/lib/ablation";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
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
    path: "/red-team",
    title: "Red Team: your attack becomes the standard",
    description:
      "ATR is an open detection standard fed by red-team research. A probe becomes a versioned rule with an ID that never changes, and the finder's name can go on its author line.",
  });
}

interface AttributionStat {
  number: string;
  numberZh?: string;
  label: string;
  labelZh: string;
  detail: string;
  detailZh: string;
  /** Site path (without locale) the card links to, if any. */
  href?: string;
  hrefLabel?: string;
  hrefLabelZh?: string;
}

/*
 * Dates checked 2026-11-04:
 * - Microsoft Security Blog "When prompts become shells", 2026-05-07
 *   (microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/).
 * - CVE-2026-26030 record published 2026-02-19T16:00Z (cveawg.mitre.org;
 *   GHSA-xjw9-4gw8-4rqx published the same day).
 * - microsoft/agent-governance-toolkit #1981 opened 2026-05-11T06:07:03Z by copilot-swe-agent.
 * - ATR commit d80373cc (rules ATR-2026-00440/00441) 2026-05-11T08:22:50Z.
 * - `npm view agent-threat-rules time`: 2.1.2 published 2026-05-11T08:24:50Z.
 * - PR authors via `gh pr view`: AGT #2308/#3025, skill-scanner #79/#99,
 *   misp-galaxy #1207, misp-taxonomies #323, OWASP harness #74, sage #33 were
 *   all opened by eeee2345; skill-scanner #80 by vineethsai7.
 * - skill-scanner #289: vineethsai7 comment 2026-11-02.
 */
const ATTRIBUTION_STATS: AttributionStat[] = [
  {
    number: "4 days",
    numberZh: "4 天",
    label: "From Microsoft's write-up to the rule on npm",
    labelZh: "從 Microsoft 發文到規則上 npm",
    detailZh:
      "Microsoft Security 在 2026-05-07 的部落格寫了 Semantic Kernel CVE-2026-26030。這個 CVE 的紀錄 2026-02-19 就公開了，從紀錄算起是 80 天。2026-05-10，ATR 維護者開了 AGT#1937，把這個 CVE 對應到 ATR 規則。AGT 維護者把 issue 指派給 Microsoft 的 Copilot SWE Agent，它在 2026-05-11 06:07 UTC 開了一個 regression-test PR，內容預設 ATR 已經涵蓋這個 CVE。成對的規則在 08:22 UTC 合併進 ATR，距離那個 PR 開出來 2 小時 16 分鐘。v2.1.2 在 08:24 上了 npm。",
    detail:
      "Microsoft Security wrote up Semantic Kernel CVE-2026-26030 on its blog on 2026-05-07. The CVE record itself had been public since 2026-02-19, so counted from the record it took 80 days. On 2026-05-10 the ATR maintainer filed AGT#1937, mapping the CVE to ATR rules. An AGT maintainer assigned that issue to Microsoft's Copilot SWE Agent, and at 06:07 UTC on 2026-05-11 it opened a regression-test PR that assumed ATR already covered the CVE. The paired rules merged into ATR at 08:22 UTC, 2h 16m after that PR opened. v2.1.2 was on npm at 08:24.",
  },
  {
    number: "SHIPPED",
    label: "Integrations recorded as shipped in ADOPTERS.md",
    labelZh: "ADOPTERS.md 記錄為已上線的整合",
    href: "/ecosystem",
    hrefLabel: "Full list and evidence on the ecosystem page",
    hrefLabelZh: "完整名單和每筆證據在生態系頁",
    detailZh:
      "完整名單在生態系頁。以下幾個專案，是 ATR 維護者開 pull request、各專案自己的維護者審過後合併的例子。唯一的例外是 Cisco 的 rule-packs CLI（#80），那是 Cisco 的維護者寫的。Microsoft Agent Governance Toolkit 收進來的是範例目錄。Cisco AI Defense 在 skill-scanner 收了一個規則包。2026-11-02，Cisco 的一位維護者寫道，因為誤報率太高，他們很可能會移除 ATR；一個只告警的規則包（#289）在 2026-11-05 被關閉，沒有合併。CIRCL/MISP 合併了一份 taxonomy 和一份 galaxy。OWASP Agent Security Regression Harness 合併了四個從 ATR 規則衍生的情境，檔案裡沒有寫 ATR 的名字。Gen Digital Sage 合併了 agent 層的威脅 pattern。",
    detail:
      "The full list is on the ecosystem page. The projects below are examples where the ATR maintainer opened a pull request and the project's own maintainers reviewed and merged it. The one exception is Cisco's rule-packs CLI (#80), which a Cisco maintainer wrote. Microsoft Agent Governance Toolkit took them as example directories. Cisco AI Defense took a rule pack in skill-scanner. On 2026-11-02 a Cisco maintainer wrote that they will likely remove ATR because the false-positive rate is too high, and a report-only pack (#289) was closed unmerged on 2026-11-05. CIRCL/MISP merged a taxonomy and a galaxy. The OWASP Agent Security Regression Harness merged four scenarios derived from ATR rules, and the files do not name ATR. Gen Digital Sage merged agent-layer threat patterns.",
  },
  {
    number: "RULECOUNT",
    label: "Rules, each with an author line and a stable ID",
    labelZh: "條規則，每條都有作者欄位和固定編號",
    detailZh:
      "每條規則都有 author 欄位，以及發布後就不再更動的 ATR-YYYY-NNNNN 編號。很多規則也在 metadata_provenance 記下來源，可能是某個語料或某份安全公告。攻擊是你帶來的，作者欄就可以寫你的名字。",
    detail:
      "Every rule has an author field and an ATR-YYYY-NNNNN ID that never changes once published. Many also record the corpus or advisory they came from in metadata_provenance. If you bring the attack, your name can go on the author line.",
  },
  {
    number: "0 FP",
    label: "Required of a rule pull request before it merges",
    labelZh: "規則 pull request 合併前必須做到",
    detailZh:
      "規則安全閘（scripts/check-rules-safety.ts）在每個 pull request 的必過檢查 Validate Rules & Build 裡執行，只檢查這個 pull request 新增或修改的規則。規則自己的 true positive 必須全部命中；在 benign、extended、code、research-mention 四份語料上必須 0 FP，不能跟其他規則衝突，也要涵蓋自己的 true_negatives。閘門每次跑都會印出用了多少樣本，以那個為準，不以本頁的任何數字為準。現在規則的 pull request 要合併，就得過這一關。較早批次的規則並沒有全部通過：用 2026-10-22 的 main（b9d16840）重跑，2026-05-12 sprint 的 71 條有 33 條沒過，2026-06 巨量掃描的 29 條有 4 條沒過，結果和 2026-10-19 相同（data/gate-reruns/2026-10-19_red-team-rule-batches.json）。寧可漏掉一個巧妙的變體，也不放出一條誤報。數字按車道分開公布，不合成單一個好看的數字。",
    detail:
      "The rule safety gate (scripts/check-rules-safety.ts) runs inside the required Validate Rules & Build check on every pull request. It checks the rules that pull request adds or changes. Each rule's own true positives must match. It needs 0 FP on the benign, extended, code and research-mention corpora, 0 conflicts with other rules, and coverage of its own true_negatives. The gate prints the sample counts it used on every run, and those are the figures of record, not any number on this page. Passing it is the merge condition for rule pull requests now. Earlier batches did not all pass. Re-run at main b9d16840 on 2026-10-22, it fails 33 of the 71 rules from the 2026-05-12 sprint and 4 of the 29 from the 2026-06 mega-scan, the same as on 2026-10-19 (data/gate-reruns/2026-10-19_red-team-rule-batches.json). Missing a clever variant is the preferred failure over shipping a false positive. Figures are published per lane, not as one flattering number.",
  },
];

interface ContributorBenefit {
  for: string;
  forZh: string;
  benefit: string;
  benefitZh: string;
  proof: string;
  proofZh: string;
}

const CONTRIBUTOR_BENEFITS: ContributorBenefit[] = [
  {
    for: "Academic researchers",
    forZh: "學術研究者",
    benefitZh: "你描述的攻擊，會變成一份能引用的成果，放在論文旁邊。它有固定編號，也真的有下游在用。論文本身可能鎖在付費牆後面。",
    proofZh: "你的名字可以寫在規則檔的 author 欄，旁邊是發布後就不再更動的規則編號。",
    benefit:
      "The attack you described gets a citable artifact next to your paper. It has a stable ID and real downstream users. A paper alone can sit behind a paywall.",
    proof:
      "Your name can go on the rule file's author line, next to a rule ID that never changes once published.",
  },
  {
    for: "Corporate red teams",
    forZh: "企業紅隊",
    benefitZh: "你的團隊找到的變體，不再只是內部發現，每個防守的人都叫得出它的名字。你的團隊可以掛名成為 ATR 規則庫的作者，這個規則庫有一部分已被 Cisco AI Defense、MISP 和 Gen Digital Sage 的專案合併。",
    proofZh: "ATR 維護者開了一個 issue，把兩個 CVE 對應到 ATR 規則。Microsoft 的 Copilot SWE Agent 被指派到這個 issue，開了一個預設 ATR 已涵蓋的 PR（issue 為 AGT #1937，PR 為 #1981，2026-05-11 合併）。署名一條 ATR-2026-NNNNN 規則，是任何人都查得到的紀錄。",
    benefit:
      "The variant your team found stops being an internal finding. It becomes something every defender can name. Your team can be named as the author in the ATR rule corpus, parts of which projects at Cisco AI Defense, MISP and Gen Digital Sage have merged.",
    proof:
      "An ATR maintainer filed an issue mapping two CVEs to ATR rules. Microsoft's Copilot SWE Agent was assigned it and opened a PR that assumed ATR coverage (issue AGT #1937, PR #1981, merged 2026-05-11). Authoring an ATR-2026-NNNNN rule is a record anyone can check.",
  },
  {
    for: "Independent researchers",
    forZh: "獨立研究者",
    benefitZh: "不用自己寫 regex，也能送出一條偵測。你給攻擊範例和良性範例，維護者照著寫 regex，再讓它跑完整道閘門。",
    proofZh: "你給的良性相似樣本會成為規則的 true negative。合併前，regex 一個都不能命中，在良性語料上也要 0 FP。這道規則安全閘，現在每個規則 pull request 都要過。較早批次的規則並沒有全部通過，重跑紀錄在 data/gate-reruns/2026-10-19_red-team-rule-batches.json。",
    benefit:
      "Ship a detection without writing the regex yourself. Send attack examples and benign ones. A maintainer writes the regex from them and runs it through the full gate.",
    proof:
      "Your benign look-alikes become the rule's true negatives. Before it merges, the regex must match none of them and hold 0 FP on the benign corpora. That is the rule safety gate every rule pull request has to pass now. Rules from earlier batches did not all pass it; the re-run record is in data/gate-reruns/2026-10-19_red-team-rule-batches.json.",
  },
  {
    for: "Bug bounty hunters",
    forZh: "賞金獵人",
    benefitZh: "一個攻擊，兩份收穫：賞金，加上一條之後到處都抓得到它的永久規則。這可以和 Huntr.dev、HackerOne 的 AI 範圍、Protect AI 的賞金計畫並行。",
    proofZh: "ATR 提案採 MIT 授權、可以引用，不會和 NDA 衝突。負責任揭露的期限由賞金計畫決定，ATR 在揭露之後才發布偵測，並公開記下發現者。",
    benefit:
      "One attack, two payoffs: the bounty, and a permanent rule that catches it everywhere after. It fits alongside Huntr.dev, HackerOne's AI scope and Protect AI's bounty program.",
    proof:
      "ATR proposals are MIT-licensed and citable, and there is no NDA conflict. The bounty program owns the responsible-disclosure window. ATR ships the detection only after disclosure, and credits the finder publicly.",
  },
];

/*
 * Traditional Chinese for the entries in data/red-team-tools.json. The JSON
 * holds the English of record (scripts/verify-red-team-links.mjs allows no
 * other fields), so the /zh page reads its wording from here, keyed by name.
 * Keep each one in step with its English entry; an entry missing here falls
 * back to the English.
 */
const TOOL_ZH: Readonly<Record<string, { hook: string; what: string }>> = {
  TextAttack: {
    hook: "QData 實驗室的 NLP 對抗攻擊框架（ACL 2020）。",
    what: "Issue #824 提議做一個 PyPI 配套套件 textattack-detection-atr，以外掛的形式提供，不動 TextAttack 的核心。唯一的請求是在 README 加上互相連結。",
  },
  "Microsoft PyRIT": {
    hook: "Microsoft 內部用來對正式上線的 LLM 產品做紅隊測試的工具組，由 Roman Lutz 主導。",
    what: "新增一個 ATR 資料集載入器，把規則集當成 PyRIT 的攻擊來源；PR #1715 在 2026-05-27 合併。",
  },
  HackAPrompt: {
    hook: "一份 60 萬筆以上提示詞的資料集（公開版本有 601,757 筆），來自一場全球性的提示詞攻擊競賽。參賽者想辦法讓 gpt-3.5-turbo、FlanT5-XXL 或 text-davinci-003 印出指定的句子，或說出隱藏的密鑰。描述這份資料集的論文（Schulhoff 等人，EMNLP 2023）列在 EMNLP 2023 的 Best Paper Awards 名單上。",
    what: "上線 5 條 ATR 規則（ATR-2026-00452..00456），2026-05-12 移入 rules/。每條各針對語料裡看得到的一種攻擊手法：強迫輸出指定句子、要求說出密鑰、逐字元加反斜線編碼、要求輸出不加句號，以及針對空白輸入的條件句。另外還有其他規則在 YAML 裡提到 HackAPrompt。召回率在固定的 4,780 筆子集上量測：在固定的資料集版本上，用固定種子隨機抽 5,000 筆，再扣掉短於 3 個字元的 220 筆。每筆提示詞都當成 LLM 輸入送進評估程式，只要有任何一條規則命中，就算偵測到。有幾條註明 HackAPrompt 的規則正是從這份子集寫出來的，所以下面的目前召回率屬於樣本內；後面附上消融參考值，也就是同一批提示詞、拿掉所有註明 HackAPrompt 的規則後的結果。這份語料 100% 是攻擊，沒有良性樣本，所以算不出精確度或誤報率。",
  },
  "Promptfoo + llm-guard": {
    hook: "promptfoo 紅隊外掛裡的攻擊範例，以及 llm-guard 掃描器測試裡的測試案例，兩者都是 MIT 授權。",
    what: "上線 6 條 ATR 規則（ATR-2026-00500..00505），2026-05-12 移入 rules/。其中四條從 promptfoo 的外掛範例歸納而來（SSRF、資料外洩、發散式重複、工具探查），兩條來自 llm-guard 的測試案例（假造錯誤狀態來接管，以及套取系統提示詞；後者也參考了 promptfoo）。範例裡寫死的主機名稱、網址、字詞和工具名稱，都改寫成 pattern。每條規則的描述都寫明出自哪份語料。這些規則出自 2026-05-12 的那次匯入，共 94 筆樣本（llm-guard 44 筆、promptfoo 44 筆、NeMo Guardrails 6 筆）。和廠商的 repository 逐筆比對：79 筆與其標示的廠商檔案逐字相同，3 筆是從該檔案截短或改寫，2 筆出自另一家廠商的測試套件，10 筆在釘選 commit 的廠商 repository 裡找不到逐字相同的內容。現在這些規則改在 126 筆攻擊案例和 20 筆良性案例上量測；案例由程式從 llm-guard、promptfoo 和 NVIDIA NeMo Guardrails（Apache-2.0；只用來量測，沒有任何規則是從它寫出來的）的固定 commit 擷取並去重，任何一條規則命中就算偵測到。三套中有兩套正是這些規則的來源，所以下面的目前召回率有一部分屬於樣本內；後面附上消融參考值，也就是同一批案例、拿掉所有註明這三家廠商之一或帶有 vendor-corpus-import 標籤的規則後的結果。即使這樣也不算樣本外：剩下的規則有些在 YAML 裡帶有廠商的文字，另有五筆 NeMo Guardrails 案例和 garak 語料共用同一個越獄範本，而其他規則正是從 garak 語料挖出來的（兩者的影響量測檔裡都有算）。20 筆良性案例太少，談不上精確度，只列出被標記的筆數。從 agent-threat-rules#709 起，ATR-2026-00500 和 -00501 命中它們所引用類別裡的全部 3 筆廠商案例，ATR-2026-00505 命中它的 true positive 所依據的全部 6 筆廠商案例（hunt）；在那之前，00500 和 00501 分別只命中 1 筆和 0 筆。",
  },
  "OWASP LLM Top 10 + MITRE ATLAS": {
    hook: "OWASP 整理的 LLM 應用程式十大風險，以及 MITRE ATLAS：針對 AI 系統的對抗技術與案例研究目錄。",
    what: "2026-05-12 上線 8 條 ATR 規則（ATR-2026-00510..00517）。每條規則的 references 都標明一個 OWASP LLM Top 10（2025）類別（LLM01、LLM02、LLM06 或 LLM10）和一個 MITRE ATLAS 技術；8 條中有 6 條在描述裡引用了所依據的 ATLAS 案例研究（AML.CS0022、CS0036、CS0038、CS0039 與 CS0045、CS0041、CS0056）。",
  },
  Promptfoo: {
    hook: "開源的 LLM 紅隊與評估工具，會產生對抗測試，拿去跑 LLM 應用程式。",
    what: "PR #8529 新增一個 MCP 紅隊範例，用 ATR 當確定性的防禦層：Promptfoo 負責跑探測，ATR 規則給出判定。",
  },
};

/* zh labels for the measurement figures named in the JSON. */
const FIGURE_LABEL_ZH: Readonly<Record<string, string>> = {
  hackaprompt: "HackAPrompt",
  "vendor-guardrail-suites": "固定版本的廠商測試套件",
};

/* What the ablation removed, in Chinese (mirrors ABLATION_REMOVED in lib/recall.ts). */
function ablationRemovedZh(source: string, n: string): string {
  if (source === "vendor-guardrail-suites") {
    return `註明 llm-guard、promptfoo 或 NeMo Guardrails，或帶有 vendor-corpus-import 標籤的 ${n} 條規則`;
  }
  return ` YAML 註明這份語料的 ${n} 條規則`;
}

/*
 * The Chinese counterpart of currentRecallSentence (lib/recall.ts), built from
 * the same measurement files, so the figures cannot drift from the English.
 */
function currentRecallSentenceZh(
  stats: Pick<SiteStats, "benchmarks">,
  figures: readonly { source: string; label: string }[],
): string {
  const found = figureMeasurements(stats, figures);
  if (found.length === 0) return "";
  const parts = found.map(({ m, label }) => {
    const name = FIGURE_LABEL_ZH[m.source] ?? label;
    const size = m.attacks === null ? `${count(m.samples)} 筆樣本` : `${count(m.attacks)} 筆攻擊樣本`;
    const benign = m.benign && m.falsePositives !== null
      ? `，hunt 車道在 ${count(m.benign)} 筆良性樣本中標記 ${count(m.falsePositives)} 筆`
      : "";
    const lanes = ablationLanes(m);
    const ablation = m.ablation && lanes
      ? `；拿掉${ablationRemovedZh(m.source, count(m.ablation.rulesRemoved))}後是 ${lanes}（這是消融參考值，接近樣本外成績，但不保證是）`
      : "";
    return `${name}（${size}）：${recallLanes(m)}${benign}${ablation}`;
  });
  const missing = found.some(({ m }) => m.enforce === null) ? `；${toFullWidth(NO_ENFORCE_RECORD.zh)}` : "";
  return (
    "目前的召回率，hunt 車道（載入所有成熟度）／enforce 車道（只載入 stable，用於封鎖）：" +
    `${parts.join("；")}（${commonStamp(found.map((f) => f.m), true, true)}）${missing}。`
  );
}

/* Shared type scale: inner page, 48px title, serif section titles, sans body. */
const KICKER = "text-[13px] text-stone mb-4";
const H2 = "text-[30px] md:text-[36px] leading-[1.2] tracking-[-0.01em] text-ink mb-5 max-w-[760px]";
const INTRO = "text-[16px] text-graphite leading-[1.75] max-w-[720px] mb-4";
const BODY = "text-[15px] text-graphite leading-[1.75]";
const NOTE = "text-[15px] text-graphite leading-[1.75] max-w-[720px] mb-4";
const LINK = "text-[15px] text-blue underline underline-offset-[5px] decoration-1 hover:text-blue-hover";
const SMALL_LINK = "text-[14px] text-blue underline underline-offset-[4px] decoration-1 hover:text-blue-hover";
const SECTION = "px-6 md:px-14 mb-20 md:mb-28";
const nowrap = (text: string) => <span className="whitespace-nowrap">{text}</span>;

/* "HackAPrompt 量測檔" but "廠商測試套件量測檔": a space only after a Latin word. */
const withZhSuffix = (label: string, suffix: string) => (/[A-Za-z0-9]$/.test(label) ? `${label} ${suffix}` : `${label}${suffix}`);

function Diple() {
  return <Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />;
}

export default async function RedTeamPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const stats = loadSiteStats();
  const adopters = loadAdopters();
  // Same count as /ecosystem: every ADOPTERS.md entry with status "shipped".
  const shippedCount = [
    ...adopters.tierS, ...adopters.tier1, ...adopters.tier2, ...adopters.tier3, ...adopters.tier4,
  ].filter((a) => a.status === "shipped").length;
  const garak = findBenchmark(stats, "garak");
  const vendorSuites = findBenchmark(stats, "vendor-guardrail-suites");
  const vendorAblation = vendorSuites ? ablationLanes(vendorSuites) : null;

  const inProduction = RED_TEAM_TOOLS.filter(
    (t) => t.status === "in-production" || t.status === "corpus",
  );
  const inReview = RED_TEAM_TOOLS.filter((t) => t.status === "in-review");

  const hookOf = (t: RedTeamTool) => (zh ? TOOL_ZH[t.name]?.hook ?? t.hook : t.hook);
  const whatOf = (t: RedTeamTool) => (zh ? TOOL_ZH[t.name]?.what ?? t.what_atr_did : t.what_atr_did);
  const recallOf = (t: RedTeamTool) =>
    zh ? currentRecallSentenceZh(stats, t.figures ?? []) : currentRecallSentence(stats, t.figures ?? []);

  const statusLabel = (t: RedTeamTool) => {
    if (t.status === "corpus") return zh ? "語料已匯入" : "Corpus ingested";
    if (t.status === "in-production") return zh ? "已合併進上游" : "Merged upstream";
    return zh ? "提案還開著" : "Proposal open";
  };

  const toolRow = (t: RedTeamTool) => (
    <div key={t.name} className="grid grid-cols-1 md:grid-cols-[260px_minmax(0,1fr)] gap-x-8 gap-y-3 py-6 border-b border-fog">
      <div>
        <h3 className="text-[17px] text-ink font-normal mb-1">{t.name}</h3>
        <div className="text-[13px] text-stone">{t.org}</div>
        <div className="text-[13px] text-stone mt-1">{statusLabel(t)}</div>
      </div>
      <div className="max-w-[720px]">
        <p className={`${BODY} mb-3`}>{hookOf(t)}</p>
        <p className="text-[15px] text-ink leading-[1.75] mb-3">{whatOf(t)}</p>
        {recallOf(t) && <p className={`${BODY} mb-3`}>{recallOf(t).trim()}</p>}
        <div className="flex flex-wrap gap-x-6 gap-y-2">
          <a href={t.homepage} target="_blank" rel="noopener noreferrer" className={SMALL_LINK}>
            {zh ? "工具" : "Tool"}<Diple />
          </a>
          {t.prUrl && (
            <a href={t.prUrl} target="_blank" rel="noopener noreferrer" className={SMALL_LINK}>
              {t.prUrl.includes("/commit/") ? "Commit" : t.prUrl.includes("/issues/") ? "Issue" : "PR"}<Diple />
            </a>
          )}
          {figureMeasurements(stats, t.figures ?? []).map(({ m, label }) => (
            <a
              key={m.measurement_file}
              href={`${REPO_BLOB_URL}${m.measurement_file}`}
              target="_blank"
              rel="noopener noreferrer"
              className={SMALL_LINK}
            >
              {zh ? withZhSuffix(FIGURE_LABEL_ZH[m.source] ?? label, "量測檔") : `${label} measurement`}<Diple />
            </a>
          ))}
        </div>
      </div>
    </div>
  );

  const sprintCorpora = [
    { corpus: "HackAPrompt", samples: zh ? "4,780（601,757 筆中以固定種子抽出的子集）" : "4,780 (seeded subset of 601,757)", rules: "5", ruleIds: "ATR-2026-00452..00456", recall: zh ? "28.6% 至 66.0%（hunt，載入全部規則，樣本內；於 3a6145b7 與 92c0d0fe 重跑）" : "28.6% to 66.0% (hunt, every rule loaded, in-sample; re-run at 3a6145b7 and 92c0d0fe)" },
    { corpus: "promptfoo + llm-guard", samples: zh ? "94（2026-05-12 匯入，含 6 筆 NeMo Guardrails；其中 79 筆與其標示的廠商檔案逐字相同）" : "94 (2026-05-12 import, 6 of them NeMo Guardrails; 79 occur verbatim in the vendor file they name)", rules: "6", ruleIds: "ATR-2026-00500..00505", recall: vendorSuites ? (zh ? `${recallLanes(vendorSuites)}（${count(vendorSuites.attacks ?? vendorSuites.samples)} 筆固定版本的廠商攻擊案例，部分屬樣本內${vendorAblation ? `；消融參考值 ${vendorAblation}` : ""}；${measuredStamp(vendorSuites, true, true)}）` : `${recallLanes(vendorSuites)} (${count(vendorSuites.attacks ?? vendorSuites.samples)} pinned vendor attack cases, partly in-sample${vendorAblation ? `; ablation reference ${vendorAblation}` : ""}; ${measuredStamp(vendorSuites, false)})`) : "" },
    { corpus: "PromptInject", samples: zh ? "整個語料庫" : "full corpus", rules: "4", ruleIds: "ATR-2026-00506..00509", recall: "" },
    { corpus: "OWASP LLM Top 10 + ATLAS PoCs", samples: zh ? "8 個標準分類" : "8 standard categories", rules: "8", ruleIds: "ATR-2026-00510..00517", recall: "" },
    { corpus: "Garak in-the-wild jailbreak", samples: "650", rules: zh ? "已有覆蓋" : "existing coverage", ruleIds: "", recall: garak ? (zh ? `${recallLanes(garak)}（${measuredStamp(garak, true, true)}；部分屬於開卷考，規則看過這份語料）` : `${recallLanes(garak)} (${measuredStamp(garak, false)}; partly closed-book)`) : "" },
  ];

  const megaCorpora = [
    { corpus: "LLMail-Inject", ruleIds: "ATR-2026-01860..01865", note: "" },
    { corpus: "InjecAgent", ruleIds: "ATR-2026-00550 / 00584 / 00700 / 00859 / 01000", note: "" },
    { corpus: "AgentDojo", ruleIds: "ATR-2026-00715 / 00720 / 01751..01754", note: "" },
    { corpus: "ToolEmu", ruleIds: "ATR-2026-00702 / 00718 / 00719 / 01301", note: "" },
    { corpus: "MCPSecBench", ruleIds: "ATR-2026-01300 / 01306 / 01307 / 01310 / 01615 / 01616", note: "" },
    { corpus: "AgentPoison", ruleIds: "ATR-2026-01774 / 01800", note: "" },
    { corpus: "TensorTrust", ruleIds: "", note: zh ? "現有規則已涵蓋，沒有新的漏抓" : "Already covered, no new misses" },
    { corpus: "PoisonedRAG", ruleIds: "", note: zh ? "現有規則已涵蓋，沒有新的漏抓" : "Already covered, no new misses" },
  ];

  const notImported = [
    {
      name: "PyRIT Pliny L1B3RT4S",
      org: "Microsoft AI Red Team / Pliny",
      decision: zh ? "拒絕導入" : "Refused",
      reason: zh
        ? "Anthropic 的使用政策，不允許負責匯入的 subagent 讀這份資料集。來源查證不了的材料，ATR 不收。"
        : "Anthropic's usage policy kept the subagents doing the import from reading this dataset. ATR does not import material whose provenance it cannot verify.",
    },
    {
      name: "AdvBench",
      org: "Zou et al., GCG paper",
      decision: zh ? "重新分類" : "Reclassified",
      reason: zh
        ? "改放進測試語料庫（data/test-corpora/），不當規則來源。AdvBench 寫的是攻擊者想讓模型做的行為，不是包裝好的攻擊 payload。它拿來量攻擊成功率，本身沒有可以直接偵測的模式。"
        : "Moved to the test corpora (data/test-corpora/) instead of being used as a rule source. AdvBench describes the behaviors an attacker is after, not wrapped attack payloads. It measures attack success rates and doesn't directly give you a pattern to detect.",
    },
    {
      name: "HarmBench",
      org: "Center for AI Safety · Dan Hendrycks",
      decision: zh ? "重新分類" : "Reclassified",
      reason: zh
        ? "改放進測試語料庫。HarmBench 的 320 個行為，寫的是想要的輸出，不是攻擊的句法。拿來量 ATR 的覆蓋率，不拿來寫規則。"
        : "Moved to the test corpora. HarmBench's 320 behaviors describe target outputs, not attack syntax. It is used to measure ATR's coverage, not to write rules.",
    },
    {
      name: "JailbreakBench",
      org: "Princeton · Patrick Chao",
      decision: zh ? "重新分類" : "Reclassified",
      reason: zh
        ? "改放進測試語料庫。JBB-Behaviors 是 jailbreak 排行榜的標準輸入，寫的是請求的內容，不是攻擊的模式。拿來跑 benchmark，不拿來寫規則。"
        : "Moved to the test corpora. JBB-Behaviors is the standard input for a jailbreak leaderboard. It describes what is being asked for, not attack patterns. It is used for benchmarking, not for writing rules.",
    },
    {
      name: zh ? "語料庫指紋規則（維持原樣）" : "Corpus-fingerprint rules (kept as-is)",
      org: zh ? "例如 ATR-2026-02016" : "e.g. ATR-2026-02016",
      decision: zh ? "保留，不泛化" : "Kept, not generalized",
      reason: zh
        ? "少數規則鎖定某份語料裡非常字面的字串，例如 ATR-2026-02016 比對 HackAPrompt 裡倒著拼的 canary 字。它們是那份語料的指紋，不是能推廣的攻擊模式，規則描述裡也寫明了。硬要放寬，誤報率會高到不能接受，所以維持字面比對。描述裡這樣標明的規則都停在 test，封鎖車道只載入 stable，所以它們只告警、不封鎖。"
        : "A few rules anchor on very literal strings from one corpus, such as the reversed canary word from HackAPrompt in ATR-2026-02016. They fingerprint that corpus rather than an attack pattern that generalizes, and their descriptions say so. Loosening them would push the FP rate past what is acceptable, so they stay literal. The rules whose descriptions say this are all at test maturity; the blocking lane loads only stable, so they alert and never block.",
    },
  ];

  return (
    <Phrased>
    <div className="pt-20 pb-24">
      {/* ============================================================
          HERO
      ============================================================ */}
      <section className="px-6 md:px-14 mb-20 md:mb-28">
        <Reveal>
          <div className={KICKER}>{zh ? "給紅隊" : "For red teams"}</div>
        </Reveal>
        <Reveal delay={0.1}>
          <h1 className="text-[32px] md:text-[48px] leading-[1.15] tracking-[-0.01em] text-ink mb-6 max-w-[820px]">
            {zh ? (
              <>
                你找到攻擊。
                <br />
                它變成一條規則。
                <br />
                四天後上了 npm。
              </>
            ) : (
              <>
                You find the attack.
                <br />
                It becomes a rule.
                <br />
                Four days later it was on npm.
              </>
            )}
          </h1>
        </Reveal>
        <Reveal delay={0.2}>
          <p className="text-[17px] text-graphite leading-[1.75] mb-8 max-w-[720px]">
            {zh ? (
              <>
                以 Semantic Kernel CVE-2026-26030 為例：Microsoft 在 {nowrap("2026-05-07")} 發文說明，對應的 ATR 規則在 {nowrap("2026-05-11")} 隨 v2.1.2 上了 npm。這個 CVE 的紀錄其實 2 月就公開了。把攻擊寫下來一次，所有防守的人就能用同一個名字稱呼它。
              </>
            ) : (
              <>
                Take Semantic Kernel CVE-2026-26030. Microsoft wrote it up on {nowrap("2026-05-07")}, and the matching ATR
                rules reached npm in v2.1.2 on {nowrap("2026-05-11")}. The CVE record itself had been public since
                February. Write an attack down once and every defender can call it by the same name.
              </>
            )}
          </p>
        </Reveal>
        <Reveal delay={0.3}>
          <div className="flex flex-wrap gap-x-8 gap-y-3">
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=red-team-probe.yml"
              target="_blank"
              rel="noopener noreferrer"
              className={LINK}
            >
              {zh ? "送一個 probe" : "Submit a probe"}<Diple />
            </a>
            <a href="#how-it-works" className={LINK}>
              {zh ? "流程怎麼走" : "How it works"}<Diple />
            </a>
          </div>
        </Reveal>
      </section>

      {/* ============================================================
          THE NUMBERS
      ============================================================ */}
      <section className={SECTION}>
        <Reveal>
          <div className={KICKER}>{zh ? "攻擊為什麼該寫進標準" : "Why an attack belongs in the standard"}</div>
        </Reveal>
        <dl className="border-t border-ink">
          {ATTRIBUTION_STATS.map((s, i) => (
            <div key={i} className="grid md:grid-cols-[200px_minmax(0,1fr)] gap-x-8 gap-y-2 py-6 border-b border-fog">
              <dt className="font-title text-[26px] md:text-[30px] leading-none text-ink tabular-nums whitespace-nowrap">
                {s.number === "RULECOUNT" ? stats.ruleCount : s.number === "SHIPPED" ? shippedCount : zh && s.numberZh ? s.numberZh : s.number}
              </dt>
              <dd className="max-w-[720px]">
                <div className="text-[16px] text-ink mb-2">{zh ? s.labelZh : s.label}</div>
                <p className={BODY}>{zh ? s.detailZh : s.detail}</p>
                {s.href ? (
                  <a href={`/${locale}${s.href}`} className={`${SMALL_LINK} inline-block mt-2`}>
                    {zh ? s.hrefLabelZh : s.hrefLabel}<Diple />
                  </a>
                ) : null}
              </dd>
            </div>
          ))}
        </dl>
      </section>

      {/* ============================================================
          WHAT YOU GET — segmented by who you are
      ============================================================ */}
      <section className={SECTION}>
        <Reveal>
          <div className={KICKER}>{zh ? "你能拿到什麼" : "What you get"}</div>
          <h2 className={H2}>
            {zh
              ? "攻擊進了標準之後，你手上會留下什麼，要看你是誰。"
              : "What your attack leaves you once it's in the standard depends on who you are."}
          </h2>
        </Reveal>
        <div className="border-t border-ink mt-8">
          {CONTRIBUTOR_BENEFITS.map((b, i) => (
            <Reveal key={i} delay={0.05 + i * 0.05}>
              <div className="grid grid-cols-1 md:grid-cols-[260px_minmax(0,1fr)] gap-x-8 gap-y-2 py-6 border-b border-fog">
                <h3 className="text-[17px] text-ink font-normal">{zh ? b.forZh : b.for}</h3>
                <div className="max-w-[720px]">
                  <p className="text-[16px] text-ink leading-[1.75] mb-2">{zh ? b.benefitZh : b.benefit}</p>
                  <p className={BODY}>{zh ? b.proofZh : b.proof}</p>
                </div>
              </div>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ============================================================
          HOW IT WORKS — a maintainer converts the probe
      ============================================================ */}
      <section id="how-it-works" className={`${SECTION} pt-12 md:pt-16 border-t border-ink`}>
        <Reveal>
          <div className={KICKER}>{zh ? "送出 probe 之後" : "What happens after you submit"}</div>
          <h2 className={H2}>
            {zh
              ? "你送樣本。維護者寫 regex。閘門全過，才合併。"
              : "You send samples. A maintainer writes the regex. It merges only if the gate passes."}
          </h2>
        </Reveal>

        <ol className="border-t border-fog mt-8">
          {[
            {
              n: "01",
              title: zh ? "你填一張表" : "You fill in a form",
              lead: zh
                ? "3 個攻擊樣本，3 個長得很像但無害的樣本，攻擊類別，再加上出處的論文或 repo。大約 3 到 5 分鐘。"
                : "3 attack samples, 3 benign look-alikes, the attack category, and the paper or repo it came from. It takes 3 to 5 minutes.",
              note: zh ? "不用學 schema，不用寫 YAML，也不用 fork。" : "You don't learn the schema or write YAML, and you don't fork anything.",
            },
            {
              n: "02",
              title: zh ? "維護者照你的樣本寫 regex" : "A maintainer writes the regex from your samples",
              lead: zh
                ? "維護者看過你的 issue，照你給的攻擊樣本寫偵測用的 regex。你給的無害樣本，就成了這條規則的 true negative。想自己寫 regex 也可以，貼在 PR 留言裡，或自己開一個 PR。"
                : "A maintainer reads your issue and writes a detection regex from your attack samples. Your benign look-alikes become the true negatives. You can also propose a regex yourself, in a PR comment or a PR of your own.",
              note: zh
                ? "PR 要合併，得先過閘門：你自己的 true positive 要 100% 命中，在 benign、extended、code、research-mention 四份語料上都是 0 FP，也不能跟其他規則衝突。用了多少樣本，以閘門跑的時候印出來的為準。較早批次的規則並沒有全部通過，重跑紀錄在 data/gate-reruns/2026-10-19_red-team-rule-batches.json。"
                : "To merge, your pull request has to pass the gate. Every one of your true positives must match. It needs 0 FP on the benign, extended, code and research-mention corpora, and 0 conflicts with other rules. The gate prints the sample counts it used. Rules from earlier batches did not all pass it; the re-run record is data/gate-reruns/2026-10-19_red-team-rule-batches.json.",
            },
            {
              n: "03",
              title: zh ? "閘門過了，整條規則送 PR" : "The gate passes, and the full rule goes up as a PR",
              lead: zh
                ? "不管 regex 是誰寫的，都要看它的形狀：會不會太死，能不能再放寬一點抓到變體。閘門沒過，就先留在提案階段，繼續收緊 regex，判對錯的依據還是你的測試案例。"
                : "Whoever wrote the regex, someone checks its shape. Is it too literal? Could it generalize? If the gate fails, it stays a proposal while the regex is tightened, and your test cases are still the ground truth.",
              note: "",
            },
            {
              n: "04",
              title: zh ? "下游的副本要靠 PR 更新" : "Downstream copies are refreshed by pull request",
              lead: zh
                ? "合併進別的專案的 ATR 規則不會自己更新。要由 ATR 維護者再開 PR：例如 MISP galaxy 在 2026-07-14 的 #1236，Cisco 規則包在 2026-08-03 的 #142。直接用 npm 套件的人，裝新版就拿得到新規則。"
                : "ATR rules merged into other projects do not update themselves. The ATR maintainer refreshes them by pull request: for example the MISP galaxy in #1236 on 2026-07-14 and the Cisco pack in #142 on 2026-08-03. If you use the npm package, a new release brings the new rules.",
              note: zh
                ? "Microsoft Copilot 的 regression PR，從開出來到對應的規則合併進 ATR，花了 2 小時 16 分鐘（2026-05-11 06:07 至 08:22 UTC）。兩分鐘後，v2.1.2 上了 npm。這段只算 PR 到合併；從 Microsoft 5/7 發文算起是四天。"
                : "Microsoft Copilot's regression PR went from opened to the matching rules merged into ATR in 2h 16m (2026-05-11, 06:07 to 08:22 UTC). Two minutes later, v2.1.2 was on npm. That counts from the PR only. From Microsoft's write-up on 2026-05-07, it was four days.",
            },
          ].map((step, i) => (
            <Reveal key={step.n} delay={0.1 + i * 0.05}>
              <li className="grid grid-cols-[40px_minmax(0,1fr)] md:grid-cols-[64px_minmax(0,1fr)] gap-x-6 py-6 border-b border-fog">
                <span className="font-data text-[14px] text-stone pt-1">{step.n}</span>
                <div className="max-w-[720px]">
                  <h3 className="font-title text-[22px] text-ink mb-2">{step.title}</h3>
                  <p className="text-[16px] text-graphite leading-[1.75] mb-2">{step.lead}</p>
                  {step.note && <p className={BODY}>{step.note}</p>}
                </div>
              </li>
            </Reveal>
          ))}
        </ol>
      </section>

      {/* ============================================================
          OFFENSIVE TOOLS AND CORPORA
      ============================================================ */}
      <section className={SECTION}>
        <Reveal>
          <div className={KICKER}>{zh ? "攻擊方的工具和語料" : "Offensive tools and corpora"}</div>
          <h2 className={H2}>
            {zh
              ? "這些攻擊工具和語料，已經在替標準添規則。下一個可以是你的工具。"
              : "These offensive tools and corpora already feed the standard. Yours could be next."}
          </h2>
          <p className={`${INTRO} mb-10`}>
            {zh
              ? "這裡只列紅隊工具，也就是攻擊測試框架和對抗語料。防守端的框架在 /ecosystem。"
              : "Only red-team tools are listed here: offensive testing frameworks and adversarial corpora. Defensive frameworks are on /ecosystem."}
          </p>
        </Reveal>

        <Reveal>
          <div className={KICKER}>
            {zh
              ? `已合併進上游，或語料已匯入（${inProduction.length}）`
              : `Merged upstream or corpus ingested (${inProduction.length})`}
          </div>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="border-t border-ink mb-12">{inProduction.map(toolRow)}</div>
        </Reveal>

        <Reveal>
          <div className={KICKER}>
            {zh ? `還開著的提案（${inReview.length}）` : `Open proposals (${inReview.length})`}
          </div>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="border-t border-ink">{inReview.map(toolRow)}</div>
        </Reveal>
      </section>

      {/* ============================================================
          CONTINUOUS CORPUS INTEGRATION
      ============================================================ */}
      <section className={SECTION}>
        <Reveal>
          <div className={KICKER}>{zh ? "持續匯入語料" : "Continuous corpus integration"}</div>
          <h2 className={H2}>{zh ? "5 個語料庫，71 條新規則。" : "Five corpora, 71 new rules."}</h2>
          <p className="text-[16px] text-ink leading-[1.75] max-w-[720px] mb-4">
            {zh
              ? "HackAPrompt 召回率從 28.6% 升到 66.0%。這是樣本內的數字：2026-05-12 那次 sprint，載入全部規則，量測用的就是挖出這些規則的同一份 4,780 筆子集。"
              : "HackAPrompt recall went from 28.6% to 66.0%. That is in-sample: from the 2026-05-12 sprint, with every rule loaded, measured on the same 4,780-prompt subset the rules were mined from."}
          </p>
          <p className={NOTE}>
            {zh
              ? "2026-05-12，11 個 agent 平行跑，匯入了五個外部語料庫。這次 sprint 的兩個 commit（e9efefdd、92c0d0fe）新增 71 個規則檔，編號 ATR-2026-00452..00522。v2.2.0 changelog 寫的是 75 條，因為它還算進了同一天稍早、在 commit 80dbd0ab 加入的 4 條 CVE 規則（00448..00451），那個 commit 在 sprint 的兩個 commit 之前。完整的版本紀錄在 /changelog。"
              : "On 2026-05-12, 11 agents running in parallel ingested five external corpora. The sprint's two commits (e9efefdd, 92c0d0fe) added 71 rule files, ATR-2026-00452..00522. The v2.2.0 changelog says 75 because it also counts four CVE rules, 00448..00451, added earlier that day in commit 80dbd0ab, before the sprint commits. The full version record is at /changelog."}
          </p>
          <p className={NOTE}>
            {zh
              ? "上面兩個 HackAPrompt 數字都是重跑的。用的是固定的 4,780 筆子集，資料集版本釘死，用固定的亂數種子抽樣。一次跑在 sprint 前一個 commit（3a6145b7，偵測到 1,368 筆），一次跑在 sprint 的發布 commit（92c0d0fe，偵測到 3,154 筆），兩次都載入全部規則，也就是今天 hunt 車道載入的範圍。28.6% 本身也是樣本內：從同一份子集挖出來的 ATR-2026-00442..00447，那時已經載入了。"
              : "Both HackAPrompt figures are re-runs on a fixed 4,780-prompt subset, a seeded sample at a pinned dataset revision. One ran at the commit before the sprint (3a6145b7, 1,368 detected), the other at the sprint's release commit (92c0d0fe, 3,154 detected). Both loaded every rule, which is what the hunt lane loads today. The 28.6% is itself in-sample: ATR-2026-00442..00447, mined from the same subset, were already loaded."}
          </p>
          <p className={NOTE}>
            {zh
              ? "當時公布的 66.2%，在 sprint 的兩個 commit（e9efefdd、92c0d0fe）上都重現不出來，最高只到 66.0%，所以撤回。現在的 hunt 和 enforce 數字，以及消融參考值，在上方的 HackAPrompt 條目。重跑步驟寫在 data/hackaprompt/METHOD.md。"
              : "The 66.2% published at the time could not be reproduced at the sprint commits e9efefdd and 92c0d0fe (66.0% at best), so it is withdrawn. Current hunt and enforce figures, and the ablation reference, are in the HackAPrompt entry above. The re-run procedure is in data/hackaprompt/METHOD.md."}
          </p>
          <p className={`${NOTE} mb-10`}>
            {zh
              ? `現在的規則來自 CVE 和安全公告的掃描、benchmark 漏抓樣本的挖掘，還有貢獻者。每一條都要透過維護者合併的 pull request 才進得了 main。從六月到現在，標準從 462 條長到 ${stats.ruleCount} 條，以 agent-threat-rules 發布在 npm 上。`
              : `Rules now come from CVE and advisory sweeps, mining benchmark misses, and contributors. Each one reaches main through a pull request a maintainer merges. Since June the standard has grown from 462 to ${stats.ruleCount} rules, published on npm as agent-threat-rules.`}
          </p>
        </Reveal>
        <Reveal delay={0.1}>
          <dl className="border-t border-ink mb-10">
            {sprintCorpora.map((row) => (
              <div key={row.corpus} className="grid grid-cols-1 md:grid-cols-[260px_minmax(0,1fr)] gap-x-8 gap-y-1.5 py-5 border-b border-fog">
                <dt className="text-[16px] text-ink">{row.corpus}</dt>
                <dd className="max-w-[720px] text-[15px] text-graphite leading-[1.7] space-y-1">
                  <div>
                    <span className="text-stone">{zh ? "樣本：" : "Samples: "}</span>
                    {row.samples}
                  </div>
                  <div>
                    <span className="text-stone">{zh ? "新規則：" : "Rules: "}</span>
                    {row.rules}
                    {row.ruleIds && <span className="font-data text-[13px] text-ink ml-3 break-words">{row.ruleIds}</span>}
                  </div>
                  {row.recall && (
                    <div>
                      <span className="text-stone">{zh ? "召回率：" : "Recall: "}</span>
                      {row.recall}
                    </div>
                  )}
                </dd>
              </div>
            ))}
          </dl>
        </Reveal>
        <Reveal delay={0.2}>
          <h3 className="font-title text-[22px] text-ink mb-3">{zh ? "這 71 條規則的閘門紀錄" : "The gate record for these 71 rules"}</h3>
          {(zh
            ? [
                "這 71 條規則當時跑品質閘的紀錄，沒有 commit 進 repo。所以「全部通過、在良性語料上 0 FP」這句話撤回，改成實際重測：用 repo 裡的規則安全閘 scripts/check-rules-safety.ts，2026-10-19 跑了一次，2026-10-22 又跑一次。",
                "用 92c0d0fe 當時的閘和語料：71 條在 432 份良性 SKILL.md 上都沒有誤報。10 條沒過，原因都是有自己的 true positive 沒命中。這 10 條裡，1 條另外在 1,352 筆 extended 良性樣本中誤報 1 筆，1 條在 157 筆 research-mention 樣本中誤報 1 筆，2 條跟其他規則的 true negative 衝突。",
                "用 2026-10-22 的 main（b9d16840，ATR 4.1.5）：33 條沒過，其中 26 條至少誤報 1 筆良性樣本。分開看，467 份 SKILL.md 上有 4 條，13,620 筆 extended 上有 26 條，69 筆程式碼上有 1 條，157 筆 research-mention 上有 2 條。這 26 條沒有一條的 maturity 是 stable，所以都不會載入 enforce 車道。24 條在 alert 和 hunt 車道，2 條只在 hunt 車道。2026-10-19 在 9d74fc50 跑出來的結果一模一樣，雖然這段期間 main 上改過紀錄裡的 9 條規則。",
                "誤報最多的是 ATR-2026-00454（maturity test，在 alert 和 hunt 車道），467 份 SKILL.md 中誤報 152 份，13,620 筆 extended 中誤報 1,376 筆。其他每一條，在任何一份語料上都不超過 23 筆。上方 HackAPrompt 的 hunt 和 alert 數字，00454 也算在分子裡：2026-10-19 的 HackAPrompt 量測中，它在 hunt 車道命中 4,780 筆裡的 757 筆。紀錄在 data/gate-reruns/2026-10-19_red-team-rule-batches.json。",
                "另外，有 53 條規則的 regex，已經從字面比對改寫成多層的結構 pattern。",
              ]
            : [
                "No record of the quality gate's run on these 71 rules was committed. The claim that all of them passed with 0 FP on the benign corpus is withdrawn. In its place are two re-runs of the repository's rule safety gate, scripts/check-rules-safety.ts, on 2026-10-19 and 2026-10-22.",
                "With the gate and corpora as of 92c0d0fe, none of the 71 flags any of the 432 benign SKILL.md files. 10 fail, all for missing one of their own true positives. Of those 10, 1 also flags 1 of 1,352 extended benign samples, 1 flags 1 of 157 research-mention samples, and 2 conflict with another rule's true negatives.",
                "At main b9d16840 on 2026-10-22 (ATR 4.1.5): 33 fail; 26 flag at least one benign sample (4 on the 467 SKILL.md files, 26 on 13,620 extended samples, 1 on 69 code samples, 2 on 157 research-mention samples). None of those 26 has maturity stable, so none loads in the enforce lane. 24 load in the alert and hunt lanes, 2 in the hunt lane only. The 2026-10-19 run at 9d74fc50 gave the same results, even though nine of the recorded rules changed on main in between.",
                "The worst by far is ATR-2026-00454 (maturity test, alert and hunt lanes): 152 of the 467 SKILL.md files and 1,376 of the 13,620 extended samples; every other rule flags at most 23 samples on any corpus. 00454 also counts toward the HackAPrompt hunt and alert figures above: in the 2026-10-19 HackAPrompt measurement it matches 757 of the 4,780 prompts in the hunt lane. Record: data/gate-reruns/2026-10-19_red-team-rule-batches.json.",
                "Separately, 53 rules had their regex generalized from literal fingerprints to multi-layer structural patterns.",
              ]
          ).map((para) => (
            <p key={para} className={NOTE}>{para}</p>
          ))}
        </Reveal>

        <Reveal delay={0.3}>
          <div className={`${KICKER} mt-16`}>{zh ? "2026-06 巨量掃描" : "2026-06 mega-scan"}</div>
          <h2 className={H2}>
            {zh
              ? "8 個語料庫，29 條偵測規則，2 個沒有新的漏抓"
              : "8 corpora, 29 detection rules, 2 with no new misses"}
          </h2>
          <p className={`${INTRO} mb-10`}>
            {zh
              ? "把 8 個公開的 agent 紅隊語料庫拿來跑現有規則，找出漏抓的攻擊變體，再寫成新規則。6 個語料庫產出 29 條偵測規則。另外 2 個（TensorTrust、PoisonedRAG）找不到現有規則漏掉的東西。"
              : "8 public agent red-team corpora were run against the existing rules to find the attack variants they missed, and those misses became new rules. 6 corpora produced 29 detection rules. The other 2, TensorTrust and PoisonedRAG, turned up nothing the existing rules didn't already catch."}
          </p>
        </Reveal>
        <Reveal delay={0.1}>
          <dl className="border-t border-ink mb-10">
            {megaCorpora.map((row) => (
              <div key={row.corpus} className="grid grid-cols-1 md:grid-cols-[260px_minmax(0,1fr)] gap-x-8 gap-y-1 py-4 border-b border-fog items-baseline">
                <dt className="text-[16px] text-ink">{row.corpus}</dt>
                <dd>
                  {row.ruleIds && <span className="font-data text-[13px] text-ink break-words">{row.ruleIds}</span>}
                  {row.note && <span className="text-[15px] text-stone">{row.note}</span>}
                </dd>
              </div>
            ))}
          </dl>
        </Reveal>
        <Reveal delay={0.2}>
          <h3 className="font-title text-[22px] text-ink mb-3">{zh ? "這 29 條規則的閘門紀錄" : "The gate record for these 29 rules"}</h3>
          {(zh
            ? [
                "29 條是去重後的數字，有幾條來自好幾個語料庫都漏抓的同一種攻擊。照規則檔裡的 maturity 分：15 條 stable，12 條 test，1 條 experimental，1 條 draft。它們當時跑閘門的紀錄沒有 commit，所以「全部通過、0 FP」這句話撤回，改成實測。",
                "2026-10-22 在 main b9d16840（ATR 4.1.5）重跑規則安全閘，結果和 2026-10-19 相同。29 條在 467 份良性 SKILL.md 上都沒有誤報。4 條沒過。其中 3 條在 13,620 筆 extended 良性樣本中，各誤報 2 到 4 筆。這 3 條都是 maturity test，在 alert 和 hunt 車道，不在 enforce 車道，其中 1 條另外跟其他規則的 true negative 衝突。",
                "剩下 1 條是 ATR-2026-00550，detection method 是 trace，閘門沒辦法拿文字樣本跑它，所以算不通過。2026-10-19 那次，閘門把它記成 true positive 沒命中；閘門的這項檢查後來在 2f0605c3 改過。紀錄同上。",
              ]
            : [
                "29 distinct rules after de-duplication. Several came from misses shared across corpora. By the maturity in their rule files: 15 stable, 12 test, 1 experimental, 1 draft. No record of their gate runs was committed, so the claim that all cleared it with 0 FP is withdrawn.",
                "In its place is a measurement: the rule safety gate re-run at main b9d16840 (ATR 4.1.5) on 2026-10-22, with the same results as on 2026-10-19. None of the 29 flags any of the 467 benign SKILL.md files; 4 fail, 3 of them flagging 2 to 4 of the 13,620 extended benign samples each. All three are maturity test, so they load in the alert and hunt lanes, not enforce, and one also conflicts with another rule's true negatives.",
                "The fourth, ATR-2026-00550, uses the trace detection method, which the gate cannot run on a text sample, so it does not pass. On 2026-10-19 the gate reported it as missing its own true positives; that check changed in 2f0605c3. Same record as above.",
              ]
          ).map((para) => (
            <p key={para} className={NOTE}>{para}</p>
          ))}
        </Reveal>
      </section>

      {/* ============================================================
          WHAT WE DON'T IMPORT
      ============================================================ */}
      <section className={SECTION}>
        <Reveal>
          <div className={KICKER}>{zh ? "刻意不收的語料" : "Left out on purpose"}</div>
          <h2 className={H2}>{zh ? "哪些沒收進來，為什麼。" : "What ATR doesn't import, and why."}</h2>
          <p className={`${INTRO} mb-10`}>
            {zh
              ? "ATR 不是找得到的語料庫都收。下面這些資料集，是刻意決定不拿來寫規則的，附上原因。"
              : "ATR doesn't import every corpus it can find. These datasets were deliberately kept out of rule writing, with the reason for each."}
          </p>
        </Reveal>
        <Reveal delay={0.1}>
          <dl className="border-t border-ink">
            {notImported.map((item) => (
              <div key={item.name} className="grid grid-cols-1 md:grid-cols-[260px_minmax(0,1fr)] gap-x-8 gap-y-2 py-5 border-b border-fog">
                <dt>
                  <div className="text-[16px] text-ink mb-1">{item.name}</div>
                  <div className="text-[13px] text-stone">{item.org}</div>
                  <div className="text-[13px] text-ink mt-1">{item.decision}</div>
                </dt>
                <dd className={`${BODY} max-w-[720px]`}>{item.reason}</dd>
              </div>
            ))}
          </dl>
        </Reveal>
      </section>

      {/* ============================================================
          CLOSING
      ============================================================ */}
      <section className="px-6 md:px-14">
        <Reveal>
          <div className="border-t border-ink pt-8 md:pt-10">
            <div className={KICKER}>{zh ? "送出一個 probe" : "Submit a probe"}</div>
            <h2 className={H2}>
              {zh
                ? "填一張表，大約 3 到 5 分鐘。規則上會一直留著你的名字，每個採用 ATR 的防守者用的都是這一條。"
                : "Spend 3 to 5 minutes on a form. Your name stays on the rule, and every defender who adopts ATR shares it."}
            </h2>
            <p className="text-[16px] text-graphite leading-[1.75] mb-8 max-w-[720px]">
              {zh
                ? "MIT 授權，不用簽 CLA，沒有遙測，永遠免費。攻擊本身要怎麼發表，權利全在你。ATR 只把它寫成一條偵測規則，誰都能用固定編號引用。"
                : "MIT licensed, no CLA, no telemetry, free for good. You keep every right to publish the attack itself. ATR only carries the detection, as a rule anyone can cite by its stable ID."}
            </p>
            <div className="flex flex-wrap gap-x-8 gap-y-3">
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=red-team-probe.yml"
                target="_blank"
                rel="noopener noreferrer"
                className={LINK}
              >
                {zh ? "開 probe issue" : "Open a probe issue"}<Diple />
              </a>
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules"
                target="_blank"
                rel="noopener noreferrer"
                className={LINK}
              >
                {zh ? "看 repo" : "Read the repo"}<Diple />
              </a>
              <a href={`/${locale}/ecosystem`} className={LINK}>
                {zh ? "防守端看 /ecosystem" : "The defensive side: /ecosystem"}<Diple />
              </a>
            </div>
          </div>
        </Reveal>
        <Reveal delay={0.1}>
          <p className="text-[13px] text-stone leading-[1.7] mt-8 max-w-[720px]">
            {zh
              ? `${stats.ruleCount} 條規則已部署，分在 ${stats.categoryCount} 個威脅類別。每一條都有 author 欄位和固定的規則編號。`
              : `${stats.ruleCount} rules deployed across ${stats.categoryCount} threat categories. Each has an author field and a stable rule ID.`}
          </p>
          <p className="text-[13px] text-stone leading-[1.7] mt-3 max-w-[720px]">
            {zh
              ? "利益揭露：維護者創辦並控制 PANGUARD AI, INC.，這家公司販售以 ATR 為基礎的 agent 資安產品。"
              : "Interests: the maintainer founded and controls PANGUARD AI, INC., which sells AI agent security products built on ATR."}
          </p>
        </Reveal>
      </section>
    </div>
    </Phrased>
  );
}
