/* ATD — Agentic Threat Detection. Companion standard to the ATR rule format:
 * the executable detection layer beneath the prose frameworks (OWASP Agentic
 * Top 10, MITRE ATLAS, CSA MAESTRO, AVID). Rendered as a standards-document
 * page mirroring /spec. DRAFT — pre-governance; honest status throughout.
 */
import Link from "next/link";
import type { Metadata } from "next";
import { pageMetadata } from "@/lib/seo";
import { locales, type Locale } from "@/lib/i18n";
import { RFC2119 } from "@/components/spec/RFC2119";
import { NormativeBadge, InformativeBadge } from "@/components/spec/Badges";
import { ATD_TECHNIQUES, ATD_TACTICS, ATD_STATS } from "@/lib/atd-data";
import { loadSiteStats, type BenchmarkMeasurement } from "@/lib/stats";
import { count, findBenchmark, measuredStamp, pct, pctHunt } from "@/lib/recall";

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
    path: "/atd",
    title: "ATD: Agentic Threat Detection",
    description:
      locale === "zh"
        ? "Agentic Threat Detection（ATD）：收錄 agent 特有威脅技法的開放知識庫草案。替收進來的 runtime 攻擊手法命名，對到 OWASP、ATLAS、CWE、AVID，讓偵測規則有地方掛。"
        : "Agentic Threat Detection (ATD): a draft open knowledge base of agent-native threat techniques. It names the runtime attack techniques it lists, maps them to OWASP, ATLAS, CWE and AVID, and gives detection rules something to hang from.",
  });
}

const ATD_VERSION = "0.1.0";
const ATD_STATUS_EN = "Editor's Draft · pre-governance";
const ATD_STATUS_ZH = "Editor's Draft · 治理前草案";
const ATD_DATE = "2026-06-13";
const ATD_DOI = "10.5281/zenodo.19178002";

/**
 * A benchmark proof card, read from the measurement file (lib/recall.ts): the
 * hunt figure, then the enforce figure where the measurement records it, with
 * the corpus, version and date it belongs to. No measurement, no card.
 */
function proofCard(m: BenchmarkMeasurement | null, zh: boolean, corpus: { en: string; zh: string }, note?: { en: string; zh: string }): { v: string; l: string } | null {
  if (!m) return null;
  const v = m.enforce ? `${pctHunt(m.recall)} / ${pct(m.enforce.recall)}` : pctHunt(m.recall);
  const lanes = m.enforce ? "hunt / enforce" : "hunt";
  const extra = note ? (zh ? `；${note.zh}` : `; ${note.en}`) : "";
  return zh
    ? { v, l: `召回率，${lanes}（${corpus.zh}，n=${count(m.samples)}，${measuredStamp(m, true, true)}${extra}）` }
    : { v, l: `recall, ${lanes} (${corpus.en}, n=${count(m.samples)}, ${measuredStamp(m, false)}${extra})` };
}

const sevColor: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--high)",
  medium: "var(--medium)",
};

interface Section {
  num: string;
  id: string;
  status: "normative" | "informative";
  en: { title: string; body: string };
  zh: { title: string; body: string };
}

const SECTIONS: Section[] = [
  {
    num: "1",
    id: "abstract",
    status: "informative",
    en: {
      title: "Abstract",
      body: `<p>Agentic Threat Detection (ATD) is the open, machine-readable knowledge base of agent-native threat techniques. Agents fail in ways no earlier security taxonomy has a name for. A poisoned tool description. A forged agent card. A memory write that lies dormant for three sessions. ATD gives each one a name, a permanent ID and a stable definition. Then it maps each to the established prose frameworks, <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/" target="_blank" rel="noopener noreferrer">OWASP Agentic Top 10</a>, <a href="https://atlas.mitre.org/" target="_blank" rel="noopener noreferrer">MITRE ATLAS</a>, <a href="https://cwe.mitre.org/" target="_blank" rel="noopener noreferrer">CWE</a> and <a href="https://avidml.org/" target="_blank" rel="noopener noreferrer">AVID</a>, with real-world evidence that the attack has actually happened.</p>
<p>Those frameworks tell you <em>what</em> can go wrong with an agent. ATD is the layer underneath. It names <em>how</em> each technique shows up at the point where it can be observed at runtime: the prompt, the tool call, the tool response, the message between agents, the memory write, the trace. That is where a detection rule has to hang. Until a technique has a name, every team writes the description again from scratch. A technique enters the catalog as soon as an attack is documented, before any detection rule exists for it, so the vocabulary leads the tooling instead of trailing it. Once a technique has a detection rule that passes the gate, ATD binds the two. Coverage is something to grow. It is not a condition of entry. ATD is to agent threats what <a href="https://atlas.mitre.org/" target="_blank" rel="noopener noreferrer">MITRE ATLAS</a> is to AI attacks and <a href="https://cwe.mitre.org/" target="_blank" rel="noopener noreferrer">CWE</a> is to software weaknesses: one citable index a whole ecosystem can point at.</p>
<p>Today the catalog names <strong>${"{TECH}"} techniques across ${"{TACTICS}"} tactics</strong>. Every one maps to at least one upstream framework, and <strong>${"{RULES}"} are already bound to a live detection rule that passes the gate</strong>. Breadth is what a reference is measured by. The rate it grows says the attack surface is still expanding.</p>
<p class="atd-note"><strong>Status:</strong> Editor's Draft. It is a request for comments and an open invitation to co-author. It is not a ratified standard yet, and earns that title only when it meets the neutrality bar in §8. It is published openly to find collaborators and mapping partners, not to claim authority.</p>`,
    },
    zh: {
      title: "摘要",
      body: `<p>Agentic Threat Detection（ATD）是一套開放、機器可讀的知識庫，收錄 agent 特有的威脅技法。agent 出事的方式，既有的資安分類大多叫不出名字。一段被下毒的 tool description，一張偽造的 agent card，一次寫進記憶後潛伏了三個 session 的內容。ATD 替每一種取名，給它永久 ID 和穩定的定義，再對到既有的文字型框架：<a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/" target="_blank" rel="noopener noreferrer">OWASP Agentic Top 10</a>、<a href="https://atlas.mitre.org/" target="_blank" rel="noopener noreferrer">MITRE ATLAS</a>、<a href="https://cwe.mitre.org/" target="_blank" rel="noopener noreferrer">CWE</a>、<a href="https://avidml.org/" target="_blank" rel="noopener noreferrer">AVID</a>，並附上這種攻擊真的發生過的佐證。</p>
<p>那些框架告訴你 agent <em>會出什麼錯</em>。ATD 在它們底下一層，說明每條技法在 runtime 看得到的地方<em>怎麼</em>現形：prompt、tool call、tool response、agent 之間的訊息、記憶寫入、trace。偵測規則就得掛在這些地方。技法還沒有名字之前，每個團隊都得從頭寫一遍描述。攻擊一被記錄下來，技法就進目錄，不必等偵測規則出現，所以用詞永遠走在工具前面。等某條技法有了通過閘門的偵測規則，ATD 就把兩者綁在一起。覆蓋率是要慢慢長的，不是入門條件。ATD 之於 agent 威脅，就像 <a href="https://atlas.mitre.org/" target="_blank" rel="noopener noreferrer">MITRE ATLAS</a> 之於 AI 攻擊、<a href="https://cwe.mitre.org/" target="_blank" rel="noopener noreferrer">CWE</a> 之於軟體弱點：一份整個生態都能指著引用的索引。</p>
<p>目錄目前已替 <strong>${"{TACTICS}"} 個戰術底下的 ${"{TECH}"} 條技法</strong>命名。每一條至少對到一個上游框架，其中 <strong>${"{RULES}"} 條已綁定一條上線中、通過閘門的偵測規則</strong>。參考資料看的就是這個廣度。它長得多快，也說明這片攻擊面還在擴大。</p>
<p class="atd-note"><strong>狀態：</strong>Editor's Draft。這是一份徵求意見稿，歡迎一起撰寫。它<strong>還不是</strong>正式通過的標準，要達到 §8 的中立門檻才算得上。公開它是為了找協作者和對照夥伴，不是要宣稱權威。</p>`,
    },
  },
  {
    num: "2",
    id: "scope",
    status: "normative",
    en: {
      title: "Scope: what ATD is and is not",
      body: `<p>ATD lists <strong>agent-runtime threat techniques that can be detected in agent I/O</strong>: prompts and content, tool calls, tool responses, messages between agents, memory operations, traces, screen state and payment mandates.</p>
<ul>
<li>ATD <strong>MUST NOT</strong> mint identifiers for vulnerability instances. A specific CVE in a specific MCP server belongs in CVE, GHSA, OSV or AVID. ATD references it and does not replace it.</li>
<li>ATD <strong>MUST NOT</strong> present itself as a competing top-level risk taxonomy. The "top ten agentic risks" framing belongs to OWASP ASI. ATD sits beneath it and makes it runnable.</li>
<li>ATD <strong>MUST</strong> map every technique to at least one upstream framework, or document the gap where no mapping exists yet.</li>
</ul>
<p>The boundary is deliberate. Vulnerability registries that copied CVE's territory, such as the now-archived GSD, fragmented and stalled. ATD fills the <em>executable detection</em> layer that nobody covers. It does not refight a settled lane.</p>`,
    },
    zh: {
      title: "範圍：ATD 是什麼、不是什麼",
      body: `<p>ATD 列的是<strong>能在 agent I/O 觀測到的 agent-runtime 威脅技法</strong>：prompt 與內容、tool call、tool response、agent 之間的訊息、記憶操作、trace、螢幕狀態、payment mandate。</p>
<ul>
<li>ATD <strong>MUST NOT</strong> 替漏洞實例發識別碼。某個 MCP server 的某個 CVE，歸 CVE、GHSA、OSV 或 AVID 管。ATD 引用它，不取代它。</li>
<li>ATD <strong>MUST NOT</strong> 把自己當成另一套互相競爭的頂層風險分類。「agentic 十大風險」這個框架屬於 OWASP ASI。ATD 在它底下，讓它跑得起來。</li>
<li>ATD <strong>MUST</strong> 讓每條技法至少對到一個上游框架。還對不到的，要把缺口記下來。</li>
</ul>
<p>這條界線是刻意劃的。過去搶 CVE 地盤的漏洞登錄，例如已經封存的 GSD，最後四分五裂、停擺。ATD 補的是沒人做的<em>可執行偵測</em>這一層，不去重打已經定下來的仗。</p>`,
    },
  },
  {
    num: "3",
    id: "model",
    status: "normative",
    en: {
      title: "Conceptual model",
      body: `<p>ATD uses two axes, both borrowed from standards that already work:</p>
<ul>
<li><strong>Tactic / Technique matrix</strong>, from MITRE ATLAS. A <code>Tactic</code> is the adversary's goal phase. A <code>Technique</code> is a concrete attack pattern that can be detected. A <code>Sub-technique</code> is a variant.</li>
<li><strong>Abstraction hierarchy</strong>, from CWE. Each technique is tagged <code>pillar</code>, <code>class</code>, <code>base</code> or <code>variant</code>.</li>
</ul>
<p><strong>Identifiers.</strong> Tactics run <code>ATD-TA1</code> … <code>ATD-TA9</code>. Techniques are <code>ATD-T0001</code>: zero-padded, sequential, permanent and never reused. Sub-techniques use dotted notation, as in <code>ATD-T0001.001</code>. Each detection rule also carries a UUIDv4, so a rule survives renaming. Techniques are the catalog. Rules are the executable instances bound to them.</p>
<p><strong>Maturity.</strong> Every technique and every rule has a status on the ladder <code>experimental → test → stable</code>, plus <code>deprecated</code>. Production consumers <strong>SHOULD</strong> auto-sync only <code>stable</code>.</p>`,
    },
    zh: {
      title: "概念模型",
      body: `<p>ATD 用兩條軸，都借自已經證明可行的標準：</p>
<ul>
<li><strong>Tactic / Technique 矩陣</strong>，來自 MITRE ATLAS。<code>Tactic</code> 是攻擊者的目標階段，<code>Technique</code> 是具體、可偵測的攻擊模式，<code>Sub-technique</code> 是它的變體。</li>
<li><strong>抽象層級</strong>，來自 CWE。每條技法標上 <code>pillar</code>、<code>class</code>、<code>base</code> 或 <code>variant</code>。</li>
</ul>
<p><strong>識別碼。</strong>Tactic 是 <code>ATD-TA1</code> … <code>ATD-TA9</code>。Technique 是 <code>ATD-T0001</code>，補零、依序編號、永久有效，不會重用。sub-technique 用點號，例如 <code>ATD-T0001.001</code>。每條偵測規則另外帶一個 UUIDv4，改名之後還追得到。technique 是目錄，rule 是綁在上面、可以執行的實例。</p>
<p><strong>成熟度。</strong>每條技法和規則都有一個階段：<code>experimental → test → stable</code>，另外還有 <code>deprecated</code>。正式環境的使用端 <strong>SHOULD</strong> 只自動同步 <code>stable</code>。</p>`,
    },
  },
  {
    num: "5",
    id: "schema",
    status: "normative",
    en: {
      title: "Entry schema",
      body: `<p>A technique entry is a YAML or JSON document, validated against a normative JSON Schema (Draft 2020-12) that ships in the repo. It is designed to be compatible with the OSV and Sigma ecosystems. Required fields:</p>
<pre><code>atd_id            ATD-T####            permanent
schema_version    SemVer, no "v"       additive-minor guarantee (OSV)
title             short imperative phrase
tactic            ATD-TA#
abstraction       pillar | class | base | variant
status            experimental | test | stable | deprecated
description       the technique and its attack mechanism
detection_surface content | tool_input | tool_response |
                  inter_agent_msg | memory_op | trace | screen | payment_mandate
mappings          owasp_asi[] · mitre_atlas[] · cwe[] · avid[] · maestro_layer[]
references         advisory / CVE / research URLs (evidence it is real)
detection_rules   UUIDv4[] into the rule corpus</code></pre>
<p>A detection rule reuses the ATR rule schema already in production: regex or conditions, <code>true_positives</code> <strong>and</strong> <code>true_negatives</code> as a precision test, false-positive notes, response actions, and a valid <code>agent_source.type</code>.</p>`,
    },
    zh: {
      title: "條目結構",
      body: `<p>technique 條目是一份 YAML 或 JSON 文件，要通過 repo 裡附的 normative JSON Schema（Draft 2020-12）驗證。設計上和 OSV、Sigma 生態相容。必填欄位：</p>
<pre><code>atd_id            ATD-T####            永久
schema_version    SemVer, 無 "v"        加法式 minor 保證(OSV)
title             簡短祈使片語
tactic            ATD-TA#
abstraction       pillar | class | base | variant
status            experimental | test | stable | deprecated
description       技法與其攻擊機制
detection_surface content | tool_input | tool_response |
                  inter_agent_msg | memory_op | trace | screen | payment_mandate
mappings          owasp_asi[] · mitre_atlas[] · cwe[] · avid[] · maestro_layer[]
references         advisory / CVE / research URL(真實證據)
detection_rules   UUIDv4[] 指向 rule corpus</code></pre>
<p>偵測規則沿用已經在正式環境跑的 ATR 規則 schema：regex 或 conditions、<code>true_positives</code> <strong>和</strong> <code>true_negatives</code>（用來測精準度）、誤報註記、回應動作，以及合法的 <code>agent_source.type</code>。</p>`,
    },
  },
  {
    num: "6",
    id: "mappings",
    status: "informative",
    en: {
      title: "Mappings & interoperability",
      body: `<p>Legitimacy comes from interoperability, not from declaring authority. Every ATD technique maps to OWASP ASI, MITRE ATLAS and CWE wherever a slot exists. AVID and the MAESTRO layer are added where they apply. When a technique falls in a gap no upstream framework names yet, ATD records the gap and feeds it back to those projects as a proposed technique and case study. The catalog grows by crosswalk. It does not claim a lane of its own.</p>
<p>ATD is designed to interoperate with <a href="https://avidml.org/" target="_blank" rel="noopener noreferrer">AVID</a>, not compete with it. AVID already operates a governed AI vulnerability registry that is open to submissions. ATD supplies the executable detection that AVID's "Detection" report type expects.</p>`,
    },
    zh: {
      title: "對照與互通",
      body: `<p>正當性來自互通，不是自己宣布權威。只要有對應的位置，每條 ATD 技法都會對到 OWASP ASI、MITRE ATLAS 和 CWE。適用的話，再加上 AVID 和 MAESTRO 層。技法落在上游框架還沒命名的缺口時，ATD 會記下這個缺口，再以提議技法和案例研究的形式，回饋給那些專案。目錄靠對照長大，不另立地盤。</p>
<p>ATD 設計上要和 <a href="https://avidml.org/" target="_blank" rel="noopener noreferrer">AVID</a> 互通，不是競爭。AVID 已經在營運一個有治理、開放投稿的 AI 漏洞登錄。AVID 的「Detection」報告類型需要可執行的偵測，ATD 補的就是這一塊。</p>`,
    },
  },
  {
    num: "7",
    id: "conformance",
    status: "normative",
    en: {
      title: "Conformance",
      body: `<ul>
<li>A <strong>conformant technique entry</strong> MUST validate against the JSON Schema, carry at least one framework mapping or a documented gap, and cite at least one reference.</li>
<li>A <strong>conformant detection rule</strong> MUST pass the precision gate. Every declared true positive matches. The published benign corpus produces zero false positives. No rule conflicts with another.</li>
<li>A <strong>conformant consumer</strong> MUST honor the maturity field and SHOULD expose the <code>ATD-T####</code> id on every detection it emits.</li>
</ul>`,
    },
    zh: {
      title: "符規",
      body: `<ul>
<li><strong>符規的技法條目</strong> MUST 通過 JSON Schema 驗證，至少帶一個框架對照或記錄下來的缺口，並至少引用一個來源。</li>
<li><strong>符規的偵測規則</strong> MUST 通過精準度閘門：每個宣告的正例都要命中，在公開的良性語料上零誤報，規則之間沒有衝突。</li>
<li><strong>符規的使用端</strong> MUST 遵守 maturity 欄位，並 SHOULD 在每筆偵測上帶出 <code>ATD-T####</code> id。</li>
</ul>`,
    },
  },
  {
    num: "8",
    id: "governance",
    status: "informative",
    en: {
      title: "Governance & status",
      body: `<p>ATD is governed by a written charter. It is published as an open draft and an invitation to co-author. It earns the title <em>standard</em> when it meets a concrete, public neutrality bar taken from the OpenSSF project lifecycle: <strong>at least three maintainers from at least two organizations</strong>. Those seats are actively being filled.</p>
<p>Governance follows a Minimal Viable Governance charter. Maintainers decide by lazy consensus, with a simple-majority vote of the Technical Steering Committee as the fallback. Charter amendments need a two-thirds vote, and no single person has a veto. The specification is CC-BY-4.0 and forkable by design, so no party can hold it hostage. There is a committed roadmap to a neutral foundation home: an OpenSSF working group, or the OWASP GenAI Security Project.</p>
<p class="atd-note">Call for collaborators. If your team works on agent security, <strong>map your tooling to ATD, submit a technique, or take a maintainer seat</strong>. See <a href="/${"{LOCALE}"}/contribute">/contribute</a>.</p>`,
    },
    zh: {
      title: "治理與狀態",
      body: `<p>ATD 依書面章程治理，以開放草案的形式發布，歡迎一起撰寫。要達到一條具體、公開的中立門檻，它才稱得上 <em>standard</em>。這條門檻取自 OpenSSF 的專案生命週期：<strong>至少三位 maintainer，分屬至少兩個組織</strong>。這些席位正在積極補上。</p>
<p>治理採 Minimal Viable Governance 章程。maintainer 之間用 lazy consensus 決定，談不攏時由 Technical Steering Committee 簡單多數表決。修改章程要三分之二同意，沒有任何一個人能否決。規格以 CC-BY-4.0 授權，設計上就能 fork，沒有哪一方能綁架它。另外也已承諾遷到中立的基金會：OpenSSF 的 working group，或 OWASP GenAI Security Project。</p>
<p class="atd-note">徵求協作者。如果你的團隊在做 agent 安全，<strong>可以把工具對到 ATD、投一條技法，或接下 maintainer 席位</strong>。請看 <a href="/${"{LOCALE}"}/contribute">/contribute</a>。</p>`,
    },
  },
];
export default async function ATDPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: rawLocale } = await params;
  const locale: Locale = rawLocale === "zh" ? "zh" : "en";
  const zh = locale === "zh";
  const status = locale === "zh" ? ATD_STATUS_ZH : ATD_STATUS_EN;
  const stats = loadSiteStats();
  const selfTest = findBenchmark(stats, "atr-self-test");
  const garak = findBenchmark(stats, "garak");

  // Section bodies carry {LOCALE} for internal links and {TECH}/{TACTICS}/{RULES}
  // so the coverage numbers stay sourced from ATD_STATS — never hardcoded in prose.
  const renderBody = (body: string) =>
    body
      .replace(/\{LOCALE\}/g, locale)
      .replace(/\{TECH\}/g, String(ATD_STATS.techniques))
      .replace(/\{TACTICS\}/g, String(ATD_STATS.tactics))
      .replace(/\{RULES\}/g, String(ATD_STATS.withLiveRule));

  return (
    <main
      id="main-content"
      className="spec-document atd-doc w-full max-w-7xl mx-auto px-5 md:px-8 pt-24 md:pt-28 pb-24"
      lang={locale === "zh" ? "zh-Hant" : "en"}
    >
      <header
        className="atd-masthead mb-10 md:mb-12"
        lang={locale === "zh" ? "zh-Hant" : "en"}
      >
        {/* ATD logo — enumeration bracket [ATD] in ATR palette (ink mark, blue dots) */}
        <div className="atd-logo" aria-label="ATD">
          <svg width="168" height="56" viewBox="0 0 168 56" role="img" aria-label="ATD" style={{ display: "block" }}>
            <path d="M26 11 L13 11 L13 45 L26 45" fill="none" stroke="#07142A" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
            <path d="M142 11 L155 11 L155 45 L142 45" fill="none" stroke="#07142A" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
            <text x="84" y="38" textAnchor="middle" style={{ fontFamily: "var(--font-data)", fontWeight: 700, fontSize: "31px", letterSpacing: "1px" }} fill="#07142A">ATD</text>
            <circle cx="38" cy="48" r="2.1" fill="#2563EB" />
            <circle cx="46" cy="48" r="2.1" fill="#2563EB" />
            <circle cx="54" cy="48" r="2.1" fill="#2563EB" />
          </svg>
        </div>

        <p className="atd-eyebrow">
          {locale === "zh"
            ? "agent 威脅技法的開放知識庫 · RFC 草案 · 徵求協作者 · 與 ATR 搭配"
            : "Open knowledge base of agent threat techniques · draft RFC · call for collaborators · companion to ATR"}
        </p>

        <h1>Agentic Threat Detection</h1>

        <p className="atd-sub">
          {locale === "zh"
            ? "一份收錄 agent runtime 威脅手法的開放知識庫，還在草案階段。收進來的每一種手法都有名字、穩定的 ID，也對到 OWASP、MITRE ATLAS、CWE、AVID，讓偵測有地方掛。ATLAS 替 AI 攻擊命名，CWE 替軟體弱點命名。ATD 想替 agent 威脅做同樣的事。"
            : "An open knowledge base of agent-runtime threat techniques, still in draft. Each technique it lists gets a name, a stable ID and a crosswalk to OWASP, MITRE ATLAS, CWE and AVID, so detection has somewhere to hang. MITRE ATLAS names AI attacks. CWE names software weaknesses. ATD sets out to do the same for agent threats."}
        </p>

        <div className="doc-status not-prose" role="note">
          <strong>{status}</strong>
          <span className="pipe">·</span>
          <span><span className="opacity-70">{locale === "zh" ? "版本" : "Version"}</span> {ATD_VERSION}</span>
          <span className="pipe">·</span>
          <span><span className="opacity-70">{locale === "zh" ? "日期" : "Date"}</span> {ATD_DATE}</span>
          <span className="pipe">·</span>
          <span><span className="opacity-70">{locale === "zh" ? "正式網址" : "Canonical"}</span> <a href={`/${locale}/atd`}>/atd</a></span>
          <span className="pipe">·</span>
          <span><span className="opacity-70">{locale === "zh" ? "編輯" : "Editor"}</span> Adam Lin</span>
        </div>
      </header>

      <section aria-label="coverage" className="mb-10 md:mb-12">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { v: String(ATD_STATS.techniques), l: locale === "zh" ? "條技法已編目" : "techniques cataloged" },
            { v: String(ATD_STATS.withCve), l: locale === "zh" ? "有 CVE 佐證" : "CVE-backed" },
            { v: String(ATD_STATS.withLiveRule), l: locale === "zh" ? "條已綁定偵測規則（這是覆蓋率，不是門檻）" : "bound to a rule (coverage, not a gate)" },
            ...[
              proofCard(
                selfTest,
                zh,
                { en: "in-house self-test corpus", zh: "ATR 內部自測語料" },
                selfTest && selfTest.falsePositives !== null && selfTest.benign !== null
                  ? { en: `${count(selfTest.falsePositives)} of ${count(selfTest.benign)} benign samples flagged in the hunt lane, not out-of-sample`, zh: `hunt lane 在 ${count(selfTest.benign)} 個良性樣本上誤報 ${count(selfTest.falsePositives)} 次，不能當樣本外證據` }
                  : undefined,
              ),
              proofCard(garak, zh, { en: "garak in-the-wild", zh: "garak in-the-wild" }, { en: "partly closed-book, since many rules were written from this corpus", zh: "部分屬於 closed-book，不少規則就是從這份語料寫出來的" }),
            ].flatMap((c) => c ?? []),
          ].map((m, i) => (
            <div key={i} style={{ background: "var(--spec-tint)", borderRadius: "10px", padding: "0.9rem 1rem" }}>
              <div className="text-navy-ink" style={{ fontFamily: "var(--font-data)", fontSize: "1.35rem", fontWeight: 600, letterSpacing: "-0.01em" }}>{m.v}</div>
              <div className="text-stone" style={{ fontSize: "0.72rem", marginTop: "0.25rem", lineHeight: 1.35 }}>{m.l}</div>
            </div>
          ))}
        </div>
        <p className="text-stone" style={{ fontSize: "0.8rem", marginTop: "0.9rem", lineHeight: 1.6 }}>
          {locale === "zh" ? (
            <>ATD 的偵測規則隨 ATR 發布。ATR 已合併進 Cisco AI Defense 的開源 skill-scanner，用在 Microsoft Agent Governance Toolkit 的範例裡，也在 MISP/CIRCL 有對照。這些使用端整合的是 ATR 規則，不代表它們背書這份草案標準。DOI{" "}<a className="text-navy underline" href={`https://doi.org/${ATD_DOI}`} target="_blank" rel="noopener noreferrer">{ATD_DOI}</a>。</>
          ) : (
            <>ATD&apos;s detection rules ship in ATR. ATR has been merged into Cisco AI Defense&apos;s open-source skill-scanner, is used in Microsoft Agent Governance Toolkit examples, and is mapped in MISP/CIRCL. Those consumers integrate ATR rules. That is not an endorsement of this draft standard. DOI{" "}<a className="text-navy underline" href={`https://doi.org/${ATD_DOI}`} target="_blank" rel="noopener noreferrer">{ATD_DOI}</a>.</>
          )}
        </p>
      </section>

      <RFC2119 locale={locale} />

      <div className="grid grid-cols-1 lg:grid-cols-[16rem_minmax(0,1fr)] gap-10 lg:gap-14 mt-6">
        <aside aria-label="ATD table of contents" className="lg:order-first">
          <nav className="spec-toc">
            <p
              className="text-xs font-semibold uppercase tracking-wider text-stone mb-3"
              style={{ fontFamily: "var(--font-body)" }}
            >
              {locale === "zh" ? "目錄" : "Contents"}
            </p>
            <ol>
              {SECTIONS.filter((s) => parseInt(s.num) < 4).map((s) => (
                <li key={s.id}>
                  <a href={`#${s.id}`}>
                    <span className="toc-section-num">§{s.num}</span>
                    {s[locale].title}
                  </a>
                </li>
              ))}
              <li>
                <a href="#catalog">
                  <span className="toc-section-num">§4</span>
                  {locale === "zh" ? "技法目錄" : "Technique catalog"}
                </a>
              </li>
              {SECTIONS.filter((s) => parseInt(s.num) > 4).map((s) => (
                <li key={s.id}>
                  <a href={`#${s.id}`}>
                    <span className="toc-section-num">§{s.num}</span>
                    {s[locale].title}
                  </a>
                </li>
              ))}
              <li>
                <a href="#downloads">
                  <span className="toc-section-num">§9</span>
                  {locale === "zh" ? "下載與檔案" : "Downloads & artifacts"}
                </a>
              </li>
            </ol>
            <hr className="my-5 border-fog" />
            <p
              className="text-xs uppercase tracking-wider text-stone mb-2"
              style={{ fontFamily: "var(--font-body)" }}
            >
              {locale === "zh" ? "相關文件" : "Related documents"}
            </p>
            <ul className="space-y-2 text-sm" style={{ fontFamily: "var(--font-body)" }}>
              <li>
                <Link href={`/${locale}/spec`} className="text-navy underline decoration-navy/30 hover:decoration-navy">
                  /spec
                </Link>
              </li>
              <li>
                <Link href={`/${locale}/governance`} className="text-navy underline decoration-navy/30 hover:decoration-navy">
                  /governance
                </Link>
              </li>
              <li>
                <Link href={`/${locale}/contribute`} className="text-navy underline decoration-navy/30 hover:decoration-navy">
                  /contribute
                </Link>
              </li>
              <li>
                <Link href={`/${locale}/threats`} className="text-navy underline decoration-navy/30 hover:decoration-navy">
                  /threats
                </Link>
              </li>
            </ul>
          </nav>
        </aside>

        <div className="min-w-0 spec-measure-wide">
          {SECTIONS.filter((s) => parseInt(s.num) < 4).map((s) => (
            <section key={s.id} id={s.id} aria-labelledby={`${s.id}-heading`}>
              <h2 id={`${s.id}-heading`}>
                <a href={`#${s.id}`} className="section-anchor" aria-hidden="true">§{s.num}</a>
                {s[locale].title}
                {s.status === "normative" ? <NormativeBadge className="ml-2 align-middle" /> : <InformativeBadge className="ml-2 align-middle" />}
              </h2>
              <div className="spec-body min-w-0 overflow-x-auto -mx-2 px-2" dangerouslySetInnerHTML={{ __html: renderBody(s[locale].body) }} />
            </section>
          ))}

          <section id="catalog" aria-labelledby="catalog-heading">
            <h2 id="catalog-heading">
              <a href="#catalog" className="section-anchor" aria-hidden="true">§4</a>
              {locale === "zh" ? "技法目錄" : "Technique catalog"}
              <NormativeBadge className="ml-2 align-middle" />
            </h2>
            <div className="spec-body">
              <p>
                {locale === "zh"
                  ? `這是完整目錄。${ATD_STATS.techniques} 條技法，依 ${ATD_TACTICS.length} 個戰術階段排列，從 MCP 協定層、multi-agent 之間的互動，一路到 agentic commerce。每條都有永久 ID 和穩定的定義，對到 OWASP ASI、MITRE ATLAS、CWE，並附真實的 CVE 或研究佐證。其中 ${ATD_STATS.withLiveRule} 條已綁定一條上線中的 ATR 偵測規則。其餘只做了記錄，但在這裡的地位完全一樣：替威脅命名，不必等規則先出現。已記錄、但還沒有公開實例的，標成 research 或 aspirational，絕不假裝成 CVE。每個框架識別碼都在 2026-06-14 對原始來源核對過。`
                  : `This is the full index. ${ATD_STATS.techniques} techniques, laid out along ${ATD_TACTICS.length} tactic phases, from the MCP protocol layer through multi-agent dynamics to agentic commerce. Each carries a permanent ID, a stable definition and a crosswalk to OWASP ASI, MITRE ATLAS and CWE, backed by a real CVE or a research citation. ${ATD_STATS.withLiveRule} are already bound to a live ATR detection rule. The rest are documented techniques and stand on exactly equal footing here, because naming a threat does not wait for a rule. Entries with no public instance are marked research or aspirational, never dressed up as a CVE. Every framework ID was checked against its primary source on 2026-06-14.`}
              </p>
            </div>
            {ATD_TACTICS.map((tac) => {
              const items = ATD_TECHNIQUES.filter((t) => t.tactic === tac.id);
              if (items.length === 0) return null;
              return (
                <div key={tac.id} className="mb-7 mt-6">
                  <h3 className="text-navy-ink mb-3" style={{ fontFamily: "var(--font-spec), Georgia, serif", fontSize: "1.05rem", fontWeight: 600 }}>
                    <span style={{ fontFamily: "var(--font-data)", color: "var(--navy)" }}>{tac.id}</span> · {tac.name}
                    <span className="text-mist" style={{ fontSize: "0.8rem", fontWeight: 400 }}> ({items.length})</span>
                  </h3>
                  <div className="space-y-3">
                    {items.map((t) => (
                      <div key={t.id} style={{ border: "0.5px solid var(--fog)", borderRadius: "8px", padding: "0.85rem 1rem", background: "var(--paper)" }}>
                        <div className="flex items-center flex-wrap gap-x-2 gap-y-1" style={{ marginBottom: "0.3rem" }}>
                          <span style={{ width: 7, height: 7, borderRadius: "50%", background: sevColor[t.severity], display: "inline-block" }} aria-hidden="true" />
                          <span style={{ fontFamily: "var(--font-data)", fontSize: "0.8rem", color: "var(--navy)", fontWeight: 600 }}>{t.id}</span>
                          <span className="text-ink" style={{ fontWeight: 500, fontSize: "0.96rem" }}>{t.title}</span>
                          {t.atrRule && (
                            <Link href={`/${locale}/rules/${t.atrRule}`} style={{ fontFamily: "var(--font-data)", fontSize: "0.68rem", background: "var(--navy)", color: "#fff", borderRadius: "3px", padding: "2px 7px", textDecoration: "none" }}>
                              {locale === "zh" ? "上線規則 ↗" : "live rule ↗"}
                            </Link>
                          )}
                        </div>
                        <p className="text-graphite" style={{ fontSize: "0.86rem", lineHeight: 1.55, margin: "0 0 0.5rem" }}>{t.mechanism}</p>
                        <div className="flex flex-wrap gap-1.5 items-center" style={{ fontFamily: "var(--font-data)", fontSize: "0.68rem" }}>
                          {t.evidence.kind === "cve" && t.evidence.url ? (
                            <a href={t.evidence.url} target="_blank" rel="noopener noreferrer" style={{ background: "#FBECEC", color: "#A32D2D", borderRadius: "3px", padding: "2px 7px", textDecoration: "none" }}>{t.evidence.label} ↗</a>
                          ) : t.evidence.kind === "research" ? (
                            <a href={t.evidence.url} target="_blank" rel="noopener noreferrer" style={{ background: "var(--ash)", color: "var(--graphite)", borderRadius: "3px", padding: "2px 7px", textDecoration: "none" }}>{locale === "zh" ? "研究 ↗" : "research ↗"}</a>
                          ) : (
                            <span style={{ background: "var(--ash)", color: "var(--mist)", borderRadius: "3px", padding: "2px 7px" }}>{locale === "zh" ? "前瞻，尚無實例" : "aspirational"}</span>
                          )}
                          {t.asi.map((a) => <span key={a} style={{ background: "#EAF1FB", color: "#185FA5", borderRadius: "3px", padding: "2px 6px" }}>{a}</span>)}
                          {t.atlas.map((a) => <span key={a} style={{ background: "var(--spec-tint)", color: "var(--navy)", borderRadius: "3px", padding: "2px 6px" }}>{a}</span>)}
                          {t.cwe.map((c) => <span key={c} style={{ background: "var(--ash)", color: "var(--stone)", borderRadius: "3px", padding: "2px 6px" }}>{c}</span>)}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </section>

          {SECTIONS.filter((s) => parseInt(s.num) > 4).map((s) => (
            <section key={s.id} id={s.id} aria-labelledby={`${s.id}-heading`}>
              <h2 id={`${s.id}-heading`}>
                <a href={`#${s.id}`} className="section-anchor" aria-hidden="true">§{s.num}</a>
                {s[locale].title}
                {s.status === "normative" ? <NormativeBadge className="ml-2 align-middle" /> : <InformativeBadge className="ml-2 align-middle" />}
              </h2>
              <div className="spec-body min-w-0 overflow-x-auto -mx-2 px-2" dangerouslySetInnerHTML={{ __html: renderBody(s[locale].body) }} />
            </section>
          ))}

          <section id="downloads" aria-labelledby="downloads-heading">
            <h2 id="downloads-heading">
              <a href="#downloads" className="section-anchor" aria-hidden="true">§9</a>
              {locale === "zh" ? "下載與檔案" : "Downloads & artifacts"}
              <InformativeBadge className="ml-2 align-middle" />
            </h2>
            <div className="spec-body">
              <ul>
                <li><a href="/atd/atd-techniques.json" target="_blank" rel="noopener noreferrer">atd-techniques.json</a> — {locale === "zh" ? "完整目錄，機器可讀，欄位與 OSV、Sigma 相容" : "the full enumeration, machine-readable, with OSV- and Sigma-compatible fields"}</li>
                <li><a href="/atd/atd-technique.schema.json" target="_blank" rel="noopener noreferrer">atd-technique.schema.json</a> — {locale === "zh" ? "normative JSON Schema（Draft 2020-12）" : "the normative JSON Schema (Draft 2020-12)"}</li>
                <li><Link href={`/${locale}/spec`}>/spec</Link> — {locale === "zh" ? "ATR 規則格式，技法綁定的可執行規則就照這個寫" : "the ATR rule format, used by the executable rules that techniques bind to"}</li>
                <li>DOI <a href={`https://doi.org/${ATD_DOI}`} target="_blank" rel="noopener noreferrer">{ATD_DOI}</a> — {locale === "zh" ? "研究與引用用的存檔" : "research & citation artifact"}</li>
              </ul>
            </div>
          </section>

          <hr className="my-12 border-fog" />
          <p className="spec-meta">
            {locale === "zh" ? "編輯：" : "Editor: "}Adam Lin ·{" "}
            {locale === "zh" ? "規格" : "Specification"} CC-BY-4.0 ·{" "}
            {locale === "zh" ? "Schema 與工具" : "Schema & tooling"} Apache-2.0 ·{" "}
            {locale === "zh" ? "規則庫" : "Rule corpus"} MIT · ISO 8601 {ATD_DATE} ·{" "}
            {locale === "zh"
              ? "Editor's Draft，治理前，還不是正式通過的標準。"
              : "Editor's Draft, pre-governance. Not a ratified standard."}
          </p>
        </div>
      </div>
    </main>
  );
}
