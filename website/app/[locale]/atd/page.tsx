/* ATD — Agentic Threat Detection. Companion standard to the ATR rule format:
 * the executable detection layer beneath the prose frameworks (OWASP Agentic
 * Top 10, MITRE ATLAS, CSA MAESTRO, AVID). Rendered as a standards-document
 * page mirroring /spec. DRAFT — pre-governance; honest status throughout.
 */
import Link from "next/link";
import type { Metadata } from "next";
import { locales, type Locale } from "@/lib/i18n";
import { RFC2119 } from "@/components/spec/RFC2119";
import { NormativeBadge, InformativeBadge } from "@/components/spec/Badges";
import { ATD_TECHNIQUES, ATD_TACTICS, ATD_STATS } from "@/lib/atd-data";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  return {
    title: "ATD — Agentic Threat Detection | ATR",
    description:
      locale === "zh"
        ? "Agentic Threat Detection (ATD):agent 原生威脅技法的開放知識庫。為每種 runtime 攻擊手法命名,對映 OWASP/ATLAS/CWE/AVID,讓偵測規則有處可掛。"
        : "Agentic Threat Detection (ATD): an open knowledge base of agent-native threat techniques. Names every runtime attack technique, maps it to OWASP/ATLAS/CWE/AVID, and gives detection rules something to hang from.",
  };
}

const ATD_VERSION = "0.1.0";
const ATD_STATUS_EN = "Editor's Draft — pre-governance";
const ATD_STATUS_ZH = "Editor's Draft — 治理前草案";
const ATD_DATE = "2026-06-13";
const ATD_DOI = "10.5281/zenodo.19178002";

// Verified benchmark proof (state/facts.json, 2026-06-14). Real corpora.
const PROOF = {
  skill: { recall: 100, fp: 0, n: 341 },
  garak: { recall: 98, n: 650 },
  pint: { recall: 63.2, precision: 99.7, n: 850 },
};

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
      body: `<p>Agentic Threat Detection (ATD) is the open, machine-readable knowledge base of agent-native threat techniques. Agents fail in ways no prior security taxonomy has a name for — a poisoned tool description, a forged agent card, a memory write that lies dormant for three sessions. ATD gives each of those a name, a permanent ID, and a stable definition, then maps it to the established prose frameworks — <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/" target="_blank" rel="noopener noreferrer">OWASP Agentic Top 10</a>, <a href="https://atlas.mitre.org/" target="_blank" rel="noopener noreferrer">MITRE ATLAS</a>, <a href="https://cwe.mitre.org/" target="_blank" rel="noopener noreferrer">CWE</a>, <a href="https://avidml.org/" target="_blank" rel="noopener noreferrer">AVID</a> — with real-world evidence that the attack has actually occurred.</p>
<p>Those frameworks tell you <em>what</em> can go wrong with an agent. ATD is the layer underneath that names <em>how</em> each technique manifests at the point it can be observed at runtime — the prompt, the tool call, the tool response, the inter-agent message, the memory write, the trace. That is where a detection rule has to hang, and until a technique is named, every team reinvents the description from scratch. A technique enters the catalog the moment an attack is documented — before any detection rule exists for it — so the vocabulary always leads the tooling, never lags it. Where a technique has earned a gate-passing detection rule, ATD binds the two; coverage is a property to grow, not a condition of entry. ATD is to agent threats what <a href="https://atlas.mitre.org/" target="_blank" rel="noopener noreferrer">MITRE ATLAS</a> is to AI attacks and <a href="https://cwe.mitre.org/" target="_blank" rel="noopener noreferrer">CWE</a> is to software weaknesses: a single, citable index that a whole ecosystem can point at.</p>
<p>The catalog today names <strong>${"{TECH}"} techniques across ${"{TACTICS}"} tactics</strong>, every one mapped to at least one upstream framework, with <strong>${"{RULES}"} already bound to a live, gate-passing detection rule</strong>. That is the breadth a reference is measured by — and the rate it grows tells you the surface is still expanding.</p>
<p class="atd-note"><strong>Status:</strong> an Editor's Draft — a request for comments and an open invitation to co-author. It is not yet a ratified standard; it earns that title when it meets the §8 neutrality bar. We publish it openly to gather collaborators and mapping partners, not to claim authority.</p>`,
    },
    zh: {
      title: "Abstract (摘要)",
      body: `<p>Agentic Threat Detection (ATD) 是 agent 原生威脅技法的開放、機器可讀知識庫。agent 出錯的方式,既有的安全分類大多沒有名字 ── 一段被下毒的 tool description、一張偽造的 agent card、一次潛伏三個 session 的 memory 寫入。ATD 為每一種命名、給它一個永久 ID 與穩定定義,再對映既有的論述型框架 ── <a href="https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/" target="_blank" rel="noopener noreferrer">OWASP Agentic Top 10</a>、<a href="https://atlas.mitre.org/" target="_blank" rel="noopener noreferrer">MITRE ATLAS</a>、<a href="https://cwe.mitre.org/" target="_blank" rel="noopener noreferrer">CWE</a>、<a href="https://avidml.org/" target="_blank" rel="noopener noreferrer">AVID</a> ── 並附帶該攻擊確實發生過的真實佐證。</p>
<p>那些框架告訴你 agent <em>會出什麼錯</em>。ATD 是其下的一層,為每條技法<em>如何</em>在可觀測之處顯現命名 ── prompt、tool call、tool response、inter-agent 訊息、memory 寫入、trace。那正是偵測規則必須掛上的地方;而在技法被命名之前,每個團隊都從零重寫一遍描述。一條技法在攻擊被記錄的當下就進入目錄 ── 早於任何偵測規則的存在 ── 讓詞彙永遠領先工具,而非落後。當技法已長出一條通過閘門的偵測規則,ATD 把兩者綁定;覆蓋率是要成長的屬性,不是進入的條件。ATD 之於 agent 威脅,如同 <a href="https://atlas.mitre.org/" target="_blank" rel="noopener noreferrer">MITRE ATLAS</a> 之於 AI 攻擊、<a href="https://cwe.mitre.org/" target="_blank" rel="noopener noreferrer">CWE</a> 之於軟體弱點:一套整個生態都能指向的、可引用的索引。</p>
<p>目錄至今已為 <strong>${"{TACTICS}"} 個戰術下的 ${"{TECH}"} 條技法</strong>命名,每條至少對映一個上游框架,其中 <strong>${"{RULES}"} 條已綁定一條 live、通過閘門的偵測規則</strong>。這正是一套參考被衡量的廣度 ── 而它成長的速度,告訴你這片攻擊面仍在擴張。</p>
<p class="atd-note"><strong>狀態:</strong>Editor's Draft ── 一份 request for comments,公開邀請共同撰寫。它<strong>尚未</strong>是 ratified standard;唯有達到 §8 的中立門檻後才冠此名。我們公開它是為了徵集協作者與對映夥伴,不是宣稱權威。</p>`,
    },
  },
  {
    num: "2",
    id: "scope",
    status: "normative",
    en: {
      title: "Scope — what ATD is and is not",
      body: `<p>ATD enumerates <strong>agent-runtime threat techniques detectable in agent I/O</strong>: prompt/content, tool calls, tool responses, inter-agent messages, memory operations, traces, screen state, and payment mandates.</p>
<ul>
<li>ATD <strong>MUST NOT</strong> mint vulnerability instance identifiers. A specific CVE in a specific MCP server lives in CVE / GHSA / OSV / AVID; ATD references it, it does not replace it.</li>
<li>ATD <strong>MUST NOT</strong> present itself as a competing top-level risk taxonomy. The "top ten agentic risks" framing belongs to OWASP ASI; ATD sits beneath it and makes it runnable.</li>
<li>ATD <strong>MUST</strong> map every technique to at least one upstream framework, or document the gap where none exists yet.</li>
</ul>
<p>This boundary is deliberate. Vulnerability registries that mirrored CVE's territory (e.g. the now-archived GSD) fragmented and stalled. ATD fills the uncovered <em>executable detection</em> layer, it does not re-fight a settled lane.</p>`,
    },
    zh: {
      title: "Scope ── ATD 是什麼、不是什麼",
      body: `<p>ATD 列舉 <strong>可在 agent I/O 觀測到的 agent-runtime 威脅技法</strong>:prompt/content、tool call、tool response、inter-agent 訊息、memory 操作、trace、螢幕狀態、payment mandate。</p>
<ul>
<li>ATD <strong>MUST NOT</strong> 鑄造漏洞實例識別碼。特定 MCP server 的特定 CVE 屬於 CVE / GHSA / OSV / AVID;ATD 引用它,不取代它。</li>
<li>ATD <strong>MUST NOT</strong> 自居為競爭性的頂層風險分類。「agentic 十大風險」的框架屬於 OWASP ASI;ATD 在其下,讓它可執行。</li>
<li>ATD <strong>MUST</strong> 為每條技法至少對映一個上游框架,或在尚無對映時記錄該缺口。</li>
</ul>
<p>此邊界是刻意的。鏡像 CVE 地盤的漏洞登錄(如已封存的 GSD)碎片化而停擺。ATD 填的是無人覆蓋的 <em>可執行偵測</em> 層,不重打已定的戰場。</p>`,
    },
  },
  {
    num: "3",
    id: "model",
    status: "normative",
    en: {
      title: "Conceptual model",
      body: `<p>ATD uses two axes, borrowed from proven standards:</p>
<ul>
<li><strong>Tactic / Technique matrix</strong> (MITRE ATLAS model): a <code>Tactic</code> is the adversary's goal-phase; a <code>Technique</code> is a concrete, detectable attack pattern; a <code>Sub-technique</code> is a variant.</li>
<li><strong>Abstraction hierarchy</strong> (CWE model): each technique is tagged <code>pillar</code> / <code>class</code> / <code>base</code> / <code>variant</code>.</li>
</ul>
<p><strong>Identifiers.</strong> Tactics are <code>ATD-TA1</code> … <code>ATD-TA9</code>. Techniques are <code>ATD-T0001</code> (zero-padded, sequential, permanent, never reused); sub-techniques use dotted notation <code>ATD-T0001.001</code>. Each individual detection rule additionally carries a UUIDv4 so rules survive renaming — techniques are the catalog, rules are the executable instances bound to them.</p>
<p><strong>Maturity.</strong> Every technique and every rule carries a status on the ladder <code>experimental → test → stable</code> (plus <code>deprecated</code>). Production consumers <strong>SHOULD</strong> auto-sync only <code>stable</code>.</p>`,
    },
    zh: {
      title: "概念模型",
      body: `<p>ATD 採用兩條軸,借自已驗證的標準:</p>
<ul>
<li><strong>Tactic / Technique 矩陣</strong>(MITRE ATLAS 模型):<code>Tactic</code> 是對手的目標階段;<code>Technique</code> 是具體、可偵測的攻擊模式;<code>Sub-technique</code> 是變體。</li>
<li><strong>抽象層級</strong>(CWE 模型):每條技法標 <code>pillar</code> / <code>class</code> / <code>base</code> / <code>variant</code>。</li>
</ul>
<p><strong>識別碼。</strong>Tactic 為 <code>ATD-TA1</code> … <code>ATD-TA9</code>。Technique 為 <code>ATD-T0001</code>(補零、序列、永久、不重用);sub-technique 用點記法 <code>ATD-T0001.001</code>。每條偵測規則另帶 UUIDv4,使規則在改名後仍可追蹤 ── technique 是 catalog,rule 是綁定其上的可執行實例。</p>
<p><strong>成熟度。</strong>每條技法與規則皆帶階梯狀態 <code>experimental → test → stable</code>(加 <code>deprecated</code>)。production 消費者 <strong>SHOULD</strong> 只自動同步 <code>stable</code>。</p>`,
    },
  },
  {
    num: "5",
    id: "schema",
    status: "normative",
    en: {
      title: "Entry schema",
      body: `<p>A technique entry is a YAML/JSON document validated against a normative JSON Schema (Draft 2020-12), shipped in-repo. It is designed to be compatible with the OSV and Sigma ecosystems. Required fields:</p>
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
<p>A detection rule reuses the ATR rule schema already in production: regex/conditions, <code>true_positives</code> <strong>and</strong> <code>true_negatives</code> (a precision test), false-positive notes, response actions, and a valid <code>agent_source.type</code>.</p>`,
    },
    zh: {
      title: "Entry schema",
      body: `<p>technique entry 是 YAML/JSON 文件,對 normative JSON Schema(Draft 2020-12)驗證,隨 repo 發布,設計上與 OSV 及 Sigma 生態相容。必填欄位:</p>
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
<p>detection rule 重用已在 production 的 ATR rule schema:regex/conditions、<code>true_positives</code> <strong>與</strong> <code>true_negatives</code>(精準度測試)、false-positive 註記、response action、合法的 <code>agent_source.type</code>。</p>`,
    },
  },
  {
    num: "6",
    id: "mappings",
    status: "informative",
    en: {
      title: "Mappings &amp; interoperability",
      body: `<p>Legitimacy comes from interoperability, not from declaring authority. Every ATD technique maps to OWASP ASI, MITRE ATLAS and CWE where a slot exists; AVID and the MAESTRO layer are added where they apply. Where a technique falls in a gap no upstream framework yet names, ATD records the gap and feeds it back to those projects as a proposed technique and case study — the catalog grows by crosswalk, not by claiming a lane of its own.</p>
<p>ATD is designed to interoperate with — not compete against — <a href="https://avidml.org/" target="_blank" rel="noopener noreferrer">AVID</a>, which already operates a governed, submission-open AI vulnerability registry. ATD supplies the executable detection AVID's "Detection" report type expects.</p>`,
    },
    zh: {
      title: "對映與互通",
      body: `<p>合法性來自互通,而非自封權威。每條 ATD 技法在有對應槽時對映 OWASP ASI、MITRE ATLAS、CWE;在適用時加上 AVID 與 MAESTRO 層。當一條技法落在上游框架尚未命名的缺口,ATD 記錄該缺口,並以提議技法與案例研究回饋給那些專案 ── 目錄靠 crosswalk 成長,而非自闢一條地盤。</p>
<p>ATD 設計上與 <a href="https://avidml.org/" target="_blank" rel="noopener noreferrer">AVID</a> 互通而非競爭 ── AVID 已營運一個有治理、開放投稿的 AI 漏洞登錄。ATD 提供 AVID「Detection」報告類型所期待的可執行偵測。</p>`,
    },
  },
  {
    num: "7",
    id: "conformance",
    status: "normative",
    en: {
      title: "Conformance",
      body: `<ul>
<li>A <strong>conformant technique entry</strong> MUST validate against the JSON Schema, carry at least one framework mapping (or a documented gap), and cite at least one reference.</li>
<li>A <strong>conformant detection rule</strong> MUST pass the precision gate: every declared true-positive matches, zero false positives on the published benign corpus, and no cross-rule conflict.</li>
<li>A <strong>conformant consumer</strong> MUST honor the maturity field and SHOULD expose the <code>ATD-T####</code> id on every detection it emits.</li>
</ul>`,
    },
    zh: {
      title: "Conformance",
      body: `<ul>
<li><strong>conformant technique entry</strong> MUST 通過 JSON Schema 驗證,至少帶一個框架對映(或記錄缺口),並至少引一個 reference。</li>
<li><strong>conformant detection rule</strong> MUST 通過精準度閘:每條宣告的 true-positive 命中、對公開 benign corpus 零誤報、無跨規則衝突。</li>
<li><strong>conformant consumer</strong> MUST 尊重 maturity 欄,並 SHOULD 在每筆偵測上揭露 <code>ATD-T####</code> id。</li>
</ul>`,
    },
  },
  {
    num: "8",
    id: "governance",
    status: "informative",
    en: {
      title: "Governance &amp; status",
      body: `<p>ATD is governed by a written charter and published as an open draft and an invitation to co-author. It earns the title <em>standard</em> when it meets a concrete, public neutrality bar adopted from the OpenSSF project lifecycle — <strong>at least three maintainers across at least two organizations</strong> — and we are actively seating them.</p>
<p>Governance follows a Minimal Viable Governance charter: lazy consensus of maintainers, a simple-majority Technical Steering Committee fallback, charter amendments by a two-thirds vote, and no single-person veto. The specification is CC-BY-4.0 and forkable by design — no party can hold it hostage — with a committed roadmap to a neutral foundation home (an OpenSSF working group, or the OWASP GenAI Security Project).</p>
<p class="atd-note">Call for collaborators — if your team works on agent security, <strong>map your tooling to ATD, submit a technique, or take a maintainer seat</strong>. See <a href="/${"{LOCALE}"}/contribute">/contribute</a>.</p>`,
    },
    zh: {
      title: "治理與狀態",
      body: `<p>ATD 依書面 charter 治理,以開放草案發布,並公開邀請共同撰寫。它在達到一條具體、公開的中立門檻(採自 OpenSSF 專案生命週期:<strong>至少三名 maintainer,橫跨至少兩個組織</strong>)後冠上 <em>standard</em> 之名 ── 我們正在積極就位。</p>
<p>治理採 Minimal Viable Governance charter:maintainer 的 lazy consensus、Technical Steering Committee 簡單多數 fallback、章程修訂需三分之二投票、無單人否決。規格以 CC-BY-4.0 授權且設計上可 fork ── 無任何一方能挾持它 ── 並承諾遷往中立基金會(OpenSSF working group,或 OWASP GenAI Security Project)。</p>
<p class="atd-note">徵求協作者 ── 若你的團隊從事 agent 安全,<strong>把工具對映到 ATD、投一條技法、或擔任 maintainer 席位</strong>。見 <a href="/${"{LOCALE}"}/contribute">/contribute</a>。</p>`,
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
  const status = locale === "zh" ? ATD_STATUS_ZH : ATD_STATUS_EN;

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
            ? "agent 威脅技法權威知識庫 · 草案 RFC · 徵求協作者 · ATR 之伴隨標準"
            : "Authoritative knowledge base of agent threat techniques · draft RFC · call for collaborators · companion to ATR"}
        </p>

        <h1>Agentic Threat Detection</h1>

        <p className="atd-sub">
          {locale === "zh"
            ? "agent runtime 威脅手法的權威開放知識庫 —— 為每一種攻擊手法命名、給它一個穩定的 ID、對映到 OWASP、MITRE ATLAS、CWE、AVID,讓偵測有處可掛。如同 ATLAS 之於 AI 攻擊、CWE 之於軟體弱點:這個時代 agent 威脅的命名與索引。"
            : "The authoritative open knowledge base of agent-runtime threat techniques — it gives every attack technique a name, a stable ID, and a crosswalk to OWASP, MITRE ATLAS, CWE and AVID, so detection has somewhere to hang. What MITRE ATLAS is to AI attacks and CWE is to software weaknesses: the naming and index of agent threats for this era."}
        </p>

        <div className="doc-status not-prose" role="note">
          <strong>{status}</strong>
          <span className="pipe">·</span>
          <span><span className="opacity-70">{locale === "zh" ? "版本" : "Version"}</span> {ATD_VERSION}</span>
          <span className="pipe">·</span>
          <span><span className="opacity-70">{locale === "zh" ? "日期" : "Date"}</span> {ATD_DATE}</span>
          <span className="pipe">·</span>
          <span><span className="opacity-70">{locale === "zh" ? "正式版" : "Canonical"}</span> <a href={`/${locale}/atd`}>/atd</a></span>
          <span className="pipe">·</span>
          <span><span className="opacity-70">{locale === "zh" ? "編輯" : "Editor"}</span> Adam Lin</span>
        </div>
      </header>

      <section aria-label="coverage" className="mb-10 md:mb-12">
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { v: String(ATD_STATS.techniques), l: locale === "zh" ? "技法已編目" : "techniques cataloged" },
            { v: String(ATD_STATS.withCve), l: locale === "zh" ? "有 CVE 佐證" : "CVE-backed" },
            { v: String(ATD_STATS.withLiveRule), l: locale === "zh" ? "已綁定偵測規則(覆蓋率,非門檻)" : "bound to a rule (coverage, not a gate)" },
            { v: `${PROOF.skill.recall}% · 0 FP`, l: locale === "zh" ? `recall(skill 語料 n=${PROOF.skill.n})` : `recall · ${PROOF.skill.fp} FP (skill corpus, n=${PROOF.skill.n})` },
            { v: `${PROOF.garak.recall}%`, l: locale === "zh" ? `recall(garak 野外 n=${PROOF.garak.n})` : `recall (garak in-the-wild, n=${PROOF.garak.n})` },
          ].map((m, i) => (
            <div key={i} style={{ background: "var(--spec-tint)", borderRadius: "10px", padding: "0.9rem 1rem" }}>
              <div className="text-navy-ink" style={{ fontFamily: "var(--font-data)", fontSize: "1.35rem", fontWeight: 600, letterSpacing: "-0.01em" }}>{m.v}</div>
              <div className="text-stone" style={{ fontSize: "0.72rem", marginTop: "0.25rem", lineHeight: 1.35 }}>{m.l}</div>
            </div>
          ))}
        </div>
        <p className="text-stone" style={{ fontSize: "0.8rem", marginTop: "0.9rem", lineHeight: 1.6 }}>
          {locale === "zh" ? (
            <>ATD 的偵測規則由 ATR 發布 —— 已在 production:Microsoft Agent Governance Toolkit、Cisco AI Defense;並於 MISP/CIRCL 對映。consumer 整合的是 ATR 規則,非對本草案標準的背書。DOI{" "}<a className="text-navy underline" href={`https://doi.org/${ATD_DOI}`} target="_blank" rel="noopener noreferrer">{ATD_DOI}</a>。</>
          ) : (
            <>ATD&apos;s detection rules ship in ATR — in production in Microsoft Agent Governance Toolkit and Cisco AI Defense, and mapped in MISP/CIRCL. Consumers integrate ATR rules; this is not an endorsement of this draft standard. DOI{" "}<a className="text-navy underline" href={`https://doi.org/${ATD_DOI}`} target="_blank" rel="noopener noreferrer">{ATD_DOI}</a>.</>
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
                  {locale === "zh" ? "下載與產物" : "Downloads & artifacts"}
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
                  ? `這是完整目錄 ── ${ATD_STATS.techniques} 條技法,沿 ${ATD_TACTICS.length} 個戰術階段排列,從 MCP 協定層一路到 multi-agent 動態與 agentic commerce。每條都有一個永久 ID、一段穩定定義,並對映 OWASP ASI / MITRE ATLAS / CWE,附上真實 CVE 或研究佐證。其中 ${ATD_STATS.withLiveRule} 條已綁定一條 live 的 ATR 偵測規則 ── 其餘是僅被記錄的技法,在此地位完全相同:命名一個威脅不需要先有規則。已記錄而尚無公開實例者誠實標 research / aspirational,絕不偽裝成 CVE。每個框架識別碼都對原始來源現驗 (2026-06-14)。`
                  : `This is the full index — ${ATD_STATS.techniques} techniques laid out along ${ATD_TACTICS.length} tactic phases, from the MCP protocol layer through multi-agent dynamics to agentic commerce. Each carries a permanent ID, a stable definition, and a crosswalk to OWASP ASI / MITRE ATLAS / CWE, backed by a real CVE or research citation. ${ATD_STATS.withLiveRule} are already bound to a live ATR detection rule; the rest are documented techniques and stand on exactly equal footing here — naming a threat does not wait for a rule to exist. Documented entries with no public instance are honestly marked research / aspirational, never dressed up as a CVE. Every framework id is verified against its primary source (2026-06-14).`}
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
                              {locale === "zh" ? "live 規則 ↗" : "live rule ↗"}
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
                            <span style={{ background: "var(--ash)", color: "var(--mist)", borderRadius: "3px", padding: "2px 7px" }}>{locale === "zh" ? "前瞻(尚無實例)" : "aspirational"}</span>
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
              {locale === "zh" ? "下載與產物" : "Downloads & artifacts"}
              <InformativeBadge className="ml-2 align-middle" />
            </h2>
            <div className="spec-body">
              <ul>
                <li><a href="/atd/atd-techniques.json" target="_blank" rel="noopener noreferrer">atd-techniques.json</a> — {locale === "zh" ? "完整 enumeration(機器可讀,OSV/Sigma 相容欄位)" : "the full enumeration (machine-readable; OSV/Sigma-compatible fields)"}</li>
                <li><a href="/atd/atd-technique.schema.json" target="_blank" rel="noopener noreferrer">atd-technique.schema.json</a> — {locale === "zh" ? "normative JSON Schema (Draft 2020-12)" : "the normative JSON Schema (Draft 2020-12)"}</li>
                <li><Link href={`/${locale}/spec`}>/spec</Link> — {locale === "zh" ? "ATR 規則格式(技法綁定的可執行規則)" : "the ATR rule format (the executable rules techniques bind to)"}</li>
                <li>DOI <a href={`https://doi.org/${ATD_DOI}`} target="_blank" rel="noopener noreferrer">{ATD_DOI}</a> — {locale === "zh" ? "研究與引用 artifact" : "research & citation artifact"}</li>
              </ul>
            </div>
          </section>

          <hr className="my-12 border-fog" />
          <p className="spec-meta">
            {locale === "zh" ? "編輯" : "Editor"}: Adam Lin —{" "}
            {locale === "zh" ? "規格" : "Specification"} CC-BY-4.0 ·{" "}
            {locale === "zh" ? "Schema 與工具" : "Schema &amp; tooling"} Apache-2.0 ·{" "}
            {locale === "zh" ? "規則庫" : "Rule corpus"} MIT — ISO 8601 {ATD_DATE} —{" "}
            {locale === "zh"
              ? "Editor's Draft,治理前;非 ratified standard。"
              : "Editor's Draft, pre-governance; not a ratified standard."}
          </p>
        </div>
      </div>
    </main>
  );
}
