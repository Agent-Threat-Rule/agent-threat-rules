import { Reveal } from "@/components/Reveal";
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
    path: "/governance",
    title: "Governance",
    description:
      "How ATR is governed: who maintains it, how rules merge, what happens if the lead maintainer steps away, and the lead maintainer's conflict-of-interest disclosure.",
  });
}

export default async function GovernancePage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";

  return (
    <Phrased>
    <div className="pt-20 pb-20 px-6 md:px-14 max-w-[972px]">
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "治理" : "Governance"}
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <h1 className="text-[32px] md:text-[48px] leading-[1.12] tracking-[-0.01em] font-medium text-ink mb-4">
          {zh ? "ATR 怎麼治理，都寫在公開紀錄裡。" : "Governance is on the public record."}
        </h1>
      </Reveal>
      <Reveal delay={0.1}>
        <p className="text-base text-stone font-light max-w-[640px] leading-[1.8] mb-12">
          {zh
            ? "誰在維護、規則怎麼進來、spec 怎麼改、首席維護者有什麼利益衝突，全部寫在這一頁，也都能在 GitHub 上查。ATR 是 MIT 授權的開放標準，不隸屬任何公司。任何人都能檢查流程，標準才站得住腳，不用靠哪個權威背書。"
            : "Who maintains ATR, how a rule gets in, how the spec changes, what conflicts the lead maintainer has: all of it is on this page, and all of it can be audited on GitHub. ATR is an MIT-licensed open standard, and no company owns it. A standard earns trust when anyone can audit its process. No authority has to vouch for it."}
        </p>
      </Reveal>

      {/* Current maintainers */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "現任維護者" : "Current maintainers"}
        </div>
        <h2 className="font-display text-xl font-medium tracking-[-0.5px] mb-6">
          {zh ? "負責規則品質、PR 審查和發版。" : "Responsible for rule quality, PR review and releases."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border-t border-ink mb-12">
          <div className="py-6 border-b border-fog">
            <div className="flex flex-col md:flex-row md:items-start md:gap-8">
              <div className="md:w-48 flex-shrink-0 mb-4 md:mb-0">
                <div className="font-display text-base font-bold text-ink">Adam Lin</div>
                <div className="font-data text-xs text-stone mt-1">林冠辛</div>
                <div className="font-data text-xs text-stone mt-2">Lead Maintainer</div>
              </div>
              <div>
                <p className="text-sm text-graphite leading-[1.7] mb-3">
                  {zh
                    ? "ATR 的創辦人和主要維護者。負責設計規則品質門檻（RFC-001）、對外聯繫社群，也審查外部整合。GitHub：eeee2345（Adamthereal）。"
                    : "Founder and main maintainer of ATR. Owns the RFC-001 quality bar, community outreach and the review of ecosystem integrations. GitHub: eeee2345 (Adamthereal)."}
                </p>
                <a
                  href="mailto:adam@agentthreatrule.org"
                  className="font-data text-xs text-blue hover:underline"
                >
                  adam@agentthreatrule.org
                </a>
              </div>
            </div>
          </div>
          <div className="py-6 border-b border-fog">
            <p className="text-sm text-stone leading-[1.7]">
              {zh
                ? "除了首席維護者，GitHub 上另有兩位維護者有寫入權限，還有一位協作者負責整理 issue。不過到目前為止，PR 的合併仍集中在首席維護者手上，這是接下來要分散的部分。招募更多維護者的條件寫在下面。路線圖上有一項是評估把標準託管給中立基金會，例如 Linux Foundation、OpenSSF 或同等級的組織；最終目標是成立技術指導委員會（TSC）。"
                : "Besides the lead maintainer, two more maintainers have write access on GitHub, and one collaborator triages issues. Merging pull requests still rests with the lead maintainer, and spreading that out comes next. The criteria for more maintainers are below. Evaluating a transfer to a neutral foundation, such as the Linux Foundation, OpenSSF or an equivalent, is on the roadmap. The goal is a Technical Steering Committee."}
            </p>
          </div>
        </div>
      </Reveal>

      {/* Merge policy */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "合併政策" : "Merge policy"}
        </div>
        <h2 className="font-display text-xl font-medium tracking-[-0.5px] mb-4">
          {zh ? "每條規則要過六道關，才能合併。" : "Six gates before any rule merges."}
        </h2>
      </Reveal>
      <Reveal delay={0.05}>
        <p className="text-sm text-graphite leading-[1.7] max-w-[640px] mb-5">
          {zh
            ? "第 5 道是人工審查，其餘五道由機器執行，每一道都在公開的 CI log 留下紀錄。一條規則為什麼通過、為什麼被擋，誰都看得到。品質不只靠維護者的眼光，還有任何人都能重跑的測試。"
            : "Gate 5 is a human review. Machines enforce the other five, and each leaves a trace in a public CI log. Anyone can see why a rule passed or why it was blocked. Quality does not rest on a maintainer's judgment alone. It also rests on tests anyone can re-run."}
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border-t border-ink mb-12">
          {[
            {
              gate: zh ? "1 · 語法驗證" : "1 · Schema validation",
              desc: zh
                ? "YAML schema 合法，regex 有效且沒有 ReDoS，至少 1 個 TP 和 1 個 TN。"
                : "A valid YAML schema, a valid regex with no ReDoS, and at least 1 TP and 1 TN.",
            },
            {
              gate: zh ? "2 · RFC-001 品質門檻" : "2 · RFC-001 quality gate",
              desc: zh
                ? "信心分數決定規則進哪一條偵測車道。分數看的是精確度、野外驗證、覆蓋深度，以及已知的繞過手法有沒有寫下來。分數不夠的規則永遠不會升到 enforce，但仍可以用 advisory 的形式存在。門檻是一條公開的公式，誰都能拿來重算。"
                : "A confidence score decides which detection lane a rule enters. It weighs precision, in-the-wild validation, coverage depth and documented evasions. A rule below the bar is never promoted to enforce, though it may still exist as advisory. The threshold is a published formula that anyone can recompute.",
            },
            {
              gate: zh ? "3 · 良性語料 0 FP" : "3 · Benign corpus 0 FP",
              desc: zh
                ? "每個 PR 都會跑良性語料閘，新規則在上面必須是 0 誤報。這是合併時的最低門檻。發布之後，誤報率會在更大的良性語料上逐車道量測、公開，不會被單一數字蓋過去。"
                : "A new rule must record zero false positives on the benign corpus gate that runs on every PR. That is the floor at merge time. After release, false-positive rates are measured lane by lane on a larger benign corpus and published, never hidden behind a single figure.",
            },
            {
              gate: zh ? "4 · 跨規則衝突檢查" : "4 · Cross-rule conflict check",
              desc: zh
                ? "同一個輸入，新規則不能跟現有規則給出互相矛盾的結果。"
                : "On the same input, a new rule must not conflict with existing rules.",
            },
            {
              gate: zh ? "5 · 人工審查" : "5 · Human review",
              desc: zh
                ? "維護者審 regex 的形狀、test case 的覆蓋，還有來源文件。要到 Stable 等級，來源必須經過人工審查。"
                : "A maintainer reviews the regex shape, test-case coverage and source citation. The stable tier requires provenance that a human has reviewed.",
            },
            {
              gate: zh ? "6 · PR 規範" : "6 · PR compliance",
              desc: zh
                ? "每個 PR 最多 10 條新規則。test_cases 必須同時有 true_positives 和 true_negatives。"
                : "At most 10 new rules per PR. test_cases must include both true_positives and true_negatives.",
            },
          ].map((item) => (
            <div key={item.gate} className="py-4 border-b border-fog">
              <div className="text-[13px] text-stone mb-2">{item.gate}</div>
              <p className="text-sm text-graphite leading-[1.7]">{item.desc}</p>
            </div>
          ))}
        </div>
      </Reveal>

      {/* Decision-making */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "決策流程" : "Decision-making"}
        </div>
        <h2 className="font-display text-xl font-medium tracking-[-0.5px] mb-4">
          {zh ? "改什麼，就過什麼樣的關。" : "Different changes have different bars."}
        </h2>
      </Reveal>
      <Reveal delay={0.05}>
        <p className="text-sm text-graphite leading-[1.7] max-w-[640px] mb-5">
          {zh
            ? "改一條規則跟改 spec 是兩回事。規則錯了，可以撤下，也可以修正。spec 是每一個符規引擎都依賴的契約，要改，就得讓所有實作者都看得到，也來得及反應。門檻多高，看這個改動會牽動多少人。"
            : "Changing a rule and changing the spec are different acts. A wrong rule can be deprecated or revised. The spec is the contract every conforming engine relies on, so a change to it has to reach every implementer with time to react. The bar rises with the number of people a change affects."}
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border-t border-ink mb-12">
          {[
            {
              kind: zh ? "新增規則" : "Add a rule",
              quorum: zh
                ? "1 位維護者核可，加上自動安全閘通過"
                : "1 maintainer approval + automated safety-gate pass",
              detail: zh
                ? "規則 PR 先跑六道安全閘（見上面的合併政策）。通過之後，一位維護者人工審過就能合併。不要求兩人核可，因為規則的客觀品質已經由安全閘把關。"
                : "Rule PRs run through the six safety gates (see Merge policy above). Once they pass, one maintainer's review is enough to merge. A second reviewer is not required, because the gates already cover objective quality.",
            },
            {
              kind: zh ? "修改 spec（SPEC.md）" : "Spec amendment (SPEC.md)",
              quorum: zh
                ? "先開 RFC issue，公開徵求意見 14 天（複雜提案延長到 30 天），再由 2 位維護者核可"
                : "RFC issue first + 14-day public comment window (30 days for complex proposals) + 2 maintainer approvals",
              detail: zh
                ? "spec 是所有相容引擎之間的契約。任何 spec 變動，都要先用 issue 提出 RFC，公開徵求意見 14 天（複雜提案延長到 30 天），讓每個實作者都看到，之後才收 PR。現在是 BDFL 階段，「2 位核可」是首席維護者加上另一位維護者。TSC 成立之後，改成 TSC 過半數核可。"
                : "The spec is the contract between all conforming engines. Any spec change starts as an RFC issue with a 14-day public comment window (30 days for complex proposals), so every implementer sees it. Only then is the PR accepted. In the current BDFL phase, the two approvals are the lead maintainer's and one other maintainer's. When the TSC is formed, the bar becomes a TSC majority.",
            },
            {
              kind: zh ? "破壞性變更（SemVer 主版號）" : "Breaking change (SemVer major bump)",
              quorum: zh
                ? "走修改 spec 的流程，加上 30 天前公告，以及一筆 CHANGELOG 紀錄"
                : "Spec-amendment process + 30-day advance notice + CHANGELOG entry",
              detail: zh
                ? "會破壞 rule schema、engine API，或改變既有 rule_id 語意的改動，都算破壞性變更。要提前 30 天在 GOVERNANCE.md 標題、CHANGELOG 公告，並通知 @adopters，讓上游採用者有時間因應。"
                : "Any change that breaks the rule schema, the engine API or the meaning of an existing rule_id is breaking. Notice goes out 30 days ahead through GOVERNANCE.md, the CHANGELOG and an @adopters notification, so upstream adopters have time to react.",
            },
            {
              kind: zh ? "新增或撤換維護者" : "Add or remove a maintainer",
              quorum: zh
                ? "所有現任維護者核可，加上受邀者書面同意"
                : "All current maintainers approve + the invited person agrees in writing",
              detail: zh
                ? "新增要所有現任維護者核可。撤換要 2/3 多數，BDFL 階段不適用。"
                : "Adding a maintainer needs every current maintainer's approval. Removal needs a 2/3 majority, which does not apply under BDFL.",
            },
            {
              kind: zh ? "把規則標為 deprecated" : "Deprecate a rule",
              quorum: zh
                ? "1 位維護者核可，另有 30 天緩衝期"
                : "1 maintainer approval, with a 30-day grace period",
              detail: zh
                ? "deprecated 的規則仍留在規則庫裡，但引擎 MUST NOT 預設啟用。30 天後可以從規則庫移除。已經在用的下游，可以釘在 deprecated 的版本。"
                : "A deprecated rule stays in the corpus, but engines MUST NOT enable it by default. After 30 days it may be removed from the corpus. Downstream adopters who depended on it can pin to a deprecated version.",
            },
          ].map((row) => (
            <div key={row.kind} className="py-5 border-b border-fog">
              <div className="grid grid-cols-1 md:grid-cols-[200px_1fr] gap-3 md:gap-6">
                <div>
                  <div className="font-display text-sm font-semibold text-ink">{row.kind}</div>
                </div>
                <div>
                  <div className="text-[13px] text-stone mb-2">
                    {row.quorum}
                  </div>
                  <p className="text-sm text-graphite leading-[1.7]">{row.detail}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </Reveal>

      {/* Working group */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "工作小組" : "Working group"}
        </div>
        <h2 className="font-display text-xl font-medium tracking-[-0.5px] mb-4">
          {zh ? "目前還沒有。成立的條件寫在下面。" : "There isn't one yet. The conditions for starting one are written below."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border-t border-ink pt-6 mb-12 text-sm text-graphite leading-[1.7]">
          <p className="mb-3">
            {zh
              ? "OASIS CTI、OpenTelemetry SIG、OWASP 工作小組都有固定會議。ATR 還沒到需要固定開會的規模。現在所有討論都在 GitHub Issues 和 PR 上非同步進行，公開，也都留下紀錄。實作者才幾個，沒人提出需求就先設委員會，沒有必要。"
              : "OASIS CTI, the OpenTelemetry SIGs and OWASP working groups all hold scheduled meetings. ATR is not yet big enough for standing meetings to be worth their cost. For now every discussion happens asynchronously and in the open, on the record in GitHub Issues and PRs. A standard with a handful of implementers should not set up a committee before anyone asks for one."}
          </p>
          <p className="mb-3">
            {zh
              ? "要不要成立，看需求。你如果手上有實際在做的整合、想把 spec 往某個方向推，或代表一個實作者，想在標準化過程裡有固定的發言管道，就開一個標題以 [WG-proposal] 開頭的 issue。只要有 3 個以上彼此獨立的實作者提出同樣的需求，維護者就會開始每兩週一次的工作小組會議。條件就寫在這裡，誰都可以拿來用。"
              : "Whether one forms depends on demand. If you have integration work under way, want to push the spec in a particular direction, or represent an implementer that wants a structured voice in the process, open an issue whose title starts with [WG-proposal]. When three or more independent implementers ask for the same thing, the maintainers will schedule a recurring working-group meeting every two weeks. The trigger is written here, and anyone may invoke it."}
          </p>
        </div>
      </Reveal>

      {/* Become a maintainer */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "想成為維護者" : "Become a maintainer"}
        </div>
        <h2 className="font-display text-xl font-medium tracking-[-0.5px] mb-4">
          {zh ? "正在積極招募。" : "Actively recruiting."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border-t border-ink pt-6 mb-12 text-sm text-graphite leading-[1.7]">
          <p className="mb-3">
            {zh
              ? "合併權集中在一個人手上，是 ATR 目前已知最大的結構風險。要分散出去，得等貢獻者合併過足夠多的 PR，夠資格拿到 commit 權限。更多維護者正在招募。"
              : "Merge rights resting with one person is the largest known structural risk to ATR. They spread out once contributors have merged enough pull requests to earn commit rights. More maintainers are being recruited."}
          </p>
          <p className="mb-3 font-semibold text-ink">
            {zh ? "候選條件：" : "Candidate criteria:"}
          </p>
          <ul className="list-disc pl-6 mb-3 space-y-1">
            <li>
              {zh
                ? "過去六個月內，在 ATR repo 合併過至少三個有實質內容的 PR（新規則、schema 修正、引擎改進，或文件的實質改寫）"
                : "At least three substantive PRs merged in the ATR repo in the past six months (new rules, schema fixes, engine improvements, or substantive documentation rewrites)"}
            </li>
            <li>
              {zh
                ? "熟悉 SPEC.md，能解釋其中的符規條款"
                : "Knows SPEC.md well enough to explain its conformance clauses"}
            </li>
            <li>
              {zh
                ? "能配合非同步審查。不需要即時回應，但 PR 平均應在 7 天內收到第一次審查回覆"
                : "Can review asynchronously. There is no real-time requirement, but PRs should get a first review response within 7 days on average"}
            </li>
            <li>
              {zh
                ? "在公開場合（GitHub、issue 留言、研討會）代表 ATR 時，語氣保持中立，不暗示任何商業利益"
                : "Keeps a neutral tone when representing ATR in public (GitHub, issue comments, conferences), and does not imply any commercial interest"}
            </li>
          </ul>
          <p>
            {zh ? "申請方式：" : "How to apply: "}
            {zh ? "寄信到 " : "write to "}
            <a
              href="mailto:adam@agentthreatrule.org?subject=ATR%20maintainer%20application"
              className="text-blue hover:underline"
            >
              adam@agentthreatrule.org
            </a>
            {zh
              ? "，主旨寫「ATR maintainer application」。信裡附上你最近的 PR 連結，以及你想負責哪一塊（rules / spec / engine / documentation）。"
              : " with the subject 'ATR maintainer application'. Include links to your recent PRs and the area you want to take on (rules / spec / engine / documentation)."}
          </p>
        </div>
      </Reveal>

      {/* Succession plan */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "繼承計畫" : "Succession plan"}
        </div>
        <h2 className="font-display text-xl font-medium tracking-[-0.5px] mb-4">
          {zh ? "如果首席維護者沒辦法繼續。" : "If the lead maintainer becomes unavailable."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border-t border-ink pt-6 mb-12">
          <div className="space-y-4 text-sm text-graphite leading-[1.7]">
            <p>
              {zh
                ? "短期（30 天內）：GitHub 上的 CODEOWNERS 檔和 CI 照常運作，PR 照樣能審查、合併。但發新的 npm 版本，要有發布權限的維護者用 2FA 核准，CI 只能先 stage。ATR 不依賴任何單一伺服器或封閉系統。規則是純文字 YAML，誰都可以 fork。"
                : "Short term (within 30 days): the CODEOWNERS file and CI keep running on GitHub, and pull requests can still be reviewed and merged. A new npm release, though, needs a maintainer with publish rights to approve it with 2FA; CI can only stage it. ATR does not depend on a single server or a closed system. The rules are plain-text YAML, and anyone can fork them."}
            </p>
            <p>
              {zh
                ? "中期：由其他現任維護者接手 PR 審查和合併。人手不夠時，會從外部貢獻者裡找臨時維護者，條件是：過去六個月內合併過至少三個有實質內容的 PR、實際熟悉 schema 的實作，而且能配合非同步審查。邀請發出、對方也同意之前，不會公布人選。"
                : "Medium term: the other current maintainers take over PR review and merging. If that is not enough, interim maintainers will be sought among external contributors who have merged at least three substantive PRs in the past six months, have shown hands-on familiarity with the schema implementation, and can review asynchronously. No candidate is named before the invitation has been sent and accepted."}
            </p>
            <p>
              {zh
                ? "長期：ATR 的路線圖包括評估把標準移交給中立基金會（Linux Foundation 或 OpenSSF）。移交的條件是：有兩位以上的外部維護者，以及至少一個組織願意提供資源支持治理。"
                : "Long term: the ATR roadmap includes evaluating a transfer to a neutral foundation (Linux Foundation or OpenSSF). A transfer requires two or more external maintainers, and at least one organization willing to fund the overhead of governance."}
            </p>
          </div>
        </div>
      </Reveal>

      {/* Conflict of interest */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "利益衝突揭露" : "Conflict-of-interest disclosure"}
        </div>
        <h2 className="font-display text-xl font-medium tracking-[-0.5px] mb-4">
          {zh ? "為什麼要揭露。" : "Why this disclosure exists."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border-t border-ink pt-6 mb-12">
          <div className="space-y-4 text-sm text-graphite leading-[1.7]">
            <p className="text-ink">
              {zh
                ? "利益揭露：維護者創辦並控制 PANGUARD AI, INC.，這家公司販售以 ATR 為基礎的 agent 資安產品。"
                : "Interests: the maintainer founded and controls PANGUARD AI, INC., which sells AI agent security products built on ATR."}
            </p>
            <p>
              {zh
                ? "ATR（Agent Threat Rules）是 MIT 授權的開放標準，在 Agent-Threat-Rule 這個 GitHub 組織底下維護。上面這件事不藏，直接寫下來，揭露本身就是治理的一部分。維護者確實有利益，所以 ATR 把決策過程公開，讓任何人都能檢查這些利益有沒有影響決定。"
                : "ATR (Agent Threat Rules) is an MIT-licensed open standard maintained under the Agent-Threat-Rule GitHub organization. The interest above is not hidden. Writing it down is part of the governance. The lead maintainer does have interests. So the decision process is open, and anyone can check whether those interests bent a decision."}
            </p>
            <p>
              {zh
                ? "界線是：ATR 的規則、CHANGELOG、benchmark 資料和文件，都不得被任何商業利益左右。ATR 的 issue tracker 和 PR 審查對所有人開放，包括這個商業利益的競爭對手。他們可以提規則、審 PR，也可以把整套標準 fork 走。GOVERNANCE.md 在 GitHub 上公開，誰都能查。"
                : "The boundary: ATR's rules, CHANGELOG, benchmark data and documentation must not be distorted by any commercial interest. ATR's issue tracker and PR review are open to everyone, including competitors of that commercial interest. They may propose rules, review pull requests and fork the entire standard. GOVERNANCE.md is public on GitHub for anyone to audit."}
            </p>
            <p>
              {zh
                ? "如果你看到有人越過這條界線，請在 GitHub 開 issue，或寫信到 contact@agentthreatrule.org。"
                : "If you see this boundary being crossed, open an issue on GitHub or email contact@agentthreatrule.org."}
            </p>
          </div>
        </div>
      </Reveal>

      {/* Contribution rights */}
      <Reveal>
        <div className="text-[13px] text-stone mb-3">
          {zh ? "貢獻者權利" : "Contributor rights"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border-t border-ink pt-6 mb-12 text-sm text-graphite leading-[1.7]">
          <p className="mb-3">
            {zh
              ? "所有貢獻都以 MIT 授權發布。你的攻擊研究，你保留以任何形式使用的全部權利。ATR 只取用其中的偵測規則，研究本身仍歸你。"
              : "All contributions are published under the MIT license. Contributors keep every right to use their attack research in any form. ATR carries the detection, not ownership of the research."}
          </p>
          <p>
            {zh
              ? "貢獻者的名字寫在規則的 author 欄位。"
              : "A contributor's name goes in the rule's author field."}
          </p>
        </div>
      </Reveal>

      {/* Links */}
      <Reveal>
        <div className="flex flex-wrap gap-x-6 gap-y-2">
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/GOVERNANCE.md"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline"
          >
            {zh ? "在 GitHub 查看 GOVERNANCE.md" : "View GOVERNANCE.md on GitHub"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
          </a>
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/CODE_OF_CONDUCT.md"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline"
          >
            {zh ? "行為準則" : "Code of Conduct"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
          </a>
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/SECURITY.md"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline"
          >
            {zh ? "安全揭露政策" : "Security policy"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
          </a>
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/CONTRIBUTORS.md"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline"
          >
            {zh ? "貢獻者名單" : "Contributors list"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
          </a>
          <Link href={`/${locale}/about`} className="font-data text-xs text-blue hover:underline">
            {zh ? "關於 ATR" : "About ATR"}<Sign name="diple" size={10} className="ml-1.5 align-[-1px]" />
          </Link>
        </div>
      </Reveal>
    </div>
    </Phrased>
  );
}
