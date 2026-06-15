import { Reveal } from "@/components/Reveal";
import { locales, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";
import Link from "next/link";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Governance — ATR",
  description:
    "ATR governance model: named maintainers, merge policy, succession plan, and the lead maintainer's conflict-of-interest disclosure.",
};

export default async function GovernancePage({
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
          {zh ? "治理" : "Governance"}
        </div>
      </Reveal>
      <Reveal delay={0.05}>
        <h1 className="font-display text-[clamp(28px,4vw,48px)] font-extrabold tracking-[-2px] leading-[1.08] text-ink mb-4">
          {zh ? "治理是寫在公開記錄裡的。" : "Governance is on the public record."}
        </h1>
      </Reveal>
      <Reveal delay={0.1}>
        <p className="text-base text-stone font-light max-w-[640px] leading-[1.8] mb-12">
          {zh
            ? "一個標準的可信度，來自它的流程可以被任何人審查——不是來自單一權威說了算。ATR 是 MIT 授權的開放標準，不隸屬任何公司。誰維護、規則怎麼進、spec 怎麼改、首席維護者有什麼利益衝突，全部寫在這一頁，也全部寫在 GitHub 上可被審計。"
            : "A standard earns trust when its process can be audited by anyone — not when a single authority vouches for it. ATR is an MIT-licensed open standard, not owned by any company. Who maintains it, how a rule gets in, how the spec changes, what the lead maintainer's conflicts are — all of it is on this page, and all of it is auditable on GitHub."}
        </p>
      </Reveal>

      {/* Current maintainers */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "現任維護者" : "Current maintainers"}
        </div>
        <h2 className="font-display text-xl font-extrabold tracking-[-0.5px] mb-6">
          {zh ? "負責規則品質、PR 審核、與發布。" : "Responsible for rule quality, PR review, and releases."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog mb-12">
          <div className="p-6 md:p-8 border-b border-fog">
            <div className="flex flex-col md:flex-row md:items-start md:gap-8">
              <div className="md:w-48 flex-shrink-0 mb-4 md:mb-0">
                <div className="font-display text-base font-bold text-ink">Adam Lin</div>
                <div className="font-data text-xs text-stone mt-1">林冠辛</div>
                <div className="font-data text-xs text-blue mt-2">Lead Maintainer</div>
              </div>
              <div>
                <p className="text-sm text-graphite leading-[1.7] mb-3">
                  {zh
                    ? "ATR 的創始人與主要維護者。負責規則品質門檻設計（RFC-001）、社群外展、以及生態系整合審核。GitHub: eeee2345 (Adamthereal)。"
                    : "Founder and primary maintainer of ATR. Responsible for RFC-001 quality standard design, community outreach, and ecosystem integration review. GitHub: eeee2345 (Adamthereal)."}
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
          <div className="p-6 md:p-8 bg-ash/30">
            <p className="text-sm text-stone leading-[1.7]">
              {zh
                ? "ATR 目前是單一維護者啟動的——和 Linus Torvalds 1991 年的 Linux、Florian Roth 的 Sigma 同一條路徑：一個人開頭，定義格式與品質門檻，社群再接手治理。這是誠實的現狀，不是道歉。第二位維護者的招募正在進行（見下方條件），把標準託管到中立基金會（Linux Foundation、OpenSSF 或同級）的評估也在路線圖上。終點是 Technical Steering Committee；起點本來就只能有一個人。"
                : "ATR was started by a single maintainer — the same path Linus Torvalds took with Linux in 1991, and Florian Roth with Sigma: one person defines the format and the quality bar, the community takes over governance. That is the honest present state, not an apology. Recruitment of a second maintainer is underway (criteria below), and evaluating transfer to a neutral foundation (Linux Foundation, OpenSSF, or equivalent) is on the roadmap. The destination is a Technical Steering Committee; every standard that reaches one started with someone willing to write the first rule."}
            </p>
          </div>
        </div>
      </Reveal>

      {/* Merge policy */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "合併政策" : "Merge policy"}
        </div>
        <h2 className="font-display text-xl font-extrabold tracking-[-0.5px] mb-4">
          {zh ? "每條規則要過六道關才能 merge。" : "Six gates before any rule merges."}
        </h2>
      </Reveal>
      <Reveal delay={0.05}>
        <p className="text-sm text-graphite leading-[1.7] max-w-[640px] mb-5">
          {zh
            ? "這些閘是機器執行的，每一道都在公開的 CI log 裡留痕——任何人都能看到一條規則為什麼通過、或為什麼被擋。品質不靠維護者的判斷力背書，而靠可重跑的測試。"
            : "These gates are machine-enforced, and every one leaves a trace in a public CI log — anyone can see why a rule passed, or why it was blocked. Quality is not vouched for by a maintainer's judgment; it is demonstrated by tests anyone can re-run."}
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="space-y-px bg-fog mb-12">
          {[
            {
              gate: zh ? "1 · 語法驗證" : "1 · Schema validation",
              desc: zh
                ? "合法 YAML schema、有效 regex（無 ReDoS）、至少 1 TP + 1 TN。"
                : "Valid YAML schema, valid regex (no ReDoS), at least 1 TP and 1 TN.",
            },
            {
              gate: zh ? "2 · RFC-001 品質門檻" : "2 · RFC-001 quality gate",
              desc: zh
                ? "信心分數（精準度、野外驗證、覆蓋深度、已知規避手法的文件）決定規則進哪一條偵測車道。分數沒到，規則不會被升到 enforce——但仍可以 advisory 形式存在。門檻是公開的公式，不是維護者的喜好。"
                : "A confidence score — precision, in-the-wild validation, coverage depth, documented evasions — decides which detection lane a rule enters. Below the bar, a rule is never promoted to enforce, but may still exist as advisory. The threshold is a published formula, not a maintainer's preference.",
            },
            {
              gate: zh ? "3 · 良性語料 0 FP" : "3 · Benign corpus 0 FP",
              desc: zh
                ? "新規則必須在每個 PR 的良性語料閘上 0 誤報。這是 merge 時的最低門檻；發布後，誤報率會在更大的良性語料上逐車道公開量測，不靠單一數字蓋過。"
                : "A new rule must record zero false positives on the per-PR benign corpus gate. This is the floor at merge time; after release, false-positive rates are measured lane by lane on a larger benign corpus and published, never hidden behind a single figure.",
            },
            {
              gate: zh ? "4 · 跨規則衝突檢查" : "4 · Cross-rule conflict check",
              desc: zh
                ? "新規則不得與現有規則在相同輸入產生矛盾結果。"
                : "New rule must not conflict with existing rules on the same input.",
            },
            {
              gate: zh ? "5 · 人工審核" : "5 · Human review",
              desc: zh
                ? "維護者審核 regex 形狀、test case 覆蓋、以及來源文件。Stable 等級需要 human-reviewed provenance。"
                : "Maintainer reviews regex shape, test case coverage, and source citation. Stable tier requires human-reviewed provenance.",
            },
            {
              gate: zh ? "6 · PR 合規性" : "6 · PR compliance",
              desc: zh
                ? "每個 PR 最多 10 條新規則。test_cases 必須包含 true_positives + true_negatives。"
                : "Maximum 10 new rules per PR. test_cases must include true_positives and true_negatives.",
            },
          ].map((item) => (
            <div key={item.gate} className="bg-paper p-5 md:p-6">
              <div className="font-data text-xs text-blue tracking-wide uppercase mb-2">{item.gate}</div>
              <p className="text-sm text-graphite leading-[1.7]">{item.desc}</p>
            </div>
          ))}
        </div>
      </Reveal>

      {/* Decision-making */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "決策流程" : "Decision-making"}
        </div>
        <h2 className="font-display text-xl font-extrabold tracking-[-0.5px] mb-4">
          {zh ? "每種改動有自己的審核門檻。" : "Different changes have different bars."}
        </h2>
      </Reveal>
      <Reveal delay={0.05}>
        <p className="text-sm text-graphite leading-[1.7] max-w-[640px] mb-5">
          {zh
            ? "改一條規則和改 spec 不是同一回事。規則錯了可以撤、可以修；spec 是每一個相容引擎共同遵守的契約，動它要給所有 implementer 看得到、來得及反應的時間。門檻的高低，照的是這個改動會牽動多少人。"
            : "Changing a rule and changing the spec are not the same act. A wrong rule can be deprecated or revised; the spec is the contract every conforming engine relies on, so changing it has to be visible to every implementer with time to react. The bar scales with how many people a change moves."}
        </p>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="border border-fog mb-12">
          {[
            {
              kind: zh ? "新增規則" : "Add a rule",
              quorum: zh
                ? "1 名維護者核可 + 自動安全閘通過"
                : "1 maintainer approval + automated safety-gate pass",
              detail: zh
                ? "規則 PR 走六道安全閘(見上面合併政策),通過後一位維護者人工 review 即可 merge。不需要二人核可,因為安全閘已經涵蓋了規則的客觀品質。"
                : "Rule PRs run through the six safety gates (see Merge policy above). Once they pass, a single maintainer review is sufficient to merge. Two-reviewer requirement is not enforced because the safety gates already cover objective quality.",
            },
            {
              kind: zh ? "修改 spec(ATR-SPEC-v1)" : "Spec amendment (ATR-SPEC-v1)",
              quorum: zh
                ? "RFC issue 先開 + 14 天公開評論窗口(複雜提案延長至 30 天)+ 2 名維護者核可"
                : "RFC issue opened first + 14-day public comment window (extended to 30 for complex proposals) + 2 maintainer approvals",
              detail: zh
                ? "spec 是所有相容引擎的契約。任何 spec 變動都要先以 issue 形式提出 RFC、開 14 天公開評論窗口(複雜提案延長至 30 天)讓所有 implementer 看到,然後才接受 PR。在目前 BDFL 階段,「2 名核可」將由首席維護者加上一名外部 reviewer(待指定後)滿足。TSC 成立後改為 TSC 過半數核可。"
                : "The spec is the contract between all conforming engines. Any spec change is opened first as an RFC issue with a 14-day public comment window (extended to 30 for complex proposals) so every implementer sees it, then the PR is accepted. Under the current BDFL phase the 'two approvals' bar will be satisfied by the lead maintainer plus one external reviewer once designated. When the TSC is formed the bar becomes a TSC majority.",
            },
            {
              kind: zh ? "breaking change(SemVer 主版號)" : "Breaking change (SemVer major bump)",
              quorum: zh
                ? "spec amendment 流程 + 30 天提前公告 + CHANGELOG 條目"
                : "Spec-amendment process + 30-day advance notice + CHANGELOG entry",
              detail: zh
                ? "任何破壞 rule schema、engine API、或既有 rule_id 語意的改動都算 breaking。提前 30 天在 GOVERNANCE.md 標題、CHANGELOG、@adopters 通知,讓上游採用者有時間應對。"
                : "Any change that breaks the rule schema, the engine API, or the semantics of an existing rule_id counts as breaking. A 30-day advance notice goes out via GOVERNANCE.md, CHANGELOG, and an @adopters notification so upstream adopters have time to react.",
            },
            {
              kind: zh ? "新增 / 撤換維護者" : "Add or remove a maintainer",
              quorum: zh
                ? "所有現任維護者核可 + 被邀請者書面同意"
                : "All current maintainers approve + the invited party agrees in writing",
              detail: zh
                ? "目前只有一名維護者,所以加第二位維護者要這名維護者本人同意。當有 2+ 名維護者時,新增需要全員核可。撤換需要 2/3 多數(BDFL 階段不適用)。"
                : "There is currently one maintainer, so adding a second requires that maintainer to agree. Once 2+ maintainers exist, additions require unanimous approval. Removal requires a 2/3 majority (not applicable under BDFL).",
            },
            {
              kind: zh ? "把 rule 標記為 deprecated" : "Deprecate a rule",
              quorum: zh
                ? "1 名維護者核可,加 30 天 grace period"
                : "1 maintainer approval, with a 30-day grace period",
              detail: zh
                ? "deprecated 規則仍會留在 corpus 但 engine MUST NOT 預設啟用。30 天後可以從 corpus 刪除;之前已採用的下游可以 pin 到 deprecated 版本。"
                : "Deprecated rules remain in the corpus but engines MUST NOT enable them by default. After 30 days the rule may be removed from the corpus; downstream adopters who depended on it can pin to a deprecated version.",
            },
          ].map((row) => (
            <div key={row.kind} className="p-5 md:p-6 border-b border-fog last:border-b-0">
              <div className="grid grid-cols-1 md:grid-cols-[200px_1fr] gap-3 md:gap-6">
                <div>
                  <div className="font-display text-sm font-semibold text-ink">{row.kind}</div>
                </div>
                <div>
                  <div className="font-data text-xs text-blue tracking-wide uppercase mb-2">
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
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "工作小組" : "Working group"}
        </div>
        <h2 className="font-display text-xl font-extrabold tracking-[-0.5px] mb-4">
          {zh ? "目前還沒有,但路徑開放。" : "There isn't one yet, and the path to forming one is open."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="bg-paper border border-fog p-6 md:p-8 mb-12 text-sm text-graphite leading-[1.7]">
          <p className="mb-3">
            {zh
              ? "OASIS CTI、OpenTelemetry SIG、OWASP Working Group 都開定期會議。ATR 還沒到需要排程會議的規模——目前所有討論都在 GitHub Issues 與 PR 上非同步、公開、留痕進行。一個只有少數 implementer 的標準，不該先有委員會再有需求。"
              : "OASIS CTI, OpenTelemetry SIGs, and OWASP Working Groups all run scheduled meetings. ATR is not yet at the scale where standing meetings earn their cost — for now every discussion happens asynchronously, in the open, on the public record in GitHub Issues and PRs. A standard with a handful of implementers should not stand up a committee before there is demand for one."}
          </p>
          <p className="mb-3">
            {zh
              ? "成立工作小組的路徑是開放的，而且是需求驅動的：如果你有實際的整合工作、想推動 spec 的某個方向、或代表一個 implementer 想要在標準化過程中有結構化的話語權，開一個標題以 [WG-proposal] 開頭的 issue。當 3 個或以上獨立的 implementer 表達相同需求，維護者會發起固定週期（雙週）的工作小組會議。觸發條件寫在這裡，誰都能援引。"
              : "The path to forming one is open, and it is demand-driven: if you have active integration work, want to push the spec in a particular direction, or represent an implementer that wants structured voice in the process, open an issue titled with the prefix [WG-proposal]. When three or more independent implementers express the same need, the maintainers will schedule a recurring (bi-weekly) working-group meeting. The trigger is written here, and anyone may invoke it."}
          </p>
        </div>
      </Reveal>

      {/* Become a maintainer */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "想成為維護者" : "Become a maintainer"}
        </div>
        <h2 className="font-display text-xl font-extrabold tracking-[-0.5px] mb-4">
          {zh ? "我們正在主動招募。" : "We are actively recruiting."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="bg-paper border border-fog p-6 md:p-8 mb-12 text-sm text-graphite leading-[1.7]">
          <p className="mb-3">
            {zh
              ? "單一維護者是 ATR 目前已知的最大結構風險，這一點我們公開講。從一個人到一個 Technical Steering Committee（TSC），是每個開放標準都走過的路——分散治理的方式，是真的有人 merge 過足夠多的東西、值得拿到 commit 權。我們正在主動招募第二位、第三位維護者。"
              : "A single maintainer is the largest known structural risk to ATR, and we state it plainly. The path from one person to a Technical Steering Committee (TSC) is the one every open standard walks — governance distributes when contributors have merged enough to have earned commit rights, not before. We are actively recruiting a second and third maintainer."}
          </p>
          <p className="mb-3 font-semibold text-ink">
            {zh ? "候選條件:" : "Candidate criteria:"}
          </p>
          <ul className="list-disc pl-6 mb-3 space-y-1">
            <li>
              {zh
                ? "過去六個月內,在 ATR repo merge 過至少三個 substantive PR(新規則、schema 修正、engine 改進、或文件實質改寫)"
                : "Merged at least three substantive PRs in the ATR repo in the prior six months (new rules, schema fixes, engine improvements, or substantive documentation rewrites)"}
            </li>
            <li>
              {zh
                ? "熟悉 ATR-SPEC-v1 的內容到能解釋 conformance 條款的程度"
                : "Familiar enough with ATR-SPEC-v1 to explain its conformance clauses"}
            </li>
            <li>
              {zh
                ? "能配合非同步審核(沒有實時要求,但 PR 平均應在 7 天內收到第一次審核回應)"
                : "Able to accommodate asynchronous review (no real-time requirement, but PRs should receive a first review response within an average of 7 days)"}
            </li>
            <li>
              {zh
                ? "在公開場合(GitHub、issue 留言、conference)代表 ATR 時,語氣維持中立、不暗示任何商業利益"
                : "When representing ATR publicly (GitHub, issue comments, conferences), maintains a neutral register and does not imply any commercial interest"}
            </li>
          </ul>
          <p>
            {zh ? "申請方式:" : "How to apply: "}
            {zh ? "寄信至 " : ""}
            <a
              href="mailto:adam@agentthreatrule.org?subject=ATR%20maintainer%20application"
              className="text-blue hover:underline"
            >
              adam@agentthreatrule.org
            </a>
            {zh
              ? " 主旨「ATR maintainer application」,內容包含你近期的 PR 連結與你想接哪一塊(rules / spec / engine / documentation)。"
              : " with subject 'ATR maintainer application'. Include links to your recent PRs and which area you want to take on (rules / spec / engine / documentation)."}
          </p>
        </div>
      </Reveal>

      {/* Succession plan */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "繼承計畫" : "Succession plan"}
        </div>
        <h2 className="font-display text-xl font-extrabold tracking-[-0.5px] mb-4">
          {zh ? "如果首席維護者無法履行職責。" : "If the lead maintainer becomes unavailable."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="bg-paper border border-fog p-6 md:p-8 mb-12">
          <div className="space-y-4 text-sm text-graphite leading-[1.7]">
            <p>
              {zh
                ? "短期（30 天內）：GitHub 的 CODEOWNERS 檔案與 CI 自動化維護繼續運作，已合併的規則繼續透過 npm 發布。ATR 不依賴單一伺服器或閉源系統——規則是純文字 YAML，任何人都可以 fork。"
                : "Short term (within 30 days): The CODEOWNERS file and CI automation continue to function on GitHub. Merged rules continue to publish via npm. ATR has no dependency on a single server or closed system — rules are plain-text YAML and anyone can fork."}
            </p>
            <p>
              {zh
                ? "中期:第二位維護者(招募進行中)接任 PR 審核職責。如果 30 天後仍未找到正式維護者,外部臨時維護者的招募條件是:在過去六個月內 merge 過至少三個 substantive PR、對 schema 有實作熟悉度、且能配合非同步審核。具體人選不會在這個頁面公告;當邀請發出且對方同意後,姓名才會出現在「現任維護者」區塊。"
                : "Medium term: a second maintainer (recruitment ongoing) takes over PR review. If none is identified within 30 days, interim maintainers will be sought from external contributors who meet the following criteria: merged at least three substantive PRs in the prior six months, demonstrated familiarity with the schema implementation, and able to accommodate asynchronous review. Specific names are NOT published on this page until the invitation has been sent AND the candidate has accepted — at which point the new maintainer appears under 'Current maintainers' above."}
            </p>
            <p>
              {zh
                ? "長期：ATR 路線圖包含將標準轉移至中立基金會（Linux Foundation 或 OpenSSF）的評估。轉移條件：有兩名以上外部維護者，以及至少一個組織願意提供資源支持治理。"
                : "Long term: The ATR roadmap includes evaluating transfer to a neutral foundation (Linux Foundation or OpenSSF). Transfer requires: two or more external maintainers, and at least one organization willing to fund governance overhead."}
            </p>
          </div>
        </div>
      </Reveal>

      {/* Conflict of interest */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "利益衝突揭露" : "Conflict-of-interest disclosure"}
        </div>
        <h2 className="font-display text-xl font-extrabold tracking-[-0.5px] mb-4">
          {zh ? "為什麼揭露這件事。" : "Why this disclosure exists."}
        </h2>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="bg-paper border border-fog p-6 md:p-8 mb-12">
          <div className="space-y-4 text-sm text-graphite leading-[1.7]">
            <p>
              {zh
                ? "ATR（Agent Threat Rules）是 MIT 授權的開放標準，由 Agent-Threat-Rule GitHub 組織維護。首席維護者在 AI agent 安全領域另持有商業利益（commercial affiliation）。我們不掩蓋這件事，而是寫下來——揭露本身就是治理機制。一個標準的中立性，不靠維護者沒有利益來證明，而靠他的決策過程公開到任何人都能檢查有沒有被利益扭曲。"
                : "ATR (Agent Threat Rules) is an MIT-licensed open standard maintained under the Agent-Threat-Rule GitHub organization. The lead maintainer also holds a commercial affiliation in AI agent security. We do not hide this; we write it down — the disclosure itself is the governance mechanism. A standard's neutrality is not proven by a maintainer having no interests, but by a decision process open enough that anyone can check whether those interests bent it."}
            </p>
            <p>
              {zh
                ? "界限：ATR 的規則、CHANGELOG、benchmark 資料、以及文件不得被任何商業利益所操控。ATR 的 issue tracker 與 PR review 流程對所有人開放，包括該商業利益的競爭對手——他們可以提規則、可以審你的 PR、可以 fork 整套標準。GOVERNANCE.md 在 GitHub 上公開查閱。中立不是宣稱來的，是這些開放的入口逐一證成的。"
                : "The boundary: ATR's rules, CHANGELOG, benchmark data, and documentation must not be distorted by any commercial interest. ATR's issue tracker and PR review process is open to everyone — including competitors of that commercial interest, who may propose rules, review pull requests, and fork the entire standard. GOVERNANCE.md is publicly auditable on GitHub. Neutrality is not asserted; it is what these open doors, one by one, demonstrate."}
            </p>
            <p>
              {zh
                ? "如果你觀察到任何違反這個界限的情況，請在 GitHub 開 issue 或寄信至 contact@agentthreatrule.org。"
                : "If you observe any violation of this boundary, please open an issue on GitHub or email contact@agentthreatrule.org."}
            </p>
          </div>
        </div>
      </Reveal>

      {/* Contribution rights */}
      <Reveal>
        <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-3">
          {zh ? "貢獻者權利" : "Contributor rights"}
        </div>
      </Reveal>
      <Reveal delay={0.1}>
        <div className="bg-ash p-6 md:p-8 mb-12 text-sm text-graphite leading-[1.7]">
          <p className="mb-3">
            {zh
              ? "所有貢獻都以 MIT 授權發布。貢獻者保留以任何方式使用其攻擊研究的所有權利——ATR 只攜帶偵測，不佔有研究本身。"
              : "All contributions are published under MIT license. Contributors retain all rights to use their attack research in any form — ATR carries the detection, not ownership of the research."}
          </p>
          <p>
            {zh
              ? "貢獻者的名字出現在規則的 author 欄位和 metadata_provenance.discovered_by 欄位。當 MISP 匯出到 STIX，當 NIST 引用規則，署名隨著傳遞。"
              : "A contributor's name appears in the rule's author field and metadata_provenance.discovered_by field. When MISP exports to STIX, when NIST cites the rule, attribution travels with it."}
          </p>
        </div>
      </Reveal>

      {/* Links */}
      <Reveal>
        <div className="flex flex-wrap gap-4">
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/GOVERNANCE.md"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline"
          >
            {zh ? "在 GitHub 查看 GOVERNANCE.md" : "View GOVERNANCE.md on GitHub"} &rarr;
          </a>
          <span className="text-fog">|</span>
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/CODE_OF_CONDUCT.md"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline"
          >
            {zh ? "行為準則" : "Code of Conduct"} &rarr;
          </a>
          <span className="text-fog">|</span>
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/SECURITY.md"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline"
          >
            {zh ? "安全揭露政策" : "Security policy"} &rarr;
          </a>
          <span className="text-fog">|</span>
          <a
            href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/CONTRIBUTORS.md"
            target="_blank"
            rel="noopener noreferrer"
            className="font-data text-xs text-blue hover:underline"
          >
            {zh ? "貢獻者名單" : "Contributors list"} &rarr;
          </a>
          <span className="text-fog">|</span>
          <Link href={`/${locale}/about`} className="font-data text-xs text-blue hover:underline">
            {zh ? "關於 ATR" : "About ATR"} &rarr;
          </Link>
        </div>
      </Reveal>
    </div>
  );
}
