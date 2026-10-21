import { Reveal } from "@/components/Reveal";
import { loadSiteStats } from "@/lib/stats";
import { REPO_BLOB_URL, count, currentRecallSentence, figureMeasurements, findBenchmark, measuredStamp, recallLanes } from "@/lib/recall";
import { locales, type Locale } from "@/lib/i18n";
import { RED_TEAM_TOOLS } from "@/lib/red-team-tools";
import { ablationLanes } from "@/lib/ablation";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Red Team — Your attack becomes the standard | ATR",
  description:
    "ATR is an open detection standard fed by red-team research. A probe found today becomes a versioned rule that propagates to Cisco AI Defense, MISP, and OWASP — keeping defenders evolving at the same speed as attackers. Attribution stays attached to the rule ID, permanently.",
};

interface AttributionStat {
  number: string;
  label: string;
  detail: string;
}

const ATTRIBUTION_STATS: AttributionStat[] = [
  {
    number: "2h 16m",
    label: "Copilot PR to merged rule",
    detail:
      "2026-05-07 Microsoft Security disclosed Semantic Kernel CVE-2026-26030. 2026-05-10 the ATR maintainer filed AGT#1937 mapping it to ATR rules; 2026-05-11 06:07 UTC, after an AGT maintainer assigned that issue to it, a Microsoft Copilot SWE Agent opened a regression-test PR presuming ATR already covered it. 08:22 UTC the paired rules were merged into ATR; 08:24 UTC v2.1.2 published on npm. Once the gap was reported, the loop to a shared detection closed in hours, not committee cycles.",
  },
  {
    number: "5",
    label: "Independent organizations have merged ATR work",
    detail:
      'Microsoft Agent Governance Toolkit (example directories). Cisco AI Defense (rule pack in skill-scanner). CIRCL/MISP (taxonomies + galaxy merged by the project lead). OWASP A-S-R-H (lead merged with "Welcome to the team"). Gen Digital Sage (Norton / Avast parent security team merged). A rule written once becomes vocabulary shared across organizations — which is the point of a standard.',
  },
  {
    number: "RULECOUNT",
    label: "Rules, each with an author line and a stable ID",
    detail:
      "Every rule carries an author field and a stable ATR-YYYY-NNNNN ID that never changes after publication; many also record the corpus or advisory they came from in metadata_provenance. A contributor who brings the attack can be credited on the author line.",
  },
  {
    number: "0 FP",
    label: "Required of a rule pull request before it merges",
    detail:
      "The rule safety gate (scripts/check-rules-safety.ts) runs in the required Validate Rules & Build check on every pull request and checks the rules that pull request adds or changes: own true positives must match, 0 FP across the benign, extended, code and research-mention corpora, 0 cross-rule conflicts, and own true_negative coverage. The gate prints the sample counts it used on every run — those are the figures of record, not a number on this page. It is the merge condition for rule pull requests now; earlier batches did not all pass it. Re-run at main b9d16840 on 2026-10-22, 33 of the 71 rules of the 2026-05-12 sprint and 4 of the 29 of the 2026-06 mega-scan fail it, the same as on 2026-10-19 (data/gate-reruns/2026-10-19_red-team-rule-batches.json). The standard would rather miss a clever variant than corrupt the corpus with a false positive — and it publishes its real per-lane figures rather than a single flattering one.",
  },
];

interface ContributorBenefit {
  for: string;
  benefit: string;
  proof: string;
}

const CONTRIBUTOR_BENEFITS: ContributorBenefit[] = [
  {
    for: "Academic researchers",
    benefit:
      "A citable artifact paired with the attack you described — one with a stable ID, real downstream consumers, and fire counts in production telemetry, not just a paper that sits behind a paywall.",
    proof:
      "Your name can go on the rule file's author line, next to a rule ID that never changes after publication.",
  },
  {
    for: "Corporate red teams",
    benefit:
      "The variant your team found stops being an internal finding and becomes shared defensive vocabulary. Your team appears as the discoverer in the rule corpus that Cisco AI Defense, MISP, OWASP A-S-R-H, and Gen Digital Sage all pull from.",
    proof:
      "Microsoft's Copilot SWE Agent, assigned an ATR maintainer's issue that mapped two CVEs to ATR rules, opened a PR presuming ATR coverage (AGT #1937 → #1981, merged 2026-05-11). Originating an ATR-2026-NNNNN rule is durable, verifiable provenance — it sits in a public corpus, not a slide.",
  },
  {
    for: "Independent researchers",
    benefit:
      "Ship a detection without hand-writing regex. Submit positive and negative examples; a maintainer writes the regex from them and runs it through the full gate.",
    proof:
      "Your benign look-alikes become the rule's true negatives. The regex must match none of them and hold 0 FP on the benign corpora before it merges: the rule safety gate every rule pull request has to pass now. Rules from earlier batches did not all pass it; see the re-run record in data/gate-reruns/2026-10-19_red-team-rule-batches.json.",
  },
  {
    for: "Bug bounty hunters",
    benefit:
      "The same attack does two jobs: the bounty payout, and a permanent rule that catches it everywhere afterward. Composes cleanly with Huntr.dev, HackerOne AI scope, and Protect AI bounty programmes.",
    proof:
      "ATR proposals are MIT-licensed and citable. No NDA conflict — the bounty programme owns the responsible-disclosure window; ATR ships the detection only after disclosure, with public attribution to the finder.",
  },
];

export default async function RedTeamPage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : "en") as Locale;
  const zh = locale === "zh";
  const stats = loadSiteStats();
  const garak = findBenchmark(stats, "garak");
  const vendorSuites = findBenchmark(stats, "vendor-guardrail-suites");
  const vendorAblation = vendorSuites ? ablationLanes(vendorSuites) : null;

  const inProduction = RED_TEAM_TOOLS.filter(
    (t) => t.status === "in-production" || t.status === "corpus",
  );
  const inReview = RED_TEAM_TOOLS.filter((t) => t.status === "in-review");

  return (
    <div className="pt-20 pb-24">
      {/* ============================================================
          HERO — bolder claim, concrete cadence number up front
      ============================================================ */}
      <section className="px-6 max-w-[1120px] mx-auto mb-24 md:mb-32">
        <Reveal>
          <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-6">
            {zh ? "獻給紅隊" : "For red teams"}
          </div>
        </Reveal>
        <Reveal delay={0.1}>
          <h1 className="font-display text-[clamp(40px,6.5vw,80px)] font-extrabold tracking-[-3px] leading-[0.98] mb-8 max-w-[920px]">
            {zh ? (
              <>
                你找到攻擊。
                <br />
                我們發 detection 規則。
                <br />
                <span className="text-blue">2 小時 16 分鐘。</span>
              </>
            ) : (
              <>
                Find the attack.
                <br />
                We ship the rule.
                <br />
                <span className="text-blue">2 hours 16 minutes.</span>
              </>
            )}
          </h1>
        </Reveal>
        <Reveal delay={0.2}>
          <p className="font-display text-[clamp(18px,2.2vw,24px)] text-stone font-light leading-snug mb-10 max-w-[760px]">
            {zh ? (
              <>
                一個攻擊被結晶成一條規則，那條規則就成了所有防禦者共用的字彙。Cisco AI Defense 的 skill-scanner 內建一份、MISP export
                到 STIX 時帶著發現者的署名。這是一道閉環飛輪：攻擊餵養標準，標準與威脅同速演化。
              </>
            ) : (
              <>
                One attack, crystallized into one rule, becomes a word every
                defender shares. Cisco AI
                Defense ships it in skill-scanner, MISP exports it to STIX with
                the discoverer&apos;s name attached. A closed-loop flywheel:
                attacks feed the standard, and the standard evolves at the same
                speed as the threat.
              </>
            )}
          </p>
        </Reveal>
        <Reveal delay={0.3}>
          <div className="flex flex-wrap gap-3">
            <a
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=red-team-probe.yml"
              target="_blank"
              rel="noopener noreferrer"
              className="bg-ink text-paper px-7 py-3 rounded-sm text-base font-semibold hover:bg-ink/85 transition-colors"
            >
              {zh ? "送一個 probe →" : "Submit a probe →"}
            </a>
            <a
              href="#how-it-works"
              className="border border-fog text-ink px-7 py-3 rounded-sm text-base font-semibold hover:bg-ash/40 transition-colors"
            >
              {zh ? "怎麼跑 →" : "How it works →"}
            </a>
          </div>
        </Reveal>
      </section>

      {/* ============================================================
          THE BIG NUMBERS — 4 confident hits, expanded
      ============================================================ */}
      <section className="px-6 max-w-[1120px] mx-auto mb-24 md:mb-32">
        <Reveal>
          <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-10">
            {zh ? "為什麼一個攻擊該進標準" : "Why an attack belongs in the standard"}
          </div>
        </Reveal>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-12">
          {ATTRIBUTION_STATS.map((s, i) => (
            <Reveal key={i} delay={0.1 + i * 0.08}>
              <div className="border-l-2 border-blue pl-6">
                <div className="font-display text-[clamp(36px,4.5vw,56px)] font-extrabold tracking-[-2px] text-ink mb-2 leading-none">
                  {s.number === "RULECOUNT" ? stats.ruleCount : s.number}
                </div>
                <div className="font-display text-base font-semibold text-ink mb-3">
                  {s.label}
                </div>
                <p className="text-sm text-stone leading-relaxed">{s.detail}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ============================================================
          WHAT YOU GET — the value prop, segmented by who you are
      ============================================================ */}
      <section className="px-6 max-w-[1120px] mx-auto mb-24 md:mb-32">
        <Reveal>
          <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-4">
            {zh ? "你能拿到什麼" : "What you get"}
          </div>
          <h2 className="font-display text-[clamp(28px,4vw,44px)] font-extrabold tracking-[-2px] leading-[1.05] mb-12 max-w-[720px]">
            {zh
              ? "你的攻擊進了標準之後，留下什麼 — 依你是誰而不同。"
              : "What your attack leaves behind once it's in the standard — depending on who you are."}
          </h2>
        </Reveal>
        <div className="space-y-8">
          {CONTRIBUTOR_BENEFITS.map((b, i) => (
            <Reveal key={i} delay={0.05 + i * 0.05}>
              <div className="grid grid-cols-1 md:grid-cols-12 gap-6 md:gap-8 py-6 border-t border-fog">
                <div className="md:col-span-3">
                  <div className="font-data text-xs text-stone tracking-wide mb-1 uppercase">
                    {zh ? "適用對象" : "For"}
                  </div>
                  <div className="font-display text-base font-semibold text-ink">
                    {b.for}
                  </div>
                </div>
                <div className="md:col-span-9">
                  <p className="text-base text-ink leading-relaxed mb-3 font-medium">
                    {b.benefit}
                  </p>
                  <p className="text-sm text-stone leading-relaxed">
                    {b.proof}
                  </p>
                </div>
              </div>
            </Reveal>
          ))}
        </div>
      </section>

      {/* ============================================================
          HOW IT WORKS — a maintainer converts the probe
      ============================================================ */}
      <section
        id="how-it-works"
        className="bg-ink text-paper px-6 py-20 md:py-24 mb-24 md:mb-32"
      >
        <div className="max-w-[1120px] mx-auto">
          <Reveal>
            <div className="font-data text-xs font-medium text-paper/60 tracking-[3px] uppercase mb-4">
              {zh
                ? "送一個 probe 之後會發生什麼"
                : "What happens after you submit"}
            </div>
            <h2 className="font-display text-[clamp(28px,4vw,44px)] font-extrabold tracking-[-2px] leading-[1.05] mb-12 max-w-[720px]">
              {zh
                ? "Probe 進來、maintainer 寫 regex、quality gate 全綠才 merge。"
                : "Probe in. A maintainer writes the regex. Quality gate validates. Merge if green."}
            </h2>
          </Reveal>

          <div className="space-y-12">
            <Reveal delay={0.1}>
              <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
                <div className="md:col-span-2 font-display text-5xl font-extrabold text-paper/40 leading-none">
                  01
                </div>
                <div className="md:col-span-10">
                  <h3 className="font-display text-xl font-bold mb-3">
                    {zh ? "你填表單" : "You fill the form"}
                  </h3>
                  <p className="text-base text-paper/80 leading-relaxed mb-2">
                    {zh
                      ? "3 個攻擊樣本、3 個 benign lookalike、攻擊類別、來源論文/repo。3-5 分鐘。"
                      : "3 attack samples, 3 benign lookalikes, attack category, source paper / repo. Takes 3-5 minutes."}
                  </p>
                  <p className="text-sm text-paper/60">
                    {zh
                      ? "沒有 schema 要學、沒有 YAML 要寫、不用 fork repo。"
                      : "No schema to learn. No YAML to write. No fork."}
                  </p>
                </div>
              </div>
            </Reveal>

            <Reveal delay={0.15}>
              <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
                <div className="md:col-span-2 font-display text-5xl font-extrabold text-paper/40 leading-none">
                  02
                </div>
                <div className="md:col-span-10">
                  <h3 className="font-display text-xl font-bold mb-3">
                    {zh
                      ? "Maintainer 從你的樣本寫 regex"
                      : "A maintainer writes the regex from your samples"}
                  </h3>
                  <p className="text-base text-paper/80 leading-relaxed mb-2">
                    {zh
                      ? "Maintainer 審你的 issue，從你的 positive examples 寫 detection regex，你的 benign lookalike 則成為 true negatives。你也可以自己提 regex，留在 PR comment 或另開一條 PR。"
                      : "A maintainer reviews your issue and writes a detection regex from your positive examples; your benign lookalikes become the true negatives. You can also propose a regex yourself, in a PR comment or in a PR of your own."}
                  </p>
                  <p className="text-sm text-paper/60">
                    {zh
                      ? "Gate（你的 PR 合併前必須通過）= 自己 TP 必須 100% 命中 + benign、extended、code、research-mention corpus 全部 0 FP + 跨規則 0 衝突。樣本數以 gate 執行時印出的為準。較早批次的規則並非全部通過，重跑紀錄見 data/gate-reruns/2026-10-19_red-team-rule-batches.json。"
                      : "Gate (your pull request must pass it to merge) = your TPs must match 100% + 0 FP on the benign, extended, code and research-mention corpora + 0 cross-rule conflicts. The gate prints the sample counts it used. Rules from earlier batches did not all pass it; the re-run record is data/gate-reruns/2026-10-19_red-team-rule-batches.json."}
                  </p>
                </div>
              </div>
            </Reveal>

            <Reveal delay={0.2}>
              <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
                <div className="md:col-span-2 font-display text-5xl font-extrabold text-paper/40 leading-none">
                  03
                </div>
                <div className="md:col-span-10">
                  <h3 className="font-display text-xl font-bold mb-3">
                    {zh
                      ? "Gate 過了 → 完整規則送 PR"
                      : "Gate clears → complete rule on a PR"}
                  </h3>
                  <p className="text-base text-paper/80 leading-relaxed mb-2">
                    {zh
                      ? "不論 regex 是誰寫的，都會審 regex shape 是否太字面、需不需要 generalize。Gate 沒過就留在 proposal，繼續收緊 regex（仍然會用你的 test cases）。"
                      : "Whoever wrote the regex, it gets a shape review: is it too literal, can it generalize? If the gate doesn't clear, it stays a proposal while the regex is tightened (still using your test cases as ground truth)."}
                  </p>
                </div>
              </div>
            </Reveal>

            <Reveal delay={0.25}>
              <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
                <div className="md:col-span-2 font-display text-5xl font-extrabold text-paper/40 leading-none">
                  04
                </div>
                <div className="md:col-span-10">
                  <h3 className="font-display text-xl font-bold mb-3">
                    {zh
                      ? "規則自動往下游傳"
                      : "Rule auto-propagates downstream"}
                  </h3>
                  <p className="text-base text-paper/80 leading-relaxed mb-2">
                    {zh
                      ? "Cisco AI Defense 跟 release tag、MISP taxonomy + galaxy 每次 release 拉、OWASP A-S-R-H 在 fixture 中引用 rule ID。這是飛輪的下半圈:一個攻擊變成一條規則,一條規則變成所有防禦者共用的字彙。"
                      : "Cisco AI Defense pins to release tags. MISP taxonomy + galaxy pull on every release. OWASP A-S-R-H references rule IDs in fixtures. This is the back half of the flywheel: one attack becomes one rule, and one rule becomes vocabulary every defender shares."}
                  </p>
                  <p className="text-sm text-paper/60">
                    {zh
                      ? "Microsoft Copilot 的 regression PR 從開 PR 到對應規則合併進 ATR 用了 2 小時 16 分鐘（06:07 → 08:22 UTC）,兩分鐘後 v2.1.2 發布到 npm。標準與威脅同速演化,靠的就是這個節奏。"
                      : "Microsoft Copilot's regression PR went from opened to the matching rules merged into ATR in 2h 16m (06:07 → 08:22 UTC); v2.1.2 reached npm two minutes later. That cadence is how a standard stays level with the threat instead of lagging it."}
                  </p>
                </div>
              </div>
            </Reveal>
          </div>
        </div>
      </section>

      {/* ============================================================
          RED TEAM TOOLS IN MOTION — only actual red team tooling
      ============================================================ */}
      <section className="px-6 max-w-[1120px] mx-auto mb-24 md:mb-32">
        <Reveal>
          <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-4">
            {zh ? "攻擊側的工具與語料" : "Offensive tools and corpora"}
          </div>
          <h2 className="font-display text-[clamp(28px,4vw,40px)] font-extrabold tracking-[-2px] leading-[1.05] mb-4 max-w-[720px]">
            {zh
              ? "攻擊側的工具與語料,正在餵養標準。你的工具可以是下一個。"
              : "The offensive side is already feeding the standard. Your tool can be next."}
          </h2>
          <p className="text-base text-stone font-light max-w-[640px] mb-12">
            {zh
              ? "這些是真的紅隊工具（offensive testing）與對抗語料 — 每一個都是飛輪的入口。防禦端框架在 /ecosystem。"
              : "These are red-team tools — offensive testing frameworks and adversarial corpora. Each is an entry point into the flywheel. Defensive frameworks live on /ecosystem."}
          </p>
        </Reveal>

        <Reveal>
          <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-4">
            {zh
              ? `已合併上游或已消化語料 (${inProduction.length})`
              : `Merged upstream or corpus ingested (${inProduction.length})`}
          </div>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="space-y-px bg-fog mb-12">
            {inProduction.map((t) => (
              <div key={t.name} className="bg-paper p-6 md:p-8">
                <div className="grid grid-cols-1 md:grid-cols-12 gap-6">
                  <div className="md:col-span-3">
                    <h3 className="font-display text-lg font-bold text-ink mb-1">
                      {t.name}
                    </h3>
                    <div className="font-data text-xs text-stone">{t.org}</div>
                    <div className="font-data text-xs text-green mt-2 uppercase tracking-wide">
                      {t.status === "corpus"
                        ? zh
                          ? "資料集已消化"
                          : "Corpus ingested"
                        : zh
                          ? "已合併上游"
                          : "Merged upstream"}
                    </div>
                  </div>
                  <div className="md:col-span-9">
                    <p className="text-sm text-stone leading-relaxed mb-2">
                      {t.hook}
                    </p>
                    <p className="text-base text-ink leading-relaxed mb-3">
                      {t.what_atr_did}
                      {currentRecallSentence(stats, t.figures ?? [])}
                    </p>
                    <div className="flex flex-wrap gap-3">
                      <a
                        href={t.homepage}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-data text-xs text-blue hover:underline"
                      >
                        {zh ? "工具 →" : "Tool →"}
                      </a>
                      {t.prUrl && (
                        <a
                          href={t.prUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-data text-xs text-blue hover:underline"
                        >
                          {t.prUrl.includes("/commit/") ? "Commit →" : "PR →"}
                        </a>
                      )}
                      {figureMeasurements(stats, t.figures ?? []).map(({ m, label }) => (
                        <a
                          key={m.measurement_file}
                          href={`${REPO_BLOB_URL}${m.measurement_file}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="font-data text-xs text-blue hover:underline"
                        >
                          {zh ? `${label} 量測檔 →` : `${label} measurement →`}
                        </a>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Reveal>

        <Reveal>
          <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-4">
            {zh
              ? `仍開著的提案 (${inReview.length})`
              : `Open proposals (${inReview.length})`}
          </div>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-fog">
            {inReview.map((t) => (
              <a
                key={t.name}
                href={t.prUrl ?? t.homepage}
                target="_blank"
                rel="noopener noreferrer"
                className="bg-paper p-6 hover:bg-ash/30 transition-colors"
              >
                <div className="font-display text-base font-bold text-ink mb-1">
                  {t.name}
                </div>
                <div className="font-data text-xs text-stone mb-3">{t.org}</div>
                <p className="text-sm text-stone leading-relaxed mb-3">
                  {t.hook}
                </p>
                <p className="text-sm text-ink leading-relaxed">
                  {t.what_atr_did}
                  {currentRecallSentence(stats, t.figures ?? [])}
                </p>
              </a>
            ))}
          </div>
        </Reveal>
      </section>

      {/* ============================================================
          CONTINUOUS CORPUS INTEGRATION — renamed from sprint framing
      ============================================================ */}
      <section className="px-6 max-w-[1120px] mx-auto mb-24 md:mb-32">
        <Reveal>
          <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-4">
            {zh ? "持續語料庫整合" : "Continuous corpus integration"}
          </div>
          <h2 className="font-display text-[clamp(24px,3.4vw,36px)] font-extrabold tracking-[-2px] leading-tight mb-4 max-w-[720px]">
            {zh
              ? "5 個語料庫 · 71 條新規則 · HackAPrompt 召回率 28.6% → 66.0%（2026-05-12 該次 sprint，載入全部規則，在挖出規則的同一份 4,780 筆子集上量測，屬樣本內）"
              : "5 corpora · 71 new rules · HackAPrompt recall 28.6% → 66.0% (2026-05-12 sprint, every rule loaded, measured on the 4,780-prompt subset the rules were mined from, so in-sample)"}
          </h2>
          <p className="text-base text-stone font-light max-w-[640px] mb-4">
            {zh
              ? "2026-05-12：11 個並行 agent 消化五個外部語料庫。該次 sprint 的兩個 commit（e9efefdd、92c0d0fe）新增 71 個規則檔，ATR-2026-00452..00522；v2.2.0 changelog 寫的 75 條，另外算進了同一天稍早（commit 80dbd0ab，在 sprint 的兩個 commit 之前）加入的 4 條 CVE 規則（00448..00451）。詳細版本記錄在 /changelog。"
              : "2026-05-12: 11 parallel agents ingested five external corpora. The sprint's two commits (e9efefdd, 92c0d0fe) added 71 rule files, ATR-2026-00452..00522; the 75 in the v2.2.0 changelog also counts four CVE rules (00448..00451) added earlier the same day, in commit 80dbd0ab, before the sprint commits. Full version record at /changelog."}
          </p>
          <p className="text-base text-stone font-light max-w-[640px] mb-4">
            {zh
              ? "上面兩個 HackAPrompt 數字是重跑出來的：在固定的 4,780 筆子集上（固定 dataset revision 與亂數種子抽樣），分別於 sprint 前一個 commit（3a6145b7，偵測 1,368 筆）與 sprint 的發布 commit（92c0d0fe，偵測 3,154 筆）執行，載入全部規則，也就是今天 hunt lane 載入的範圍。28.6% 本身也屬樣本內：從同一份子集挖出的 ATR-2026-00442..00447 當時已經載入。當時公布的 66.2% 在 sprint 的兩個 commit（e9efefdd、92c0d0fe）都無法重現（最高 66.0%），已撤回。現在的 hunt / enforce 數字與消融參考值見上方 HackAPrompt 條目，重跑步驟見 data/hackaprompt/METHOD.md。"
              : "Both HackAPrompt figures are re-runs on a fixed 4,780-prompt subset (a seeded sample at a pinned dataset revision): at the commit before the sprint (3a6145b7, 1,368 detected) and at the sprint's release commit (92c0d0fe, 3,154 detected), with every rule loaded, which is what the hunt lane loads today. The 28.6% is itself in-sample: ATR-2026-00442..00447, mined from the same subset, were already loaded. The 66.2% published at the time could not be reproduced at the sprint commits e9efefdd and 92c0d0fe (66.0% at best) and is withdrawn. Current hunt and enforce figures, and the ablation reference, are in the HackAPrompt entry above; the re-run procedure is in data/hackaprompt/METHOD.md."}
          </p>
          <p className="text-base text-stone font-light max-w-[640px] mb-10">
            {zh
              ? `現在的規則來自 CVE 與安全公告掃描、benchmark 漏報挖掘與貢獻者，每一條都經由維護者合併的 pull request 進入 main。從六月起，標準從 462 條成長到目前的 ${stats.ruleCount} 條（發布於 npm 上的 agent-threat-rules）。`
              : `Rules now come from CVE and advisory sweeps, benchmark-miss mining and contributors, and each one reaches main through a pull request a maintainer merges. Since June the standard has grown from 462 to the current ${stats.ruleCount} rules (published as agent-threat-rules on npm).`}
          </p>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-fog mb-8">
            {[
              { corpus: "HackAPrompt", samples: zh ? "4,780（601,757 筆中以固定種子抽出的子集）" : "4,780 (seeded subset of 601,757)", rules: "5", ruleIds: "ATR-2026-00452..00456", recall: zh ? "28.6% → 66.0%（hunt，載入全部規則，樣本內；於 3a6145b7 與 92c0d0fe 重跑）" : "28.6% → 66.0% (hunt, every rule loaded, in-sample; re-run at 3a6145b7 and 92c0d0fe)" },
              { corpus: "promptfoo + llm-guard", samples: zh ? "94（2026-05-12 匯入，含 6 筆 NeMo Guardrails；其中 79 筆與其標示的廠商檔案逐字相同）" : "94 (2026-05-12 import, 6 of them NeMo Guardrails; 79 occur verbatim in the vendor file they name)", rules: "6", ruleIds: "ATR-2026-00500..00505", recall: vendorSuites ? (zh ? `${recallLanes(vendorSuites)}（${count(vendorSuites.attacks ?? vendorSuites.samples)} 筆固定版本的廠商攻擊案例，部分屬樣本內${vendorAblation ? `；消融參考值 ${vendorAblation}` : ""}；${measuredStamp(vendorSuites, true, true)}）` : `${recallLanes(vendorSuites)} (${count(vendorSuites.attacks ?? vendorSuites.samples)} pinned vendor attack cases, partly in-sample${vendorAblation ? `; ablation reference ${vendorAblation}` : ""}; ${measuredStamp(vendorSuites, false)})`) : "" },
              { corpus: "PromptInject", samples: zh ? "全語料庫" : "full corpus", rules: "4", ruleIds: "ATR-2026-00506..00509", recall: "" },
              { corpus: "OWASP LLM Top 10 + ATLAS PoCs", samples: zh ? "8 標準分類" : "8 standard categories", rules: "8", ruleIds: "ATR-2026-00510..00517", recall: "" },
              { corpus: zh ? "Garak in-the-wild jailbreak" : "Garak in-the-wild jailbreak", samples: "650", rules: zh ? "已有覆蓋" : "existing coverage", ruleIds: garak ? (zh ? `${recallLanes(garak)} recall（${measuredStamp(garak, true, true)}；部分屬 closed-book）` : `${recallLanes(garak)} recall (${measuredStamp(garak, false)}; partly closed-book)`) : "", recall: "" },
            ].map((row) => (
              <div key={row.corpus} className="bg-paper p-5 md:p-6">
                <div className="font-display text-sm font-bold text-ink mb-2">{row.corpus}</div>
                <div className="font-data text-xs text-stone mb-1">{zh ? "樣本：" : "Samples: "}{row.samples}</div>
                <div className="font-data text-xs text-stone mb-1">{zh ? "新規則：" : "Rules: "}{row.rules}</div>
                {row.ruleIds && <div className="font-data text-xs text-blue mb-1">{row.ruleIds}</div>}
                {row.recall && <div className="font-data text-xs text-green">{zh ? "召回率：" : "Recall: "}{row.recall}</div>}
              </div>
            ))}
          </div>
        </Reveal>
        <Reveal delay={0.2}>
          <p className="text-xs text-stone max-w-[640px]">
            {zh
              ? "這 71 條規則當時的品質門檻執行紀錄沒有 commit 進 repo，所以「全部通過、benign corpus 0 FP」的說法撤回，改成實測（重跑 repo 的規則安全閘 scripts/check-rules-safety.ts，2026-10-19 首次、2026-10-22 再跑一次）。用 92c0d0fe 當時的閘與語料：71 條都沒有在 432 份良性 SKILL.md 上誤報；10 條未通過，原因都是有 true positive 沒命中，其中 1 條另在 1,352 筆 extended 良性樣本中誤報 1 筆、1 條在 157 筆 research-mention 樣本中誤報 1 筆、2 條與其他規則的 true negative 衝突。用 2026-10-22 的 main（b9d16840，ATR 4.1.5）：33 條未通過；26 條至少誤報 1 筆良性樣本（467 份 SKILL.md 上 4 條、13,620 筆 extended 上 26 條、69 筆程式碼上 1 條、157 筆 research-mention 上 2 條）。這 26 條沒有一條是 maturity stable，所以都不在 enforce lane；24 條在 alert 與 hunt lane，2 條只在 hunt lane。這和 2026-10-19 在 9d74fc50 的結果完全相同，雖然期間 main 改了紀錄中的 9 條規則。誤報最多的是 ATR-2026-00454（maturity test，在 alert 與 hunt lane）：467 份 SKILL.md 中 152 份、13,620 筆 extended 中 1,376 筆；其餘每條在任一語料上都不超過 23 筆。00454 也是上方 HackAPrompt hunt 與 alert 數字的分子來源之一：在 2026-10-19 的 HackAPrompt 量測中，它在 hunt lane 命中 4,780 筆中的 757 筆。紀錄見 data/gate-reruns/2026-10-19_red-team-rule-batches.json。53 條規則的 regex 已從字面模式泛化為多層結構 pattern。"
              : "No record of the quality gate's run on these 71 rules was committed, so the claim that all passed it with 0 FP on the benign corpus is withdrawn and replaced by two measurements (the repository's rule safety gate, scripts/check-rules-safety.ts, re-run on 2026-10-19 and again on 2026-10-22). With the gate and corpora as of 92c0d0fe: none of the 71 flags any of the 432 benign SKILL.md files; 10 fail, all for missing one of their own true positives, and of those, 1 also flags 1 of 1,352 extended benign samples, 1 flags 1 of 157 research-mention samples and 2 conflict with another rule's true negatives. At main b9d16840 on 2026-10-22 (ATR 4.1.5): 33 fail; 26 flag at least one benign sample (4 on the 467 SKILL.md files, 26 on 13,620 extended samples, 1 on 69 code samples, 2 on 157 research-mention samples). None of those 26 has maturity stable, so none loads in the enforce lane; 24 load in the alert and hunt lanes, 2 in the hunt lane only. These are the same results as the 2026-10-19 run at 9d74fc50, although nine of the recorded rules changed on main in between. By far the largest is ATR-2026-00454 (maturity test, alert and hunt lanes): 152 of the 467 SKILL.md files and 1,376 of the 13,620 extended samples; every other rule flags at most 23 samples on any corpus. 00454 also counts toward the HackAPrompt hunt and alert figures above: in the 2026-10-19 HackAPrompt measurement it matches 757 of the 4,780 prompts in the hunt lane. Record: data/gate-reruns/2026-10-19_red-team-rule-batches.json. 53 rules had regex generalized from literal fingerprints to multi-layer structural patterns."}
          </p>
        </Reveal>
        <Reveal delay={0.3}>
          <div className="font-data text-xs uppercase tracking-[2px] text-stone mb-3 mt-16">
            {zh ? "2026-06 巨量掃描" : "2026-06 mega-scan"}
          </div>
          <h2 className="font-display text-[clamp(24px,3.4vw,36px)] font-extrabold tracking-[-2px] leading-tight mb-4 max-w-[720px]">
            {zh
              ? "8 個語料庫 · 29 條偵測規則 · 2 個無新增 miss"
              : "8 corpora · 29 detection rules · 2 with no novel misses"}
          </h2>
          <p className="text-base text-stone font-light max-w-[640px] mb-10">
            {zh
              ? "消化 8 個公開 agent 紅隊語料庫,找出現有規則漏抓的攻擊變體並結晶成新規則。6 個語料庫產出 29 條偵測規則,2 個(TensorTrust、PoisonedRAG)在現有覆蓋之外無新增 miss。"
              : "Ingested 8 public agent red-team corpora to surface attack variants existing rules missed and crystallize them into new rules. 6 corpora produced 29 detection rules; 2 (TensorTrust, PoisonedRAG) yielded no novel misses beyond existing coverage."}
          </p>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-fog mb-8">
            {[
              { corpus: "LLMail-Inject", ruleIds: "ATR-2026-01860..01865", note: "" },
              { corpus: "InjecAgent", ruleIds: "ATR-2026-00550 / 00584 / 00700 / 00859 / 01000", note: "" },
              { corpus: "AgentDojo", ruleIds: "ATR-2026-00715 / 00720 / 01751..01754", note: "" },
              { corpus: "ToolEmu", ruleIds: "ATR-2026-00702 / 00718 / 00719 / 01301", note: "" },
              { corpus: "MCPSecBench", ruleIds: "ATR-2026-01300 / 01306 / 01307 / 01310 / 01615 / 01616", note: "" },
              { corpus: "AgentPoison", ruleIds: "ATR-2026-01774 / 01800", note: "" },
              { corpus: "TensorTrust", ruleIds: "", note: zh ? "已有覆蓋 — 無新增 miss" : "Existing coverage — no novel misses" },
              { corpus: "PoisonedRAG", ruleIds: "", note: zh ? "已有覆蓋 — 無新增 miss" : "Existing coverage — no novel misses" },
            ].map((row) => (
              <div key={row.corpus} className="bg-paper p-5 md:p-6">
                <div className="font-display text-sm font-bold text-ink mb-2">{row.corpus}</div>
                {row.ruleIds && <div className="font-data text-xs text-blue mb-1">{row.ruleIds}</div>}
                {row.note && <div className="font-data text-xs text-stone mb-1">{row.note}</div>}
              </div>
            ))}
          </div>
        </Reveal>
        <Reveal delay={0.2}>
          <p className="text-xs text-stone max-w-[640px]">
            {zh
              ? "29 條為去重後的 distinct 規則;部分源自跨語料庫共通的 miss。依規則檔的 maturity:15 條 stable、12 條 test、1 條 experimental、1 條 draft。它們當時的門檻執行紀錄沒有 commit,所以「全部通過、0 FP」的說法撤回,改成實測:2026-10-22 在 main b9d16840(ATR 4.1.5)重跑規則安全閘(與 2026-10-19 的結果相同),29 條都沒有在 467 份良性 SKILL.md 上誤報;4 條未通過,其中 3 條在 13,620 筆 extended 良性樣本中各誤報 2 到 4 筆(都是 maturity test,在 alert 與 hunt lane,不在 enforce lane,其中 1 條另與其他規則的 true negative 衝突),1 條(ATR-2026-00550,detection method 為 trace)是 gate 無法在文字樣本上執行的規則,因此不通過(2026-10-19 時 gate 把它記為 true positive 沒命中;gate 的這項檢查在 2f0605c3 改過)。紀錄同上。"
              : "29 distinct rules after de-duplication; several emerged from misses shared across corpora. By the maturity in their rule files: 15 stable, 12 test, 1 experimental, 1 draft. No record of their gate runs was committed, so the claim that all cleared it with 0 FP is withdrawn and replaced by a measurement: the rule safety gate re-run at main b9d16840 (ATR 4.1.5) on 2026-10-22, with the same results as on 2026-10-19. None of the 29 flags any of the 467 benign SKILL.md files; 4 fail, 3 of them flagging 2 to 4 of 13,620 extended benign samples each (all maturity test: alert and hunt lanes, not enforce; one of them also conflicts with another rule's true negatives), 1 (ATR-2026-00550, detection method trace) that the gate cannot run on a text sample, so it does not pass (on 2026-10-19 the gate reported it as missing its own true positives; that check changed in 2f0605c3). Same record."}
          </p>
        </Reveal>
      </section>

      {/* ============================================================
          WHAT WE DON'T IMPORT
      ============================================================ */}
      <section className="px-6 max-w-[1120px] mx-auto mb-24 md:mb-32">
        <Reveal>
          <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-4">
            {zh ? "我們不導入什麼" : "What we don't import"}
          </div>
          <h2 className="font-display text-[clamp(24px,3.4vw,36px)] font-extrabold tracking-[-2px] leading-tight mb-4 max-w-[720px]">
            {zh
              ? "誠實說明範圍界限。"
              : "Honest scope boundaries."}
          </h2>
          <p className="text-base text-stone font-light max-w-[640px] mb-10">
            {zh
              ? "一個標準的可信度,一部分來自它拒絕了什麼。ATR 不引入所有可能的語料庫——以下是我們主動決定不引入的資料集,以及原因。"
              : "Part of what a standard is worth comes from what it refuses. ATR does not import every available corpus — below are the datasets we made an active decision to leave out, and why."}
          </p>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="space-y-px bg-fog">
            {[
              {
                name: "PyRIT Pliny L1B3RT4S",
                org: "Microsoft AI Red Team / Pliny",
                decision: zh ? "拒絕導入" : "Refused",
                reason: zh
                  ? "Anthropic 使用政策不允許我們的 subagent 消費此資料集。ATR 不導入無法驗證來源的材料。"
                  : "Anthropic usage policy prevented our subagents from consuming this dataset. ATR does not import material it cannot verify provenance for.",
              },
              {
                name: "AdvBench",
                org: "Zou et al. — GCG paper",
                decision: zh ? "重新分類" : "Reclassified",
                reason: zh
                  ? "重新分類為測試語料庫（data/test-corpora/）而非規則來源。AdvBench 描述目標行為，而非包裝好的攻擊 payload——它衡量攻擊成功率，不直接產生可偵測的模式。"
                  : "Reclassified as a test corpus (data/test-corpora/) rather than a rule source. AdvBench describes target behaviors, not wrapped attack payloads — it measures attack success rates and does not directly yield detectable patterns.",
              },
              {
                name: "HarmBench",
                org: "Center for AI Safety · Dan Hendrycks",
                decision: zh ? "重新分類" : "Reclassified",
                reason: zh
                  ? "重新分類為測試語料庫。HarmBench 的 320 個行為描述目標輸出，不是攻擊句法。用於評估 ATR 覆蓋率，不用於生成規則。"
                  : "Reclassified as a test corpus. HarmBench's 320 behaviors describe target outputs, not attack syntax. Used to measure ATR coverage, not to generate rules.",
              },
              {
                name: "JailbreakBench",
                org: "Princeton · Patrick Chao",
                decision: zh ? "重新分類" : "Reclassified",
                reason: zh
                  ? "重新分類為測試語料庫。JBB-Behaviors 是 jailbreak 排行榜的標準輸入，描述請求內容而非攻擊模式。用於 benchmark，不用於規則生成。"
                  : "Reclassified as a test corpus. JBB-Behaviors is a standardized leaderboard input describing request content rather than attack patterns. Used for benchmarking, not rule generation.",
              },
              {
                name: zh ? "4 條語料庫指紋規則 (KEPT-AS-IS)" : "4 corpus-fingerprint rules (KEPT-AS-IS)",
                org: "ATR-GARAK-a7fcb4e5 + 3 others",
                decision: zh ? "保留，不泛化" : "Kept, not generalized",
                reason: zh
                  ? "這 4 條規則的 regex 非常字面——它們是語料庫指紋，不是可泛化的攻擊模式。泛化這些規則會帶來無法接受的 FP rate。保留為 experimental，並明確標注為語料庫指紋，不用於生產封鎖。"
                  : "These 4 rules have highly literal regexes — they are corpus fingerprints, not generalizable attack patterns. Generalizing them would produce an unacceptable FP rate. Kept as experimental with explicit corpus-fingerprint notation; not used for production blocking.",
              },
            ].map((item) => (
              <div key={item.name} className="bg-paper p-6 md:p-7">
                <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-start">
                  <div className="md:col-span-3">
                    <div className="font-display text-sm font-bold text-ink mb-1">{item.name}</div>
                    <div className="font-data text-xs text-stone mb-2">{item.org}</div>
                    <span className={`font-data text-xs uppercase tracking-wide px-2 py-0.5 rounded-sm ${
                      item.decision === "Refused" || item.decision === "拒絕導入"
                        ? "bg-critical/10 text-critical"
                        : item.decision === "Kept, not generalized" || item.decision === "保留，不泛化"
                        ? "bg-blue/10 text-blue"
                        : "bg-stone/10 text-stone"
                    }`}>
                      {item.decision}
                    </span>
                  </div>
                  <div className="md:col-span-9">
                    <p className="text-sm text-graphite leading-[1.7]">{item.reason}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Reveal>
      </section>

      {/* ============================================================
          FINAL CTA — terse, confident
      ============================================================ */}
      <section className="px-6 max-w-[1120px] mx-auto">
        <Reveal>
          <div className="border border-ink p-8 md:p-12">
            <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-4">
              {zh ? "送一個 probe" : "Submit a probe"}
            </div>
            <h2 className="font-display text-[clamp(28px,4vw,44px)] font-extrabold tracking-[-2px] leading-[1.05] mb-6 max-w-[720px]">
              {zh
                ? "10 分鐘填表 → 永久署名 → 一條規則,所有採用 ATR 的防禦者共用。"
                : "10 minutes of form-filling. Permanent attribution. One rule, shared by every defender who adopts ATR."}
            </h2>
            <p className="text-base text-stone leading-relaxed mb-8 max-w-[640px]">
              {zh
                ? "MIT 授權、無 CLA、無遙測、永遠免費。你保留出版攻擊本身的所有權利 — ATR 只負責把它變成一條全世界都能引用的偵測規則。"
                : "MIT licensed. No CLA. No telemetry. Forever free. You keep every right to publish the attack itself — ATR only carries the detection, as a rule anyone, anywhere can cite by its stable ID."}
            </p>
            <div className="flex flex-wrap gap-3">
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules/issues/new?template=red-team-probe.yml"
                target="_blank"
                rel="noopener noreferrer"
                className="bg-ink text-paper px-7 py-3 rounded-sm text-base font-semibold hover:bg-ink/85 transition-colors"
              >
                {zh ? "開 probe issue →" : "Open a probe issue →"}
              </a>
              <a
                href="https://github.com/Agent-Threat-Rule/agent-threat-rules"
                target="_blank"
                rel="noopener noreferrer"
                className="border border-fog text-ink px-7 py-3 rounded-sm text-base font-semibold hover:bg-ash/40 transition-colors"
              >
                {zh ? "看 repo →" : "Read the repo →"}
              </a>
              <a
                href={`/${locale}/ecosystem`}
                className="border border-fog text-ink px-7 py-3 rounded-sm text-base font-semibold hover:bg-ash/40 transition-colors"
              >
                {zh
                  ? "防禦端在 /ecosystem →"
                  : "Defensive side at /ecosystem →"}
              </a>
            </div>
          </div>
        </Reveal>
        <Reveal delay={0.1}>
          <p className="text-xs text-stone mt-6 max-w-[640px]">
            {zh
              ? `已部署 ${stats.ruleCount} 條規則，跨 ${stats.categoryCount} 個威脅類別。每條都有 author 欄位和固定的規則 ID。`
              : `${stats.ruleCount} rules deployed across ${stats.categoryCount} threat categories. Every one has an author field and a stable rule ID.`}
          </p>
        </Reveal>
      </section>
    </div>
  );
}
