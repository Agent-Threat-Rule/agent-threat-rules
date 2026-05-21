import { Reveal } from "@/components/Reveal";
import { loadSiteStats } from "@/lib/stats";
import { locales, type Locale } from "@/lib/i18n";
import type { Metadata } from "next";

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: "Red Team — Your attack becomes the standard | ATR",
  description:
    "ATR is the only public detection standard built from red-team research. Your discovered probe becomes a permanent rule, auto-propagating to Microsoft Agent Governance Toolkit, Cisco AI Defense, MISP, and OWASP within hours. Attribution stays attached. Forever.",
};

interface RedTeamTool {
  name: string;
  status: "in-production" | "in-review" | "corpus";
  org: string;
  homepage: string;
  prUrl?: string;
  hook: string;
  what_atr_did: string;
}

const RED_TEAM_TOOLS: RedTeamTool[] = [
  {
    name: "NVIDIA Garak",
    org: "NVIDIA AI Red Team",
    status: "in-review",
    homepage: "https://github.com/NVIDIA/garak",
    prUrl: "https://github.com/NVIDIA/garak/pull/1676",
    hook: "The reference open-source LLM vulnerability scanner. 50+ probe families, jmartin-tech + leondz maintainers.",
    what_atr_did:
      "Wrapped 421 ATR rules as garak detectors. PR #1676 cleared two review rounds; in-the-wild benchmark posted 97.1% recall on garak's own community jailbreak corpus. Per-family: latentinjection 34.4%, sysprompt_extraction 67.9%, dan 90.2%, ATR-core families ~80%+.",
  },
  {
    name: "HarmBench",
    org: "Center for AI Safety · Dan Hendrycks",
    status: "in-review",
    homepage: "https://github.com/centerforaisafety/HarmBench",
    prUrl: "https://github.com/centerforaisafety/HarmBench/issues/93",
    hook: "320-behavior standardized red-team benchmark — the citation when comparing attack methods across target models.",
    what_atr_did:
      "Issue #93 proposes pairing every behavior with a content-layer rule, adding detection-rate and bypass-rate columns next to ASR. Pre-PR gap-analysis offer attached.",
  },
  {
    name: "AgentDojo",
    org: "ETH Zurich SPY Lab · Florian Tramèr",
    status: "in-review",
    homepage: "https://github.com/ethz-spylab/agentdojo",
    prUrl: "https://github.com/ethz-spylab/agentdojo/issues/160",
    hook: "The only agent-specific attack benchmark with a real tool-use harness. 78 attack tasks across 4 environments.",
    what_atr_did:
      "Issue #160 proposes a detection-evaluator extension that runs ATR rules against AgentDojo attack tasks. Honest about regex limits against paraphrase / multilingual; reports per-task expected detection rate.",
  },
  {
    name: "JailbreakBench",
    org: "Princeton · Patrick Chao (PAIR / TAP)",
    status: "in-review",
    homepage: "https://github.com/JailbreakBench/jailbreakbench",
    prUrl: "https://github.com/JailbreakBench/jailbreakbench/issues/48",
    hook: "Standardized jailbreak leaderboard with fixed eval interface. JBB-Behaviors is the citation for 'attack X beats baseline'.",
    what_atr_did:
      "Issue #48 proposes a registered-detector backend interface (ATR as one possible reference implementation). Adds detection-rate + bypass-rate + agreement-with-refusal as new comparable axes.",
  },
  {
    name: "TextAttack",
    org: "QData · ACL 2020",
    status: "in-review",
    homepage: "https://github.com/QData/TextAttack",
    prUrl: "https://github.com/QData/TextAttack/issues/824",
    hook: "3.1k stars. The reference NLP-adversarial framework, used in undergraduate security curricula.",
    what_atr_did:
      "Issue #824 proposes a textattack-detection-atr companion PyPI package — plugin-shaped, zero core changes. Single ask: README cross-link.",
  },
  {
    name: "Microsoft Counterfit",
    org: "Microsoft Azure Security",
    status: "in-review",
    homepage: "https://github.com/Azure/counterfit",
    prUrl: "https://github.com/Azure/counterfit/issues/96",
    hook: "Metasploit-shape CLI for AI red-teaming. The clean abstraction for command-line attack runs.",
    what_atr_did:
      "Issue #96 proposes a counterfit-detection-atr companion package adding a detection lane to scan output. Plugin-first; respects the project's maintenance state.",
  },
  {
    name: "Microsoft PyRIT",
    org: "Microsoft AI Red Team",
    status: "in-review",
    homepage: "https://github.com/microsoft/PyRIT",
    prUrl: "https://github.com/microsoft/PyRIT/pull/1715",
    hook: "The toolkit Microsoft uses internally to red-team production LLM products. Roman Lutz leads.",
    what_atr_did:
      "Added an ATR dataset loader exposing the rule corpus as PyRIT attack sources. Roman reviewed within 2 min on first push; iterating on doc shape.",
  },
  {
    name: "HackAPrompt",
    org: "Schulhoff et al. — Learn Prompting · EMNLP 2023",
    status: "corpus",
    homepage: "https://hackaprompt.com",
    prUrl: "https://github.com/Agent-Threat-Rule/agent-threat-rules/pull/51",
    hook: "The largest crowd-sourced prompt-injection competition corpus, 4,780 competition samples across GPT/Claude/PaLM. EMNLP 2023 best-paper nominee.",
    what_atr_did:
      "Clustered 4,780 HackAPrompt samples by attack family. Shipped 5 ATR rules (ATR-2026-00452..00456) from dominant clusters. HackAPrompt recall: 28.6% before sprint → 66.2% after. 100% precision maintained. Each rule cites the HackAPrompt cluster in metadata_provenance.",
  },
  {
    name: "NeMo-Guardrails + llm-guard + Promptfoo",
    org: "NVIDIA · Protect AI · Promptfoo Inc.",
    status: "corpus",
    homepage: "https://github.com/NVIDIA/NeMo-Guardrails",
    prUrl: "https://github.com/Agent-Threat-Rule/agent-threat-rules/pull/52",
    hook: "Vendor test suites from three production guardrail systems. Combined 94 adversarial samples covering jailbreak, injection, and output sanitization.",
    what_atr_did:
      "Ingested combined 94-sample corpus. Shipped 6 ATR rules (ATR-2026-00500..00505) covering attack patterns present across all three vendor test suites. Each rule validated against the vendor's own test cases as true-positive ground truth.",
  },
  {
    name: "PromptInject",
    org: "agencyenterprise · NeurIPS 2022 Best Paper",
    status: "in-review",
    homepage: "https://github.com/agencyenterprise/PromptInject",
    prUrl: "https://github.com/agencyenterprise/PromptInject/issues/9",
    hook: "The original academic benchmark for prompt injection. 8.2k stars; cited by every prompt-injection paper since 2022.",
    what_atr_did:
      "Shipped 4 ATR rules (ATR-2026-00506..00509) closing user_input injection gaps identified from PromptInject attack taxonomy. Issue #9 proposes a corpus-to-ATR pipeline pairing every PromptInject attack with a matched detection rule.",
  },
  {
    name: "OWASP LLM Top 10 + MITRE ATLAS PoCs",
    org: "OWASP · MITRE",
    status: "corpus",
    homepage: "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    prUrl: "https://github.com/Agent-Threat-Rule/agent-threat-rules/pull/53",
    hook: "Standards-defined PoC attack patterns from OWASP LLM01-LLM10 and corresponding MITRE ATLAS technique catalog (AML.T00XX series).",
    what_atr_did:
      "Shipped 8 ATR rules (ATR-2026-00510..00517), each mapping to a named OWASP LLM category (LLM01-LLM10) and a specific MITRE ATLAS technique. Rules are standards-aligned at the metadata_provenance level.",
  },
  {
    name: "PromptInject",
    org: "agencyenterprise · NeurIPS 2022 Best Paper",
    status: "in-review",
    homepage: "https://github.com/agencyenterprise/PromptInject",
    prUrl: "https://github.com/agencyenterprise/PromptInject/issues/9",
    hook: "The original academic benchmark that started prompt-injection research. 8.2k stars; cited by every prompt-injection paper since.",
    what_atr_did:
      "Issue #9 proposes a corpus-to-ATR pipeline turning every PromptInject attack into a paired ATR rule. The reference academic benchmark gets defensive parity.",
  },
  {
    name: "Promptfoo",
    org: "Promptfoo Inc.",
    status: "in-review",
    homepage: "https://github.com/promptfoo/promptfoo",
    prUrl: "https://github.com/promptfoo/promptfoo/pull/8529",
    hook: "10k stars, used by red teams at Klarna, Discord, Anduril. Promptfoo runs adversarial tests; ATR catches what Promptfoo found.",
    what_atr_did:
      "PR #8529 adds an MCP red-team example using ATR as the deterministic defense layer. Promptfoo runs the probe; ATR rules return the verdict.",
  },
  {
    name: "Damn Vulnerable MCP Server",
    org: "harishsg993010",
    status: "in-review",
    homepage: "https://github.com/harishsg993010/damn-vulnerable-MCP-server",
    prUrl:
      "https://github.com/harishsg993010/damn-vulnerable-MCP-server/pull/29",
    hook: "A CTF-style training target with 10 intentionally-vulnerable MCP scenarios. The DVWA of agent security.",
    what_atr_did:
      "PR #29 ships the blue-team detection guide — every CTF challenge gets a paired ATR rule so trainees learn detection alongside the attack.",
  },
];

interface AttributionStat {
  number: string;
  label: string;
  detail: string;
}

const ATTRIBUTION_STATS: AttributionStat[] = [
  {
    number: "2h 16m",
    label: "Disclosure → npm publish",
    detail:
      "2026-05-07 Microsoft Security disclosed Semantic Kernel CVE-2026-26030. 2026-05-11 06:07 UTC Microsoft Copilot SWE Agent opened a regression-test PR presuming ATR coverage. 08:24 UTC v2.1.2 published on npm with paired rules. End-to-end loop.",
  },
  {
    number: "7",
    label: "Tier-1 institutions integrating",
    detail:
      'Microsoft (Agent Governance Toolkit weekly auto-sync). Cisco AI Defense (314-rule pack in production). CIRCL/MISP (taxonomies + galaxy merged by project lead). OWASP (Project Lead merged with "Welcome to the team"). FINOS, NIST OSCAL, UK Gov AISI in motion.',
  },
  {
    number: "421",
    label: "Rules. Each with your name attached forever",
    detail:
      "Every rule carries author + metadata_provenance.discovered_by. Microsoft AGT, Cisco AI Defense, MISP, OWASP all preserve it on sync. When MISP exports to STIX, attribution survives. When NIST cites the rule, lineage is intact.",
  },
  {
    number: "0 FP",
    label: "Required across 3,551 benign samples",
    detail:
      "6-check quality gate: own-TP must match + 1,784 benign + 157 research-mention + 1,611 cross-rule conflict-free + own true_negative coverage. Rules that fire on the paper describing the attack don't ship.",
  },
];

interface OnDeckTool {
  name: string;
  org: string;
  why: string;
  filing: string;
  status: "queued" | "scheduled";
}

const ON_DECK: OnDeckTool[] = [
  {
    name: "InjecAgent",
    org: "UIUC Kang Lab",
    why: "Cleanest direct-vs-indirect agent injection taxonomy. 1,054 attack cases. Complements AgentDojo coverage.",
    filing: "2026-05-19",
    status: "queued",
  },
  {
    name: "GPTFuzz",
    org: "NDSS 2024 · Jiahao Yu",
    why: "First credible LLM fuzzer. Pairing fuzz output with ATR detection closes the loop on what their tool discovers.",
    filing: "2026-05-22",
    status: "queued",
  },
  {
    name: "R-Judge",
    org: "Tongxin Yuan et al.",
    why: "162-scenario agent safety benchmark with LLM-as-judge evaluator. ATR adds the complementary content-rule defense lane next to the judge layer.",
    filing: "2026-05-26",
    status: "queued",
  },
  {
    name: "PromptBench",
    org: "Microsoft Research",
    why: "MS Research LLM robustness eval framework. Second cross-link inside Microsoft after AGT + PyRIT.",
    filing: "2026-06-02",
    status: "queued",
  },
  {
    name: "Giskard",
    org: "YC W23",
    why: "ML testing framework with red-team mode. Open-source core + commercial cloud — integrate at OSS core.",
    filing: "2026-06-06",
    status: "queued",
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
      "Citable artifact paired with your attack. Concrete adoption metrics for your CV: number of rules, downstream consumers, fire counts in production telemetry.",
    proof:
      "Your name appears in the rule file's author + metadata_provenance.discovered_by. When MISP exports the taxonomy to STIX, your attribution propagates. When NIST cites the rule in a publication (in-progress with iMichaela at NIST OSCAL), the lineage is intact.",
  },
  {
    for: "Corporate red teams",
    benefit:
      "Your adversarial work becomes the defensive standard before competitors. Your team shows up as the discoverer in 350+ rules consumed by every major AI-security platform.",
    proof:
      "Microsoft's Copilot SWE Agent already opens PRs presuming ATR coverage (AGT #1981, closed 2026-05-11). Being the originator of ATR-2026-NNNNN rules is a real authority signal in vendor-eval conversations.",
  },
  {
    for: "Independent researchers",
    benefit:
      "Ship detection without writing regex. Submit positive + negative examples — auto-regex tries 4 variants against the full gate, ~30% pass on first attempt.",
    proof:
      "Auto-regex deterministic generator clears 0 FP across 3,551 samples (benign + extended + research-mention + cross-rule). The PR labels itself gate-passed and goes straight to maintainer review.",
  },
  {
    for: "Bug bounty hunters",
    benefit:
      "A second income stream for the same attack: the bug-bounty payout AND a permanent detection rule. Combines well with Huntr.dev, Hackerone AI scope, Protect AI bounty programmes.",
    proof:
      "ATR proposals are MIT-licensed and citable. No NDA conflict — the bounty programme owns the responsible-disclosure window; ATR ships detection after disclosure with public attribution.",
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
                Microsoft Copilot SWE Agent 自己會開 PR 預設 ATR 存在。Cisco AI
                Defense production 內建 314 條規則。MISP 全部 export 到 STIX
                帶你的署名。NeurIPS 2024 的 HarmBench / AgentDojo /
                JailbreakBench 下一個 wave 接進來。
              </>
            ) : (
              <>
                Microsoft&apos;s Copilot SWE Agent already opens PRs presuming
                ATR exists. Cisco AI Defense ships 314 of our rules by default.
                MISP exports them to STIX with your name on them. NeurIPS
                2024&apos;s HarmBench, AgentDojo, JailbreakBench wire through
                next.
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
              href="#on-deck"
              className="border border-fog text-ink px-7 py-3 rounded-sm text-base font-semibold hover:bg-ash/40 transition-colors"
            >
              {zh ? "看下一波接什麼 →" : "See who&apos;s next →"}
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
            {zh ? "為什麼這值得貢獻" : "Why this is worth your time"}
          </div>
        </Reveal>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-12">
          {ATTRIBUTION_STATS.map((s, i) => (
            <Reveal key={i} delay={0.1 + i * 0.08}>
              <div className="border-l-2 border-blue pl-6">
                <div className="font-display text-[clamp(36px,4.5vw,56px)] font-extrabold tracking-[-2px] text-ink mb-2 leading-none">
                  {s.number}
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
              ? "依你是誰，紅隊貢獻有四種具體報酬。"
              : "Four concrete payoffs depending on who you are."}
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
          HOW IT WORKS — auto-regex highlighted
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
                ? "Probe 進來、auto-regex 自動產、quality gate 全綠才 merge。"
                : "Probe in. Auto-regex generates. Quality gate validates. Merge if green."}
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
                      ? "Auto-regex 跑 4 個變體"
                      : "Auto-regex tries 4 variants"}
                  </h3>
                  <p className="text-base text-paper/80 leading-relaxed mb-2">
                    {zh
                      ? "Deterministic n-gram set-cover algorithm 從你的 positive examples 萃取 distinctive phrases，建 alternation regex，加 word boundary、whitespace anchor 或 co-occurrence 約束 — 每個變體跑完整 gate。"
                      : "Deterministic n-gram set-cover algorithm extracts distinctive phrases from your positives, builds an alternation regex, tightens with word boundaries / whitespace anchors / co-occurrence constraints. Each variant runs through the full gate."}
                  </p>
                  <p className="text-sm text-paper/60">
                    {zh
                      ? "Gate = 自己 TP 必須 100% 命中 + 1,784 樣本 benign corpus 0 FP + 157 樣本 research-mention 0 FP + 跨規則 0 衝突。"
                      : "Gate = your TPs must match 100% + 1,784-sample benign corpus 0 FP + 157-sample research-mention 0 FP + 0 cross-rule conflicts."}
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
                      ? "PR 帶 gate-passed label。Maintainer 看 regex shape 是否太字面、需不需要 generalize — 通常 1-3 天 merge。沒過就留 stub，maintainer 手寫 regex（仍然會用你的 test cases）。"
                      : "PR lands with the gate-passed label. Maintainer reviews regex shape — is it too literal, can it generalize? Usually merged within 1-3 days. If gate didn't clear, stays as stub and a maintainer hand-crafts the regex (still using your test cases as ground truth)."}
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
                      ? "Microsoft AGT 每週 sync、Cisco AI Defense 跟 release tag、MISP taxonomy + galaxy 每次 release 拉、OWASP A-S-R-H 在 fixture 中引用 rule ID。你的 discovered_by 跟著整條鏈傳遞。"
                      : "Microsoft AGT syncs weekly. Cisco AI Defense pins to release tags. MISP taxonomy + galaxy pull on every release. OWASP A-S-R-H references rule IDs in fixtures. Your discovered_by field propagates through the whole chain."}
                  </p>
                  <p className="text-sm text-paper/60">
                    {zh
                      ? "Microsoft Semantic Kernel CVE 從 disclosure 到 v2.1.2 publish 用了 2 小時 16 分鐘。這就是 cadence。"
                      : "Microsoft Semantic Kernel CVE went from public disclosure to v2.1.2 npm publish in 2h 16m. That's the cadence."}
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
            {zh ? "已經在跑的紅隊整合" : "Red team tooling in motion"}
          </div>
          <h2 className="font-display text-[clamp(28px,4vw,40px)] font-extrabold tracking-[-2px] leading-[1.05] mb-4 max-w-[720px]">
            {zh
              ? "我們把 ATR 接到紅隊這邊。你的工具可以是下一個。"
              : "ATR is wired into the red-team ecosystem. Your tool can be next."}
          </h2>
          <p className="text-base text-stone font-light max-w-[640px] mb-12">
            {zh
              ? "這些是真的紅隊工具（offensive testing）。防禦端框架在 /ecosystem。"
              : "These are red-team tools — offensive testing frameworks and adversarial corpora. Defensive frameworks live on /ecosystem."}
          </p>
        </Reveal>

        <Reveal>
          <div className="font-data text-xs font-medium text-stone tracking-[2px] uppercase mb-4">
            {zh
              ? `已整合 (${inProduction.length})`
              : `Integrated (${inProduction.length})`}
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
                          ? "已整合"
                          : "Integrated"}
                    </div>
                  </div>
                  <div className="md:col-span-9">
                    <p className="text-sm text-stone leading-relaxed mb-2">
                      {t.hook}
                    </p>
                    <p className="text-base text-ink leading-relaxed mb-3">
                      {t.what_atr_did}
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
                          {zh ? "PR →" : "PR →"}
                        </a>
                      )}
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
              ? `審查中 (${inReview.length})`
              : `Under review (${inReview.length})`}
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
              ? "5 個語料庫 · 75 條新規則 · HackAPrompt 召回率 28.6% → 66.2%"
              : "5 corpora · 75 new rules · HackAPrompt recall 28.6% → 66.2%"}
          </h2>
          <p className="text-base text-stone font-light max-w-[640px] mb-10">
            {zh
              ? "2026-05-12：11 個並行 agent 消化五個外部語料庫，生成 75 條規則，均通過 6 道品質關卡，0 FP regression on benign corpus。詳細版本記錄在 /changelog。"
              : "2026-05-12: 11 parallel agents ingested five external corpora and generated 75 rules, all passing the 6-gate quality process with 0 FP regression on the benign corpus. Full version record at /changelog."}
          </p>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-px bg-fog mb-8">
            {[
              { corpus: "HackAPrompt", samples: "4,780", rules: "5", ruleIds: "ATR-2026-00452..00456", recall: "28.6% → 66.2%" },
              { corpus: zh ? "Vendor test suites" : "Vendor test suites", samples: "94", rules: "6", ruleIds: "ATR-2026-00500..00505", recall: "" },
              { corpus: "PromptInject", samples: zh ? "全語料庫" : "full corpus", rules: "4", ruleIds: "ATR-2026-00506..00509", recall: "" },
              { corpus: "OWASP LLM Top 10 + ATLAS PoCs", samples: zh ? "8 標準分類" : "8 standard categories", rules: "8", ruleIds: "ATR-2026-00510..00517", recall: "" },
              { corpus: zh ? "Garak 社群 jailbreak" : "Garak community jailbreak", samples: "666", rules: zh ? "已有覆蓋" : "existing coverage", ruleIds: "97.1% recall", recall: "" },
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
              ? "所有 75 條規則均通過 RFC-001 品質門檻、benign corpus 0 FP、跨規則衝突檢查。53 條規則的 regex 已從字面模式泛化為多層結構 pattern。詳細 changelog 見 v2.2.0。"
              : "All 75 rules passed the RFC-001 quality gate, benign corpus 0 FP, and cross-rule conflict check. 53 rules had regex generalized from literal fingerprints to multi-layer structural patterns. Full detail in v2.2.0 changelog."}
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
              ? "ATR 不引入所有可能的語料庫。以下是我們主動決定不引入的資料集，以及原因。"
              : "ATR does not import every available corpus. Below are datasets we have made an active decision not to import, and why."}
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
          ON DECK — the public pipeline
      ============================================================ */}
      <section
        id="on-deck"
        className="px-6 max-w-[1120px] mx-auto mb-24 md:mb-32"
      >
        <Reveal>
          <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-4">
            {zh ? "下一波" : "On deck"}
          </div>
          <h2 className="font-display text-[clamp(28px,4vw,44px)] font-extrabold tracking-[-2px] leading-[1.05] mb-4 max-w-[760px]">
            {zh
              ? "已經排好的紅隊整合 — 一週一個，公開排程。"
              : "Red-team integrations queued. One a week. Public schedule."}
          </h2>
          <p className="text-base text-stone font-light max-w-[680px] mb-12">
            {zh
              ? "ATR 不是只跟最大牌的整合。下面是接下來六週要送的 issue / PR — 真實日期、真實對象。Maintainer 看到自己被排上會優先 review，這是公開承諾的副作用。"
              : "ATR doesn&apos;t only chase the biggest names. Here&apos;s the queue for the next six weeks — real dates, real targets. Maintainers who see themselves on the schedule tend to review faster. That&apos;s the side-effect of a public commitment."}
          </p>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="space-y-px bg-fog">
            {ON_DECK.map((t, i) => (
              <div key={t.name} className="bg-paper p-6 md:p-7">
                <div className="grid grid-cols-1 md:grid-cols-12 gap-4 md:gap-6 items-start">
                  <div className="md:col-span-1 font-data text-xs text-stone tracking-wide">
                    {String(i + 1).padStart(2, "0")}
                  </div>
                  <div className="md:col-span-4">
                    <div className="font-display text-base font-bold text-ink mb-1">
                      {t.name}
                    </div>
                    <div className="font-data text-xs text-stone">{t.org}</div>
                  </div>
                  <div className="md:col-span-5">
                    <p className="text-sm text-ink leading-relaxed">{t.why}</p>
                  </div>
                  <div className="md:col-span-2 text-right">
                    <div className="font-data text-xs text-stone uppercase tracking-wide mb-1">
                      {zh ? "送出日" : "Filing"}
                    </div>
                    <div className="font-data text-sm text-blue font-medium">
                      {t.filing}
                    </div>
                    <div
                      className={`font-data text-xs uppercase tracking-wide mt-1 ${
                        t.status === "scheduled" ? "text-green" : "text-stone"
                      }`}
                    >
                      {t.status === "scheduled"
                        ? zh
                          ? "已排程"
                          : "scheduled"
                        : zh
                          ? "佇列中"
                          : "queued"}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Reveal>
        <Reveal delay={0.2}>
          <p className="text-xs text-stone mt-6 max-w-[640px]">
            {zh
              ? '排程從 GitHub issue / PR 同步。Merge 後從這裡移到 "Already Integrated"。Maintainer 若想插隊：security@agentthreatrule.org。'
              : 'Schedule syncs from filed GitHub issues / PRs. Once merged, entries move to "Already Integrated" above. Maintainers wanting earlier engagement: security@agentthreatrule.org.'}
          </p>
        </Reveal>
      </section>

      {/* ============================================================
          PIPELINE PROOF — concrete: what passed last week
      ============================================================ */}
      <section className="px-6 max-w-[1120px] mx-auto mb-24 md:mb-32">
        <Reveal>
          <div className="font-data text-xs font-medium text-stone tracking-[3px] uppercase mb-4">
            {zh ? "Pipeline 不是 vapor" : "Pipeline is not vapor"}
          </div>
          <h2 className="font-display text-[clamp(24px,3.4vw,36px)] font-extrabold tracking-[-2px] leading-tight mb-8 max-w-[680px]">
            {zh
              ? "Auto-regex 已經對你的範本 0 FP 跨 3,551 樣本。"
              : "Auto-regex already clears 0 FP across 3,551 samples on the sample probe."}
          </h2>
        </Reveal>
        <Reveal delay={0.1}>
          <div className="bg-ash/40 border border-fog p-6 md:p-8 font-data text-xs md:text-sm text-ink overflow-x-auto">
            <pre className="whitespace-pre leading-relaxed">{`$ npx tsx scripts/auto-regex.ts \\
    --file proposals/red-team-probes/dan-trust-phrase-wrapping.proposal.yaml \\
    --write

[auto-regex] 3 TPs, 3 TNs — generating candidate regex…
[auto-regex] gate corpora: 431 benign + 1,352 extended + 157 research + 1,611 cross-rule TNs
[auto-regex] variant 0: 3 phrases, tp=100%, fp=0
  (benign=0 ext=0 res=0 cross=0) — PASS
[auto-regex] wrote regex to proposals/red-team-probes/...

::auto-regex-summary::
{ "passed": true, "variant": 0, "tp_coverage": 1, "total_fp": 0 }`}</pre>
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
                ? "10 分鐘的填表 → 永久的署名 → 進每個主流 AI 安全平台。"
                : "10 minutes of form-filling. Permanent attribution. Ships to every major AI security platform."}
            </h2>
            <p className="text-base text-stone leading-relaxed mb-8 max-w-[640px]">
              {zh
                ? "MIT 授權、無 CLA、無遙測、永遠免費。你保留出版攻擊本身的所有權利 — ATR 只負責把它變成偵測。"
                : "MIT licensed. No CLA. No telemetry. Forever free. You retain every right to publish the attack itself — ATR only carries the detection."}
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
              ? `已部署 ${stats.ruleCount} 條規則，跨 ${stats.categoryCount} 個威脅類別。每條都有 author + metadata_provenance.discovered_by。`
              : `${stats.ruleCount} rules deployed across ${stats.categoryCount} threat categories. Every one has an author field and metadata_provenance.discovered_by intact.`}
          </p>
        </Reveal>
      </section>
    </div>
  );
}
