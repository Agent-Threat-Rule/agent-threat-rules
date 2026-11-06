export type Locale = "en" | "zh";

export const locales: Locale[] = ["en", "zh"];
export const defaultLocale: Locale = "en";

// Only strings that appear in UI. Technical terms stay English.
// Rule names, CVE IDs, framework names, severity levels — never translated.
export const messages: Record<Locale, Record<string, string>> = {
  en: {
    // Nav
    "nav.rules": "Rules",
    "nav.threats": "Threat Feed",
    "nav.coverage": "Coverage",
    "nav.integrate": "Integrate",
    "nav.contribute": "Contribute",
    "nav.wall": "Wall",
    "nav.ecosystem": "Ecosystem",
    "nav.red-team": "Red Team",
    "nav.research": "Research",
    "nav.about": "About",
    "nav.changelog": "Changelog",
    "nav.blog": "Blog",
    "nav.quality-standard": "Quality",
    "nav.cta": "Integrate",

    // Hero
    "hero.past": "We used to protect people.",
    "hero.now": "Now we protect agents.",
    "hero.sub":
      "The open detection standard for AI agent threats. YAML rules. MIT Licensed. No lock-in.",
    "hero.cta.primary": "Add ATR to Your Platform",
    "hero.cta.secondary": "Explore Rules",
    "hero.stat.rules": "Rules",
    "hero.stat.categories": "Categories",
    "hero.stat.precision": "Precision",

    // Threat
    "threat.label": "MCP skills scanned for threats",
    "threat.body":
      "AI agents now browse the web, execute code, and call external tools. Attackers trick them into <strong>leaking credentials</strong>, <strong>running reverse shells</strong>, and <strong>ignoring safety boundaries</strong>. The attack surface grows faster than any team can write rules by hand.",

    // Numbers
    "numbers.rules.desc":
      "Across {categories} threat categories. Each mapped to real CVEs and OWASP standards.",
    "numbers.precision.desc":
      "Precision on {samples} adversarial samples from a self-built corpus in PINT's format \u2014 not Lakera's official PINT benchmark.",
    "numbers.latency.desc": "99% of events resolve at Tier 0-2. Zero API cost.",
    "numbers.scan.desc":
      "Scanned across OpenClaw + Skills.sh. {critical} CRITICAL. {high} HIGH.",
    "numbers.owasp.desc": "OWASP Agentic Top 10 categories fully covered.",
    "numbers.safemcp.desc": "SAF-MCP techniques with at least one reviewed ATR rule (candidate mappings).",

    // Proof
    "proof.label": "Merged upstream",
    "proof.heading.pre": "Cisco AI Defense",
    "proof.heading.post": " merged\n34 ATR rules into its open-source skill-scanner.",
    "proof.body":
      "Their engineer submitted a PR. We reviewed it. It merged in 3 days. 1,272 additions. Then they built a --rule-packs CLI specifically to consume ATR.",
    "proof.link": "View PR #79 on GitHub",

    // Ecosystem
    "ecosystem.label": "Ecosystem",
    "ecosystem.heading": "{merged} merged. {open} pending. {total} total PRs.",
    "ecosystem.sub":
      "ATR spreads through PRs, not sales calls. Open source, MIT licensed, zero lock-in.",

    // Future

    // CTA
    "cta.heading": "Add ATR to your platform.",
    "cta.sub":
      "Four paths. TypeScript, Python, raw YAML, or SIEM queries.\nThe same path Cisco walked.",
    "cta.primary": "Integration Guide",
    "cta.secondary": "Explore All Rules",

    // Compare (NEW)
    "compare.label": "Why ATR",
    "compare.heading": "Why not write your own rules?",
    "compare.sub": "ATR vs alternatives. The honest comparison.",

    // Homepage data
    "categories.label": "What ATR Detects",
    "categories.heading":
      "{categories} threat categories. {rules} rules. Real CVEs.",
    "categories.sub":
      "Each rule links to OWASP, MITRE ATLAS, and documented exploits.",
    "scan.label": "Live Scan Data",
    "scan.mega": "Mega Scan",
    "scan.threats": "Threats Found",
    "scan.sources": "Sources",
    "scan.latency": "Avg Latency",
    "scan.skills_scanned": "skills scanned",
    "scan.flagged": "flagged",
    "scan.per_skill": "per skill scan",
    "crystal.1": "New attack pattern detected in the wild",
    "crystal.2": "LLM analyzes attack structure + intent",
    "crystal.3": "Auto-generates YAML rule proposal",
    "crystal.4": "Community reviews + precision test",
    "crystal.5": "Merged into ATR. Every engine updates.",
    "path.01.title": "Report an Evasion",
    "path.01.desc":
      "Found a bypass? File an issue. 15 minutes. Most valuable contribution.",
    "path.02.title": "Report a False Positive",
    "path.02.desc":
      "Rule triggered on legit content? Help us tune precision. 20 minutes.",
    "path.03.title": "Submit a New Rule",
    "path.03.desc":
      "Write a detection rule with the ATR schema. Full walkthrough. 1-2 hours.",
    "path.04.title": "AI-Native Contribution",
    "path.04.desc":
      "Use Claude Code or Cursor with ATR's MCP server. The AI writes the YAML. You review it.",

    // Rules page
    "rules.label": "Rule explorer",
    "rules.heading": "{count} effective rules. Search them, filter them, open any one.",
    "rules.sub":
      "Each rule has an ID of the form ATR-YYYY-NNNNN. Once published, the ID never changes, the way a CVE or CWE number doesn't. Open a rule to see what it matches, the test cases it has to pass and where it is known to miss. The list is read from the YAML files when the site is built.",
    "rules.search": "Search by name, ID or CVE",
    "rules.all_categories": "All categories",
    "rules.all_severities": "All severities",
    "rules.showing": "Showing {filtered} of {total} rule files",
    "rules.no_match": "No rule matches these filters.",
    "rules.clear": "clear filters",
    "rules.col.id": "Rule ID",
    "rules.col.name": "Name",
    "rules.col.category": "Category",
    "rules.col.severity": "Severity",
    "rules.col.cves": "CVEs",
    "rules.col.desc": "Description",
    "rules.view_yaml": "Read the YAML on GitHub",

    // Integrate page
    "integrate.ready":
      "The same {count} rules run in TypeScript, Python, a CI job or a SIEM. It is the route Cisco, Microsoft and MISP already took.",
    "integrate.schema.title": "Will the format break?",
    "integrate.schema.intro":
      "If you depend on ATR as upstream, you need to know the format won't break. Here's our commitment:",
    "integrate.schema.v1.title": "ATR Schema v1.0 (current)",
    "integrate.schema.v1.desc":
      "Published and stable. All new fields are optional additions. No existing field will be removed or renamed without a major version bump.",
    "integrate.schema.compat.title": "Backward Compatibility",
    "integrate.schema.compat.desc":
      "Breaking changes only happen on major version transitions (v1 to v2). We provide migration guides and a minimum 6-month overlap period.",
    "integrate.schema.freq.title": "Update Frequency",
    "integrate.schema.freq.desc":
      "New rules added continuously (avg 2-5 per week). Every rule passes CI validation + precision test before merge.",
    "integrate.schema.sync.title": "Sync Methods",
    "integrate.why.title": "Why not write your own rules?",
    "integrate.license.title": "License and legal",
    "integrate.cisco.title": "Case study: how Cisco did it",
    "integrate.cisco.body":
      "Cisco's AI Defense team integrated ATR rules as an upstream dependency. Their engineer submitted PR #79, we reviewed it, and it merged in 3 days. They then built a --rule-packs CLI feature (PR #80) specifically to consume ATR as a first-class rule source.",

    // Contribute page
    "contribute.governance": "Governance",
    "contribute.governance.desc":
      "How a rule gets reviewed, what maintainers do, and who decides.",
    "contribute.contributors": "Contributors",
    "contribute.contributors.desc":
      "Every confirmed bypass, false-positive report and rule is credited to the person who sent it.",
    "contribute.guide": "Rule writing guide",
    "contribute.guide.desc":
      "A full walkthrough, with examples and the schema reference.",

    // Research page
    "research.paper": "Published Paper",
    "research.benchmarks": "Benchmarks",
    "research.benchmarks.sub":
      "Measured on ATR's own corpus and on public attack datasets: deepset, Lakera Gandalf, HackAPrompt and garak.",
    "research.pint": "PINT format, self-built corpus",
    "research.self": "Self-test on ATR's own rules",
    "research.precision": "Precision",
    "research.recall": "Recall",
    "research.samples": "Samples",
    "research.gap_note":
      "In the hunt lane, precision is {precision} and recall is {recall}. That gap is expected. Regex catches the patterns it knows and misses paraphrases and attacks in other languages. The enforce lane loads only stable rules, and it is the one to run with blocking on. Its recall is {enforce}.",
    "research.gap_note_hunt_only":
      "In the hunt lane, precision is {precision} and recall is {recall}. That gap is expected. Regex catches the patterns it knows and misses paraphrases and attacks in other languages. This measurement has no enforce-lane figure.",
    "research.scan": "Ecosystem scans",
    "research.scan.sub": "The rules, run against real MCP skill registries.",
    "research.scan.mega": "Mega Scan (OpenClaw + Skills.sh)",
    "research.scan.clawhub": "ClawHub Registry Scan",
    "research.scan.scanned": "skills scanned",
    "research.scan.crawled": "skills crawled",
    "research.scan.source": "With source code",
    "research.download.csv": "Download the raw data (CSV)",
    "research.download.json": "Download the stats (JSON)",
    "research.limits": "What ATR can't detect",
    "research.limits.sub":
      "Before you rely on these rules, you should know where they miss.",
    "research.limits.full": "The full limitations document, with the evasion tests the rules carry",
    "research.limit.paraphrase": "Paraphrases",
    "research.limit.paraphrase.desc":
      "Any regex rule can be dodged by saying the same thing another way. “Ignore previous instructions” is caught. “Please set aside the guidance you were given earlier” is not.",
    "research.limit.multilang": "Other languages",
    "research.limit.multilang.desc":
      "Nearly every pattern is in English. A few rules also match phrasing in Chinese, Japanese, Korean, Russian or Arabic, and only for the attacks they were written for. An injection in any other language, or a new one in those, mostly gets through.",
    "research.limit.context": "Attacks that depend on context",
    "research.limit.context.desc":
      "“Delete all records” can be a normal request or an attack. Regex sees the words. It can't tell whether the agent was allowed to do it.",
    "research.limit.protocol": "Protocol-level attacks",
    "research.limit.protocol.desc":
      "ATR reads content, not the transport. Message replay, schema manipulation and a man-in-the-middle on the MCP transport never reach it.",
    "research.limit.multiturn": "Attacks spread over many turns",
    "research.limit.multiturn.desc":
      "Trust built up slowly over 20 turns, where no single message looks wrong, goes unnoticed. ATR judges each event on its own and doesn't connect them.",
    "research.limit.novel": "New attacks",
    "research.limit.novel.desc":
      "Regex can't match a pattern nobody has seen yet. A new technique needs a new rule.",

    // Subpages
    "coverage.label": "Standards coverage",
    "coverage.heading": "The frameworks name the threats. ATR checks for them.",
    "coverage.sub":
      "Six frameworks, among them MITRE ATLAS, OWASP, NIST AI RMF and ISO 42001, describe what can go wrong. ATR is the part you can run: a rule fires on a real agent artifact. Every rule carries mappings into all six frameworks, and CI enforces it.",
    "integrate.label": "Integrate",
    "integrate.heading": "Pick a way in. The rules are the same.",
    "research.label": "Research",
    "research.heading": "The numbers, and what ATR misses.",
    "research.sub":
      "The evasion tests are public. So is the list of attacks the rules can't catch.",
    "contribute.label": "Contribute",
    "contribute.heading":
      "One rule, proposed once, defends everyone who reads the standard.",
    "contribute.sub":
      "ATR is MIT-licensed and community-maintained. Contributing takes a text editor and a YAML file — no proprietary tooling, no telemetry, no CLA.",

    // Footer
    "footer.note":
      "ATR is a community-maintained open standard. MIT licensed. Not affiliated with any vendor.",

    // ── Standards site additions ───────────────────────────────
    // Document Status banner
    "spec.canonical": "canonical",
    "spec.version": "spec",
    "spec.date": "dated",
    "spec.generated": "page generated",
    "spec.editor": "editor",
    "spec.status_aria": "Document status",
    "spec.toc": "Contents",
    "spec.toc_aria": "Specification contents",
    "spec.read_full": "Read the full specification",
    "spec.implementer_report": "Implementer Report",
    "cite.tablist_aria": "Citation format",

    // Nav additions (kept short)
    "nav.atd": "ATD",
    "nav.spec": "Specification",
    "nav.implementers": "Implementers",
    "nav.conformance": "Conformance",
    "nav.governance": "Governance",
    "nav.community": "Community",
    "nav.charter": "Charter",
    "nav.glossary": "Glossary",
    "nav.errata": "Errata",
    "nav.citations": "Cite",

    // Homepage rewrite (standards-document hero)
    "home.title": "ATR — Agent Threat Rules",
    "home.subtitle":
      "An open detection rule format for AI agent security threats — vendor-neutral, machine-readable, peer-reviewable.",
    "home.abstract":
      "Agent Threat Rules (ATR) is an open detection rule format for AI agent security threats. Rules are written as YAML documents conforming to a versioned schema, identified by the public ATR-YYYY-NNNNN scheme, and evaluated by any conforming engine. ATR is to AI-agent threat detection what Sigma is to SIEM detection and YARA is to malware signatures: a vendor-neutral, machine-readable, peer-reviewable rule format.",
    "home.cta.spec": "Read the Specification (§3)",
    "home.cta.schema": "View the JSON Schema",
    "home.cta.implementers": "See who has implemented ATR",
    "home.section.overview": "Overview",
    "home.section.adoption": "Adoption in Production",
    "home.section.get": "Get the specification",
    "home.adoption.intro":
      "ATR has been merged into the public repositories of the organizations listed below. Each row links to the merged pull request or integration commit that constitutes the public adoption record; a merged pull request is not a statement about any vendor's commercial product.",
    "home.get.intro":
      "The specification is published in three forms. The Markdown rendering is canonical; the JSON Schema and citation block are derived artifacts.",
    "home.get.markdown": "Markdown — canonical",
    "home.get.schema": "JSON Schema — machine-readable",
    "home.get.cite": "Citation — BibTeX / DOI",

    // Spec page
    "spec.title": "ATR Specification",
    "spec.subtitle":
      "The rule format for detecting threats to AI agents, written so machines can read it. It does for agents what Sigma does for SIEM and YARA does for malware. This is a Working Draft, maintained in public by the ATR community. Where this page and the files in the repository disagree, the files win.",
    "spec.abstract.h": "Abstract",
    "spec.status.h": "Status of This Document",
    "spec.status.body":
      "This document is a Working Draft published by the ATR Community. Although the rule format has been shipping in production for over a year, the surrounding governance is still transitioning from a lead-maintainer model (BDFL) to a Technical Steering Committee. Discussion of this document takes place on the public GitHub repository.",

    // Implementers page
    "implementers.title": "Implementer report",
    "implementers.subtitle":
      "A specification counts once more than one engine implements it the same way. W3C moves a standard forward on that kind of evidence. This report lists the organizations that run or reference ATR, and each entry is independent evidence that the format can be built from the spec alone. Entries are self-declared, by pull request to ADOPTERS.md.",
    "implementers.col.org": "Organization",
    "implementers.col.role": "Conformance",
    "implementers.col.version": "Spec version",
    "implementers.col.date": "Integrated",
    "implementers.col.ref": "Public record",
    "implementers.tier.engine": "L1 Engine",
    "implementers.tier.publisher": "L2 Publisher",
    "implementers.tier.citation": "L1 Citation",
    "implementers.tier.galaxy": "L1 Galaxy",
    "implementers.tier.accepted": "Submission in review",
    "implementers.empty":
      "No entries yet. Open a PR against ADOPTERS.md to add your organization.",

    // Conformance page
    "conformance.title": "Conformance",
    "conformance.subtitle":
      "A rule written in Taipei should run unchanged on an engine in Seattle. Conformance is what makes that true. Three levels spell out what a system has to do before it can say it implements ATR, so that every conforming engine gives the same rule the same verdict. Each level has a test suite, published as YAML fixtures in the repository. You show conformance by passing it, not by claiming it.",
    "conformance.l1.title": "L1 engine conformance",
    "conformance.l1.body":
      "The L1 engine is what makes the format portable. It MUST parse every rule that validates against spec/atr-schema.yaml. It MUST evaluate detection.conditions with the semantics in §3.5, and it MUST honor the scan_target and status semantics. That way a rule gets the same verdict no matter who wrote the engine. An L1 engine MAY refuse rules outside the scan_target it declares.",
    "conformance.l2.title": "L2 publisher conformance",
    "conformance.l2.body":
      "An L2 publisher puts out rules in its own vendor-prefixed range, such as ACME-YYYY-NNNNN, and follows every ATR semantic. It MUST honor the deprecation policy in §3.7 and SHOULD include test_cases with every rule it publishes.",
    "conformance.l3.title": "L3 sub-range authority",
    "conformance.l3.body":
      "An L3 sub-range authority is a national or organizational body that issues rules under a sovereign prefix, such as ATR-TW-2026-NNNNN. Authority is granted through the procedure in /charter §5. Once the TSC is seated, it grants it. Until then the lead maintainer (BDFL) does.",
    "conformance.testsuite.h": "Test suite",
    "conformance.testsuite.body":
      "The L1 engine test suite is a set of YAML fixtures under spec/conformance/ in the main repository. Each fixture pairs a rule with the result it must give on a fixed event. The contract lives in the fixtures, not in any one implementation. An implementation passes when every fixture comes out as declared. Two engines that both pass agree, by construction, on every rule the suite covers.",
    "conformance.self.h": "Self-certification",
    "conformance.self.body":
      "To self-certify, run the test suite locally, then open a pull request against ADOPTERS.md with your integration details. The maintainers can check any self-certification at any time by re-running the suite against a published artifact. Once the TSC is seated, it takes that on.",

    // Errata page
    "errata.title": "Errata",
    "errata.subtitle":
      "A standing record of errors found in published versions of the ATR specification, kept in public the way W3C and IETF specs keep theirs. A published version never changes. Its errors are corrected here, in the open, with credit to whoever found them. Each entry names the affected version, where the error is, the corrected text and the date the correction went out.",
    "errata.empty":
      "No errata are on record for the current Working Draft. That isn't a claim that it has no errors. It means none has been confirmed in a published version yet. If you find one, open an issue in the repository. A confirmed report goes here instead of being patched quietly.",
    "errata.col.version": "Affected version",
    "errata.col.section": "Section",
    "errata.col.summary": "Summary",
    "errata.col.date": "Published",

    // Glossary
    "glossary.title": "Glossary",
    "glossary.subtitle":
      "What the key terms in the specification mean. When a term's technical meaning differs from everyday use, the technical meaning applies inside the spec.",

    // Charter
    "charter.title": "Project charter",
    "charter.subtitle":
      "A standard outlives the people who start it only if its rules are written down. This charter says what ATR is and isn't, how decisions get made and how the Technical Steering Committee is seated. These commitments hold no matter who maintains the project.",
    "charter.mission.h": "Mission",
    "charter.mission.body":
      "ATR gives people who defend AI agents one shared format for writing, exchanging and evaluating detection rules. A defender in one organization can build on a rule written by a defender in another, even in another country, and nobody has to reinvent the format. A shared format is infrastructure, not a product. It belongs to no vendor and answers to the community that maintains it.",
    "charter.scope.h": "Scope",
    "charter.scope.in":
      "In scope: the rule format, the reference engine, the rule schema, the conformance levels and the mappings to other frameworks (OWASP, MITRE ATLAS, NIST AI RMF, SAFE-MCP).",
    "charter.scope.out":
      "Out of scope: vendor-specific tooling, commercial integrations, runtime enforcement policy and incident response coordination. Those belong to downstream implementers. The standard stays narrow on purpose, so any of them can build on it without inheriting someone else's product decisions.",
    "charter.governance.h": "Governance",
    "charter.governance.body":
      "Today ATR is governed by one lead maintainer (BDFL). A Technical Steering Committee is being set up to take over that role. Authority sitting with one maintainer is a phase, not the design. The criteria for the handover and the TSC seating process were written down in advance, in GOVERNANCE.md and docs/BDFL-charter.md, so the move to shared governance happens by rule and not by accident.",
    "charter.ip.h": "Intellectual property",
    "charter.ip.body":
      "ATR is released under the MIT License, permanently. The published standard has no path to another license. Every contribution is MIT-licensed when it is submitted. There is no CLA to sign and no rights to assign. Anyone can adopt, extend or fork the rules, including vendors who compete with each other. The DOI for citation is 10.5281/zenodo.19178002.",

    // Citations
    "citations.title": "Citation",
    "citations.subtitle":
      "A standard becomes infrastructure once other people's work can point at it and trust it not to move. ATR is built to be cited, by a paper, a CVE record or a CI script. Its IDs never change after publication, and its DOI will outlast any URL. Use one of the formats below.",

    // Mission articulation (used on /, /about, /charter)
    "mission.title": "Mission",
    "mission.body":
      "Defenders work in different organizations, in different countries, against the same AI-agent attack surface. ATR exists so that work composes — so that a rule written in Taipei detects an attack first reported in Seattle without anyone re-implementing the rule format.",
    "mission.tagline":
      "One open format. One peer-reviewable schema. One canonical URL.",

    "vision.title": "Long-term Vision",
    "vision.body":
      "The maturity of AI-agent security as a discipline is rate-limited by the absence of a shared rule format. ATR provides that format. The goal is for ATR to occupy the same architectural slot for AI-agent runtimes that Sigma occupies for SIEM detection and YARA occupies for malware signatures — neutral, peer-reviewable, and free for any party to implement, extend, or cite.",
  },
  zh: {
    // Nav
    "nav.rules": "規則",
    "nav.threats": "威脅情報",
    "nav.coverage": "覆蓋率",
    "nav.integrate": "整合",
    "nav.contribute": "貢獻",
    "nav.wall": "貢獻牆",
    "nav.ecosystem": "生態系",
    "nav.red-team": "紅隊",
    "nav.research": "研究",
    "nav.about": "關於",
    "nav.changelog": "版本歷程",
    "nav.blog": "Blog",
    "nav.quality-standard": "品質標準",
    "nav.cta": "整合",

    // Hero
    "hero.past": "我們過去保護人。",
    "hero.now": "現在我們保護 Agent。",
    "hero.sub":
      "AI Agent 威脅的開放偵測標準。YAML 規則、MIT 授權、零鎖定。",
    "hero.cta.primary": "將 ATR 加入你的平台",
    "hero.cta.secondary": "瀏覽規則",
    "hero.stat.rules": "Rules",
    "hero.stat.categories": "Categories",
    "hero.stat.precision": "Precision",

    // Threat
    "threat.label": "MCP skills 威脅掃描",
    "threat.body":
      "AI Agent 現在能瀏覽網頁、執行程式碼、呼叫外部工具。攻擊者利用它們<strong>洩漏憑證</strong>、<strong>執行惡意指令</strong>、<strong>繞過安全邊界</strong>。攻擊面的增長速度超過任何團隊手寫規則的速度。",

    // Numbers
    "numbers.rules.desc":
      "橫跨 {categories} 個威脅類別。每條規則都對應真實 CVE 和 OWASP 標準。",
    "numbers.precision.desc":
      "在 {samples} 個對抗樣本上的 Precision。語料是 PINT 格式的自建語料,不是 Lakera 官方 PINT benchmark。",
    "numbers.latency.desc":
      "99% 的事件在 Tier 0-2 解決。零 API 成本。",
    "numbers.scan.desc":
      "掃描 OpenClaw + Skills.sh。{critical} CRITICAL、{high} HIGH。",
    "numbers.owasp.desc": "OWASP Agentic Top 10 全部覆蓋。",
    "numbers.safemcp.desc":
      "至少有一條經審查 ATR 規則對應的 SAF-MCP 技術(候選對照)。",

    // Proof
    "proof.label": "已合併至上游",
    "proof.heading.pre": "Cisco AI Defense",
    "proof.heading.post":
      " 把 34 條 ATR 規則合併進它的開源 skill-scanner。",
    "proof.body":
      "他們的工程師提了 PR。我們 review 完。3 天合併。1,272 行新增。然後他們建了 --rule-packs CLI 專門消費 ATR。",
    "proof.link": "在 GitHub 查看 PR #79",

    // Ecosystem
    "ecosystem.label": "生態系",
    "ecosystem.heading":
      "{merged} 個已合併。{open} 個待審。共 {total} 個 PR。",
    "ecosystem.sub":
      "ATR 透過 PR 擴散，不是透過銷售。開源、MIT 授權、零鎖定。",

    // Future

    // CTA
    "cta.heading": "將 ATR 加入你的平台。",
    "cta.sub":
      "四條路徑。TypeScript、Python、原始 YAML、或 SIEM queries。\n跟 Cisco 走的同一條路。",
    "cta.primary": "Integration Guide",
    "cta.secondary": "瀏覽所有規則",

    // Compare
    "compare.label": "為什麼選 ATR",
    "compare.heading":
      "為什麼不自己寫規則？",
    "compare.sub":
      "ATR vs 替代方案。誠實的比較。",

    // Homepage data
    "categories.label": "ATR 偵測什麼",
    "categories.heading":
      "{categories} 個威脅類別。{rules} 條規則。真實 CVE。",
    "categories.sub":
      "每條規則都連結到 OWASP、MITRE ATLAS 和已記錄的漏洞。",
    "scan.label": "即時掃描數據",
    "scan.mega": "Mega Scan",
    "scan.threats": "發現威脅",
    "scan.sources": "數據來源",
    "scan.latency": "平均延遲",
    "scan.skills_scanned": "skills 已掃描",
    "scan.flagged": "已標記",
    "scan.per_skill": "每 skill 掃描",
    "crystal.1":
      "在野外偵測到新攻擊模式",
    "crystal.2": "LLM 分析攻擊結構 + 意圖",
    "crystal.3": "自動產生 YAML 規則提案",
    "crystal.4": "社群審查 + precision 測試",
    "crystal.5":
      "合併到 ATR。所有引擎自動更新。",
    "path.01.title": "回報繞過方法",
    "path.01.desc":
      "找到了繞過方法？提一個 issue。只要 15 分鐘。最有價值的貢獻。",
    "path.02.title": "回報誤判",
    "path.02.desc":
      "規則對合法內容觸發了？幫我們調整 precision。20 分鐘。",
    "path.03.title": "提交新規則",
    "path.03.desc":
      "用 ATR schema 寫一條偵測規則。有完整教學。1-2 小時。",
    "path.04.title": "AI 原生貢獻",
    "path.04.desc":
      "用 Claude Code 或 Cursor 配合 ATR 的 MCP server。AI 寫 YAML，你審查。",

    // Rules page
    "rules.label": "規則總覽",
    "rules.heading":
      "{count} 條生效規則。可以搜尋、篩選，點開任何一條細看。",
    "rules.sub":
      "每條規則都有一個 ATR-YYYY-NNNNN 編號，發布之後就不會再改，跟 CVE、CWE 編號一樣。點開一條，可以看到它比對什麼、要通過哪些測試案例，以及已知會漏掉什麼。這份清單在網站建置時，直接從 YAML 檔讀出來。",
    "rules.search":
      "用名稱、編號或 CVE 搜尋",
    "rules.all_categories": "全部類別",
    "rules.all_severities": "全部嚴重度",
    "rules.showing": "共 {total} 個規則檔，顯示 {filtered} 個",
    "rules.no_match":
      "沒有符合條件的規則。",
    "rules.clear": "清除篩選",
    "rules.col.id": "規則編號",
    "rules.col.name": "名稱",
    "rules.col.category": "類別",
    "rules.col.severity": "嚴重度",
    "rules.col.cves": "CVE",
    "rules.col.desc": "說明",
    "rules.view_yaml": "到 GitHub 看 YAML",

    // Integrate page
    "integrate.ready":
      "同一套 {count} 條規則，可以接進 TypeScript、Python、CI 或 SIEM。Cisco、Microsoft、MISP 走的就是這條路。",
    "integrate.schema.title": "格式會不會改壞？",
    "integrate.schema.intro":
      "如果你依賴 ATR 作為上游，你需要知道格式不會壞掉。這是我們的承諾：",
    "integrate.schema.v1.title":
      "ATR Schema v1.0（當前版本）",
    "integrate.schema.v1.desc":
      "已發布且穩定。所有新欄位都是可選的。現有欄位不會在沒有 major version 變更的情況下移除或重新命名。",
    "integrate.schema.compat.title": "向後相容性",
    "integrate.schema.compat.desc":
      "破壞性變更只在 major version 轉換時發生（v1 → v2）。提供遷移指南和至少 6 個月的重疊支援期。",
    "integrate.schema.freq.title": "更新頻率",
    "integrate.schema.freq.desc":
      "新規則持續新增（平均每週 2-5 條）。每條規則都通過 CI 驗證 + precision 測試才能 merge。",
    "integrate.schema.sync.title": "同步方法",
    "integrate.why.title":
      "為什麼不自己寫規則？",
    "integrate.license.title": "授權與法律",
    "integrate.cisco.title": "實例：Cisco 怎麼接",
    "integrate.cisco.body":
      "Cisco 的 AI Defense 團隊將 ATR rules 作為上游依賴整合。他們的工程師提交了 PR #79，我們 review 完，3 天合併。然後他們建了 --rule-packs CLI（PR #80）專門消費 ATR。",

    // Contribute page
    "contribute.governance": "治理",
    "contribute.governance.desc":
      "規則怎麼審、維護者做什麼，最後由誰拍板。",
    "contribute.contributors": "貢獻者",
    "contribute.contributors.desc":
      "確認過的繞過、誤判回報、規則，每一筆都會記在送出的人名下。",
    "contribute.guide": "規則撰寫指南",
    "contribute.guide.desc":
      "從頭帶一遍，附範例和 schema 說明。",

    // Research page
    "research.paper": "已發布論文",
    "research.benchmarks": "基準測試",
    "research.benchmarks.sub":
      "在 ATR 自己的語料上量，也在幾份公開的攻擊資料集上量：deepset、Lakera Gandalf、HackAPrompt、garak。",
    "research.pint": "PINT 格式，自建語料",
    "research.self": "用 ATR 自己的規則自測",
    "research.precision": "Precision",
    "research.recall": "Recall",
    "research.samples": "樣本數",
    "research.gap_note":
      "在 hunt 車道，precision 是 {precision}，recall 是 {recall}。差這麼多是預料中的事。regex 抓得到它認得的寫法，換個說法、換種語言就漏掉。enforce 車道只載入 stable 規則，要開封鎖就用這條，它的 recall 是 {enforce}。",
    "research.gap_note_hunt_only":
      "在 hunt 車道，precision 是 {precision}，recall 是 {recall}。差這麼多是預料中的事。regex 抓得到它認得的寫法，換個說法、換種語言就漏掉。這次量測沒有 enforce 車道的數字。",
    "research.scan": "生態系掃描",
    "research.scan.sub":
      "把規則拿去掃真實的 MCP skill 註冊表。",
    "research.scan.mega": "Mega Scan（OpenClaw + Skills.sh）",
    "research.scan.clawhub": "ClawHub 註冊表掃描",
    "research.scan.scanned": "skills 已掃描",
    "research.scan.crawled": "skills 已爬取",
    "research.scan.source": "有源碼",
    "research.download.csv": "下載原始資料（CSV）",
    "research.download.json": "下載統計數字（JSON）",
    "research.limits": "ATR 偵測不到的東西",
    "research.limits.sub":
      "要靠這些規則之前，你該先知道它們會漏掉什麼。",
    "research.limits.full":
      "完整的限制文件，和規則附帶的繞過測試",
    "research.limit.paraphrase": "換句話說",
    "research.limit.paraphrase.desc":
      "任何 regex 規則，都能用意思一樣、說法不同的句子繞過。「Ignore previous instructions」會被抓到，「please set aside the guidance you were given earlier」不會。",
    "research.limit.multilang": "其他語言",
    "research.limit.multilang.desc":
      "比對條件幾乎都是英文。只有少數規則另外收了中文、日文、韓文、俄文或阿拉伯文的寫法，而且只針對它們原本要抓的那一招。用其他語言寫的注入，或用這幾種語言寫的新招，大多會漏掉。",
    "research.limit.context": "要看情境的攻擊",
    "research.limit.context.desc":
      "「Delete all records」可能是正常指令，也可能是攻擊。regex 只看字面，看不出 agent 有沒有被授權做這件事。",
    "research.limit.protocol": "協定層攻擊",
    "research.limit.protocol.desc":
      "ATR 檢查的是內容，不是傳輸。訊息重放、schema 竄改、MCP 傳輸層的中間人攻擊，它都看不到。",
    "research.limit.multiturn": "拆成很多輪的攻擊",
    "research.limit.multiturn.desc":
      "花 20 輪慢慢把信任拉高，每一則訊息單獨看都沒問題。ATR 不會把它們串起來看，每個事件都分開判斷。",
    "research.limit.novel": "新型攻擊",
    "research.limit.novel.desc":
      "還沒出現過的攻擊，regex 不可能比對得到。新手法要有新規則。",

    // Subpages
    "coverage.label": "標準對照",
    "coverage.heading":
      "框架替威脅取名字，ATR 負責把它抓出來。",
    "coverage.sub":
      "MITRE ATLAS、OWASP、NIST AI RMF、ISO 42001 等六份框架，說明的是什麼可能出錯。ATR 是能實際執行的那一層：規則會在真實的 agent 檔案上觸發。每條規則都附有對這六份框架的對照，由 CI 強制檢查。",
    "integrate.label": "整合",
    "integrate.heading":
      "接法不只一種，規則都是同一套。",
    "research.label": "研究",
    "research.heading":
      "數字，還有 ATR 抓不到的東西。",
    "research.sub":
      "繞過測試是公開的。規則抓不到哪些攻擊，也一樣攤開來。",
    "contribute.label": "貢獻",
    "contribute.heading":
      "一條規則，提一次，保護每一個讀這個標準的人。",
    "contribute.sub":
      "ATR 是 MIT 授權、社群維護。貢獻只需要一個文字編輯器和一個 YAML 檔案——零專有工具、零遙測、零 CLA。",

    // Footer
    "footer.note":
      "ATR 是社群維護的開放標準。MIT 授權。不隸屬於任何廠商。",

    // ── Standards site additions ───────────────────────────────
    "spec.canonical": "正式網址",
    "spec.version": "規格版本",
    "spec.date": "日期",
    "spec.generated": "頁面產生於",
    "spec.editor": "編者",
    "spec.status_aria": "文件狀態",
    "spec.toc": "目錄",
    "spec.toc_aria": "規格目錄",
    "spec.read_full": "看完整規格",
    "spec.implementer_report": "實作者報告 (Implementer Report)",
    "cite.tablist_aria": "引用格式",

    "nav.atd": "ATD",
    "nav.spec": "規格 (Specification)",
    "nav.implementers": "實作者 (Implementers)",
    "nav.conformance": "符規 (Conformance)",
    "nav.governance": "治理 (Governance)",
    "nav.community": "社群 (Community)",
    "nav.charter": "章程 (Charter)",
    "nav.glossary": "詞彙 (Glossary)",
    "nav.errata": "勘誤 (Errata)",
    "nav.citations": "引用 (Cite)",

    "home.title": "ATR — Agent Threat Rules",
    "home.subtitle":
      "AI Agent 安全威脅的開放偵測規則格式 ── 廠商中立、機器可讀、可同儕審查 (peer-reviewable)。",
    "home.abstract":
      "Agent Threat Rules (ATR) 是 AI Agent 安全威脅的開放偵測規則格式。規則以 YAML 撰寫,遵循版本化 schema,使用公開的 ATR-YYYY-NNNNN 識別碼方案,可由任何符規引擎評估。ATR 之於 AI Agent 威脅偵測,如同 Sigma 之於 SIEM 偵測、YARA 之於惡意程式簽章 ── 一個廠商中立、機器可讀、可同儕審查的規則格式。",
    "home.cta.spec": "閱讀規格 (§3)",
    "home.cta.schema": "查看 JSON Schema",
    "home.cta.implementers": "查看實作者列表",
    "home.section.overview": "Overview",
    "home.section.adoption": "Production 採用",
    "home.section.get": "取得規格",
    "home.adoption.intro":
      "ATR 已合併進下表列出的組織自家的公開 repository。每一列連結到構成公開採用紀錄的合併 pull request 或整合 commit;已合併的 PR 不等於對任何廠商商業產品的陳述。",
    "home.get.intro":
      "規格以三種形式發布。Markdown 渲染為正本 (canonical);JSON Schema 與引用 (citation) 為衍生產物 (derived artifact)。",
    "home.get.markdown": "Markdown — 正本",
    "home.get.schema": "JSON Schema — 機器可讀",
    "home.get.cite": "引用 — BibTeX / DOI",

    "spec.title": "ATR 規格",
    "spec.subtitle":
      "偵測 AI agent 威脅用的規則格式，寫成機器讀得懂的樣子。它對 agent 的意義，就像 Sigma 之於 SIEM、YARA 之於惡意程式。目前是 Working Draft，由 ATR 社群公開維護。這一頁和 repository 裡的檔案說法不一致時，以檔案為準。",
    "spec.abstract.h": "摘要 (Abstract)",
    "spec.status.h": "本文件狀態 (Status of This Document)",
    "spec.status.body":
      "本文件為 ATR 社群發布的 Working Draft。儘管規則格式已在生產環境運行超過一年,周邊治理仍處於從首席維護者模型 (BDFL) 過渡到技術指導委員會 (TSC) 的階段。本文件的討論於公開 GitHub repository 進行。",

    "implementers.title": "實作者報告",
    "implementers.subtitle":
      "一份規格，要有不只一個引擎用同樣的方式實作出來，才算數。W3C 推進標準，看的也是這種證據。這份報告列出執行或引用 ATR 的組織，每一筆都是獨立的證據，說明這個格式光靠規格就做得出來。名單由各組織自己對 ADOPTERS.md 開 pull request 登記。",
    "implementers.col.org": "組織",
    "implementers.col.role": "符規等級",
    "implementers.col.version": "規格版本",
    "implementers.col.date": "整合日期",
    "implementers.col.ref": "公開紀錄",
    "implementers.tier.engine": "L1 Engine",
    "implementers.tier.publisher": "L2 Publisher",
    "implementers.tier.citation": "L1 Citation",
    "implementers.tier.galaxy": "L1 Galaxy",
    "implementers.tier.accepted": "Submission in review",
    "implementers.empty":
      "目前無紀錄。對 ADOPTERS.md 開 PR 即可加入你的組織。",

    "conformance.title": "符規",
    "conformance.subtitle":
      "在台北寫的規則，要能原封不動跑在西雅圖的引擎上。靠的就是符規。三個等級講清楚，一個系統要做到什麼，才能說自己實作了 ATR，讓每個符規的引擎對同一條規則給出同樣的判定。每個等級都有測試套件，以 YAML fixture 的形式放在 repository 裡。符規要跑過測試才算，不是自己說了算。",
    "conformance.l1.title": "L1 引擎符規",
    "conformance.l1.body":
      "格式能不能帶著走，看的是 L1 引擎。它 MUST 能解析每一條通過 spec/atr-schema.yaml 驗證的規則，MUST 依 §3.5 定義的語意評估 detection.conditions，也 MUST 遵守 scan_target 與 status 的語意。這樣同一條規則，不管引擎是誰寫的，判定都一樣。L1 引擎 MAY 拒絕超出自己宣告 scan_target 的規則。",
    "conformance.l2.title": "L2 發布者符規",
    "conformance.l2.body":
      "L2 發布者在自己的廠商前綴範圍裡發布規則，例如 ACME-YYYY-NNNNN，語意完全照 ATR 走。它 MUST 遵守 §3.7 的棄用政策，SHOULD 為每一條發布的規則附上 test_cases。",
    "conformance.l3.title": "L3 子範圍管理單位",
    "conformance.l3.body":
      "L3 子範圍管理單位，是在主權前綴下發布規則的國家或組織，例如 ATR-TW-2026-NNNNN。授權依 /charter §5 的程序核發。TSC 成立後由 TSC 核發，在那之前由首席維護者（BDFL）代行。",
    "conformance.testsuite.h": "測試套件",
    "conformance.testsuite.body":
      "L1 引擎的測試套件，是主 repository 裡 spec/conformance/ 底下的 YAML fixture。每個 fixture 把一條規則，和它在某個固定事件上應該得出的結果配成一對。規範寫在 fixture 裡，不在任何一個實作裡。每個 fixture 都跑出宣告的結果，就算通過。兩個都通過的引擎，在套件涵蓋的每一條規則上，結果一定一致。",
    "conformance.self.h": "自我認證",
    "conformance.self.body":
      "自我認證的做法：在本機跑測試套件，再對 ADOPTERS.md 開 pull request，附上整合資訊。維護者隨時可以拿已發布的產物重跑套件，查核你的認證。TSC 成立後，改由 TSC 負責。",

    "errata.title": "勘誤",
    "errata.subtitle":
      "這裡記錄 ATR 規格各個已發布版本裡找到的錯誤，像 W3C、IETF 的規格一樣公開保存。已發布的版本不會再改，裡面的錯就在這裡公開更正，並註明是誰發現的。每一筆都寫明受影響的版本、錯在哪裡、更正後的文字，以及更正發布的日期。",
    "errata.empty":
      "目前的 Working Draft 還沒有勘誤紀錄。這不代表沒有錯，只是已發布的版本裡，還沒有任何錯誤被確認。發現了請到 repository 開 issue。確認的回報會記在這裡，不會私下悄悄修掉。",
    "errata.col.version": "受影響版本",
    "errata.col.section": "章節",
    "errata.col.summary": "摘要",
    "errata.col.date": "發布日期",

    "glossary.title": "詞彙表",
    "glossary.subtitle":
      "規格裡重要術語的定義。如果某個術語的技術意思跟一般用法不同，在規格裡以技術意思為準。",

    "charter.title": "專案章程",
    "charter.subtitle":
      "一個標準要比發起它的人活得久，規矩就得白紙黑字寫下來。這份章程寫明 ATR 是什麼、不是什麼、事情怎麼決定，以及技術指導委員會（TSC）怎麼成立。不管之後由誰維護，這些承諾都不變。",
    "charter.mission.h": "使命",
    "charter.mission.body":
      "ATR 給守護 AI agent 的人一個共用的偵測規則格式，用來寫規則、交換規則、評估規則。一個組織的防守者，可以直接接著用另一個組織、甚至另一個國家的人寫的規則，不必有人重新發明格式。共用格式是基礎建設，不是產品。它不屬於任何廠商，只對維護它的社群負責。",
    "charter.scope.h": "範圍",
    "charter.scope.in":
      "範圍內：規則格式、參考引擎、規則 schema、符規等級，以及對其他框架的對照（OWASP、MITRE ATLAS、NIST AI RMF、SAFE-MCP）。",
    "charter.scope.out":
      "範圍外：廠商專屬工具、商業整合、runtime 執行政策、事件應變協調。這些是下游實作者的事。標準刻意保持窄，讓誰都能在上面蓋東西，又不必承接別人的產品決定。",
    "charter.governance.h": "治理",
    "charter.governance.body":
      "ATR 目前由一位首席維護者（BDFL）治理，技術指導委員會（TSC）正在籌組，之後會接手這個角色。權力集中在一位維護者身上是過渡期，不是設計。交接條件和 TSC 的成立程序，事先就寫在 GOVERNANCE.md 和 docs/BDFL-charter.md 裡，讓走向共同治理照規則發生，不是碰運氣。",
    "charter.ip.h": "智慧財產",
    "charter.ip.body":
      "ATR 以 MIT License 發布，而且是永久的，已發布的標準沒有改用其他授權的路。所有貢獻在送出時就以 MIT 授權，不用簽 CLA，也不用讓渡任何權利。任何人都可以採用、擴充或 fork 這些規則，彼此競爭的廠商也一樣。引用用的 DOI 是 10.5281/zenodo.19178002。",

    "citations.title": "引用",
    "citations.subtitle":
      "別人的論文、CVE 紀錄、CI 腳本可以指向它，而它不會跑掉，一個標準才算成了基礎建設。ATR 本來就是做來給人引用的。編號發布後就不再改，DOI 也比任何網址都長命。引用時用下面任一種格式。",

    "mission.title": "使命",
    "mission.body":
      "防禦者在不同組織、不同國家工作,面對同一 AI Agent 攻擊面。ATR 存在的理由,是讓工作能彼此組合 ── 讓台北寫的一條規則能偵測首先在西雅圖被通報的攻擊,而不必有人重新實作規則格式。",
    "mission.tagline":
      "一個開放格式。一個可同儕審查的 schema。一個正式網址 (canonical URL)。",

    "vision.title": "長期願景",
    "vision.body":
      "AI Agent 安全作為一個學科,其成熟度受制於缺乏共同的規則格式。ATR 提供這個格式。我們的目標是讓 ATR 在 AI Agent runtime 的架構位置中,佔據 Sigma 在 SIEM 偵測、YARA 在惡意程式簽章中的同等位置 ── 中立、可同儕審查、任何單位皆可自由實作、延伸或引用。",
  },
};

export function t(
  locale: Locale,
  key: string,
  vars?: Record<string, string | number>,
): string {
  let text = messages[locale]?.[key] ?? messages.en[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) {
      text = text.replace(`{${k}}`, String(v));
    }
  }
  return text;
}
