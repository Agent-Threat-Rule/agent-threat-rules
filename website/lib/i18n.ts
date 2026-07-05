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
      "Precision on {samples} adversarial samples. External PINT benchmark.",
    "numbers.latency.desc": "99% of events resolve at Tier 0-2. Zero API cost.",
    "numbers.scan.desc":
      "Scanned across OpenClaw + Skills.sh. {critical} CRITICAL. {high} HIGH.",
    "numbers.owasp.desc": "OWASP Agentic Top 10 categories fully covered.",
    "numbers.safemcp.desc": "SAFE-MCP technique coverage. 78 of 85.",

    // Proof
    "proof.label": "Already in production",
    "proof.heading.pre": "Cisco AI Defense",
    "proof.heading.post": " ships\n34 ATR rules as upstream.",
    "proof.body":
      "Their engineer submitted a PR. We reviewed it. It merged in 3 days. 1,272 additions. Then they built a --rule-packs CLI specifically to consume ATR.",
    "proof.link": "View PR #79 on GitHub",

    // Ecosystem
    "ecosystem.label": "Ecosystem",
    "ecosystem.heading": "{merged} merged. {open} pending. {total} total PRs.",
    "ecosystem.sub":
      "ATR spreads through PRs, not sales calls. Open source, MIT licensed, zero lock-in.",

    // Future
    "future.label": "The Future",
    "future.heading": "ATR rules don't have to be written by hand.",
    "future.sub":
      "Threat Cloud crystallization turns new attacks into detection rules automatically.",
    "future.note":
      "Traditional rules are written by hand, on weekly cycles. Threat Cloud shrinks new rule turnaround from weeks to hours.",

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
    "rules.label": "Rule Explorer",
    "rules.heading": "{count} detection rules. Browse, filter, inspect.",
    "rules.sub":
      "Every rule carries a stable ATR-YYYY-NNNNN identifier — CVE/CWE-style, permanent once published. Parsed from YAML at build time; click any rule to read its detection logic, test cases, and known limitations.",
    "rules.search": "Search rules... (name, ID, CVE)",
    "rules.all_categories": "All categories",
    "rules.all_severities": "All severities",
    "rules.showing": "Showing {filtered} of {total} rules",
    "rules.no_match": "No rules match your filters.",
    "rules.clear": "clear filters",
    "rules.col.id": "Rule ID",
    "rules.col.name": "Name",
    "rules.col.category": "Category",
    "rules.col.severity": "Severity",
    "rules.col.cves": "CVEs",
    "rules.col.desc": "Description",
    "rules.view_yaml": "View YAML on GitHub",

    // Integrate page
    "integrate.ready":
      "{count} rules, written once, runnable anywhere. Wire the same ruleset into TypeScript, Python, CI, or a SIEM — the path Cisco, Microsoft, and MISP already walked.",
    "integrate.schema.title": "Schema Stability Guarantee",
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
    "integrate.why.title": "Why ATR Instead of Writing Your Own?",
    "integrate.license.title": "License & Legal",
    "integrate.cisco.title": "Case Study: How Cisco Did It",
    "integrate.cisco.body":
      "Cisco's AI Defense team integrated ATR rules as an upstream dependency. Their engineer submitted PR #79, we reviewed it, and it merged in 3 days. They then built a --rule-packs CLI feature (PR #80) specifically to consume ATR as a first-class rule source.",

    // Contribute page
    "contribute.crystal.title": "Threat Cloud Crystallization",
    "contribute.crystal.sub":
      "Traditional rules take weeks to write, review, and ship. Threat Cloud targets hours.",
    "contribute.governance": "Governance",
    "contribute.governance.desc":
      "Rule review process, maintainer roles, decision-making.",
    "contribute.contributors": "Contributors",
    "contribute.contributors.desc":
      "Credit wall. Every confirmed evasion, FP report, and rule gets credited.",
    "contribute.guide": "Rule Writing Guide",
    "contribute.guide.desc":
      "Complete walkthrough with examples and schema reference.",

    // Research page
    "research.paper": "Published Paper",
    "research.benchmarks": "Benchmarks",
    "research.benchmarks.sub":
      "Tested against our own corpus and public adversarial datasets (deepset, Lakera Gandalf, HackAPrompt, garak).",
    "research.pint": "PINT-format (self-built)",
    "research.self": "Self-Test (Own Rules)",
    "research.precision": "Precision",
    "research.recall": "Recall",
    "research.samples": "Samples",
    "research.gap_note":
      "The gap between {precision}% precision and {recall}% recall is expected. Regex catches known patterns but misses paraphrases and multilingual attacks.",
    "research.scan": "Ecosystem Scan Data",
    "research.scan.sub": "Real scans of real MCP skill registries.",
    "research.scan.mega": "Mega Scan (OpenClaw + Skills.sh)",
    "research.scan.clawhub": "ClawHub Registry Scan",
    "research.scan.scanned": "skills scanned",
    "research.scan.crawled": "skills crawled",
    "research.scan.source": "With source code",
    "research.download.csv": "Download raw data (CSV)",
    "research.download.json": "Download stats (JSON)",
    "research.limits": "What ATR Cannot Detect",
    "research.limits.sub":
      "We publish this section because honest limitations build more trust than false confidence.",
    "research.limits.full": "Full limitations document with 64 evasion tests",
    "research.limit.paraphrase": "Paraphrase Attacks",
    "research.limit.paraphrase.desc":
      'Any regex rule can be bypassed by semantically equivalent rephrasing. "Ignore previous instructions" is detected; "please set aside the guidance you were given earlier" is not.',
    "research.limit.multilang": "Multi-Language Attacks",
    "research.limit.multilang.desc":
      "All patterns are English-only. Injection payloads in Spanish, Chinese, Arabic, or any other language bypass all rules completely.",
    "research.limit.context": "Context-Dependent Attacks",
    "research.limit.context.desc":
      '"Delete all records" might be legitimate or malicious. Regex matches patterns without understanding authorization context.',
    "research.limit.protocol": "Protocol-Level Attacks",
    "research.limit.protocol.desc":
      "ATR inspects content, not transport. Message replay, schema manipulation, MCP transport-level MITM are invisible.",
    "research.limit.multiturn": "Multi-Turn Behavioral Patterns",
    "research.limit.multiturn.desc":
      "Gradual trust escalation across 20 turns, where no single message is detectable, is not correlated. ATR evaluates events independently.",
    "research.limit.novel": "Novel Attacks",
    "research.limit.novel.desc":
      "By definition, regex cannot detect attack patterns that don't exist yet. New techniques require new rules.",

    // Subpages
    "coverage.label": "Standards Coverage",
    "coverage.heading": "The frameworks name the threat. ATR runs it.",
    "coverage.sub":
      "MITRE ATLAS, OWASP, NIST AI RMF, ISO 42001 — six frameworks classify what can go wrong. ATR is the executable layer underneath: detection that fires on a real agent artifact. Every rule carries mappings into all six frameworks, enforced in CI.",
    "integrate.label": "Integrate",
    "integrate.heading": "Four paths. Same destination.",
    "research.label": "Research",
    "research.heading": "Data, benchmarks, and honest limitations.",
    "research.sub":
      "ATR publishes evasion tests openly. We tell you what we can't catch.",
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
    "spec.version": "version",
    "spec.date": "updated",
    "spec.editor": "editor",
    "spec.status_aria": "Document status",
    "spec.toc": "Table of Contents",
    "spec.toc_aria": "Specification table of contents",
    "spec.read_full": "Read the full specification",
    "spec.implementer_report": "Implementer Report",
    "cite.tablist_aria": "Citation format selector",

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
      "ATR is in production at the organizations listed below. Each row links to the merged pull request or integration commit that constitutes the public adoption record.",
    "home.get.intro":
      "The specification is published in three forms. The Markdown rendering is canonical; the JSON Schema and citation block are derived artifacts.",
    "home.get.markdown": "Markdown — canonical",
    "home.get.schema": "JSON Schema — machine-readable",
    "home.get.cite": "Citation — BibTeX / DOI",

    // Spec page
    "spec.title": "ATR Specification",
    "spec.subtitle":
      "The canonical, machine-readable rule format for detecting AI agent threats — what Sigma is to SIEM and YARA is to malware. A Working Draft maintained in the open by the ATR Community; the files in the repository, not this page, are authoritative.",
    "spec.abstract.h": "Abstract",
    "spec.status.h": "Status of This Document",
    "spec.status.body":
      "This document is a Working Draft published by the ATR Community. Although the rule format has been shipping in production for over a year, the surrounding governance is still transitioning from a single-maintainer model (BDFL) to a Technical Steering Committee. Discussion of this document takes place on the public GitHub repository.",

    // Implementers page
    "implementers.title": "Implementer Report",
    "implementers.subtitle":
      "A specification is only real when more than one engine implements it the same way. This report lists the organizations that run or reference ATR — each one independent evidence that the format can be implemented from the spec alone, the way W3C advances a standard on the strength of its implementations. Self-declared via pull request to the ADOPTERS.md registry.",
    "implementers.col.org": "Organization",
    "implementers.col.role": "Conformance",
    "implementers.col.version": "Spec Version",
    "implementers.col.date": "Integration Date",
    "implementers.col.ref": "Public Reference",
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
      "Conformance is what lets a rule written in Taipei run unchanged on an engine in Seattle. Three levels define what it means to claim a system implements ATR — so that any conforming engine evaluates the same rule the same way. Each level has a test suite published as YAML fixtures in the repository; conformance is demonstrated, not asserted.",
    "conformance.l1.title": "L1 Engine Conformance",
    "conformance.l1.body":
      "An L1 engine is what makes the format portable. It MUST parse every rule that validates against spec/atr-schema.yaml, MUST evaluate detection.conditions with the semantics defined in §3.5, and MUST honor scan_target and status semantics — so that the same rule yields the same verdict regardless of who wrote the engine. L1 engines MAY refuse rules outside their declared scan_target.",
    "conformance.l2.title": "L2 Publisher Conformance",
    "conformance.l2.body":
      "An L2 publisher publishes rules in a vendor-prefixed sub-range (e.g., ACME-YYYY-NNNNN) that follow all ATR semantics. L2 publishers MUST honor the deprecation policy in §3.7 and SHOULD include test_cases for every published rule.",
    "conformance.l3.title": "L3 Sub-range Authority",
    "conformance.l3.body":
      "An L3 sub-range authority is a national or organizational body that mints rules under a sovereign prefix (e.g., ATR-TW-2026-NNNNN). Authority is granted following the procedure in /charter §5; the TSC grants it once seated — until then the lead maintainer (BDFL) acts in this role.",
    "conformance.testsuite.h": "Test Suite",
    "conformance.testsuite.body":
      "The L1 engine test suite consists of YAML fixtures stored under spec/conformance/ in the main repository. Each fixture pairs a rule with its expected evaluation outcome on a fixed event — the contract is in the fixture, not in any one implementation. An implementation passes if every fixture evaluates as declared. Two engines that both pass agree, by construction, on every rule the suite covers.",
    "conformance.self.h": "Self-Certification",
    "conformance.self.body":
      "Implementations self-certify by running the test suite locally and opening a pull request against ADOPTERS.md with the integration metadata. The maintainers (the TSC once seated) may verify a self-certification at any time by re-running the suite against a published artifact.",

    // Errata page
    "errata.title": "Errata",
    "errata.subtitle":
      "A standing record of errors found in published versions of the ATR specification — kept in the open the way W3C and IETF specifications carry their errata. Every published version is permanent; the errors in it are corrected here, in public, with attribution. Each entry names the affected version, where the error sits, the corrective text, and the date the correction was published.",
    "errata.empty":
      "No errata are on record for the current Working Draft. The absence of entries is not a claim of perfection — it means no error has yet been confirmed in a published version. If you find one, open an issue on the repository; a confirmed report is added here, not quietly patched.",
    "errata.col.version": "Affected Version",
    "errata.col.section": "Section",
    "errata.col.summary": "Summary",
    "errata.col.date": "Published",

    // Glossary
    "glossary.title": "Glossary",
    "glossary.subtitle":
      "Definitions for key terms used throughout the specification. Where a term has a precise technical meaning that differs from common usage, the technical meaning takes precedence within the spec.",

    // Charter
    "charter.title": "Project Charter",
    "charter.subtitle":
      "A standard outlives the people who start it only if its rules are written down. This charter sets out what ATR is, what it is not, how decisions are made, and how the Technical Steering Committee is seated — the commitments that hold regardless of who maintains the project.",
    "charter.mission.h": "Mission",
    "charter.mission.body":
      "ATR exists to give the AI-agent security community a single shared format for declaring, exchanging, and evaluating detection rules — so that a defender in one organization can build on a rule written by a defender in another, in another country, without anyone re-inventing the rule format. A shared format is infrastructure, not a product: it belongs to no vendor and answers to the community that maintains it.",
    "charter.scope.h": "Scope",
    "charter.scope.in":
      "In scope: the rule format, the reference engine, the rule schema, conformance levels, and the cross-framework mappings (OWASP, MITRE ATLAS, NIST AI RMF, SAFE-MCP).",
    "charter.scope.out":
      "Out of scope: vendor-specific tooling, commercial integrations, runtime enforcement policy, and incident response coordination. These are the work of downstream implementers, and the standard stays deliberately narrow so that any of them can build on it without inheriting someone else's product decisions.",
    "charter.governance.h": "Governance",
    "charter.governance.body":
      "ATR is governed today by a single lead maintainer (BDFL), with a Technical Steering Committee being stood up to take that role. Concentrating authority in one maintainer is a phase, not the design: the transition criteria and the TSC seating process are written down in advance — in GOVERNANCE.md and docs/BDFL-charter.md — precisely so the move to shared governance happens by rule, not by accident.",
    "charter.ip.h": "Intellectual Property",
    "charter.ip.body":
      "ATR is released under the MIT License — permanently, with no path to relicensing the published standard. All contributions are MIT-licensed by submission; there is no CLA to sign and no rights to assign. Anyone may adopt, extend, or fork the rules, including vendors who compete with one another. The DOI for citation is 10.5281/zenodo.19178002.",

    // Citations
    "citations.title": "Citation",
    "citations.subtitle":
      "A standard becomes infrastructure the day other people's work can point at it and not have it move. ATR is built to be cited — by a paper, a CVE record, a CI script — through identifiers that never change after publication and a DOI that outlives any URL. The formats below are how you reference it.",

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
    "nav.rules": "\u898F\u5247",
    "nav.threats": "\u5A01\u8105\u60C5\u5831",
    "nav.coverage": "\u8986\u84CB\u7387",
    "nav.integrate": "\u6574\u5408",
    "nav.contribute": "\u8CA2\u737B",
    "nav.wall": "\u8CA2\u737B\u7246",
    "nav.ecosystem": "\u751F\u614B\u7CFB",
    "nav.red-team": "\u7D05\u968A",
    "nav.research": "\u7814\u7A76",
    "nav.about": "\u95DC\u65BC",
    "nav.changelog": "\u7248\u672C\u6B77\u7A0B",
    "nav.blog": "Blog",
    "nav.quality-standard": "\u54C1\u8CEA\u6A19\u6E96",
    "nav.cta": "\u6574\u5408",

    // Hero
    "hero.past": "\u6211\u5011\u904E\u53BB\u4FDD\u8B77\u4EBA\u3002",
    "hero.now": "\u73FE\u5728\u6211\u5011\u4FDD\u8B77 Agent\u3002",
    "hero.sub":
      "AI Agent \u5A01\u8105\u7684\u958B\u653E\u5075\u6E2C\u6A19\u6E96\u3002YAML \u898F\u5247\u3001MIT \u6388\u6B0A\u3001\u96F6\u9396\u5B9A\u3002",
    "hero.cta.primary": "\u5C07 ATR \u52A0\u5165\u4F60\u7684\u5E73\u53F0",
    "hero.cta.secondary": "\u700F\u89BD\u898F\u5247",
    "hero.stat.rules": "Rules",
    "hero.stat.categories": "Categories",
    "hero.stat.precision": "Precision",

    // Threat
    "threat.label": "MCP skills \u5A01\u8105\u6383\u63CF",
    "threat.body":
      "AI Agent \u73FE\u5728\u80FD\u700F\u89BD\u7DB2\u9801\u3001\u57F7\u884C\u7A0B\u5F0F\u78BC\u3001\u547C\u53EB\u5916\u90E8\u5DE5\u5177\u3002\u653B\u64CA\u8005\u5229\u7528\u5B83\u5011<strong>\u6D29\u6F0F\u6191\u8B49</strong>\u3001<strong>\u57F7\u884C\u60E1\u610F\u6307\u4EE4</strong>\u3001<strong>\u7E5E\u904E\u5B89\u5168\u908A\u754C</strong>\u3002\u653B\u64CA\u9762\u7684\u589E\u9577\u901F\u5EA6\u8D85\u904E\u4EFB\u4F55\u5718\u968A\u624B\u5BEB\u898F\u5247\u7684\u901F\u5EA6\u3002",

    // Numbers
    "numbers.rules.desc":
      "\u6A6B\u8DE8 {categories} \u500B\u5A01\u8105\u985E\u5225\u3002\u6BCF\u689D\u898F\u5247\u90FD\u5C0D\u61C9\u771F\u5BE6 CVE \u548C OWASP \u6A19\u6E96\u3002",
    "numbers.precision.desc":
      "\u5728 {samples} \u500B\u5C0D\u6297\u6A23\u672C\u4E0A\u7684 Precision\u3002\u5916\u90E8 PINT benchmark\u3002",
    "numbers.latency.desc":
      "99% \u7684\u4E8B\u4EF6\u5728 Tier 0-2 \u89E3\u6C7A\u3002\u96F6 API \u6210\u672C\u3002",
    "numbers.scan.desc":
      "\u6383\u63CF OpenClaw + Skills.sh\u3002{critical} CRITICAL\u3001{high} HIGH\u3002",
    "numbers.owasp.desc": "OWASP Agentic Top 10 \u5168\u90E8\u8986\u84CB\u3002",
    "numbers.safemcp.desc":
      "SAFE-MCP \u6280\u8853\u8986\u84CB\u7387\u300278/85\u3002",

    // Proof
    "proof.label": "\u5DF2\u5728\u751F\u7522\u74B0\u5883\u904B\u884C",
    "proof.heading.pre": "Cisco AI Defense",
    "proof.heading.post":
      " \u5C07\n34 \u689D ATR \u898F\u5247\u4F5C\u70BA\u4E0A\u6E38\u4F9D\u8CF4\u3002",
    "proof.body":
      "\u4ED6\u5011\u7684\u5DE5\u7A0B\u5E2B\u63D0\u4E86 PR\u3002\u6211\u5011 review \u5B8C\u30023 \u5929\u5408\u4F75\u30021,272 \u884C\u65B0\u589E\u3002\u7136\u5F8C\u4ED6\u5011\u5EFA\u4E86 --rule-packs CLI \u5C08\u9580\u6D88\u8CBB ATR\u3002",
    "proof.link": "\u5728 GitHub \u67E5\u770B PR #79",

    // Ecosystem
    "ecosystem.label": "\u751F\u614B\u7CFB",
    "ecosystem.heading":
      "{merged} \u500B\u5DF2\u5408\u4F75\u3002{open} \u500B\u5F85\u5BE9\u3002\u5171 {total} \u500B PR\u3002",
    "ecosystem.sub":
      "ATR \u900F\u904E PR \u64F4\u6563\uff0c\u4E0D\u662F\u900F\u904E\u92B7\u552E\u3002\u958B\u6E90\u3001MIT \u6388\u6B0A\u3001\u96F6\u9396\u5B9A\u3002",

    // Future
    "future.label": "\u672A\u4F86",
    "future.heading": "ATR \u898F\u5247\u4E0D\u9700\u8981\u624B\u5BEB\u3002",
    "future.sub":
      "Threat Cloud \u7D50\u6676\u6A5F\u5236\u81EA\u52D5\u5C07\u65B0\u653B\u64CA\u8F49\u5316\u70BA\u5075\u6E2C\u898F\u5247\u3002",
    "future.note":
      "\u50B3\u7D71\u898F\u5247\u7531\u4EBA\u5DE5\u64B0\u5BEB\uff0c\u9031\u671F\u4EE5\u9031\u8A08\u3002Threat Cloud \u8B93\u65B0\u898F\u5247\u7684\u7522\u51FA\u5F9E\u6578\u9031\u7E2E\u77ED\u5230\u6578\u5C0F\u6642\u3002",

    // CTA
    "cta.heading": "\u5C07 ATR \u52A0\u5165\u4F60\u7684\u5E73\u53F0\u3002",
    "cta.sub":
      "\u56DB\u689D\u8DEF\u5F91\u3002TypeScript\u3001Python\u3001\u539F\u59CB YAML\u3001\u6216 SIEM queries\u3002\n\u8DDF Cisco \u8D70\u7684\u540C\u4E00\u689D\u8DEF\u3002",
    "cta.primary": "Integration Guide",
    "cta.secondary": "\u700F\u89BD\u6240\u6709\u898F\u5247",

    // Compare
    "compare.label": "\u70BA\u4EC0\u9EBC\u9078 ATR",
    "compare.heading":
      "\u70BA\u4EC0\u9EBC\u4E0D\u81EA\u5DF1\u5BEB\u898F\u5247\uff1f",
    "compare.sub":
      "ATR vs \u66FF\u4EE3\u65B9\u6848\u3002\u8AA0\u5BE6\u7684\u6BD4\u8F03\u3002",

    // Homepage data
    "categories.label": "ATR \u5075\u6E2C\u4EC0\u9EBC",
    "categories.heading":
      "{categories} \u500B\u5A01\u8105\u985E\u5225\u3002{rules} \u689D\u898F\u5247\u3002\u771F\u5BE6 CVE\u3002",
    "categories.sub":
      "\u6BCF\u689D\u898F\u5247\u90FD\u9023\u7D50\u5230 OWASP\u3001MITRE ATLAS \u548C\u5DF2\u8A18\u9304\u7684\u6F0F\u6D1E\u3002",
    "scan.label": "\u5373\u6642\u6383\u63CF\u6578\u64DA",
    "scan.mega": "Mega Scan",
    "scan.threats": "\u767C\u73FE\u5A01\u8105",
    "scan.sources": "\u6578\u64DA\u4F86\u6E90",
    "scan.latency": "\u5E73\u5747\u5EF6\u9072",
    "scan.skills_scanned": "skills \u5DF2\u6383\u63CF",
    "scan.flagged": "\u5DF2\u6A19\u8A18",
    "scan.per_skill": "\u6BCF skill \u6383\u63CF",
    "crystal.1":
      "\u5728\u91CE\u5916\u5075\u6E2C\u5230\u65B0\u653B\u64CA\u6A21\u5F0F",
    "crystal.2": "LLM \u5206\u6790\u653B\u64CA\u7D50\u69CB + \u610F\u5716",
    "crystal.3": "\u81EA\u52D5\u7522\u751F YAML \u898F\u5247\u63D0\u6848",
    "crystal.4": "\u793E\u7FA4\u5BE9\u67E5 + precision \u6E2C\u8A66",
    "crystal.5":
      "\u5408\u4F75\u5230 ATR\u3002\u6240\u6709\u5F15\u64CE\u81EA\u52D5\u66F4\u65B0\u3002",
    "path.01.title": "\u56DE\u5831\u7E5E\u904E\u65B9\u6CD5",
    "path.01.desc":
      "\u627E\u5230\u4E86\u7E5E\u904E\u65B9\u6CD5\uff1F\u63D0\u4E00\u500B issue\u3002\u53EA\u8981 15 \u5206\u9418\u3002\u6700\u6709\u50F9\u503C\u7684\u8CA2\u737B\u3002",
    "path.02.title": "\u56DE\u5831\u8AA4\u5224",
    "path.02.desc":
      "\u898F\u5247\u5C0D\u5408\u6CD5\u5167\u5BB9\u89F8\u767C\u4E86\uff1F\u5E6B\u6211\u5011\u8ABF\u6574 precision\u300220 \u5206\u9418\u3002",
    "path.03.title": "\u63D0\u4EA4\u65B0\u898F\u5247",
    "path.03.desc":
      "\u7528 ATR schema \u5BEB\u4E00\u689D\u5075\u6E2C\u898F\u5247\u3002\u6709\u5B8C\u6574\u6559\u5B78\u30021-2 \u5C0F\u6642\u3002",
    "path.04.title": "AI \u539F\u751F\u8CA2\u737B",
    "path.04.desc":
      "\u7528 Claude Code \u6216 Cursor \u914D\u5408 ATR \u7684 MCP server\u3002AI \u5BEB YAML\uff0C\u4F60\u5BE9\u67E5\u3002",

    // Rules page
    "rules.label": "Rule Explorer",
    "rules.heading":
      "{count} \u689D\u5075\u6E2C\u898F\u5247\u3002\u700F\u89BD\u3001\u904E\u6FFE\u3001\u6AA2\u67E5\u3002",
    "rules.sub":
      "\u6BCF\u689D\u898F\u5247\u90FD\u6709\u7A69\u5B9A\u7684 ATR-YYYY-NNNNN \u8B58\u5225\u78BC\u2014\u2014CVE/CWE \u9AD4\u88C1\uFF0C\u4E00\u7D93\u767C\u5E03\u6C38\u4E0D\u66F4\u6539\u3002\u898F\u5247\u5728 build time \u5F9E YAML \u89E3\u6790\uFF1B\u9EDE\u64CA\u4EFB\u4F55\u898F\u5247\uFF0C\u67E5\u770B\u5B83\u7684\u5075\u6E2C\u908F\u8F2F\u3001\u6E2C\u8A66\u6848\u4F8B\u8207\u5DF2\u77E5\u9650\u5236\u3002",
    "rules.search":
      "\u641C\u7D22\u898F\u5247\u2026\uff08\u540D\u7A31\u3001ID\u3001CVE\uff09",
    "rules.all_categories": "\u6240\u6709\u985E\u5225",
    "rules.all_severities": "\u6240\u6709\u56B4\u91CD\u7B49\u7D1A",
    "rules.showing": "\u986F\u793A {filtered} / {total} \u689D\u898F\u5247",
    "rules.no_match":
      "\u6C92\u6709\u898F\u5247\u7B26\u5408\u4F60\u7684\u904E\u6FFE\u689D\u4EF6\u3002",
    "rules.clear": "\u6E05\u9664\u904E\u6FFE",
    "rules.col.id": "Rule ID",
    "rules.col.name": "\u540D\u7A31",
    "rules.col.category": "\u985E\u5225",
    "rules.col.severity": "\u56B4\u91CD\u7B49\u7D1A",
    "rules.col.cves": "CVEs",
    "rules.col.desc": "\u63CF\u8FF0",
    "rules.view_yaml": "\u5728 GitHub \u67E5\u770B YAML",

    // Integrate page
    "integrate.ready":
      "{count} \u689D\u898F\u5247\uFF0C\u5BEB\u4E00\u6B21\uFF0C\u4EFB\u4F55\u5730\u65B9\u90FD\u80FD\u8DD1\u3002\u540C\u4E00\u4EFD\u898F\u5247\u96C6\uFF0C\u63A5\u9032 TypeScript\u3001Python\u3001CI \u6216 SIEM\u2014\u2014Cisco\u3001Microsoft\u3001MISP \u5DF2\u7D93\u8D70\u904E\u7684\u8DEF\u3002",
    "integrate.schema.title": "Schema \u7A69\u5B9A\u6027\u4FDD\u8B49",
    "integrate.schema.intro":
      "\u5982\u679C\u4F60\u4F9D\u8CF4 ATR \u4F5C\u70BA\u4E0A\u6E38\uff0C\u4F60\u9700\u8981\u77E5\u9053\u683C\u5F0F\u4E0D\u6703\u58DE\u6389\u3002\u9019\u662F\u6211\u5011\u7684\u627F\u8AFE\uff1A",
    "integrate.schema.v1.title":
      "ATR Schema v1.0\uff08\u7576\u524D\u7248\u672C\uff09",
    "integrate.schema.v1.desc":
      "\u5DF2\u767C\u5E03\u4E14\u7A69\u5B9A\u3002\u6240\u6709\u65B0\u6B04\u4F4D\u90FD\u662F\u53EF\u9078\u7684\u3002\u73FE\u6709\u6B04\u4F4D\u4E0D\u6703\u5728\u6C92\u6709 major version \u8B8A\u66F4\u7684\u60C5\u6CC1\u4E0B\u79FB\u9664\u6216\u91CD\u65B0\u547D\u540D\u3002",
    "integrate.schema.compat.title": "\u5411\u5F8C\u76F8\u5BB9\u6027",
    "integrate.schema.compat.desc":
      "\u7834\u58DE\u6027\u8B8A\u66F4\u53EA\u5728 major version \u8F49\u63DB\u6642\u767C\u751F\uff08v1 \u2192 v2\uff09\u3002\u63D0\u4F9B\u9077\u79FB\u6307\u5357\u548C\u81F3\u5C11 6 \u500B\u6708\u7684\u91CD\u758A\u652F\u63F4\u671F\u3002",
    "integrate.schema.freq.title": "\u66F4\u65B0\u983B\u7387",
    "integrate.schema.freq.desc":
      "\u65B0\u898F\u5247\u6301\u7E8C\u65B0\u589E\uff08\u5E73\u5747\u6BCF\u9031 2-5 \u689D\uff09\u3002\u6BCF\u689D\u898F\u5247\u90FD\u901A\u904E CI \u9A57\u8B49 + precision \u6E2C\u8A66\u624D\u80FD merge\u3002",
    "integrate.schema.sync.title": "\u540C\u6B65\u65B9\u6CD5",
    "integrate.why.title":
      "\u70BA\u4EC0\u9EBC\u7528 ATR \u800C\u4E0D\u662F\u81EA\u5DF1\u5BEB\uff1F",
    "integrate.license.title": "\u6388\u6B0A\u8207\u6CD5\u5F8B",
    "integrate.cisco.title": "\u6848\u4F8B\uff1ACisco \u600E\u9EBC\u505A\u7684",
    "integrate.cisco.body":
      "Cisco \u7684 AI Defense \u5718\u968A\u5C07 ATR rules \u4F5C\u70BA\u4E0A\u6E38\u4F9D\u8CF4\u6574\u5408\u3002\u4ED6\u5011\u7684\u5DE5\u7A0B\u5E2B\u63D0\u4EA4\u4E86 PR #79\uff0C\u6211\u5011 review \u5B8C\uff0C3 \u5929\u5408\u4F75\u3002\u7136\u5F8C\u4ED6\u5011\u5EFA\u4E86 --rule-packs CLI\uff08PR #80\uff09\u5C08\u9580\u6D88\u8CBB ATR\u3002",

    // Contribute page
    "contribute.crystal.title": "Threat Cloud \u7D50\u6676\u6A5F\u5236",
    "contribute.crystal.sub":
      "\u50B3\u7D71\u898F\u5247\u9700\u8981\u6578\u9031\u64B0\u5BEB\u3001\u5BE9\u67E5\u3001\u767C\u5E03\u3002Threat Cloud \u76EE\u6A19\u6578\u5C0F\u6642\u3002",
    "contribute.governance": "\u6CBB\u7406",
    "contribute.governance.desc":
      "\u898F\u5247\u5BE9\u67E5\u6D41\u7A0B\u3001\u7DAD\u8B77\u8005\u89D2\u8272\u3001\u6C7A\u7B56\u6A5F\u5236\u3002",
    "contribute.contributors": "\u8CA2\u737B\u8005",
    "contribute.contributors.desc":
      "\u69AE\u8B7D\u724C\u3002\u6BCF\u500B\u78BA\u8A8D\u7684\u7E5E\u904E\u3001\u8AA4\u5224\u56DE\u5831\u548C\u898F\u5247\u90FD\u6703\u88AB\u8A18\u529F\u3002",
    "contribute.guide": "\u898F\u5247\u64B0\u5BEB\u6307\u5357",
    "contribute.guide.desc":
      "\u5B8C\u6574\u6559\u5B78\uff0C\u9644\u7BC4\u4F8B\u548C schema \u53C3\u8003\u3002",

    // Research page
    "research.paper": "\u5DF2\u767C\u5E03\u8AD6\u6587",
    "research.benchmarks": "Benchmarks",
    "research.benchmarks.sub":
      "\u7528\u6211\u5011\u81EA\u5DF1\u7684\u8A9E\u6599\u5EAB,\u4EE5\u53CA\u516C\u958B\u5C0D\u6297\u8CC7\u6599\u96C6(deepset\u3001Lakera Gandalf\u3001HackAPrompt\u3001garak)\u6E2C\u8A66\u3002",
    "research.pint": "PINT \u683C\u5F0F\uff08\u81EA\u5EFA\u8A9E\u6599\uff09",
    "research.self": "Self-Test\uff08\u81EA\u6709\u898F\u5247\uff09",
    "research.precision": "Precision",
    "research.recall": "Recall",
    "research.samples": "\u6A23\u672C\u6578",
    "research.gap_note":
      "{precision}% precision \u548C {recall}% recall \u4E4B\u9593\u7684\u5DEE\u8DDD\u662F\u9810\u671F\u7684\u3002Regex \u80FD\u6293\u5230\u5DF2\u77E5\u6A21\u5F0F\uff0C\u4F46\u6703\u6F0F\u6389\u91CD\u8FF0\u548C\u591A\u8A9E\u8A00\u653B\u64CA\u3002",
    "research.scan": "\u751F\u614B\u7CFB\u6383\u63CF\u6578\u64DA",
    "research.scan.sub":
      "\u771F\u5BE6\u6383\u63CF\u771F\u5BE6\u7684 MCP skill \u8A3B\u518A\u8868\u3002",
    "research.scan.mega": "Mega Scan\uff08OpenClaw + Skills.sh\uff09",
    "research.scan.clawhub": "ClawHub \u8A3B\u518A\u8868\u6383\u63CF",
    "research.scan.scanned": "skills \u5DF2\u6383\u63CF",
    "research.scan.crawled": "skills \u5DF2\u722C\u53D6",
    "research.scan.source": "\u6709\u6E90\u78BC",
    "research.download.csv": "\u4E0B\u8F09\u539F\u59CB\u6578\u64DA (CSV)",
    "research.download.json": "\u4E0B\u8F09\u7D71\u8A08 (JSON)",
    "research.limits": "ATR \u7121\u6CD5\u5075\u6E2C\u4EC0\u9EBC",
    "research.limits.sub":
      "\u6211\u5011\u767C\u5E03\u9019\u500B\u7AE0\u7BC0\uff0C\u56E0\u70BA\u8AA0\u5BE6\u7684\u9650\u5236\u6BD4\u865B\u5047\u7684\u81EA\u4FE1\u66F4\u80FD\u5EFA\u7ACB\u4FE1\u4EFB\u3002",
    "research.limits.full":
      "\u5B8C\u6574\u9650\u5236\u6587\u4EF6\uff0C\u5305\u542B 64 \u500B evasion test",
    "research.limit.paraphrase": "\u91CD\u8FF0\u653B\u64CA",
    "research.limit.paraphrase.desc":
      "\u4EFB\u4F55 regex \u898F\u5247\u90FD\u53EF\u4EE5\u88AB\u8A9E\u7FA9\u7B49\u50F9\u7684\u91CD\u8FF0\u7E5E\u904E\u3002\u300CIgnore previous instructions\u300D\u6703\u88AB\u5075\u6E2C\uff1B\u300Cplease set aside the guidance you were given earlier\u300D\u4E0D\u6703\u3002",
    "research.limit.multilang": "\u591A\u8A9E\u8A00\u653B\u64CA",
    "research.limit.multilang.desc":
      "\u6240\u6709\u6A21\u5F0F\u90FD\u662F\u82F1\u6587\u7684\u3002\u7528\u897F\u73ED\u7259\u8A9E\u3001\u4E2D\u6587\u3001\u963F\u62C9\u4F2F\u8A9E\u6216\u4EFB\u4F55\u5176\u4ED6\u8A9E\u8A00\u5BEB\u7684\u6CE8\u5165\u653B\u64CA\u6703\u5B8C\u5168\u7E5E\u904E\u3002",
    "research.limit.context": "\u4E0A\u4E0B\u6587\u76F8\u95DC\u653B\u64CA",
    "research.limit.context.desc":
      "\u300CDelete all records\u300D\u53EF\u80FD\u662F\u5408\u6CD5\u6216\u60E1\u610F\u7684\u3002Regex \u5339\u914D\u6A21\u5F0F\u4F46\u4E0D\u7406\u89E3\u6388\u6B0A\u4E0A\u4E0B\u6587\u3002",
    "research.limit.protocol": "\u5354\u8B70\u5C64\u653B\u64CA",
    "research.limit.protocol.desc":
      "ATR \u6AA2\u67E5\u5167\u5BB9\uff0C\u4E0D\u6AA2\u67E5\u50B3\u8F38\u3002Message replay\u3001schema manipulation\u3001MCP \u50B3\u8F38\u5C64 MITM \u662F\u4E0D\u53EF\u898B\u7684\u3002",
    "research.limit.multiturn": "\u591A\u8F2A\u884C\u70BA\u6A21\u5F0F",
    "research.limit.multiturn.desc":
      "20 \u8F2A\u5C0D\u8A71\u4E2D\u7684\u6F38\u9032\u5F0F\u4FE1\u4EFB\u5347\u7D1A\uff0C\u55AE\u4E00\u8A0A\u606F\u7121\u6CD5\u5075\u6E2C\uff0CATR \u4E0D\u6703\u95DC\u806F\u3002ATR \u7368\u7ACB\u8A55\u4F30\u6BCF\u500B\u4E8B\u4EF6\u3002",
    "research.limit.novel": "\u65B0\u578B\u653B\u64CA",
    "research.limit.novel.desc":
      "\u6839\u64DA\u5B9A\u7FA9\uff0Cregex \u7121\u6CD5\u5075\u6E2C\u9084\u4E0D\u5B58\u5728\u7684\u653B\u64CA\u6A21\u5F0F\u3002\u65B0\u6280\u8853\u9700\u8981\u65B0\u898F\u5247\u3002",

    // Subpages
    "coverage.label": "\u6A19\u6E96\u8986\u84CB",
    "coverage.heading":
      "\u6846\u67B6\u5B9A\u7FA9\u5A01\u8105\uff0CATR \u8B93\u5B83\u8DD1\u8D77\u4F86\u3002",
    "coverage.sub":
      "MITRE ATLAS\u3001OWASP\u3001NIST AI RMF\u3001ISO 42001\u2014\u2014\u516D\u500B\u6846\u67B6\u5206\u985E\u300C\u4EC0\u9EBC\u6703\u51FA\u932F\u300D\u3002ATR \u662F\u5176\u4E0B\u53EF\u57F7\u884C\u7684\u90A3\u4E00\u5C64\uFF1A\u80FD\u5728\u771F\u5BE6 agent \u6210\u54C1\u4E0A\u958B\u706B\u7684\u5075\u6E2C\u3002\u6BCF\u4E00\u689D\u898F\u5247\u90FD\u5E36\u6709\u9019\u516D\u500B\u6846\u67B6\u7684\u5C0D\u61C9\uff0C\u4E26\u7531 CI \u5F37\u5236\u3002",
    "integrate.label": "Integrate",
    "integrate.heading":
      "\u56DB\u689D\u8DEF\u5F91\u3002\u540C\u4E00\u500B\u7D42\u9EDE\u3002",
    "research.label": "\u7814\u7A76",
    "research.heading":
      "\u6578\u64DA\u3001Benchmark \u548C\u8AA0\u5BE6\u7684\u9650\u5236\u3002",
    "research.sub":
      "ATR \u516C\u958B\u767C\u5E03 evasion test\u3002\u6211\u5011\u544A\u8A34\u4F60\u6211\u5011\u6293\u4E0D\u5230\u4EC0\u9EBC\u3002",
    "contribute.label": "\u8CA2\u737B",
    "contribute.heading":
      "\u4E00\u689D\u898F\u5247\uFF0C\u63D0\u4E00\u6B21\uFF0C\u4FDD\u8B77\u6BCF\u4E00\u500B\u8B80\u9019\u500B\u6A19\u6E96\u7684\u4EBA\u3002",
    "contribute.sub":
      "ATR \u662F MIT \u6388\u6B0A\u3001\u793E\u7FA4\u7DAD\u8B77\u3002\u8CA2\u737B\u53EA\u9700\u8981\u4E00\u500B\u6587\u5B57\u7DE8\u8F2F\u5668\u548C\u4E00\u500B YAML \u6A94\u6848\u2014\u2014\u96F6\u5C08\u6709\u5DE5\u5177\u3001\u96F6\u9059\u6E2C\u3001\u96F6 CLA\u3002",

    // Footer
    "footer.note":
      "ATR \u662F\u793E\u7FA4\u7DAD\u8B77\u7684\u958B\u653E\u6A19\u6E96\u3002MIT \u6388\u6B0A\u3002\u4E0D\u96B8\u5C6C\u65BC\u4EFB\u4F55\u5EE0\u5546\u3002",

    // \u2500\u2500 Standards site additions \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    "spec.canonical": "\u6B63\u5F0F\u7DB2\u5740",
    "spec.version": "\u7248\u672C",
    "spec.date": "\u66F4\u65B0\u65BC",
    "spec.editor": "\u7DE8\u8F2F",
    "spec.status_aria": "\u6587\u4EF6\u72C0\u614B",
    "spec.toc": "\u76EE\u9304",
    "spec.toc_aria": "\u898F\u683C\u76EE\u9304",
    "spec.read_full": "\u95B1\u8B80\u5B8C\u6574\u898F\u683C",
    "spec.implementer_report": "\u5BE6\u4F5C\u8005\u5831\u544A (Implementer Report)",
    "cite.tablist_aria": "\u5F15\u7528\u683C\u5F0F\u9078\u64C7\u5668",

    "nav.atd": "ATD",
    "nav.spec": "\u898F\u683C (Specification)",
    "nav.implementers": "\u5BE6\u4F5C\u8005 (Implementers)",
    "nav.conformance": "\u7B26\u898F (Conformance)",
    "nav.governance": "\u6CBB\u7406 (Governance)",
    "nav.community": "\u793E\u7FA4 (Community)",
    "nav.charter": "\u7AE0\u7A0B (Charter)",
    "nav.glossary": "\u8A5E\u5F59 (Glossary)",
    "nav.errata": "\u52D8\u8AA4 (Errata)",
    "nav.citations": "\u5F15\u7528 (Cite)",

    "home.title": "ATR \u2014 Agent Threat Rules",
    "home.subtitle":
      "AI Agent \u5B89\u5168\u5A01\u8105\u7684\u958B\u653E\u5075\u6E2C\u898F\u5247\u683C\u5F0F \u2500\u2500 \u5EE0\u5546\u4E2D\u7ACB\u3001\u6A5F\u5668\u53EF\u8B80\u3001\u53EF\u540C\u5115\u5BE9\u67E5 (peer-reviewable)\u3002",
    "home.abstract":
      "Agent Threat Rules (ATR) \u662F AI Agent \u5B89\u5168\u5A01\u8105\u7684\u958B\u653E\u5075\u6E2C\u898F\u5247\u683C\u5F0F\u3002\u898F\u5247\u4EE5 YAML \u64B0\u5BEB,\u9075\u5FAA\u7248\u672C\u5316 schema,\u4F7F\u7528\u516C\u958B\u7684 ATR-YYYY-NNNNN \u8B58\u5225\u78BC\u65B9\u6848,\u53EF\u7531\u4EFB\u4F55\u7B26\u898F\u5F15\u64CE\u8A55\u4F30\u3002ATR \u4E4B\u65BC AI Agent \u5A01\u8105\u5075\u6E2C,\u5982\u540C Sigma \u4E4B\u65BC SIEM \u5075\u6E2C\u3001YARA \u4E4B\u65BC\u60E1\u610F\u7A0B\u5F0F\u7C3D\u7AE0 \u2500\u2500 \u4E00\u500B\u5EE0\u5546\u4E2D\u7ACB\u3001\u6A5F\u5668\u53EF\u8B80\u3001\u53EF\u540C\u5115\u5BE9\u67E5\u7684\u898F\u5247\u683C\u5F0F\u3002",
    "home.cta.spec": "\u95B1\u8B80\u898F\u683C (\u00A73)",
    "home.cta.schema": "\u67E5\u770B JSON Schema",
    "home.cta.implementers": "\u67E5\u770B\u5BE6\u4F5C\u8005\u5217\u8868",
    "home.section.overview": "Overview",
    "home.section.adoption": "Production \u63A1\u7528",
    "home.section.get": "\u53D6\u5F97\u898F\u683C",
    "home.adoption.intro":
      "ATR \u5728\u4E0B\u8868\u5217\u51FA\u7684\u7D44\u7E54\u4E2D\u5DF2\u90E8\u7F72\u65BC\u751F\u7522\u74B0\u5883\u3002\u6BCF\u4E00\u5217\u9023\u7D50\u5230\u69CB\u6210\u516C\u958B\u63A1\u7528\u7D00\u9304\u7684\u5408\u4F75 pull request \u6216\u6574\u5408 commit\u3002",
    "home.get.intro":
      "\u898F\u683C\u4EE5\u4E09\u7A2E\u5F62\u5F0F\u767C\u5E03\u3002Markdown \u6E32\u67D3\u70BA\u6B63\u672C (canonical);JSON Schema \u8207\u5F15\u7528 (citation) \u70BA\u884D\u751F\u7522\u7269 (derived artifact)\u3002",
    "home.get.markdown": "Markdown \u2014 \u6B63\u672C",
    "home.get.schema": "JSON Schema \u2014 \u6A5F\u5668\u53EF\u8B80",
    "home.get.cite": "\u5F15\u7528 \u2014 BibTeX / DOI",

    "spec.title": "ATR \u898F\u683C (Specification)",
    "spec.subtitle":
      "AI agent \u5A01\u8105\u5075\u6E2C\u7684\u6B63\u672C\u3001\u6A5F\u5668\u53EF\u8B80\u898F\u5247\u683C\u5F0F \u2500\u2500 \u4E00\u5982 Sigma \u4E4B\u65BC SIEM\u3001YARA \u4E4B\u65BC malware\u3002\u7531 ATR \u793E\u7FA4\u65BC\u516C\u958B\u8655\u7DAD\u8B77\u7684 Working Draft;\u4EE5 repository \u4E2D\u7684\u6A94\u6848\u70BA\u6E96,\u800C\u975E\u672C\u9801\u3002",
    "spec.abstract.h": "\u6458\u8981 (Abstract)",
    "spec.status.h": "\u672C\u6587\u4EF6\u72C0\u614B (Status of This Document)",
    "spec.status.body":
      "\u672C\u6587\u4EF6\u70BA ATR \u793E\u7FA4\u767C\u5E03\u7684 Working Draft\u3002\u5118\u7BA1\u898F\u5247\u683C\u5F0F\u5DF2\u5728\u751F\u7522\u74B0\u5883\u904B\u884C\u8D85\u904E\u4E00\u5E74,\u5468\u908A\u6CBB\u7406\u4ECD\u8655\u65BC\u5F9E\u55AE\u4E00\u7DAD\u8B77\u8005\u6A21\u578B (BDFL) \u904E\u6E21\u5230\u6280\u8853\u6307\u5C0E\u59D4\u54E1\u6703 (TSC) \u7684\u968E\u6BB5\u3002\u672C\u6587\u4EF6\u7684\u8A0E\u8AD6\u65BC\u516C\u958B GitHub repository \u9032\u884C\u3002",

    "implementers.title": "Implementer Report",
    "implementers.subtitle":
      "\u4E00\u500B\u898F\u683C\u8981\u5230\u6709\u4E0D\u53EA\u4E00\u500B\u5F15\u64CE\u80FD\u7528\u540C\u4E00\u7A2E\u65B9\u5F0F\u5BE6\u4F5C\u5B83\u6642,\u624D\u7B97\u771F\u5BE6\u3002\u672C\u5831\u544A\u5217\u51FA\u57F7\u884C\u6216\u5F15\u7528 ATR \u7684\u7D44\u7E54\u2014\u2014\u6BCF\u4E00\u500B\u90FD\u662F\u4E00\u500B\u7368\u7ACB\u8B49\u64DA:\u8B49\u660E\u9019\u500B\u683C\u5F0F\u53EF\u4EE5\u53EA\u6191\u898F\u683C\u5C31\u88AB\u5BE6\u4F5C\u51FA\u4F86\u2014\u2014\u9019\u6B63\u662F W3C \u9760\u5BE6\u4F5C\u6578\u91CF\u63A8\u9032\u6A19\u6E96\u7684\u65B9\u5F0F\u3002\u900F\u904E pull request \u5C0D ADOPTERS.md registry \u81EA\u6211\u5BA3\u544A (self-declaration)\u3002",
    "implementers.col.org": "\u7D44\u7E54",
    "implementers.col.role": "\u7B26\u898F\u7B49\u7D1A",
    "implementers.col.version": "\u898F\u683C\u7248\u672C",
    "implementers.col.date": "\u6574\u5408\u65E5\u671F",
    "implementers.col.ref": "\u516C\u958B\u6191\u64DA",
    "implementers.tier.engine": "L1 Engine",
    "implementers.tier.publisher": "L2 Publisher",
    "implementers.tier.citation": "L1 Citation",
    "implementers.tier.galaxy": "L1 Galaxy",
    "implementers.tier.accepted": "Submission in review",
    "implementers.empty":
      "\u76EE\u524D\u7121\u7D00\u9304\u3002\u5C0D ADOPTERS.md \u958B PR \u5373\u53EF\u52A0\u5165\u4F60\u7684\u7D44\u7E54\u3002",

    "conformance.title": "\u7B26\u898F (Conformance)",
    "conformance.subtitle":
      "\u7B26\u898F,\u6B63\u662F\u8B93\u4E00\u689D\u5728\u53F0\u5317\u5BEB\u7684\u898F\u5247,\u80FD\u539F\u5C01\u4E0D\u52D5\u8DD1\u5728\u897F\u96C5\u5716\u7684\u5F15\u64CE\u4E0A\u3002\u4E09\u500B\u7B49\u7D1A\u5B9A\u7FA9\u300C\u5BE6\u4F5C ATR\u300D\u4EE3\u8868\u7684\u610F\u6DB5\u2014\u2014\u4EFB\u4F55\u7B26\u898F\u7684\u5F15\u64CE,\u5C0D\u540C\u4E00\u689D\u898F\u5247\u90FD\u8A55\u4F30\u51FA\u540C\u4E00\u500B\u7D50\u679C\u3002\u6BCF\u4E00\u7B49\u7D1A\u5728 repository \u4E2D\u4EE5 YAML fixture \u5F62\u5F0F\u767C\u5E03\u5C0D\u61C9\u7684\u6E2C\u8A66\u5957\u4EF6 (test suite);\u7B26\u898F\u9760\u8DD1\u51FA\u4F86,\u4E0D\u9760\u5BA3\u7A31\u3002",
    "conformance.l1.title": "L1 Engine Conformance",
    "conformance.l1.body":
      "L1 engine \u662F\u8B93\u683C\u5F0F\u53EF\u651C\u7684\u90A3\u4E00\u5C64\u3002\u5B83 MUST \u80FD\u89E3\u6790\u4EFB\u4F55\u901A\u904E spec/atr-schema.yaml \u9A57\u8B49\u7684\u898F\u5247,MUST \u4EE5 \u00A73.5 \u5B9A\u7FA9\u7684\u8A9E\u610F\u8A55\u4F30 detection.conditions,\u4E26 MUST \u9075\u5B88 scan_target \u8207 status \u7684\u8A9E\u610F\u2014\u2014\u597D\u8B93\u540C\u4E00\u689D\u898F\u5247,\u7121\u8AD6\u5F15\u64CE\u51FA\u81EA\u8AB0\u624B,\u90FD\u5F97\u51FA\u540C\u4E00\u500B\u5224\u5B9A\u3002L1 engine MAY \u62D2\u7D55\u843D\u5728\u5176\u5BA3\u544A scan_target \u7BC4\u570D\u5916\u7684\u898F\u5247\u3002",
    "conformance.l2.title": "L2 Publisher Conformance",
    "conformance.l2.body":
      "L2 publisher \u5728\u5EE0\u5546\u524D\u7DB4 (vendor-prefixed) \u7684\u5B50\u7BC4\u570D (\u4F8B\u5982 ACME-YYYY-NNNNN) \u5167\u767C\u5E03\u7B26\u5408 ATR \u8A9E\u610F\u7684\u898F\u5247\u3002L2 publisher MUST \u9075\u5B88 \u00A73.7 \u7684\u5EE2\u68C4\u653F\u7B56,SHOULD \u70BA\u6BCF\u4E00\u689D\u767C\u5E03\u898F\u5247\u9644\u4E0A test_cases\u3002",
    "conformance.l3.title": "L3 Sub-range Authority",
    "conformance.l3.body":
      "L3 sub-range authority \u662F\u570B\u5BB6\u7D1A\u6216\u7D44\u7E54\u7D1A\u7684\u4E3B\u9AD4,\u5728\u4E3B\u6B0A (sovereign) \u524D\u7DB4\u4E0B\u9444\u9020\u898F\u5247 (\u4F8B\u5982 ATR-TW-2026-NNNNN)\u3002\u6388\u6B0A\u4F9D /charter \u00A75 \u7A0B\u5E8F\u6838\u767C;TSC \u6210\u7ACB\u5F8C\u7531\u5176\u6838\u767C,\u5728\u6B64\u4E4B\u524D\u7531\u4E3B\u7406\u4EBA (BDFL) \u66AB\u4EE3\u3002",
    "conformance.testsuite.h": "\u6E2C\u8A66\u5957\u4EF6 (Test Suite)",
    "conformance.testsuite.body":
      "L1 engine \u6E2C\u8A66\u5957\u4EF6\u7531\u4E3B repository \u4E2D spec/conformance/ \u4E0B\u7684 YAML fixture \u7D44\u6210\u3002\u6BCF\u500B fixture \u914D\u5C0D\u4E00\u689D\u898F\u5247\u8207\u5176\u5728\u56FA\u5B9A\u4E8B\u4EF6 (event) \u4E0A\u7684\u9810\u671F\u8A55\u4F30\u7D50\u679C\u2014\u2014\u5951\u7D04\u5BEB\u5728 fixture \u88E1,\u4E0D\u5BEB\u5728\u4EFB\u4F55\u55AE\u4E00\u5BE6\u4F5C\u88E1\u3002\u5BE6\u4F5C\u901A\u904E\u7684\u689D\u4EF6\u662F:\u6BCF\u500B fixture \u90FD\u5982\u5BA3\u544A\u822C\u8A55\u4F30\u3002\u5169\u500B\u90FD\u901A\u904E\u7684\u5F15\u64CE,\u5728\u6E2C\u8A66\u5957\u4EF6\u6DB5\u84CB\u7684\u6BCF\u4E00\u689D\u898F\u5247\u4E0A,\u7531\u69CB\u9020\u4FDD\u8B49\u5F7C\u6B64\u4E00\u81F4\u3002",
    "conformance.self.h": "\u81EA\u6211\u8A8D\u8B49 (Self-Certification)",
    "conformance.self.body":
      "\u5BE6\u4F5C\u8005\u5728\u672C\u5730\u57F7\u884C\u6E2C\u8A66\u5957\u4EF6,\u4E26\u5C0D ADOPTERS.md \u958B\u7ACB pull request \u52A0\u5165\u6574\u5408 metadata,\u5373\u53EF\u81EA\u6211\u8A8D\u8B49 (self-certify)\u3002\u7DAD\u8B77\u8005(TSC \u6210\u7ACB\u5F8C)\u53EF\u96A8\u6642\u5C0D\u4EFB\u4E00\u5DF2\u767C\u5E03\u7522\u7269\u91CD\u8DD1\u6E2C\u8A66\u5957\u4EF6\u4EE5\u9A57\u8B49\u81EA\u6211\u8A8D\u8B49\u3002",

    "errata.title": "\u52D8\u8AA4 (Errata)",
    "errata.subtitle":
      "ATR \u898F\u683C\u5DF2\u767C\u5E03\u7248\u672C\u4E2D\u767C\u73FE\u4E4B\u932F\u8AA4\u7684\u5E38\u8A2D\u7D00\u9304\u2014\u2014\u5C31\u50CF W3C \u8207 IETF \u898F\u683C\u90A3\u6A23\u516C\u958B\u4FDD\u7559\u52D8\u8AA4\u3002\u6BCF\u4E00\u500B\u5DF2\u767C\u5E03\u7248\u672C\u90FD\u662F\u6C38\u4E45\u7684;\u88E1\u9762\u7684\u932F\u8AA4\u5728\u9019\u88E1\u516C\u958B\u66F4\u6B63\u3001\u4E26\u6A19\u660E\u4F86\u6E90\u3002\u6BCF\u4E00\u7B46\u7D00\u9304\u6A19\u793A\u53D7\u5F71\u97FF\u7248\u672C\u3001\u932F\u8AA4\u6240\u5728\u4F4D\u7F6E\u3001\u66F4\u6B63\u6587\u5B57\u3001\u4EE5\u53CA\u66F4\u6B63\u767C\u5E03\u65E5\u671F\u3002",
    "errata.empty":
      "\u76EE\u524D Working Draft \u5C1A\u7121\u52D8\u8AA4\u7D00\u9304\u3002\u6C92\u6709\u7D00\u9304\u4E26\u975E\u5BA3\u7A31\u5B8C\u7F8E\u2014\u2014\u53EA\u662F\u5C1A\u672A\u6709\u4EFB\u4F55\u5DF2\u767C\u5E03\u7248\u672C\u7684\u932F\u8AA4\u7D93\u78BA\u8A8D\u3002\u82E5\u4F60\u767C\u73FE\u4E00\u500B,\u8ACB\u65BC repository \u958B issue;\u7D93\u78BA\u8A8D\u7684\u56DE\u5831\u6703\u88AB\u52A0\u9032\u9019\u88E1,\u800C\u975E\u975C\u9ED8\u4FEE\u88DC\u3002",
    "errata.col.version": "\u53D7\u5F71\u97FF\u7248\u672C",
    "errata.col.section": "\u7AE0\u7BC0",
    "errata.col.summary": "\u6458\u8981",
    "errata.col.date": "\u767C\u5E03\u65E5\u671F",

    "glossary.title": "\u8A5E\u5F59\u8868 (Glossary)",
    "glossary.subtitle":
      "\u898F\u683C\u4E2D\u95DC\u9375\u8853\u8A9E\u7684\u5B9A\u7FA9\u3002\u7576\u8853\u8A9E\u5728 spec \u4E2D\u7684\u7CBE\u78BA\u6280\u8853\u610F\u6DB5\u8207\u4E00\u822C\u7528\u6CD5\u4E0D\u540C\u6642,\u4EE5 spec \u4E2D\u7684\u6280\u8853\u610F\u6DB5\u70BA\u6E96\u3002",

    "charter.title": "\u5C08\u6848\u7AE0\u7A0B (Project Charter)",
    "charter.subtitle":
      "\u6A19\u6E96\u80FD\u5426\u6BD4\u555F\u52D5\u5B83\u7684\u4EBA\u6D3B\u5F97\u66F4\u4E45,\u53D6\u6C7A\u65BC\u5B83\u7684\u898F\u5247\u6709\u6C92\u6709\u88AB\u767D\u7D19\u9ED1\u5B57\u5BEB\u4E0B\u4F86\u3002\u672C\u7AE0\u7A0B\u8F09\u660E ATR \u662F\u4EC0\u9EBC\u3001\u4E0D\u662F\u4EC0\u9EBC\u3001\u6C7A\u7B56\u5982\u4F55\u505A\u6210\u3001\u4EE5\u53CA\u6280\u8853\u6307\u5C0E\u59D4\u54E1\u6703 (TSC) \u5982\u4F55\u5C31\u4EFB \u2014\u2014 \u9019\u4E9B\u627F\u8AFE\u7121\u8AD6\u7531\u8AB0\u7DAD\u8B77\u7686\u6210\u7ACB\u3002",
    "charter.mission.h": "\u4F7F\u547D",
    "charter.mission.body":
      "ATR \u70BA AI Agent \u5B89\u5168\u793E\u7FA4\u63D0\u4F9B\u4E00\u500B\u5171\u540C\u7684\u5075\u6E2C\u898F\u5247\u683C\u5F0F \u2500\u2500 \u8B93\u67D0\u500B\u7D44\u7E54\u7684\u9632\u79A6\u8005,\u80FD\u76F4\u63A5\u6CBF\u7528\u53E6\u4E00\u500B\u7D44\u7E54\u3001\u751A\u81F3\u53E6\u4E00\u500B\u570B\u5BB6\u7684\u9632\u79A6\u8005\u6240\u5BEB\u7684\u898F\u5247,\u800C\u4E0D\u5FC5\u6709\u4EBA\u91CD\u65B0\u767C\u660E\u898F\u5247\u683C\u5F0F\u3002\u5171\u540C\u683C\u5F0F\u662F\u57FA\u790E\u5EFA\u8A2D,\u4E0D\u662F\u7522\u54C1:\u5B83\u4E0D\u5C6C\u65BC\u4EFB\u4F55\u5EE0\u5546,\u53EA\u5C0D\u7DAD\u8B77\u5B83\u7684\u793E\u7FA4\u8CA0\u8CAC\u3002",
    "charter.scope.h": "\u7BC4\u570D (Scope)",
    "charter.scope.in":
      "\u7BC4\u570D\u5167:\u898F\u5247\u683C\u5F0F\u3001reference engine\u3001rule schema\u3001\u7B26\u898F\u7B49\u7D1A\u3001\u8DE8\u6846\u67B6\u5C0D\u61C9 (OWASP\u3001MITRE ATLAS\u3001NIST AI RMF\u3001SAFE-MCP)\u3002",
    "charter.scope.out":
      "\u7BC4\u570D\u5916:\u5EE0\u5546\u5C08\u5C6C\u5DE5\u5177\u3001\u5546\u696D\u6574\u5408\u3001runtime enforcement \u653F\u7B56\u3001\u4E8B\u4EF6\u56DE\u61C9\u5354\u8ABF\u3002\u9019\u4E9B\u662F\u4E0B\u6E38\u5BE6\u4F5C\u8005\u7684\u5DE5\u4F5C;\u6A19\u6E96\u523B\u610F\u4FDD\u6301\u72F9\u7A84,\u597D\u8B93\u4EFB\u4F55\u5BE6\u4F5C\u8005\u90FD\u80FD\u5728\u5176\u4E0A\u5EFA\u69CB,\u800C\u4E0D\u5FC5\u627F\u63A5\u5225\u4EBA\u7684\u7522\u54C1\u6C7A\u7B56\u3002",
    "charter.governance.h": "\u6CBB\u7406 (Governance)",
    "charter.governance.body":
      "ATR \u73FE\u7531\u55AE\u4E00\u9996\u5E2D\u7DAD\u8B77\u8005\u6CBB\u7406 (BDFL),\u6280\u8853\u6307\u5C0E\u59D4\u54E1\u6703 (TSC) \u6B63\u5728\u7C4C\u7D44\u4EE5\u627F\u63A5\u6B64\u89D2\u8272\u3002\u6B0A\u529B\u96C6\u4E2D\u65BC\u55AE\u4E00\u7DAD\u8B77\u8005\u662F\u904E\u6E21\u968E\u6BB5,\u4E0D\u662F\u8A2D\u8A08\u672C\u8EAB:\u904E\u6E21\u689D\u4EF6\u8207 TSC \u5C31\u4EFB\u7A0B\u5E8F\u4E8B\u5148\u5BEB\u5B9A\u65BC GOVERNANCE.md \u8207 docs/BDFL-charter.md \u2014\u2014 \u6B63\u662F\u70BA\u4E86\u8B93\u8D70\u5411\u5171\u4EAB\u6CBB\u7406\u4E00\u4E8B\u4F9D\u898F\u5247\u767C\u751F,\u800C\u975E\u5076\u7136\u767C\u751F\u3002",
    "charter.ip.h": "\u667A\u6167\u8CA1\u7522 (Intellectual Property)",
    "charter.ip.body":
      "ATR \u63A1 MIT License \u6C38\u4E45\u767C\u5E03,\u5DF2\u767C\u5E03\u7684\u6A19\u6E96\u6C92\u6709\u4EFB\u4F55\u91CD\u65B0\u6388\u6B0A\u7684\u8DEF\u5F91\u3002\u6240\u6709\u8CA2\u737B\u7686\u4EE5 MIT License \u63D0\u4EA4:\u7121 CLA \u9700\u7C3D\u7F72,\u4EA6\u7121\u6B0A\u5229\u9700\u8B93\u6E21\u3002\u4EFB\u4F55\u4EBA \u2014\u2014 \u5305\u542B\u5F7C\u6B64\u7AF6\u722D\u7684\u5EE0\u5546 \u2014\u2014 \u7686\u5F97\u63A1\u7528\u3001\u64F4\u5145\u6216 fork \u9019\u4E9B\u898F\u5247\u3002\u5F15\u7528 DOI \u70BA 10.5281/zenodo.19178002\u3002",

    "citations.title": "\u5F15\u7528 (Citation)",
    "citations.subtitle":
      "\u4E00\u500B\u6A19\u6E96\u6210\u70BA\u57FA\u790E\u5EFA\u8A2D\u7684\u90A3\u4E00\u5929,\u662F\u5225\u4EBA\u7684\u5DE5\u4F5C\u80FD\u6307\u5411\u5B83\u3001\u800C\u5B83\u4E0D\u518D\u79FB\u52D5\u7684\u90A3\u4E00\u5929\u3002ATR \u751F\u4F86\u5C31\u662F\u8981\u88AB\u5F15\u7528\u7684 \u2014\u2014 \u88AB\u4E00\u7BC7\u8AD6\u6587\u3001\u4E00\u7B46 CVE \u7D00\u9304\u3001\u4E00\u652F CI \u8173\u672C\u5F15\u7528 \u2014\u2014 \u9760\u7684\u662F\u767C\u5E03\u5F8C\u6C38\u4E0D\u6539\u52D5\u7684\u8B58\u5225\u78BC,\u4EE5\u53CA\u4E00\u500B\u6BD4\u4EFB\u4F55\u7DB2\u5740\u90FD\u9577\u58FD\u7684 DOI\u3002\u4E0B\u5217\u683C\u5F0F,\u5C31\u662F\u5F15\u7528\u5B83\u7684\u65B9\u5F0F\u3002",

    "mission.title": "\u4F7F\u547D",
    "mission.body":
      "\u9632\u79A6\u8005\u5728\u4E0D\u540C\u7D44\u7E54\u3001\u4E0D\u540C\u570B\u5BB6\u5DE5\u4F5C,\u9762\u5C0D\u540C\u4E00 AI Agent \u653B\u64CA\u9762\u3002ATR \u5B58\u5728\u7684\u7406\u7531,\u662F\u8B93\u5DE5\u4F5C\u80FD\u5F7C\u6B64\u7D44\u5408 \u2500\u2500 \u8B93\u53F0\u5317\u5BEB\u7684\u4E00\u689D\u898F\u5247\u80FD\u5075\u6E2C\u9996\u5148\u5728\u897F\u96C5\u5716\u88AB\u901A\u5831\u7684\u653B\u64CA,\u800C\u4E0D\u5FC5\u6709\u4EBA\u91CD\u65B0\u5BE6\u4F5C\u898F\u5247\u683C\u5F0F\u3002",
    "mission.tagline":
      "\u4E00\u500B\u958B\u653E\u683C\u5F0F\u3002\u4E00\u500B\u53EF\u540C\u5115\u5BE9\u67E5\u7684 schema\u3002\u4E00\u500B\u6B63\u5F0F\u7DB2\u5740 (canonical URL)\u3002",

    "vision.title": "\u9577\u671F\u9858\u666F",
    "vision.body":
      "AI Agent \u5B89\u5168\u4F5C\u70BA\u4E00\u500B\u5B78\u79D1,\u5176\u6210\u719F\u5EA6\u53D7\u5236\u65BC\u7F3A\u4E4F\u5171\u540C\u7684\u898F\u5247\u683C\u5F0F\u3002ATR \u63D0\u4F9B\u9019\u500B\u683C\u5F0F\u3002\u6211\u5011\u7684\u76EE\u6A19\u662F\u8B93 ATR \u5728 AI Agent runtime \u7684\u67B6\u69CB\u4F4D\u7F6E\u4E2D,\u4F54\u64DA Sigma \u5728 SIEM \u5075\u6E2C\u3001YARA \u5728\u60E1\u610F\u7A0B\u5F0F\u7C3D\u7AE0\u4E2D\u7684\u540C\u7B49\u4F4D\u7F6E \u2500\u2500 \u4E2D\u7ACB\u3001\u53EF\u540C\u5115\u5BE9\u67E5\u3001\u4EFB\u4F55\u55AE\u4F4D\u7686\u53EF\u81EA\u7531\u5BE6\u4F5C\u3001\u5EF6\u4F38\u6216\u5F15\u7528\u3002",
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
