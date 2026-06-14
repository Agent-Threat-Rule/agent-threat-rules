/* ATD enumeration — the technique catalog rendered on /atd and exported as
 * machine-readable JSON. Every CVE here was verified against nvd.nist.gov and
 * every MITRE ATLAS id against the authoritative mitre-atlas/atlas-data
 * dist/ATLAS.yaml (2026-06-14). Entries with no public CVE are marked
 * "research" (with a real advisory/paper) or "aspirational" (forward-looking,
 * no public instance yet) — never dressed up as a CVE. `atrRule` links the
 * live, gate-passing ATR detection rule where one exists.
 */
export type EvidenceKind = "cve" | "research" | "aspirational";
export type Severity = "critical" | "high" | "medium";

export interface ATDTechnique {
  id: string; // ATD-T####
  tactic: string; // ATD-TA#
  title: string;
  mechanism: string;
  severity: Severity;
  evidence: { kind: EvidenceKind; label: string; url?: string };
  asi: string[]; // OWASP Agentic Top 10 2026
  atlas: string[]; // MITRE ATLAS (verified; [] if none verifiable)
  cwe: string[];
  atrRule?: string; // live ATR rule id, if one ships
}

export const ATD_TACTICS: { id: string; name: string }[] = [
  { id: "ATD-TA1", name: "Protocol & Interconnect" },
  { id: "ATD-TA2", name: "Memory & Context Integrity" },
  { id: "ATD-TA3", name: "Goal, Planning & Reasoning" },
  { id: "ATD-TA4", name: "Identity, Authz & Delegation" },
  { id: "ATD-TA5", name: "Tool & Supply Chain" },
  { id: "ATD-TA6", name: "Execution & Autonomy" },
  { id: "ATD-TA7", name: "Multi-Agent Dynamics" },
  { id: "ATD-TA8", name: "Model-Intrinsic & Governance" },
  { id: "ATD-TA9", name: "Agentic Commerce (forward)" },
];

export const ATD_TECHNIQUES: ATDTechnique[] = [
  // ---- TA1 Protocol & Interconnect ----
  {
    id: "ATD-T0001",
    tactic: "ATD-TA1",
    title: "Shell metacharacter injection through MCP tool parameters",
    mechanism: "Unsanitized MCP tool input reaches execSync/exec, yielding RCE on the server host.",
    severity: "high",
    evidence: { kind: "cve", label: "CVE-2025-53355", url: "https://nvd.nist.gov/vuln/detail/CVE-2025-53355" },
    asi: ["ASI05", "ASI02"], atlas: ["AML.T0053"], cwe: ["CWE-77"],
    atrRule: "ATR-2026-01927",
  },
  {
    id: "ATD-T0002",
    tactic: "ATD-TA1",
    title: "curl-fallback command injection in an MCP server",
    mechanism: "A failed fetch falls back to exec'ing curl with an unsanitized URL, enabling RCE.",
    severity: "high",
    evidence: { kind: "cve", label: "CVE-2025-53967", url: "https://nvd.nist.gov/vuln/detail/CVE-2025-53967" },
    asi: ["ASI05", "ASI02"], atlas: ["AML.T0053"], cwe: ["CWE-420"],
    atrRule: "ATR-2026-01928",
  },
  {
    id: "ATD-T0003",
    tactic: "ATD-TA1",
    title: "Command injection in a scaffolded MCP stdio server",
    mechanism: "Generated server concatenates tool input into exec(), giving RCE to anything built from it.",
    severity: "critical",
    evidence: { kind: "cve", label: "CVE-2025-54994", url: "https://nvd.nist.gov/vuln/detail/CVE-2025-54994" },
    asi: ["ASI04", "ASI05"], atlas: ["AML.T0010.005"], cwe: ["CWE-78"],
    atrRule: "ATR-2026-00577",
  },
  {
    id: "ATD-T0004",
    tactic: "ATD-TA1",
    title: "Line-jumping — tool-description injection at listing time",
    mechanism: "Hidden instructions in a tool description enter the model context at tools/list, before any call.",
    severity: "high",
    evidence: { kind: "research", label: "Trail of Bits / Invariant Labs", url: "https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/" },
    asi: ["ASI04", "ASI01"], atlas: ["AML.T0110", "AML.T0104"], cwe: ["CWE-1427"],
    atrRule: "ATR-2026-00579",
  },
  {
    id: "ATD-T0005",
    tactic: "ATD-TA1",
    title: "Rug pull — silent mutation of an approved tool",
    mechanism: "A server approved once later changes a tool's definition with no integrity re-check.",
    severity: "high",
    evidence: { kind: "research", label: "Invariant Labs", url: "https://github.com/invariantlabs-ai/mcp-injection-experiments" },
    asi: ["ASI04"], atlas: ["AML.T0109", "AML.T0110"], cwe: ["CWE-494"],
    atrRule: "ATR-2026-00581",
  },
  {
    id: "ATD-T0006",
    tactic: "ATD-TA1",
    title: "Missing-auth MCP proxy command execution",
    mechanism: "No auth between client and MCP proxy lets any local/web-driven request spawn MCP processes.",
    severity: "critical",
    evidence: { kind: "cve", label: "CVE-2025-49596", url: "https://nvd.nist.gov/vuln/detail/CVE-2025-49596" },
    asi: ["ASI03", "ASI05"], atlas: [], cwe: ["CWE-306"],
  },
  {
    id: "ATD-T0007",
    tactic: "ATD-TA1",
    title: "RCE from a malicious upstream MCP server",
    mechanism: "A client is RCE'd via a crafted authorization_endpoint URL in an untrusted server's response.",
    severity: "critical",
    evidence: { kind: "cve", label: "CVE-2025-6514", url: "https://nvd.nist.gov/vuln/detail/CVE-2025-6514" },
    asi: ["ASI04", "ASI05"], atlas: ["AML.T0010.005"], cwe: ["CWE-78"],
  },
  {
    id: "ATD-T0008",
    tactic: "ATD-TA1",
    title: "DNS-rebinding to a localhost MCP server",
    mechanism: "A malicious page rebinds DNS to reach an unauthenticated localhost MCP server cross-origin.",
    severity: "high",
    evidence: { kind: "cve", label: "CVE-2025-66416", url: "https://nvd.nist.gov/vuln/detail/CVE-2025-66416" },
    asi: ["ASI07", "ASI03"], atlas: [], cwe: ["CWE-1188"],
  },
  {
    id: "ATD-T0009",
    tactic: "ATD-TA1",
    title: "Session ID / auth token placed in a URL query string",
    mechanism: "A credential in the query string leaks via server logs, proxies, CDNs, history, and Referer.",
    severity: "medium",
    evidence: { kind: "research", label: "Vulnerable MCP Project (Equixly)", url: "https://vulnerablemcp.info/" },
    asi: ["ASI03", "ASI07"], atlas: [], cwe: ["CWE-598"],
    atrRule: "ATR-2026-00580",
  },
  // ---- TA2 Memory & Context ----
  {
    id: "ATD-T0010",
    tactic: "ATD-TA2",
    title: "Serialized-object smuggling through an LLM response field",
    mechanism: "Injected output carries a serialization marker; deserialization rehydrates it as trusted and exfiltrates secrets.",
    severity: "critical",
    evidence: { kind: "cve", label: "CVE-2025-68664", url: "https://nvd.nist.gov/vuln/detail/CVE-2025-68664" },
    asi: ["ASI06", "ASI01"], atlas: ["AML.T0051.001"], cwe: ["CWE-502"],
  },
  {
    id: "ATD-T0011",
    tactic: "ATD-TA2",
    title: "Persistent memory / context-store poisoning",
    mechanism: "Attacker-controlled content is written into data the agent later reads back as trusted context.",
    severity: "high",
    evidence: { kind: "research", label: "MITRE ATLAS — Context Poisoning", url: "https://atlas.mitre.org/" },
    asi: ["ASI06"], atlas: ["AML.T0080"], cwe: ["CWE-349"],
  },
  // ---- TA3 Goal / Planning / Reasoning ----
  {
    id: "ATD-T0012",
    tactic: "ATD-TA3",
    title: "Indirect prompt injection via tool / API response",
    mechanism: "Malicious text in returned tool data overrides the agent's plan and redirects its actions.",
    severity: "high",
    evidence: { kind: "research", label: "InjecAgent, arXiv 2403.02691", url: "https://arxiv.org/abs/2403.02691" },
    asi: ["ASI01"], atlas: ["AML.T0051.001", "AML.T0099"], cwe: ["CWE-1427"],
    atrRule: "ATR-2026-00584",
  },
  {
    id: "ATD-T0013",
    tactic: "ATD-TA3",
    title: "System-prompt / guardrail extraction to plan evasion",
    mechanism: "Crafted queries coerce the agent to reveal its hidden system prompt, exposing control logic.",
    severity: "medium",
    evidence: { kind: "research", label: "MITRE ATLAS — Extract LLM System Prompt", url: "https://atlas.mitre.org/" },
    asi: ["ASI01", "ASI09"], atlas: ["AML.T0056"], cwe: ["CWE-200"],
  },
  // ---- TA4 Identity / Authz / Delegation ----
  {
    id: "ATD-T0014",
    tactic: "ATD-TA4",
    title: "Confused-deputy token passthrough in an MCP server",
    mechanism: "A server forwards a held token to a downstream API without audience validation, escalating privilege.",
    severity: "high",
    evidence: { kind: "research", label: "MCP Authorization spec (confused-deputy)", url: "https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization" },
    asi: ["ASI03"], atlas: [], cwe: ["CWE-441"],
  },
  // ---- TA5 Tool & Supply Chain ----
  {
    id: "ATD-T0015",
    tactic: "ATD-TA5",
    title: "Agent reads .env / secret files without consent",
    mechanism: "An agent tool reads credential files (.env, credentials, .npmrc) outside any user-approved scope.",
    severity: "high",
    evidence: { kind: "research", label: "ModelContextProtocol-Security advisory", url: "https://github.com/modelcontextprotocol-security/vulnerability-db" },
    asi: ["ASI02", "ASI06"], atlas: ["AML.T0053"], cwe: ["CWE-538"],
    atrRule: "ATR-2026-00583",
  },
  {
    id: "ATD-T0016",
    tactic: "ATD-TA5",
    title: "Hallucinated-dependency squatting (slopsquatting)",
    mechanism: "The model recommends a fabricated package name an attacker pre-registers, pulling code into the agent env.",
    severity: "medium",
    evidence: { kind: "research", label: "MITRE ATLAS — Publish Hallucinated Entities", url: "https://atlas.mitre.org/" },
    asi: ["ASI04", "ASI08"], atlas: ["AML.T0060", "AML.T0062"], cwe: ["CWE-1427"],
  },
  // ---- TA6 Execution & Autonomy ----
  {
    id: "ATD-T0017",
    tactic: "ATD-TA6",
    title: "Path-traversal blacklist bypass via non-canonical paths",
    mechanism: "Exact-string path checks are bypassed with ../, /./, redundant slashes to reach sensitive files.",
    severity: "medium",
    evidence: { kind: "cve", label: "CVE-2025-66689", url: "https://nvd.nist.gov/vuln/detail/CVE-2025-66689" },
    asi: ["ASI02", "ASI03"], atlas: ["AML.T0053"], cwe: ["CWE-22"],
    atrRule: "ATR-2026-00578",
  },
  {
    id: "ATD-T0018",
    tactic: "ATD-TA6",
    title: "MCP filesystem sandbox escape via symlink following",
    mechanism: "A symlink inside an allowed directory resolves to an out-of-scope path, granting system file access.",
    severity: "high",
    evidence: { kind: "cve", label: "CVE-2025-53109", url: "https://nvd.nist.gov/vuln/detail/CVE-2025-53109" },
    asi: ["ASI02", "ASI05"], atlas: ["AML.T0053"], cwe: ["CWE-59"],
  },
  {
    id: "ATD-T0019",
    tactic: "ATD-TA6",
    title: "Prompt-injection-to-RCE via an agent's file-write capability",
    mechanism: "Injected instructions drive the agent to write a startup/config file that yields persistent code execution.",
    severity: "critical",
    evidence: { kind: "research", label: "Pillar Security — Antigravity (no CVE assigned)", url: "https://www.pillar.security/blog/prompt-injection-leads-to-rce-and-sandbox-escape-in-antigravity" },
    asi: ["ASI05", "ASI01"], atlas: ["AML.T0053", "AML.T0051.001"], cwe: ["CWE-94"],
  },
  // ---- TA7 Multi-Agent Dynamics ----
  {
    id: "ATD-T0020",
    tactic: "ATD-TA7",
    title: "Agent Card poisoning to capture A2A task routing",
    mechanism: "A rogue A2A agent advertises an instruction-laden Agent Card so the orchestrator routes tasks to it.",
    severity: "high",
    evidence: { kind: "research", label: "Trustwave SpiderLabs — Agent-in-the-Middle", url: "https://www.levelblue.com/blogs/spiderlabs-blog/agent-in-the-middle-abusing-agent-cards-in-the-agent-2-agent-protocol-to-win-all-the-tasks" },
    asi: ["ASI07", "ASI10"], atlas: ["AML.T0051.001"], cwe: ["CWE-345"],
  },
  {
    id: "ATD-T0021",
    tactic: "ATD-TA7",
    title: "Cross-agent injection propagation (cascading compromise)",
    mechanism: "One compromised agent emits content that injects the next downstream agent, cascading through the swarm.",
    severity: "high",
    evidence: { kind: "research", label: "InjecAgent + multi-agent control-flow hijack", url: "https://arxiv.org/abs/2403.02691" },
    asi: ["ASI08", "ASI07", "ASI10"], atlas: ["AML.T0051.001", "AML.T0080"], cwe: ["CWE-1427"],
  },
  // ---- TA8 Model-Intrinsic & Governance ----
  {
    id: "ATD-T0022",
    tactic: "ATD-TA8",
    title: "Trace tampering / non-tamper-evident agent audit logs",
    mechanism: "An agent logs reasoning but not the actual tool call, or logs are mutable — defeating after-the-fact audit.",
    severity: "medium",
    evidence: { kind: "research", label: "EU AI Act Art.12 logging / observability gap", url: "https://artificialintelligenceact.eu/article/12/" },
    asi: ["ASI10"], atlas: [], cwe: ["CWE-778"],
  },
  // ---- TA9 Agentic Commerce (forward) ----
  {
    id: "ATD-T0023",
    tactic: "ATD-TA9",
    title: "Adversarial transaction steering of a purchasing agent",
    mechanism: "Injected content in a listing/page steers an autonomous-commerce agent to overpay or leak payment authority.",
    severity: "medium",
    evidence: { kind: "aspirational", label: "Forward-looking — no public instance yet", url: "https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol" },
    asi: ["ASI01", "ASI02", "ASI09"], atlas: [], cwe: ["CWE-1427"],
  },
  {
    id: "ATD-T0024",
    tactic: "ATD-TA9",
    title: "Payment-mandate forgery in an agent-to-agent handshake",
    mechanism: "A rogue agent spoofs delegated payment authority or mandate scope in an agentic-commerce exchange.",
    severity: "medium",
    evidence: { kind: "aspirational", label: "Forward-looking — protocols (AP2-class) emerging", url: "https://fidoalliance.org/fido-alliance-to-develop-standards-for-trusted-ai-agent-interactions/" },
    asi: ["ASI03", "ASI07"], atlas: [], cwe: ["CWE-345"],
  },

  // ---- TA2/TA8 addenda: 2026-06 research (verified arXiv) ----
  {
    id: "ATD-T0026",
    tactic: "ATD-TA2",
    title: "Sleeper (dormant) memory poisoning",
    mechanism: "Attacker-controlled external content is written into the agent's persistent memory and lies dormant across sessions, re-emerging in later conversations to steer actions — decoupling the injection event from the malicious effect in time. The deterministic detection chokepoint is the memory-write boundary.",
    severity: "high",
    evidence: { kind: "research", label: "Hidden in Memory: Sleeper Memory Poisoning in LLM Agents (arXiv 2605.15338)", url: "https://arxiv.org/abs/2605.15338" },
    asi: ["ASI06"], atlas: ["AML.T0080"], cwe: ["CWE-349"],
  },
  {
    id: "ATD-T0025",
    tactic: "ATD-TA8",
    title: "Acoustic prompt injection of a voice agent",
    mechanism: "An imperceptible adversarial audio perturbation mixed into normal speech drives a voice / audio-LLM agent to issue real tool calls, under audio-data-only access and with no textual user instruction. Text-layer rules cannot see it; detection is limited to the trace plane (a voice-initiated session producing high-risk tool calls with no corresponding textual instruction).",
    severity: "high",
    evidence: { kind: "research", label: "AudioHijack — imperceptible auditory prompt injection (arXiv 2604.14604, IEEE S&P 2026)", url: "https://arxiv.org/abs/2604.14604" },
    asi: ["ASI01"], atlas: [], cwe: ["CWE-1427"],
  },
  {
    "id": "ATD-T0027",
    "tactic": "ATD-TA3",
    "title": "Persona/roleplay jailbreak to override safety policy",
    "mechanism": "Attacker assigns the model an unrestricted alter-ego or fictional character (DAN, AIM, Developer Mode, dual-response split, grandma/historical/amoral persona, game-master) so it treats safety-violating output as in-character roleplay rather than its own refusal-bound behavior.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "NVIDIA garak dan/AutoDAN/TAP probes; in-the-wild jailbreak corpus; HackAPrompt persona templates"
    },
    "asi": [
      "ASI01"
    ],
    "atlas": [
      "AML.T0054",
      "AML.T0051.000"
    ],
    "cwe": [
      "CWE-1427"
    ],
    "atrRule": "ATR-2026-00457"
  },
  {
    "id": "ATD-T0028",
    "tactic": "ATD-TA3",
    "title": "Direct instruction override and goal hijacking",
    "mechanism": "Untrusted input issues imperative directives (ignore/forget previous instructions, redefine the system prompt, force verbatim payload output) or pivots the objective via false premise / goal drift, displacing the agent's assigned goal and constraints without persona framing.",
    "severity": "critical",
    "evidence": {
      "kind": "research",
      "label": "PromptInject (Perez & Ribeiro 2022); HackAPrompt 'I have been PWNED'; CVE-2024-5184 EmailGPT"
    },
    "asi": [
      "ASI01"
    ],
    "atlas": [
      "AML.T0051",
      "AML.T0051.000"
    ],
    "cwe": [
      "CWE-1427"
    ],
    "atrRule": "ATR-2026-00004"
  },
  {
    "id": "ATD-T0029",
    "tactic": "ATD-TA3",
    "title": "Encoding/cipher obfuscation to smuggle harmful instructions past plaintext filters",
    "mechanism": "Harmful instructions are wrapped in a reversible visible encoding (Base16/32/64/85, hex, Morse, NATO, leetspeak, Braille, Ecoji, Base2048, ROT/cipher, homoglyph) and the model is asked to decode-then-execute, exploiting that plaintext-trained safety classifiers do not generalize to the encoded form.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "garak encoding probe family; Wei et al. arXiv:2307.02483; DRA disguise-reconstruction"
    },
    "asi": [
      "ASI01"
    ],
    "atlas": [
      "AML.T0054",
      "AML.T0051",
      "AML.T0068"
    ],
    "cwe": [
      "CWE-1427"
    ],
    "atrRule": "ATR-2026-00256"
  },
  {
    "id": "ATD-T0030",
    "tactic": "ATD-TA3",
    "title": "Invisible Unicode steganographic smuggling of agent instructions",
    "mechanism": "Instructions are hidden in imperceptible Unicode that renders blank to humans but tokenizes for the model: zero-width chars, BiDi RLO/LRO overrides, Unicode Tag-block (U+E0000-E007F), variation-selector ASCII smuggling, breaking keyword matching and human audit while preserving model comprehension.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "garak badchars (arXiv:2106.09898); Trojan Source BiDi class; Goodside ASCII-smuggling via Unicode tags"
    },
    "asi": [
      "ASI01"
    ],
    "atlas": [
      "AML.T0051"
    ],
    "cwe": [
      "CWE-1427"
    ],
    "atrRule": "ATR-2026-00276"
  },
  {
    "id": "ATD-T0031",
    "tactic": "ATD-TA3",
    "title": "Hypothetical/fictional/tense reframing to bypass refusal",
    "mechanism": "The harmful request is wrapped in a distancing frame — fictional/story/academic context, past/future tense rewrite, hypothetical-response or function-masking continuation — so the model answers the harmful core believing it is producing fiction or historical analysis.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "garak phrasing probe; Andriushchenko & Flammarion arXiv:2407.11969 (past-tense)"
    },
    "asi": [
      "ASI01"
    ],
    "atlas": [
      "AML.T0054"
    ],
    "cwe": [
      "CWE-1427"
    ],
    "atrRule": "ATR-2026-00409"
  },
  {
    "id": "ATD-T0032",
    "tactic": "ATD-TA3",
    "title": "Coercive output-format and conditional-unlock pressure",
    "mechanism": "The prompt applies threats, ultimatums, or fabricated conditional-unlock rules to force the model into an attacker-specified output mode or override its formatting/refusal policy.",
    "severity": "medium",
    "evidence": {
      "kind": "research",
      "label": "garak goodside.ThreatenJSON (Goodside 2023)"
    },
    "asi": [
      "ASI01"
    ],
    "atlas": [
      "AML.T0051",
      "AML.T0054"
    ],
    "cwe": [],
    "atrRule": "ATR-2026-00287"
  },
  {
    "id": "ATD-T0033",
    "tactic": "ATD-TA3",
    "title": "Casual-authority impersonation for scope escalation and output redirect",
    "mechanism": "Conversational, informal authority claims (\"the orchestrator wants...\", \"the boss said skip...\") assert delegated permission to widen the agent's scope, disable safety filters, or redirect output to an attacker endpoint, evading explicit-injection detection.",
    "severity": "critical",
    "evidence": {
      "kind": "research",
      "label": "crystallized from 62 adversarial casual-authority-redirect samples (0% prior detection)"
    },
    "asi": [
      "ASI01",
      "ASI10"
    ],
    "atlas": [
      "AML.T0051"
    ],
    "cwe": [],
    "atrRule": "ATR-2026-00132"
  },
  {
    "id": "ATD-T0034",
    "tactic": "ATD-TA3",
    "title": "Foot-in-the-door gradual compliance escalation",
    "mechanism": "The attacker establishes compliance with a benign request, then incrementally escalates toward harmful instructions while citing the agent's prior compliance as justification.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "garak continuation probe + Cialdini foot-in-the-door literature"
    },
    "asi": [
      "ASI01"
    ],
    "atlas": [
      "AML.T0051"
    ],
    "cwe": [],
    "atrRule": "ATR-2026-00269"
  },
  {
    "id": "ATD-T0035",
    "tactic": "ATD-TA8",
    "title": "Token-level adversarial suffix and special-token boundary injection",
    "mechanism": "Model-intrinsic exploitation: gradient-optimized suffixes (GCG bracket/word-salad) or model-specific control tokens (<|endoftext|>, ChatML <|im_start|>system, glitch tokens) are appended to shift output toward compliance or reset safety context with no semantic framing.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "Zou et al. GCG arXiv:2307.15043; garak gcg/suffix; SolidGoldMagikarp glitch tokens"
    },
    "asi": [
      "ASI01"
    ],
    "atlas": [
      "AML.T0054",
      "AML.T0051"
    ],
    "cwe": [
      "CWE-1427"
    ],
    "atrRule": "ATR-2026-00267"
  },
  {
    "id": "ATD-T0036",
    "tactic": "ATD-TA8",
    "title": "Output-boundary bypass to elicit harmful or prohibited content",
    "mechanism": "An attacker shapes the request — completion-baiting, structured harm solicitation, or vulnerable-population framing — so the model emits content it would refuse if asked directly.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "garak continuation/lmrc/donotanswer; HarmBench arXiv:2402.04249"
    },
    "asi": [
      "ASI01"
    ],
    "atlas": [
      "AML.T0054",
      "AML.T0057"
    ],
    "cwe": [
      "CWE-1427"
    ],
    "atrRule": "ATR-2026-00279"
  },
  {
    "id": "ATD-T0037",
    "tactic": "ATD-TA8",
    "title": "Coercing the model to generate weaponized or scanner-evading output",
    "mechanism": "The model is directed to produce operational malicious artifacts (malware code, sub-functions) or known-bad test signatures (EICAR/GTUBE) that probe whether the output pipeline has any AV/scanning layer.",
    "severity": "critical",
    "evidence": {
      "kind": "research",
      "label": "garak malwaregen + av_spam_scanning (EICAR/GTUBE)"
    },
    "asi": [
      "ASI01",
      "ASI08"
    ],
    "atlas": [
      "AML.T0053"
    ],
    "cwe": [],
    "atrRule": "ATR-2026-00413"
  },
  {
    "id": "ATD-T0038",
    "tactic": "ATD-TA8",
    "title": "Model IP and training-data extraction via systematic inference probing",
    "mechanism": "An attacker issues bulk or divergent-repetition queries against the inference API to recover memorized training data or distill the model's behavior into a functional clone.",
    "severity": "medium",
    "evidence": {
      "kind": "research",
      "label": "ATLAS AML.CS0056 distillation; promptfoo divergent-repetition; Carlini et al. extraction"
    },
    "asi": [
      "ASI01"
    ],
    "atlas": [
      "AML.T0040",
      "AML.T0024"
    ],
    "cwe": [
      "CWE-200"
    ],
    "atrRule": "ATR-2026-00502"
  },
  {
    "id": "ATD-T0039",
    "tactic": "ATD-TA6",
    "title": "Human-in-the-loop trust and approval-fatigue exploitation",
    "mechanism": "Agent output is weaponized against the supervising human via fabricated confidence, suppressed uncertainty, manufactured urgency, or risky actions batched among benign ones to fatigue and bypass human approval gates.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "OWASP ASI09 Human-Agent Trust Exploitation"
    },
    "asi": [
      "ASI09"
    ],
    "atlas": [],
    "cwe": [],
    "atrRule": "ATR-2026-00077"
  },
  {
    "id": "ATD-T0040",
    "tactic": "ATD-TA6",
    "title": "Agent rationalizes bypassing a required human-approval or safety gate",
    "mechanism": "The agent skips a mandated approval/safety control — invoking a destructive tool with no preceding human-approval span, or self-justifying a direct path ('to be more efficient') — collapsing the human-in-the-loop checkpoint.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "trace-method require-primitive (destructive call lacking approval span)"
    },
    "asi": [
      "ASI04",
      "ASI05"
    ],
    "atlas": [
      "AML.T0053"
    ],
    "cwe": [
      "CWE-862",
      "CWE-841"
    ],
    "atrRule": "ATR-2026-00549"
  },
  {
    "id": "ATD-T0041",
    "tactic": "ATD-TA6",
    "title": "Agent code-execution sandbox escape achieves host RCE or boot-time persistence",
    "mechanism": "An agent's code-interpreter or VM sandbox is broken out of — via arbitrary file write to a startup path, eval/dynamic-import primitives, or a boundary flaw — yielding host code execution that can persist across restarts.",
    "severity": "critical",
    "evidence": {
      "kind": "cve",
      "label": "CVE-2026-27597 (Enclave VM escape CVSS 10.0); CVE-2026-25592 (Semantic Kernel file-write persistence); CVE-2026-2275 (CrewAI CodeInterpreter)"
    },
    "asi": [
      "ASI05",
      "ASI06"
    ],
    "atlas": [
      "AML.T0050"
    ],
    "cwe": [
      "CWE-94",
      "CWE-693"
    ],
    "atrRule": "ATR-2026-00436"
  },
  {
    "id": "ATD-T0042",
    "tactic": "ATD-TA6",
    "title": "Consequential autonomous action without human-in-the-loop confirmation",
    "mechanism": "An agent executes a high-risk, often irreversible operation — payment/transfer, shell command, destructive call, internal-network fetch — without an explicit per-turn human approval gate.",
    "severity": "critical",
    "evidence": {
      "kind": "research",
      "label": "OWASP ASI Excessive Autonomy / Insufficient Human Oversight"
    },
    "asi": [
      "ASI07",
      "ASI06"
    ],
    "atlas": [
      "AML.T0053",
      "AML.T0101"
    ],
    "cwe": [
      "CWE-862"
    ],
    "atrRule": "ATR-2026-00098"
  },
  {
    "id": "ATD-T0043",
    "tactic": "ATD-TA6",
    "title": "Runaway self-perpetuating execution loop (denial-of-wallet)",
    "mechanism": "An agent enters an unbounded retry, recursive self-invocation, or tight tool-call loop with no termination condition, exhausting compute, budget, or downstream services.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "ATLAS AML.T0034 Cost Harvesting; OWASP LLM10 Unbounded Consumption"
    },
    "asi": [
      "ASI07"
    ],
    "atlas": [
      "AML.T0034",
      "AML.T0046"
    ],
    "cwe": [
      "CWE-835"
    ],
    "atrRule": "ATR-2026-00050"
  },
  {
    "id": "ATD-T0044",
    "tactic": "ATD-TA7",
    "title": "Inter-agent identity spoofing and forged-message injection",
    "mechanism": "A compromised or peer agent spoofs another agent's identity, forges system-level message tags, or injects unauthenticated A2A messages to exploit inter-agent trust for privilege escalation or orchestrator bypass.",
    "severity": "critical",
    "evidence": {
      "kind": "research",
      "label": "A2A trust-boundary abuse; Trustwave Agent-in-the-Middle class"
    },
    "asi": [
      "ASI07",
      "ASI10"
    ],
    "atlas": [
      "AML.T0051.001",
      "AML.T0051"
    ],
    "cwe": [],
    "atrRule": "ATR-2026-00030"
  },
  {
    "id": "ATD-T0045",
    "tactic": "ATD-TA7",
    "title": "Multi-agent consensus and Sybil manipulation",
    "mechanism": "Instructions spin up multiple fake agent identities to coordinate votes, flood false proposals, or overwhelm a multi-agent consensus or voting mechanism toward an attacker-chosen outcome.",
    "severity": "critical",
    "evidence": {
      "kind": "research",
      "label": "Sybil-attack literature applied to agent consensus"
    },
    "asi": [
      "ASI10",
      "ASI07"
    ],
    "atlas": [
      "AML.T0043"
    ],
    "cwe": [],
    "atrRule": "ATR-2026-00108"
  },
  {
    "id": "ATD-T0046",
    "tactic": "ATD-TA5",
    "title": "Hidden directive embedded in MCP tool description subverts consent or safety gating",
    "mechanism": "A tool's natural-language description or docstring carries imperative instructions (auto-forward results, skip user confirmation, ignore safety policy) that the model obeys at invocation time.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "Invariant Labs tool-poisoning PoC; Repello AI tool-description directive class"
    },
    "asi": [
      "ASI04",
      "ASI02"
    ],
    "atlas": [
      "AML.T0053"
    ],
    "cwe": [
      "CWE-94",
      "CWE-1427"
    ],
    "atrRule": "ATR-2026-00100"
  },
  {
    "id": "ATD-T0047",
    "tactic": "ATD-TA5",
    "title": "Tool schema-description divergence hides write or admin capability behind a read-only claim",
    "mechanism": "A tool advertises safe/read-only behavior in its description while its JSON schema or runtime accepts undeclared write-capable, admin, or debug parameters that exceed the stated function.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "schema-vs-description contradiction class; over-permissioned/hidden-capability skills"
    },
    "asi": [
      "ASI02",
      "ASI05"
    ],
    "atlas": [
      "AML.T0010",
      "AML.T0056"
    ],
    "cwe": [
      "CWE-1427",
      "CWE-440"
    ],
    "atrRule": "ATR-2026-00106"
  },
  {
    "id": "ATD-T0048",
    "tactic": "ATD-TA5",
    "title": "Unauthenticated MCP server or agent API exposes privileged operations",
    "mechanism": "An MCP server, agent control API, or admin endpoint ships with authentication disabled or missing on critical functions, letting an unauthenticated caller invoke tools, exfiltrate data, or take over the cluster.",
    "severity": "critical",
    "evidence": {
      "kind": "cve",
      "label": "CVE-2026-32211 (Azure MCP missing-auth); CVE-2026-44338 (PraisonAI unauth agent API)"
    },
    "asi": [
      "ASI05",
      "ASI03"
    ],
    "atlas": [
      "AML.T0049",
      "AML.T0040"
    ],
    "cwe": [
      "CWE-306"
    ],
    "atrRule": "ATR-2026-00435"
  },
  {
    "id": "ATD-T0049",
    "tactic": "ATD-TA5",
    "title": "Untrusted tool output rendered without sanitization triggers terminal or browser code execution",
    "mechanism": "Tool/skill output containing ANSI/OSC escape sequences or XSS payloads is passed unsanitized into a CLI terminal or web agent UI, hijacking the display, forging prompts, or executing script in the operator's session.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "ANSI/OSC terminal-injection class + XSS-in-agent-UI"
    },
    "asi": [
      "ASI08",
      "ASI02"
    ],
    "atlas": [
      "AML.T0057",
      "AML.T0077"
    ],
    "cwe": [
      "CWE-150",
      "CWE-79"
    ],
    "atrRule": "ATR-2026-00259"
  },
  {
    "id": "ATD-T0050",
    "tactic": "ATD-TA5",
    "title": "Agent SSRF via unvalidated fetch URL reaches cloud metadata or internal services",
    "mechanism": "An agent fetch/RAG/retrieval tool accepts an attacker-influenced URL whose validator can be bypassed (encoding, decimal/hex IP, IPv6 loopback, DNS rebinding) to reach link-local cloud-metadata endpoints or internal hosts.",
    "severity": "high",
    "evidence": {
      "kind": "cve",
      "label": "CVE-2026-2286 (CrewAI RAG URL-validation bypass); ATR-2026-00547 is filed under privilege-escalation, same SSRF class (cross-category)"
    },
    "asi": [
      "ASI02",
      "ASI05"
    ],
    "atlas": [
      "AML.T0049"
    ],
    "cwe": [
      "CWE-918",
      "CWE-552"
    ],
    "atrRule": "ATR-2026-00013"
  },
  {
    "id": "ATD-T0051",
    "tactic": "ATD-TA5",
    "title": "Malicious code execution staged inside an installed skill package",
    "mechanism": "A SKILL.md or bundled script carries executable attack payloads — base64/raw-IP droppers, reverse shells, fake-backup credential stealers, or C2 callbacks — that run when the skill is installed or invoked.",
    "severity": "critical",
    "evidence": {
      "kind": "research",
      "label": "Snyk ToxicSkills (Feb 2026); ClawHavoc AMOS infostealer; Cato MedusaLocker-via-skill"
    },
    "asi": [
      "ASI04"
    ],
    "atlas": [
      "AML.T0010"
    ],
    "cwe": [
      "CWE-506"
    ],
    "atrRule": "ATR-2026-00121"
  },
  {
    "id": "ATD-T0052",
    "tactic": "ATD-TA5",
    "title": "Skill instruction smuggling via hidden/invisible payload channels",
    "mechanism": "Attack instructions are concealed in a skill's text where a human reviewer cannot see them — HTML comments, Unicode Tag characters (U+E0000 range), or other invisible glyphs — but the agent still parses and obeys them.",
    "severity": "critical",
    "evidence": {
      "kind": "research",
      "label": "Snyk ToxicSkills Unicode-tag smuggling; ClawHavoc HTML-comment variants"
    },
    "asi": [
      "ASI04"
    ],
    "atlas": [
      "AML.T0010"
    ],
    "cwe": [
      "CWE-506"
    ],
    "atrRule": "ATR-2026-00128"
  },
  {
    "id": "ATD-T0053",
    "tactic": "ATD-TA5",
    "title": "Skill supply-chain tampering: rug-pull, time-bomb, and self-modifying persistence",
    "mechanism": "A skill is architected to mutate after trust is granted — remote dynamic-code loading, time-gated exfiltration triggers, post-install hooks, self-rewriting SKILL.md, or worm-style propagation — so benign-at-review content turns malicious at runtime.",
    "severity": "critical",
    "evidence": {
      "kind": "cve",
      "label": "CVE-2025-59536 (Claude Code SessionStart pre-trust RCE); Mini Shai-Hulud npm worm (2026-05-11)"
    },
    "asi": [
      "ASI04"
    ],
    "atlas": [
      "AML.T0010"
    ],
    "cwe": [
      "CWE-494"
    ],
    "atrRule": "ATR-2026-00126"
  },
  {
    "id": "ATD-T0054",
    "tactic": "ATD-TA5",
    "title": "Upstream-skill impersonation: typosquat, fork-claim, and slopsquat baiting",
    "mechanism": "A malicious package masquerades as a trusted tool via misspelled/namespace-colliding names, false 'community fork / enhanced version' install instructions, or hallucinated-dependency baiting, hijacking the trust of the legitimate upstream.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "VirusTotal hightower6eu 314-skill AMOS campaign; OWASP AST04 metadata impersonation"
    },
    "asi": [
      "ASI04"
    ],
    "atlas": [
      "AML.T0010"
    ],
    "cwe": [
      "CWE-829"
    ],
    "atrRule": "ATR-2026-00151"
  },
  {
    "id": "ATD-T0055",
    "tactic": "ATD-TA5",
    "title": "Weaponized skill turning the agent into an offensive/over-privileged actor",
    "mechanism": "An approved skill exploits the post-consent gap to direct the agent itself into offensive operations or excessive scope — running attacker tooling, installing unauthorized background tasks, or loading unsafe model artifacts — beyond what the user sanctioned.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "Cato Networks MedusaLocker-via-skill (Dec 2025); garak fileformats.HF_Files"
    },
    "asi": [
      "ASI04"
    ],
    "atlas": [],
    "cwe": [
      "CWE-269"
    ],
    "atrRule": "ATR-2026-00122"
  },
  {
    "id": "ATD-T0056",
    "tactic": "ATD-TA4",
    "title": "Agent tool exceeds delegated permission scope to reach admin or out-of-bounds functions",
    "mechanism": "An agent invokes tools or administrative functions beyond its granted authority — abruptly or via incremental scope creep — accessing user-management, system-settings, or admin panels it was never delegated.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "authorization-boundary violation (abrupt + gradual scope creep)"
    },
    "asi": [
      "ASI03"
    ],
    "atlas": [
      "AML.T0040",
      "AML.T0047"
    ],
    "cwe": [
      "CWE-269",
      "CWE-862"
    ],
    "atrRule": "ATR-2026-00040"
  },
  {
    "id": "ATD-T0057",
    "tactic": "ATD-TA4",
    "title": "Credential/secret file harvest combined with network exfiltration",
    "mechanism": "Agent or MCP-tool instructions read well-known credential stores (.env, ~/.aws/credentials, SSH keys, .npmrc, browser cookie DBs) and pipe or POST them to an external endpoint in the same context, producing host credential theft with lateral-movement reach.",
    "severity": "critical",
    "evidence": {
      "kind": "research",
      "label": "MITRE ATT&CK T1552.001 Credentials In Files"
    },
    "asi": [
      "ASI02",
      "ASI06"
    ],
    "atlas": [
      "AML.T0055",
      "AML.T0083",
      "AML.T0090",
      "AML.T0098"
    ],
    "cwe": [
      "CWE-522"
    ],
    "atrRule": "ATR-2026-00113"
  },
  {
    "id": "ATD-T0058",
    "tactic": "ATD-TA4",
    "title": "Agent memory or context store written across a conversation or tenant boundary",
    "mechanism": "An agent writes into a memory/vector store scoped to a different conversation or tenant than the active trace, escaping its data boundary to plant content that later sessions will read.",
    "severity": "critical",
    "evidence": {
      "kind": "research",
      "label": "trace-method forbid-primitive (write target conversation.id != active trace)"
    },
    "asi": [
      "ASI04",
      "ASI06"
    ],
    "atlas": [
      "AML.T0080"
    ],
    "cwe": [
      "CWE-668",
      "CWE-349"
    ],
    "atrRule": "ATR-2026-00551"
  },
  {
    "id": "ATD-T0059",
    "tactic": "ATD-TA2",
    "title": "Sensitive data exfiltration via agent-rendered markdown image/link URL",
    "mechanism": "The agent is coerced into emitting markdown image or link syntax whose attacker-controlled URL encodes conversation, secret, or context data, so the rendering client auto-fetches it and leaks the data out-of-band.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "embracethered.com markdown-image-exfiltration; garak web_injection probe"
    },
    "asi": [
      "ASI06",
      "ASI08"
    ],
    "atlas": [
      "AML.T0024",
      "AML.T0057"
    ],
    "cwe": [
      "CWE-200"
    ],
    "atrRule": "ATR-2026-00261"
  },
  {
    "id": "ATD-T0060",
    "tactic": "ATD-TA2",
    "title": "Tool-response-embedded exfiltration channel",
    "mechanism": "A tool or MCP response embeds a secret-harvesting instruction or sensitive-data addendum inside otherwise legitimate-looking output, exploiting the agent's trust in tool results to smuggle credentials or context into the next turn.",
    "severity": "critical",
    "evidence": {
      "kind": "research",
      "label": "ATR adversarial corpus; SAFE-MCP SMCP-T012"
    },
    "asi": [
      "ASI06",
      "ASI08"
    ],
    "atlas": [
      "AML.T0054"
    ],
    "cwe": [
      "CWE-200"
    ],
    "atrRule": "ATR-2026-00136"
  },
  {
    "id": "ATD-T0061",
    "tactic": "ATD-TA2",
    "title": "Credential elicitation in model output (secret completion / verbatim disclosure)",
    "mechanism": "A prompt coaxes the model to generate, complete, partially reveal, or echo back live API keys, tokens, or secrets present in context (including obfuscated/encoded forms) so the secret materializes directly in the response.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "ATR red-team corpus; garak leakreplay/encoding probes"
    },
    "asi": [
      "ASI06"
    ],
    "atlas": [
      "AML.T0057"
    ],
    "cwe": [
      "CWE-200"
    ],
    "atrRule": "ATR-2026-00021"
  },
  {
    "id": "ATD-T0062",
    "tactic": "ATD-TA2",
    "title": "Cross-context / cross-user memory leakage in multi-agent delegation",
    "mechanism": "A privileged context attribute (session, user, or conversation id) fails to stay constant across an agent delegation chain or shared memory store, letting one user's or agent's context surface to another party.",
    "severity": "high",
    "evidence": {
      "kind": "cve",
      "label": "CVE-2026-41712 (Spring AI ChatMemory cross-user leak)"
    },
    "asi": [
      "ASI06"
    ],
    "atlas": [],
    "cwe": [
      "CWE-668"
    ],
    "atrRule": "ATR-2026-00548"
  },
  {
    "id": "ATD-T0063",
    "tactic": "ATD-TA2",
    "title": "Offline training / fine-tuning corpus contamination",
    "mechanism": "An attacker plants malicious or label-flipped samples into a model's training or fine-tuning dataset so the deployed model carries an attacker-chosen behavior or backdoor.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "MITRE ATLAS AML.T0020 Poison Training Data + AML.T0018"
    },
    "asi": [
      "ASI06"
    ],
    "atlas": [
      "AML.T0020",
      "AML.T0018"
    ],
    "cwe": [
      "CWE-349"
    ],
    "atrRule": "ATR-2026-00073"
  },
  {
    "id": "ATD-T0064",
    "tactic": "ATD-TA3",
    "title": "Forged trusted-output-component manipulation",
    "mechanism": "The agent emits output whose citations, source attributions, or structured 'verified' fields are attacker-forged, so a downstream consumer trusts fabricated components as authoritative.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "MITRE ATLAS AML.T0067 LLM Trusted Output Components Manipulation"
    },
    "asi": [
      "ASI01",
      "ASI08"
    ],
    "atlas": [
      "AML.T0067"
    ],
    "cwe": [
      "CWE-345"
    ]
  },
  {
    "id": "ATD-T0065",
    "tactic": "ATD-TA5",
    "title": "Sensitive-data exfiltration via legitimate agent tool invocation",
    "mechanism": "The agent invokes an otherwise-sanctioned tool (send, post, upload, write, fetch) to ship sensitive context or data to an attacker-controlled destination.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "MITRE ATLAS AML.T0086 Exfiltration via AI Agent Tool Invocation"
    },
    "asi": [
      "ASI06",
      "ASI02"
    ],
    "atlas": [
      "AML.T0086"
    ],
    "cwe": [
      "CWE-200"
    ]
  },
  {
    "id": "ATD-T0066",
    "tactic": "ATD-TA6",
    "title": "Delayed or conditional execution of injected instructions",
    "mechanism": "An injected instruction defers its own effect to a later turn or a trigger condition so the malicious action fires after review rather than at ingestion time.",
    "severity": "medium",
    "evidence": {
      "kind": "research",
      "label": "MITRE ATLAS AML.T0094 Delay Execution of LLM Instructions"
    },
    "asi": [
      "ASI01",
      "ASI07"
    ],
    "atlas": [
      "AML.T0094"
    ],
    "cwe": [
      "CWE-506"
    ]
  },
  {
    "id": "ATD-T0067",
    "tactic": "ATD-TA1",
    "title": "Unauthenticated MCP transport endpoint exposed to network reach",
    "mechanism": "An MCP server's SSE/HTTP transport port is bound to a routable interface with no auth, so a remote or cross-origin caller can open a session and invoke tools.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "SAFE-MCP SAFE-T1005 Exposed Endpoint Exploit"
    },
    "asi": [
      "ASI03",
      "ASI05"
    ],
    "atlas": [],
    "cwe": [
      "CWE-668"
    ]
  },
  {
    "id": "ATD-T0068",
    "tactic": "ATD-TA4",
    "title": "OAuth consent phishing to bind an attacker-controlled MCP authorization grant",
    "mechanism": "A user is steered through a real OAuth consent screen for an attacker's client/redirect so the agent ends up holding a token scoped to the attacker.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "SAFE-MCP SAFE-T1007 OAuth Authorization Phishing"
    },
    "asi": [
      "ASI03"
    ],
    "atlas": [],
    "cwe": [
      "CWE-1021"
    ]
  },
  {
    "id": "ATD-T0069",
    "tactic": "ATD-TA4",
    "title": "OAuth protocol downgrade to defeat PKCE or strip token binding",
    "mechanism": "The MCP authorization handshake is forced onto a weaker flow (implicit grant, dropped PKCE/state) so an intercepted code or token can be replayed.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "SAFE-MCP SAFE-T1408 OAuth Protocol Downgrade"
    },
    "asi": [
      "ASI03"
    ],
    "atlas": [],
    "cwe": [
      "CWE-757"
    ]
  },
  {
    "id": "ATD-T0070",
    "tactic": "ATD-TA4",
    "title": "Agent reads process environment variables to harvest injected secrets",
    "mechanism": "An agent or MCP tool enumerates process env vars (printenv, process.env, os.environ) to lift API keys and tokens injected at server startup.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "SAFE-MCP SAFE-T1503 Env-Var Scraping"
    },
    "asi": [
      "ASI06"
    ],
    "atlas": [
      "AML.T0055"
    ],
    "cwe": [
      "CWE-526"
    ]
  },
  {
    "id": "ATD-T0071",
    "tactic": "ATD-TA5",
    "title": "Cross-server tool-chaining pivot reaches an unrelated tool's resources",
    "mechanism": "The agent is steered to pass one tool's output as another connected tool's input so a low-trust tool drives a high-privilege tool's action across server boundaries.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "SAFE-MCP SAFE-T1703 Tool-Chaining Pivot"
    },
    "asi": [
      "ASI05",
      "ASI03"
    ],
    "atlas": [
      "AML.T0047"
    ],
    "cwe": [
      "CWE-441"
    ]
  },
  {
    "id": "ATD-T0072",
    "tactic": "ATD-TA5",
    "title": "Outbound webhook used as covert command-and-control channel",
    "mechanism": "An agent tool registers or polls an attacker-controlled webhook/URL, turning routine outbound HTTP into a tasking and data-return channel.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "SAFE-MCP SAFE-T1901 Outbound Webhook C2"
    },
    "asi": [
      "ASI08",
      "ASI06"
    ],
    "atlas": [
      "AML.T0072"
    ],
    "cwe": [
      "CWE-918"
    ]
  },
  {
    "id": "ATD-T0073",
    "tactic": "ATD-TA8",
    "title": "Agent model-output reconnaissance and guardrail fingerprinting",
    "mechanism": "An attacker systematically probes an agent's responses to fingerprint the underlying model, its guardrails, or its output format in order to tailor a follow-on attack.",
    "severity": "medium",
    "evidence": {
      "kind": "research",
      "label": "MITRE ATLAS AML.T0063 Discover AI Model Outputs"
    },
    "asi": [
      "ASI01"
    ],
    "atlas": [
      "AML.T0063"
    ],
    "cwe": [
      "CWE-200"
    ]
  },
  {
    "id": "ATD-T0074",
    "tactic": "ATD-TA2",
    "title": "RAG and retrieval-index target reconnaissance",
    "mechanism": "An attacker enumerates an agent's RAG or retrieval index to locate documents to poison or sensitive entries to exfiltrate.",
    "severity": "medium",
    "evidence": {
      "kind": "research",
      "label": "MITRE ATLAS AML.T0064 Gather RAG-Indexed Targets"
    },
    "asi": [
      "ASI06"
    ],
    "atlas": [
      "AML.T0064"
    ],
    "cwe": [
      "CWE-200"
    ]
  },
  {
    "id": "ATD-T0075",
    "tactic": "ATD-TA4",
    "title": "Agent configuration and permission reconnaissance",
    "mechanism": "An attacker discovers an agent's configuration, connected tools, and granted permissions to plan a tailored privilege-escalation or tool-abuse attack.",
    "severity": "medium",
    "evidence": {
      "kind": "research",
      "label": "MITRE ATLAS AML.T0084 Discover AI Agent Configuration"
    },
    "asi": [
      "ASI03"
    ],
    "atlas": [
      "AML.T0084"
    ],
    "cwe": [
      "CWE-200"
    ]
  },
  {
    "id": "ATD-T0076",
    "tactic": "ATD-TA9",
    "title": "Fraudulent transaction execution by a compromised commerce agent",
    "mechanism": "A compromised or manipulated purchasing or payment agent executes unauthorized or fraudulent transactions on the user's behalf.",
    "severity": "high",
    "evidence": {
      "kind": "research",
      "label": "SAFE-MCP SAFE-T2104 Fraudulent Transactions"
    },
    "asi": [
      "ASI06",
      "ASI01"
    ],
    "atlas": [],
    "cwe": [
      "CWE-840"
    ]
  },
  {
    "id": "ATD-T0077",
    "tactic": "ATD-TA4",
    "title": "Broken object or workspace authorization in an agent tool (IDOR)",
    "mechanism": "An agent or MCP tool serves or mutates data across a user, workspace, or tenant boundary because it omits object-level authorization, letting one principal reach another principal's resources.",
    "severity": "high",
    "evidence": {
      "kind": "cve",
      "label": "CVE-2026-46519 MCP Server Kubernetes tool access-control bypass (~36 instances incl. FlowiseAI cross-workspace)"
    },
    "asi": [
      "ASI03"
    ],
    "atlas": [],
    "cwe": [
      "CWE-639",
      "CWE-863",
      "CWE-284"
    ]
  },
  {
    "id": "ATD-T0078",
    "tactic": "ATD-TA5",
    "title": "Prompt-to-SQL injection via an agent's natural-language database tool",
    "mechanism": "An agent's database or query tool builds a SQL/query string from natural-language or model output without parameterization, so a crafted prompt injects the query and can escalate to RCE.",
    "severity": "critical",
    "evidence": {
      "kind": "cve",
      "label": "CVE-2026-25879 Langroid prompt-to-SQL injection leading to RCE"
    },
    "asi": [
      "ASI05",
      "ASI02"
    ],
    "atlas": [
      "AML.T0053"
    ],
    "cwe": [
      "CWE-89"
    ]
  },
  {
    "id": "ATD-T0079",
    "tactic": "ATD-TA8",
    "title": "Secret leakage through agent or MCP server logs and traces",
    "mechanism": "An agent or MCP server writes tool arguments, queries, or responses containing credentials or secrets into logs or traces, exposing them to anyone with log or trace access.",
    "severity": "high",
    "evidence": {
      "kind": "cve",
      "label": "CVE-2026-44969 dbt MCP server logs tool arguments incl. credentials (also n8n-MCP)"
    },
    "asi": [
      "ASI06"
    ],
    "atlas": [],
    "cwe": [
      "CWE-532"
    ]
  },
  {
    "id": "ATD-T0080",
    "tactic": "ATD-TA1",
    "title": "Cross-client data leak via shared MCP server state",
    "mechanism": "A shared MCP server or transport mixes state across concurrent clients (a race condition or missing per-client isolation), so one client receives another client's data or context.",
    "severity": "high",
    "evidence": {
      "kind": "cve",
      "label": "CVE-2026-25536 @modelcontextprotocol/sdk cross-client data leak via shared server state"
    },
    "asi": [
      "ASI06",
      "ASI07"
    ],
    "atlas": [],
    "cwe": [
      "CWE-362"
    ]
  },
];

export const ATD_STATS = {
  techniques: ATD_TECHNIQUES.length,
  withLiveRule: ATD_TECHNIQUES.filter((t) => t.atrRule).length,
  withCve: ATD_TECHNIQUES.filter((t) => t.evidence.kind === "cve").length,
  tactics: ATD_TACTICS.length,
};

// Map the internal render-model to the normative schema shape used by the
// public, downloadable enumeration (atd-techniques.json) and validated by
// scripts/validate-atd.ts. The page renders the simple model; the published
// artifact conforms to atd-technique.schema.json.
const TACTIC_SURFACE: Record<string, string[]> = {
  "ATD-TA1": ["tool_input", "tool_response"],
  "ATD-TA2": ["memory_op"],
  "ATD-TA3": ["content", "tool_response"],
  "ATD-TA4": ["tool_input"],
  "ATD-TA5": ["tool_input", "tool_response"],
  "ATD-TA6": ["tool_input", "trace"],
  "ATD-TA7": ["inter_agent_msg"],
  "ATD-TA8": ["trace"],
  "ATD-TA9": ["payment_mandate"],
};

export function toATDRecord(t: ATDTechnique) {
  const refType =
    t.evidence.kind === "cve"
      ? "cve"
      : t.evidence.kind === "aspirational"
        ? "vendor"
        : "research";
  return {
    atd_id: t.id,
    schema_version: "0.1.0",
    title: t.title,
    tactic: t.tactic,
    abstraction: "base",
    status: "experimental",
    severity: t.severity,
    description: t.mechanism,
    detection_surface: TACTIC_SURFACE[t.tactic] ?? ["content"],
    mappings: {
      owasp_asi: t.asi,
      mitre_atlas: t.atlas,
      cwe: t.cwe,
      ...(t.asi.length === 0 && t.atlas.length === 0
        ? { gap_note: "No upstream framework names this technique yet." }
        : {}),
    },
    references: t.evidence.url
      ? [{ type: refType, url: t.evidence.url }]
      : [],
    ...(t.atrRule ? { atr_rule: t.atrRule } : {}),
  };
}
