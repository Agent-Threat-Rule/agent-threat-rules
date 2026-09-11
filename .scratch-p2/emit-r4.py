import json
pats = {p["name"]: p["value"] for p in json.load(open(".scratch-p2/r4-pat.json"))}
sam  = {s["id"]: s["text"] for s in json.load(open(".scratch-p2/r4-sam.json"))}
def sq(s): return "'" + s.replace("'", "''") + "'"
def tc(ids, verdict):
    return "".join("    - input: %s\n      expected: %s\n" % (json.dumps(sam[i]), verdict) for i in ids)
TP = ["TP-rewrite-obfuscate","TP-type-jailbreak","TP-evolved-skill"]
TN = ["BN-attack-surface","BN-attack-simulation","BN-attacks-plural","BN-jailbreak-detector",
      "BN-security-skill","BN-no-metadata","BN-taxonomy-yaml","BN-atr-rule","BN-paper-writeup",
      "BN-desc-mentions-attack","BN-registry-json","BN-purpose-analysis"]
Y = f"""title: 'Installable Skill Manifest Self-Declares an Attack or Jailbreak Purpose'
id: ATR-2026-02818
rule_version: 1
# status must NOT be `draft`: src/engine.ts:407 skips draft rules before any
# lane check, so a draft rule is counted in the corpus and never evaluated.
status: experimental
description: >
  Detects a well-formed agent skill manifest whose own frontmatter metadata
  declares the artifact to be an attack: a `metadata:` block carrying
  `category: attack`, `type: jailbreak`, `class: exploit` or equivalent. Such a
  skill is directly installable into an agent and turns the host into a
  jailbreak-rewriting tool for whatever prompt it is handed.
  Source: JailbreakSkill (skills/registry.json plus 18 rewrite-*/SKILL.md files
  and 24 evolved_skill_examples/*/SKILL.md), where the attack category is
  emitted by the generator itself.
  WHY THIS KEYS ON THE DECLARATION AND NOT ON THE DESCRIPTION PROSE. Measured
  during harvest: of six real attack-declared SKILL.md files run against all 785
  rules, four matched nothing and the two that did matched only incidentally —
  one on the words "stay in character", one because its description literally
  contained "[INSERT PROMPT HERE]". The obvious repair, matching descriptions
  that talk about bypassing refusal paths, is the known false-positive mode of
  this codebase: a jailbreak DETECTOR, a prompt-injection auditor and an
  incident write-up helper all describe the same technique in the same words,
  and all three were authored as benign twins here. The frontmatter
  self-declaration carries the intent without the prose, so the rule uses only
  that.
  STRUCTURE IS LOAD-BEARING. The category value must terminate at end of line:
  `category: attack-surface` on a STRIDE threat-modelling skill, `attack_simulation`
  on a breach-and-attack-simulation runner and `attacks` on a MITRE ATLAS lookup
  skill all contain the substring and all must stay silent. The `metadata:` key
  must be present and the category must be indented beneath it, which is what
  keeps an ordinary technique-taxonomy YAML — `- id: T1059 / name: ... /
  category: attack` — out of scope.
  HONEST LIMITATION: this is a self-declaration detector, so an attacker who
  edits one line evades it completely. Its value is at registry and install
  time, against skills whose generator emits truthful metadata; it is not a
  containment control and must not be relied on as one.
author: 'ATR Project'
date: '2026/08/24'
schema_version: '1.0'
detection_tier: pattern
maturity: test
severity: high
references:
  owasp_llm:
    - 'LLM01:2025'
  owasp_agentic:
    - 'ASI05:2026'
  mitre_atlas:
    - AML.T0051 - LLM Prompt Injection
    - AML.T0054 - LLM Jailbreak
  papers:
    - 'JailbreakSkill: agent skills as a jailbreak-rewriting substrate — repo: https://github.com/BattleWen/JailbreakSkill, skills/registry.json, skills/rewrite-*/SKILL.md, evolved_skill_examples/{{effectiveness,novelty}}/*/SKILL.md'
compliance:
  nist_ai_rmf:
    - subcategory: "MG.3.2"
      context: "A skill manifest is third-party supplied content that augments agent behaviour; MG.3.2 requires monitoring of such supplied artifacts, and a manifest that declares itself an attack is the clearest possible case."
      strength: primary
    - subcategory: "GV.6.1"
      context: "GV.6.1 requires policies governing third-party AI supply-chain risk; this rule is the technical control enforcing such a policy at skill registry and install time."
      strength: secondary
    - subcategory: "MS.2.7"
      context: "MS.2.7 requires AI system security and resilience to be evaluated; installing a declared jailbreak-rewriting capability into the agent is a direct loss of that resilience."
      strength: secondary
  iso_42001:
    - clause: "8.1"
      context: "ISO/IEC 42001 Clause 8.1 (operational planning and control, including control of externally provided processes) is operationalised by rejecting externally supplied skill packages that declare an offensive purpose."
      strength: primary
    - clause: "6.1.2"
      context: "ISO/IEC 42001 Clause 6.1.2 (AI risk assessment) identifies malicious extension of agent capability as a treated risk; this rule is the corresponding detective control."
      strength: secondary
  eu_ai_act:
    - article: "15"
      context: "Article 15 (accuracy, robustness and cybersecurity) requires resistance to attempts to alter the system's use; installing a skill whose declared purpose is defeating the model's refusal path is exactly such an alteration."
      strength: primary
    - article: "9"
      context: "Article 9 (risk management system) requires identified risks to be addressed by appropriate measures; screening skill manifests before installation is that measure."
      strength: secondary
    - article: "14"
      context: "Article 14 (human oversight) requires that operators can supervise system capability changes; surfacing an attack-declared skill at install time is what makes that supervision possible."
      strength: secondary
tags:
  category: skill-compromise
  subcategory: attack-declared-skill-manifest
  scan_target: skill
  confidence: high
agent_source:
  type: mcp_exchange
  framework: [any]
  provider: [any]
detection:
  conditions:
    - field: content
      operator: regex
      value: {sq(pats['skill-frontmatter-declares-attack'])}
      description: 'Skill frontmatter (--- / name: / metadata:) whose indented category|type|class|kind|purpose key resolves, at end of line, to attack|jailbreak|exploit|offensive'
  condition: any
  false_positives:
    - 'An authorised red-team or model-evaluation skill library that honestly categorises its payload skills as attacks. The manifest is indistinguishable from a hostile one; only the deployment context differs, which is why this rule alerts rather than blocks.'
    - 'Security research that reproduces a JailbreakSkill manifest verbatim inside a document.'
response:
  actions: [alert]
  message_template: >
    [ATR-2026-02818] This skill manifest declares an attack/jailbreak purpose in
    its own frontmatter metadata. Installing it gives the agent a prompt-rewriting
    capability whose stated goal is defeating refusal behaviour. Confirm the
    source is an authorised red-team library before allowing installation.
test_cases:
  true_positives:
{tc(TP, "triggered")}  true_negatives:
{tc(TN, "not_triggered")}"""
open(".scratch-p2/staged/skill-compromise/ATR-2026-02818-skill-manifest-declares-attack-purpose.yaml","w").write(Y)
print("written")
