# ATR Semgrep Rule Pack

A Semgrep ruleset that ports a selection of Agent Threat Rules (ATR) detections to
Semgrep's generic-mode pattern engine. The rules flag AI-agent and MCP supply-chain
attack signatures in source code, skill files, and IDE/agent configuration files:
credential exfiltration, install-time and auto-run backdoors, dead-man's-switch
persistence, time-gated payloads, rules-file backdoors, tool impersonation, and LLM
output XSS.

Each rule is a one-to-one port of a published ATR YAML rule. The ATR rule ID is recorded
in every rule's metadata (`atr-rule-id`) and the `source-rule-url` links back to the
upstream rule.

## Running

Scan a directory with the whole pack:

```
semgrep --config integrations/semgrep/rules .
```

Run a single rule:

```
semgrep --config integrations/semgrep/rules/atr-hades-agent-credential-exfil .
```

Run the rule pack's own test suite:

```
semgrep test integrations/semgrep/rules/
```

A future build will publish this pack as a named registry ruleset so it can be pulled
directly (`semgrep --config <ruleset-url>`) without a local checkout.

## License

MIT. Each rule carries `license: MIT` in its metadata. You may copy these rules into your
own pipeline or into the upstream Semgrep registry.

## What these rules are, and what they are not

These are signature-based pattern detections. They match known attack shapes — specific
command structures, credential-path-plus-exfil co-location windows, typosquatted tool
names, and documented campaign indicators (Hades, Miasma, Mini Shai-Hulud, ClawHavoc,
ToxicSkills). They are written for high precision: every rule is tested to fire on its
true-positive samples and stay silent on its true-negative samples, and the whole pack
runs clean (zero findings) against ATR's 432-file benign skill corpus.

Honest limitations:

- Signature detection catches known shapes. Novel obfuscation, heavy encoding, or attack
  variants outside the co-location windows can evade these patterns. ATR documents known
  evasion techniques; treat a clean scan as "no known signature matched", not "safe".
- Generic mode matches raw bytes, not parsed syntax. It has no taint tracking and no data
  flow. A few rules use co-location windows (for example, a credential read within ~250
  characters of an outbound send) as a proxy for a real data flow.
- These rules are an aid to review, not a replacement for it. A WARNING-severity rule
  (impersonation) in particular flags names that warrant a publisher check, not a
  guaranteed compromise.

## Rules

| Rule ID | ATR rule | What it detects | Severity |
|---------|----------|-----------------|----------|
| `atr-hades-agent-credential-exfil` | ATR-2026-00576 | AI-agent credential/config read co-located with an outbound send (Hades / Shai-Hulud harvester) | ERROR |
| `atr-miasma-agent-config-backdoor` | ATR-2026-00575 | npm install-time exec or agent auto-run config write paired with fetch/spawn (Miasma worm) | ERROR |
| `atr-shai-hulud-dead-mans-switch` | ATR-2026-00525 | GitHub-token watchdog wired to a destructive action (Mini Shai-Hulud) | ERROR |
| `atr-skill-data-exfiltration` | ATR-2026-00149 | Sensitive-file archive/read plus exfil sink, DNS exfil, or cloud-metadata access | ERROR |
| `atr-skill-malicious-code` | ATR-2026-00121 | Base64-exec, password-archive evasion, raw-IP/paste-service RCE, reverse shell | ERROR |
| `atr-skill-time-gated-exfil` | ATR-2026-00157 | Time check gating a credential read or outbound request (rug-pull timebomb) | ERROR |
| `atr-rules-file-backdoor` | ATR-2026-00512 | AI coding-assistant rules-file edit paired with an exfil/inject directive | ERROR |
| `atr-cursor-mcp-autorun-rce` | ATR-2026-00419 | IDE MCP config with a shell-binary or inline-exec command field (CVE-2025-54136) | ERROR |
| `atr-mcp-skill-impersonation` | ATR-2026-00060 | Typosquatted or fake-upgrade MCP tool names | WARNING |
| `atr-llm-output-xss` | ATR-2026-00516 | Prompt eliciting an XSS payload (cookie/DOM theft) from the model | ERROR |

Upstream rules live in the [agent-threat-rules](https://github.com/Agent-Threat-Rule/agent-threat-rules)
repository under `rules/<category>/`.
