# Precision repair — the broad rules a 142K wild scan over-fires on

A re-scan of the agent-skill ecosystem (~142,000 skills across OpenClaw /
ClawHub / Skills.sh / npm-MCP / pypi-MCP / GitHub) flagged ~2,500 skills. Manual
+ semantic review showed the overwhelming majority are NOT new malware: they are
dual-use security skills (pentest libraries), legit-org skills (Anthropic /
OpenAI / NVIDIA), documentation, and legitimate MCP servers — false positives.

The value of the scan was not new rules (the existing ruleset already covers the
real attack patterns it found). It was identifying which rules over-fire. The
four top-firing rules:

| Rule | Wild hits | 65K-benign FP | Diagnosis |
|------|----------:|--------------:|-----------|
| ATR-2026-00419 (Cursor MCP zero-click) | 320 | 1 | fires on legit `mcpServers` config examples in docs |
| ATR-2026-00276 (invisible unicode/BiDi) | 297 | **15** | **fires on a single incidental zero-width char** |
| ATR-2026-00135 (exfil URL in instructions) | 73 | 2 | fires on "verify your API key" setup prose |
| ATR-2026-00149 (skill exfil compound) | 64 | 3 | fires on a few docs mentioning wallet/cookie paths |

## The key finding: only one is a benign-gate failure

Three of the four PASS the 65,000-sample benign gate (1-3 FP). Their wild
over-firing is on dual-use / docs / MCP-config content that the benign gate does
not contain. Tightening their regex would lose true-attack recall without
fixing a measured benign FP. The correct fix for those is structural, not a
regex change:

1. Expand the benign gate with representative wild-scan dual-use / doc / legit-
   MCP-config samples, so the gate measures the real distribution the rules face.
2. Use scan-context discrimination (a config shown in a doc vs. a config being
   auto-loaded) — an engine/semantic concern, not a content regex.

A dual-use security skill that legitimately contains attack techniques is not a
false positive to suppress by blunting the rule; it is an advisory-tier signal
the consumer decides on. Blunting the deterministic rule to hide it would lose
real detections.

## The one real fix: ATR-2026-00276

This rule DID fail the benign gate: `[​‌⁠]` matched any single
zero-width character, and benign content carries incidental ones (copy-paste
artifacts, e.g. "area of ​​IT"). Tightened to require 3+ zero-width chars
interspersed through text — the hidden-instruction signature (breaking up
"ignore​ previous​ instructions​" to evade keyword filters) — while a lone
incidental char is now correctly benign.

- 65K-benign FP: **15 → 1** (the remaining hit is a jailbreak mislabeled benign
  in the corpus — a true positive, not an FP).
- Own true-positives: 4/4 still caught (the BiDi-override conditions are
  unchanged; one 2-char TP was strengthened to 3+, one 1-char TP was reclassified
  as a true-negative since a single word-joiner is benign).
- validate: PASS.

## Side note — benign corpus contamination

Several "benign" gate samples are themselves jailbreak prompts (e.g. a 16
zero-width-char "exception to ethical protocols" DAN prompt). The benign gate
should be audited for attack contamination — it understates true precision and
makes legitimate attack rules look like they FP.
