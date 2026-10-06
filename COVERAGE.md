# ATR Coverage Report

> **Status: manually maintained snapshot, last reviewed 2026-09-22.**
> This file is **not generated** — no script writes it, so it drifts. It had
> stood untouched since 2026-03-12, when it described a 71-rule, v0.4.0 corpus,
> and by then every number and nearly every rule ID in it was wrong.
>
> Authoritative sources, in order of preference:
>
> | You want | Read this | Generated? |
> |---|---|---|
> | Live rule counts, categories, benchmarks | [`data/stats.json`](data/stats.json) | yes |
> | OWASP Agentic Top 10 per-category rule counts | [`docs/OWASP-AGENTIC-MAPPING.md`](docs/OWASP-AGENTIC-MAPPING.md) | yes |
> | SAFE-MCP technique coverage | [`docs/SAFE-MCP-MAPPING.md`](docs/SAFE-MCP-MAPPING.md) | yes |
> | Version-pinned benchmark results | README §Evaluation | from `data/measurements/` |
> | What ATR structurally cannot detect | [`LIMITATIONS.md`](LIMITATIONS.md) | no |
>
> Quote those. Do not quote a rule count from this page — it does not carry one.

## Framework Coverage Summary

Reviewed 2026-09-22 against the rules then on disk. Every rule in the repository
carries at least one OWASP Agentic (`ASI`) tag, and every ASI category from
ASI01 to ASI10 has rules mapped to it.

| Framework | Coverage | Per-category detail |
|---|---|---|
| OWASP Agentic Top 10 (2026) | **10 / 10 categories** | [`docs/OWASP-AGENTIC-MAPPING.md`](docs/OWASP-AGENTIC-MAPPING.md) |
| OWASP LLM Top 10 (2025) | **10 / 10 risks** have tagged rules | per-rule `compliance` / `tags` fields |
| SAFE-MCP (OpenSSF) | **78 / 85 techniques** (conservative lower bound) | [`docs/SAFE-MCP-MAPPING.md`](docs/SAFE-MCP-MAPPING.md) |
| MITRE ATLAS | referenced across the corpus | per-rule `mitre_atlas` field |
| MITRE ATT&CK | referenced across the corpus | per-rule mapping fields |

Reproduce the ASI verdict yourself:

```bash
for i in 01 02 03 04 05 06 07 08 09 10; do
  printf 'ASI%s: %s rules\n' "$i" "$(grep -rl "ASI$i" rules/ | wc -l)"
done
```

Counting *rules that mention a tag* is a coarser measure than the generated
mapping doc's parse of the `compliance` field, so treat the numbers that command
prints as an upper bound and the generated doc as the citable figure.

### A note on the category titles

Earlier revisions of this file labelled ASI07 "Multi-Agent Manipulation", ASI08
"Agentic RAG Poisoning" and ASI09 "Insufficient Logging and Monitoring", and
recorded ASI07 and ASI09 as uncovered gaps. Those titles came from a draft
taxonomy that OWASP did not ship. Under Agentic Top 10 v1.0 (December 2025) the
categories are **ASI07 Insecure Inter-Agent Communication**, **ASI08 Cascading
Failures** and **ASI09 Human-Agent Trust Exploitation**, and all three have
rules. The old "6 of 10 covered, 2 partial, 2 gaps" verdict was wrong on both
the taxonomy and the count; it is removed rather than carried forward.

---

## Historical snapshot: per-rule framework tables (v0.4.0 era, 2026-03-12)

**Do not use the rule IDs below.** They use the retired three-digit scheme
(`ATR-2026-001`), which was replaced by the five-digit scheme
(`ATR-2026-00001`). They also enumerate a 71-rule corpus that has since grown by
an order of magnitude, so these tables are badly incomplete as well as
mis-numbered. They are kept only as a record of what the early mapping work
covered.

For a live answer, read the rule's own fields:

```bash
# every CVE referenced anywhere in the corpus
grep -rhoE 'CVE-[0-9]{4}-[0-9]+' rules/ | sort -u

# rules mapped to a given ATLAS technique
grep -rl 'AML.T0051' rules/
```

### CVE mappings (historical)

| CVE | Description |
|-----|-------------|
| CVE-2024-5184 | LLM prompt injection vulnerability |
| CVE-2024-3402 | LLM prompt injection bypass |
| CVE-2024-22524 | Indirect prompt injection via content |
| CVE-2025-53773 | GitHub Copilot RCE via prompt injection |
| CVE-2025-32711 | System prompt leakage / indirect injection |
| CVE-2026-24307 | Agent memory/context manipulation |
| CVE-2025-68143 | MCP tool response RCE |
| CVE-2025-68144 | MCP tool response injection |
| CVE-2025-68145 | MCP tool response exploitation |
| CVE-2025-6514 | MCP malicious response |
| CVE-2025-59536 | Tool output injection / hidden capability |
| CVE-2026-21852 | MCP server compromise |
| CVE-2026-0628 | Privilege escalation via agent tools |

The corpus now references far more CVEs than this table lists. Mappings are
based on attack pattern similarity; empirical validation against live CVE
payloads has not been performed.

### MITRE ATLAS techniques (historical)

AML.T0051 (LLM Prompt Injection) and its `.000` / `.001` sub-techniques,
AML.T0054 (LLM Jailbreak), AML.T0053 (LLM Plugin Compromise), AML.T0056 (LLM
Meta Prompt Extraction), AML.T0043 (Craft Adversarial Data), AML.T0010 (ML
Supply Chain Compromise), AML.T0040 (AI Model Inference API Access), AML.T0046
(Spamming ML System with Chaff Data), AML.T0049 (Exploit Public-Facing
Application), AML.T0050 (Command and Scripting Interpreter), AML.T0047
(ML-Enabled Product or Service), AML.T0044 (Full ML Model Access), AML.T0024
(Exfiltration via ML Inference API), AML.T0020 (Poison Training Data),
AML.T0018 (Backdoor ML Model), AML.T0055 (Unsecured Credentials), AML.T0057
(LLM Data Leakage), AML.T0052.000 (Spearphishing via Social Engineering LLM).

### MITRE ATT&CK techniques (historical)

T1059 (Command and Scripting Interpreter), T1071 (Application Layer Protocol),
T1083 (File and Directory Discovery), T1090 (Proxy), T1548 (Abuse Elevation
Control Mechanism), T1611 (Escape to Host), T1078 (Valid Accounts), T1550 (Use
Alternate Authentication Material), T1565 (Data Manipulation), T1565.001 (Stored
Data Manipulation), T1195 (Supply Chain Compromise).

---

## Known Gaps

These are structural limits of pattern-based detection. They are not fixed by
adding rules, and they do not expire the way a rule count does.
[`LIMITATIONS.md`](LIMITATIONS.md) is the fuller treatment.

1. **Multi-modal attacks (image-based prompt injection)** -- ATR rules operate on text content only. Attacks embedded in images, audio, or video (e.g. OCR-based prompt injection via screenshots, steganographic payloads in images sent to vision models) are not detectable with regex patterns.

2. **Embedding and vector poisoning attacks** -- Attacks that manipulate vector embeddings at the numerical level (e.g. adversarial perturbations to embedding vectors, cosine similarity manipulation) are outside the scope of text-based regex detection. Textual RAG poisoning is covered; embedding-level attacks are not.

3. **OAuth/SSO token theft via agent** -- ATR detects credential exposure in agent output, but coverage is thin for agents being manipulated into initiating OAuth flows, intercepting authorization codes, or abusing delegated credentials through redirect manipulation.

4. **Real-time behavioral anomaly detection** -- ATR rules use static pattern matching. They cannot detect anomalies that require temporal analysis, such as unusual tool call frequency, atypical data access patterns over time, or gradual behavioral drift. That needs runtime statistical analysis, not regex.

5. **Misinformation and hallucination detection** -- Rules tagged LLM09 exist, but no rule attempts to decide whether an output is factually true. Detecting hallucination requires ground-truth comparison or semantic analysis, which pattern matching cannot do.

6. **Logging and monitoring completeness** -- ATR defines what to detect, not how to log or monitor. Ensuring sufficient logging coverage is an engine and platform concern, not a rule concern.

7. **Adversarial suffix attacks** -- GCG-style adversarial suffixes produce statistically random-looking token sequences that cannot be reliably matched by regex without extreme false positive rates.

8. **Multilingual prompt injection** -- Some obfuscation is covered (homoglyphs, encoding), but injection payloads written entirely in non-English languages are not systematically addressed. The rules are English-first.

9. **Agent-to-agent protocol-level attacks** -- ATR rules inspect message content, not protocol metadata. Attacks that manipulate message routing, ordering, timing, or protocol headers in multi-agent frameworks are not covered.

10. **Model denial-of-service via context stuffing** -- Resource exhaustion patterns are detected, but deliberate context-window stuffing designed to push the system prompt out of context is not specifically modelled.
