# Dual-Use Security Skills Corpus

Confirmed-legitimate security skills (penetration testing, CTF, bug bounty,
red-team tooling) harvested from real ecosystem scans.

These skills **contain attack patterns** (e.g. `eval(atob(...))`, exfil-style
example URLs, injection payloads) because they are security education or
tooling — **not because they perform a malicious action against the user.**

## Why a separate bucket (not `benign-corpus-extended/`)

The plain benign corpus asserts "no rule may fire on this text." If these
dual-use skills went there, any rule that legitimately detects (say) an
`eval(atob)` exfil payload would be rejected as a false positive — sacrificing
real malware detection that shares the same surface pattern.

Instead these serve a **different gate semantic**, to be wired when the
malicious-action / T2 semantic layer lands:

> A rule MAY fire on a dual-use skill **only if** an actual malicious-action
> indicator is also present (exfil destination, C2 callback, concealment,
> credential theft + transmission) — not merely an attack *mention* or example.

This operationalizes the design decision: **detect malicious action, not
attack knowledge.** Regex alone cannot distinguish "example in docs" from
"executed behavior"; that distinction is the T2 layer's job.

## Format

JSONL, one skill per line: `{ source, source_id, fired_rules, note, text }`.
`fired_rules` records which rules currently false-positive on it (the round-2
hardening worklist).

Source: ecosystem wild scan 2026-06-03 (98,883 unique SKILL.md, deduped).
