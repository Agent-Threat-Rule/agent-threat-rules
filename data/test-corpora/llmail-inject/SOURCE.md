# llmail-inject

- Upstream: https://huggingface.co/datasets/microsoft/llmail-inject-challenge
- Revision: `1063bdf01ec8762b812d5e06ee768a06faa5a6f7`
- Files: `data/raw_submissions_phase1.jsonl`, `data/raw_submissions_phase2.jsonl`
- License (dataset card front matter, quoted): `license: mit`
- Retrieved: 2026-10-06
- Row filter: all five objectives true (email.retrieved, defense.undetected, exfil.sent, exfil.destination, exfil.content); deduplicated on subject+body; stratified by phase/level in sha256 order; at most 3000
- Rows kept: 1973

Regenerate with `npx tsx scripts/sync-agent-attack-corpora.ts --write`.
