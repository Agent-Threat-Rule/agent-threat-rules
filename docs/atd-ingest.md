# CVE -> ATD ingest — the WHAT layer's daily feed

ATR has three layers, mirroring the vulnerability stack: ATD is the WHAT
(technique knowledge base, like ATT&CK/CWE), the rules are the HOW (detection,
like Sigma), and the wild-scan/instance layer is the WHICH. The daily collector
caught frontline agent CVEs and `promote-detection-ready.ts` turned the
generalizable ones into rules — but nothing fed ATD. A CVE either became a
detection rule or vanished; the knowledge base stayed hand-maintained.

`scripts/atd/ingest-cve-to-atd.ts` closes that gap:

```
agent-relevant CVE  ->  ATD technique (always)  ->  if generalizable -> ATR rule
```

## Three outcomes per CVE

- **ENRICH** — if the CVE's CWE matches an existing technique, the CVE is added
  as real-world evidence on that technique. Automatic, schema-validated, low
  risk. This turns ATD from 80 hand-written techniques into a living evidence
  base.
- **DRAFT** — if a CWE has NO covering technique but is corroborated by 2+
  independent CVEs (`--min-evidence`, default 2), Claude drafts a full
  candidate technique entry — title, description, tactic, abstraction,
  detection_surface, OWASP ASI / MITRE ATLAS mappings — via a direct
  `@anthropic-ai/sdk` call (same pattern as `scripts/fn-mine-llm.ts`). The
  draft is validated against `atd-technique.schema.json`; a failure triggers
  one corrective retry with the validator's error message, and a cluster that
  still fails is dropped (never force-written) and logged. Survivors land in
  `data/atd-ingest/new-technique-drafts-<date>.json` for HUMAN review — never
  auto-merged into the catalog, since a new technique is a claim about the
  threat taxonomy, not a row to mint. `atd_id` is assigned deterministically
  (next free `ATD-Tnnnn` after the real catalog) but is explicitly provisional:
  re-check it's still free at merge time. A CWE already covered by a prior
  run's draft is skipped (`loadAlreadyDraftedCwes`) so an unresolved cluster
  doesn't spawn a near-duplicate review PR every day it runs.
- **RAW** — everything that doesn't clear the DRAFT bar (no CWE at all, or a
  CWE seen only once) is dumped as a flat list in
  `data/atd-ingest/candidates-<date>.json` for human triage. Fabricating a
  technique off a single unconfirmed data point would be worse than saying
  "not enough signal yet" — in the current backlog roughly 3 in 4 CVE
  candidates have no extracted CWE at all and cannot be responsibly clustered.

The agent-relevance gate (`agentRelevance()`, reused from the GHSA collector) is
re-applied as defence in depth: a stray non-agent CVE must never reach ATD.

## Daily flywheel

`.github/workflows/atd-ingest.yml` runs daily after the collector + promote-cve,
and opens a **draft** PR (label `atd,needs-human-review`) only when something
actually changed on disk — a quiet no-op day opens no PR. Nothing auto-merges;
nothing is auto-minted into the catalog.

## Usage

```
npx tsx scripts/atd/ingest-cve-to-atd.ts                                # dry-run, ENRICH/RAW only
npx tsx scripts/atd/ingest-cve-to-atd.ts --write                        # apply enrichments
npx tsx scripts/atd/ingest-cve-to-atd.ts --write --draft-techniques     # + Claude-drafted new techniques
npx tsx scripts/atd/ingest-cve-to-atd.ts --source ghsa --max 200
npx tsx scripts/atd/ingest-cve-to-atd.ts --draft-techniques --min-evidence 3 --max-new-techniques 5
```

`--draft-techniques` requires `ANTHROPIC_API_KEY` in the environment; if unset
it logs a warning and skips LLM drafting without failing the run (ENRICH/RAW
still complete). Model defaults to `claude-sonnet-5`, overridable via
`ATR_ATDMINE_MODEL`.

## Note

Candidate/draft tactics are only as good as the proposal's `tags.category`.
Some collector rows are mis-categorized (e.g. an MCP-server network-binding CVE
tagged `model-abuse`), so a deterministic category-derived tactic — and
Claude's own tactic pick, which is told to cross-check but not blindly trust
that suggestion — are both starting points for the reviewer, not a verdict.
Fixing collector categorization upstream improves candidate and draft quality.
