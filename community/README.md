# Community records

| File | What it is |
|---|---|
| `members.yaml` | The public directory at agentthreatrule.org/community. People are listed only after they confirm their entry. |
| `ledger.jsonl` | The community ledger: one public, verifiable piece of work per line. Empty until the first events are recorded. |
| `ledger.schema.json` | The format of a ledger line. |
| `tiers.yaml` | How tiers are earned from ledger events. |
| `drafts/` | Forms that are written but not open yet, with the reason in each file. |

## How the ledger works

Every event links to public evidence, such as a merged pull request, an issue comment or a verified receipt, and says who verified it: CI, or a maintainer who is not the person who did the work.

| Code | Event |
|---|---|
| E1 | Contribution accepted (rule, test question, specification, code, docs) |
| E2 | Review comment that led to a change |
| E3 | Confirmed defect in a rule, test, scoring rule or mapping |
| E4 | Receipt signed by someone other than the maintainers and verified by CI |
| E5 | Calibration run under an analysis plan fixed before the runs |
| E6 | Mapping reviewed by someone from the framework concerned |
| E7 | Adoption by an organization, re-checked monthly |
| E8 | A contribution adopted by another unit or cited by a receipt |
| E9 | Test question (atomic) accepted out of draft |

Tiers are computed from these events by `scripts/community/ledger.ts`:

```bash
npx tsx scripts/community/ledger.ts validate
npx tsx scripts/community/ledger.ts compute
```

Rules that do not change:

- Money never grants a tier. There is no event type for payment, sponsorship or membership fees.
- Automatic grants stop at reviewer, which is only nominated; a maintainer confirms it. Advisor and TSC seats are decided by people.
- Nobody verifies their own event.
- "Working on" on a member card comes from events in the last 90 days. Projects someone said they are interested in are shown separately, as interests.
