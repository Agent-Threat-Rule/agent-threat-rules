# ATR Telemetry Feedback Spec

> Optional feedback channel for downstream consumers (Microsoft AGT,
> Cisco AI Defense, MISP, OWASP A-S-R-H, any custom integration).
> Consumers POST a periodic aggregate of "what fired in your production
> environment" so ATR can auto-promote rules that work in the wild and
> auto-demote rules that produce real-world FPs.

This spec is implemented opt-in by each consumer. ATR ships the
endpoint + ingestion pipeline; consumers decide whether to wire it up.

## Why this exists

ATR's pre-merge quality gate ([QUALITY-GATE.md](QUALITY-GATE.md))
validates against ~480 internal samples. Real consumer traffic is
several orders of magnitude bigger and shaped differently. Without
telemetry feedback, the maturity ladder relies on time-in-main +
proxy heuristics — fine, but slower and less accurate than direct
signal from the people actually shipping ATR.

When telemetry is wired:

- Rules with high wild-match counts + low FP-dismissal rate
  auto-promote `experimental → test → stable` faster than the time
  threshold alone.
- Rules with even a few real-world FP dismissals auto-demote
  `stable → test → experimental` before the FP pattern spreads.
- The website's coverage stats publish real "X% of stable rules
  fired in N production environments last week" numbers.

## Endpoint

`POST https://telemetry.agentthreatrule.org/v1/report`

Headers:

- `Content-Type: application/json`
- `X-ATR-Consumer: <consumer-id>` — e.g. `microsoft-agt`,
  `cisco-ai-defense`, `misp-galaxy`. Consumer IDs are coordinated
  out-of-band with the ATR team to prevent spoofing. Unknown consumer
  IDs return 401.
- `X-ATR-Signature: sha256=<hex>` — HMAC-SHA256 over the JSON body
  using the consumer's pre-shared key. Body is rejected if the HMAC
  doesn't validate.

Rate limit: 1 report per consumer per hour. Reports are
batch-aggregates, not per-event streams. Per-event streaming is
explicitly out of scope — ATR does not want, store, or process
end-user data.

## Request body

```json
{
  "consumer_id": "microsoft-agt",
  "consumer_version": "2.4.1",
  "report_period_start": "2026-05-12T00:00:00Z",
  "report_period_end": "2026-05-19T00:00:00Z",
  "atr_version": "2.1.3",
  "deployment_count": 142,
  "rules": [
    {
      "rule_id": "ATR-2026-00440",
      "fire_count": 18,
      "fp_dismissed_count": 0,
      "fp_confirmed_count": 0,
      "action_distribution": {
        "alert": 18,
        "shadow": 0,
        "deny": 0
      },
      "confidence_buckets": {
        "high": 18,
        "medium": 0,
        "low": 0
      }
    },
    {
      "rule_id": "ATR-2026-00402",
      "fire_count": 314,
      "fp_dismissed_count": 12,
      "fp_confirmed_count": 0,
      "action_distribution": {
        "alert": 314,
        "shadow": 0,
        "deny": 0
      },
      "confidence_buckets": {
        "high": 220,
        "medium": 80,
        "low": 14
      }
    }
  ]
}
```

Field definitions:

- `consumer_id` — string. Registered consumer identifier.
- `consumer_version` — string. SemVer of the consumer integration.
  Helps debug "rule fired only on AGT v2.4+" patterns.
- `report_period_start` / `report_period_end` — ISO-8601. The
  aggregation window. Typically 7 days, but consumers can choose any
  cadence ≥1 hour.
- `atr_version` — string. SemVer of the ATR rule pack the consumer
  was running during the window. ATR uses this to correlate report
  data with rule revisions.
- `deployment_count` — integer. How many distinct production
  deployments / sessions / customers contributed to the aggregate.
  ATR uses this for confidence weighting; a 1000-deployment report
  carries more signal than a 1-deployment report.
- `rules[].rule_id` — string. ATR-2026-NNNNN form.
- `rules[].fire_count` — integer. Total times the rule produced a
  match during the window, aggregated across all deployments.
- `rules[].fp_dismissed_count` — integer. Of the matches, how many
  were dismissed as false positives by the consumer's operator /
  customer / triage flow. Includes "rule fired but was suppressed by
  downstream policy" cases.
- `rules[].fp_confirmed_count` — integer. Of the matches, how many
  were sent back as a confirmed-FP report (the consumer expects ATR
  to file or has filed an issue).
- `rules[].action_distribution` — counts per resolved action. The
  semantics depend on the consumer's runtime; `alert` / `shadow` /
  `deny` are the canonical bucket names.
- `rules[].confidence_buckets` — counts per confidence band
  (`high` ≥0.8, `medium` 0.5-0.8, `low` <0.5).

Only rules that produced at least one match in the window are
reported. The endpoint does not want zero-rows; they're inferred from
the rule list ATR already publishes.

## Response

```json
{
  "accepted": true,
  "consumer_id": "microsoft-agt",
  "report_id": "rep_2026_05_19_microsoft_agt_142",
  "ingest_lag_ms": 84,
  "auto_actions": [
    {
      "rule_id": "ATR-2026-00402",
      "action": "demote",
      "from": "stable",
      "to": "test",
      "reason": "fp_dismissed_count (12) exceeds threshold for stable tier (≤3 per 1000 fires)"
    }
  ]
}
```

`auto_actions` lists any maturity-tier changes triggered by this
report. Empty array means no immediate action. Actions are committed
within 24 hours via the standard maturity-promote workflow.

## ATR-side ingestion

Reports land in `data/telemetry/reports/<consumer>/<YYYY-MM-DD>.json`.
Daily, `scripts/aggregate-telemetry.ts` (planned) walks the
last 30 days of reports per rule and computes:

- `total_fires_30d`
- `fp_rate_30d` (= sum of fp_dismissed + fp_confirmed / total)
- `consumer_count_30d` (distinct consumer_ids reporting)
- `deployment_count_30d` (sum of distinct deployments)

These feed back into `scripts/maturity-promote.ts` as additional
signal. Specifically:

- Rules promoted by maturity-promote get an "audit" check: if the
  rule has telemetry from ≥1 consumer with `fp_rate_30d > 0.01`
  (>1% FP), the promotion is blocked.
- Rules with `total_fires_30d ≥ 50` from ≥3 distinct consumers can
  promote `test → stable` even if the wild-match heuristic fails —
  real fires count as wild matches.
- Rules with `fp_rate_30d > 0.05` (>5% FP) on a stable rule trigger
  auto-demotion to `test` plus an FP-report issue cross-linking the
  contributing consumer's report id.

## What ATR will NOT store

- End-user prompts, attack payloads, or any raw event content.
- IP addresses, session ids, user identifiers from the consumer's
  customer base.
- Per-deployment timing or geolocation.

If a consumer accidentally includes any of the above, the ingest
endpoint rejects the report and emails the contact registered for
that consumer.

## Reference implementations

When the first consumer wires this up, the reference client will
land at `src/telemetry/client.ts` with a TypeScript helper:

```ts
import { reportToATR } from "agent-threat-rules/telemetry";

await reportToATR({
  consumerId: "my-platform",
  periodStart: lastReportEnd,
  periodEnd: now,
  rules: aggregatedRuleStats,
  atrVersion: "2.1.3",
  deploymentCount: activeCustomers,
});
```

A Python equivalent will ship in the `pyatr` package.

## Status

| Component                                    | State                                                        |
| -------------------------------------------- | ------------------------------------------------------------ |
| Spec (this doc)                              | v0.1 draft, 2026-05-12                                       |
| Endpoint `telemetry.agentthreatrule.org`     | Not yet deployed — waiting for first consumer commitment     |
| HMAC consumer key registry                   | Manual coordination via adam@agentthreatrule.org         |
| `src/telemetry/client.ts`                    | Not built — implements once endpoint lands                   |
| `scripts/aggregate-telemetry.ts`             | Not built — implements once first reports land               |
| `scripts/maturity-promote.ts` telemetry hook | Wired as TODO comment — activates when telemetry data exists |

If you maintain a downstream consumer and want to implement this
spec, please open an issue or email `adam@agentthreatrule.org`.
First implementer gets their feedback prioritised in the spec
revision.
