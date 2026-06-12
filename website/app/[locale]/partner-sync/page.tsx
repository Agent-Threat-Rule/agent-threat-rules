import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Partner Live Sync — ATR',
  description:
    'Live rule sync for qualifying security platforms. ATR confirmed rules, polled on your own cadence, authenticated via partner API key.',
};

// Keep the copy deliberately terse. This page is not for general users; it's the
// page we link to in the 403 response from /api/atr-rules/live when someone tries
// to hit it without a partner key. One-page, no marketing gloss.

export default function PartnerSyncPage() {
  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="text-3xl font-bold">Partner Live Sync</h1>
      <p className="mt-2 text-neutral-400">
        Live pull of ATR confirmed rules from Threat Cloud. Partner-tier API key required.
      </p>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">Who this is for</h2>
        <p>
          Security platforms, model vendors, and enterprise SOC teams that embed ATR rules into
          their own detection stack and want to minimise npm-publish lag. For casual users,{' '}
          <code className="rounded bg-neutral-800 px-1">npm install agent-threat-rules</code> or{' '}
          <code className="rounded bg-neutral-800 px-1">pip install pyatr</code> is the right path.
        </p>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">Getting a key</h2>
        <p>
          Email <a className="underline" href="mailto:adam@agentthreatrule.org">adam@agentthreatrule.org</a>{' '}
          with: organisation name, intended use, approximate poll interval. Keys are issued
          manually during the early-partner phase. No cost. MIT terms still apply to the rules
          themselves.
        </p>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">Endpoint</h2>
        <pre className="overflow-x-auto rounded bg-neutral-900 p-4 text-sm">
{`GET https://tc.agentthreatrule.org/api/atr-rules/live?since=<ISO-8601>
Authorization: Bearer <partner-key>`}
        </pre>
        <p className="text-sm text-neutral-400">
          Responds with <code>ETag</code> + <code>Last-Modified</code>. Send{' '}
          <code>If-None-Match</code> on subsequent polls to get a{' '}
          <code>304 Not Modified</code> when nothing has changed — no body, no rate-limit cost.
        </p>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">Response shape</h2>
        <pre className="overflow-x-auto rounded bg-neutral-900 p-4 text-sm">
{`{
  "ok": true,
  "data": [
    {
      "ruleId": "ATR-2026-00150",
      "ruleContent": "title: ...\\nid: ATR-2026-00150\\n...",
      "publishedAt": "2026-04-17T00:03:42.124Z",
      "source": "atr" | "atr-community",
      "category": "context-exfiltration",
      "severity": "critical",
      "mitreTechniques": "AML.T0057",
      "tags": "..."
    }
  ],
  "meta": { "total": 642, "etag": "W/\\"642-2026-04-17T00:03:42Z\\"" }
}`}
        </pre>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">Minimum polling example</h2>
        <pre className="overflow-x-auto rounded bg-neutral-900 p-4 text-sm">
{`# 5-minute cadence, ETag-aware
LAST_ETAG=""
while true; do
  RESP=$(curl -sS -w '\\n%{http_code}' \\
    -H "Authorization: Bearer $ATR_PARTNER_KEY" \\
    \${LAST_ETAG:+-H "If-None-Match: $LAST_ETAG"} \\
    "https://tc.agentthreatrule.org/api/atr-rules/live")
  STATUS=$(echo "$RESP" | tail -1)
  if [ "$STATUS" = "304" ]; then
    echo "no change"
  elif [ "$STATUS" = "200" ]; then
    echo "$RESP" | head -n-1 | jq '.data | length' # process rules
    LAST_ETAG=$(curl -sSI -H "Authorization: Bearer $ATR_PARTNER_KEY" \\
      "https://tc.agentthreatrule.org/api/atr-rules/live" | grep -i etag | cut -d' ' -f2- | tr -d '\\r')
  fi
  sleep 300
done`}
        </pre>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">Limits</h2>
        <ul className="list-disc pl-6">
          <li>Global rate limit applies. 1-minute polls are fine; sub-minute will 429.</li>
          <li>
            Rules can change in both directions — a rule can be quarantined post-canary. Treat the
            full response as the current authoritative set, not an append-only log.
          </li>
          <li>
            Partner keys are audit-logged. Key compromise? Email us, we revoke and re-issue.
          </li>
          <li>
            Confirmed only. Canary rules are not exposed here. If you want canary signal, email.
          </li>
        </ul>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">Why this exists</h2>
        <p className="text-neutral-400">
          npm publish cycles give ~10-minute latency from TC canary-pass to a released package.
          That is fine for most. Partners that want to tie rule updates to their own deploy
          cadence, or who cannot re-install npm packages on every flywheel cycle, use this
          endpoint instead.
        </p>
      </section>
    </main>
  );
}
