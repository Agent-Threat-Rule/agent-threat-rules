import type { Metadata } from 'next';
import { loadSiteStats } from '@/lib/stats';

export const metadata: Metadata = {
  title: 'NVIDIA garak × ATR — ATR',
  description:
    'Auto-convert NVIDIA garak red-team findings into ATR detection rules. 421 ATR rules wrapped as garak detectors (PR #1676, 97.1% recall on garak community jailbreak corpus). Every probe becomes a MIT-licensed defensive rule downstream.',
};

export default function GarakIntegratePage() {
  const stats = loadSiteStats();
  const ruleCountStr = `${stats.ruleCount} rules today`.padEnd(25);
  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="text-3xl font-bold">NVIDIA garak × ATR</h1>
      <p className="mt-2 text-neutral-400">
        Turn every garak failed probe into a MIT-licensed ATR detection rule. Zero extra red-team
        work, full provenance on the author line.
      </p>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">The idea</h2>
        <p>
          <a className="underline" href="https://github.com/NVIDIA/garak">
            garak
          </a>{' '}
          finds attacks at the LLM layer. ATR defends at the agent layer (tool calls, skills, MCP).
          Same attack payload, different defence surface. The bridge is a single Python script:
          garak reports in, ATR proposals out, crystallisation loop does the rest.
        </p>

        <pre className="overflow-x-auto rounded bg-neutral-900 p-4 text-sm">
{`garak (red team)                    ATR (standard)           downstream
─────────────────                    ──────────────           ──────────
Probes claude-3.7                    ${ruleCountStr}npm: agent-threat-rules
Probes gpt-5                 ──▶     +auto-crystallised       PyPI: pyatr
Probes gemini-2-pro                  from garak evidence      Cisco AI Defense
Writes report.jsonl                  canary 24h               OWASP Agentic Top 10
                                     auto-merge               your CI pipeline`}
        </pre>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">One-time setup</h2>
        <ol className="list-decimal space-y-2 pl-6">
          <li>
            Email <a className="underline" href="mailto:attlab0527@gmail.com">attlab0527@gmail.com</a>{' '}
            with your org name to receive a partner API key (manual issuance during early-partner
            phase, no cost, MIT terms).
          </li>
          <li>
            Fetch the pipe script: it lives in the ATR repo.{' '}
            <code className="rounded bg-neutral-800 px-1">
              curl -O https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/main/scripts/garak-to-tc.py
            </code>
          </li>
          <li>Set the key in your environment:{' '}
            <code className="rounded bg-neutral-800 px-1">export ATR_PARTNER_KEY=…</code>
          </li>
        </ol>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">Run it</h2>

        <p className="text-sm text-neutral-400">After a garak eval session:</p>
        <pre className="overflow-x-auto rounded bg-neutral-900 p-4 text-sm">
{`# Native garak JSONL report
python3 garak-to-tc.py \\
    --input ~/.local/share/garak/runs/2026-04-18-claude-3-7/report.jsonl \\
    --partner-name  nvidia-airt \\
    --target-model  claude-3-7-sonnet \\
    --garak-version 0.14.1

# Or ATR-style eval (from scripts/eval-garak.sh in this repo)
python3 garak-to-tc.py \\
    --input data/garak-benchmark/garak-eval-report.json \\
    --partner-name  nvidia-airt \\
    --dry-run   # inspect before submitting`}
        </pre>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">Two modes</h2>
        <p>
          The script has two submission modes. The default (<code>--mode drafter</code>) is what
          you want.
        </p>
        <ul className="list-disc pl-6">
          <li>
            <strong>drafter</strong> (default). POSTs each failed probe to{' '}
            <code>/api/atr-proposals/from-payload</code>. Server-side runs a tool-use LLM drafter
            (grep existing rules for dedup, fetch research for grounding, write YAML with 3+
            conditions / 5+ TP / 5+ TN / 3+ evasion tests), passes RFC-001 quality gate, self-tests
            its own regex, then files as a proposal. Each call takes 30-60s. This is the mode that
            produces real ATR rules.
          </li>
          <li>
            <strong>proposal</strong> (legacy). POSTs a client-built literal draft. Fast but the
            LLM reviewer typically rejects these as too narrow (literal fingerprint ≠ detection
            rule). Only use if you have your own YAML-generation step upstream.
          </li>
        </ul>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">What happens downstream</h2>
        <ol className="list-decimal space-y-1 pl-6">
          <li>
            Each unique failed probe → one proposal in <code>/api/atr-proposals</code> with full
            garak provenance embedded.
          </li>
          <li>
            TC crystallisation LLM reads the attack payload + garak metadata and drafts a
            generalised detection regex.
          </li>
          <li>
            Rule enters 24h canary. Every ATR-integrated client in the field gets a sampling dose
            (~10%). If any client reports false positives, the rule is quarantined automatically.
          </li>
          <li>
            Survives canary → safety gate (0 FP on 432-sample benign corpus, test_cases present,
            ≤10 rules per PR) → auto-merged into <code>agent-threat-rules</code> main →
            <code>npm publish</code> fires within minutes → every downstream consumer upgrades on
            next install.
          </li>
          <li>
            Every resulting rule carries{' '}
            <code>author: nvidia-airt (via garak vX.Y.Z)</code> and{' '}
            <code>metadata_provenance.garak_probe: &lt;probe-id&gt;</code>. Attribution is
            permanent and machine-readable.
          </li>
        </ol>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">What counts as a failed probe</h2>
        <p>The script treats a garak attempt as a rule candidate when either:</p>
        <ul className="list-disc pl-6">
          <li>
            At least one garak detector returned a score above 0.5 (the target model fell for the
            probe).
          </li>
          <li>
            The input is an ATR-style eval report and the prompt appears in{' '}
            <code>missed_samples</code> — garak flagged it malicious and ATR had no pattern for it
            yet (highest-signal candidates).
          </li>
        </ul>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">Rate limits &amp; safety</h2>
        <ul className="list-disc pl-6">
          <li>
            Default 100ms delay between POSTs. At 666 findings (the public garak
            in-the-wild-jailbreak set) that is about a minute.
          </li>
          <li>
            <code>patternHash</code> is a sha256 of the prompt, so re-running on the same report is
            idempotent — TC recognises duplicate submissions and just bumps a confirmation
            counter, never creates duplicate rules.
          </li>
          <li>
            All traffic is authenticated with your partner key. Key compromise? Email and we revoke
            and re-issue.
          </li>
          <li>
            Every submitted proposal is reviewable and rejectable via the TC admin dashboard
            before it enters canary.
          </li>
        </ul>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">Related</h2>
        <ul className="list-disc pl-6">
          <li>
            <a className="underline" href="/integrate">/integrate</a> — general adopters (npm +
            PyPI), no partner key needed
          </li>
          <li>
            <a className="underline" href="/partner-sync">/partner-sync</a> — live rule pull for
            platforms that consume ATR downstream
          </li>
          <li>
            <a
              className="underline"
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/scripts/garak-to-tc.py"
            >
              scripts/garak-to-tc.py
            </a>{' '}
            — source, 300 lines, no dependencies beyond Python stdlib
          </li>
        </ul>
      </section>
    </main>
  );
}
