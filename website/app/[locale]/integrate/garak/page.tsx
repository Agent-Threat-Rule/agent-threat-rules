import type { Metadata } from 'next';
import { loadSiteStats } from '@/lib/stats';
import { locales, type Locale } from '@/lib/i18n';

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export const metadata: Metadata = {
  title: 'NVIDIA garak × ATR — ATR',
  description:
    'A red-team standard feeds a detection standard. NVIDIA garak finds the attack; ATR turns it into a versioned, MIT-licensed detection rule. Two standards interoperate instead of duplicating each other (integration PR #1676, open).',
};

export default async function GarakIntegratePage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : 'en') as Locale;
  const zh = locale === 'zh';
  const stats = loadSiteStats();
  const ruleCountStr = `${stats.ruleCount} rules today`.padEnd(25);

  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="text-3xl font-bold">NVIDIA garak × ATR</h1>
      <p className="mt-2 text-neutral-400">
        {zh
          ? 'garak 是紅隊的標準,ATR 是偵測的標準。一個找到攻擊,另一個把它變成一條版本化、MIT 授權的偵測規則。標準之間互餵,不重造彼此——每個 probe 的來源都留在 author 欄位。'
          : "garak is a standard for red teaming; ATR is a standard for detection. One finds the attack, the other turns it into a versioned, MIT-licensed detection rule. Standards feed each other instead of reinventing each other — every probe's provenance stays on the author line."}
      </p>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">{zh ? '概念' : 'The idea'}</h2>
        <p>
          <a className="underline" href="https://github.com/NVIDIA/garak">
            garak
          </a>{' '}
          {zh ? (
            <>
              在 LLM 層找攻擊。ATR 在 agent 層防禦(tool calls、skills、MCP)。同一個攻擊
              payload,兩個不同的偵測面——一個標準量它能不能突破模型,另一個標準量它能不能
              在真實 agent 成品上被攔下來。橋接只是一支 Python 腳本:garak 報告進來,ATR 提案
              出去,結晶 loop 處理其餘的事。一條在這裡寫下的規則,下游每個消費 ATR 的引擎都收得到。
            </>
          ) : (
            <>
              finds attacks at the LLM layer. ATR defends at the agent layer (tool calls, skills,
              MCP). One attack payload, two detection surfaces — one standard measures whether it
              breaks the model, the other measures whether it can be caught on a real agent artifact.
              The bridge is just a Python script: garak reports in, ATR proposals out, the
              crystallisation loop does the rest. A rule written here reaches every engine that
              consumes ATR downstream.
            </>
          )}
        </p>

        <pre className="overflow-x-auto rounded bg-neutral-900 p-4 text-sm">
{`garak (red team)                    ATR (standard)           downstream consumers
─────────────────                    ──────────────           ────────────────────
Probes claude-3.7                    ${ruleCountStr}npm: agent-threat-rules
Probes gpt-5                 ──▶     +auto-crystallised       PyPI: pyatr
Probes gemini-2-pro                  from garak evidence      your CI pipeline
Writes report.jsonl                  canary 24h
                                     auto-merge

garak PR status: integration PR #1676 OPEN (under maintainer review, not merged)`}
        </pre>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">{zh ? '一次性設定' : 'One-time setup'}</h2>
        <ol className="list-decimal space-y-2 pl-6">
          <li>
            {zh ? '寄信到 ' : 'Email '}
            <a className="underline" href="mailto:adam@agentthreatrule.org">
              adam@agentthreatrule.org
            </a>{' '}
            {zh ? (
              <>
                附上你的組織名稱以取得 partner API key(早期夥伴階段手動發放,無費用,MIT 條款)。
              </>
            ) : (
              <>
                with your org name to receive a partner API key (manual issuance during
                early-partner phase, no cost, MIT terms).
              </>
            )}
          </li>
          <li>
            {zh ? '抓 pipe 腳本:它在 ATR repo 裡。' : 'Fetch the pipe script: it lives in the ATR repo.'}{' '}
            <code className="rounded bg-neutral-800 px-1 break-all">
              curl -O https://raw.githubusercontent.com/Agent-Threat-Rule/agent-threat-rules/main/scripts/garak-to-tc.py
            </code>
          </li>
          <li>
            {zh ? '在環境變數設定 key:' : 'Set the key in your environment:'}{' '}
            <code className="rounded bg-neutral-800 px-1 break-all">export ATR_PARTNER_KEY=…</code>
          </li>
        </ol>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">{zh ? '執行' : 'Run it'}</h2>

        <p className="text-sm text-neutral-400">
          {zh ? '跑完一次 garak eval session 後:' : 'After a garak eval session:'}
        </p>
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
        <h2 className="text-xl font-semibold">{zh ? '兩種模式' : 'Two modes'}</h2>
        <p>
          {zh ? (
            <>
              腳本有兩種提交模式。預設(<code>--mode drafter</code>)就是你要的。
            </>
          ) : (
            <>
              The script has two submission modes. The default (<code>--mode drafter</code>) is what
              you want.
            </>
          )}
        </p>
        <ul className="list-disc pl-6">
          <li>
            {zh ? (
              <>
                <strong>drafter</strong>(預設)。把每個失敗的 probe POST 到{' '}
                <code>/api/atr-proposals/from-payload</code>。Server 端跑 tool-use LLM drafter
                (grep 既有規則做去重、抓 research 做佐證、寫含 3+ conditions / 5+ TP / 5+ TN / 3+
                evasion tests 的 YAML),通過 RFC-001 品質閘門,自測自己的 regex,然後立案成
                proposal。每次呼叫 30-60s。這個模式產出真正的 ATR 規則。
              </>
            ) : (
              <>
                <strong>drafter</strong> (default). POSTs each failed probe to{' '}
                <code>/api/atr-proposals/from-payload</code>. Server-side runs a tool-use LLM drafter
                (grep existing rules for dedup, fetch research for grounding, write YAML with 3+
                conditions / 5+ TP / 5+ TN / 3+ evasion tests), passes RFC-001 quality gate,
                self-tests its own regex, then files as a proposal. Each call takes 30-60s. This is
                the mode that produces real ATR rules.
              </>
            )}
          </li>
          <li>
            {zh ? (
              <>
                <strong>proposal</strong>(legacy)。POST client 端建好的字面草案。快,但 LLM reviewer
                通常會以「太窄」(字面指紋 ≠ 偵測規則)退回。只有你上游自己有 YAML 產生步驟才用。
              </>
            ) : (
              <>
                <strong>proposal</strong> (legacy). POSTs a client-built literal draft. Fast but the
                LLM reviewer typically rejects these as too narrow (literal fingerprint ≠ detection
                rule). Only use if you have your own YAML-generation step upstream.
              </>
            )}
          </li>
        </ul>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">
          {zh ? '下游會發生什麼' : 'What happens downstream'}
        </h2>
        <ol className="list-decimal space-y-1 pl-6">
          <li>
            {zh ? (
              <>
                每個唯一的失敗 probe → <code>/api/atr-proposals</code> 下一條 proposal,內嵌完整 garak
                來源。
              </>
            ) : (
              <>
                Each unique failed probe → one proposal in <code>/api/atr-proposals</code> with full
                garak provenance embedded.
              </>
            )}
          </li>
          <li>
            {zh
              ? 'TC 結晶 LLM 讀攻擊 payload + garak metadata,起草一條一般化的偵測 regex。'
              : 'TC crystallisation LLM reads the attack payload + garak metadata and drafts a generalised detection regex.'}
          </li>
          <li>
            {zh
              ? '規則進入 24h canary。每個在野的 ATR 整合 client 收到取樣劑量(~10%)。若任何 client 回報誤判,規則自動隔離。'
              : 'Rule enters 24h canary. Every ATR-integrated client in the field gets a sampling dose (~10%). If any client reports false positives, the rule is quarantined automatically.'}
          </li>
          <li>
            {zh ? (
              <>
                通過 canary → 安全閘門(432 樣本良性語料 0 FP、test_cases 齊備、每個 PR ≤10 條規則)→
                自動 merge 進 <code>agent-threat-rules</code> main →{' '}
                <code>npm publish</code> 數分鐘內觸發 → 每個下游消費者在下次安裝時升級。
              </>
            ) : (
              <>
                Survives canary → safety gate (0 FP on 432-sample benign corpus, test_cases present,
                ≤10 rules per PR) → auto-merged into <code>agent-threat-rules</code> main →
                <code>npm publish</code> fires within minutes → every downstream consumer upgrades on
                next install.
              </>
            )}
          </li>
          <li>
            {zh ? (
              <>
                每條產出的規則都帶 <code>author: nvidia-airt (via garak vX.Y.Z)</code> 與{' '}
                <code>metadata_provenance.garak_probe: &lt;probe-id&gt;</code>。歸屬永久且機器可讀。
              </>
            ) : (
              <>
                Every resulting rule carries{' '}
                <code>author: nvidia-airt (via garak vX.Y.Z)</code> and{' '}
                <code>metadata_provenance.garak_probe: &lt;probe-id&gt;</code>. Attribution is
                permanent and machine-readable.
              </>
            )}
          </li>
        </ol>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">
          {zh ? '什麼算失敗的 probe' : 'What counts as a failed probe'}
        </h2>
        <p>
          {zh
            ? '腳本在以下任一情況把一個 garak attempt 當成規則候選:'
            : 'The script treats a garak attempt as a rule candidate when either:'}
        </p>
        <ul className="list-disc pl-6">
          <li>
            {zh
              ? '至少一個 garak detector 回傳分數高於 0.5(目標模型中招)。'
              : 'At least one garak detector returned a score above 0.5 (the target model fell for the probe).'}
          </li>
          <li>
            {zh ? (
              <>
                輸入是 ATR 風格的 eval report,且該 prompt 出現在{' '}
                <code>missed_samples</code> — garak 標記它為惡意,而 ATR 尚無對應 pattern
                (最高訊號的候選)。
              </>
            ) : (
              <>
                The input is an ATR-style eval report and the prompt appears in{' '}
                <code>missed_samples</code> — garak flagged it malicious and ATR had no pattern for
                it yet (highest-signal candidates).
              </>
            )}
          </li>
        </ul>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">{zh ? '速率限制與安全' : 'Rate limits & safety'}</h2>
        <ul className="list-disc pl-6">
          <li>
            {zh ? (
              <>
                每次 POST 之間預設 100ms 延遲,跑完約一分鐘。兩個數字都公開:在 garak 公開
                in-the-wild jailbreak 集(650 筆)上,recall 是 98.0%;在完整 garak 語料
                (3,475 筆,涵蓋全部 probe 家族)上,recall 是 38.5%。落差是刻意的——regex
                偵測層不去打某些 probe 家族(例如純語意越獄),硬塞只會換來脆弱簽章與誤報。
                列出較低的那個數字,是因為一個標準的可信度,取決於它願不願意公開自己最差的數字。
              </>
            ) : (
              <>
                Default 100ms delay between POSTs; a run takes about a minute. Both figures are
                published. On the public garak in-the-wild jailbreak set (650 samples) recall is
                98.0%; on the full garak corpus (3,475 samples, every probe family) recall is 38.5%.
                The gap is deliberate — the regex detection layer does not chase some probe families
                (pure semantic jailbreaks, for instance); forcing it to would buy brittle signatures
                and false positives. We report the lower number because a standard earns trust by
                publishing its worst figure, not hiding it.
              </>
            )}
          </li>
          <li>
            {zh ? (
              <>
                <code>patternHash</code> 是 prompt 的 sha256,所以對同一份 report 重跑是冪等的 — TC
                辨識重複提交,只 bump 一個確認計數,絕不建立重複規則。
              </>
            ) : (
              <>
                <code>patternHash</code> is a sha256 of the prompt, so re-running on the same report
                is idempotent — TC recognises duplicate submissions and just bumps a confirmation
                counter, never creates duplicate rules.
              </>
            )}
          </li>
          <li>
            {zh
              ? '所有流量都用你的 partner key 認證。Key 外洩?寄信,我們撤銷並重發。'
              : 'All traffic is authenticated with your partner key. Key compromise? Email and we revoke and re-issue.'}
          </li>
          <li>
            {zh
              ? '每個提交的 proposal 在進入 canary 前,都可透過 TC admin dashboard 審查與退回。'
              : 'Every submitted proposal is reviewable and rejectable via the TC admin dashboard before it enters canary.'}
          </li>
        </ul>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">{zh ? '相關' : 'Related'}</h2>
        <ul className="list-disc pl-6">
          <li>
            <a className="underline" href={`/${locale}/integrate`}>
              /integrate
            </a>{' '}
            {zh
              ? '— 一般採用者(npm + PyPI),不需 partner key'
              : '— general adopters (npm + PyPI), no partner key needed'}
          </li>
          <li>
            <a className="underline" href={`/${locale}/partner-sync`}>
              /partner-sync
            </a>{' '}
            {zh
              ? '— 給下游消費 ATR 的平台用的即時規則拉取'
              : '— live rule pull for platforms that consume ATR downstream'}
          </li>
          <li>
            <a
              className="underline"
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/scripts/garak-to-tc.py"
            >
              scripts/garak-to-tc.py
            </a>{' '}
            {zh
              ? '— 原始碼,300 行,除 Python stdlib 外無依賴'
              : '— source, 300 lines, no dependencies beyond Python stdlib'}
          </li>
        </ul>
      </section>
    </main>
  );
}
