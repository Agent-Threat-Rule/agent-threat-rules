import type { Metadata } from 'next';
import { pageMetadata } from '@/lib/seo';
import { loadSiteStats } from '@/lib/stats';
import {
  GARAK_BOTH_CLOSED_BOOK,
  LANES_EXPLAINED,
  commonStamp,
  count,
  findBenchmark,
  recallLanes,
} from '@/lib/recall';
import { locales, type Locale } from '@/lib/i18n';

export function generateStaticParams() {
  return locales.map((locale) => ({ locale }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ locale: string }>;
}): Promise<Metadata> {
  const { locale } = await params;
  return pageMetadata({
    locale,
    path: "/integrate/garak",
    title: "NVIDIA garak × ATR",
    description:
      "A red-team tool feeds a detection standard. NVIDIA garak finds attacks, and ATR has written detection rules from garak's probe corpus. garak does not ship ATR. garak PR #1676, which proposed ATR detectors for garak, was withdrawn by its ATR author on 2026-08-04 without being merged.",
  });
}

export default async function GarakIntegratePage({
  params,
}: {
  params: Promise<{ locale: string }>;
}) {
  const { locale: raw } = await params;
  const locale = (locales.includes(raw as Locale) ? raw : 'en') as Locale;
  const zh = locale === 'zh';
  const stats = loadSiteStats();
  const garak = findBenchmark(stats, 'garak');
  const full = findBenchmark(stats, 'garak-full');
  const ruleCountStr = `${stats.ruleCount} rules today`.padEnd(25);

  return (
    <main className="mx-auto max-w-3xl px-6 py-16">
      <h1 className="text-3xl font-bold">NVIDIA garak × ATR</h1>
      <p className="mt-2 text-neutral-400">
        {zh
          ? 'garak 是紅隊工具，ATR 是偵測標準。garak 找到攻擊，ATR 把它寫成有版本、MIT 授權的偵測規則。所以 ATR 不必自己再建一套攻擊語料。每個 probe 從哪裡來，都留在 author 欄位上。'
          : "garak is a red-teaming tool. ATR is a detection standard. garak finds the attack, and ATR turns it into a versioned, MIT-licensed detection rule. So ATR doesn't have to build its own attack corpus, and every probe's origin stays on the author line."}
      </p>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">{zh ? '想法' : 'The idea'}</h2>
        <p>
          <a className="underline" href="https://github.com/NVIDIA/garak">
            garak
          </a>{' '}
          {zh ? (
            <>
              在 LLM 這一層找攻擊。ATR 守的是 agent 這一層：tool call、skill、MCP。同一個攻擊
              payload，有兩個地方可以抓。一個標準量它能不能突破模型，另一個量它在真實的 agent
              成品上攔不攔得下來。中間的橋只是一支 Python 腳本：garak 報告進去，ATR 提案出來，
              結晶流程起草規則，再交給維護者審。在這裡寫下的一條規則，下游每個用 ATR 的引擎都收得到。
            </>
          ) : (
            <>
              finds attacks at the LLM layer. ATR defends the agent layer: tool calls, skills,
              MCP. The same attack payload can be caught in two places. One standard measures whether
              it breaks the model. The other measures whether it can be stopped on a real agent artifact.
              The bridge is a single Python script. garak reports go in, ATR proposals come out, the
              crystallisation loop drafts rules, and a maintainer reviews them. A rule written here reaches every engine
              downstream that consumes ATR.
            </>
          )}
        </p>

        <pre className="overflow-x-auto  bg-neutral-900 p-4 text-sm">
{`garak (red team)                    ATR (standard)           downstream consumers
─────────────────                    ──────────────           ────────────────────
Probes claude-3.7                    ${ruleCountStr}npm: agent-threat-rules
Probes gpt-5                 ──▶     +auto-crystallised       PyPI: pyatr
Probes gemini-2-pro                  from garak evidence      your CI pipeline
Writes report.jsonl                  canary 24h
                                     maintainer review

garak PR #1676 (ATR detectors inside garak): withdrawn by its ATR author on
2026-08-04, not merged. garak does not ship ATR.`}
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
                附上你的組織名稱，申請 partner API key。早期夥伴階段是人工發放，不收費，採 MIT 條款。
              </>
            ) : (
              <>
                with your org name to get a partner API key. In the early-partner phase keys
                are issued by hand, at no cost, under MIT terms.
              </>
            )}
          </li>
          <li>
            {zh
              ? '橋接腳本 garak-to-tc.py 在 2026-06-20 移出了公開 repo，目前沒有公開。'
              : 'The bridge script, garak-to-tc.py, was moved out of the public repository on 2026-06-20. It is not published right now.'}
          </li>
          <li>
            {zh ? '把 key 設成環境變數：' : 'Set the key in your environment:'}{' '}
            <code className="bg-neutral-800 px-1 break-all">export ATR_PARTNER_KEY=…</code>
          </li>
        </ol>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">{zh ? '跑起來' : 'Run it'}</h2>

        <p className="text-sm text-neutral-400">
          {zh ? '跑完一次 garak eval 之後：' : 'After a garak eval session:'}
        </p>
        <pre className="overflow-x-auto  bg-neutral-900 p-4 text-sm">
{`# Native garak JSONL report
python3 garak-to-tc.py \\
    --input ~/.local/share/garak/runs/2026-04-18-claude-3-7/report.jsonl \\
    --partner-name  your-org \\
    --target-model  claude-3-7-sonnet \\
    --garak-version 0.14.1

# Or ATR-style eval (from scripts/eval-garak.sh in this repo)
python3 garak-to-tc.py \\
    --input data/garak-benchmark/garak-eval-report.json \\
    --partner-name  your-org \\
    --dry-run   # inspect before submitting`}
        </pre>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">{zh ? '兩種模式' : 'Two modes'}</h2>
        <p>
          {zh ? (
            <>
              腳本有兩種提交模式。用預設的 <code>--mode drafter</code> 就對了。
            </>
          ) : (
            <>
              The script has two submission modes. The default, <code>--mode drafter</code>, is the
              one you want.
            </>
          )}
        </p>
        <ul className="list-disc pl-6">
          <li>
            {zh ? (
              <>
                <strong>drafter</strong>（預設）。把每個失敗的 probe POST 到{' '}
                <code>/api/atr-proposals/from-payload</code>。伺服器端會跑一個能用工具的 LLM drafter。
                它先 grep 既有規則去重，抓研究資料當佐證，再寫出 YAML：至少 3 個 conditions、5 個 TP、
                5 個 TN、3 個 evasion tests。接著過 RFC-001 品質閘，自己測自己的 regex，最後立案成
                proposal。每次呼叫要 30 到 60 秒。真正的 ATR 規則，是這個模式產出來的。
              </>
            ) : (
              <>
                <strong>drafter</strong> (default). POSTs each failed probe to{' '}
                <code>/api/atr-proposals/from-payload</code>. The server runs an LLM drafter with
                tools. It greps existing rules to avoid duplicates, fetches research to ground the rule,
                and writes YAML with at least 3 conditions, 5 TPs, 5 TNs and 3 evasion tests. Then it
                passes the RFC-001 quality gate, tests its own regex, and files the result as a proposal.
                Each call takes 30 to 60 seconds. This is the mode that produces real ATR rules.
              </>
            )}
          </li>
          <li>
            {zh ? (
              <>
                <strong>proposal</strong>（舊模式）。POST 一份在 client 端組好的字面草案。很快，但 LLM
                reviewer 多半會以「太窄」退回，因為字面指紋不等於偵測規則。除非你上游已經有自己產 YAML
                的步驟，否則別用。
              </>
            ) : (
              <>
                <strong>proposal</strong> (legacy). POSTs a literal draft built on the client. It is
                fast, but the LLM reviewer usually rejects these as too narrow. A literal fingerprint
                is not a detection rule. Use it only if you already generate YAML upstream.
              </>
            )}
          </li>
        </ul>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">
          {zh ? '送出之後' : 'What happens downstream'}
        </h2>
        <ol className="list-decimal space-y-1 pl-6">
          <li>
            {zh ? (
              <>
                每個不重複的失敗 probe → <code>/api/atr-proposals</code> 裡的一條 proposal，完整的
                garak 來源一起帶著。
              </>
            ) : (
              <>
                Each unique failed probe → one proposal in <code>/api/atr-proposals</code>, carrying
                its full garak provenance.
              </>
            )}
          </li>
          <li>
            {zh
              ? 'TC 的結晶 LLM 讀攻擊 payload 和 garak metadata，起草一條泛化過的偵測 regex。'
              : "TC's crystallisation LLM reads the attack payload and the garak metadata, and drafts a generalised detection regex."}
          </li>
          <li>
            {zh
              ? '規則先在 Threat Cloud 上跑 24 小時 canary。'
              : 'The rule runs a 24h canary on Threat Cloud.'}
          </li>
          <li>
            {zh ? (
              <>
                撐過 canary → 安全閘（良性 skill 語料上 0 FP、test_cases 要齊、每個 PR 最多 10 條規則；
                語料以 <code>data/skill-benchmark/benign/</code> 為準，閘會遞迴讀裡面所有 .md）→
                以 PR 送進 <code>agent-threat-rules</code> main，維護者審過後手動合併（repo 已關掉 auto-merge）→{' '}
                跟著下一個版本發布（CI 先在 npm 上 stage，維護者用 2FA 核准）→ 下游每個使用者下次安裝時升級。
              </>
            ) : (
              <>
                Passes canary → safety gate (0 FP on the benign skill corpus, test_cases present,
                at most 10 rules per PR; the gate reads every <code>.md</code> file under{' '}
                <code>data/skill-benchmark/benign/</code>, subdirectories included) → opened as a PR against <code>agent-threat-rules</code> main, which a maintainer reviews and merges by hand, since auto-merge is off in the repository →
                ships in the next release, which CI stages on npm and a maintainer approves with 2FA →
                every downstream consumer gets it on its next install.
              </>
            )}
          </li>
          <li>
            {zh ? (
              <>
                每條產出的規則都帶 <code>author: your-org (via garak vX.Y.Z)</code> 與{' '}
                <code>metadata_provenance.garak_probe: &lt;probe-id&gt;</code>。歸屬是永久的，機器也讀得懂。
              </>
            ) : (
              <>
                Every resulting rule carries{' '}
                <code>author: your-org (via garak vX.Y.Z)</code> and{' '}
                <code>metadata_provenance.garak_probe: &lt;probe-id&gt;</code>. The attribution is
                permanent, and machines can read it.
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
            ? '只要符合下面任一條，腳本就把這次 garak attempt 當成規則候選：'
            : 'The script treats a garak attempt as a rule candidate when either of these holds:'}
        </p>
        <ul className="list-disc pl-6">
          <li>
            {zh
              ? '至少一個 garak detector 給出高於 0.5 的分數，也就是目標模型中招了。'
              : 'At least one garak detector scored it above 0.5. The target model fell for the probe.'}
          </li>
          <li>
            {zh ? (
              <>
                輸入是 ATR 格式的 eval report，而且這個 prompt 出現在{' '}
                <code>missed_samples</code>。garak 判定它惡意，ATR 卻還沒有對應的 pattern。
                這種候選的訊號最強。
              </>
            ) : (
              <>
                The input is an ATR-style eval report and the prompt appears in{' '}
                <code>missed_samples</code>. garak flagged it as malicious and ATR had no pattern for
                it yet. These are the strongest candidates.
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
                每次 POST 之間預設隔 100ms，整個跑完大約一分鐘。
                {garak && full && (
                  <>
                    {`兩份語料、兩個 lane 的數字都公開。在 garak 公開的 in-the-wild jailbreak 集（${count(garak.samples)} 筆）上，recall 是 ${recallLanes(garak)}；在完整的 garak 語料（${count(full.samples)} 筆，涵蓋所有 probe 家族）上是 ${recallLanes(full)}（${commonStamp([garak, full], true)}）。`}
                    {LANES_EXPLAINED.zh}
                    {GARAK_BOTH_CLOSED_BOOK.zh}
                    {"兩份語料的落差，有一部分是刻意的。regex 偵測層不去追某些 probe 家族，像純語意的越獄；硬要追，只會換來脆弱的簽章和誤報。另一部分是 in-the-wild 的數字，有不少靠的是從那份語料寫出來的規則。比較低的數字一樣列出來。一個標準敢不敢公開自己最差的數字，決定別人信不信它。"}
                  </>
                )}
              </>
            ) : (
              <>
                POSTs are 100ms apart by default, so a run takes about a minute.{' '}
                {garak && full && (
                  <>
                    Both corpora are published, in both lanes. On the public garak in-the-wild
                    jailbreak set ({count(garak.samples)} samples), recall is {recallLanes(garak)}. On the
                    full garak corpus ({count(full.samples)} samples, every probe family) it is{' '}
                    {recallLanes(full)} ({commonStamp([garak, full], false)}). {LANES_EXPLAINED.en}{' '}
                    {GARAK_BOTH_CLOSED_BOOK.en}{' '}
                    Part of the gap between the two corpora is deliberate. The regex detection layer does
                    not chase some probe families, such as pure semantic jailbreaks. Forcing it to would
                    buy brittle signatures and false positives. The rest comes from the in-the-wild figure
                    resting partly on rules written from that corpus. The lower figures are published too.
                    A standard earns trust by showing its worst numbers, not by hiding them.
                  </>
                )}
              </>
            )}
          </li>
          <li>
            {zh ? (
              <>
                <code>patternHash</code> 是 prompt 的 sha256，所以同一份 report 重跑幾次都一樣。TC
                認得重複提交，只會把確認次數加一，不會建出重複的規則。
              </>
            ) : (
              <>
                <code>patternHash</code> is a sha256 of the prompt, so re-running the same report is
                idempotent. TC recognises a duplicate submission and only bumps a confirmation
                counter. It never creates a duplicate rule.
              </>
            )}
          </li>
          <li>
            {zh
              ? '所有流量都用你的 partner key 認證。key 外洩的話，寄信過來，舊的會撤銷，再重發一把。'
              : 'All traffic is authenticated with your partner key. If the key leaks, send an email. It gets revoked and a new one is issued.'}
          </li>
          <li>
            {zh
              ? '每個提交的 proposal 進 canary 之前，都能在 TC admin dashboard 上審查、退回。'
              : 'Before a submitted proposal enters canary, it can be reviewed and rejected in the TC admin dashboard.'}
          </li>
        </ul>
      </section>

      <section className="mt-10 space-y-3">
        <h2 className="text-xl font-semibold">{zh ? '相關頁面' : 'Related'}</h2>
        <ul className="list-disc pl-6">
          <li>
            <a className="underline" href={`/${locale}/integrate`}>
              /integrate
            </a>{' '}
            {zh
              ? '給一般採用者（npm、PyPI），不需要 partner key'
              : 'for general adopters (npm, PyPI). No partner key needed.'}
          </li>
          <li>
            <a className="underline" href={`/${locale}/partner-sync`}>
              /partner-sync
            </a>{' '}
            {zh
              ? '給下游用 ATR 的平台，即時拉取規則'
              : 'for platforms downstream that pull ATR rules live'}
          </li>
          <li>
            <a
              className="underline"
              href="https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/scripts/garak-miss-to-proposals.ts"
            >
              scripts/garak-miss-to-proposals.ts
            </a>{' '}
            {zh
              ? '公開 repo 裡的管線，把 ATR 在 garak benchmark 上漏掉的 prompt 轉成規則提案'
              : 'is the pipeline in the public repository that turns prompts ATR misses on the garak benchmark into rule proposals'}
          </li>
        </ul>
      </section>
    </main>
  );
}
