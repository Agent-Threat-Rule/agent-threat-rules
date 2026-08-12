# Verdict × Maturity 稽核:`critical` 無條件 deny,是設計還是 bug?

調查日期:2026-08-12 · 基準:`origin/main` @ `161782bca` · 本文只做調查,不改任何 code。

---

## 0. 結論先講

**選 (C):規範沒說。** 而且是「連 outcome 這個概念都沒進過任何規範文件」等級的沒說。

- 不是 **(A)**:找不到任何一句原文說「severity 決定 response、maturity 決定 lane、兩者正交」。這個矩陣只寫在 `src/verdict.ts:51-59` 自己的 docstring 裡,以及一份**描述它是缺陷**的文件(`docs/RESPONSE-ACTION-ELIGIBILITY.md`)。全庫 `.md` 搜 `allow/ask/deny` / `permissionDecision` / `determineOutcome` / `VerdictOutcome`,除了那份缺陷文件與第三方 skill 語料,零命中。
- 不是 **(B)**:也找不到任何一句規範級(RFC 2119 MUST/MUST NOT)的「未成熟的規則不得阻擋」。最接近的三句都是 SHOULD / 部署指引語氣,而且對象是 **operator**,不是 engine。

但 (C) **不等於沒事**。出貨預設值(lane 未設 → `hunt`)加上 verdict 矩陣(critical → deny),合起來與專案自己公開的三處敘述互相牴觸:

| 專案自己怎麼寫 | 出貨實際行為 |
|---|---|
| `README.md:212-214` lane 表:`enforce` = **Auto-block**;`hunt` = **Advisory / eval (default)** | 預設 `hunt`,`atr guard` 對 benign 輸入回 `permissionDecision: deny` |
| `docs/QUALITY-STANDARD.md:228`「Enterprise blocking: Only use rules with `maturity: stable` and `confidence >= 80`」 | 228 條非 stable 的 critical 規則在預設路徑上一律 deny |
| `spec/atr-method-v1.1.md:164`「Engines SHOULD NOT auto-block ... without operator policy explicitly enabling it」 | 沒有任何 operator policy 入口(CLI 無 `--lane`,無 `ATR_MIN_MATURITY`),預設就 auto-block |

所以問題的正確形狀是:**這是一個從未被規範、且與專案自述互相矛盾的預設值,需要的是一個決策(並把決策寫進規範),不是把 `verdict.ts` 當 bug 修掉就結案。**

### 一個必須先更正的前提

「verdict 路徑不看 lane」這句話**字面為真、推論會錯**。

`verdict.ts` 確實沒讀 `config.lane`,但 lane gate 在 `src/engine.ts:383`(`evaluateRaw` 內)就已經濾掉不合格 maturity 的規則,而 `computeVerdict(matches)`(`engine.ts:1664`)吃的是**濾過之後**的 match 陣列。實測 `lane: 'enforce'` 時同一個 payload 命中 0 條、outcome = `allow`(見 §1)。

**lane 沒有被繞過。真正成立的事實是:出貨程式碼裡沒有任何一個呼叫者把 lane 設成 `hunt` 以外,而且使用者也沒有任何入口可以設。** 這兩件事的修法完全不同,不能混談。

---

## 1. 重現(我親自跑的,含 CONTROL)

harness 紀律:`new ATREngine(...)` 的 constructor 不編譯 pattern,漏了 `await engine.loadRules()` 會對任何輸入回 0 match、看起來像乾淨。所以先跑 CONTROL:拿一個**文件已記載會命中**的 payload 掃,掃不到就 abort。

CONTROL payload 取自 `docs/RESPONSE-ACTION-ELIGIBILITY.md:60-71` 的公開重現案例:`google-chrome --no-sandbox &`(合法的 headless Chrome 旗標,是已確認的 false positive)。

走的是**生產路徑**:`HookHandler.handlePreToolUse` — `atr init` 裝進 Claude Code PreToolUse hook 的那條。

```
$ npx tsx <probe>.ts   # 全文見附錄 A
[CONTROL] {"lane":"(unset -> default)","loaded":784,"decision":"deny",
          "reason":"DENY: Hidden Capability in MCP Skill [critical/93% confidence] (3 rules matched)",
          "matched":["ATR-2026-00062","ATR-2026-00040","ATR-2026-00099"]}
[lane=hunt]    matched=["ATR-2026-00062","ATR-2026-00040","ATR-2026-00099"]
[lane=alert]   matched=["ATR-2026-00062","ATR-2026-00040","ATR-2026-00099"]
[lane=enforce] matched=[]                          <-- lane gate 有效
[default lane] outcome=deny
   matched ATR-2026-00062 severity=critical maturity=test status=experimental conf=0.93
   matched ATR-2026-00040 severity=critical maturity=test status=experimental conf=0.92
   matched ATR-2026-00099 severity=low      maturity=test status=experimental conf=0.71
EXIT=0
```

`decision` 經 `toClaudeCodePreToolUse`(`src/hook-handler.ts:94-104`)1:1 映射成 `hookSpecificOutput.permissionDecision`。

再用合成規則直接探 `computeVerdict`,把 maturity 與 confidence 都掃過一遍:

```
[computeVerdict] severity=critical maturity=draft        confidence=0.1/0.5/0.9 -> deny / deny / deny
[computeVerdict] severity=critical maturity=experimental confidence=0.1/0.5/0.9 -> deny / deny / deny
[computeVerdict] severity=critical maturity=test         confidence=0.1/0.5/0.9 -> deny / deny / deny
[computeVerdict] severity=critical maturity=stable       confidence=0.1/0.5/0.9 -> deny / deny / deny
```

**一旦 critical 規則進了 match 陣列,maturity 與 confidence 都不再是輸入。** 對應原始碼:

```ts
// src/verdict.ts:61-75
function determineOutcome(severity: ATRSeverity, confidence: number): VerdictOutcome {
  if (severity === 'critical') {
    return 'deny';
  }
  ...
}
```

### 語料現況(獨立重數,不是引用記憶)

```
$ python3 count.py   # 附錄 B;規則檔直讀 YAML,不經 engine
rule files on disk        : 784
live (engine can fire)    : 777      # 扣掉 status draft/deprecated 與 maturity deprecated
```

| severity | stable | test | experimental | draft | 合計 |
|---|---:|---:|---:|---:|---:|
| critical | 43 | 206 | 15 | 7 | **271** |
| high | 51 | 321 | 43 | 6 | 421 |
| medium | 12 | 64 | 6 | 0 | 82 |
| low | 0 | 3 | 0 | 0 | 3 |

**critical 且非 `maturity: stable` = 228 條。** 這 228 條在預設 `hunt` 下命中即 deny,在 `enforce` lane 則一條都不會開火。

critical 規則的 `tags.confidence` 分佈:`high` 249 / `medium` 22 — 這個欄位才是 verdict 用的 confidence 來源(見 §6.1)。

---

## 2. 規範怎麼說 —— 逐條引文

### 2.1 核心 SPEC:完全沒提 verdict

`SPEC.md` 有 §3 Conventions(RFC 2119)、§6 Detection Semantics、§7 Match Output、§11 Conformance。**沒有任何一節定義 allow/ask/deny。** §7 規定 engine MUST 吐出的最小 Match 欄位是 `rule_id / corpus_version / input_identifier / matched_at / severity / category / matched_conditions` — **沒有 outcome / decision / verdict**。

conformance 測試套件(`conformance/v1.0/`)的 fixture 也只驗 TP/FP 是否命中,不驗任何 outcome。**所以 verdict 矩陣不是標準的一部分,它是參考實作的私有決定。**

`SPEC.md` 唯一沾邊的是 §5.5:

> `SPEC.md:177-179`
> Engines MUST NOT execute response actions automatically without an explicit configuration directive from the operator. The `response` field is a recommendation expressed by the Rule author, not a directive to the Engine.

這句管的是 `response.actions` 的**執行**,不是 hook 的 block 決定 —— 這點 `docs/RESPONSE-ACTION-ELIGIBILITY.md:360-364` 自己也標成「未解的解釋爭議」。要說 `permissionDecision: deny` 等同 Appendix A 的 `block_request`、因此落入這條 MUST NOT,是**一個解釋**,不是原文明說。我把它記為爭議,不當作結論。

### 2.2 Method spec:唯一一句「沒有 operator policy 就不該 auto-block」

> `spec/atr-method-v1.1.md:164`
> Engines MUST preserve the `provenance` field in Match output (per SPEC §7) ... Engines **SHOULD NOT auto-block** on a hash match **without operator policy explicitly enabling it**; the default response action SHOULD be `log_alert` until provenance is operator-trusted.

範圍限於 Signature method,不是通則。但它確立了專案的立場:**auto-block 要有 operator policy**。目前的預設路徑沒有這個 policy,也沒有地方可以表達它。

### 2.3 Quality standard:三句直指「未成熟不該 block」,但語氣是部署指引

`docs/QUALITY-STANDARD.md` 自稱是「authoritative source for "can I trust this rule in production?"」(L5)。

> `L43` (EXPERIMENTAL) CI-validated rules with benchmark coverage. **Safe for evaluation and non-blocking alerting.**
> `L70` (STABLE) Production-ready rules validated on real-world data. **Safe for blocking actions in enterprise deployments.**
> `L112` (confidence 60-79) **Alert-only, do not block**
> `L228` **Enterprise blocking**: Only use rules with `maturity: stable` and `confidence >= 80`
> `L232-239` Filter rules by maturity **in your scanner configuration**: `min_maturity: stable`

三點要誠實標出來:

1. 這是寫給 **consumer / operator** 的指引(標題就是「For Consumers」),不是寫給 engine 的 MUST。它假設「過濾是你自己在 scanner config 做的事」。
2. `L232-239` 示範的 `min_maturity` / `min_confidence` 設定,**在本 repo 的參考引擎裡不存在**(見 §4)。標準給的逃生門,出貨產品沒開。
3. 這份文件的 maturity 階梯只有 DRAFT / EXPERIMENTAL / STABLE / DEPRECATED —— **`test` 這一級根本不在裡面**,而 271 條 critical 有 206 條是 `test`。schema(`SPEC.md:115`)與 `rule-contract.ts:20` 都有 `test`,quality standard 沒跟上。206 條落在標準沒定義的格子裡。

### 2.4 Rule-writing guide:severity 是「衝擊」,不是「動作」

> `docs/rule-writing-guide.md:50-56` Severity Calibration
> `critical` | Immediate data loss, credential exposure, or system compromise
> `high` | Significant security boundary violation
> ...

severity 定義的是**攻擊若為真的衝擊**;maturity 定義的是**規則本身有多可信**。兩者在欄位定義層面確實是不同維度 —— 但**沒有任何文件把這個維度差異接到 response 上**,反而同一份 guide 在 L589 把「動作強度」綁到 `confidence` 而非 severity:

> `docs/rule-writing-guide.md:589`
> **Fix**: Use `alert` and `snapshot` for low-confidence pattern rules. Reserve blocking actions for `confidence: high` rules.

也就是說,專案在文件層面對「什麼可以 block」給過**兩套不同答案**(maturity=stable / confidence=high),而引擎兩套都沒實作,實作的是第三套(severity=critical)。

### 2.5 README:把預設 lane 明寫成「Advisory / eval」

> `README.md:212-214`
> | `enforce` | `stable` rules behind an embedding `confirm` guard | **Auto-block** | ~0.24% |
> | `alert` | `stable` + `test` | Analyst / correlation | — |
> | `hunt` | all rules except `deprecated` | **Advisory / eval (default)** | ~9% |
>
> `README.md:216` Lanes are opt-in and fully backward-compatible: the default is `hunt`, so existing integrations behave exactly as before.

這是最直接可引用的矛盾:**公開文件把預設設定描述成 advisory,實測預設設定會回 deny。**(~9% FP 這個數字是專案公布的 lane-keyed 值,我沒有重跑 65K gate,不在此背書。)

---

## 3. git 歷史:時間線說明了為什麼沒人接起來

| 時間 | commit | 事件 |
|---|---|---|
| 2026-03-11 | `37d8aafd5` v0.2.1 | **`src/verdict.ts` 誕生**(163 行,一次到位)。同 commit 一起進來的還有 `hook-handler.ts` / `action-executor.ts` / adapters。 |
| 2026-06-16 | `bf5e62c69` v3.5.0 | **lane + `rule-contract.ts` 誕生**。`verdict.ts` 一行未動。 |

`git log --follow -- src/verdict.ts` 只有一個 commit;`git log -S"determineOutcome" --all` 也只有那一個。**`determineOutcome` 從寫下那天到今天,一個字沒改過。**

那個 commit 的 message 是 `fix: second review — 2 high + 5 medium + 1 low fixes, bump v0.2.1`,列的八個修正項**沒有一項提到 verdict / severity / 阻擋策略**。verdict.ts 是夾在一次泛用 review 裡順手寫進來的基礎建設,沒有留下設計討論。

lane 那個 commit 反而有明確的設計陳述:

> `bf5e62c69` commit message
> Lanes (enforce/alert/hunt): maturity-driven precision/recall trade. **Default hunt, opt-in, backward-compatible.** enforce ~0.24% FP / hunt ~9% on a 65K benign gate.

**「opt-in、backward-compatible」= 刻意不動既有行為。** 所以這不是「lane 想管 verdict 但漏接了」,而是 lane 從設計那天起,範圍就只有「哪些規則能開火」,從未主張要管「開火之後怎麼處置」。

**PR 討論:查無。** `gh search issues --repo Agent-Threat-Rule/agent-threat-rules "verdict"` → `[]`;搜 `"deny"` → `[]`。唯一討論過這件事的地方是 PR #446 的 body(2026-08 行動資格政策),而且是**主動聲明 scope out**:

> PR #446 body
> **Removing actions does not stop the hook denying.** `src/hook-handler.ts` never reads `response.actions`; `permissionDecision` is derived from severity and confidence. `ATR-2026-00062` will still deny `google-chrome --no-sandbox` after this PR. That path has no precision input at all and is listed as follow-up work — fixing it changes what the engine blocks and needs its own recall A/B, which would contaminate this PR's zero-cost argument.

同樣的話寫進了已 merge 的文件:

> `docs/RESPONSE-ACTION-ELIGIBILITY.md:145-149`
> **`permissionDecision` is unchanged.** `computeVerdict()` derives allow/ask/deny from `severity` and `confidence` alone; `response.actions` is not an input. Stripping every action off a `severity: critical` rule still leaves the hook returning `deny`.
>
> `docs/RESPONSE-ACTION-ELIGIBILITY.md:365-367`
> The verdict path (`severity` + `confidence` → `permissionDecision`) has **no precision input at all**. That is a second, larger line: it _would_ change what the engine blocks, so it needs its own recall analysis and is out of scope here.

**結論:這個行為是已知的、已寫進 repo 文件的、被刻意延後的未決事項。既不是無人發現的 bug,也不是有人拍板過的設計。**

---

## 4. lane 到底在保護什麼?誰真的會設它?

### 4.1 lane 保護的是「開火」,而開火會連帶三件事

lane gate 在 `engine.ts:383`,位置在 match 產生之前,所以它同時決定:

1. Match 輸出 / 告警 / SIEM 噪音;
2. `ActionExecutor` 會派送哪些 `response.actions`(executor 本身不看 lane/maturity — `docs/RESPONSE-ACTION-ELIGIBILITY.md:9-12`);
3. `computeVerdict` 的輸入陣列 —— **所以 lane 間接決定 verdict**(§1 實測 `enforce` → `allow`)。

`rule-contract.ts:52-66` 的註解把 `enforce` 定義成 the auto-block lane:

```ts
// src/quality/rule-contract.ts:52-58
 *   enforce -> stable only        (lowest FP; the auto-block lane)
 *   alert   -> stable + test      (analyst / correlation lane)
 *   hunt    -> all (except deprecated)   (advisory / eval; default)
```

`engine.ts:214-220` 的 config 註解也同樣寫 `'enforce' : only maturity=stable rules (auto-block lane, lowest FP)`。

**問題不在 lane 的語意,在於沒有人選它。**

### 4.2 全庫盤點:實際會設 lane 的呼叫者

| 位置 | 有設 lane? | 性質 |
|---|---|---|
| `src/cli.ts:660` `cmdGuard`(`atr guard` — `atr init` 裝進 hook 的那個) | ❌ `new ATREngine({ rulesDir })` | 出貨 |
| `src/cli/scan-handler.ts:163,259`(`atr scan`) | ❌ | 出貨 |
| `src/mcp-server.ts:207`(MCP server) | ❌ | 出貨 |
| `src/cli/tc-pipeline.ts:218` | ❌ | 出貨 |
| `src/adapters/mastra.ts:64` | ❌ | 出貨 adapter |
| `src/adapters/openshell-filter.ts:142` | ❌ | 出貨 adapter |
| `src/adapters/nemoclaw-preflight.ts:206` | ❌ | 出貨 adapter |
| `src/eval/skill-benchmark.ts:124`、`src/eval/eval-harness.ts:300` | ❌ | 評測 |
| `scripts/eval-std-corpora.ts:432` | ✅ `--lane` 旗標 | 量測腳本 |
| `scripts/detection-boundary/gap-lanes.ts:36` | ✅ | 分析腳本 |
| `tests/lane-confirm.test.ts` | ✅ | 測試 |

**出貨程式碼 0 處設 lane。設 lane 的全部是量測腳本與測試。**

再往使用者端查:`action.yml`、`src/mcp-server.ts`、`src/mcp-tools/*.ts`、`INTEGRATION.md`、`docs/quick-start.md`、`docs/deployment-guide.md` 搜 `lane` → **零命中**。CLI 沒有 `--lane`,沒有 `ATR_LANE` 環境變數,`ATREngineConfig`(`engine.ts:192-229`)也沒有 `minMaturity` 欄位。

> **所以:今天一個 operator 想跑 enforce lane,唯一的辦法是自己寫 TypeScript 直接 `new ATREngine({ lane: 'enforce' })`。CLI / GitHub Action / MCP server 一律做不到。**
>
> 這正好把 `QUALITY-STANDARD.md:232-239`(「在你的 scanner config 裡設 `min_maturity: stable`」)變成一句無法執行的指引,也讓 `atr-method-v1.1.md:164` 的 "operator policy" 無處可表達。

順帶一提,`engines/*/INTERFACE-CONTRACT.md`(給第三方引擎的介面契約)**確實**定義了 `ATR_MIN_SEVERITY`(預設 `informational`)與 `ATR_MIN_MATURITY`(預設 `draft`)兩個載入期過濾器 —— 見 `engines/go/INTERFACE-CONTRACT.md:193-194`、`engines/python/INTERFACE-CONTRACT.md:253-254`、`engines/typescript/INTERFACE-CONTRACT.md:387-388`。**本 repo 的參考 TS 引擎沒有實作這兩個變數**(全 `src/` grep `ATR_MIN_MATURITY` 零命中),而且兩者的預設值都是「全放行」。

---

## 5. 下游怎麼用 —— 各做各的,而且全部只看 severity

這決定了矩陣的影響範圍,結論跟直覺不同。

| 消費端 | 決策依據 | 預設門檻 | 看 maturity? |
|---|---|---|---|
| `src/verdict.ts`(hook / guard 路徑) | severity + tag-confidence | critical→deny, high≥0.8→deny | ❌ |
| `src/adapters/mastra.ts:29` | `DEFAULT_BLOCK_SEVERITIES` | `["critical","high"]` | ❌ |
| `src/adapters/openshell-filter.ts:61,193` | `ATR_MIN_SEVERITY` | `high` | ❌ |
| `src/adapters/nemoclaw-preflight.ts:59,301` | `ATR_MIN_SEVERITY` | `high` | ❌ |
| `integrations/langchain/langchain_atr_guardrail.py:78` | `block_severity` | `critical` | ❌ |
| `integrations/pydantic-ai/pydantic_ai_atr.py:86` | `block_severity` | `critical` | ❌ |
| `integrations/rampart`(README:11) | 載入期 `min_severity` | `high` | ❌ |
| `integrations/goose`(pyatr) | pyatr 只跳過 `status` draft/deprecated(`python/pyatr/engine.py:211`) | — | ❌ pyatr 全無 maturity 概念 |

兩個推論,都跟「改 verdict.ts 就解決了」相反:

1. **`verdict.ts` 的矩陣影響範圍只有 hook / `atr guard` 這一條**。改它不會動到上面任何一個 adapter 或下游整合。
2. **但「critical = 該擋」這個慣例已經被下游各自獨立重新實作了七次。** 真正的跨實作介面是 **rule 檔上的 `severity` 標籤本身**,不是 `verdict.ts`。這跟 `docs/RESPONSE-ACTION-ELIGIBILITY.md:88-91` 對 `response.actions` 的論點是同一個結構:「rule 檔就是介面,而這個介面正在做未經證實的宣告」。
3. 沒有任何一個消費端看 maturity。所以如果決策是「未成熟不得阻擋」,那就**不是改一個函式**,而是要進 SPEC + 更新全部 adapter + 通知下游 —— 這是標準層級的變更。

---

## 6. 其他在調查中撞到的東西(都影響決策,但不是本題)

### 6.1 verdict 用的 `confidence` 不是 QUALITY-STANDARD 說的那個 confidence

`QUALITY-STANDARD.md:102-132` 定義的 confidence 是 **0-100 的數值分數**,由 precision 0.4 + coverage 0.2 + wild validation 0.3 + evasion docs 0.1 算出來,也是 `L228`「blocking 需 confidence ≥ 80」講的那一個。schema 也有這個欄位(`types.ts:327-328`)。

**引擎從來沒讀過它。** 全 `src/engine.ts` 找不到 `rule.confidence`。match 的 confidence 來自:

```ts
// src/engine.ts:653 / 818 / 971(三處相同)
const baseConfidence = rule.tags.confidence === 'high' ? 0.9 : rule.tags.confidence === 'medium' ? 0.7 : 0.5;
const confidence = Math.min(baseConfidence + matchRatio * 0.1, 1.0);
```

也就是**作者自填的 `tags.confidence` 三檔枚舉**,跟 wild 量測無關。271 條 critical 裡 249 條標 `high` → 命中即 ≥0.9。

後果:就算有人想照 `QUALITY-STANDARD.md:228` 實作「confidence ≥ 80 才 block」,**現行引擎的 confidence 語意也對不上**。任何以 confidence 為基礎的修法都得先處理這個錯位。這跟 `wild_fp_rate: 0` 那次(230 條 `?? 0` 假零值,PR #433)是同一種病:一個看起來像安全閥的欄位,實際沒接上。

### 6.2 有一處程式碼**刻意依賴** critical→deny

```
// src/engine.ts:372-374
// Don't short-circuit -- continue for telemetry, but blacklist match
// has critical severity which guarantees DENY verdict
```

Tier 1 已知惡意 skill 黑名單命中,是靠「發 critical → verdict 保證 deny」來達成阻擋的。**這是唯一一處把 critical→deny 當成契約在用的地方**,任何改動 verdict 的方案都必須不打斷它。這也是反對「無條件把 critical 降級」的最強技術理由。

兩個要注意的細節(查 `src/tier1-blacklist.ts:78-107`):

- 黑名單 match 是在規則迴圈**之前**就 push 進 `matches`(`engine.ts:371`),**不經過 lane gate**。所以它在 `enforce` lane 也照樣進 verdict。
- 但那個合成規則 `status: 'stable'`、`confidence: 1.0`、**沒有 `maturity` 欄位**。`normalizeMaturity(undefined)` 會安全歸類為 `'experimental'`(`rule-contract.ts:47-50`)。
- → **若採 O2(verdict 依 maturity 判斷),黑名單命中會被降成 `ask`。** 這是實作時必踩的坑,不是理論風險。另外 `severity: entry.severity` 是從黑名單條目讀的,不是寫死 critical —— 那句「guarantees DENY」其實建立在資料假設上。

### 6.3 測試把矩陣釘住了,但只釘 stable 的情況

`tests/verdict.test.ts:82-89` 明確斷言 `returns deny for a single critical match`。但 fixture 工廠 `makeRule`(L12-30)寫死 `status: 'stable'` 且**完全不設 `maturity`**。

→ 矩陣是被測試刻意釘住的(所以不能說「沒人想過」),但**「不成熟的 critical 規則會不會 deny」這個案例從來沒有被測試表達過**。改動 verdict 會踩到既有測試,這點要先知道。

### 6.4 `auto_response_threshold` 是死欄位

`isAutoResponseEnabled()`(`verdict.ts:33-49`)被 export,但 engine / executor / hook handler 都不呼叫它。這是 repo 內第二個「讀起來像安全閥、實際沒接線」的欄位,`docs/RESPONSE-ACTION-ELIGIBILITY.md:99-104` 與 `:350-351` 已經記載。

---

## 7. 所以要決策什麼(選項並陳,本文不主張任何一個)

因為是 (C),需要的是拍板 + 寫進規範。三條路,代價不同:

**O1 — 改預設 lane(`hunt` → `alert` 或 `enforce`)。**
一行改動,語意上最貼近 README 已公布的定義。代價是 recall:`enforce` 只剩 43 條 critical + 51 條 high 會開火,且 confirm-rule 沒有 embedding module 時會被丟棄。`docs/RESPONSE-ACTION-ELIGIBILITY.md:356-359` 已把它標成「a product decision, not a rule-quality one」。**這條路不需要動 `verdict.ts`。**

**O2 — 讓 verdict 變 maturity-aware**(例:`critical` + `stable` → deny;`critical` + 其他 → ask)。
保住 `hunt` 的可見度,同時拿掉未經量測的阻擋。代價:需要自己的 recall A/B(PR #446 已預告),會踩 `tests/verdict.test.ts`,且必須不打斷 §6.2 的黑名單路徑(黑名單 match 的 rule 是合成的,maturity 要確認)。另外只修這條路徑,§5 的七個下游消費端不受影響 —— 要一致就得進 SPEC。

**O3 — 維持行為,修文件。**
把 verdict 矩陣正式寫進 SPEC(它現在完全不在標準裡),並修正 `README.md:214` 對預設 lane 的「Advisory / eval」描述,承認預設會 deny。安全性不變,誠實度提升,成本最低。**但這等於正式宣告 228 條非 stable 的 critical 規則有阻擋權,與 `QUALITY-STANDARD.md:228` 直接衝突,所以 QUALITY-STANDARD 也得同步改。**

三條路都繞不開的前置工作:**`QUALITY-STANDARD.md` 的 maturity 階梯要補上 `test` 這一級**(§2.3)—— 206 條 critical 卡在標準沒定義的格子裡,任何以 maturity 為基礎的政策都得先定義它。

---

## 8. 本文沒做到 / 不主張的

- **沒重跑 65K benign gate**。`enforce ~0.24% / hunt ~9%` 是引用 `README.md:214` 與 v3.5.0 CHANGELOG 的既有公布值,不是我的量測,不在此背書。
- **沒做 recall A/B**。O1 / O2 的偵測代價我沒量,只給了「哪些規則會被排除」的靜態計數(228 / 271)。
- **沒有量測「預設路徑在 benign 語料上的 deny 率」**。那需要跑全語料 × verdict 路徑,不在本次範圍。§1 只證明了單一 payload 的 deny,是既有公開重現案例。
- **§2.1 關於 `SPEC.md` §5.5 是否涵蓋 `permissionDecision` 的討論是解釋,不是結論。** 原文沒有明說。
- **`spec/atr-method-v1.1.md:164` 的 SHOULD NOT 範圍限於 Signature rules**,我沒有把它當成通則引用。

---

## 附錄 A — 重現腳本(生產路徑 + CONTROL)

```ts
import { ATREngine } from '../src/engine.js';
import { HookHandler } from '../src/hook-handler.js';
import { ActionExecutor } from '../src/action-executor.js';
import { DefaultAdapter } from '../src/adapters/default-adapter.js';
import { computeVerdict } from '../src/verdict.js';
import type { HookInput, ATRRule, ATRMatch } from '../src/types.js';

const RULES = '<repo>/rules';
// 文件已記載會命中的合法輸入 — docs/RESPONSE-ACTION-ELIGIBILITY.md §1a
const CONTROL_CMD = 'google-chrome --no-sandbox &';

async function run(lane: 'hunt' | 'alert' | 'enforce' | undefined, cmd: string) {
  const engine = new ATREngine(lane ? { rulesDir: RULES, lane } : { rulesDir: RULES });
  const loaded = await engine.loadRules();          // 少這行 => 任何輸入都 0 match
  const handler = new HookHandler({ engine, executor: new ActionExecutor(new DefaultAdapter()) });
  const out = await handler.handlePreToolUse({
    hook: 'PreToolUse', tool_name: 'Bash', tool_input: { command: cmd },
  } as HookInput) as Record<string, unknown>;
  return { lane: lane ?? '(unset)', loaded, decision: out['decision'],
           matched: (out['matched_rules'] as string[]) ?? [] };
}

const control = await run(undefined, CONTROL_CMD);
if (control.matched.length === 0) {
  console.error('CONTROL FAILED: 0 matches on a documented-matching payload. Aborting.');
  process.exit(2);                                   // 沒 control 的 0 = 沒跑
}
for (const lane of ['hunt', 'alert', 'enforce'] as const) console.log(await run(lane, CONTROL_CMD));

// 合成探針:maturity / confidence 是不是 critical 判決的輸入?
const mk = (maturity: string): ATRRule => ({ /* severity: 'critical', maturity, ... */ } as ATRRule);
for (const maturity of ['draft', 'experimental', 'test', 'stable'])
  for (const confidence of [0.1, 0.5, 0.9])
    console.log(maturity, confidence,
      computeVerdict([{ rule: mk(maturity), confidence } as ATRMatch]).outcome);
```

## 附錄 B — 語料計數方法

直讀 `rules/**/*.yaml`,不經 engine(避免 harness 風險),套用引擎自己的排除規則:

- `status` 為 `draft` / `deprecated` → `src/engine.ts:381` 在任何 lane 之前就跳過;
- `maturity` 為 `deprecated` → `rule-contract.ts:62` 在任何 lane 都不開火;
- 無法辨識的 maturity → 依 `normalizeMaturity`(`rule-contract.ts:49`)歸為 `experimental`。

784 檔全數可解析,777 條 live。

## 附錄 C — 引文索引

| 主張 | 出處 |
|---|---|
| critical 無條件 deny | `src/verdict.ts:61-75` |
| 矩陣只寫在 docstring | `src/verdict.ts:51-59` |
| lane gate 在 match 產生前 | `src/engine.ts:383`、`src/quality/rule-contract.ts:60-66` |
| verdict 吃 lane 過濾後的 matches | `src/engine.ts:1664` |
| lane 預設 hunt | `src/engine.ts:303`(`this.config.lane ?? 'hunt'`) |
| `atr guard` 不設 lane | `src/cli.ts:649-660` |
| enforce = auto-block lane | `src/engine.ts:214-216`、`src/quality/rule-contract.ts:54` |
| SPEC 未定義 verdict | `SPEC.md` §7 / §11 / `conformance/v1.0/` |
| response 是建議非指令 | `SPEC.md:177-179` |
| 沒有 operator policy 不該 auto-block(Signature) | `spec/atr-method-v1.1.md:164` |
| experimental = non-blocking alerting | `docs/QUALITY-STANDARD.md:43` |
| stable = safe for blocking | `docs/QUALITY-STANDARD.md:70` |
| blocking 只給 stable + conf≥80 | `docs/QUALITY-STANDARD.md:228` |
| 預設 lane 被描述為 advisory/eval | `README.md:214` |
| severity = 衝擊校準 | `docs/rule-writing-guide.md:50-56` |
| 阻擋動作保留給 confidence: high | `docs/rule-writing-guide.md:589` |
| 已知且刻意延後 | `docs/RESPONSE-ACTION-ELIGIBILITY.md:145-149, 365-367`、PR #446 body |
| verdict.ts 誕生日 | commit `37d8aafd5`(2026-03-11, v0.2.1) |
| lane 誕生日 + opt-in 宣告 | commit `bf5e62c69`(2026-06-16, v3.5.0) |
| engine confidence 來自 tags | `src/engine.ts:653, 818, 971` |
| 黑名單依賴 critical→deny | `src/engine.ts:372-374`、`src/tier1-blacklist.ts:78-107` |
| 測試釘住 critical→deny | `tests/verdict.test.ts:82-89` |
| 下游各自實作 severity 門檻 | `src/adapters/mastra.ts:29`、`openshell-filter.ts:61`、`nemoclaw-preflight.ts:59`、`integrations/langchain/*.py:78`、`integrations/pydantic-ai/*.py:86` |
| 第三方引擎契約有 ATR_MIN_MATURITY | `engines/{go,python,typescript}/INTERFACE-CONTRACT.md` |
