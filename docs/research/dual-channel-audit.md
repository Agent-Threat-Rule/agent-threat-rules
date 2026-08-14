# 雙通道稽核:`permissionDecision` 與 `response.actions` 為什麼會互相矛盾

調查報告。**不改任何 production code**,只量測與記錄。

- 基準 commit:`994b01b2b`(`origin/main`,2026-08-14)
- 分支:`docs/dual-channel-audit`
- 硬碟規則數:784(`find rules -name "*.yaml" | wc -l`)= `data/stats.json`.rules.total 784,無漂移
- 量測腳本:`.scratch-audit/audit2.ts`、`.scratch-audit/audit3.ts`、`.scratch-audit/elig-coverage.ts`
  (未提交,列在下方「重現」章節)

---

## 0. 一句話結論

引擎有 **三條**決策通道,不是兩條,而且三條的判準各自獨立:

| 通道 | 判準 | 誰在用 |
|---|---|---|
| A `permissionDecision` | **只看最高嚴重度那一條 match 的 severity + confidence** | 只有 Claude Code hook(`src/hook-handler.ts`,全 repo 唯一出現處) |
| B `response.actions` → `ActionExecutor` | **所有 match 的 actions 聯集**,不看 severity、不看 lane、不看 maturity | ATR 自帶的兩個 adapter,而兩個都不真的阻斷 |
| C `match.rule.severity` + 自訂 floor | 下游自己訂的 severity 門檻 | **本 repo 內外每一個下游整合** |

矛盾的根在 `src/verdict.ts:127` `computeVerdict()`:
`outcome` 由 `matches[0]`(最高嚴重度)單獨決定,`actions` 由 `collectUniqueActions()` 對**全部** match 取聯集。
兩個欄位來自同一個 verdict 物件,但用了兩套不同的資料。

---

## 1. 現象複現(實跑,不是推導)

### 1a. 最小複現:`allow` + `block_tool` 同時發生

走真正的出貨路徑 `HookHandler.handlePreToolUse → engine.evaluateWithVerdict(event, executor) → ActionExecutor.execute`,
verdict 讀的是 `toClaudeCodePreToolUse()` 產出的 Claude Code 契約欄位,不是 ATR 內部的 `decision`:

```
輸入:{ hook: "PreToolUse", tool_name: "bash", tool_input: { command: "ls -la /tmp" } }

{
  "permissionDecision": "allow",
  "executed": ["block_tool", "alert"],
  "matched": ["ATR-2026-00099"],
  "reason": "ALLOW: High-Risk Tool Invocation Without Human Confirmation
             [low/71% confidence] (1 rule matched)"
}
```

機制:`ATR-2026-00099`(`rules/excessive-autonomy/ATR-2026-00099-high-risk-tool-gate.yaml`)
`severity: low`、`response.actions: [block_tool, alert]`。
`determineOutcome()` 對 `low` 一律回 `allow`;`collectUniqueActions()` 照樣把 `block_tool` 收進去;
`engine.ts:1668` 的條件是 `if (executor && verdict.actions.length > 0)` —— **不看 outcome**,所以 `allow` 也照跑。

### 1b. 這不是人造樣本 —— Claude Code 的真實工具名就會踩到

`atr init` 寫進 `.claude/settings.local.json` 的 hook 是 `npx agent-threat-rules guard`,matcher 為空(match all tools)。
把 Claude Code 真實工具名配良性參數逐一餵進去(`.scratch-audit/audit3.ts` B 段):

| tool_name | 參數 | permissionDecision | 實際執行的 action |
|---|---|---|---|
| **Bash** | `{command:"ls -la"}` | `allow` | `block_tool`, `alert` |
| **BashOutput** | `{bash_id:"1"}` | `allow` | `block_tool`, `alert` |
| **KillShell** | `{shell_id:"1"}` | `allow` | `block_tool`, `alert` |
| Read / Write / Edit / Glob / Grep / Task / WebFetch / WebSearch / TodoWrite / NotebookEdit | 良性 | `allow` | (無) |

`ATR-2026-00099` 的 pattern[5] 是 `(?i)(exec|execute|run_command|shell|bash|cmd|...)`,
比對欄位是 `tool_name` —— Claude Code 的工具就叫 `Bash`。
**裝了 ATR guard 的 Claude Code,每一次 Bash 呼叫都會走到「A 通道放行、B 通道 block_tool」。**

### 1c. 端到端:真的 `atr guard` stdio loop

不是我拼裝的 handler,是 CLI 本體(`src/cli.ts` `cmdGuard`,`StdioAdapter`):

```
$ printf '%s\n' '{ this is not json' \
  '{"hook":"PreToolUse","tool_name":"Read","tool_input":{"content":"hello world"}}' \
  '{"hook":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | npx tsx src/cli.ts guard
```

stdout(Claude Code 讀的):
```json
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"Guard error (fail-open): Expected property name or '}' in JSON at position 2 (line 1 column 3)"},"atr_decision":"allow"}
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"No rules matched."},"atr_decision":"allow"}
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"ALLOW: High-Risk Tool Invocation Without Human Confirmation [low/71% confidence] (1 rule matched)"},"atr_decision":"allow","matched_rules":["ATR-2026-00099"]}
```

stderr:
```
[atr-guard] Loaded 784 rules from .../rules
[atr-guard] Error: Expected property name or '}' in JSON at position 2 (line 1 column 3)
{"type":"alert","severity":"low","reason":"ALLOW: High-Risk Tool Invocation ...","matchCount":1}
```

第三行的 `block_tool` **在 stdout 與 stderr 都完全沒有痕跡**。它被寫進 `StdioAdapter` 的私有 `responseBuffer`,
而 `flushResponses()` 全 repo 沒有任何呼叫者(見 §2)。

---

## 2. 通道 B 的真實效果:ATR 自帶的 adapter 都不阻斷

全 repo `implements PlatformAdapter` 只有兩個:

```
$ grep -rn "implements PlatformAdapter" src tests examples scripts
src/adapters/default-adapter.ts:29:export class DefaultAdapter implements PlatformAdapter {
src/adapters/stdio-adapter.ts:29:export class StdioAdapter implements PlatformAdapter {
```

`src/adapters/` 底下另外三個檔(`mastra.ts` / `nemoclaw-preflight.ts` / `openshell-filter.ts`)
**不是 PlatformAdapter**,它們是走通道 C 的獨立元件(見 §3)。

實測(`.scratch-audit/audit2.ts` P2 段,直接對兩個 adapter 送 `[block_tool, kill_agent, quarantine_session]`):

| adapter | `kill_agent` 回傳 | 可觀測副作用 |
|---|---|---|
| `DefaultAdapter` | `success:true`,`"[kill_agent] logged (no-op) for verdict: allow"` | **無**。檔頭自述 "performs no actual enforcement" |
| `StdioAdapter` | `success:true`,`"Agent kill requested via stdio protocol"` | 寫進私有 `responseBuffer`,**沒有讀者** |

`StdioAdapter` 的分工:
- `blockInput` / `blockOutput` / `blockTool` / `quarantineSession` / `resetContext` / `reducePermissions` / `killAgent`
  → `responseBuffer.push(...)`,而 `flushResponses()` 唯一出現處就是它自己的定義:
  ```
  $ grep -rn "flushResponses" src tests bin scripts
  src/adapters/stdio-adapter.ts:37:  flushResponses(): readonly unknown[] {
  ```
- `alert` / `escalate` / `snapshot` → 寫 stderr(**唯一真的看得到的**)
- `shadow` → 只在 `ATR_SHADOW_LOG` 有設時寫 stderr

而且 `HookHandler.evaluateAndRespond()`(`src/hook-handler.ts:252`)只解構 `{ verdict }`,
`evaluateWithVerdict` 回傳的 `actionResults` 被直接丟掉 —— 連錯誤都不會浮出來。

**所以問題一的答案:是的,`DefaultAdapter` 是徹底 no-op;出貨路徑用的 `StdioAdapter` 在阻斷類動作上也等同 no-op。
但下游自訂 adapter 會真的執行 —— 而 `response.actions` 正是 ATR 給下游的介面。**

### 2a. SPEC 的正規動作字彙與引擎能派送的集合完全不交集

`SPEC.md` Appendix A(v1.0.0 normative):
`block_request, log_alert, quarantine_artifact, require_human_review, redact_match, rate_limit_source, revoke_credential, notify_operator`

`src/action-executor.ts` `ACTION_METHOD_MAP`:
`block_input, block_output, block_tool, quarantine_session, reset_context, alert, shadow, snapshot, escalate, reduce_permissions, kill_agent`

交集 = **空集合**。硬碟上活躍規則實際用到的動作:

| action | 活躍規則數 | 引擎會不會派送 |
|---|---:|---|
| `alert` | 776 | 會 |
| `block_input` | 374 | 會 |
| `block_tool` | 272 | 會 |
| `snapshot` | 244 | 會 |
| `escalate` | 130 | 會 |
| `require_human_review` | 11 | **不會**(SPEC 字彙,走 "Unknown action" 分支) |
| `reduce_permissions` | 6 | 會 |
| `block_output` | 6 | 會 |
| `quarantine_session` | 5 | 會 |
| `quarantine_artifact` | 3 | **不會** |
| `kill_agent` | 1 | 會 |
| `reset_context` | 1 | 會 |
| `log_alert` | 1 | **不會** |

`SPEC.md` §5.5 同時寫著:

> Engines MUST NOT execute response actions automatically without an explicit
> configuration directive from the operator. The `response` field is a
> recommendation expressed by the Rule author, not a directive to the Engine.

`cmdGuard`(`src/cli.ts:664-665`)在**沒有任何 operator directive** 的情況下無條件建 `ActionExecutor` 並傳進 `HookHandler`。
規範說「建議」,實作說「照跑」。

### 2b. `auto_response_threshold` 是死欄位

443 條活躍規則沒有這個欄位,其餘 334 條有(`critical` 63 / `high` 189 / `medium` 80 / `low` 2)。
`isAutoResponseEnabled()` 定義在 `src/verdict.ts:33`,呼叫者只有 `src/index.ts` 的 re-export 與 `tests/verdict.test.ts`。
**引擎、executor、hook handler 都沒有呼叫它。** 而且它的 `thresholdMap` 只有 high/medium/low,
`critical` 這個值本身就會回 `false` —— 63 條規則寫了一個連 map 都沒有的值。
(此點 `docs/RESPONSE-ACTION-ELIGIBILITY.md` §1 已記載,此處為獨立複驗。)

---

## 3. 下游整合實際上讀哪條通道

`permissionDecision` 這個字串在全 repo(排除 node_modules)只出現在:
`src/hook-handler.ts`、`tests/claude-code-contract.test.ts`、`scripts/gate-action-eligibility.ts`、
`src/quality/action-eligibility.ts`、兩份文件、兩筆語料樣本、一份 CVE proposal。
**沒有任何一個 integration 讀它。**
`response.actions` 也一樣:`grep -rln "\.actions\b" integrations/ python/ engines/ examples/ conformance/` 零命中。

逐一對照(repo 內為讀原始碼;repo 外為 2026-08-14 現抓):

| 整合 | 位置 | 讀哪條通道 | 判準 / 預設 | 阻斷方式 |
|---|---|---|---|---|
| Claude Code hook | `src/hook-handler.ts` | **A** `permissionDecision` | severity+confidence 決策矩陣 | hook 契約 deny / ask |
| goose plugin | `integrations/goose/scripts/atr_scan.py` | **C** severity | `_BLOCK_SEVERITIES = {critical, high}` | `sys.exit(2)` |
| LangChain guardrail | `integrations/langchain/langchain_atr_guardrail.py` | **C** severity | `block_severity="critical"` | 換成 `ToolMessage` |
| Pydantic AI | `integrations/pydantic-ai/pydantic_ai_atr.py` | **C** severity | `block_severity="critical"`;結果側預設**不擋**(`block_on_result=False`) | `raise ModelRetry` |
| rampart evaluator | `integrations/rampart/src/atr_rules_evaluator.py` | **C** severity | `min_severity=None`(可選) | 回 `EvalOutcome.DETECTED` |
| semgrep rule pack | `integrations/semgrep/rules/` | **無**(只搬 detection) | Semgrep 自己的 severity | Semgrep finding |
| Mastra processor | `src/adapters/mastra.ts` | **C** severity | `["critical","high"]` | `abort()` |
| NemoClaw preflight | `src/adapters/nemoclaw-preflight.ts` | **C** severity | `ATR_MIN_SEVERITY` 預設 `high` | gate verdict |
| OpenShell filter | `src/adapters/openshell-filter.ts` | **C** severity | `ATR_MIN_SEVERITY` 預設 `high` | `exit 1` |
| MCP server | `src/mcp-server.ts` | **無決策**,只回 matches | `min_severity` 過濾 | 不阻斷 |
| pyatr(Python 引擎) | `python/pyatr/` | **兩條都沒有** | `ATRMatch` 只有 severity + confidence,連 `actions` 欄位都不存在 | 呼叫端自理 |
| converters(elastic/splunk/sarif/generic-regex) | `src/converters/` | **無**(`grep -c actions` = 0) | 目標平台自己的 severity | 不阻斷 |
| Sigma export | `scripts/generate-sigma.py` | **C** severity | `severity` → Sigma `level`;不搬 actions | 由 SIEM 決定 |
| **NeMo Agent Toolkit ATR** | `Agent-Threat-Rule/NeMo-Agent-Toolkit-atr` `src/nat/plugins/atr/detector.py` | **C** severity | `DEFAULT_DENY_SEVERITIES`,`action = "deny" if any(m.severity in self._deny) else "log"` | deny verdict |
| **AG2 (AutoGen)** | `ag2ai/ag2classic` `.../capabilities/atr_guardrail.py` | **C** severity | `min_severity="low"`,`action ∈ {allow,warn,block}` | drop LLM input / redact tool output |

`INTEGRATION.md`(給下游看的官方指引)自己也是通道 C:
第 45 / 90 / 163 行的範例都是 `match.rule.severity === 'critical' && match.confidence > 0.8`,
全文沒有出現 `permissionDecision`,也沒有出現 `response.actions`。

**結論:通道 A 只服務 Claude Code 一家;通道 B 沒有任何已知消費者在真的執行阻斷;
所有下游走的是第三條 —— 各自 hard-code 一個 severity floor。
因為預設 floor 多半是 `critical`/`high`,`ATR-2026-00099`(`low`)在下游整合裡是完全不會擋的;
唯一會被它「擋」的地方,是 ATR 自己那條沒有讀者的 buffer。**

### 3a. Sigma / Go / Rust 的現況

- **Sigma**:存在,但不在 `src/converters/`(那裡是 elastic / splunk / sarif / sage / generic-regex)。
  轉換器是 `scripts/generate-sigma.py`,產出在 `docs/sigma-export/rules/`(現有 5 條)。
  它把 ATR `severity` 映射成 Sigma `level`(`SEVERITY_TO_LEVEL`,第 66 / 508-512 行),
  **完全不搬 `response.actions`**(`grep -cE '\bactions\b' scripts/generate-sigma.py` = 0,
  匯出的 `.sigma.yml` 也沒有 actions 欄位)。→ 通道 C。
  另外 `ADOPTERS.md` 的 SigmaHQ 條目是 tools 目錄的 cross-listing(`SigmaHQ/sigma#6015`),不是這支轉換器。
- **Go**:`engines/go/` 只有 `README.md` + `INTERFACE-CONTRACT.md`,**沒有實作**。
- **Rust**:全 repo 沒有 Rust 實作。

---

## 4. 這個矛盾的實際後果(具體情境)

### 情境 1 —— 使用者裝了 `atr init`,跑 `Bash` 指令(§1b 實測)
- ATR 判定:`permissionDecision: allow` → **Claude Code 執行指令**。
- 同時 executor 跑 `block_tool`,寫進沒人讀的 buffer;`alert` 寫進 stderr。
- 使用者看到:指令正常執行,外加 stderr 一行 `{"type":"alert","severity":"low",...}`。
- **實際安全效果 = 零**,但日誌長期看起來像「有個 block 在跑」。
- 危險的是換 adapter 的那一天:下游若照 `response.actions` 實作一個真的 `blockTool`,
  **同一批事件會從「全放行」瞬間變成「每次 Bash 都被擋」**,而 verdict 通道從頭到尾都說 allow,
  除錯的人會在 hook 輸出裡找不到任何線索。

### 情境 2 —— 反方向:`deny` 但零阻斷動作
92 條活躍的 `critical`/`high` 規則的 actions 全在 OBSERVE 層(alert/snapshot/escalate/shadow),
沒有任何 `block_*`(critical 25 條 + high 67 條)。
實測(§5 A 段,1469 筆自有 TP):479 次 `deny` 裡有 **127 次**完全沒有執行任何 INTERRUPT 以上的動作。
- Claude Code:擋下來了。
- 走通道 B 的下游自訂 adapter:什麼都沒收到,**放行**。
- 兩個平台對同一事件的行為相反,而規則檔看起來完全一樣。
- **而且這一類會隨著 action-eligibility 線做好它的事而變多** —— 那條線的做法就是把沒賺到的
  `block_*` 降級成 `alert`,降級不動 severity,所以 verdict 照樣 deny。

### 情境 3 —— `ask` 被動作通道搶先
`high` + confidence < 0.8 → `ask`(要使用者按核准)。實測 99 次 `ask` 裡有 **37 次**同時執行了 INTERRUPT 以上的動作。
在真實 adapter 上,使用者還沒看到提示,tool 就已經被 block 掉了 —— 「請你決定」和「已經替你決定」同時發生。

### 情境 4 —— guard 自己壞掉
壞 JSON 行 → `permissionDecision: allow`(§1c 第一行輸出)。
攻擊者只要讓 hook 的輸入不可解析(或讓 engine 拋錯),就得到全面放行,而 stdout 看起來是一次正常的 allow。

---

## 5. 量化:兩通道在真實語料上分歧多少

### 5a. 母體(自己重算,與複核者數字一致)

```
find rules -name "*.yaml" | wc -l                → 784
python3 -c "...json.load(open('data/stats.json'))['rules']['total']" → 784   # 無漂移
```

`status` 非 `draft`/`deprecated`(= `engine.ts:382` 的活躍定義)= **777** 條。

| 指標 | 數字 |
|---|---:|
| 活躍規則 | 777 |
| 宣告 `block_input`/`block_tool`/`quarantine_session` 的活躍規則 | **646** |
| ↳ 其中 maturity 非 `stable` | **548** |
| 宣告任一「引擎會派送的阻斷/降級/終止動作」的活躍規則 | 657(非 stable 559) |
| 活躍 `critical`+`high` 規則 | 692 |
| ↳ actions 全在 OBSERVE 層(deny/ask 但零阻斷) | **92**(critical 25 / high 67) |
| 活躍 `medium`/`low` 規則 | 85 |
| ↳ 帶 INTERRUPT 以上動作(可能 allow/ask 但會 block) | **57**(medium 56 / low 1) |
| ↳ severity `low`,**永遠不可能 deny** | 1(`ATR-2026-00099`) |

複核者的 646 / 548 完全複現。方法:`.scratch-audit/count-actions.py`(直接 parse YAML,不經引擎)。

### 5b. 動態分歧(走真實 hook 路徑)

樣本 = 全體活躍規則自有的 `test_cases.true_positives`(每條取前 2 筆),1469 筆。
載體固定為中性的 `tool_name: "Read"`(見下方「量測誠實聲明」)。

| 指標 | 數字 |
|---|---:|
| 樣本數 | 1469 |
| `permissionDecision` = allow / ask / deny | 891 / 99 / 479 |
| **allow 但執行了任何 action** | 0 |
| **ask 但執行了 INTERRUPT 以上** | **37** |
| **deny 但零阻斷動作** | **127** |

再跑一次 `data/skill-benchmark/benign`(466 份,載體 `Read`,`.scratch-audit/repro-dual-channel.ts`):
allow 128 / ask 84 / deny 254;allow+動作 = 0;ask+INTERRUPT = 2。

### 量測誠實聲明(第一輪我自己翻的車)

第一輪 sweep 我用 `tool_name: "Bash"` 當載體,結果是 **894/894 的 allow 全部伴隨 `block_tool`** —— 100%。
那個數字是我自己造出來的:`ATR-2026-00099` 的 pattern[5] 直接吃 `bash`,所以每一筆樣本都額外多命中它一條。
第二輪換成中性載體 `Read` 重跑,內容驅動的 allow+動作分歧就變成 **0**。

兩個數字都是真的,意思不同:
- **內容驅動**的分歧:0 —— 因為所有靠 content 命中的阻斷型規則 severity 都 ≥ medium,verdict 不會是 allow。
- **工具名驅動**的分歧:100% —— 而 Claude Code 的工具真的就叫 `Bash`。這不是汙染,這是出貨現實(§1b 單獨量)。

把兩者混在一起報,就會得到一個 894 的假數字。分開報才是真的。

### CONTROL(不含這些就當作沒跑)

`new ATREngine(...)` 的 constructor 不編譯 pattern;`HookHandler` 的 engine 沒接上時 **fail-open 回 `allow`**,
而 `allow` 是 truthy —— 只檢查「有回值」是假通過。三支腳本各自帶硬性 control,任一不成立 `exit 3` 且不輸出數字:

| Control | 斷言 | 實測 |
|---|---|---|
| C1 | `engine.loadRules() >= 700` | 784 ✓ |
| C2 | critical 規則的 TP 必須拿到 `permissionDecision === 'deny'`(≥3) | audit2:114;audit3:30 ✓ |
| C3 | 那些 deny 必須真的執行到 action(≥3) | audit2:114;audit3:30 ✓ |
| C4 | 良性事件 + 中性載體必須 `allow` 且 `executed=[]` | ✓(否則 A 段數字全是載體造成的) |
| elig-C1 | `corpus_digest` 現算 == 檔案內的值 | `7d96f3060335ba6f925a27b444e69ec1` == ✓ |
| elig-C2 | 我算的違規數必須與 `gate-action-eligibility.ts` 一致 | 0 == 0 ✓ |

---

## 6. `action-eligibility` 那條線有沒有真的蓋到每一條規則?

**有,646/646 全覆蓋,而且是可驗證的 —— 但它蓋的是動作 blast radius,不是本報告的矛盾。**

用 gate 自己的函式(`detectionFingerprint` / `maxTierFor` / `actionTier`)重算,不重寫一份邏輯:

| 指標 | 646 條中 |
|---|---:|
| 在 `data/benign-fp-measurement.json` 裡有紀錄 | 646 |
| `detection_fingerprint` 對得上(= 量測描述的是硬碟上這條規則) | **646** |
| `isMeasured()` = true(有可用證據) | **646** |
| 未量測 | **0** |
| 宣告動作 > 已賺到的 tier(違規) | **0** |

賺到的 tier 分佈 vs 宣告的 tier 分佈:

| tier | earned | declared |
|---|---:|---:|
| observe | 0 | 0 |
| interrupt | 6 | 639 |
| degrade | 542 | 2 |
| terminate | 98 | 5 |

量測基準:`sample_count = 5352`,語料 `data/skill-benchmark/benign` + `data/benign-corpus-extended` + `data/benign-code`。
646 條裡 `fp_count = 0` 的 527 條、`fp_count > 0` 的 119 條。
`gate-action-eligibility.ts --json` 現跑:`{"checked": 784, "violations": []}`,exit 0。

**所以「這個漏洞已被那條線覆蓋」這句話,一半對一半錯:**

對的一半 —— 動作面確實全部經過實測認證,0 條 overreach,這不是論證,是量測。

錯的一半,三點:

1. **它明說自己不管 verdict 通道。** `src/quality/action-eligibility.ts:36-41` 自己寫的:
   > `response.actions` feeds the ActionExecutor. It does NOT feed the hook verdict:
   > `src/verdict.ts` computeVerdict derives allow/ask/deny from severity and confidence alone...
   > This module governs executed response actions, not the hook's block decision.

   本報告的矛盾(A 說 allow、B 說 block)剛好落在它宣告不管的那一半。
   `ATR-2026-00099` 的 `block_tool` 是**合法賺到**的(earned = degrade ≥ interrupt),
   eligibility 線沒有理由拿掉它 —— 矛盾照樣成立。

2. **它是 authoring/CI 時的閘,不是 runtime 過濾。**
   `grep -rn "action-eligibility" src/` 在 `src/` 底下只命中 `action-executor.ts` 的**註解**;
   真正的 import 只有 `scripts/`(gate、downgrade)與 `tests/`。
   Runtime 上 `ActionExecutor` 依然沒有 lane、沒有 maturity、沒有 eligibility 過濾。
   規則若來自 fork、下游自帶規則庫,或過閘後被改,runtime 沒有第二道防線。

3. **「已量測」的成色要打折。** 646 條裡:
   - `skill_path_unmeasured: true` 的有 **537** 條 —— 而 `findViolations()` **完全不讀這個欄位**
     (`MeasurementRecord` 宣告了它,程式碼只讀 `partial_measurement`)。
     這 537 條的量測沒有走過 skill-path 複合閘。
   - `partial_measurement: true` 的有 4 條。
   - 5,352 筆語料的 rule of three:0 FP 只能把 95% 上界壓到約 0.056%,不是 0。這一點模組 docstring 自己有寫。

---

## 7. fail-open / fail-close:註解與行為哪個對?

**行為對,`src/hook-handler.ts:211` 的註解錯。**

該註解寫:
> Default to PreToolUse framing: on an unparseable line the error path
> **fail-closes to a deny**, and a deny must reach Claude Code as a real block.

實際:
- `HookHandler` 建構子 `this.failOpen = config.failOpen ?? true`(`hook-handler.ts:162`)→ **預設 fail-open**。
- `handleError()`(`hook-handler.ts:275`)`if (this.failOpen) return allowOutput(...)`。
- CLI:`const failOpen = options['fail-open'] !== 'false'`(`cli.ts:652`)→ 出貨預設也是 **true**。
- 檔頭 `hook-handler.ts:9-10` 反而寫對了:
  > CRITICAL: Fail-open on all errors -- default to "allow"...

實測三種情形:

| 情形 | 設定 | `permissionDecision` |
|---|---|---|
| (a) engine 沒接上 | `failOpen` 預設 | **`allow`**,reason = `Guard error (fail-open): Cannot read properties of undefined (reading 'evaluateWithVerdict')` |
| (b) engine 沒接上 | `failOpen: false` | `deny` |
| (c) 壞 JSON 行(真 stdio loop) | CLI 預設 | **`allow`**,reason = `Guard error (fail-open): Expected property name or '}' ...` |
| (d) `timeoutMs: 1` + 200KB 輸入 | — | `allow` —— 但**逾時沒有觸發**;regex 是同步的,timer callback 排在它後面(`withTimeout` 的 ReDoS 註解自己有寫) |

同一個檔案裡兩處註解互相矛盾(第 9-10 行說 fail-open,第 211 行說 fail-close),
行為站在第 9-10 行那邊。

另外:`toClaudeCodePostToolUse()` 不會發出 `permissionDecision`,只在 deny/ask 時發 `decision: "block"`。
所以 PostToolUse 路徑上兩通道的落差表現方式與 PreToolUse 不同(A 通道只有「block / 不 block」兩態)。

---

## 8. 修法選項(並陳,不主張)

### 對於「A 說 allow、B 說 block」

**O1. `computeVerdict` 讓兩個欄位用同一組資料**
在 `verdict.ts` 只從「決定了 outcome 的那些 match」收 actions,或反過來讓任何 INTERRUPT 以上的
action 把 outcome 抬到至少 `ask`。
成本:改的是引擎的封鎖行為,需要獨立的 recall 分析。`ATR-2026-00099` 會從 allow 變 ask —— 意味著
**每一次 Bash 呼叫都要使用者按核准**,幾乎確定不能接受,所以這個選項必須配 O5。

**O2. `engine.ts:1668` 加 outcome 閘**
`if (executor && verdict.actions.length > 0 && verdict.outcome !== 'allow')`。
成本:最小、行為最好預測;但它把「B 通道可以在 A 通道放行時獨立示警」這個能力一併關掉,
且 `alert`/`snapshot` 這種 OBSERVE 動作在 allow 時本來就該跑,所以真要做應該只閘 INTERRUPT 以上。

**O3. 把 tier 閘搬進 executor(runtime 版的 eligibility)**
`ActionExecutor` 讀 lane + eligibility tier,在 dispatch 前過濾。
成本:executor 要拿到 lane 與 measurement,是目前架構上沒有的依賴;但它同時補上 §6 的第 2、3 點
(runtime 沒有第二道防線)。

**O4. 修規則,不修引擎**
把 `ATR-2026-00099` 的 severity 從 `low` 提到 `medium`(→ ask),或把 `block_tool` 降成 `alert`。
成本:只解決這一條;`medium` 那 56 條同型規則還在。而且提 severity 會讓每次 Bash 都變 ask(同 O1 的問題)。

**O5. 修 `ATR-2026-00099` 的 detection**
它的 pattern[5] 在 `tool_name` 上比對裸字 `bash`/`exec`/`shell`,而這正是 Claude Code 工具的名字。
加負向 lookahead 或改用 `tool_args` 的實際指令內容,能同時消掉「每次 Bash 都命中」與後續所有連鎖。
成本:動 detection = 動 recall,要重跑 65K benign gate 與 wild FP;而且這條規則的設計本意
(「高風險工具一律要人確認」)跟「Claude Code 的 Bash 就是高風險工具」其實不衝突 —— 真正的問題是
`severity: low` 讓它永遠只能走 B 通道。

### 對於「B 通道沒有讀者」

**O6. 把 `StdioAdapter.responseBuffer` 接進 hook 輸出**,或把那些方法的假裝拿掉。
(`docs/RESPONSE-ACTION-ELIGIBILITY.md` §9 已列為 open item,此處複述以求完整。)

**O7. 讓 `HookHandler` 至少不要丟掉 `actionResults`** —— 現在連 action 執行失敗都不會浮出來。

### 對於「規範與實作不一致」

**O8. 讓 `SPEC.md` §5.5 與 `cmdGuard` 對齊**:
要嘛 `cmdGuard` 預設不傳 executor(需要 `--execute-actions` 之類的明示 directive),
要嘛改 SPEC 承認傳 executor 就是 directive。
**O9. 讓 Appendix A 的字彙與 `ACTION_METHOD_MAP` 至少有交集**(目前 15 條規則寫的是 SPEC 字彙,全部靜默失效)。

### 對於 fail-open

**O10. 修 `hook-handler.ts:211` 的註解**(零風險,純文件錯誤)。
**O11. 分開處理「解析失敗」與「評估失敗」**:壞 JSON 是輸入問題(可以 deny),engine 例外是可用性問題(fail-open 合理)。
目前兩者共用 `handleError()`,只能一起選。

### 對於通道 C

**O12. `INTEGRATION.md` 明確說出「有三條通道、下游應該讀哪一條」。**
目前它示範的是 severity floor,而 `permissionDecision` / `response.actions` 在該文件中一次都沒出現 ——
下游各自發明門檻的現況,是這份文件造成的,不是意外。

---

## 9. 我做不到的部分(直說)

- **沒有量「真的會阻斷的 adapter」在真實流量下的後果。** repo 裡不存在這種 adapter,
  所有後果分析(情境 1 的第二段、情境 2)是基於「下游若照 `response.actions` 實作」的推論,
  不是量測。這一點無法在本 repo 內量。
- **repo 外的整合只驗了 2 個**(NeMo Agent Toolkit ATR、AG2),用 GitHub API 抓原始碼現讀。
  另外 4 個 adapter-tier adopter(LiteLLM #28050、Microsoft Agent Framework #6528、
  OpenAI Guardrails #77、rulezet #50)**沒有逐一讀原始碼**,表格中未列入。
- **Claude Code 對 hook stderr 的處理方式沒有驗證。** §4 情境 1 說「使用者看到 stderr 一行」,
  ATR 那一端我實測了,Claude Code 那一端怎麼呈現(顯示 / 吞掉 / 餵給模型)我沒有驗。
- **`ask + INTERRUPT` 的 37 次沒有逐條追出是哪些規則組合造成的**,只有總數。
- **benign gate 的已知污染沒有納入考量。** 5,352 筆語料的組成本身有獨立的爭議,
  本報告只用它來回答「eligibility 線有沒有覆蓋」,沒有引用它的 FP 率當作對外數字。

---

## 10. 重現

```bash
git -C <atr-repo> worktree add -f /tmp/dualchan/wt -b docs/dual-channel-audit origin/main
ln -sfn <atr-repo>/node_modules /tmp/dualchan/wt/node_modules
cd /tmp/dualchan/wt

# 母體靜態統計(646 / 548 / 92 / 57)
python3 .scratch-audit/count-actions.py . /tmp/rules-rows.json

# 雙通道複現 + adapter 行為 + fail-open(P1~P4)
npx tsx .scratch-audit/audit2.ts

# 中性載體 sweep + Claude Code 工具名 + 真 stdio loop(A/B/C)
npx tsx .scratch-audit/audit3.ts

# eligibility 覆蓋率(646/646)
npx tsx .scratch-audit/elig-coverage.ts
npx tsx scripts/gate-action-eligibility.ts --json   # exit 0, violations: []

# 最小手動複現:一行就看得到矛盾
printf '%s\n' '{"hook":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"}}' \
  | npx tsx src/cli.ts guard
# stdout: permissionDecision "allow"
# stderr: {"type":"alert",...}  ← block_tool 在兩邊都看不到
```

量測腳本在 `.scratch-audit/`(未提交)。所有 exit code 直接判定,沒有 grep 輸出字串。
