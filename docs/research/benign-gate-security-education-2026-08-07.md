# benign gate 裡的資安教材:算 benign 還是該分流?

**裁定日期** 2026-08-07 · **量測基準** origin/main `e2e930c1d` · **語料** 5,352 筆
(`data/skill-benchmark/benign` + `data/benign-corpus-extended` + `data/benign-code`)

## 問題

`scripts/gate-promotion-fp.ts` 對 776 條會 fire 的規則跑 5,352 筆 benign 樣本:
clean 598 · dirty 178 · **FP 總數 14,561**。收緊規則的人一致回報,殘留 FP 幾乎
全是滲透測試 / 資安教材文件逐字寫著 `' OR '1'='1`、`/etc/passwd`、`; DROP TABLE`、
`find / -name "id_rsa"`。

一份逐字引用攻擊 payload 當教學範例的資安教材,對偵測規則來說算 benign 還是
該分流出去?

## 裁定

**語料一條不動、一條不移(採 A);gate 多報一行分段(採 B 的報告面,不採它的
實質面)。對外數字永遠是總數 14,561,不准引用「一般 benign FP」那一半。**

依據是下面的規模量測:嚴格判準下資安教材只解釋 **3.6%** 的 FP,寬到不可辯護的
判準下也只有 **22%**。分流買不到修正,只買到數字變好看 —— 而這個 repo 今晚整晚
都在修「閘報出它從未取得的 clean」,再造一個同類缺陷是不可接受的。

## 1. 前人做過什麼(不重造,不推翻)

`47d75f33a` (2026-06-21) 的稽核 `docs/research/precision-repair-broad-rules-2026-06-21.md`
已經把同一個問題分成兩群並分開處置,而且**只有一群被隔離**:

| 母體 | 規模 | 處置 | 理由 |
|---|---:|---|---|
| 真越獄樣本被標成 benign(DAN persona / ethics bypass) | 86(0.13%) | **隔離** `_contamination-jailbreak.txt` | 標籤錯誤 —— 同一批樣本在 `dan-corpus.json` 裡是 true positive,一份母體兩個相反標籤 |
| dual-use SEO 模板(`ignore all previous instructions … [TARGETLANGUAGE]`) | 675(1.04%) | **留在 benign gate** | 不是攻擊。規則對它們開火就是真 FP |

該文的政策原句:

> A dual-use security skill that legitimately contains attack techniques is not a
> false positive to suppress by blunting the rule; it is an advisory-tier signal
> the consumer decides on. Blunting the deterministic rule to hide it would lose
> real detections.

以及它對「語料該往哪走」的指示是**擴大**而非縮小:

> Expand the benign gate with representative wild-scan dual-use / doc / legit-MCP-
> config samples, so the gate measures the real distribution the rules face.

而且該次稽核已經量過同一個問題的答案:清掉 86 條污染只把 65K FP 率從 8.0% 挪到
7.9% ——「殘留 FP 是 dual-use intent,只有語意/情境層能分開,不是清語料或鈍化
regex 能解的」。

**資安教材是第 2 群的近親,不是第 1 群。**本次裁定延伸該政策,沒有推翻它。
(相關但不同的機制:PR #373 的 benign 語料採集器帶 jailbreak-exclusion filter,
擋的是「採集時就別把攻擊收進來」,與「已在語料裡的教材怎麼處置」是兩件事。)

## 2. 規模(腳本量的,不是 LLM 數的)

判準 = `src/corpus/security-content.ts`:**逐字攻擊 payload ≥1** ﹠
**相異資安主題標記 ≥2**。只提 OWASP 不算,只出現 `../../` 也不算。

| | 樣本數 | 佔語料 | 貢獻 FP | 佔 14,561 |
|---|---:|---:|---:|---:|
| **嚴格判準**(payload AND ≥2 主題) | 37 | 0.69% | **526** | **3.61%** |
| 寬鬆上界(payload OR ≥1 主題) | 642 | 12.0% | 3,212 | 22.1% |

來源分佈(嚴格判準的 37 條):

| 來源檔 | 樣本 | FP |
|---|---:|---:|
| `data/benign-corpus-extended/skills-sh.jsonl` | 31 | 439 |
| `data/benign-corpus-extended/wild-fp-confirmed.jsonl` | 6 | 87 |
| 其餘 6 個來源(arxiv / npm / pypi / official-skills / agent-ops / benign-code / skill-benchmark md) | 0 | 0 |

FP 前 20 大規則(佔全部 FP 的 89.2%)的分段:

| 規則 | FP 總 | 一般 | 資安內容 | 自宣告 TP |
|---|---:|---:|---:|---:|
| ATR-2026-00061 | 2814 | 2777 | 37 | 0/2 |
| ATR-2026-00012 | 1672 | 1637 | 35 | 7/10 |
| ATR-2026-00454 | 1337 | 1315 | 22 | 8/8 |
| ATR-2026-01610 | 1180 | 1165 | 15 | 3/4 |
| ATR-2026-00066 | 1035 | 1011 | 24 | 0/3 |
| ATR-2026-00020 | 739 | 732 | 7 | 5/5 |
| ATR-2026-00063 | 637 | 614 | 23 | 0/2 |
| ATR-2026-00217 | 588 | 576 | 12 | 5/5 |
| ATR-2026-00142 | 426 | 409 | 17 | 5/5 |
| ATR-2026-00064 | 403 | 383 | 20 | 0/2 |

(其餘 10 條的分段比例一致,均在 1–10% 區間。重現指令:
`npx tsx scripts/measure-security-content-fp.ts` —— 它把全部規則跑在被標記的 37 條上,
輸出即 526/14,561 這個頭條數字。)

**這張表就是裁定的依據。**前 20 大規則的資安內容佔比是 1.3%。最大的單一 FP 源
ATR-2026-00061 有 2,814 個 FP,其中 37 個落在資安內容上 —— 它的 FP 根本不是教材
問題,是規則自己在註解裡承認的結構問題(`condition: any` 疊五個能力原語,
`exec` 無字界匹配到 "execution",`\$\{?[A-Z_]+\}?` 匹配到每個 README 印過的
shell 變數)。

**順帶抓到的**:00061 / 00066 / 00063 / 00064 / 00062 在 gate 的事件形狀下,
對自己宣告的 true positives 是 **0 命中**。幾千個 FP 配上零自證 —— 這是獨立於
本線的問題,已記在此。

## 3. 兩個實驗(可驗證,不是論證)

### 實驗 A —「規則可以變聰明」:部分證偽

改法:把 `condition: any` 疊加的獨立指標,改成 `condition: all` 要求
**credential artifact** 與 **執行原語 / 外傳目的地**共現。
recall 用 6,709 筆攻擊樣本量(全 repo 規則的 `test_cases.true_positives`
+ garak in-the-wild + llm-guard + promptfoo + nemo-guardrails + promptinject),
不是只用規則自己的 5 條 test case。

重現:
```
npx tsx scripts/measure-rule-fp-segmented.ts <rulesDir> <ATR-id...>   # FP + 分段 + 自宣告 TP
npx tsx scripts/measure-rule-recall-ab.ts <baseRulesDir> <variantRulesDir> <ATR-id...>  # A/B attack recall
```

| 規則 | FP | 攻擊 recall | 判讀 |
|---|---|---|---|
| ATR-2026-00113 | 332 → **118**(−64.5%) | 94 → **31**(−67.0%) | 自宣告 TP 5/5 → 1/5 |
| ATR-2026-00217 | 588 → **31**(−94.7%) | 14 → **5**(−64.3%) | 自宣告 TP 5/5 → 5/5 |

兩點必須講清楚:

1. **共現要求確實砍得動 FP,但不是免費的。**兩條都付出約 2/3 的攻擊 recall。
2. **只看規則自己的 test case 會得到相反結論。**00217 的自宣告 TP 是 5/5 不變 ——
   因為它那 5 條剛好都含外傳動作。放到 6,709 筆攻擊語料才看得到 −64%。
   **「規則變聰明」的 recall 不可以用規則自己的 test case 量。**

3. **它砍掉的不是資安教材的 FP。**00113 的資安內容 FP 只從 28 掉到 14,一般 FP
   從 304 掉到 104。也就是說共現要求修的是「一般 benign 上的過度開火」,
   跟教材無關 —— 又一個「教材不是問題根因」的獨立佐證。

結論:regex 層可以用共現換 precision,交換率大約是「砍 64–95% FP 換掉 64–67%
recall」。**要不付 recall 就得到 precision,需要 regex 以外的層** —— 這與
2026-06-21 的結論(「只有語意/情境層能分開 dual-use intent」)一致。

### 實驗 B —「標記分流」:規模不足以成為解法

見上表。嚴格判準 3.61%,寬鬆上界 22.1%。而寬鬆判準會把 12% 的 benign 語料標成
「資安內容」,那個口徑站不住(它會撞爆 `SECURITY_CONTENT_BUDGET` ratchet,而且
在真攻擊語料上的標記率會跳到 2.9%,撞爆 `LAUNDERING_CEILING`)。

**所以 (B) 的實質面不採用。**

## 4. 判準與防濫用

判準寫在 `src/corpus/security-content.ts`,可腳本化、可重跑、可被人審(regex
清單全部攤開)。四道防線,每一道都是 `tests/benign-gate-security-content.test.ts`
的斷言,不是註解:

| # | 濫用方式 | 防線 | 現值 |
|---|---|---|---|
| 1 | 判準放寬成掃地機 | `SECURITY_CONTENT_BUDGET` = 2% | 實測 37/5352 = 0.69% |
| 2 | 把真攻擊標成「教材」洗白 | `LAUNDERING_CEILING` = 1%,對規則自宣告 TP 與 garak in-the-wild 各測一次 | 實測 1/3805 = 0.03% · 0/650 = 0.00% |
| 3 | 結果導向(看哪些樣本害我 FP 再反推判準) | 判準模組零 import,拿不到引擎/規則 id/FP 計數;測試斷言之 | — |
| 4 | 分段被拿去縮小語料或改變判定 | 測試斷言 `partitionByFp()` 與 `resolveExitCode()` 的引數不得出現 `security`;並斷言 `general + security == total` | — |

**`LAUNDERING_CEILING` 是實測校準出來的,不是憑感覺挑的。** 原本訂 5%,然後刻意
把攻擊語言(`ignore all previous instructions`、`do anything now`、
jailbreak / DAN / prompt injection)偷渡進 payload 與主題清單 —— 這是最典型的
洗白手法。結果 garak 標記率跳到 3.85%,**5% 沒有咬住**。上限因此收到 1%,
再破壞一次確認會紅(2.92% > 1%),還原後綠。

ratchet 已親自破壞兩次確認會紅:
- 判準由 AND 放寬成 OR → 預算斷言紅(6.65% > 2%)+ 窄口徑斷言紅。
- 攻擊語言偷渡進清單 → 洗白斷言紅(2.92% > 1%)。
兩次都還原,還原後 8/8 綠。

## 5. gate 的輸出怎麼變

`scripts/gate-promotion-fp.ts` 多印兩行,**headline / clean·dirty / exit code
完全不變**:

```
[fp-gate] corpus split — security-content 37/5352 (0.7%) · general 5315
[fp-gate] FP split — general N · security-content M (x% of total).
          Both are false positives; the outward number is the total.
```

dirty 清單每條後面附註 `(M on security content)`。**一條 400 FP 全部落在資安
內容上的規則,照樣 FAIL 這道閘。**

## 6. 對外數字口徑

`state/benchmark-claims.json` 的 `benign-gate-fp` 條目維持 `status: MISLABELED`、
`outward_safe: false` —— 本線沒有解決它的效度缺口(「65K」標籤掛錯語料、
兩個 lane 數字都還沒在新語料上重測)。本線新增的是:

- 這次量到的硬數字(5,352 / 776 effective / 14,561 FP / 178 dirty)連同條件。
- **新增禁令:分段出來的「一般 benign FP」永遠不可單獨對外引用。**
  對外的 FP 數字是總數。分段是內部診斷用的,不是折扣。

## 7. 沒做到的 / 留給下一手

- **14,561 是真債,本線沒有還。**它主要由少數結構性過寬的規則造成
  (00061 一條 2,814),不是語料問題。
- 5 條規則(00061/00062/00063/00064/00066)在 gate 的事件形狀下對自己宣告的
  true positives 零命中,值得獨立一線。
- 判準是 regex,對「引用 payload」與「執行 payload」的區分能力有上限;
  真正的分辨要語意/情境層 —— 與 2026-06-21 的結論相同,七週內兩次從不同方向
  撞到同一堵牆。
