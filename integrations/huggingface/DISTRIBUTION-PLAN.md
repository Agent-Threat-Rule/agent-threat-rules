# ATR × Hugging Face 分發計劃(2026-07-10)

品牌線:ATR 獨立標準線 — 全程只提 ATR/pyatr,絕不提 PanGuard。
定位:HF hub = 分發面(上架自己的 Dataset/Space/Model),不是「PR 進別人 repo」。smolagents PR 已另走(#2489)。

現況盤點(現驗):
- ATR 在 HF 上零足跡(greenfield)。需先認領 HF org handle(建議 Agent-Threat-Rule,對齊 GitHub org)。
- pyatr 已上 PyPI v0.2.6,bundled 規則可用 → Space 可零改動直接跑。
- 技能安全語料:466 benign + 32 malicious 的 SKILL.md(直接數得),benign 含 evasive 硬負樣本。
- 論文:Zenodo DOI 10.5281/zenodo.19178002。
- UK AISI Inspect @task wrapper 已存在(HF-adjacent eval 生態已有一腳)。
- 規則總數目前有漂移(disk 675 / stats.json 655 / main 708~713 不一致)→ 計劃一律不硬寫規則總數,dataset 用實測語料數。

---

## 優先序(ROI ÷ 摩擦)

### 1. Gradio Space(live demo)★ 旗艦 · ⚠️ 卡 HF 付費牆(2026-07-10 實測)
狀態:app.py + requirements.txt + README(Space card)已建於 space/,pyatr 整合已驗(惡意→critical、良性→0 誤報、語法 OK)。
⚠️ 血的教訓:HF 已把免費 Gradio/Docker Space 收掉 — create_repo 回 402:org 需 Team/Enterprise、個人需 PRO。免費只剩 Static Space。org 與個人兩命名空間都試過都 402。
可行路徑(擇一,待用戶決定):
  (a) PRO 訂閱(~$9/月)→ 個人 RKUANAT/agent-threat-scanner 跑真 pyatr 引擎;
  (b) Static Space(免費+可掛 org)→ 但要把 pyatr 引擎忠實移植成 client-side JS(零寬正規化/normalized-raw 雙搜/event_type 欄位路由含 TS 相容怪癖/any-all 邏輯 + 1.37MB 規則 bundle)= 真專案有分歧風險,非快速 demo;
  (c) 暫不發(建議)→ Dataset 已扛公信力,demo 程式碼在 space/ + README 連過去,想跑的人自 pip install。
regex 相容性已查:2230 patterns 中 1225 條 (?i) 前綴(可轉 JS i flag)、0 條中段內聯 flag、lookbehind 現代 JS OK — 靜態移植難點在引擎語意層不在 regex 層。

### 2. Dataset(技能安全 benchmark)★ 可信度 · 佔位獨佔
內容:466 benign + 32 malicious 的 SKILL.md,轉成 HF-loadable(JSONL/parquet),欄位建議:text / label(benign|malicious) / attack_type / source。
差異化:目前公開的「SKILL.md 攻擊偵測 benchmark + 硬負樣本」幾乎沒有,ATR 幾乎獨佔這個 niche。
Dataset card:引 benchmark/METHODOLOGY.md 出處 + DOI + 明確授權;lane 化 precision 講清楚(不吹 0.3%)。
安全考量:惡意樣本要清楚標註;真正可武器化的 payload 考慮 defang 或只留 label/pattern。
效率:半天(寫一支 convert 腳本 + 卡片)。
未來 Phase 2(重安全審):wild scan 確認 malware 語料(96,096 掃描 / 751 確認)另議,涉真惡意樣本公開的法遵/倫理,先不做。

### 3. HF Papers — 誠實限制:arXiv-centric
HF Papers 主要索引 arXiv。ATR 論文在 Zenodo 非 arXiv → 無法直接上 HF Papers。
選項:(a) 只在 Space/Dataset 卡片連 DOI(link-only,零成本,先做);(b) 若要進 HF Papers,得先把論文放上 arXiv(另一個決策,不在本計劃硬推)。
不要對外宣稱「ATR 在 HF Papers」直到真的有 arXiv id。

### 4. Model(encoder 分類器)— 未來 · 卡在未訓練
主權語意層的 encoder(ModernBERT/DeBERTa)目前 tighten-only 接口已建、未開訓(memory)。
不能上架不存在的模型。這是 HF 最「對」的長期用法,但屬 Phase 2,等訓練完成再上。
不寫任何「模型已上 HF」的假宣稱。

---

## 兩道閘(任何上線前)
1. 背壓:approvals 現積壓 33 份(7 過期)≥ 門檻。發布=對外動作 → 先清佇列再上線(python3 bin/expire-stale-approvals.py 先 dry-run)。
2. HF 授權:huggingface-skills MCP 本 session 未授權(非互動無法 OAuth)。上線需 (a) 互動 session 授權該 MCP,或 (b) huggingface_hub CLI + HF token。
   secret 紀律:HF token 走 env / huggingface-cli login,絕不進 argv。

## 建議執行順序
org handle → Space(旗艦,已 ready)→ Dataset → 卡片 link 論文 DOI → (未來) arXiv + Model。
每個「上線」動作照鐵律:做好 → 送出前停下貼回你確認 → 才 push。
