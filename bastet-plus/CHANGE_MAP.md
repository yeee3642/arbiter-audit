# 變更對照表：原版 → Bastet+

`IMPROVEMENTS.md` 用文字描述改了什麼。這份是機械化的檔案層級對照，方便逐項驗證。

**必須先講的限制：** `bastet-plus` 是**重寫**不是 patch，跟上游沒有共同的 git 祖先，所以
`git diff` 這種東西不存在。下表是人工對應，只有行數是機械抓的。唯一能機械驗證的部分是
detector prompt（見最後一節）。

---

## 1. 檔案對照

### 有對應關係的

| 原版 | 行數 | Bastet+ | 行數 | 說明 |
|---|---:|---|---:|---|
| `cli/commands/scan/scan.py` | 196 | `bastet_plus/pipeline.py` | 225 | 掃描主流程。原版的 n8n webhook + `while True` 輪詢換成直接呼叫；新增切片、多次取樣、驗證階段 |
| `cli/commands/evaluate/eval.py` | 132 | `bastet_plus/metrics.py` | 183 | 評估。修掉提早 break、跨類別誤計分、除以零、無 seed 抽樣四個問題；評分單位改成 (file, class)，加 file-level 與 Wilson 區間 |
| `cli/models/audit_report.py` | 16 | `bastet_plus/schema.py` | 233 | finding 結構。原版把缺失的 severity 默默改寫成 `high`；新版 schema 為唯一真相來源，prompt 的輸出契約由它產生，所有代換都記錄在 `coerced_fields` |
| `cli/utils/report_generator/*.py` | 176 | `bastet_plus/report.py` | 124 | 報表輸出。移除 pdf，新增 SARIF |
| `cli/main.py` + 各 `__init__.py` | 136 | `bastet_plus/cli.py` | 162 | CLI 進入點 |
| `n8n_workflow/*.json` | 334 KB | `prompts/legacy/*.md` | 57 檔 | 56 支 detector prompt。由 `tools/extract_prompts.py` 抽出，可重跑 |

### 沒有對應、直接捨棄的

| 原版 | 行數 | 為什麼不帶過來 |
|---|---:|---|
| `cli/http_client/n8n/**` | 736 | n8n REST API 的非同步 SDK。全專案只有 `check.py` 用到，而 `check.py` 本身是誤入版控的範例程式（裡面寫死了開發者本機的 `project_id = "ERfhTxouVBTw1wVo"`）。其中 `config/http_config.py`、`config/__init__.py` 是 0 位元組空檔。Bastet+ 沒有 n8n 可以講話 |
| `cli/check.py` | 131 | 同上，死碼 |
| `cli/models/n8n/*.py` | 75 | n8n execution / webhook node 的型別 |
| `cli/commands/init/import_workflow.py` | 141 | 把 workflow 匯入 n8n。沒有 n8n 就不需要 |
| `docker-compose.yml` / `Dockerfile` / `init/01-n8n.sql` | — | Docker + Postgres + n8n 的部署堆疊。84 KB 的 SQL 是 n8n 的初始資料庫 |
| `cli/commands/fetch/fetch.py` | 54 | 從 Etherscan 抓鏈上合約。功能正常，只是與 harness 無關，沒有必要重寫 |

### 全新、原版沒有對應物的

| Bastet+ | 行數 | 對應 `IMPROVEMENTS.md` |
|---|---:|---|
| `bastet_plus/llm.py` | 315 | A2、B6、B8。重試/退避/逾時、sqlite 回應快取、token 計費、structured-output ladder、`--log-calls` 逐次呼叫記錄 |
| `bastet_plus/slicing.py` | 237 | B1。Solidity 切片。**注意：這項從未被量測過**，benchmark 檔案全部小於門檻 |
| `bastet_plus/verify.py` | 101 | B3。對抗式複核 |
| `bastet_plus/grounding.py` | 121 | B4。證據落地驗證，同時產生行號 |
| `bastet_plus/dedupe.py` | 108 | B2、B5。自洽性投票與跨 detector 去重 |
| `bastet_plus/bench.py` | 174 | A/B 執行器 |
| `bastet_plus/config.py` | 75 | B6。環境變數設定 |
| `tests/test_offline.py` | 146 | 42 項離線測試，不需網路 |

**合計：** 原版 `cli/` 約 1 926 行 Python，其中約 1 080 行（56%）是 n8n 相關的膠水或死碼。
Bastet+ 為 2 218 行，加上測試與工具。

---

## 2. Detector prompt：唯一能機械驗證的部分

`tools/prompt_diff.py` 直接比對「原版 n8n 裡的文字」與「Bastet+ 實際送出的文字」：

```bash
python tools/prompt_diff.py              # 56 支的摘要表
python tools/prompt_diff.py slippage__0  # 單一支的完整 unified diff
```

輸出已存於 `docs/prompt_change_summary.txt` 與 `docs/prompt_diff_example.txt`。

結論：

- **56/56 支的漏洞知識段落與原版逐位元組相同。**
- 附加的內容有兩塊，性質**不同**：
  1. `## Output contract` — 由 `schema.py` 產生，純格式。取代原版那個與 schema 對不上的輸出區塊（`IMPROVEMENTS.md` A1）。
  2. `## Discipline`（438 字元）— **不是純格式**。它告訴模型「已在可見範圍實作的防護不算漏洞」「不確定就降低 confidence」。這是反誤報的偵測指引。

因此 legacy vs enhanced **不是乾淨的 harness-only 比較**。`--no-discipline` 可以把這塊剝掉單獨量測，結果見 `RESULTS.md`。

---

## 3. 怎麼自己驗證

```bash
# prompt 確實沒被動過知識段落
python tools/prompt_diff.py

# 原版的缺陷確實存在（對照 original/ 這個 clone）
#   severity 默默改寫
sed -n '18,22p' ../original/cli/models/audit_report.py
#   無 sleep、無逾時、無重試的輪詢
sed -n '99,116p' ../original/cli/commands/scan/scan.py
#   第一個命中就跳出
sed -n '64,70p' ../original/cli/commands/evaluate/eval.py
#   除以零
sed -n '131,134p' ../original/cli/commands/evaluate/eval.py

# 死碼確實沒人用
grep -rn "http_client" ../original/cli --include=*.py

# 所有數字可從原始輸出重算
ls benchmark_results/comparison_*.json
```
