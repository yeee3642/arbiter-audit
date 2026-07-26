# Bastet+

[OneSavieLabs/Bastet](https://github.com/OneSavieLabs/Bastet) 的 harness 重建版。

56 支漏洞偵測 prompt 原封不動從上游的 n8n workflow JSON 抽出來重用，但外圍的骨架全部換掉：
沒有 n8n、沒有 Docker、沒有 Postgres、沒有 webhook。一個只用標準函式庫的 Python 套件，
直接對任何 OpenAI 相容端點說話，外加原本管線缺少的四件事 —— 原始碼切片、自洽性取樣、
證據落地驗證、對抗式複核。

| 文件 | 內容 |
|---|---|
| [`IMPROVEMENTS.md`](IMPROVEMENTS.md) | 逐項缺陷與修法（英文） |
| [`RESULTS.md`](RESULTS.md) | A/B 量測、trivial baseline、以及為什麼這些數字不能當泛化估計 |
| [`DECISIONS.md`](DECISIONS.md) | 開發過程記錄：踩到的問題，以及在看到結果之後才做的修改 |
| [`CHANGE_MAP.md`](CHANGE_MAP.md) | 原版檔案 → 新模組的對照，含可自行驗證的指令 |

---

## 先讀這段：這些數字能宣稱什麼

在 `ais3/llama-3.3-70b` 上、20 個檔案、18 支 detector、兩邊同模型同端點：

| | per (file,class) F1 | file-level F1 |
|---|---|---|
| 恆答「有漏洞」（trivial baseline） | 0.140 | 0.621 |
| 恆答「有漏洞」，除檔名 `clean_*` 外 | 0.154 | 0.667 |
| **原版 harness** | **0.111** | **0.667** |
| Bastet+，同模型 verifier | 0.210 | 0.667 |
| Bastet+，強 verifier，**純 harness 改動** | **0.333** | 0.900 |
| Bastet+，強 verifier + Discipline prompt 區塊 | 0.302 | **1.000** |

正確的讀法是：**原版低於常數基線，Bastet+ 跨過去了** —— 而且三個配置裡只有一個真的跨過。
不是「F1 提升 2.7 倍」。原版的 0.111 低於恆答 yes 的 0.140；原版與 Bastet+ 同模型 verifier
的 file-level 分數都跟 trivial baseline 一模一樣，在檔案層級無法與常數答案區分。

**而且連這個改善也只有部分經得起檢定**（`tools/significance.py`，輸出見 `docs/significance.txt`）：

| 差異 | 檢定 | 判定 |
| --- | --- | --- |
| Precision 0.061 → 0.182 | 兩比例 z, p = 0.024（觀測叢集在 20 檔內，偏樂觀） | 有跡象，未確立 |
| Recall 6/9 → 8/9 | McNemar p = 0.50 | **沒有證據** |
| File-level 0.667 → 1.000 | 分母 9，95% CI [0.70, 1.00] | 方向明確，幅度未定 |

真陽性 (檔案,類別) 配對總共只有 **9** 個，乾淨檔只有 **11** 個。recall 那 22 個百分點的
差異實際上是**兩個案例**。

附加到 prompt 的 `## Discipline` 區塊不是純 plumbing，已用 `--no-discipline` 單獨量過：
它壓掉 2 個乾淨檔的告警（file-level 滿分因此有一部分要歸功於 prompt 而非 harness），
代價是吃掉一個真陽性。純 harness 的改動仍然大幅跨過 trivial baseline。

**這些是 dev-set 數字，不是泛化估計。** benchmark 是我自己寫的、標註也是我自己標的，
而且我在看到模型輸出之後改過其中 4 個案例，最後又在同一組資料上挑出「較強 verifier」
這個建議配置。細節與其他保留意見見 [`DECISIONS.md`](DECISIONS.md) 與 `RESULTS.md`。

真正站得住、不依賴任何資料集或我的標註的，是 `IMPROVEMENTS.md` 裡那些讀原始碼就能驗證的
缺陷：severity 278/278 被默默改寫成 `high`、61% 的回應不是純 JSON、`while True` 無逾時輪詢、
評估程式的四個 bug。

---

## 快速開始

```bash
cp .env.example .env    # 把 BASTET_LLM_BASE_URL 指向你的模型
python -m bastet_plus packs
python -m bastet_plus scan path/to/contracts --packs slippage,owasp2025
```

除了 Python 3.10+ 標準函式庫之外沒有任何相依。

建議配置是非對稱的 —— 偵測用便宜模型，複核用較強模型：

```bash
python -m bastet_plus scan contracts/ --samples 3 --verifier-model <stronger-model>
```

### 跑 A/B

```bash
python -m bastet_plus bench --samples 3
```

## 架構

```
contract.sol
     |
     v
[ slicing.py ]      Solidity 切片。每個切片都帶著所屬合約的 pragma、import、
     |              狀態變數與 modifier，所以函式不會在看不到 storage 的情況下被判斷。
     |              *** 此項從未被量測 —— benchmark 檔案全部小於切片門檻 ***
     v
[ detectors.py ]    56 支從 n8n workflow 抽出的 detector prompt。輸出契約由
     |              schema.py 產生而非逐支手寫，所以不會走鐘。
     v
[ llm.py ]          重試 + 退避 + 逾時 + sqlite 回應快取 + token 計費。
     |  x k         structured output 階梯：json_schema -> json_object -> 文字擷取 -> 修復。
     v
[ dedupe.py ]       自洽性投票。候選必須被多數取樣產生才留下。
     v
[ grounding.py ]    引用的程式碼真的存在於原始檔嗎？零 token 成本的誤報過濾，
     |              同時產生行號。
     v
[ verify.py ]       全新的一次呼叫，框架設定為「反駁」，必須說得出具體攻擊路徑
     |              才留下。
     v
[ dedupe.py ]       跨 detector 去重，一個 bug 一行。
     v
[ report.py ]       md / json / csv / sarif
```

## 指令

| 指令 | 用途 |
|---|---|
| `packs` | 列出 detector pack |
| `scan <path>` | 掃描檔案或目錄；`--legacy` 改跑原版單次呼叫管線 |
| `bench` | 在標註 benchmark 上 A/B 兩條管線 |

常用旗標：

| 旗標 | 效果 |
|---|---|
| `--samples N` | 自洽性：每支 detector 跑 N 次，取多數 |
| `--verifier-model` | 複核用不同（較強）的模型 |
| `--no-verify` | 關掉對抗式複核 |
| `--no-slice` | 整檔送入，與原版相同 |
| `--keep-ungrounded` | 保留引用程式碼找不到的 finding |
| `--no-discipline` | 剝掉 prompt 裡的 Discipline 區塊，用來區分「prompt 的貢獻」與「harness 的貢獻」 |
| `--log-calls PATH` | 每次 LLM 呼叫寫一行 JSONL（完整 messages、回應、usage、延遲） |
| `--min-severity` | 嚴重度下限 |
| `--no-cache` | 略過回應快取 |

每個旗標對應一項改動，可以逐項 ablate。

## 稽核用的產出

| 檔案 | 內容 |
|---|---|
| `benchmark_results/comparison_*.json` | 每個 arm 的完整 findings、per-file 預測、stats |
| `docs/run_log_llama70b_2026-07-26.txt` | A/B 那次跑的 console log |
| `docs/significance.txt` | 顯著性檢定：哪些差異真的有證據支持 |
| `docs/prompt_change_summary.txt` | 56 支 prompt 的機械化改動摘要 |
| `docs/prompt_diff_example.txt` | 單支 prompt 的完整 unified diff |
| `--log-calls` 的 JSONL | 完整請求/回應記錄（預設關閉，會內嵌合約原始碼） |

**回應快取不能當稽核紀錄。** 它的 key 是 request 的 sha256，只存回應 —— 能告訴你模型說了
什麼，永遠無法告訴你它被問了什麼。這就是 `--log-calls` 存在的理由。

## Benchmark

`benchmark/cases/` 有 20 個標註過的 Solidity 檔案：9 個有漏洞、11 個乾淨。每個有漏洞的案例
都配一個功能等價的安全雙胞胎，只差在受測的那道防護。

配對是重點。一個看到 swap 就喊「滑點！」的偵測器在有漏洞的那一半可以拿到 100% recall
而毫無用處。安全雙胞胎才讓 precision 可量測。

這是替代品，不是真實資料集的替換 —— 上游的 Bastet 資料集（450 個 Code4rena 專案、
約 4 400 個 findings）透過 Google Drive 發佈，不在 repo 裡。為什麼它在這個專案跑不起來，
見 `RESULTS.md`。

## 與上游的關係

detector prompt 是 Bastet 作者的成果，除了輸出契約區塊之外原封不動使用。
`tools/extract_prompts.py` 可從 `n8n_workflow/*.json` 重新產生 `prompts/legacy/`，
所以上游的 prompt 更新可以一行指令跟上。
