# 開發過程記錄

這份文件記錄 `bastet-plus` 開發過程中的判斷、踩到的問題，以及**在看到實驗結果之後才做的修改**。

寫這份的原因很直接：這個專案主張「每個 finding 都要有證據」，但它自己的開發過程原本沒有留下任何證據。整包程式是在一個**沒有版本控制**的工作目錄裡寫完的，最後才複製進 clone、以**單一 squashed commit** 推上去。所以沒有 commit 序列可以還原過程，這份文件是事後補的替代品，可信度低於真正的 git 歷史，這點必須先說清楚。

---

## 1. 最該揭露的一件事：benchmark 是在看到模型輸出之後改過的

`benchmark/cases/` 的案例和 `benchmark/labels.json` 的標註**都是我自己寫的**，而且我在跑過模型、看到輸出之後修改過其中 4 個案例。

具體是這樣發生的：第一次對 `slippage_vuln_01.sol` 做端到端測試時，`access_control__1` detector 回報「`harvest()` 沒有權限控制，任何人都能呼叫」。這在真實 vault 設計裡是可辯護的發現 —— permissionless harvest 很常見（keeper 會呼叫），但配上零滑點保護就是三明治攻擊的入口。可是我的標註說這個檔案只有 `slippage` 這一類，所以它會被計為誤報。

我的處理是**修改案例**：幫 `harvest()` 加上 `onlyStrategist`，讓它跟安全版 `slippage_safe_01.sol` 只差在滑點保護。同一批我還改了：

| 檔案 | 改了什麼 | 為什麼 |
|---|---|---|
| `slippage_vuln_01.sol` | `harvest()` 加 `onlyStrategist` | 消除 access_control 的合理讀法 |
| `access_control_vuln_01.sol` | `sweep()` 的 `transfer` 加 `require` | 消除 unchecked_call 的合理讀法 |
| `randomness_vuln_01.sol` | `drawWinner()` 加 operator 檢查 | 消除 access_control 的合理讀法 |
| `reentrancy_vuln_02.sol` / `_safe_02.sol` | `stake()` 真的去 `transferFrom` NFT | 原本的簡化寫法本身就是個 bug |

**這件事的性質要講清楚。** 往好處說，這讓每個案例只帶一個漏洞類別，是受控實驗該有的樣子。往壞處說，這是**拿 benchmark 去遷就 harness 的輸出** —— 我看到什麼被扣分，就去改扣分的來源。在真實資料集上你沒有這個權力。

因此 `RESULTS.md` 的數字必須理解成 **dev-set 數字**，不是泛化估計。

## 2. 第二件：報告的配置是在報告的同一組資料上選出來的

我跑了四個配置（原版、verification off、同模型 verifier、強 verifier），在**同一組 20 個檔案**上比較，然後把表現最好的「強 verifier」當成建議配置寫進 README。

這就是在測試集上做模型選擇。正確做法是 train/dev 調參、test 只碰一次。我沒有這麼做，因為只有一組 20 個檔案 —— 而那組也是我自己寫的。

## 3. 第三件：`## Discipline` block 不是純 harness 改動

`IMPROVEMENTS.md` 原本宣稱「detector prompt 原封不動，只換掉 output contract 區塊」，因此 A/B 量的是 harness 而非 prompt。

用 `tools/prompt_diff.py` 機械化產生 diff 之後，發現這個說法**不完全成立**。附加到每個 prompt 的其實有兩塊：

1. `## Output contract` —— 由 `schema.py` 產生，純格式，取代原版那個跟 schema 對不上的區塊。這塊算 plumbing。
2. `## Discipline` —— **不是 plumbing**。它告訴模型「已經在可見範圍內實作的防護不算漏洞」「不確定就降低 confidence 而不是略過」。這是反誤報的**偵測指引**，438 個字元，本身就可能推高 precision。

所以 legacy vs enhanced 的比較**不是乾淨的 harness-only A/B**。已經加了 `--no-discipline` 讓這個混淆因子可以被單獨量測，量測結果見 `RESULTS.md`。

---

## 4. 過程中踩到的問題

按發生順序：

**第一次 benchmark run 整輪作廢。** 用 `python ... | Tee-Object -FilePath "benchmark_results\run.log"` 想同時留 log，但 `benchmark_results\` 目錄還不存在，Tee-Object 直接失敗並吃掉整條 pipeline 的輸出。process 還在跑但看不到任何進度。整輪砍掉重跑。教訓：要留 log 就在程式裡留，不要靠 shell pipeline。

**grounding 的空白正規化不夠。** 一開始只把連續空白 collapse 成單一空格，結果模型只要重新排版（`swap(a, 0, path)` 變成 `swap( a , 0 , path )`）就比對不到，證據驗證會誤殺真 finding。改成**完全移除空白**再比對，並把最小比對長度提高到 8 個字元避免 `return;` 這種雜訊。方向上刻意選寬鬆 —— 這個過濾器是在**丟掉** finding，漏判的代價是 recall。

**`dedupe._merge` 把 provenance 截斷（嚴重）。** 合併後的 detector 來源字串原本只保留前 3 個名字加 `...`。但下游 `metrics.evaluate` 正是用這個字串把 finding 歸類到漏洞類別的，所以被截掉的 detector 等於該類別的預測消失了。

實際後果：`randomness_vuln_01.sol` 上 enhanced 確實正確報出「drawWinner 的隨機性可預測」，但 `owasp2025__7` 被截進 `...` 裡，評分把它算成 randomness 的**漏報**，同時把 access_control 和 oracle 算成**誤報**。造成兩個假的 regression（randomness、unchecked_call 各少一個 TP）。修正後 recall 從 0.667 升到 0.889。

**教訓：任何會被下游拿去做分類歸屬的字串，都不能為了顯示美觀而截斷。**

**`dedupe._similar` 把共用的 function 名當成相似證據。** 修完上一個之後，端到端測試出現同一個 `withdraw()` 上兩筆幾乎相同的 reentrancy finding 沒有合併 —— 因為相似度是算在 summary+description 上，兩個 detector 的 rationale 差很多，稀釋掉了。改成 summary 單獨算一次、summary+description 算一次取較寬鬆者。

結果**過度合併**：reentrancy finding 和 unchecked_call finding 被併成一筆，因為它們唯一的共同 token 就是 `withdraw`。最終修法是**在算相似度前把 function 名從 signature 裡剔除** —— 位置已經由 function 名比對這一關把守，signature 應該只描述「是哪一類 bug」。

**我自己製造了 mojibake。** 用 `Get-Content ... | Set-Content -Encoding utf8` 改寫 `RESULTS.md`，PowerShell 的文字 roundtrip 把 em-dash 和 `×` 全變成 `?`。諷刺的是我當時剛寫完「原版 prompt 有 mojibake」那一節。教訓：改檔案不要走 PowerShell 文字 pipeline。

**file-level 指標是事後才加的。** 一開始只有 per-(file, class) 一種評分。跑完強 verifier 那組之後才發現「11 個乾淨檔案全部零告警」這個結果在 per-class 指標上完全看不出來（因為殘餘誤報全部落在**確實有漏洞**的檔案上，只是類別標錯）。回頭補了 `EvalResult.file_level`。這是指標設計不足，不是 bug，但同樣是「看到結果才決定怎麼量」的例子。

---

## 5. 沒有做、但應該做的量測

- **污染（contamination）。** 這些 detector 針對的是公開的 Code4rena 稽核報告，2020–2024 那批幾乎確定在模型的預訓練資料裡。分數有多少來自記憶而非偵測，完全沒量。可行做法是切 competition 截止日前後的 repo 做對照。
- **切片（slicing）。** `benchmark/cases/` 每個檔案都小於 12 000 字元的切片門檻，所以 `--no-slice` 在這個 benchmark 上是 no-op。這項改動從來沒被量過。
- **在真實資料集上跑。** 見 `RESULTS.md` 的 caveats：標註粒度、上游評分協定的天花板、以及成本，三者都擋著。

---

## 6. 已修正的流程缺失

| 缺失 | 現況 |
|---|---|
| 開發過程無版本控制 | 已記錄於此。後續改動應該逐項 commit |
| 沒有 LLM 呼叫記錄 | 已加 `--log-calls PATH`，輸出 JSONL，含完整 messages、回應、usage、latency、走到 structured-output ladder 哪一階 |
| response cache 不能當稽核紀錄 | cache 的 key 是 request 的 sha256，只存回應。它能告訴你模型說了什麼，永遠無法告訴你它被問了什麼。這是 `--log-calls` 存在的原因 |
| run log 只在暫存目錄 | 已收進 `docs/run_log_llama70b_2026-07-26.txt` |
| prompt 改動只有文字描述 | 已加 `tools/prompt_diff.py`，可機械化產生；輸出存於 `docs/` |
