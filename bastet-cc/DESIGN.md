# Bastet-CC 設計文件

版本 1.0（2026-07-25）。本文件是實作規格：介面、演算法、資料結構全部寫死，照抄即可動工。
所有日期以 2026-07-31 發表日倒推。所有隨機種子一律 `20260725`。

---

## 0. 設計原則（三條，衝突時依序讓步）

1. **公平對照優先於絕對分數。** 兩套系統（我們的 routed 管線、忠實模擬的 broadcast 管線）必須共用除了「規劃層」以外的一切：同一個 executor、同一個 parser、同一個 scorer、同一個模型。任何差異都要能指著一行程式碼說「差別只在這裡」。
2. **每個 LLM 產物都是版本化檔案。** 合成偵測器落地成 markdown、掃描結果落地成 JSONL、校準參數落地成 JSON。重現一個 run 不需要重跑任何 LLM 呼叫。
3. **宣稱分層，逐層落袋。** 成本、覆蓋率、評分缺陷三個宣稱已經實測落袋；F1 勝負是最後一層，輸了前三層仍然成立（見 §3.5）。

---

## 1. 工具架構

### 1.1 模組地圖

```
bastet_cc/
  solidity.py     [既有] index_repo() tree-sitter 函式級索引
  routing.py      [既有] fit()/route()/cost()/broadcast_cost()，Detector/Slice/Task
  evaluate.py     [既有] 修正版計分；本次新增 upstream_score() 忠實復刻上游缺陷版
  tags.py         [新] 標籤正規化與分類表
  llm.py          [新] 推理後端抽象
  prompts.py      [新] 三種 prompt 的組裝器 + 統一輸出 schema
  plan.py         [新] 雙模式規劃器（routed / broadcast），唯一的分岔點
  executor.py     [新] 非同步執行、快取、續跑
  findings.py     [新] Finding 資料結構 + LLM 輸出解析
  retrieve.py     [新] 語料知識庫（identifier Jaccard 檢索）
  verify.py       [新] detect→verify 對抗驗證
  aggregate.py    [新] repo 層級聚合與校準（本設計新增的第五層創新）
  runstore.py     [新] run manifest、task_id、結果存取
  synth/          [新] 偵測器合成
    localize.py     S1 證據定位
    induce.py       S2 模式歸納
    hints.py        S3 routing_hints 驗證
    gate.py         S4 品質閘門
    assemble.py     md 組裝與 index.json 更新
scripts/
  make_splits.py  產生並凍結 data/splits.json
  run_scan.py     CLI：掃描一組 repo（指定 mode / detector set / model）
  run_synthesis.py CLI：S1→S4 全流程
  run_eval.py     CLI：對一個 run 目錄計分（兩種 scorer）
  run_ablation.py CLI：E2 消融矩陣
  charts.py       簡報圖表（先載入 dataviz skill 再實作）
data/
  splits.json     凍結的 32/10/12 切分（D1 產生後不得再改）
  kb.json         檢索知識庫（S1 的副產品）
detectors/          56 個上游偵測器（既有）
detectors_synth/    合成偵測器（S4 通過後才進入）
runs/<run_id>/      每個 run 一個目錄
```

### 1.2 核心資料結構（寫死）

既有的 `Detector` / `Slice` / `Task` 不動，`Detector` 加兩個欄位（frontmatter 同步新增）：

```python
@dataclass
class Detector:
    # ... 既有欄位 ...
    required_hints: list[str] = field(default_factory=list)  # AND 語意的硬前置條件
    gated: bool = False        # S4 未過閘：finding 必須經 verifier confirmed 才計分
    synthesized: bool = False  # 是否為合成偵測器
```

`required_hints` 語意：routed 模式下，檔案的 identifier 集合必須**包含全部** required_hints 才產生 Task（`routing_hints` 維持既有 OR 語意）。用途：ERC777 偵測器寫 `required_hints: ["tokensReceived"]`、ERC1155 寫 `["onERC1155Received"]` 之類的硬守門，把類別性偵測器的 FP 在零成本處砍掉。`route()` 修改量：在既有 `idents & sig` 判斷前多一行 all-of 檢查。

```python
# findings.py
@dataclass
class Finding:
    repo: str
    detector_id: str
    tag: str            # 經 tags.canonical_tag() 正規化
    subtag: str
    severity: str       # "High" | "Medium" | "Low"
    path: str
    contract: str
    function: str
    description: str
    evidence: str       # 行號引用，如 "L42-L47"
    confidence: float   # 模型自評 0..1
    verdict: str        # "unverified" | "confirmed" | "rejected" | "uncertain"
    task_id: str

# llm.py
@dataclass
class LLMResult:
    text: str
    parsed: dict | None     # JSON 解析成功才有
    model: str
    input_tokens: int
    output_tokens: int
    latency_s: float
    attempts: int           # 含重試
    error: str | None       # timeout / rate limit / json_invalid / context_overflow
```

統一輸出 schema（兩種模式、手寫與合成偵測器、全部共用；定義在 `prompts.OUTPUT_SCHEMA`）：

```json
{"findings": [{
  "contract": "string", "function": "string", "vulnerable": true,
  "subtag": "string", "severity": "High|Medium|Low",
  "description": "string", "evidence": "string (line refs)",
  "confidence": 0.0
}]}
```

上游每個 chainLlm 節點有自己的 schema；改用統一 schema 是對 broadcast 忠實度的唯一偏離，
但這是共用 parser 的前提，且兩臂承受同樣的偏離，對照仍然成立。此偏離要寫進簡報的方法段。

### 1.3 介面（函式簽章層級）

```python
# tags.py
TAXONOMY: dict[str, list[str]]          # 38 主 tag -> subtags，從 Tag Definitions.md 手工轉錄一次
OUT_OF_TAXONOMY = {"XSS Attack", "RCE", "Multisig", "Rebalance"}
def canonical_tag(raw: str) -> str      # 大小寫摺疊（Logic error -> Logic Error）、strip
def explode_labels(df: pd.DataFrame) -> pd.DataFrame
    # 多標籤列炸開成一列一 tag；新增欄 canonical_tag, in_taxonomy(bool)
    # OUT_OF_TAXONOMY 保留但 in_taxonomy=False：不合成偵測器、不進主計分、附錄單獨報告

# llm.py
class LLMClient:
    def __init__(self, base_url: str, api_key: str, model: str,
                 max_concurrency: int = 32, timeout_s: int = 120,
                 max_retries: int = 3, log_path: Path | None = None): ...
    async def complete(self, system: str, user: str,
                       schema: dict | None = None,
                       temperature: float = 0.0,
                       max_tokens: int = 3072) -> LLMResult: ...
    # 實作要點：
    # - OpenAI 相容 /chat/completions；schema 非 None 時先試 response_format=
    #   {"type":"json_object"}，端點不支援（400）就 fallback 到 prompt 內嵌 schema 指示
    # - JSON 解析失敗：剝 ``` fence 再 parse；仍失敗 -> 帶原輸出重試一次「repair」呼叫；
    #   仍失敗 -> LLMResult(error="json_invalid")，不丟例外
    # - 重試：429/5xx/timeout 指數退避 2s/8s/32s；每次呼叫的 usage 與 latency 寫進 log_path (JSONL)
    # - 併發用 asyncio.Semaphore(max_concurrency)；換模型 = 換一個 LLMClient 實例，管線零改動

# prompts.py
PROMPT_VERSION = "v1"                   # 任何 prompt 文案改動必須 bump，task_id 含它
def build_prompt(task: Task, exemplars: list[dict] | None) -> tuple[str, str]
    # 回傳 (system, user)。system 固定審計員角色 + OUTPUT_SCHEMA 指示。
    # user = detector md 的 "## Detection prompt" 全文（上游原文）
    #      + exemplars 非空時的 "### Similar audited findings" 區塊（見 §2.5）
    #      + "### Code under review" + 每個 slice 以
    #        「// FILE path | CONTRACT c | FUNCTION f | L{start}-L{end}」開頭串接
    # broadcast 模式的 task 只有一個全檔 slice，exemplars=None，其餘完全同一條路
def build_verify_prompt(finding: Finding, context_source: str,
                        tag_definition: str, checks: list[str]) -> tuple[str, str]

# plan.py — 唯一的模式分岔點
def plan(mode: Literal["routed", "broadcast"],
         detectors: list[Detector],
         repo_root: Path,
         repo_index: dict | None,        # broadcast 模式可為 None
         signatures: dict | None) -> list[Task]
    # routed: 委派 routing.route()（signatures 來自 routing.fit()，在全部偵測器 prompt 上擬合一次）
    # broadcast: glob("**/*.sol") 不排除 vendor/test、不看 scope.txt（忠實復刻上游），
    #   每檔一個全檔 Slice(contract="", function="<file>", start_line=1, end_line=行數, source=全文)，
    #   每個 (detector, file) 一個 Task。檔案 >200_000 chars 截斷並記 warning（上游此時直接爆 context）

# runstore.py
def task_id(task: Task, model: str, prompt_version: str) -> str
    # sha256(detector.id | prompt_version | model | repo | path | sorted(slice.id))[:16]
class RunStore:
    def __init__(self, run_dir: Path): ...
    def write_manifest(self, cfg: dict) -> None       # 見 §1.6
    def done_ids(self) -> set[str]                    # 讀 results.jsonl 已完成 task_id
    def append(self, task_id: str, result: LLMResult, findings: list[dict]) -> None
    def load_findings(self) -> list[Finding]

# executor.py
async def run_tasks(tasks: list[Task], client: LLMClient, store: RunStore,
                    exemplar_fn: Callable[[Task], list[dict]] | None = None) -> None
    # 1. skip = store.done_ids()；2. 其餘依 task_id 排序後丟進 semaphore gather
    # 3. 每完成一個立即 append（append-only，中斷任意時點皆可續跑）
    # 4. 每 500 個 task 印進度（done/total、平均延遲、error 計數）

# findings.py
def parse_findings(task: Task, result: LLMResult) -> list[Finding]
    # parsed 為 None -> []；vulnerable=false 的項目丟棄；
    # tag 取 detector.tags[0] 經 canonical_tag()（偵測器決定 tag，模型只定 subtag/severity/description）
    # confidence 缺失補 0.5；contract/function 對不上 slice 清單時保留但 evidence 加註 "unmatched"

# retrieve.py
def build_kb(train_df: pd.DataFrame, localizations: list[dict], out: Path) -> None
    # 只用 TRAIN-SYN 切分的 finding。每筆存：
    # {repo, tag, subtag, severity, description, fault_pattern, identifiers: [...], snippet}
    # identifiers/snippet 來自 S1 定位結果（§2.4），description 定位失敗者仍收錄但無 identifiers
def query_kb(kb: list[dict], task: Task, k: int = 2) -> list[dict]
    # 過濾：kb 項的 tag ∈ task.detector.tags 且 kb 項的 repo != task 的 repo（防洩漏，硬性）
    # 排序：Jaccard(task 全部 slice 的 identifier 聯集, kb 項 identifiers) 由高到低，取前 k
    # 無 identifiers 的 kb 項排最後備位。不用 embedding（§2.4 說明取捨）

# verify.py
async def verify_findings(findings: list[Finding], repo_index: dict,
                          client: LLMClient, store: RunStore) -> list[Finding]
    # 每個 finding 一次呼叫；context = 該函式全文 ±30 行；回填 verdict

# aggregate.py
@dataclass
class Calibration:
    detector_prior: dict[str, float]   # Laplace 平滑精確度 (tp+1)/(tp+fp+2)，clip [0.2, 0.95]
    tau: float                          # 全域門檻
    verify_multiplier: dict[str, float] # {"confirmed":1.0,"unverified":0.7,"uncertain":0.4,"rejected":0.0}
def fit_calibration(findings: list[Finding], truth: pd.DataFrame,
                    repos: list[str]) -> Calibration
    # 在 DEV 上：先以 verdict 乘數固定，掃 tau ∈ {0.10,0.15,...,0.60} 取 macro-F1 最大者
def aggregate(findings: list[Finding], calib: Calibration) -> dict[str, dict[str, bool]]
    # score(repo, tag) = max over findings of prior[detector_id] * confidence * mult[verdict]
    # 預測正 = score >= tau。回傳 {tag: {repo: bool}}，直接餵 evaluate.score_all()

# evaluate.py 新增
def upstream_score(dataset, predictions, sample_size, seed) -> dict
    # 忠實復刻上游 eval.py 的缺陷抽樣：以「finding 列」為抽樣單位建正負池
    #（正 repo 的其他列會落入負池），混淆矩陣算法照抄。用途：E1 對照口徑 + E6 取證
```

### 1.4 掃描管線資料流（一次 run 的完整路徑）

```
repo 目錄
  └─ routed:   solidity.index_repo() ──┐
  └─ broadcast: (跳過索引) ────────────┤
                                       ▼
              plan(mode, detectors, ...) ──> list[Task]        ← 唯一分岔點
                                       ▼
              executor.run_tasks(tasks, client, store, exemplar_fn)
                │  exemplar_fn: routed 且 detector.synthesized 時 = query_kb，否則 None
                │  每 task: build_prompt → client.complete → parse_findings → store.append
                                       ▼
              store.load_findings() ──> list[Finding]（verdict 全為 unverified）
                                       ▼
              verify.verify_findings()（依 §2.6 的啟用矩陣，可整段跳過）
                                       ▼
              aggregate(findings, calib) ──> {tag: {repo: bool}}
                                       ▼
              evaluate.score_all() / evaluate.upstream_score() ──> 混淆矩陣 + per-tag 拆解
```

Broadcast 臂的固定配置：`exemplar_fn=None`、跳過 verify、`aggregate` 用
`Calibration(detector_prior=全 1.0, tau=任意 finding 即正, multiplier=全 1.0)`——
即「任何節點回報 vulnerable 就把 repo 判正」，這正是上游的行為。兩臂的差異因此被壓縮成
plan 分岔 + 三個開關，全部可在 manifest 裡逐項核對。

### 1.5 推理後端抽象

單一 `LLMClient` 類別即可，不做 provider plugin 系統（6 天內是過度設計）。換模型 = 建構子換
`model` 字串；所有實驗腳本從 CLI `--model` 收。每次呼叫寫一行 JSONL 到
`runs/<id>/llm_log.jsonl`：`{ts, task_id, model, input_tokens, output_tokens, latency_s,
attempts, error}`。成本圖表直接從這個檔案聚合，不另設計量系統。

### 1.6 Run manifest、續跑、可重現性

每個 run 目錄：

```
runs/<run_id>/
  manifest.json    # 見下
  tasks.jsonl      # 規劃出的全部 task（task_id, detector_id, repo, path, slice_ids, code_chars）
  results.jsonl    # append-only：{task_id, error, findings: [...], usage}
  llm_log.jsonl
  findings.json    # 解析後全部 Finding（run 結束時匯出）
  predictions.json # aggregate 輸出
  scores.json      # 兩種 scorer 的結果
```

`manifest.json` 欄位（寫死）：`run_id, created_at, mode, model, temperature, prompt_version,
detector_set_hash（全部 md 檔 sha256 排序後再 hash）, splits_hash, repos: [...],
planned_tasks, code_hash（bastet_cc/*.py 內容 hash）, calibration_path, notes`。

續跑 = 重跑同一個 `run_scan.py --run-id <id>` 命令；executor 讀 `done_ids()` 跳過已完成者。
task_id 含 prompt_version 與 model，任何會改變輸出的變因都會使快取自然失效。溫度全程 0
（唯一例外 S2 合成用 0.3，但其產物是落地的 md 檔，掃描重現性不依賴重新合成）。

---

## 2. 核心創新：批判、排序、補遺

### 2.1 結論先講

你規劃的四層裡，(c) 已落袋是地基；(a) 是簡報的主角但也是最大風險源；(d) 是 (a) 的必要配套
（沒有 verify，合成偵測器的 FP 會把 precision 拖死）；(b) 價值最低，降級成只服務合成偵測器
的輕量版，是第一個可砍項。**你漏掉的一層是 (e) repo 層級聚合與校準**——評分單位是
repo×tag 的混淆矩陣，但管線輸出是函式級 finding，中間那個決策層（多少證據、多可信才把
repo 判正）是直接優化目標指標的槓桿，LLM 成本為零，卻沒有人做它。上游的行為等價於
「tau=0、prior=1」，這本身就是它 F1 上不去的原因之一。

**投入產出排序（高到低）：(e) 校準 → (a) 合成 → (d) 驗證 → (b) 檢索。**
(c) 不排，它是前提。另補一個微創新 (f)：`required_hints` 硬前置守門（§1.2），半天工作量，
專治類別性偵測器（ERC777/ERC1155/Upgradeable）的無差別誤報。

### 2.2 (c) 確定性路由——定位

已完成、已量化（−87.5% 呼叫、−88.6% token）。在簡報裡的角色不是「創新之一」而是
**「讓一切變得可跑」的前提**：對手連自己的 benchmark 都跑不完（344K 呼叫、序列 165 小時），
我們把同一件事壓到免費端點上 40 分鐘內可完成。唯一還要做的：`route()` 加 required_hints
的 all-of 檢查（§1.2），以及合成偵測器的 hints 走同一條 `fit()` 流程。

### 2.3 (a) 偵測器自動合成——完整演算法

目標：27 個缺失 tag（Accounting Error 47、Governance 36、Liquidation 25、Cross-Chain 11、
MEV 8、ERC1155 8、DAO 8、Upgradeable 7、ERC777 6、Pause 6、其餘 17 個長尾），
覆蓋率 15/42 → 42/42（4 個 OUT_OF_TAXONOMY tag 除外，附錄說明）。

#### S1 證據定位（`synth/localize.py`）——把 description 釘回程式碼

對 **全部 497 筆** finding 跑（不只 27 個缺失 tag——15 個已覆蓋 tag 的定位結果供 (b) 知識庫用）。
每筆一次 LLM 呼叫，共 497 次：

1. **候選函式檢索（確定性）**：從 description 抽 token——反引號內容、`[A-Za-z_][A-Za-z0-9_]{3,}`
   全部匹配、CamelCase/snake_case 切詞——與該 repo 索引的函式 identifier 集合取交集計分
   （Jaccard），取前 12 個函式、總量 cap 12,000 chars。抽不到任何交集 token 時退而取該 repo
   最大的 3 個合約的函式簽名清單（只有簽名，讓模型至少能指認位置）。
2. **LLM 定位**：輸入 description + subtag + severity + 候選函式全文。輸出 schema：
   ```json
   {"matches": [{"path": "", "contract": "", "function": "",
                 "lines": "L10-L25", "fault_pattern": ""}],
    "confidence": 0.0, "code_reachable": true}
   ```
   `fault_pattern` 規定為一句**程式碼層級**的判定描述（例：「fee 在 transfer 之後才扣，
   記帳用的是扣費前金額」），禁止複述 description。
3. **判定**：`code_reachable=false` 或 `confidence<0.4` → 標記 UNLOCALIZED。
   每個 tag 統計定位率；定位率的分佈本身進簡報（預期 Accounting Error 這類語意型 tag 偏低）。

#### S2 模式歸納（`synth/induce.py`）——每 tag 一次合成呼叫

輸入（每 tag）：
- `Tag Definitions.md` 該 tag 段落全文（含 Related subtag 清單）；
- 至多 10 個已定位三元組 `(fault_pattern, 程式碼片段 ≤80 行, subtag)`，跨 subtag 與跨 repo
  分層抽樣（每個 subtag 至少 1 個、每個 repo 至多 3 個）；
- 2 個手寫偵測器全文當風格錨點（固定用 `chainlink__chainlink_not_checking_for_stale_prices`
  與 `slippage__slippage_no_expiration_deadline`——一個知識密集型、一個範例密集型）；
- 統一輸出 schema 指示。

LLM 輸出 schema（**md 檔由我們的程式碼從這個 JSON 確定性組裝**，不讓模型直接寫 md，
保證 frontmatter 永遠合法）：

```json
{"detector": {
  "name": "",
  "vulnerability_knowledge": "",
  "checks": ["4 到 8 條可逐一核對的程式碼層級判定規則"],
  "incorrect_example": {"code": "", "explanation": ""},
  "correct_example":   {"code": "", "explanation": ""},
  "routing_hint_candidates": ["10 到 30 個候選識別字"]
}}
```

溫度 0.3（歸納需要一點泛化），每 tag 只取一次輸出，產物凍結成檔。
**description 反推判定規則的機制**就在這裡：模型看到的不是 description 原文，而是 S1 已經
翻譯成程式碼語彙的 `fault_pattern` + 真實漏洞片段，歸納的原料已經在程式碼層。

**S2b 退化路徑**：已定位三元組 <3 個的 tag → 純定義合成：只給 Tag Definitions 段落 +
該 tag 全部 description 原文，範例由模型虛構（風格錨點同上）。此路徑產出的偵測器
一律 `gated: true`。

#### S3 routing_hints 驗證（`synth/hints.py`）——確保 hints 是真實識別字

全部確定性，不用 LLM：

1. 語彙庫 V = 54 個 train repo 索引的函式 identifier 全集（tree-sitter 已收集，含呼叫名、
   型別名、成員存取）。
2. 對每個候選 h 計算：`df(h)` = 含 h 的檔案數；`pos_df(h)` = tag T 正例 repo 中含 h 的檔案數。
3. 淘汰規則（依序）：
   - `df(h)==0` → 幻覺識別字，剔除（這一條就是「確保真實出現在 Solidity 裡」的機制）；
   - `df(h)/N_files > 0.05` → 無鑑別力（`require`、`transfer` 這種），剔除，
     與 routing.fit() 的 IDF 哲學一致；
   - lift = `(pos_df/N_pos_files)/(df/N_files)` < 2.0 → 剔除；
   - tag 有 ≥3 個正例 repo 時，h 必須出現在 ≥2 個正例 repo（防單 repo 過擬合）；
     <3 個正例 repo 的 tag 豁免此條並在 manifest 標 `single_repo_hints: true`。
4. 排序 `lift * log(1+pos_df)` 取前 8。
5. **覆蓋檢查**：保留 hints 的聯集必須命中該 tag ≥80% 的已定位函式；不足則從落選名單
   依序回補直到達標或耗盡。
6. 產出 <MIN_HINTS(2) 個 hints → **不准 broadcast**（合成偵測器一律禁 broadcast，
   否則成本優勢被自己吃掉）；改用第三層 fallback：從 Tag Definitions 的 subtag 名稱
   人工整理領域詞表（例 Governance → `propose/castVote/quorum/timelock/votingPower/delegate`），
   工程師用 `grep -c` 對語彙庫核實每個詞 df>0 後填入。預估只有 2–4 個長尾 tag 走到這裡，
   30 分鐘人工。

#### S4 品質閘門（`synth/gate.py`）——leave-one-repo-out

對 finding 數前 10 的缺失 tag 跑完整 LORO；其餘 tag 跑單一 holdout（成本考量）：

1. tag T 的正例 repo R1..Rk（k≥2）：對每個 Ri，用排除 Ri 的 finding 重跑 S2（S1 定位結果
   重用，便宜），得變體偵測器 D_i。
2. 用 D_i 走正式管線（route→execute→parse）掃 Ri，以及 2 個對 T 為負的 TRAIN-SYN repo。
3. 指標：`hit(Ri)` = Ri 上出現任何 tag=T 的 finding；`fp(neg)` = 負 repo 上出現 finding。
4. **通過條件：mean(hit) ≥ 0.5 且 mean(fp) ≤ 0.5。**
5. 未過 → 一輪修補：把漏掉的真實漏洞函式全文（或誤報的函式全文）附回 S2 prompt
   （「你的 checks 漏了這個／誤殺了這個，修訂 checks」），重跑 S2+S3，再測一次。
6. 仍未過 → 偵測器保留但 `gated: true`：其 finding 必須 verifier confirmed 才進 aggregate，
   且 prior 上限 0.5。**不丟棄**——覆蓋率宣稱需要 42/42，gated 是誠實的折衷。

成本估算：S1 497 呼叫；S2 27 + 修補 ≤27；S4 top-10 tag 平均 k≈4 → 40 個變體 ×（1 次 S2 +
3 個 repo 的小規模掃描 ≈ 60 呼叫）≈ 2,500 呼叫。全部 <4,000 呼叫，半天內跑完。

**預期效果**：199 個結構性搆不到的 finding 變成可搆到。新 tag 的實際 recall 保守估 0.3–0.5，
但對手在這些 tag 上是結構性的 0，per-tag 對照圖會非常難看（對他們而言）。
**失敗模式**：(i) 語意型 tag（Accounting Error）定位率低 → S2b 品質差 → gated 比例高——
可接受，覆蓋率宣稱仍成立，precision 由 verifier 兜底；(ii) hints 過擬合 train 語彙 →
S3 第 3、4 條規則 + TEST 切分會誠實暴露，per-tag 報告；(iii) 類別型 tag（Governance/DAO）
FP 風暴 → required_hints + verifier + prior 三道閘。
**可行性**：2 天（D2 做 S1，D3 做 S2–S4），是排程的關鍵路徑之一，但每一步都有退化路徑，
不存在整體卡死的單點。

### 2.4 (b) 語料知識庫檢索——降級保留

**決定：砍掉 embedding，只用 identifier Jaccard；只對合成偵測器注入。** 理由：
(i) 端點是否供應 embedding API 未知，local BGE 是額外依賴與時間；123.65 那個解法用 BGE
是因為它整個系統只有檢索，我們的檢索只是配菜；(ii) 手寫 56 個偵測器已內建精心挑選的範例，
再注入檢索範例只會稀釋；合成偵測器的範例是模型自產的，才需要真實範例補強；(iii) S1 定位
已經免費產出了「description ↔ 函式 identifier 集合」的對映，Jaccard 檢索是零額外 LLM 成本
的十行程式碼。

實作即 §1.3 的 `build_kb`/`query_kb`。注入格式（`build_prompt` 內）：

```
### Similar audited findings (from real audits of other projects)
1. [Liquidation / Bad Debt] fault: liquidation bonus paid from pool reserves without
   checking remaining collateral...
   code: (≤10 行片段)
```

**硬性防洩漏**：`kb 項.repo != 掃描中 repo`（程式碼強制）；KB 只收 TRAIN-SYN 切分的 finding
（DEV/TEST 的 finding 永不入庫）。
**預期效果**：合成偵測器的 subtag 命中率與 description 品質提升（這兩項是 Kaggle 任務定義
的一部分，也是簡報質感）；對 F1 預期 +1~2 個百分點，屬錦上添花。
**失敗模式**：不相干範例誘導誤報——tag 過濾 + k=2 已把風險壓到最低。E2 消融會給出它的
真實貢獻，若為負就在最終配置關掉（一個 flag）。
**可行性**：0.5 天，且完全依賴 S1 產物，天然排在 S1 之後。第一順位可砍項。

### 2.5 (d) detect→verify 對抗驗證——保留，範圍收窄

**決定：單輪、只驗 finding、角色是「試圖否決的審稿人」。** 不做多輪辯論（成本與時間都不允許，
且單輪否決已能吃掉大部分 FP）。

演算法：
1. 對每個 Finding 一次呼叫：context = 該函式全文 ±30 行（從索引取，不重讀檔案）+
   tag 的官方定義 + 該偵測器的 checks 清單。
2. System prompt 固定：「你是試圖否決此漏洞報告的資深審計員。只有在你能寫出引用具體行號的
   攻擊情境時才准 confirm；若聲稱的模式在提供的上下文中已有防護，必須 reject。」
3. 輸出 schema：`{"verdict": "confirmed|rejected|uncertain", "attack_scenario": str|null,
   "reject_reason": str|null}`。confirmed 但 attack_scenario 為空 → 程式碼端降級為 uncertain。
4. **啟用矩陣（在 DEV 上定案）**：合成偵測器預設 ON；gated 偵測器強制 ON；手寫偵測器預設
   OFF，僅當該偵測器在 DEV 的 FP 率 >0.5 時個別打開。決策依據是 DEV 上的 Δprecision/Δrecall，
   `fit_calibration` 順帶輸出這張表。
5. verdict 進 `aggregate` 的乘數：confirmed 1.0 / unverified 0.7 / uncertain 0.4 / rejected 0.0。

**預期效果**：合成偵測器的 precision 從「不可用」拉到「可校準」；這是 (a) 能上場的前提。
**失敗模式**：verifier 否決跨函式/跨合約的真漏洞（context 不足）——已知限制，DEV 上量測
recall 損失，若某 tag 損失 >30% 就對該 tag 關 verifier（per-tag override 寫進 Calibration）。
**成本**：finding 數量級（每 repo 數十），全語料一輪 <5,000 呼叫。
**可行性**：1 天含校準。

### 2.6 (e) 【新增】repo 層級聚合與校準

§1.3 的 `aggregate.py` 全文即規格。再強調三個設計決定與理由：
- **全域 tau 而非 per-tag tau**：DEV 只有 10 個 repo，per-tag 網格搜尋必然過擬合；
  per-detector prior（Laplace 平滑 + clip）已提供逐偵測器的差異化，tau 只負責全域工作點。
- **max 聚合而非 noisy-OR**：noisy-OR 會讓「一個爛偵測器叫十次」贏過「一個好偵測器叫一次」，
  與我們對 FP 風暴的防禦方向相反。
- 上游等價於 `prior=1, tau→0⁺`，所以這一層同時是創新和對照敘事：
  「他們把每一聲狗吠都當成小偷。」

### 2.7 明確砍掉的東西

- **多輪 agent 對話 / 工具使用型 agent**：他們 Future Work 寫的是 agent 化，但 6 天內
  agent 迴圈的變異性會毀掉可重現性與統計功效。我們的「agent 性」體現在管線的自動編排
  （路由、合成、驗證），簡報足以對上他們的 Future Work 敘事。
- **編譯器 / Slither 混合靜態分析**：Code4rena repo 大多編不過（已實測），死路。
- **embedding 檢索**（§2.4）。
- **對上游 OpenAI 模型的付費復現**：無預算，改以同模型雙臂對照隔離「編排」變因（§3.4）。

---

## 3. 實驗 harness

### 3.1 切分策略（D1 凍結，之後不得動）

54 個 train repo → **TRAIN-SYN 32 / DEV 10 / TEST 12**，repo 級切分（一個 repo 的所有
finding 同進同出）。`scripts/make_splits.py`：
1. 標籤先過 `explode_labels`；tag 依 finding 數降冪。
2. 貪婪分配：由頻率最高的 tag 開始，盡量讓每個 tag 的正例 repo 依 32:10:12 比例分佈、
   且 finding 數前 15 的 tag 在三個切分各有 ≥1 個正例 repo；無法滿足者（正例 repo <3 的
   長尾 tag）優先保 TRAIN-SYN（合成需要原料），並記入 `splits.json` 的 `uncovered` 欄。
3. 輸出 `data/splits.json`：`{seed: 20260725, train_syn: [...], dev: [...], test: [...],
   per_tag_counts: {...}, uncovered: {...}}`，sha256 進所有 manifest。

角色分工：TRAIN-SYN = 合成原料 + 知識庫 + routing.fit 語料；DEV = 校準（tau、prior、
verifier 啟用矩陣）+ 一切 prompt 迭代；TEST = **只跑一次**，D5 之前不准任何人碰。
洩漏規則：S1–S4 只讀 TRAIN-SYN 的 finding；KB 只含 TRAIN-SYN；`query_kb` 再排除同 repo；
routing.fit 的 IDF 只用偵測器 prompt 語彙 + TRAIN-SYN 索引。

不做 LORO 交叉驗證做最終數字的理由：合成是洩漏環節，誠實的 LORO 要重合成 54 次，
工程時間不允許；固定切分 + bootstrap CI 是 6 天內統計上站得住的最強方案。

### 3.2 實驗矩陣

| ID | 問題 | 臂 | 資料 | 指標 | 必要性 |
|----|------|-----|------|------|--------|
| E1 | 我們贏了嗎 | A: broadcast 忠實模擬（56 偵測器、全檔、prior=1/tau=0、no verify）；B: Bastet-CC 完整 | TEST 12 repo | 兩種 scorer 的 macro-F1 + 混淆矩陣；A/B 同模型 550B | **必做** |
| E2 | 每層貢獻 | R0 routed-56 → R1 +合成偵測器 → R2 +verify → R3 +校準 → R4 +檢索 | DEV 調參，TEST 各跑一次 | Δmacro-F1、Δprecision/recall、Δ成本 | **必做**（R4 可砍） |
| E3 | 成本 | E1 兩臂的實測 | 同 E1 | 呼叫數、token、wall-clock、每 repo 延遲（llm_log 聚合） | **必做** |
| E4 | 覆蓋 | E1-B | TEST | per-tag recall；27 個新 tag 單獨着色；可搆到 finding 68.8%→100% | **必做** |
| E5 | 模型還是編排 | R3 換 llama-3.3-70b | DEV only | macro-F1 對 550B 的差 vs E1 兩臂的差 | 可砍 |
| E6 | 上游 scorer 壞在哪 | (i) E1-B 同一份預測過兩種 scorer；(ii) 用 GT 構造完美預測器過上游 scorer | 全 54 repo（純 pandas，零 LLM） | 完美預測器的上游 F1 < 1.0 的量化值 | **必做**（殺手級圖表） |
| E7 | 模型背過答案嗎 | 記憶探測：只給 repo 的合約名/README 要模型列已知審計發現 | TEST 6 repo | 與 GT 的 tag 重疊 vs 隨機基線 | **必做輕量版**；匿名化重掃 3 repo 可砍 |

E1 廣播臂規模：TEST 12 repo ≈ 400 個 .sol × 56 ≈ 22K 呼叫，併發 32、延遲 1.7s ≈ 20 分鐘，
**可以真跑，不用估算**——「我們替他們跑完了他們自己跑不完的 benchmark」本身就是簡報素材。

### 3.3 統計方法（寫死）

- 主檢定：**repo 級 paired bootstrap**（兩臂在同一組 TEST repo 上）。重抽 12 個 repo
  （放回）1,000 次，每次重算兩臂 macro-F1 之差，報 95% CI；CI 不含 0 才宣稱顯著。
- 輔助：per-(repo,tag) 決策對的 McNemar 精確檢定（修正版 scorer 對每個 repo 評全部出現過
  的 tag，決策單位 ≈ 12×20 = 240 對，功效足夠）。
- **per-tag 數字一律附 n；n<4 的 tag 禁止單獨宣稱，只進聚合。**
- 樣本數的誠實陳述寫進簡報：54 repo 是資料集硬上限，對手的 46/58 樣本評估同樣受此限，
  且他們連 repo 級切分都沒有。

### 3.4 效度威脅與對策

1. **模型記憶（Code4rena 報告公開）**——最大威脅，三重處理：
   (i) E7 探測直接量測記憶程度；(ii) 匿名化重掃（sed 換合約名 + 剝註解，3 個 repo）量測
   F1 跌幅，時間不夠則只做 (i)；(iii) **結構性論證**：兩臂用同一個模型，記憶對兩臂同樣
   加成，配對比較的 Δ 對記憶不敏感——這條寫進簡報，是最強的一道防線。絕對分數則明確
  標註「可能受記憶影響」。
2. **模型不同於上游（GPT-4o-mini vs 550B）**：無預算復現。對策：對照宣稱嚴格限定為
   「同模型下，編排方式 A vs B」；他們發表的 0.681/0.774 以引用形式並列，不做直接數值
   比較宣稱（何況那兩個數字自己就互相矛盾，這點單獨用一頁講）。
3. **scorer 選擇**：所有結果雙 scorer 並報。用他們的 scorer 我們也要贏給他看，用修好的
   scorer 說明真實水位。
4. **GT 標籤噪音**：正規化規則全部落在 `tags.py`，一目了然；附一組不做正規化的敏感度
   數字（純重算，零成本）。
5. **DEV 反覆偷看**：凍結協議——D4 結束時 prompt/校準/啟用矩陣全部凍結（git tag），
   TEST 只跑一次；任何 TEST 後改動必須在簡報標註為 post-hoc。
6. **test.csv 無標籤**：不用於任何量化宣稱；D6 有餘裕就掃 53 個 test repo 產出
   Kaggle 提交格式的 400 列 csv 當 demo（敘事：「同一條管線可直接參賽」）。

### 3.5 負面結果的報告策略（事前註冊，寫在這裡就是註冊）

宣稱階梯，發表時由下往上能站幾層站幾層：
- **C1 成本**：−87.5% 呼叫 / −88.6% token，同覆蓋。已落袋（實測）。
- **C2 覆蓋**：15/42 → 42/42 tag，31.2% 結構性盲區歸零。合成完成即落袋，與 F1 無關。
- **C3 評估取證**：上游 scorer 對完美預測器都給不出 1.0（E6 量化值）。零 LLM 成本，必落袋。
- **C4 修正 scorer F1 勝**：主戰場，bootstrap CI 說話。
- **C5 上游 scorer F1 勝**：加分項。
若 C4 打平或小輸：報告 CI 與 per-tag 拆解，敘事轉為「同等 F1、1/8 成本、2.8 倍覆蓋、
外加把對手的評估方法修好了」——這在 AIS3 的場合仍是完整的勝利敘事。禁止的行為：
因為 C4 難看就換 scorer、換切分、或把 TEST 重跑第二次挑好的。

---

## 4. 六天排程

關鍵路徑：**D1 executor → D2 S1+基線 → D3 合成 → D4 校準凍結 → D5 TEST**。
檢索（R4）、E5、匿名化重掃是三個洩壓閥，依序棄守。

### D1（7/25，今天）
- 必做：`tags.py` + `make_splits.py` → `splits.json` 凍結；`llm.py`（含 log）；
  `runstore.py`；`prompts.py`；`plan.py` 雙模式；`executor.py`。
- 驗收：2 個 repo 端到端 routed 掃描跑通，中斷後續跑驗證通過，llm_log 有 usage 數字。
- 可砍：無。今天全部是關鍵路徑。

### D2（7/26）
- 必做：`findings.py` 解析 + `aggregate.py`（先用 prior=1/tau 固定的 v0）；
  **基線 run**：routed-56 掃全 54 repo（≈40 分鐘）；S1 定位 497 筆（497 呼叫）；
  broadcast 臂掃 DEV+TEST 22 repo 以背景 run 掛起（≈42K 呼叫，可跨夜續跑）。
- 驗收：54 repo 的 routed-56 findings.json + 497 筆定位結果落地。
- 可砍：broadcast 可縮到只掃 TEST 12。

### D3（7/27）
- 必做：S2 歸納 27 tag → S3 hints 驗證 → `detectors_synth/` 落地；S4 閘門
  top-10 tag 完整 LORO、其餘單 holdout；`verify.py`。
- 驗收：42/42 tag 各有一個偵測器 md（含 gated 標記）；verify 在 DEV 的 finding 上跑通。
- 可砍：S4 降為全部單 holdout；長尾 tag 走 S2b 不修補。

### D4（7/28）
- 必做：完整管線（56+合成）掃 DEV → `fit_calibration`（tau、prior、verifier 啟用矩陣）；
  E2 消融 R0–R3 在 DEV 全部跑完；**EOD 凍結**（git tag `freeze-d4`）。
- 可砍：R4 檢索臂、E5。
- 風險緩衝：若合成偵測器 DEV precision 崩盤，退路是全部標 gated（verifier 硬門），
  覆蓋率宣稱不受影響。

### D5（7/29）
- 必做：TEST 12 repo 一次性跑 E1 兩臂 + E2 各臂（呼叫量小，半天內完）；E6 取證
 （純 pandas）；雙 scorer 計分 + bootstrap CI；E7 記憶探測 6 repo。
- 驗收：`scores.json` 齊備，宣稱階梯 C1–C5 逐條有數字。
- 可砍：匿名化重掃。

### D6（7/30）
- 必做：`charts.py`（實作前載入 dataviz skill）——六張圖：成本×F1 散點（兩臂）、
  per-tag 覆蓋熱圖（before/after，27 個新 tag 着色）、E2 消融瀑布、E6 完美預測器
  <1.0 長條、token/延遲成本長條、覆蓋率 15/42→42/42 環圖；簡報結果頁；
  半天緩衝給任何需要重跑的東西。
- 可砍：53 個無標籤 test repo 的 demo 掃描 + 400 列提交格式 csv。

### 7/31：發表。

---

## 附錄 A：偵測器 md 檔格式（合成品與手寫品同構）

```markdown
---
id: synth__accounting_error
name: "Accounting Error"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Accounting Error"]
routing_hints: [...S3 產出...]
required_hints: []
prompt_chars: <int>
synthesized: true
gated: false
synth_provenance: {train_findings: [Property ids], localization_rate: 0.72,
                   loro: {hit: 0.75, fp: 0.33}}
---
# Accounting Error
## Detection prompt
（S2 JSON 經 assemble.py 確定性渲染：Knowledge → Checks → Incorrect/Correct Example → Task）
```

`synth_provenance` 讓每個合成偵測器可追溯到原料 finding——審查洩漏與簡報展示都靠它。

## 附錄 B：與既有程式碼的接縫清單（工程師的第一天檢查表）

1. `routing.Detector` 加 3 欄位（§1.2）；`load_detectors` 讀新欄位（缺省向後相容）。
2. `routing.route()` 加 required_hints all-of 檢查（一行）。
3. `routing.load_detectors` 支援讀兩個目錄（`detectors/` + `detectors_synth/`）。
4. `evaluate.py` 加 `upstream_score()`；既有 `build_sample/score_all` 不動。
5. `solidity.index_repo` 不動；broadcast 臂完全繞過它。
