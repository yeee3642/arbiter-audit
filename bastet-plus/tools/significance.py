"""顯著性檢定：這些 A/B 差異裡，哪些其實有證據支持？

寫這支的原因是我在 RESULTS.md 裡宣稱「兩個 precision 信賴區間不重疊，所以改善是
真的」。那是錯的 —— 它們在 0.095 到 0.126 之間重疊。與其再手算一次錯的，不如讓
數字自己從結果檔產生。

    python tools/significance.py [legacy_tag] [enhanced_tag]

只用標準函式庫，不需要 scipy。
"""

from __future__ import annotations

import json
import math
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from bastet_plus.metrics import wilson  # noqa: E402

RESULTS = pathlib.Path(__file__).resolve().parent.parent / "benchmark_results"


def two_proportion(x1: int, n1: int, x2: int, n2: int) -> tuple[float, float]:
    """未配對的兩比例 z 檢定。回傳 (z, 雙尾 p)。"""
    if n1 == 0 or n2 == 0:
        return (0.0, 1.0)
    p1, p2 = x1 / n1, x2 / n2
    p = (x1 + x2) / (n1 + n2)
    se = math.sqrt(p * (1 - p) * (1 / n1 + 1 / n2))
    if se == 0:
        return (0.0, 1.0)
    z = (p2 - p1) / se
    return (z, math.erfc(abs(z) / math.sqrt(2)))


def mcnemar_exact(b: int, c: int) -> float:
    """配對二元結果的精確 McNemar 檢定（雙尾二項）。

    b = 只有 B 抓到的數量, c = 只有 A 抓到的數量。同時抓到或同時漏掉的不帶資訊。
    """
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def paired_positives(doc_legacy: dict, doc_enhanced: dict) -> tuple[int, int, int, int]:
    """把兩個 arm 在每個真陽性 (檔案, 類別) 上的命中情形配對起來。"""
    L = {r["file"]: r for r in doc_legacy["per_file"]}
    E = {r["file"]: r for r in doc_enhanced["per_file"]}
    both = only_l = only_e = neither = 0
    for fname, lrow in L.items():
        erow = E.get(fname)
        if erow is None:
            continue
        for cls in lrow["truth"]:
            lhit = cls in lrow["predicted"]
            ehit = cls in erow["predicted"]
            if lhit and ehit:
                both += 1
            elif lhit:
                only_l += 1
            elif ehit:
                only_e += 1
            else:
                neither += 1
    return both, only_l, only_e, neither


def main() -> int:
    ltag = sys.argv[1] if len(sys.argv) > 1 else "strongverify"
    etag = sys.argv[2] if len(sys.argv) > 2 else "strongverify"
    lp = RESULTS / f"comparison_ais3_llama-3.3-70b_{ltag}.json"
    ep = RESULTS / f"comparison_ais3_llama-3.3-70b_{etag}.json"
    ldoc = json.loads(lp.read_text(encoding="utf-8"))["arms"]["legacy"]
    edoc = json.loads(ep.read_text(encoding="utf-8"))["arms"]["enhanced"]
    lo, eo = ldoc["metrics"]["overall"], edoc["metrics"]["overall"]
    lf, ef = ldoc["metrics"]["file_level"], edoc["metrics"]["file_level"]

    print("=" * 78)
    print("顯著性檢定  原版 vs Bastet+ (%s)" % etag)
    print("=" * 78)

    n_pos = lo["tp"] + lo["fn"]
    print(f"\n真陽性 (檔案,類別) 配對總數: {n_pos}      乾淨檔數: {ldoc['metrics']['clean_files']}")
    print("所有結論都受限於這兩個數字。\n")

    # -- precision (未配對) ------------------------------------------------
    print("-" * 78)
    print("PRECISION  (未配對: 兩個 arm 產生的 finding 集合不同)")
    l_lo, l_hi = wilson(lo["tp"], lo["tp"] + lo["fp"])
    e_lo, e_hi = wilson(eo["tp"], eo["tp"] + eo["fp"])
    print(f"  原版      {lo['precision']:.3f}  95%CI [{l_lo:.3f}, {l_hi:.3f}]   {lo['tp']}/{lo['tp']+lo['fp']}")
    print(f"  Bastet+   {eo['precision']:.3f}  95%CI [{e_lo:.3f}, {e_hi:.3f}]   {eo['tp']}/{eo['tp']+eo['fp']}")
    overlap = not (l_hi < e_lo or e_hi < l_lo)
    print(f"  信賴區間重疊: {'是' if overlap else '否'}"
          + (f"  (重疊區間 {max(l_lo, e_lo):.3f} - {min(l_hi, e_hi):.3f})" if overlap else ""))
    z, p = two_proportion(lo["tp"], lo["tp"] + lo["fp"], eo["tp"], eo["tp"] + eo["fp"])
    print(f"  兩比例 z 檢定: z = {z:.2f}, p = {p:.4f}")
    print("  警告: finding 叢集在 20 個檔案內, 並非獨立觀測。有效樣本數接近檔案數")
    print("        而非 finding 數, 所以上面這個 p 值偏樂觀。")
    print("  結論: 有跡象, 未確立。")

    # -- recall (配對) -----------------------------------------------------
    print("-" * 78)
    print("RECALL  (配對: 兩個 arm 面對同一組真陽性)")
    both, only_l, only_e, neither = paired_positives(ldoc, edoc)
    r_lo, r_hi = wilson(lo["tp"], n_pos)
    er_lo, er_hi = wilson(eo["tp"], n_pos)
    print(f"  原版      {lo['recall']:.3f}  95%CI [{r_lo:.3f}, {r_hi:.3f}]   {lo['tp']}/{n_pos}")
    print(f"  Bastet+   {eo['recall']:.3f}  95%CI [{er_lo:.3f}, {er_hi:.3f}]   {eo['tp']}/{n_pos}")
    print(f"  配對表: 都抓到={both}  只有原版={only_l}  只有Bastet+={only_e}  都漏掉={neither}")
    pm = mcnemar_exact(only_e, only_l)
    print(f"  McNemar 精確檢定: p = {pm:.3f}   (不一致配對只有 {only_e + only_l} 個)")
    print("  結論: " + ("沒有證據支持這個差異。" if pm > 0.05 else "有證據。"))

    # -- file level --------------------------------------------------------
    print("-" * 78)
    print("FILE-LEVEL PRECISION")
    fl_lo, fl_hi = wilson(lf["tp"], lf["tp"] + lf["fp"])
    fe_lo, fe_hi = wilson(ef["tp"], ef["tp"] + ef["fp"])
    print(f"  原版      {lf['precision']:.3f}  95%CI [{fl_lo:.3f}, {fl_hi:.3f}]   {lf['tp']}/{lf['tp']+lf['fp']}")
    print(f"  Bastet+   {ef['precision']:.3f}  95%CI [{fe_lo:.3f}, {fe_hi:.3f}]   {ef['tp']}/{ef['tp']+ef['fp']}")
    print("  註: 滿分 1.000 建立在 9 個樣本上。區間下界才是該引用的數字。")

    # -- 不該當成效能差異的欄位 -------------------------------------------
    print("-" * 78)
    print("以下欄位不是效能差異, 不應放進對照表:")
    print(f"  帶行號的 finding: 原版 {ldoc['metrics']['findings_with_line_number']} "
          f"-> Bastet+ {edoc['metrics']['findings_with_line_number']}")
    print("    原版從未要求模型給行號, 所以必然是 0。這是新增欄位, 不是偵測變好。")
    merged = edoc["stats"].get("merged_duplicates", 0)
    print(f"  finding 總數: {ldoc['metrics']['total_findings_reported']} "
          f"-> {edoc['metrics']['total_findings_reported']}")
    print(f"    其中 {merged} 筆是跨 detector 合併(同一 bug 被多支 detector 各報一次)。")
    print("    這部分是計數規則差異, 不是過濾掉的誤報。")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
