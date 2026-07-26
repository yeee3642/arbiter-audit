#!/usr/bin/env python3
"""Would Bastet's detector hits have told ARBITER where to look?

Motivated by the prior art. SmartPoC (arXiv 2511.12993) validates findings that already
exist in an audit report, and reports 98% confirmation precision doing it. ARBITER
instead discovers from source with no report, and its measured bottleneck is not
candidate selection but hypothesis fixation: on seven of ten missed samples every attempt
reached for reentrancy while the real defect was a comparison operator, a rounding
direction, a stale price source or a missing replay guard.

That suggests a cascade -- a cheap detector proposes the vulnerability class, the
execution gate proves or refuses it -- which is the shape the prior art says works. But
the cascade is only worth building if the proposals carry information. Bastet flags every
sample, so its *sample-level* verdict is worthless as a proposal. The question is whether
its per-detector hits are informative even though its aggregate decision is not.

This script answers that from committed artefacts alone, with no new spend: for each
vulnerable sample ARBITER failed to prove, did a detector whose name matches the true
vulnerability class actually fire?
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

# Which detector-name keywords would count as naming each sample's real defect. Written
# from the benchmark's own `the_fix` text, before looking at any detector output.
CLASS_KEYWORDS: dict[str, list[str]] = {
    "reentrancy_unstake": ["reentran"],
    "missing_access_control_disburse": ["access", "control", "auth", "owner", "privile"],
    "unchecked_call_return_buyback": ["unchecked", "return", "call", "low-level", "lowlevel"],
    "tx_origin_auth_router": ["origin", "auth", "access"],
    "unbounded_queue_dos": ["dos", "denial", "loop", "gas", "unbound"],
    "forced_ether_refund": ["balance", "ether", "force", "selfdestruct", "accounting"],
    "approval_double_spend": ["approve", "approval", "allowance", "race"],
    "delegatecall_unchecked_module": ["delegatecall", "delegate"],
    "amm_spot_price_oracle": ["oracle", "price", "manipul", "spot", "chainlink"],
    "slippage_check_skipped_branch": ["slippage", "amountout", "minimum", "output"],
    "missing_deadline_signed_order": ["deadline", "expir", "timestamp"],
    "stale_cached_price_liquidation": ["stale", "price", "oracle", "liquidat"],
    "first_depositor_share_inflation": ["4626", "share", "inflat", "deposit", "round"],
    "withdraw_rounding_favours_user": ["round", "4626", "precision"],
    "fee_on_transfer_credit": ["fee", "transfer", "fot", "deflation"],
    "uint128_downcast_reward_debt": ["cast", "downcast", "overflow", "truncat", "uint"],
    "signature_replay_voucher": ["replay", "signature", "nonce", "ecdsa"],
    "ecrecover_zero_address_session": ["ecrecover", "signature", "zero", "ecdsa"],
    "commit_reveal_frontrun": ["front", "frontrun", "commit", "reveal", "mev"],
    "weak_randomness_flip_payout": ["random", "prevrandao", "blockhash", "timestamp"],
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=Path, default=Path("runs/h2h-bastet.jobs.jsonl"))
    ap.add_argument("--arbiter", type=Path, default=Path("runs/h2h-arbiter.summary.json"))
    args = ap.parse_args()

    fired: dict[str, list[str]] = defaultdict(list)
    for line in args.jobs.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("n_findings"):
            fired[row["sample"]].append(row["detector"])

    preds: dict[str, str] = {}
    if args.arbiter.exists():
        summary = json.loads(args.arbiter.read_text(encoding="utf-8"))
        for run in summary.get("predictions_by_repeat", {}).values():
            preds.update(run)

    print(f"{'sample':40s} {'ARBITER':8s} {'fired':>6s} {'on-class':>9s}  matching detectors")
    hit = miss = 0
    for slug, keywords in CLASS_KEYWORDS.items():
        sample = f"V_{slug}"
        detectors = fired.get(sample, [])
        matching = [
            d for d in detectors if any(k in d.lower() for k in keywords)
        ]
        verdict = preds.get(sample, "?")
        if verdict == "safe":  # ARBITER missed it
            if matching:
                hit += 1
            else:
                miss += 1
        print(
            f"{sample[:40]:40s} {verdict:8s} {len(detectors):6d} "
            f"{len(matching):9d}  {', '.join(_short(m) for m in matching[:3])}"
        )

    print()
    total = hit + miss
    if total:
        print(
            f"Of the {total} vulnerable samples ARBITER failed to prove, "
            f"{hit} had at least one on-class detector fire ({hit / total:.0%})."
        )
        print(
            "A cascade is worth building only if that share is high: it is the ceiling on\n"
            "how often Bastet's hits could have redirected ARBITER away from its fixation."
        )
    return 0


def _short(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", name)[:34]


if __name__ == "__main__":
    raise SystemExit(main())
