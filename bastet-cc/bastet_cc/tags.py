"""Tag normalization and the label taxonomy, in one place.

The ground truth is noisy in ways that silently corrupt scoring if handled ad hoc:
`Logic Error` (34 rows) and `Logic error` (11 rows) are the same tag, a quarter of
the rows carry comma-separated multi-labels, and four tags in train.csv (`XSS Attack`,
`RCE`, `Multisig`, `Rebalance`) do not exist in the official Tag Definitions at all.
Every module that touches labels goes through `canonical_tag`/`explode_labels`, so the
normalization policy is auditable as a single table rather than scattered `.strip()`s
(threat #4 in DESIGN §3.4: the no-normalization sensitivity check just bypasses this
module).
"""

from __future__ import annotations

import pandas as pd

# 38 main tags -> official subtags, transcribed once from `Tag Definitions.md`
# (the "Related subtag" column). Keys are the canonical spellings; note the source
# document itself titles the tag "Logic error" while the corpus mostly writes
# "Logic Error" -- the corpus-majority form is canonical here, matching
# evaluate.normalize_tag.
TAXONOMY: dict[str, list[str]] = {
    "DAO": [
        "State Update Inconsistency", "Does not match with Doc", "Bad Condition",
        "Precision Loss", "Invalid Validation", "Centralization Risk",
        "Invariant Violation", "Implementation Error",
    ],
    "DoS": [
        "Out of Gas", "Stale Value", "State Update Inconsistency",
        "Missing Initialization", "Invariant Violation", "Deprecated Library",
        "Bad Condition", "Duplicate Value", "Front Run", "Implementation Error",
        "Invalid Validation", "Precision Loss", "payable / receive()",
        "No Recovery Mechanism", "Incorrect Parameter", "Fee On Transfer Token",
        "Typo", "Missing minOut / maxAmount", "Missing Approval",
        "Execution Order Dependency", "Missing Functionality", "Reward Manipulation",
        "Refund Failed", "ERC777 Callback", "Missing Upper/Lower Bound Check",
        "Does not match with Doc", "Nonce", "1/64 Gas Rule",
        "Arbitrary Add/Remove/Set/Call", "Peg / Depeg", "Hardcoded Parameter",
        "EVM Compatibility",
        "Liquidation - Dust repay / front run evade liquidation", "Whale",
        "Case Sensitive", "Token Decimal", "onERC721Received callback",
        "Price Manipulation / Arbitrage opportunity",
    ],
    "Flashloan": [
        "Reward Manipulation", "Whale", "Bypass Mechanism",
        "Price Manipulation / Arbitrage opportunity", "Peg / Depeg", "slot0",
        "Incorrect Parameter", "Bad Condition", "State Update Inconsistency",
        "Missing Time Constraint", "Asset Theft",
    ],
    "Oracle": [
        "Price Manipulation / Arbitrage opportunity", "Incorrect Formula",
        "Hardcoded Parameter", "Token Decimal", "Precision Loss",
        "Incorrect Parameter", "Bad Condition", "Scaling", "Stale Value",
        "Invalid Validation", "State Update Inconsistency", "Duplicate Value",
        "Missing Return Check", "Misuse of Dependency", "Unsafe Downcast",
        "Does not match with Doc", "Implementation Error", "Bypass Mechanism",
        "Rounding Error",
    ],
    "Logic Error": [
        "Bad Condition", "Invalid Validation", "Stale Value",
        "State Update Inconsistency", "Price Manipulation / Arbitrage opportunity",
        "Incorrect Parameter", "Does not match with Doc", "Reward Manipulation",
        "Invariant Violation", "Bypass Mechanism", "Missing Approval",
        "Implementation Error", "Missing Functionality", "No Recovery Mechanism",
        "Missing Upper/Lower Bound Check", "Centralization Risk",
        "Missing Return Check", "Asset Theft", "Out of Gas", "Incorrect Formula",
        "Unfair Liquidation", "Cannot partial liquidations", "Front Run",
    ],
    "Reentrancy": [
        "Violating CEI / Missing nonReentrant", "Cross-Function Reentrancy",
        "Invalid Validation", "onERC721Received callback",
        "Execution Order Dependency", "ERC777 Callback", "Asset Theft",
        "Bypass Mechanism",
    ],
    "Access Control": [
        "Asset Theft", "Arbitrary Add/Remove/Set/Call", "Invalid Validation",
        "Cannot Revoke", "Implementation Error", "Missing Functionality",
        "Centralization Risk", "Price Manipulation / Arbitrage opportunity",
        "Role Takeover", "Unauthorized Upgrade", "Missing Initialization",
        "State Update Inconsistency", "Fee On Transfer Token",
        "Does not match with Doc", "Bypass Mechanism", "Reward Manipulation",
        "Bad Condition", "Missing Upper/Lower Bound Check", "No Recovery Mechanism",
        "Incorrect Parameter", "Front Run", "Out of Gas", "Duplicate Value",
        "Invariant Violation",
    ],
    "Liquidation": [
        "Bypass Mechanism", "Does not match with Doc", "Invalid Validation",
        "Incorrect Parameter", "No Incentive to Liquidate", "Bad Condition",
        "Invariant Violation",
        "Liquidation - Dust repay / front run evade liquidation", "ERC777 Callback",
        "Missing Functionality", "Price Manipulation / Arbitrage opportunity",
        "Unfair Liquidation", "State Update Inconsistency",
        "Cannot partial liquidations", "Implementation Error", "Whale",
        "Out of Gas", "Refund Failed",
    ],
    "Slippage": [
        "Missing minOut / maxAmount", "Hardcoded Parameter", "Fee On Transfer Token",
        "minOut set to 0", "Missing deadline",
        "Invalid Slippage Control / Missing slippage check", "Incorrect Formula",
    ],
    "ERC4626": [
        "Incorrect Parameter", "Inflation Attack", "Not EIP Compliant",
        "Rounding Error", "Price Manipulation / Arbitrage opportunity",
        "Missing minOut / maxAmount",
    ],
    "Input Validation": [
        "Not EIP Compliant", "Invalid Validation", "Asset Theft", "Duplicate Value",
        "Precision Loss", "Bypass Mechanism", "Bad Condition",
        "No Recovery Mechanism", "Hardcoded Parameter", "Does not match with Doc",
        "Implementation Error", "Incorrect Parameter", "Reward Manipulation",
        "Inflation Attack", "Peg / Depeg",
        "Price Manipulation / Arbitrage opportunity", "Missing Time Constraint",
        "Missing Upper/Lower Bound Check", "Front Run", "Stale Value",
        "State Update Inconsistency", "Invariant Violation", "Nonce",
    ],
    "Bad Randomness": ["Bad Condition", "Reward Manipulation", "Front Run"],
    "Chainlink": [
        "Deprecated Library", "Stale Value", "Invalid Validation",
        "Price Manipulation / Arbitrage opportunity", "Missing Return Check",
        "Unsafe Downcast", "Bad Condition", "Front Run", "Peg / Depeg",
    ],
    "Arithmetic": [
        "Unsafe Downcast", "Token Decimal", "Precision Loss", "Invalid Validation",
        "Scaling", "Incorrect Formula", "Peg / Depeg",
        "Price Manipulation / Arbitrage opportunity", "Implementation Error",
        "Front Run", "Rounding Error", "Missing Initialization",
        "Incorrect Parameter", "Bad Condition", "Missing Upper/Lower Bound Check",
        "Stale Value", "Bypass Mechanism", "State Update Inconsistency",
        "Block Time / Block Number", "Hardcoded Parameter",
        "Does not match with Doc",
    ],
    "Re-org Attack": ["State Update Inconsistency"],
    "Pause": [
        "Missing Functionality", "Centralization Risk",
        "State Update Inconsistency", "Invalid Validation", "1/64 Gas Rule",
        "Does not match with Doc", "Front Run", "Invariant Violation",
        "No Recovery Mechanism",
    ],
    "Accounting Error": [
        "Fee On Transfer Token", "State Update Inconsistency", "Bad Condition",
        "Incorrect Parameter", "Peg / Depeg",
        "Price Manipulation / Arbitrage opportunity", "Reward Manipulation",
        "Implementation Error", "Incorrect Formula", "Rebase Token", "Asset Theft",
        "Does not match with Doc", "Invalid Validation", "Invariant Violation",
        "payable / receive()", "Precision Loss", "No Recovery Mechanism", "Scaling",
    ],
    "MEV": [
        "Front Run", "Price Manipulation / Arbitrage opportunity", "Asset Theft",
        "State Update Inconsistency", "Reward Manipulation", "Bad Condition",
        "Execution Order Dependency", "Bypass Mechanism",
    ],
    "Upgradeable": [
        "Centralization Risk", "Misuse of Dependency", "Unauthorized Upgrade",
        "Storage Gap", "Diamond", "Missing Initialization", "Implementation Error",
        "Not EIP Compliant", "No Recovery Mechanism", "Invalid Validation",
        "Does not match with Doc", "Bad Condition",
    ],
    "ERC20": [
        "Missing Return Check", "State Update Inconsistency", "Not EIP Compliant",
        "Fee On Transfer Token", "No Recovery Mechanism", "Asset Theft",
        "Invalid Validation", "Rebase Token", "safeApprove", "Bad Condition",
        "Bypass Mechanism", "Does not match with Doc", "Implementation Error",
        "Refund Failed",
    ],
    "call / delegatecall": ["Missing Return Check"],
    "Uniswap": [
        "Incorrect Formula", "Implementation Error", "Hardcoded Parameter",
        "Inflation Attack", "Incorrect Parameter", "No Recovery Mechanism",
        "Rounding Error", "Price Manipulation / Arbitrage opportunity", "slot0",
        "Invalid Slippage Control / Missing slippage check",
    ],
    "Cross-Chain": [
        "Implementation Error", "No Recovery Mechanism", "Does not match with Doc",
        "Asset Theft", "Invalid Validation", "Whale", "Case Sensitive",
        "Incorrect Parameter", "Token Decimal", "EVM Compatibility",
        "State Update Inconsistency", "Missing Initialization", "Rebase Token",
        "Bypass Mechanism",
    ],
    "ERC777": [
        "ERC777 Callback", "Violating CEI / Missing nonReentrant", "Refund Failed",
        "Cross-Function Reentrancy",
    ],
    "Governance": [
        "State Update Inconsistency", "Invalid Validation", "Bypass Mechanism",
        "Incorrect Parameter", "Bad Condition", "Missing Time Constraint",
        "Does not match with Doc", "Implementation Error", "Front Run",
        "Missing Upper/Lower Bound Check", "Invariant Violation", "Nonce",
        "Centralization Risk", "Arbitrary Add/Remove/Set/Call",
        "Missing Functionality",
    ],
    "ERC1155": [
        "Not EIP Compliant", "Reward Manipulation", "State Update Inconsistency",
        "Violating CEI / Missing nonReentrant", "Asset Theft", "Invalid Validation",
        "Bad Condition",
    ],
    "ERC721": [
        "Not EIP Compliant", "Asset Theft", "Invalid Validation",
        "Violating CEI / Missing nonReentrant", "onERC721Received callback",
        "Duplicate Value", "Incorrect Parameter", "Invariant Violation",
        "Missing Functionality", "State Update Inconsistency",
    ],
    "Gnosis safe": [
        "Bypass Mechanism", "Invalid Validation", "Invariant Violation",
        "Cannot Revoke",
    ],
    "Opensea": ["Refund Failed", "Asset Theft", "Invalid Validation"],
    "EIP712": ["Not EIP Compliant", "Nonce"],
    "Bridge": ["Incorrect Parameter", "Cannot Revoke", "Invalid Validation", "Nonce"],
    "Zksync": ["EVM Compatibility", "payable / receive()"],
    "Replay Attack": [
        "Invalid Validation", "Asset Theft", "Nonce", "State Update Inconsistency",
    ],
    "Solmate": ["Missing Return Check"],
    "Compound": ["Reward Manipulation"],
    "Solidity Version": ["Misuse of Dependency"],
    "EIP4494": ["Not EIP Compliant"],
    "TWAP": [
        "Price Manipulation / Arbitrage opportunity", "Implementation Error",
        "Rounding Error", "slot0",
    ],
}

# Tags present in train.csv but absent from Tag Definitions.md (one finding each,
# except nothing): kept, flagged in_taxonomy=False, excluded from synthesis and main
# scoring, reported in an appendix (DESIGN §1.3).
OUT_OF_TAXONOMY = {"XSS Attack", "RCE", "Multisig", "Rebalance"}

# Case-insensitive lookup covering both worlds. Built once; `Logic error`,
# `logic error`, `DOS` etc. all fold to the canonical key.
_CANONICAL: dict[str, str] = {t.lower(): t for t in TAXONOMY}
_CANONICAL.update({t.lower(): t for t in OUT_OF_TAXONOMY})


def canonical_tag(raw: str) -> str:
    """Fold a raw tag string to its canonical spelling; unknown tags pass through
    stripped, so nothing is ever silently dropped."""
    s = str(raw).strip()
    return _CANONICAL.get(s.lower(), s)


def split_tags(cell: object) -> list[str]:
    """Split one multi-label cell into raw tag strings, order preserved."""
    if cell is None or (isinstance(cell, float) and pd.isna(cell)):
        return []
    return [t.strip() for t in str(cell).split(",") if t.strip()]


def explode_labels(df: pd.DataFrame, tag_col: str = "tag") -> pd.DataFrame:
    """One row per (finding, tag), with `canonical_tag` and `in_taxonomy` columns.

    25.4% of ground-truth rows are comma-separated multi-labels; every downstream
    consumer (splits, synthesis, scoring) wants atomic tags. All original columns are
    preserved so a row can always be traced back to its source finding. Duplicate tags
    within one cell (e.g. `Logic Error, Logic error`) collapse to a single row.
    """
    records: list[dict] = []
    for _, row in df.iterrows():
        seen: set[str] = set()
        for raw in split_tags(row[tag_col]):
            canon = canonical_tag(raw)
            if canon in seen:
                continue
            seen.add(canon)
            rec = row.to_dict()
            rec["canonical_tag"] = canon
            rec["in_taxonomy"] = canon in TAXONOMY
            records.append(rec)
    return pd.DataFrame.from_records(records)
