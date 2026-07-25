---
id: synth__liquidation
name: "Liquidation-Process-Flaws"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Liquidation"]
routing_hints: ["liquidate", "healthFactor", "collateralFactor", "seize", "repay", "id2asset", "NotLiquidatable", "SlippageError", "liquidationCost", "CrTooHigh", "DebtChanged", "FlashCallbackData", "MIN_COLLATERIZATION_RATIO", "_calculateLiquidation"]
required_hints: []
prompt_chars: 6270
synthesized: true
gated: false
synth_provenance: {"train_findings": ["372", "375", "367", "362", "349", "335"], "localization_rate": 1.0, "mode": "s2", "hint_candidates": 29, "hints_rejected": 1, "hint_coverage": 0.765, "single_repo_hints": true, "hint_fallback": false, "loro": {"hit": 1.0, "fp": 0.0, "folds": 2, "repaired": false}}
---

# Liquidation-Process-Flaws

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Liquidation-Process-Flaws**
Liquidation logic in lending and collateralized-debt protocols must correctly (1) determine whether a position is under-collateralized using an up-to-date price feed, (2) calculate the exact debt to repay and collateral to seize, (3) iterate over every collateral vault or token type the position holds, (4) enforce that only eligible liquidators can act and that the caller is not the position owner self-liquidating to bypass other restrictions, (5) support partial liquidation so that a liquidator can repay a fraction of the debt and receive a proportional share of collateral, (6) update all global and per-position accounting state (total debt shares, daily borrow limits, reserve balances, exchange rates) atomically with the asset transfers, (7) validate any permit or signature data against the expected asset and amounts, and (8) route every token transfer—including liquidation rewards, protocol fees, and leftover collateral—to the explicitly designated recipients. Failures in any of these steps lead to positions that cannot be liquidated, over-liquidation, asset theft via callback reentrancy or permit replay, accounting drift that breaks invariant checks, or griefing of liquidators and borrowers.

### Detection Checks

1. Liquidation eligibility check uses a collateral-ratio or health-factor calculation that does not refresh the oracle price immediately before the comparison (stale price).
2. Loop that moves collateral iterates over only a subset of the position's vault arrays (e.g., vaults[id] but not vaultsKerosene[id]), causing the total transferred amount to fall short of the calculated liquidationAssetShare and the external vault.move call to revert.
3. Function burns the full minted debt amount (dyad.mintedDyad or loans[tokenId].debtShares) without accepting a partial-repayment parameter, making partial liquidation impossible.
4. Missing authorization check that msg.sender != position owner, allowing self-liquidation to circumvent same-block deposit/withdrawal restrictions.
5. After repaying debt via debtSharesTotal -= debtShares, the daily borrow limit (dailyDebtIncreaseLimitLeft) is not increased by the repaid asset amount, creating an accounting inconsistency with the normal repay() path.
6. Permit2.permitTransferFrom (or equivalent EIP-2612 permit) is called with user-supplied permitData without verifying that permit.details.token == address(asset), enabling asset-spoofing attacks.
7. Flash-loan callback (uniswapV3FlashCallback) transfers leftover tokens to data.liquidator (msg.sender of the outer liquidate call) instead of the recipient specified in the original LiquidateParams, diverting liquidation rewards.
8. State updates (debtSharesTotal, loan cleanup, exchange-rate caches) are performed before or without atomic asset transfers, violating checks-effects-interactions and leaving the protocol in an inconsistent state if a transfer reverts.

### Examples

#### Example 1: Incorrect Example

```solidity
function liquidate(uint256 id, uint256 to) external {
    uint256 cr = collatRatio(id); // uses stale oracle price
    if (cr >= MIN_COLLATERIZATION_RATIO) revert CrTooHigh();
    // burns entire position, no partial amount param
    dyad.burn(id, msg.sender, dyad.mintedDyad(address(this), id));
    uint256 cappedCr = cr < 1e18 ? 1e18 : cr;
    uint256 liquidationAssetShare = (cappedCr - 1e18).mulWadDown(LIQUIDATION_REWARD);
    liquidationAssetShare = (liquidationAssetShare + 1e18).divWadDown(cappedCr);
    // iterates only vaults[id], omits vaultsKerosene[id]
    for (uint i = 0; i < vaults[id].length(); i++) {
        Vault v = Vault(vaults[id].at(i));
        uint256 col = v.id2asset(id).mulWadUp(liquidationAssetShare);
        v.move(id, to, col);
    }
    // no check msg.sender != owner -> self-liquidation bypass
    // no dailyDebtIncreaseLimitLeft adjustment
    emit Liquidate(id, msg.sender, to);
}
```

The function uses a stale collateral ratio, burns the full debt preventing partial liquidation, iterates over only one vault array, lacks a self-liquidation guard, and omits accounting updates for daily borrow limits.

#### Example 2: Correct Example

```solidity
function liquidate(uint256 id, uint256 to, uint256 repayShares) external {
    _updateOraclePrices(); // refresh prices before health check
    uint256 cr = collatRatio(id);
    if (cr >= MIN_COLLATERIZATION_RATIO) revert CrTooHigh();
    if (msg.sender == ownerOf(id)) revert SelfLiquidation();
    require(repayShares > 0 && repayShares <= debtShares[id], "invalid amount");
    dyad.burn(id, msg.sender, repayShares);
    uint256 cappedCr = cr < 1e18 ? 1e18 : cr;
    uint256 liquidationAssetShare = (cappedCr - 1e18).mulWadDown(LIQUIDATION_REWARD);
    liquidationAssetShare = (liquidationAssetShare + 1e18).divWadDown(cappedCr);
    liquidationAssetShare = liquidationAssetShare.mulWadDown(repayShares / debtShares[id]); // pro-rata
    // iterate ALL collateral vaults
    for (uint i = 0; i < vaults[id].length(); i++) {
        Vault v = Vault(vaults[id].at(i));
        uint256 col = v.id2asset(id).mulWadUp(liquidationAssetShare);
        v.move(id, to, col);
    }
    for (uint i = 0; i < vaultsKerosene[id].length(); i++) {
        Vault v = Vault(vaultsKerosene[id].at(i));
        uint256 col = v.id2asset(id).mulWadUp(liquidationAssetShare);
        v.move(id, to, col);
    }
    debtSharesTotal -= repayShares;
    dailyDebtIncreaseLimitLeft += repaySharesToAssets(repayShares);
    emit Liquidate(id, msg.sender, to, repayShares);
}
```

Prices are refreshed, self-liquidation is blocked, partial repayment is supported with pro-rata collateral seizure, all vault arrays are iterated, and global accounting (debtSharesTotal, dailyDebtIncreaseLimitLeft) is updated atomically.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
