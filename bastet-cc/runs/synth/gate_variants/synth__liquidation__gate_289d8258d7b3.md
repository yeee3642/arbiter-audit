# Liquidation-Process-Flaws

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Liquidation-Process-Flaws**
Liquidation logic in lending and collateralized-debt protocols must correctly identify under-collateralized positions, compute the exact debt and collateral amounts to be repaid and seized, iterate over every collateral vault or asset type backing the position, enforce that only eligible liquidators (not the position owner) can trigger the process, and support partial liquidation so that a position can be brought back above the minimum collateral ratio without being fully closed. Common failures include: (1) skipping vaults or asset types when moving collateral, causing the external transfer to revert or leaving collateral behind; (2) missing a check that `msg.sender != positionOwner`, which lets a user self-liquidate to bypass same-block deposit/withdraw restrictions; (3) burning the entire minted debt (`mintedDyad(address(this), id)`) instead of accepting a `repayAmount` parameter, which forces full liquidation and prevents incremental recovery; (4) using stale or manipulated oracle prices when calculating the collateral ratio, leading to premature or delayed liquidations; (5) failing to update position state (debt, collateral, health factor) atomically before external calls, opening reentrancy or double-liquidation windows; (6) not validating that the liquidation reward or discount stays within protocol bounds, enabling liquidator profit extraction or bad debt.

### Detection Checks

1. The liquidation function iterates over every collateral vault array (e.g., both `vaults[id]` and `vaultsKerosene[id]`) so that the sum of transferred collateral equals the computed `liquidationAssetShare`.
2. A require statement enforces `msg.sender != ownerOf(id)` (or equivalent ownership check) to prevent self-liquidation.
3. The function accepts a `uint256 repayAmount` parameter and burns only that amount (`dyad.burn(id, msg.sender, repayAmount)`), with a check that `repayAmount <= totalDebt(id)` and that post-liquidation collateral ratio >= MIN_COLLATERIZATION_RATIO.
4. Collateral ratio is computed using a fresh oracle price: the function reads `updatedAt` from the price feed and reverts if `updatedAt < block.timestamp - HEARTBEAT`.
5. State updates (debt reduction, collateral reduction, health factor recalculation) occur before any external `vault.move` or token transfer calls.
6. Liquidation reward/discount calculation clamps the result: `liquidationEquityShare = min((cappedCr - 1e18) * LIQUIDATION_REWARD, MAX_LIQUIDATION_REWARD)` and reverts if the reward exceeds a protocol-defined cap.
7. The function emits a `Liquidate` event with `id`, `liquidator`, `receiver`, `repayAmount`, and `collateralSeized` for off-chain monitoring.
8. Reentrancy guard (`nonReentrant` modifier) protects the entire liquidation flow.

### Examples

#### Example 1: Incorrect Example

```solidity
function liquidate(uint256 id, uint256 to) external isValidDNft(id) isValidDNft(to) {
    uint256 cr = collatRatio(id);
    if (cr >= MIN_COLLATERIZATION_RATIO) revert CrTooHigh();
    // Burns entire debt, no partial liquidation
    dyad.burn(id, msg.sender, dyad.mintedDyad(address(this), id));
    uint256 cappedCr = cr < 1e18 ? 1e18 : cr;
    uint256 liquidationEquityShare = (cappedCr - 1e18).mulWadDown(LIQUIDATION_REWARD);
    uint256 liquidationAssetShare = (liquidationEquityShare + 1e18).divWadDown(cappedCr);
    // Only iterates vaults[id], omits vaultsKerosene[id]
    for (uint256 i = 0; i < vaults[id].length(); i++) {
        Vault vault = Vault(vaults[id].at(i));
        uint256 collateral = vault.id2asset(id).mulWadUp(liquidationAssetShare);
        vault.move(id, to, collateral);
    }
    // No check that msg.sender != ownerOf(id) -> self-liquidation possible
    emit Liquidate(id, msg.sender, to);
}
```

The function burns the full debt, skips kerosene vaults, lacks a self-liquidation guard, and uses no oracle freshness check.

#### Example 2: Correct Example

```solidity
function liquidate(uint256 id, uint256 to, uint256 repayAmount) external nonReentrant isValidDNft(id) isValidDNft(to) {
    require(msg.sender != ownerOf(id), "Self-liquidation not allowed");
    uint256 totalDebt = dyad.mintedDyad(address(this), id);
    require(repayAmount > 0 && repayAmount <= totalDebt, "Invalid repay amount");
    // Fresh oracle price
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    require(updatedAt >= block.timestamp - HEARTBEAT, "Stale price");
    uint256 cr = collatRatio(id, price);
    require(cr < MIN_COLLATERIZATION_RATIO, "Position healthy");
    dyad.burn(id, msg.sender, repayAmount);
    uint256 cappedCr = cr < 1e18 ? 1e18 : cr;
    uint256 liquidationEquityShare = (cappedCr - 1e18).mulWadDown(LIQUIDATION_REWARD);
    liquidationEquityShare = liquidationEquityShare > MAX_LIQUIDATION_REWARD ? MAX_LIQUIDATION_REWARD : liquidationEquityShare;
    uint256 liquidationAssetShare = (liquidationEquityShare + 1e18).divWadDown(cappedCr);
    // Iterate all collateral vaults
    for (uint256 i = 0; i < vaults[id].length(); i++) {
        Vault vault = Vault(vaults[id].at(i));
        uint256 collateral = vault.id2asset(id).mulWadUp(liquidationAssetShare);
        vault.move(id, to, collateral);
    }
    for (uint256 i = 0; i < vaultsKerosene[id].length(); i++) {
        Vault vault = Vault(vaultsKerosene[id].at(i));
        uint256 collateral = vault.id2asset(id).mulWadUp(liquidationAssetShare);
        vault.move(id, to, collateral);
    }
    emit Liquidate(id, msg.sender, to, repayAmount, liquidationAssetShare);
}
```

Adds partial liquidation via repayAmount, self-liquidation guard, stale-price check, reward cap, iteration over both vault arrays, reentrancy guard, and richer event.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
