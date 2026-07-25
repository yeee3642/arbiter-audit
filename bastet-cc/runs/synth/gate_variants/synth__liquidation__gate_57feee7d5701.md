# Liquidation-Logic-Flaws

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Liquidation-Logic-Flaws**
Liquidation logic in lending protocols must correctly compute the collateral value at which a position becomes liquidatable, update all protocol accounting state when debt is repaid via liquidation, and route any callback rewards to the intended recipient. A common flaw is dividing by a collateralValue that can be zero when the collateral factor is misconfigured, causing a revert or incorrect liquidation thresholds. Another flaw is omitting the daily debt increase limit replenishment that normal repayment performs, leaving the protocol in an inconsistent state where the limit is artificially depleted. Finally, flash-loan liquidation callbacks often transfer leftover tokens to msg.sender (the liquidator) instead of the recipient parameter supplied by the user, allowing the liquidator to steal rewards meant for another address.

### Detection Checks

1. In any function that computes a liquidation start value or penalty, verify that the denominator (collateralValue or collateralFactor) is validated as non-zero before division.
2. In the liquidate() entry point, after debtSharesTotal is decreased, confirm that dailyDebtIncreaseLimitLeft (or equivalent capacity tracker) is increased by the repaid asset amount, mirroring the _repay() logic.
3. In flash-loan liquidation callbacks (e.g., uniswapV3FlashCallback), ensure that leftover asset balances are transferred to the recipient address provided in the callback parameters, not to msg.sender or a hard-coded liquidator field.
4. Check that liquidation eligibility (_checkLoanIsHealthy) uses the post-interest debt and up-to-date collateral valuation, and that the health check cannot be bypassed by stale oracle data or manipulated prices.
5. Verify that the liquidation penalty calculation clamps the penalty between MIN_LIQUIDATION_PENALTY and MAX_LIQUIDATION_PENALTY and that the formula does not underflow when fullValue == maxPenaltyValue.
6. Confirm that reserve/insurance fund accounting (reserveCost, missing) is settled before external transfers to prevent reentrancy or state inconsistency.
7. Ensure slippage protection (amount0Min, amount1Min) is enforced after the position value is sent to the liquidator, and that the check uses the actual received amounts.
8. Validate that loan cleanup (_cleanupLoan) correctly resets all storage slots (debtShares, collateral, timestamps) and emits a single Liquidate event with consistent parameters.

### Examples

#### Example 1: Incorrect Example

```solidity
function _calculateLiquidation(uint256 debt, uint256 fullValue, uint256 collateralValue) internal pure returns (uint256, uint256, uint256) {
    uint256 startLiquidationValue = debt * fullValue / collateralValue; // @audit collateralValue can be 0
    // ... penalty math ...
}

function liquidate(LiquidateParams calldata params) external {
    // ... health check ...
    debtSharesTotal -= debtShares;
    // @audit missing: dailyDebtIncreaseLimitLeft += repaidAssetAmount;
    _sendPositionValue(...);
}

function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata callbackData) external {
    FlashCallbackData memory data = abi.decode(callbackData, (FlashCallbackData));
    // ... swaps ...
    SafeERC20.safeTransfer(data.asset, data.liquidator, balance); // @audit should use data.recipient
}
```

Division by zero in _calculateLiquidation, missing daily limit replenishment in liquidate, and callback rewards sent to liquidator instead of recipient.

#### Example 2: Correct Example

```solidity
function _calculateLiquidation(uint256 debt, uint256 fullValue, uint256 collateralValue) internal pure returns (uint256, uint256, uint256) {
    require(collateralValue > 0, "ZERO_COLLATERAL_VALUE");
    uint256 startLiquidationValue = debt * fullValue / collateralValue;
    // ... penalty math ...
}

function liquidate(LiquidateParams calldata params) external {
    // ... health check ...
    debtSharesTotal -= debtShares;
    dailyDebtIncreaseLimitLeft += repaidAssetAmount; // mirror _repay()
    _sendPositionValue(...);
}

function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata callbackData) external {
    FlashCallbackData memory data = abi.decode(callbackData, (FlashCallbackData));
    // ... swaps ...
    SafeERC20.safeTransfer(data.asset, data.recipient, balance); // correct recipient
}
```

Added zero-check for collateralValue, replenished daily debt limit on liquidation, and routed callback leftovers to the intended recipient.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
