# Liquidation-Process Flaws

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Liquidation-Process Flaws**
Liquidation logic in lending protocols must correctly determine when a position becomes liquidatable, calculate the liquidator's reward and protocol reserve share, update global accounting state, and transfer the correct assets to the correct parties. A division by zero occurs if the collateral factor is zero, making collateralValue zero and causing startLiquidationValue = debt * fullValue / collateralValue to revert. State inconsistencies arise when liquidate() reduces debtSharesTotal but fails to increase dailyDebtIncreaseLimitLeft by the repaid asset amount, unlike _repay(), breaking invariant tracking. Callback handlers that return leftover tokens must respect the recipient parameter supplied by the caller; sending rewards to msg.sender (the flash-loan initiator) instead of params.recipient lets a liquidator steal the reward. Each of these flaws lets positions avoid liquidation, over-liquidates them, or diverts value to the wrong address.

### Detection Checks

1. In _calculateLiquidation or equivalent, verify collateralValue (or collateralFactorX32) is checked for zero before any division uses it as denominator.
2. In liquidate(), after debtSharesTotal -= debtShares, confirm dailyDebtIncreaseLimitLeft (or analogous capacity tracker) is increased by the asset amount repaid.
3. In any flash-callback (e.g., uniswapV3FlashCallback), ensure leftover asset balances are transferred to the recipient address provided in the liquidation params, not to msg.sender or a hard-coded liquidator field.
4. Confirm liquidation trigger condition (_checkLoanIsHealthy or similar) uses the same price oracle and collateral factor as borrowing/minting to avoid mismatched valuations.
5. Verify liquidation penalty calculation clamps penaltyFractionX96 between MIN_LIQUIDATION_PENALTY_X32 and MAX_LIQUIDATION_PENALTY_X32 and that startLiquidationValue > maxPenaltyValue before subtraction.
6. Check that _sendPositionValue or equivalent transfers exactly liquidationValue worth of collateral to the liquidator and returns any remainder to the borrower, with slippage checks against amount0Min/amount1Min.
7. Ensure reentrancy guards or checks-effects-interactions ordering protect the liquidate() flow, especially when external calls (permit2, safeTransferFrom, _sendPositionValue) occur before state updates like debtSharesTotal reduction.
8. Validate that reserveCost accounting (_handleReserveLiquidation) correctly mints/burns reserve shares and that missing (shortfall) is tracked for socialized loss distribution.

### Examples

#### Example 1: Incorrect Example

```solidity
function _calculateLiquidation(uint256 debt, uint256 fullValue, uint256 collateralValue) internal pure returns (uint256, uint256, uint256) {
    uint256 startLiquidationValue = debt * fullValue / collateralValue; // @audit division by zero if collateralValue == 0
    // ... penalty math ...
}

function liquidate(LiquidateParams calldata params) external {
    // ... health check ...
    debtSharesTotal -= loans[params.tokenId].debtShares;
    // @audit missing: dailyDebtIncreaseLimitLeft += repaidAssetAmount;
    _sendPositionValue(params.tokenId, liquidationValue, fullValue, feeValue, msg.sender);
}

function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata callbackData) external {
    FlashCallbackData memory data = abi.decode(callbackData, (FlashCallbackData));
    // ... swaps ...
    SafeERC20.safeTransfer(data.asset, data.liquidator, balance); // @audit should use data.recipient
}
```

Division by zero when collateral factor is zero; daily debt limit not replenished on liquidation; callback sends rewards to msg.sender instead of params.recipient.

#### Example 2: Correct Example

```solidity
function _calculateLiquidation(uint256 debt, uint256 fullValue, uint256 collateralValue) internal pure returns (uint256, uint256, uint256) {
    if (collateralValue == 0) revert ZeroCollateralFactor();
    uint256 startLiquidationValue = debt * fullValue / collateralValue;
    // ... penalty math with bounds checks ...
}

function liquidate(LiquidateParams calldata params) external {
    // ... health check ...
    uint256 repaidAssets = _convertToAssets(debtShares, newDebtExchangeRateX96, Math.Rounding.Up);
    debtSharesTotal -= debtShares;
    dailyDebtIncreaseLimitLeft += repaidAssets; // restore capacity
    _sendPositionValue(params.tokenId, liquidationValue, fullValue, feeValue, params.recipient);
}

function uniswapV3FlashCallback(uint256 fee0, uint256 fee1, bytes calldata callbackData) external {
    FlashCallbackData memory data = abi.decode(callbackData, (FlashCallbackData));
    // ... swaps ...
    SafeERC20.safeTransfer(data.asset, data.recipient, balance); // correct recipient
}
```

Zero-collateral guard added; daily debt limit replenished; callback respects recipient parameter.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
