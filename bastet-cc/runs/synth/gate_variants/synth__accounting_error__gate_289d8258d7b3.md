# Accounting Error

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Accounting Error**
Accounting errors occur when a protocol's internal bookkeeping diverges from the actual on-chain asset movements or economic reality. Common mechanisms include: (1) State update inconsistency — balances, totals, or indices are not adjusted atomically with transfers, mints, burns, or external calls, leaving counters stale or double-counted. (2) Missing validation of token behavior — assuming ERC20.transfer/transferFrom moves exactly the requested amount ignores fee-on-transfer, rebasing, or non-standard tokens that deliver less (or revert). (3) Incorrect formula or parameter usage — fee calculations, reward accrual, price conversions, or share minting use wrong operands (e.g., total supply instead of profit, stETH instead of WETH, full delta instead of excess over debt). (4) Cross-module desynchronization — vaults, strategies, escrows, or AMM pools update their local records at different times or with different bases, causing invariant violations. (5) Unchecked external state — reading raw contract balances (balanceOf) without verifying they match expected ratios or accounting for pending settlements leads to imbalanced deposits or overstated TVL. Auditors must trace every asset movement and verify that each corresponding accounting entry is updated in the same transaction, with the correct arithmetic, and that assumptions about token semantics are explicitly validated.

### Detection Checks

1. Verify that every external token transfer (transfer, transferFrom, safeTransfer, safeTransferFrom) is followed by a balance delta check (balanceOf after - balanceOf before) rather than trusting the requested amount.
2. Confirm that totalSupply, user balances, vault balances, strategy balances, and reward indices are updated in the same execution context as the corresponding mint, burn, deposit, withdraw, or harvest — no deferred or omitted updates.
3. Check fee and reward formulas: performance fees must mint on profit (current price - highWaterMark) * feeRate, not on totalSupply * priceFactor; management fees must use elapsed time since last charge, not absolute timestamps.
4. Ensure price oracles and conversion functions return the correct unit (e.g., WETH not stETH) and that the full conversion path (wstETH -> stETH -> WETH via Curve) is applied when the protocol accounts in underlying.
5. Validate that deposit/liquidity functions verify token ratios against pool ideal proportions before calling add_liquidity or zap, rather than depositing raw balances.
6. Confirm that rebase/elastic tokens are handled by reading current balanceOf at execution time, not by caching amounts at lock/deposit time.
7. Check that order/position lifecycle functions (stop, settle, harvest, liquidate) verify the order exists, is in the correct state, and belongs to the caller before mutating storage.
8. Ensure that early-return conditions in reward accrual (e.g., totalSupply == 0) still update lastUpdated timestamps so the baseline does not stay stale.

### Examples

#### Example 1: Incorrect Example

```solidity
function harvestStrategy(address _strategy) external {
    uint256 before = IStrategy(_strategy).balanceOf();
    IStrategy(_strategy).harvest();
    uint256 after = IStrategy(_strategy).balanceOf();
    // BUG: adds full delta even if strategy exceeds its debt limit
    vaultDetails[vault].balance += after - before;
    vaultDetails[vault].balances[_strategy] = after;
}
```

The vault balance is increased by the entire strategy balance delta without capping at the strategy's allocated debt/limit, overcounting assets when the strategy grows beyond its allowance.

#### Example 2: Correct Example

```solidity
function harvestStrategy(address _strategy) external {
    uint256 before = IStrategy(_strategy).balanceOf();
    IStrategy(_strategy).harvest();
    uint256 after = IStrategy(_strategy).balanceOf();
    uint256 debt = vaultDetails[vault].debts[_strategy];
    uint256 gain = after > debt ? after - debt : 0;
    vaultDetails[vault].balance += gain;
    vaultDetails[vault].balances[_strategy] = after;
}
```

Only the profit exceeding the strategy's debt is added to the vault balance, preventing overcounting when the strategy balance grows beyond its allocated limit.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
