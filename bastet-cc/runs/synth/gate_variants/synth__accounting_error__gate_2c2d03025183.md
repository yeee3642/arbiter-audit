# Accounting Error

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Accounting Error**
Accounting errors occur when a protocol's internal bookkeeping diverges from the actual on-chain asset movements or economic reality. Common root causes include: (1) assuming `transferFrom`/`safeTransfer` moves exactly the requested amount, which fails for fee-on-transfer or rebasing tokens where the received balance delta is smaller (or larger) than the argument; (2) updating state variables before or after external calls in an order that allows reentrancy or double-counting; (3) using stale or inflated denominators such as `totalSupply()` that includes burned or non-voting tokens when computing quotas, rewards, or fees; (4) applying formulas that reference the wrong basis (e.g., minting performance fees on total supply instead of realized profit) or skipping required conversions (e.g., returning stETH-denominated prices where WETH is expected); (5) trusting external contract balances without verifying they match the pool's ideal ratios, leading to value loss on deposits. Each of these creates a gap between recorded shares/entitlements and real value, enabling theft, unfair reward distribution, or protocol insolvency.

### Detection Checks

1. Verify that every ERC20 `transferFrom`, `safeTransfer`, or `burnFrom` call is followed by a balance delta check (`balanceAfter - balanceBefore`) instead of trusting the input `amount` parameter, especially for tokens not vetted as standard ERC20.
2. Ensure state updates (e.g., `totalSupply`, user balances, reward indexes) happen *after* the corresponding asset transfer succeeds, and that no external call intervenes between the transfer and the state write.
3. Confirm that denominators used in reward/fee/quorum calculations (e.g., `totalSupply()`, `baseSupply`) exclude burned tokens, tokens held by non-participating contracts, or other non-eligible holdings.
4. Check that performance/management fee formulas mint shares based on *profit* (delta between current NAV and high-water mark) multiplied by the fee rate, not on raw `baseSupply` or `minLpPriceFactor` alone.
5. Validate that price oracles return values in the exact unit expected by the caller (e.g., WETH per share, not stETH per share) and that any required conversion (Curve pool, wrapper contract) is applied.
6. Ensure multi-asset deposits (e.g., `add_liquidity`) compute and enforce the pool's ideal token ratios before depositing, rather than blindly sending the full contract balance of each asset.
7. For rebasing tokens, confirm that locked or staked amounts are read dynamically at withdrawal time (via `balanceOf`) rather than cached at deposit time.
8. Verify that approval mappings or nonces used for withdrawal/loan authorization are scoped to the specific operation (e.g., separate `withdrawApproval` vs `loanApproval`) so one cannot consume the other.

### Examples

#### Example 1: Incorrect Example

```solidity
function deposit(uint256 amount) external {
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    // @audit assumes full amount received; fails for fee-on-transfer
    shares[msg.sender] += amount;
    totalShares += amount;
}
```

The contract credits `amount` shares without measuring the actual tokens received, so fee-on-transfer tokens cause an accounting shortfall.

#### Example 2: Correct Example

```solidity
function deposit(uint256 amount) external {
    uint256 balBefore = IERC20(token).balanceOf(address(this));
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = IERC20(token).balanceOf(address(this)) - balBefore;
    shares[msg.sender] += received;
    totalShares += received;
}
```

Measuring the real balance delta ensures shares match assets actually received, fixing fee-on-transfer and rebasing discrepancies.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
