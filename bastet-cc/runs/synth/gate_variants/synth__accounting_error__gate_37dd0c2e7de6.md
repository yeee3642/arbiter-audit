# Accounting Error

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Accounting Error**
Accounting errors occur when a protocol's internal state diverges from the actual on-chain reality of asset balances, token mechanics, or cross-module invariants. Common root causes include: (1) assuming `transferFrom`/`burnFrom` moves exactly the requested amount, which fails for fee-on-transfer or rebasing tokens where received amounts differ; (2) reading balances or exchange rates before state-updating calls (e.g., `_updateValidator`, reward accrual) so calculations use stale values; (3) omitting supply/balance adjustments after burns, mints, or cross-contract transfers; (4) using incorrect conversion formulas or missing conversion steps (e.g., wstETH→stETH without stETH→WETH); (5) depositing full contract balances into AMMs without respecting pool ratios, causing value loss; (6) sharing approval mappings across unrelated operations (withdraw vs. loan) so approvals are double-spent; (7) calculating deltas after external calls that may refund value, conflating sent and net amounts. Auditors must trace every asset movement against the corresponding state mutation and verify that the arithmetic matches the token's true behavior.

### Detection Checks

1. Verify that every ERC20 `transferFrom`, `safeTransferFrom`, or `burnFrom` is followed by a balance-delta check (post-balance minus pre-balance) rather than trusting the input `amount` parameter.
2. Ensure state variables tracking total supply, user shares, or delegated amounts are updated atomically with the corresponding token burn/mint/transfer (e.g., `totalSupply--` inside the same transaction as `_burn`).
3. Confirm that exchange rates, prices, or accumulator values are read *after* any reward-accrual or rate-update hooks (`_updateValidator`, `updateReward`, `sync`) that mutate those values.
4. Check that fee-on-transfer and rebasing tokens are either rejected at deployment/whitelisting or handled via balance-delta accounting in every deposit/withdraw/burn path.
5. Validate that multi-asset AMM deposits (e.g., Curve `add_liquidity`) compute amounts proportional to the pool's ideal ratios instead of dumping raw contract balances.
6. Ensure approval mappings are namespaced by operation type (withdraw vs. borrow vs. spend) so an approval for one action cannot be consumed by another.
7. Verify that price/value conversion functions apply the full chain of oracle calls (e.g., wstETH→stETH→WETH→USD) without truncating intermediate steps.
8. Confirm that delta calculations around external calls (`call{value: ...}`) capture only the net change attributable to the intended swap, excluding refunds or unrelated balance changes.

### Examples

#### Example 1: Incorrect Example

```solidity
function burnFromUser(address user, uint256 amount) external {
    IERC20(token).burnFrom(user, amount); // assumes full amount burned
    totalShares -= amount; // accounting uses requested amount
}

function depositRebasing(address user, uint256 amount) external {
    IERC20(token).safeTransferFrom(user, address(this), amount);
    userDeposits[user] += amount; // records static amount
}

function withdrawRebasing(address user) external {
    uint256 amount = userDeposits[user];
    IERC20(token).safeTransfer(user, amount); // may revert or underpay after rebase
    userDeposits[user] = 0;
}
```

The burn path trusts `burnFrom` to burn exactly `amount` (fails for fee-on-transfer), the rebasing deposit records a fixed `amount` instead of the actual balance increase, and the withdraw sends that stale amount causing revert on negative rebase or underpayment on positive rebase.

#### Example 2: Correct Example

```solidity
function burnFromUser(address user, uint256 amount) external {
    uint256 pre = token.balanceOf(address(this));
    IERC20(token).burnFrom(user, amount);
    uint256 actual = token.balanceOf(address(this)) - pre;
    totalShares -= actual; // account for fee-on-transfer
}

function depositRebasing(address user) external {
    uint256 pre = token.balanceOf(address(this));
    IERC20(token).safeTransferFrom(user, address(this), type(uint256).max);
    uint256 actual = token.balanceOf(address(this)) - pre;
    userDeposits[user] += actual; // record real increase
}

function withdrawRebasing(address user) external {
    uint256 shares = userDeposits[user];
    uint256 pre = token.balanceOf(address(this));
    IERC20(token).safeTransfer(user, shares);
    uint256 actual = pre - token.balanceOf(address(this));
    userDeposits[user] -= actual; // deduct real decrease
}
```

All token movements use pre/post balance deltas to capture the true amount transferred, burned, or rebased, keeping accounting in sync with on-chain reality.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
