# Accounting Error

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Accounting Error**
Accounting errors arise when on-chain state diverges from the real asset movements or economic intent of a protocol. Common root causes include: (1) trusting external token transfers without measuring actual balance deltas, which breaks for fee-on-transfer, rebasing, or non-standard ERC-20s; (2) updating counters (totalSupply, user balances, reward indexes) in the wrong order or omitting updates entirely, creating invariant violations; (3) using stale or unvalidated inputs (prices, timestamps, order hashes) in calculations; (4) applying formulas that confuse absolute quantities with rates or that omit fee factors, leading to systematic over- or under-minting; (5) failing to synchronize cross-module records (vault↔strategy, escrow↔order, reward tracker↔token) so the same value is counted twice or not at all. Auditors must trace every asset inflow/outflow and verify that the corresponding state mutation is atomic, correctly ordered, and uses the *actual* transferred amount rather than the requested amount.

### Detection Checks

1. After any external `transferFrom`, `safeTransferFrom`, or `burnFrom` call, the contract must read the *post-transfer* balance (or `totalSupply` delta) and use that measured delta for accounting instead of the input `amount` parameter.
2. Any function that mints/burns shares or updates `totalSupply` must perform the state update in the same transaction and before any external call that could re-enter or change balances.
3. Reward/index update functions (`_updateRewardsPerToken`, `updateReward`, etc.) must update `lastUpdated`/`periodFinish` even when `totalSupply == 0` or the reward period has not started, otherwise the first depositor inherits stale history.
4. Price/valuation functions must convert through the full oracle chain (e.g., wstETH → stETH → WETH via Curve) and not stop at an intermediate unit; the returned denomination must match the caller's expectation.
5. Performance/management fee calculations must compute *incremental* profit (current NAV minus high-water mark) multiplied by the fee rate, not apply the fee rate to `totalSupply` or principal.
6. Harvest/deposit/withdraw flows that sync vault↔strategy balances must credit only the *net profit* (strategy balance after harvest minus strategy debt/limit), not the gross balance delta.
7. Order/position lifecycle functions (`stopRent`, `liquidate`, `closePosition`) must verify the order hash exists in storage and that the order is in a fulfillable state before mutating any balances or deleting records.
8. Liquidity provision helpers (`add_liquidity`, `zap`, `deposit`) must calculate token amounts in the pool's target ratio (using `calc_token_amount` or similar) instead of dumping raw contract balances, which creates imbalanced deposits and LP token shortfalls.

### Examples

#### Example 1: Incorrect Example

```solidity
function deposit(uint256 amount) external {
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    // BUG: assumes full `amount` arrived; fee-on-transfer tokens deliver less
    shares[msg.sender] += amount;
    totalSupply += amount;
}
```

The contract credits the user with the requested `amount` instead of the actual balance increase, causing an accounting mismatch for fee-on-transfer or rebasing tokens.

#### Example 2: Correct Example

```solidity
function deposit(uint256 amount) external {
    uint256 before = token.balanceOf(address(this));
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    uint256 after = token.balanceOf(address(this));
    uint256 actual = after - before;
    shares[msg.sender] += actual;
    totalSupply += actual;
}
```

Measuring the balance delta after the transfer ensures the accounting reflects the real tokens received, works for any ERC-20 variant, and preserves the invariant `totalSupply == token.balanceOf(address(this))`.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
