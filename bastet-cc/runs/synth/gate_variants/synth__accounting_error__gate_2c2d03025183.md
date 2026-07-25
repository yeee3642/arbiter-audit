# Accounting Error

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Accounting Error**
Accounting errors occur when a protocol's internal state diverges from the true on-chain reality of assets it manages. Common mechanisms include: (1) assuming `transferFrom`/`burnFrom` moves the full requested amount, while fee-on-transfer or rebasing tokens deliver less (or more) to the contract; (2) using stale cached values (e.g., `totalSupply`, `lastUpdated`, high-water marks) without synchronizing them before reads or writes; (3) computing rewards, fees, or prices with formulas that omit components (missing conversion hops, wrong denominator, profit vs. principal confusion); (4) updating state in the wrong order — e.g., emitting events or minting shares before balances are finalized — enabling reentrancy or double-counting; (5) trusting external balances (`balanceOf(this)`) without verifying they match expected deltas after transfers, swaps, or liquidity operations. These flaws let attackers drain value, brick accounting, or silently misallocate rewards/fees.

### Detection Checks

1. After any `transferFrom`, `safeTransferFrom`, `burnFrom`, or low-level `call` to an ERC20, verify the contract's actual balance delta (via `balanceOf(address(this))` before/after) matches the expected amount; revert or adjust accounting if it differs.
2. Before reading `totalSupply()`, `balanceOf()`, or any user-supplied amount for reward/fee/share calculations, ensure the relevant state (e.g., `rewardsPerToken.lastUpdated`, `lpPriceHighWaterMarks`, `lastFeeCharge`) has been updated to the current block timestamp or latest checkpoint.
3. When computing performance/management/protocol fees, confirm the formula uses *profit* (current value minus high-water mark or cost basis) multiplied by the fee rate, not total supply or principal; check for missing `(factor - DENOMINATOR)` or division by `DENOMINATOR^2` where required.
4. In price oracles or `price()` functions, trace the full conversion path (e.g., wstETH -> stETH -> WETH via Curve) and ensure every hop is applied; a single-hop return in a multi-hop asset is an accounting error.
5. When calculating protocol rewards from collected fees, verify the fee amount excludes principal/liquidity returns; `_decreaseFullLiquidityAndCollect` often returns `collectedAmount - decreaseLiquidityReturn` where the latter contains principal.
6. For quorum or voting-power denominators, exclude burned tokens and tokens held by non-voting contracts (auction, treasury, staking) from `totalSupply()`; use a `votingSupply()` or snapshot instead.
7. Before depositing into a multi-asset pool (Curve, Balancer), compute the ideal ratio from the pool's `get_virtual_price` or reserves and adjust input amounts; depositing raw `balanceOf(this)` for each token causes imbalanced deposits and LP token loss.
8. For rebase tokens (stETH, aUSDC, etc.), never cache a static `amount` at lock/deposit time and later transfer that fixed value; always read the current `balanceOf(user)` or `sharesToAssets` conversion at execution time.

### Examples

#### Example 1: Incorrect Example

```solidity
function depositRebase(address user, uint256 amount) external {
    // Record static amount at deposit time
    deposits[user] = amount;
    IERC20(rebaseToken).safeTransferFrom(user, address(this), amount);
}

function withdrawRebase(address user) external {
    // Transfer the *original* amount, ignoring rebases
    uint256 amt = deposits[user];
    delete deposits[user];
    IERC20(rebaseToken).safeTransfer(user, amt); // @audit underpays on positive rebase, reverts on negative rebase
}
```

Caches a fixed token amount at deposit and withdraws that same amount later, ignoring rebasing balance changes.

#### Example 2: Correct Example

```solidity
function depositRebase(address user, uint256 amount) external {
    uint256 sharesBefore = rebaseToken.balanceOf(address(this));
    IERC20(rebaseToken).safeTransferFrom(user, address(this), amount);
    uint256 sharesAfter = rebaseToken.balanceOf(address(this));
    deposits[user] = sharesAfter - sharesBefore; // store *shares* received
}

function withdrawRebase(address user) external {
    uint256 shares = deposits[user];
    delete deposits[user];
    // Convert current shares to assets at withdrawal time
    uint256 assets = rebaseToken.convertToAssets(shares);
    IERC20(rebaseToken).safeTransfer(user, assets);
}
```

Stores share deltas on deposit and converts shares to current asset value on withdrawal, respecting rebases.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
