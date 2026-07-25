---
id: synth__accounting_error
name: "Accounting Error"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Accounting Error"]
routing_hints: ["totalAssets", "exchangeRate", "accrue", "totalBorrows", "parameter", "totalShares", "safeCall", "dai", "_burn", "shares", "tokenAddresses", "SafeERC20", "_updateRewardsPerToken", "ethDelta"]
required_hints: []
prompt_chars: 4753
synthesized: true
gated: false
synth_provenance: {"train_findings": ["198", "18", "251", "297", "134", "450", "51", "228", "34", "387"], "localization_rate": 0.882, "mode": "s2", "hint_candidates": 30, "hints_rejected": 26, "hint_coverage": 0.533, "single_repo_hints": false, "hint_fallback": false, "loro": {"hit": 0.8, "fp": 0.5, "folds": 5, "repaired": false}}
---

# Accounting Error

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Accounting Error**
Accounting errors occur when on-chain state diverges from the real asset movements or economic reality the protocol assumes. Common mechanisms include: (1) trusting external calls without verifying the actual balance delta (fee-on-transfer, rebasing, or refunded ETH), (2) updating rewards or accrual baselines only on the happy path so the first user after a gap captures all missed accrual, (3) computing fees on a denominator that already includes prior fees causing exponential compounding, (4) omitting supply/burn counters so totalSupply drifts from circulating tokens, (5) depositing raw contract balances into multi-asset pools without enforcing target ratios, and (6) skipping validation of token properties (fee-on-transfer, rebase) at deployment or first use. Each pattern lets the protocol's internal ledger disagree with what the blockchain actually did, enabling theft, unfair reward distribution, or permanent value leakage.

### Detection Checks

1. Verify every ERC20 transferFrom/transfer/safeTransferFrom is followed by a balanceOf delta check (post - pre >= amount) or uses a pull-pattern that measures actual received amounts.
2. Ensure reward/accrual update functions (e.g., _updateRewardsPerToken) write the new baseline (lastUpdated, index, period) even when totalSupply == 0 or the period has not started, so the first depositor does not inherit stale state.
3. Confirm fee calculations use a denominator that excludes the fee shares being minted in the same transaction (e.g., totalSharesBeforeFee instead of totalShares after mint).
4. Check that every _mint/_burn internal call has a matching increment/decrement of a totalSupply or equivalent supply tracker in the same execution context.
5. Validate that multi-asset liquidity additions (Curve add_liquidity, Uniswap mint) compute amounts from target ratios or min amounts rather than raw balanceOf(this).
6. Require deployment/initialization routines to probe token behavior (fee-on-transfer via transferFrom with amount > 0 and measure received, rebase via balanceOf before/after a dummy transfer) and revert on unexpected traits.
7. Ensure ETH-denominated swap/fill functions measure msg.value sent vs. actual balance change after the external call, and treat refunded ETH as a separate accounting leg rather than netting it into a single delta.
8. Confirm that approval/allowance mappings used for privileged withdrawals are namespaced per operation (e.g., withdrawApproval vs. loanApproval) so one approval cannot be consumed by a different code path.

### Examples

#### Example 1: Incorrect Example

```solidity
function withdrawReserves(address to_, IERC20 token_, uint256 amount_) external {
    require(withdrawApproval[msg.sender][token_] >= amount_, "not approved");
    withdrawApproval[msg.sender][token_] -= amount_;
    token_.safeTransfer(to_, amount_);
}

function repayLoan(address token_, uint256 amount_) external {
    require(withdrawApproval[msg.sender][token_] >= amount_, "not approved");
    withdrawApproval[msg.sender][token_] -= amount_;
    token_.safeTransferFrom(msg.sender, address(this), amount_);
}
```

Both withdrawReserves and repayLoan consume the same withdrawApproval mapping, so an approval for a loan repayment can be reused to drain reserves via withdrawReserves.

#### Example 2: Correct Example

```solidity
function withdrawReserves(address to_, IERC20 token_, uint256 amount_) external {
    require(withdrawApproval[msg.sender][token_] >= amount_, "not approved");
    withdrawApproval[msg.sender][token_] -= amount_;
    uint256 before = token_.balanceOf(address(this));
    token_.safeTransfer(to_, amount_);
    require(token_.balanceOf(address(this)) == before - amount_, "fee-on-transfer");
}

function repayLoan(address token_, uint256 amount_) external {
    require(loanApproval[msg.sender][token_] >= amount_, "not approved");
    loanApproval[msg.sender][token_] -= amount_;
    uint256 before = token_.balanceOf(address(this));
    token_.safeTransferFrom(msg.sender, address(this), amount_);
    require(token_.balanceOf(address(this)) == before + amount_, "fee-on-transfer");
}
```

Separate approval namespaces prevent cross-operation reuse, and balance delta checks catch fee-on-transfer shortfalls.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
