# MEV-FrontRunWithdrawalApproval

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**MEV-FrontRunWithdrawalApproval**
Front-running withdrawal approvals occurs when a contract decrements a user's withdrawal allowance after validating the requested amount against the current approval. An attacker monitoring the mempool can submit a withdrawal transaction at the higher pre-reduction allowance before an admin's `setApprovalFor` transaction reduces the limit. The vulnerability stems from the check-then-decrement pattern where the state mutation (decrement) happens after the validation but within the same transaction, creating a race condition exploitable via transaction ordering. MEV bots can detect pending admin transactions that lower withdrawal caps and front-run them with maximal withdrawals at the old higher cap, draining funds that should have been restricted. This pattern appears in treasury/vesting contracts where admins dynamically adjust withdrawal limits per user or token.

### Detection Checks

1. Function validates withdrawal amount against a mutable allowance mapping (e.g., `withdrawApproval[withdrawer][token]`) before decrementing that same allowance.
2. Allowance decrement occurs unconditionally after validation without atomic check-and-update (no `require`/`revert` if allowance changed between read and write).
3. Admin function exists that reduces withdrawal approvals (e.g., `setApprovalFor`, `updateWithdrawalLimit`) without a timelock or commit-reveal scheme.
4. No access control or delay on the admin approval-reduction function, allowing immediate execution.
5. Withdrawal function lacks a deadline/expiration parameter, enabling mempool lingering.
6. Contract uses `unchecked` arithmetic for the decrement, silently wrapping on underflow instead of reverting.
7. Allowance mapping is not `immutable` or `constant` and can be modified by privileged role.
8. Validation reads allowance from storage, then later writes back a reduced value without re-reading to confirm no intermediate change.

### Examples

#### Example 1: Incorrect Example

```solidity
mapping(address => mapping(address => uint256)) public withdrawApproval;

function _checkApproval(address withdrawer, address token, uint256 amount) internal {
    uint256 approval = withdrawApproval[withdrawer][token];
    if (approval < amount) revert NotApproved();
    if (approval != type(uint256).max) {
        unchecked { withdrawApproval[withdrawer][token] = approval - amount; }
    }
}

function setApprovalFor(address withdrawer, address token, uint256 newApproval) external onlyAdmin {
    withdrawApproval[withdrawer][token] = newApproval;
}
```

The withdrawal approval is checked then decremented in `_checkApproval`, but an admin can front-run a user's withdrawal by calling `setApprovalFor` to lower the limit; the user's transaction still executes at the old higher allowance because the decrement uses the stale `approval` value read before the admin's write.

#### Example 2: Correct Example

```solidity
mapping(address => mapping(address => uint256)) public withdrawApproval;

function _checkApproval(address withdrawer, address token, uint256 amount) internal {
    uint256 approval = withdrawApproval[withdrawer][token];
    if (approval < amount) revert NotApproved();
    if (approval != type(uint256).max) {
        withdrawApproval[withdrawer][token] = approval - amount; // checked arithmetic
    }
}

function setApprovalFor(address withdrawer, address token, uint256 newApproval) external onlyAdmin {
    uint256 current = withdrawApproval[withdrawer][token];
    if (newApproval > current) revert CannotIncrease(); // only reductions via timelock
    withdrawApproval[withdrawer][token] = newApproval;
    emit ApprovalReduced(withdrawer, token, newApproval);
}
```

Removing `unchecked` ensures arithmetic safety; adding an event and restricting `setApprovalFor` to only reduce (not increase) approvals limits admin power. For full MEV resistance, wrap approval changes in a timelock or require users to sign off on new limits.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
