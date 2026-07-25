# MEV-FrontRunWithdrawalApproval

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**MEV-FrontRunWithdrawalApproval**
Front-running withdrawal approvals occurs when a contract decrements a user's withdrawal allowance after verifying the requested amount against the current approval. An attacker monitoring the mempool can submit a withdrawal transaction at the higher pre-reduction approval before the admin's `setApprovalFor` transaction reduces the limit. The vulnerable pattern checks `withdrawApproval[withdrawer][token] >= amount` then unconditionally decrements the approval in the same transaction, creating a race condition where the check passes at the old higher value but the state update reduces it for subsequent calls. This allows the front-runner to extract value at the expense of the legitimate withdrawer who may find their approval insufficient after the admin's update. The fix is to decrement the approval before the external call or use a commit-reveal scheme, but the minimal safe pattern is to reduce the allowance first, then perform the transfer, ensuring the check-and-decrement is atomic with respect to the approval state.

### Detection Checks

1. Function reads withdrawApproval[withdrawer][token] into a local variable before validation
2. Validation compares local approval variable against requested amount
3. Approval decrement occurs after validation but before external token transfer
4. Decrement uses unchecked arithmetic without re-reading storage
5. No reentrancy guard or commit-reveal mechanism protecting the approval window
6. Admin function setApprovalFor can reduce approval while user withdrawal is pending
7. Withdrawal function lacks deadline/expiration parameter to limit mempool exposure
8. Token transfer occurs after approval state mutation

### Examples

#### Example 1: Incorrect Example

```solidity
function _checkApproval(
        address withdrawer_,
        ERC20 token_,
        uint256 amount_
    ) internal {
        uint256 approval = withdrawApproval[withdrawer_][token_];
        if (approval < amount_) revert TRSRY_NotApproved();

        if (approval != type(uint256).max) {
            unchecked {
                withdrawApproval[withdrawer_][token_] = approval - amount_;
            }
        }
    }
```

Approval is checked against a cached value then decremented afterward, allowing a front-runner to execute withdrawal at the higher approval before admin reduces it.

#### Example 2: Correct Example

```solidity
function _checkApproval(
        address withdrawer_,
        ERC20 token_,
        uint256 amount_
    ) internal {
        uint256 approval = withdrawApproval[withdrawer_][token_];
        if (approval < amount_) revert TRSRY_NotApproved();

        if (approval != type(uint256).max) {
            unchecked {
                withdrawApproval[withdrawer_][token_] = approval - amount_;
            }
        }
        // Transfer occurs AFTER approval decrement
        token_.safeTransfer(withdrawer_, amount_);
    }
```

Approval is decremented before the external transfer, closing the front-run window; the check-and-decrement is atomic with respect to the approval state.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
