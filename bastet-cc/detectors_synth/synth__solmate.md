---
id: synth__solmate
name: "Solmate-Missing Return Check"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Solmate"]
routing_hints: ["SafeTransferLib", "safeApprove", "FixedPointMathLib", "ERC20", "createVault"]
required_hints: []
prompt_chars: 3526
synthesized: true
gated: true
synth_provenance: {"train_findings": ["173", "143"], "localization_rate": 1.0, "mode": "s2b", "hint_candidates": 19, "hints_rejected": 17, "hint_coverage": 1.0, "single_repo_hints": true, "hint_fallback": false, "loro": {"hit": 1.0, "fp": 0.0, "folds": 1, "repaired": false}}
---

# Solmate-Missing Return Check

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Solmate-Missing Return Check**
Solmate's SafeTransferLib implements safeTransfer and safeTransferFrom by performing a low-level call to the token contract and checking the returned boolean. However, if the target address has no code (i.e., is an EOA or a non-existent contract), the call succeeds without reverting and returns zero bytes, which Solidity treats as `false` for a `bool` return — but the library's assembly logic only checks that the call succeeded, not that the return data decodes to `true`. Consequently, transfers to addresses without contract code silently succeed, corrupting internal accounting and enabling attackers to deposit to non-existent tokens and later drain funds when a real token is deployed at that address.

### Detection Checks

1. Call to SafeTransferLib.safeTransfer or safeTransferFrom without a preceding `extcodesize(token) > 0` check.
2. Use of SafeTransferLib on a token address that is user-supplied or derived from untrusted input.
3. Absence of a require/assert verifying `token.code.length > 0` before the transfer.
4. Token address loaded from a mapping or array that can be poisoned with a zero-code address.
5. Transfer amount recorded in balances before the safeTransfer call, assuming success.
6. No fallback validation of the boolean return value from the low-level call (the library omits it).
7. Function lacks a modifier or inline check that the token is a known, deployed contract.
8. Contract uses Solmate's `LibSafeTransfer` or `SafeTransferLib` import without wrapping calls in an existence guard.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";

contract Vault {
    using SafeTransferLib for IERC20;
    mapping(address => uint256) public balances;

    function createVault(address token, uint256 amount) external {
        // @audit no check that token has code
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        balances[token] += amount; // accounting assumes success
    }
}
```

createVault calls Solmate's safeTransferFrom on a user-supplied token address without verifying the address contains contract code; a transfer to a non-existent address succeeds silently and inflates balances.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";

contract Vault {
    using SafeTransferLib for IERC20;
    mapping(address => uint256) public balances;

    function createVault(address token, uint256 amount) external {
        require(token.code.length > 0, "TOKEN_NOT_DEPLOYED");
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        balances[token] += amount;
    }
}
```

The fix adds an explicit `token.code.length > 0` check before the safeTransferFrom call, ensuring the target is a deployed contract and preventing silent success on empty addresses.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
