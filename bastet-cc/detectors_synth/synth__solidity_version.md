---
id: synth__solidity_version
name: "Solidity Version"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Solidity Version"]
routing_hints: ["selfdestruct", "ecrecover", "delegatecall", "ERC20", "ERC721", "Ownable", "ReentrancyGuard", "SafeMath"]
required_hints: []
prompt_chars: 4115
synthesized: true
gated: true
synth_provenance: {"train_findings": [], "localization_rate": 0.0, "mode": "s2b", "hint_candidates": 21, "hints_rejected": 21, "hint_coverage": 1.0, "single_repo_hints": true, "hint_fallback": false, "loro": null}
---

# Solidity Version

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Solidity Version**
Solidity compiler versions and optimizer settings can introduce subtle semantic changes or bugs that affect contract behavior. Between major versions (e.g., 0.4.x to 0.5.x, 0.6.x to 0.7.x, 0.7.x to 0.8.x) breaking changes include: explicit visibility requirements, constructor keyword, overflow checks (0.8.0+), immutable/mutable keywords, try/catch, custom errors, and ABIEncoderV2 becoming default. Minor versions may contain optimizer bugs (e.g., 0.8.13 optimizer bug with Yul inlining, 0.8.16 storage write bug) or behavioral changes (e.g., 0.8.14 changed `block.timestamp` aliasing). Contracts that do not pin a specific compiler version with `pragma solidity ^0.8.0` (caret) or `>=0.8.0 <0.9.0` risk being compiled with a buggy or semantically different version. Additionally, enabling the optimizer without testing both optimized and non-optimized bytecode can surface optimizer-specific bugs. Auditors must verify the exact compiler version and optimizer settings used in deployment match those used in testing.

### Detection Checks

1. Contract uses a floating pragma (caret `^`, tilde `~`, or `>=` without upper bound) instead of a pinned exact version (e.g., `pragma solidity 0.8.19;`).
2. Contract enables optimizer (`optimizer.enabled = true`) but does not document or test with the specific optimizer runs value; high runs (e.g., 10000) increase optimizer bug surface.
3. Contract is compiled with a version known to have critical optimizer bugs (e.g., 0.8.13, 0.8.14, 0.8.15, 0.8.16) without mitigation or version pinning to a patched version.
4. Contract relies on overflow/underflow wrapping behavior (pre-0.8.0 semantics) but uses `pragma solidity >=0.8.0` where checked arithmetic is default, causing unexpected reverts.
5. Contract uses `block.timestamp` alias `now` (removed in 0.7.0) or other deprecated syntax without version guard.
6. Contract uses inline assembly or Yul that may be affected by optimizer changes across versions (e.g., memory layout, stack usage).
7. Contract imports dependencies (OpenZeppelin, Solmate, etc.) with floating pragmas, allowing transitive compilation with incompatible versions.
8. Contract uses `try/catch` or custom errors (0.6.0+/0.8.4+) but pragma allows older versions where these features are unavailable.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    uint256 public totalAssets;
    
    function deposit(uint256 amount) external {
        totalAssets += amount; // Relies on checked arithmetic (0.8.0+)
    }
    
    function withdraw(uint256 amount) external {
        totalAssets -= amount; // Reverts on underflow in 0.8.0+, but would wrap in 0.7.x
    }
}
```

Floating pragma `^0.8.0` allows compilation with any 0.8.x version, including those with known optimizer bugs (0.8.13-0.8.16). The arithmetic behavior changes between 0.7.x (wrapping) and 0.8.x (checked), so deploying with an unintended version changes semantics.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract Vault {
    uint256 public totalAssets;
    
    function deposit(uint256 amount) external {
        totalAssets += amount;
    }
    
    function withdraw(uint256 amount) external {
        if (totalAssets < amount) revert InsufficientBalance();
        totalAssets -= amount;
    }
    
    error InsufficientBalance();
}
```

Exact pragma `0.8.19` pins the compiler to a patched version without known critical optimizer bugs. Explicit underflow check with custom error works reliably on this version.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
