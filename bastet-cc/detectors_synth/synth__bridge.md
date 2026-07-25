---
id: synth__bridge
name: "Bridge-HardcodedPredicateAddress"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Bridge"]
routing_hints: ["finalizeWithdrawal", "l1Token", "l2Token", "POS_BRIDGE"]
required_hints: []
prompt_chars: 4978
synthesized: true
gated: true
synth_provenance: {"train_findings": ["488"], "localization_rate": 1.0, "mode": "s2b", "hint_candidates": 30, "hints_rejected": 30, "hint_coverage": 1.0, "single_repo_hints": true, "hint_fallback": false, "loro": {"hit": 0.0, "fp": 0.0, "folds": 1, "repaired": true}}
---

# Bridge-HardcodedPredicateAddress

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Bridge-HardcodedPredicateAddress**
Bridge contracts often rely on predicate contracts to handle token-specific deposit and withdrawal logic (e.g., ERC20Predicate, ERC721Predicate, ERC1155Predicate). A common flaw is hardcoding a single predicate address (such as a fixed ERC20Predicate) in the bridge's deposit or withdrawal functions. This prevents the bridge from dynamically selecting the correct predicate based on the token type (ERC20, ERC721, ERC1155) or adapting to predicate upgrades or migrations. As a result, users cannot bridge tokens that require a different predicate, and the protocol cannot update the predicate address without a full contract upgrade, breaking extensibility and causing funds to be locked or deposits to revert.

### Detection Checks

1. Bridge deposit function uses a hardcoded predicate address (e.g., `address predicate = 0xFixedAddress;`) instead of looking up the predicate from a registry or mapping keyed by token type.
2. Bridge withdrawal function calls a fixed predicate address without validating that the predicate matches the token's standard (ERC20, ERC721, ERC1155).
3. No mapping or registry (e.g., `mapping(uint256 tokenType => address predicate)`) exists to resolve the correct predicate for a given token type.
4. Predicate address is set only in the constructor and lacks an admin-controlled setter (e.g., `setPredicate(uint256 tokenType, address predicate)`) for upgrades or migrations.
5. Deposit function does not verify that the token's contract implements the expected interface for the hardcoded predicate (e.g., assumes ERC20 but token is ERC721).
6. Withdrawal logic on the destination chain uses a hardcoded predicate, preventing support for new token standards added after deployment.
7. Event `PredicateUpdated(tokenType, oldPredicate, newPredicate)` is not emitted when predicate addresses change, reducing off-chain monitoring capability.
8. Bridge does not validate `tokenType` parameter against known predicate mappings, allowing invalid token types to proceed with the wrong predicate.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20Predicate {
    function depositERC20(address token, address depositor, uint256 amount, bytes calldata data) external;
}

contract Bridge {
    // Hardcoded ERC20Predicate address - cannot handle ERC721/ERC1155 or predicate upgrades
    address constant PREDICATE_ADDRESS = 0x1234567890123456789012345678901234567890;
    
    function depositERC20(
        address token,
        uint256 amount,
        bytes calldata data
    ) external {
        IERC20Predicate(PREDICATE_ADDRESS).depositERC20(token, msg.sender, amount, data);
    }
    
    function depositERC721(
        address token,
        uint256 tokenId,
        bytes calldata data
    ) external {
        // Still uses ERC20Predicate - will revert for ERC721 tokens
        IERC20Predicate(PREDICATE_ADDRESS).depositERC20(token, msg.sender, 0, data);
    }
}
```

The bridge hardcodes a single ERC20Predicate address and uses it for all token types, making it impossible to bridge ERC721 or ERC1155 tokens or adapt to predicate upgrades.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPredicate {
    function deposit(address token, address depositor, uint256 amount, uint256 tokenId, bytes calldata data) external;
}

contract Bridge {
    mapping(uint256 => address) public predicates; // tokenType => predicate address
    
    event PredicateUpdated(uint256 indexed tokenType, address indexed oldPredicate, address indexed newPredicate);
    
    function setPredicate(uint256 tokenType, address predicate) external {
        require(predicate != address(0), "zero address");
        address old = predicates[tokenType];
        predicates[tokenType] = predicate;
        emit PredicateUpdated(tokenType, old, predicate);
    }
    
    function deposit(
        uint256 tokenType,
        address token,
        uint256 amount,
        uint256 tokenId,
        bytes calldata data
    ) external {
        address predicate = predicates[tokenType];
        require(predicate != address(0), "no predicate for tokenType");
        IPredicate(predicate).deposit(token, msg.sender, amount, tokenId, data);
    }
}
```

The bridge uses a tokenType-to-predicate mapping with an admin setter, enabling dynamic predicate resolution per token type and safe upgrades.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
