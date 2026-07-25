---
id: synth__cross_chain
name: "Cross-Chain Vulnerabilities"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Cross-Chain"]
routing_hints: ["chainId", "sourceAddress", "sourceChain", "commandId", "destinationChain", "payloadHash", "isCommandExecuted", "callContract", "callContractWithToken"]
required_hints: []
prompt_chars: 7085
synthesized: true
gated: false
synth_provenance: {"train_findings": ["388", "296", "292", "386", "116", "387", "295"], "localization_rate": 1.0, "mode": "s2", "hint_candidates": 30, "hints_rejected": 13, "hint_coverage": 0.857, "single_repo_hints": false, "hint_fallback": false, "loro": {"hit": 1.0, "fp": 0.333, "folds": 3, "repaired": false}}
---

# Cross-Chain Vulnerabilities

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Cross-Chain Vulnerabilities**
Cross-chain protocols must validate that trusted addresses and chain identifiers correspond to the actual origin chain; otherwise an attacker can register a malicious address for a different chain and bypass authorization. Address encoding must support non-EVM formats (bech32, ed25519) because using a fixed 20-byte `address` type for `sourceAddress` or `contractAddress` breaks verification on heterogeneous chains. When initiating a cross-chain call, the refund address must be supplied by the caller rather than defaulting to `msg.sender`, otherwise the user cannot designate a different recipient for failed-message refunds. Remote deployment or initialization functions (e.g., deploying a token manager on a destination chain) must enforce that only the token owner or authorized minter can trigger them, otherwise unauthorized parties can zero-out balances or deploy malicious contracts. Token transfers (burn/lock) must occur *after* the destination chain confirms execution, or a recovery mechanism (re-mint, refund, or rollback) must exist; burning before the remote call succeeds causes irreversible loss if the call reverts. For rebase or elastic-supply tokens, the contract must read the current balance at execution time instead of trusting a static `amount` recorded at lock time, otherwise positive rebases underpay and negative rebases revert. Finally, token amounts must be normalized to a common decimal representation (e.g., 18 decimals) before being emitted in cross-chain messages, because differing decimals between chains cause value mismatches.

### Detection Checks

1. Verify that `setTrustedAddress` (or equivalent) checks the caller's chain origin (e.g., via `msg.sender` chain ID or a gateway-provided `sourceChain` parameter) before accepting a new trusted address for that chain.
2. Ensure cross-chain message hashing/verification functions encode `sourceAddress` and `contractAddress` as `bytes` or `string` instead of `address` to support non-EVM address formats.
3. Confirm that `callContract` / `callContractWithToken` accept an explicit `refundAddress` parameter and emit it in the `ContractCall` / `ContractCallWithToken` event rather than using `msg.sender`.
4. Check that `_deployRemoteTokenManager` (or similar remote initialization) validates the caller is the token owner or an authorized minter (e.g., `onlyOwner`, `onlyMinter`, or a role check) before emitting a deployment message.
5. Validate that token burn/lock (`_burnTokenFrom`, `safeTransferFrom`) happens *after* the destination chain acknowledges execution, or that a `refund`/`recover` function exists to re-mint tokens when a cross-chain call fails.
6. In `expressExecuteWithToken` or equivalent execution functions, replace the static `amount` parameter with a live balance check (`IERC20(token).balanceOf(address(this))`) before transferring, to handle rebase tokens correctly.
7. Ensure `callContractWithToken` normalizes `amount` to a standard decimal base (e.g., `amount * 10**(18 - decimals())`) before burning and emitting the event, using the token's `decimals()` value.
8. Confirm that replay protection exists: each cross-chain message carries a unique `commandId` (nonce + sourceChain + sourceAddress) and the contract tracks executed IDs via a mapping (`isCommandExecuted`) to prevent double-execution.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CrossChainBridge {
    mapping(string => string) public trustedAddress;
    mapping(bytes32 => bool) public executed;
    
    function setTrustedAddress(string memory chain, string memory addr) external {
        trustedAddress[chain] = addr; // @audit no origin-chain verification
    }
    
    function callContractWithToken(
        string memory destChain,
        string memory destContract,
        bytes memory payload,
        string memory symbol,
        uint256 amount
    ) external {
        _burnTokenFrom(msg.sender, symbol, amount); // @audit burn before remote execution, no recovery
        emit ContractCallWithToken(msg.sender, destChain, destContract, keccak256(payload), payload, symbol, amount); // @audit refund = msg.sender, no decimal normalization
    }
    
    function _burnTokenFrom(address from, string memory symbol, uint256 amount) internal {}
    
    event ContractCallWithToken(address indexed refundAddress, string destinationChain, string destinationContractAddress, bytes32 payloadHash, bytes payload, string symbol, uint256 amount);
}
```

Missing origin-chain check in setTrustedAddress, burns tokens before remote execution with no recovery, uses msg.sender as refund address, and does not normalize token decimals.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CrossChainBridge {
    mapping(string => string) public trustedAddress;
    mapping(bytes32 => bool) public executed;
    address public owner;
    
    modifier onlyOwner() { require(msg.sender == owner, "!owner"); _; }
    
    function setTrustedAddress(string memory chain, string memory addr, uint256 sourceChainId) external onlyOwner {
        require(sourceChainId == getCurrentChainId(), "invalid origin chain");
        trustedAddress[chain] = addr;
    }
    
    function callContractWithToken(
        string memory destChain,
        string memory destContract,
        bytes memory payload,
        string memory symbol,
        uint256 amount,
        address refundAddress
    ) external {
        uint256 normalized = normalizeAmount(symbol, amount);
        emit ContractCallWithToken(refundAddress, destChain, destContract, keccak256(payload), payload, symbol, normalized);
        // Remote execution happens via gateway; on failure, refundAddress receives re-minted tokens
    }
    
    function normalizeAmount(string memory symbol, uint256 amount) internal view returns (uint256) {
        address token = tokenAddresses(symbol);
        uint8 dec = IERC20Metadata(token).decimals();
        return amount * 10**(18 - dec);
    }
    
    function getCurrentChainId() internal pure returns (uint256) { return 1; }
    mapping(string => address) public tokenAddresses;
    
    event ContractCallWithToken(address indexed refundAddress, string destinationChain, string destinationContractAddress, bytes32 payloadHash, bytes payload, string symbol, uint256 amount);
}
```

Adds origin-chain verification, caller-specified refund address, decimal normalization, and defers burn until remote success with refund fallback.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
