---
id: synth__eip4494
name: "EIP4494-Permit-Not-EIP-Compliant"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["EIP4494"]
routing_hints: ["permit", "nonces", "DOMAIN_SEPARATOR", "PERMIT_TYPEHASH", "tokenId", "PermitSingle", "block.chainid", "ecrecover"]
required_hints: []
prompt_chars: 5817
synthesized: true
gated: true
synth_provenance: {"train_findings": [], "localization_rate": 0.0, "mode": "s2b", "hint_candidates": 21, "hints_rejected": 21, "hint_coverage": 1.0, "single_repo_hints": true, "hint_fallback": false, "loro": null}
---

# EIP4494-Permit-Not-EIP-Compliant

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**EIP4494-Permit-Not-EIP-Compliant**
EIP-4494 defines the Permit2 signature scheme that allows users to approve token spending via off-chain signatures instead of on-chain `approve()` calls. The standard requires strict adherence to the typed data structure: the domain separator must use the exact name "Permit2", version "1", and the verifying contract address; the PermitSingle struct must contain fields `details` (token, amount, expiration, nonce), `spender`, `sigDeadline`, and the `PermitDetails` struct must pack `amount` (160 bits), `expiration` (48 bits), and `nonce` (48 bits) into a single `uint256`. Nonces must be tracked per owner/token/spender triplet and incremented on each use to prevent replay. The `permit` function must verify the signature against the reconstructed digest using `ecrecover`, enforce `sigDeadline >= block.timestamp`, enforce `details.expiration >= block.timestamp`, and increment the nonce mapping only after all checks pass. Deviations such as wrong domain name/version, missing fields, incorrect struct packing, omitted deadline/expiration checks, or nonce reuse enable signature forgery, replay attacks, or unauthorized spending.

### Detection Checks

1. Verify the EIP712 domain separator uses name "Permit2", version "1", and the correct verifying contract address.
2. Confirm the PermitSingle struct includes exactly the fields: details (PermitDetails), spender (address), sigDeadline (uint256).
3. Confirm PermitDetails packs amount (uint160), expiration (uint48), nonce (uint48) into a single uint256 in that order.
4. Check that the permit function reconstructs the typed data hash using keccak256(abi.encode(...)) matching the EIP-4494 specification exactly.
5. Ensure the function validates `sigDeadline >= block.timestamp` before signature verification.
6. Ensure the function validates `details.expiration >= block.timestamp` before spending allowance.
7. Verify the nonce is read from a mapping keyed by (owner, token, spender) and incremented exactly once after successful verification.
8. Confirm the signature is verified via `ecrecover` using the correct digest prefix (\x19\x01) and domain separator.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BadPermit2 {
    mapping(address => mapping(address => mapping(address => uint256))) public nonces;
    
    function permit(
        address owner,
        address token,
        address spender,
        uint160 amount,
        uint48 expiration,
        uint48 nonce,
        uint256 sigDeadline,
        bytes calldata signature
    ) external {
        // @audit missing EIP712 domain separator validation
        // @audit wrong struct packing: amount/expiration/nonce passed separately
        // @audit no sigDeadline check
        // @audit no expiration check
        // @audit nonce not incremented after use
        bytes32 digest = keccak256(abi.encodePacked(owner, token, spender, amount, expiration, nonce, sigDeadline));
        address signer = ecrecover(digest, v, r, s);
        if (signer != owner) revert("invalid sig");
        // spending logic here
    }
}
```

The permit function uses a custom digest instead of the EIP-4494 typed data structure, omits domain separator, deadline/expiration checks, and nonce increment, enabling replay and forgery.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GoodPermit2 {
    bytes32 constant DOMAIN_SEPARATOR = keccak256(abi.encode(
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
        keccak256(bytes("Permit2")),
        keccak256(bytes("1")),
        block.chainid,
        address(this)
    ));
    
    mapping(address => mapping(address => mapping(address => uint256))) public nonces;
    
    function permit(
        address owner,
        address token,
        address spender,
        uint160 amount,
        uint48 expiration,
        uint48 nonce,
        uint256 sigDeadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (sigDeadline < block.timestamp) revert("deadline passed");
        if (expiration < block.timestamp) revert("expired");
        uint256 expectedNonce = nonces[owner][token][spender];
        if (nonce != expectedNonce) revert("invalid nonce");
        
        bytes32 permitDetailsHash = keccak256(abi.encode(
            keccak256("PermitDetails(uint160 amount,uint48 expiration,uint48 nonce)"),
            amount, expiration, nonce
        ));
        bytes32 permitSingleHash = keccak256(abi.encode(
            keccak256("PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)"),
            permitDetailsHash, spender, sigDeadline
        ));
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, permitSingleHash));
        address signer = ecrecover(digest, v, r, s);
        if (signer != owner) revert("invalid sig");
        
        nonces[owner][token][spender] = expectedNonce + 1;
        // spending logic here
    }
}
```

The permit function implements the exact EIP-4494 typed data hashing, validates both deadlines, checks and increments the per-owner/token/spender nonce, and uses the correct domain separator.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
