---
id: synth__eip712
name: "EIP712-Signature-Verification-Flaws"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["EIP712"]
routing_hints: ["DOMAIN_SEPARATOR", "_hashTypedDataV4", "EIP712", "hashStruct", "ecrecover", "signer", "block.chainid"]
required_hints: []
prompt_chars: 4616
synthesized: true
gated: true
synth_provenance: {"train_findings": ["481", "303", "304"], "localization_rate": 0.75, "mode": "s2", "hint_candidates": 29, "hints_rejected": 28, "hint_coverage": 1.0, "single_repo_hints": false, "hint_fallback": false, "loro": {"hit": 0.0, "fp": 1.0, "folds": 1, "repaired": true}}
---

# EIP712-Signature-Verification-Flaws

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**EIP712-Signature-Verification-Flaws**
EIP-712 requires structured data to be hashed in a specific way: the typehash and each dynamic parameter (bytes, string, arrays) must be individually keccak256-hashed before being combined in the final abi.encode. A common mistake is passing dynamic arrays or structs directly to abi.encode inside a single keccak256, which produces a different digest than the standard expects. This causes valid off-chain signatures to fail verification (legitimate calls revert) or, if the verifier replicates the same bug, allows replay across chains or contracts because the domain separator is not properly bound. Another flaw is hardcoding immutable addresses (e.g., guardPolicy) into initializer payloads that are later signed; when the referenced contract upgrades, previously signed messages become invalid or point to stale logic. Proper implementations must: (1) compute keccak256(abi.encode(typehash, keccak256(abi.encode(parameters...)))) for each dynamic field, (2) include the EIP-712 domain separator (name, version, chainId, verifyingContract) in the final digest, (3) enforce a strictly incrementing nonce per signer and a deadline to prevent replay, and (4) avoid embedding mutable or upgradeable addresses directly into signed payloads unless they are part of the domain separator.

### Detection Checks

1. Verify that every dynamic array (address[], bytes[], string[]) and struct field is keccak256-hashed before being passed to the outer abi.encode in the digest calculation.
2. Confirm the typehash is not mixed with raw parameters inside a single abi.encode; it must be the first element of the outer encode with pre-hashed dynamic fields following.
3. Check that _calculateDigest (or equivalent) incorporates the EIP-712 domain separator (DOMAIN_SEPARATOR or explicit name, version, chainId, verifyingContract) per EIP-712 specification.
4. Ensure a per-signer nonce is retrieved, validated against replay (strictly increasing), and atomically incremented before signature verification.
5. Validate that a deadline timestamp is present in the signed payload and enforced (deadline >= block.timestamp) to prevent indefinite replay.
6. Look for hardcoded immutable or upgradeable contract addresses embedded in signed initializer payloads; these should be resolved at execution time or included in the domain separator.
7. Confirm that abi.encodePacked is never used for dynamic types inside the digest; it must be abi.encode after individual keccak256 hashing.
8. Check that the final digest is computed as keccak256(abi.encode(typehash, hashedParam1, hashedParam2, ..., nonce, deadline)) and not keccak256(abi.encodePacked(...)) or a flat abi.encode of raw values.

### Examples

#### Example 1: Incorrect Example

```solidity
function validateBurnSignature(Types.EIP712Signature calldata signature, uint256 tokenId) external {
    _validateRecoveredAddress(
        _calculateDigest(
            keccak256(
                abi.encode(Typehash.BURN, tokenId, _getAndIncrementNonce(signature.signer), signature.deadline)
            )
        ),
        signature
    );
}
```

The typehash and parameters are hashed together in a single keccak256(abi.encode(...)), violating EIP-712 structured hashing which requires dynamic fields to be individually hashed and the domain separator included.

#### Example 2: Correct Example

```solidity
function validateBurnSignature(Types.EIP712Signature calldata signature, uint256 tokenId) external {
    bytes32 domainSeparator = _getDomainSeparator();
    uint256 nonce = _getAndIncrementNonce(signature.signer);
    require(signature.deadline >= block.timestamp, "Expired");
    bytes32 structHash = keccak256(abi.encode(
        Typehash.BURN,
        tokenId,
        nonce,
        signature.deadline
    ));
    bytes32 digest = _calculateDigest(domainSeparator, structHash);
    _validateRecoveredAddress(digest, signature);
}
```

The struct hash is computed with abi.encode of the typehash and static parameters, then combined with the domain separator in _calculateDigest per EIP-712; nonce is incremented and deadline enforced.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
