# Upgradeable-Diamond-Cut-Calldata-Mismatch

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Upgradeable-Diamond-Cut-Calldata-Mismatch**
In EIP-2535 Diamond upgrade patterns, a governance proposal typically stores a hash of the intended diamond cut (facet cuts + init calldata) during a notice period. The execution function must verify that the calldata supplied at execution time matches the originally proposed calldata by recomputing the hash and comparing it to the stored proposal hash. If the execution function only checks the hash but then passes attacker-controlled calldata to `diamondCut` without ensuring it is the exact same calldata that was hashed, a compromised governor key can substitute malicious facet cuts or init addresses after the notice period expires. The vulnerability arises because the hash validation uses the function parameters (`_diamondCut.facetCuts`, `_diamondCut.initAddress`) but the subsequent `Diamond.diamondCut(_diamondCut)` call uses the entire `_diamondCut` struct, which may contain additional fields (e.g., `initCalldata`) not covered by the hash, or the caller can simply pass a different struct that happens to hash to the same value if the hash construction is incomplete.

### Detection Checks

1. Locate functions named `executeDiamondCutProposal`, `executeUpgrade`, or similar that accept a `DiamondCutData` or equivalent struct parameter.
2. Verify that the stored proposal hash is computed over the exact same fields that are later passed to the low-level `diamondCut` function (typically `facetCuts`, `initAddress`, and `initCalldata`).
3. Ensure the execution function recomputes `keccak256(abi.encode(...))` using the calldata fields from the function parameter and compares it to the stored `proposedDiamondCutHash`.
4. Confirm that no additional fields in the struct (e.g., `initCalldata`) are omitted from the hash but used in the `diamondCut` call.
5. Check that the function resets or deletes the stored proposal (`_resetProposal`) only after successful validation to prevent replay.
6. Validate that access control (`onlyGovernor`, `onlyOwner`, timelock) restricts who can call the execution function.
7. Ensure the contract enforces a notice period (`block.timestamp >= proposedTimestamp + NOTICE_PERIOD`) or emergency council approval before execution.
8. Verify that the diamond is not frozen (`isFrozen`) unless emergency approvals are met.

### Examples

#### Example 1: Incorrect Example

```solidity
function executeDiamondCutProposal(Diamond.DiamondCutData calldata _diamondCut) external onlyGovernor {
    Diamond.DiamondStorage storage ds = Diamond.getDiamondStorage();
    require(block.timestamp >= s.proposedDiamondCutTimestamp + UPGRADE_NOTICE_PERIOD, "notice");
    require(s.proposedDiamondCutHash == keccak256(abi.encode(_diamondCut.facetCuts, _diamondCut.initAddress)), "hash");
    _resetProposal();
    Diamond.diamondCut(_diamondCut); // _diamondCut.initCalldata not covered by hash
}
```

The hash validation omits `initCalldata` from the encoded fields, allowing a governor to change the initialization calldata after the proposal is approved.

#### Example 2: Correct Example

```solidity
function executeDiamondCutProposal(Diamond.DiamondCutData calldata _diamondCut) external onlyGovernor {
    Diamond.DiamondStorage storage ds = Diamond.getDiamondStorage();
    require(block.timestamp >= s.proposedDiamondCutTimestamp + UPGRADE_NOTICE_PERIOD, "notice");
    bytes32 expectedHash = keccak256(abi.encode(_diamondCut.facetCuts, _diamondCut.initAddress, _diamondCut.initCalldata));
    require(s.proposedDiamondCutHash == expectedHash, "hash");
    _resetProposal();
    Diamond.diamondCut(_diamondCut);
}
```

The hash now covers all three fields (`facetCuts`, `initAddress`, `initCalldata`) that `diamondCut` consumes, preventing calldata substitution.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
