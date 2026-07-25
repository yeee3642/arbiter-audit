# Upgradeable-Diamond Cut Calldata Mismatch

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Upgradeable-Diamond Cut Calldata Mismatch**
In EIP-2535 Diamond upgrade patterns, a governance proposal typically commits to a specific diamond cut (facet cuts + init calldata) by storing its hash. The execution function must verify that the calldata supplied at execution time matches the originally proposed calldata, not just that its hash matches the stored proposal hash. If the execution function only checks the hash of the proposed diamond cut against a stored hash but does not ensure the _diamondCut parameter equals the originally proposed calldata, an attacker who compromises the governor key (or a malicious governor) can submit arbitrary malicious calldata that hashes to the same value (via hash collision) or, more commonly, the stored proposal hash is set to a value that the attacker can later satisfy with different calldata. The correct pattern is to store the full proposed calldata (or its hash) at proposal time and at execution time require that the calldata passed to executeDiamondCutProposal is exactly the same as the one that was proposed. Additionally, the proposal should be cleared atomically with execution to prevent replay.

### Detection Checks

1. In the diamond cut execution function, verify that the function parameters (_diamondCut.facetCuts, _diamondCut.initAddress, _diamondCut.initCalldata) are compared against the originally proposed values stored at proposal time, not only their hash.
2. Ensure the proposal storage is cleared (or marked executed) before or atomically with the external diamondCut call to prevent re-execution of the same proposal.
3. Confirm that the function enforces a notice period or security council approval before execution, and that the frozen state logic does not bypass the calldata validation.
4. Check that the hash comparison uses the exact same encoding (abi.encode of facetCuts and initAddress) as used during proposal creation; any mismatch in encoding allows substitution.
5. Validate that the function does not accept a raw calldata blob without decoding and comparing its structural components (facetCuts array, init address, init calldata).
6. Verify that only authorized roles (governor, security council) can propose and execute, and that the proposer cannot also execute without delay or secondary approval.
7. Ensure that the diamond storage layout (DiamondStorage) is not corrupted by the upgrade; the execution function should not write to storage slots reserved for the diamond standard before the cut is applied.

### Examples

#### Example 1: Incorrect Example

```solidity
function executeDiamondCutProposal(Diamond.DiamondCutData calldata _diamondCut) external onlyGovernor {
    Diamond.DiamondStorage storage ds = Diamond.getDiamondStorage();
    require(block.timestamp >= s.diamondCutStorage.proposedDiamondCutTimestamp + UPGRADE_NOTICE_PERIOD, "notice");
    require(s.diamondCutStorage.proposedDiamondCutHash == keccak256(abi.encode(_diamondCut.facetCuts, _diamondCut.initAddress)), "hash mismatch");
    _resetProposal();
    Diamond.diamondCut(_diamondCut);
    emit DiamondCutProposalExecution(_diamondCut);
}
```

The function only validates the hash of facetCuts and initAddress against the stored proposal hash, but does not verify that _diamondCut.initCalldata matches the originally proposed initCalldata, and does not ensure the full calldata matches the proposal. A compromised governor can execute arbitrary initCalldata.

#### Example 2: Correct Example

```solidity
function executeDiamondCutProposal(Diamond.DiamondCutData calldata _diamondCut) external onlyGovernor {
    Diamond.DiamondStorage storage ds = Diamond.getDiamondStorage();
    require(block.timestamp >= s.diamondCutStorage.proposedDiamondCutTimestamp + UPGRADE_NOTICE_PERIOD, "notice");
    require(s.diamondCutStorage.proposedDiamondCutHash == keccak256(abi.encode(_diamondCut.facetCuts, _diamondCut.initAddress, _diamondCut.initCalldata)), "hash mismatch");
    require(keccak256(abi.encode(_diamondCut.facetCuts, _diamondCut.initAddress, _diamondCut.initCalldata)) == s.diamondCutStorage.proposedDiamondCutHash, "calldata mismatch");
    _resetProposal();
    Diamond.diamondCut(_diamondCut);
    emit DiamondCutProposalExecution(_diamondCut);
}
```

The execution function now includes initCalldata in the hash verification and explicitly compares the full encoded proposal calldata against the stored hash, ensuring the executed cut matches the proposed cut exactly.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
