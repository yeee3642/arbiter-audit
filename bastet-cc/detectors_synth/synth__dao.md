---
id: synth__dao
name: "DAO-Governance Logic Flaws"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["DAO"]
routing_hints: ["propose", "quorum", "shares", "delegate", "Cohort", "proposalThresholdBps", "removeMember", "proposalThreshold", "addMember", "getVotes", "cancel"]
required_hints: []
prompt_chars: 5518
synthesized: true
gated: false
synth_provenance: {"train_findings": ["211", "330", "331", "223"], "localization_rate": 1.0, "mode": "s2", "hint_candidates": 30, "hints_rejected": 12, "hint_coverage": 1.0, "single_repo_hints": true, "hint_fallback": false, "loro": {"hit": 0.5, "fp": 0.0, "folds": 2, "repaired": false}}
---

# DAO-Governance Logic Flaws

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**DAO-Governance Logic Flaws**
DAO governance contracts frequently exhibit logic errors in proposal lifecycle management, member cohort administration, and voting power calculations. A common flaw is using strict inequality (`>`) instead of inclusive (`>=`) when checking if a proposer's voting power meets the proposal threshold, which incorrectly permits cancellation when voting power exactly equals the threshold. Member management functions often lack validation against governance decisions, such as re-adding addresses that were previously voted out, or swapping members during active elections without verifying election state. Voting power thresholds computed via integer division (`totalSupply * bps / 10000`) can round down to zero when the product is less than 10000, effectively allowing any token holder to create proposals. These issues stem from missing state checks (election status, prior governance actions), incorrect comparison operators, and insufficient precision handling in threshold calculations.

### Detection Checks

1. In proposal cancellation functions, verify the voting power comparison uses `>=` against the proposal threshold, not `>`, to prevent cancellation when proposer voting power equals the threshold.
2. In member addition functions (e.g., `addMember`), check for a validation that the address was not previously removed by governance (e.g., a `removedMembers` mapping or similar exclusion list) before allowing re-addition.
3. In member swap functions (e.g., `_swapMembers`), ensure there is a check that no election is currently ongoing for either the source or destination cohort before performing the removal and addition.
4. In proposal threshold calculations, confirm the formula uses a minimum threshold (e.g., `max(1, (totalSupply * bps) / 10000)`) or scales the numerator to prevent integer division from rounding down to zero.
5. In proposal creation functions, verify the proposer's voting power is checked against the threshold at the snapshot block (e.g., `block.timestamp - 1` or a dedicated snapshot), not the current block, to prevent manipulation.
6. In proposal execution/queueing logic, ensure the proposal state transitions (Pending -> Active -> Succeeded/Defeated -> Queued -> Executed) are enforced sequentially and cannot be skipped or repeated.
7. In voting functions, confirm that vote weight is snapshotted at proposal start (or a fixed block) and cannot be changed by transferring tokens after voting begins.
8. In timelock or queueing functions, verify that a minimum delay is enforced before execution and that the delay cannot be bypassed by the proposer or admin.

### Examples

#### Example 1: Incorrect Example

```solidity
function cancel(bytes32 _proposalId) external {
    if (state(_proposalId) == ProposalState.Executed) revert PROPOSAL_ALREADY_EXECUTED();
    Proposal memory proposal = proposals[_proposalId];
    unchecked {
        if (msg.sender != proposal.proposer && getVotes(proposal.proposer, block.timestamp - 1) > proposal.proposalThreshold)
            revert INVALID_CANCEL();
    }
    proposals[_proposalId].canceled = true;
    emit ProposalCanceled(_proposalId);
}

function addMember(address _newMember, Cohort _cohort) external onlyRole(MEMBER_ADDER_ROLE) {
    _addMemberToCohortArray(_newMember, _cohort);
    _scheduleUpdate();
    emit MemberAdded(_newMember, _cohort);
}

function proposalThreshold() public view returns (uint256) {
    unchecked {
        return (settings.token.totalSupply() * settings.proposalThresholdBps) / 10_000;
    }
}
```

The cancel function uses `>` instead of `>=` for the voting power check, allowing cancellation when power equals threshold. addMember lacks a check against previously removed members. proposalThreshold uses integer division that can round down to zero.

#### Example 2: Correct Example

```solidity
function cancel(bytes32 _proposalId) external {
    if (state(_proposalId) == ProposalState.Executed) revert PROPOSAL_ALREADY_EXECUTED();
    Proposal memory proposal = proposals[_proposalId];
    unchecked {
        if (msg.sender != proposal.proposer && getVotes(proposal.proposer, block.timestamp - 1) >= proposal.proposalThreshold)
            revert INVALID_CANCEL();
    }
    proposals[_proposalId].canceled = true;
    emit ProposalCanceled(_proposalId);
}

function addMember(address _newMember, Cohort _cohort) external onlyRole(MEMBER_ADDER_ROLE) {
    if (removedMembers[_newMember]) revert MEMBER_PREVIOUSLY_REMOVED();
    _addMemberToCohortArray(_newMember, _cohort);
    _scheduleUpdate();
    emit MemberAdded(_newMember, _cohort);
}

function proposalThreshold() public view returns (uint256) {
    uint256 raw = (settings.token.totalSupp() * settings.proposalThresholdBps) / 10_000;
    return raw == 0 ? 1 : raw;
}
```

Fixed cancel to use `>=` so proposer cannot cancel when voting power equals threshold. Added removedMembers check in addMember to prevent re-adding voted-out addresses. proposalThreshold now returns at least 1 to prevent zero threshold.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
