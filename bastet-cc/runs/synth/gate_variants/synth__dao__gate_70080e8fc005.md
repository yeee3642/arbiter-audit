# DAO-Governance-Member-Lifecycle-Flaws

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**DAO-Governance-Member-Lifecycle-Flaws**
DAO governance systems often manage member lifecycles through cohorts or terms, with distinct phases for election, active service, and removal. A critical flaw arises when the contract fails to enforce mutual exclusion between these phases: a member voted out or removed from one cohort can be immediately re-added to the same or a new cohort within the same governance cycle, bypassing the democratic intent of the removal. Similarly, when transitioning between cohorts (e.g., epoch rollover), the contract may delete the old cohort and initialize a new one without verifying that no elections or governance actions are pending for the old cohort. This allows a member to simultaneously exist in both the outgoing and incoming cohorts, creating duplicate voting power, governance confusion, and potential manipulation of quorum or proposal outcomes. The root cause is missing state validation: no tracking of removal history per lifecycle, no epoch/generation gating on `addMember`, and no precondition checks that the old cohort is fully inactive (no ongoing elections, no pending proposals) before it is dissolved.

### Detection Checks

1. `addMember` or equivalent does not verify the candidate has not been removed in the current governance cycle/epoch (missing `removedInCycle[member] != currentCycle` check).
2. `replaceCohort`/`rotateCohort`/`startNewEpoch` deletes or archives the old cohort without asserting `ongoingElections[oldCohortId] == 0` or `pendingProposals[oldCohortId] == 0`.
3. `removeMember`/`voteOutMember` does not record the removal in a persistent mapping keyed by member and cycle/epoch (e.g., `lastRemovedCycle[member] = currentCycle`).
4. `addMember` allows re-adding a member whose `lastRemovedCycle == currentCycle` without a cooling-off period or DAO re-approval.
5. Cohort transition logic does not increment a global `currentCycle`/`epochId` before adding new members, so old and new cohorts share the same cycle identifier.
6. `isActiveMember(member)`/`getMemberCohort(member)` returns true for multiple cohort IDs simultaneously, indicating missing mutual-exclusion invariant.
7. Election/voting functions (`startElection`, `vote`, `finalizeElection`) read cohort membership from state that can be mutated by `replaceCohort` mid-election (no snapshot or epoch-lock).
8. Security Council / admin `addMember` bypasses the same cycle/epoch checks enforced for DAO-voted additions (privileged path inconsistency).

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DAOGovernance {
    uint256 public currentCohortId;
    mapping(uint256 => address[]) public cohortMembers;
    mapping(address => bool) public isMember;
    address public securityCouncil;
    
    function replaceCohort(address[] calldata newMembers) external {
        require(msg.sender == securityCouncil, "Only SC");
        delete cohortMembers[currentCohortId]; // @audit no check for ongoing elections
        currentCohortId++;
        for (uint i = 0; i < newMembers.length; i++) {
            cohortMembers[currentCohortId].push(newMembers[i]);
            isMember[newMembers[i]] = true; // @audit no removed-in-cycle check
        }
    }
    
    function voteOutMember(address member) external {
        require(isMember[member], "Not a member");
        // ... voting logic ...
        isMember[member] = false; // @audit no removal tracking
    }
    
    function addMember(address member) external {
        require(msg.sender == securityCouncil, "Only SC");
        isMember[member] = true; // @audit can re-add immediately after voteOut
        cohortMembers[currentCohortId].push(member);
    }
}
```

The contract allows the Security Council to replace a cohort without checking for ongoing elections, and re-adds voted-out members in the same cycle because `voteOutMember` does not record the removal epoch and `addMember` does not validate against it.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DAOGovernanceFixed {
    uint256 public currentEpoch;
    mapping(uint256 => address[]) public cohortMembers;
    mapping(address => uint256) public lastRemovedEpoch;
    mapping(uint256 => uint256) public ongoingElections;
    address public securityCouncil;
    
    function replaceCohort(address[] calldata newMembers) external {
        require(msg.sender == securityCouncil, "Only SC");
        require(ongoingElections[currentEpoch] == 0, "Election in progress");
        delete cohortMembers[currentEpoch];
        currentEpoch++;
        for (uint i = 0; i < newMembers.length; i++) {
            require(lastRemovedEpoch[newMembers[i]] != currentEpoch, "Removed this epoch");
            cohortMembers[currentEpoch].push(newMembers[i]);
        }
    }
    
    function voteOutMember(address member) external {
        // ... voting logic ...
        lastRemovedEpoch[member] = currentEpoch;
    }
    
    function addMember(address member) external {
        require(msg.sender == securityCouncil, "Only SC");
        require(lastRemovedEpoch[member] != currentEpoch, "Removed this epoch");
        cohortMembers[currentEpoch].push(member);
    }
}
```

Fixed version increments `currentEpoch` on cohort rotation, blocks `replaceCohort` when elections are ongoing, records `lastRemovedEpoch` on vote-out, and gates `addMember`/`replaceCohort` additions against that epoch.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
