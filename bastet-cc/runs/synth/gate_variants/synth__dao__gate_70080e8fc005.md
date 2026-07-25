# DAO-Governance-Member-Lifecycle-Management

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**DAO-Governance-Member-Lifecycle-Management**
DAO governance contracts often manage member lifecycles across cohorts or terms. A critical flaw arises when member removal lacks persistent tracking, allowing a member voted out by the DAO to be immediately re-added by a privileged role (e.g., Security Council) within the same governance cycle. This undermines the democratic voting process. Additionally, cohort transitions must be atomic: replacing a cohort requires validating that no ongoing elections or proposals involve the outgoing members. If the old cohort is deleted and a new one created without checking for active elections, a member can exist in both cohorts simultaneously, leading to double voting rights, quorum confusion, and governance paralysis. Proper designs enforce a removal registry (e.g., a `removedMembers` mapping with timestamps or epoch IDs) and require `require(!isElectionActive(), "election in progress")` before cohort rotation.

### Detection Checks

1. Verify that member removal writes to a persistent `removedMembers` mapping (or similar) keyed by address and epoch/term, not just deletes from the active set.
2. Confirm that `addMember` or `replaceMember` checks `removedMembers[addr][currentEpoch]` and reverts if the member was previously removed in the same epoch.
3. Ensure `rotateCohort` or `replaceCohort` reads an `electionInProgress` flag or `ongoingProposalCount` and reverts when > 0.
4. Check that cohort replacement does not allow an address to appear in both `oldCohortMembers` and `newCohortMembers` simultaneously; require `require(!isMemberOfOldCohort(newMember), "duplicate across cohorts")`.
5. Validate that voting power snapshots or quorum calculations reference a single cohesive member set per epoch, not a union of old and new cohorts.
6. Confirm that only the DAO voting module (not a privileged admin) can initiate member removal, or that admin re-addition is gated by a timelock or DAO approval.
7. Check for event emission (`MemberRemoved`, `CohortRotated`) with sufficient parameters (address, epoch, reason) to enable off-chain monitoring.
8. Ensure that `isMember` view functions respect the removal registry and cohort boundaries, returning false for removed members even if re-added in the same epoch.

### Examples

#### Example 1: Incorrect Example

```solidity
contract DAOGovernance {
    address[] public cohortMembers;
    mapping(address => bool) public isMember;
    address public securityCouncil;
    bool public electionActive;

    function removeMember(address member) external {
        require(msg.sender == securityCouncil, "only council");
        for (uint i = 0; i < cohortMembers.length; i++) {
            if (cohortMembers[i] == member) {
                cohortMembers[i] = cohortMembers[cohortMembers.length - 1];
                cohortMembers.pop();
                isMember[member] = false;
                break;
            }
        }
    }

    function addMember(address newMember) external {
        require(msg.sender == securityCouncil, "only council");
        require(!isMember[newMember], "already member");
        cohortMembers.push(newMember);
        isMember[newMember] = true;
    }

    function rotateCohort(address[] calldata newMembers) external {
        require(msg.sender == securityCouncil, "only council");
        cohortMembers = newMembers;
        for (uint i = 0; i < newMembers.length; i++) {
            isMember[newMembers[i]] = true;
        }
    }
}
```

Removal only deletes from the active array with no persistent record, so a voted-out member can be re-added immediately. rotateCohort overwrites the cohort without checking electionActive, allowing members to exist in both old and new cohorts during an election.

#### Example 2: Correct Example

```solidity
contract DAOGovernance {
    uint256 public currentEpoch;
    address[] public cohortMembers;
    mapping(address => bool) public isMember;
    mapping(address => uint256) public removedAtEpoch;
    address public securityCouncil;
    bool public electionActive;

    function removeMember(address member) external {
        require(msg.sender == securityCouncil, "only council");
        require(isMember[member], "not a member");
        for (uint i = 0; i < cohortMembers.length; i++) {
            if (cohortMembers[i] == member) {
                cohortMembers[i] = cohortMembers[cohortMembers.length - 1];
                cohortMembers.pop();
                isMember[member] = false;
                removedAtEpoch[member] = currentEpoch;
                break;
            }
        }
    }

    function addMember(address newMember) external {
        require(msg.sender == securityCouncil, "only council");
        require(!isMember[newMember], "already member");
        require(removedAtEpoch[newMember] != currentEpoch, "removed this epoch");
        cohortMembers.push(newMember);
        isMember[newMember] = true;
    }

    function rotateCohort(address[] calldata newMembers) external {
        require(msg.sender == securityCouncil, "only council");
        require(!electionActive, "election in progress");
        for (uint i = 0; i < newMembers.length; i++) {
            require(!isMember[newMembers[i]], "duplicate in new cohort");
        }
        cohortMembers = newMembers;
        for (uint i = 0; i < newMembers.length; i++) {
            isMember[newMembers[i]] = true;
        }
        currentEpoch++;
    }
}
```

Removed members are tracked per epoch via removedAtEpoch; addMember blocks re-addition in the same epoch. rotateCohort checks electionActive and ensures no address overlaps with the current cohort before incrementing the epoch.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
