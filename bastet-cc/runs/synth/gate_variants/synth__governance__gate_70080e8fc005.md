# Governance

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance**
Governance systems are vulnerable when voting power can be manipulated via flash loans or instant token acquisition because snapshots are taken at vote time rather than at a fixed block before voting starts. Proposal activation often lacks rate limiting or spam protection, allowing low-stake actors to repeatedly activate dummy proposals and block legitimate ones through grace period lockouts. Parameter changes such as vote weight durations or quorum thresholds can be applied mid-vote without checking for active proposals, altering the outcome of ongoing elections. Vote accounting may reset state before external calls, enabling reentrancy that lets signers vote multiple times in a single transaction. Member management frequently omits checks preventing re-addition of previously removed addresses, allowing voted-out members to regain privileges. Execution paths sometimes validate msg.value but fail to forward it with the external call, causing actions to execute with zero value despite passing validation. Quorum calculations may incorrectly use token quantities instead of holder counts, letting multi-token holders dominate decisions meant to be one-holder-one-vote. External functions that write critical governance state often lack access control, allowing anyone to overwrite approval and disapproval supply values after action creation.

### Detection Checks

1. Verify that voting power snapshots are taken at a fixed block (e.g., proposal creation or a dedicated snapshot block) and not at vote time, preventing flash loan manipulation.
2. Ensure proposal activation enforces a minimum endorsement threshold based on total supply and includes spam protection such as activation cooldowns or submitter reputation checks.
3. Confirm that governance parameter setters (e.g., fullWeightDuration, votingPeriod, quorum thresholds) revert if any proposal is active or in voting period.
4. Check that vote accounting clears state (vote counts, hasVoted flags) only after the external call completes, not before, to prevent reentrancy double-voting.
5. Validate that member addition functions check a removal registry or governance veto list before re-adding previously removed addresses.
6. Inspect executeAction or similar execution functions for payable calls that validate msg.value but omit {value: actionInfo.value} in the external call.
7. Verify quorum and voting power functions return 1 per holder (or the documented weighting) rather than raw token balances when the policy specifies holder-count-based thresholds.
8. Ensure external functions that write actionApprovalSupply, actionDisapprovalSupply, or equivalent governance state have proper access control (onlyRole, onlyOwner, or proposal-state-gated).

### Examples

#### Example 1: Incorrect Example

```solidity
function vote(bool for_) external {
    uint256 userVotes = VOTES.balanceOf(msg.sender); // snapshot at vote time
    if (activeProposal.proposalId == 0) revert NoActiveProposalDetected();
    if (userVotesForProposal[activeProposal.proposalId][msg.sender] > 0) revert UserAlreadyVoted();
    if (for_) yesVotesForProposal[activeProposal.proposalId] += userVotes;
    else noVotesForProposal[activeProposal.proposalId] += userVotes;
    userVotesForProposal[activeProposal.proposalId][msg.sender] = userVotes;
    VOTES.transferFrom(msg.sender, address(this), userVotes);
}

function setFullWeightDuration(uint256 newDuration) external onlyGovernance {
    if (newDuration > votingPeriod()) revert InvalidDuration();
    fullWeightDuration = newDuration; // no active proposal check
}

function executeAction(ActionInfo calldata actionInfo) external payable {
    if (msg.value != actionInfo.value) revert IncorrectMsgValue();
    action.executed = true;
    (bool success, ) = executor.execute(actionInfo.target, actionInfo.value, action.isScript, actionInfo.data); // missing {value: actionInfo.value}
    if (!success) revert FailedActionExecution();
}
```

Voting snapshots balance at vote time enabling flash loans; parameter setter lacks active proposal guard; execution validates msg.value but does not forward it.

#### Example 2: Correct Example

```solidity
function vote(bool for_) external {
    uint256 userVotes = VOTES.getPastVotes(msg.sender, snapshotBlock); // fixed snapshot
    if (activeProposal.proposalId == 0) revert NoActiveProposalDetected();
    if (userVotesForProposal[activeProposal.proposalId][msg.sender] > 0) revert UserAlreadyVoted();
    if (for_) yesVotesForProposal[activeProposal.proposalId] += userVotes;
    else noVotesForProposal[activeProposal.proposalId] += userVotes;
    userVotesForProposal[activeProposal.proposalId][msg.sender] = userVotes;
    VOTES.transferFrom(msg.sender, address(this), userVotes);
}

function setFullWeightDuration(uint256 newDuration) external onlyGovernance {
    if (newDuration > votingPeriod()) revert InvalidDuration();
    if (activeProposal.proposalId != 0) revert ActiveProposalExists(); // guard
    fullWeightDuration = newDuration;
}

function executeAction(ActionInfo calldata actionInfo) external payable {
    if (msg.value != actionInfo.value) revert IncorrectMsgValue();
    action.executed = true;
    (bool success, ) = executor.execute{value: actionInfo.value}(actionInfo.target, actionInfo.value, action.isScript, actionInfo.data); // forwards value
    if (!success) revert FailedActionExecution();
}
```

Voting uses fixed snapshot block; parameter setter blocks changes during active proposals; execution forwards validated msg.value.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
