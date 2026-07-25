# Governance

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance**
Governance systems are vulnerable when voting power can be manipulated via flash loans or instant token acquisition because snapshots are taken at vote time rather than at a fixed block before voting starts. Proposal activation often lacks rate limiting or spam protection, allowing low-stake actors to repeatedly activate dummy proposals and block legitimate ones through grace period lockouts. Parameter changes such as vote weight durations or quorum thresholds can be applied mid-vote without checking for active proposals, altering the outcome of ongoing elections. Vote cancellation logic frequently uses strict inequality (>) instead of >= when comparing proposer voting power against the proposal threshold, enabling cancellation when power exactly equals the threshold. Member management allows re-adding previously removed addresses without checking removal history, letting voted-out members regain privileges. Execution paths may validate msg.value but fail to forward it in low-level calls, causing value loss. Percentage parameters are accepted without upper/lower bound checks, permitting extreme values that break economic mechanics. Quorum calculations sometimes count token quantities instead of unique holders, letting multi-token holders dominate holder-count thresholds.

### Detection Checks

1. Snapshot voting power at a fixed block (e.g., proposal creation or a dedicated snapshot block) rather than at vote time to prevent flash loan manipulation.
2. Enforce a minimum endorsement threshold and activation cooldown or rate limit in activateProposal to prevent spam proposals from blocking legitimate ones via GRACE_PERIOD.
3. Require that parameter setters (e.g., setFullWeightDuration, setMinimumBidIncrement) revert if any proposal is active or in voting period, and validate percentage inputs are within 0-100.
4. Use >= instead of > when checking proposer voting power against proposalThreshold in cancel to prevent cancellation at exact equality.
5. Maintain a removedMembers mapping and check it in addMember to prevent re-adding addresses that were governance-removed.
6. Forward msg.value in low-level calls (executor.execute) when the function is payable and validates msg.value == actionInfo.value.
7. Record vote weight at snapshot time and allow vote changes before voting ends; do not permanently lock userVotesForProposal on first vote.
8. In reclaimVotes, block reclaiming for proposals that have been activated or are in the voting window, not only the currently active proposal, and prevent vote-and-reclaim in the same transaction via a reentrancy guard or state check.

### Examples

#### Example 1: Incorrect Example

```solidity
function vote(bool for_) external {
    uint256 userVotes = VOTES.balanceOf(msg.sender);
    if (activeProposal.proposalId == 0) revert NoActiveProposalDetected();
    if (userVotesForProposal[activeProposal.proposalId][msg.sender] > 0) revert UserAlreadyVoted();
    if (for_) yesVotesForProposal[activeProposal.proposalId] += userVotes;
    else noVotesForProposal[activeProposal.proposalId] += userVotes;
    userVotesForProposal[activeProposal.proposalId][msg.sender] = userVotes;
    VOTES.transferFrom(msg.sender, address(this), userVotes);
    emit WalletVoted(activeProposal.proposalId, msg.sender, for_, userVotes);
}

function reclaimVotes(uint256 proposalId_) external {
    uint256 userVotes = userVotesForProposal[proposalId_][msg.sender];
    if (userVotes == 0) revert CannotReclaimZeroVotes();
    if (proposalId_ == activeProposal.proposalId) revert CannotReclaimTokensForActiveVote();
    if (tokenClaimsForProposal[proposalId_][msg.sender]) revert VotingTokensAlreadyReclaimed();
    tokenClaimsForProposal[proposalId_][msg.sender] = true;
    VOTES.transferFrom(address(this), msg.sender, userVotes);
}

function setFullWeightDuration(uint256 newFullWeightDuration) public onlyGovernance {
    if (newFullWeightDuration > votingPeriod()) revert FullWeightDurationGreaterThanVotingPeriod(newFullWeightDuration, votingPeriod());
    fullWeightDuration = newFullWeightDuration;
    emit FullWeightDurationSet(newFullWeightDuration);
}

function activateProposal(uint256 proposalId_) external {
    ProposalMetadata memory proposal = getProposalMetadata[proposalId_];
    if (msg.sender != proposal.submitter) revert NotAuthorizedToActivateProposal();
    if (block.timestamp > proposal.submissionTimestamp + ACTIVATION_DEADLINE) revert SubmittedProposalHasExpired();
    if ((totalEndorsementsForProposal[proposalId_] * 100) < VOTES.totalSupply() * ENDORSEMENT_THRESHOLD) revert NotEnoughEndorsementsToActivateProposal();
    if (proposalHasBeenActivated[proposalId_]) revert ProposalAlreadyActivated();
    if (block.timestamp < activeProposal.activationTimestamp + GRACE_PERIOD) revert ActiveProposalNotExpired();
    activeProposal = ActivatedProposal(proposalId_, block.timestamp);
    proposalHasBeenActivated[proposalId_] = true;
    emit ProposalActivated(proposalId_, block.timestamp);
}

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

function executeAction(ActionInfo calldata actionInfo) external payable {
    Action storage action = actions[actionInfo.id];
    if (getActionState(actionInfo) != ActionState.Queued) revert InvalidActionState(getActionState(actionInfo));
    if (block.timestamp < action.minExecutionTime) revert MinExecutionTimeNotReached();
    if (msg.value != actionInfo.value) revert IncorrectMsgValue();
    action.executed = true;
    (bool success, bytes memory result) = executor.execute(actionInfo.target, actionInfo.value, action.isScript, actionInfo.data);
    if (!success) revert FailedActionExecution(result);
    emit ActionExecuted(actionInfo.id, msg.sender, actionInfo.strategy, actionInfo.creator, result);
}

function setMinimumBidIncrement(uint256 _percentage) external onlyOwner {
    settings.minBidIncrement = SafeCast.toUint8(_percentage);
    emit MinBidIncrementPercentageUpdated(_percentage);
}
```

Vote snapshots balance at vote time enabling flash loans; reclaimVotes only blocks active proposal; setFullWeightDuration lacks active proposal check; activateProposal has no spam protection; cancel uses > instead of >=; addMember allows re-adding removed members; executeAction validates msg.value but doesn't forward it; setMinimumBidIncrement accepts any uint256 without 0-100 bound check.

#### Example 2: Correct Example

```solidity
function vote(bool for_) external {
    uint256 userVotes = VOTES.getPastVotes(msg.sender, activeProposal.snapshotBlock);
    if (activeProposal.proposalId == 0) revert NoActiveProposalDetected();
    if (block.timestamp > activeProposal.endBlock) revert VotingEnded();
    uint256 previous = userVotesForProposal[activeProposal.proposalId][msg.sender];
    if (for_) yesVotesForProposal[activeProposal.proposalId] = yesVotesForProposal[activeProposal.proposalId] - previous + userVotes;
    else noVotesForProposal[activeProposal.proposalId] = noVotesForProposal[activeProposal.proposalId] - previous + userVotes;
    userVotesForProposal[activeProposal.proposalId][msg.sender] = userVotes;
    emit WalletVoted(activeProposal.proposalId, msg.sender, for_, userVotes);
}

function reclaimVotes(uint256 proposalId_) external {
    uint256 userVotes = userVotesForProposal[proposalId_][msg.sender];
    if (userVotes == 0) revert CannotReclaimZeroVotes();
    if (proposalHasBeenActivated[proposalId_] || block.timestamp < getProposalEndBlock(proposalId_)) revert CannotReclaim();
    if (tokenClaimsForProposal[proposalId_][msg.sender]) revert VotingTokensAlreadyReclaimed();
    tokenClaimsForProposal[proposalId_][msg.sender] = true;
    VOTES.transferFrom(address(this), msg.sender, userVotes);
}

function setFullWeightDuration(uint256 newFullWeightDuration) public onlyGovernance {
    if (newFullWeightDuration > votingPeriod()) revert FullWeightDurationGreaterThanVotingPeriod(newFullWeightDuration, votingPeriod());
    if (hasActiveProposals()) revert ActiveProposalsExist();
    fullWeightDuration = newFullWeightDuration;
    emit FullWeightDurationSet(newFullWeightDuration);
}

function activateProposal(uint256 proposalId_) external {
    ProposalMetadata memory proposal = getProposalMetadata[proposalId_];
    if (msg.sender != proposal.submitter) revert NotAuthorizedToActivateProposal();
    if (block.timestamp > proposal.submissionTimestamp + ACTIVATION_DEADLINE) revert SubmittedProposalHasExpired();
    if ((totalEndorsementsForProposal[proposalId_] * 100) < VOTES.totalSupply() * ENDORSEMENT_THRESHOLD) revert NotEnoughEndorsementsToActivateProposal();
    if (proposalHasBeenActivated[proposalId_]) revert ProposalAlreadyActivated();
    if (block.timestamp < activeProposal.activationTimestamp + GRACE_PERIOD) revert ActiveProposalNotExpired();
    if (block.timestamp < lastActivationTimestamp + ACTIVATION_COOLDOWN) revert ActivationTooFrequent();
    activeProposal = ActivatedProposal(proposalId_, block.timestamp);
    lastActivationTimestamp = block.timestamp;
    proposalHasBeenActivated[proposalId_] = true;
    emit ProposalActivated(proposalId_, block.timestamp);
}

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
    if (removedMembers[_newMember]) revert MemberPreviouslyRemoved();
    _addMemberToCohortArray(_newMember, _cohort);
    _scheduleUpdate();
    emit MemberAdded(_newMember, _cohort);
}

function executeAction(ActionInfo calldata actionInfo) external payable {
    Action storage action = actions[actionInfo.id];
    if (getActionState(actionInfo) != ActionState.Queued) revert InvalidActionState(getActionState(actionInfo));
    if (block.timestamp < action.minExecutionTime) revert MinExecutionTimeNotReached();
    if (msg.value != actionInfo.value) revert IncorrectMsgValue();
    action.executed = true;
    (bool success, bytes memory result) = executor.execute{value: actionInfo.value}(actionInfo.target, actionInfo.value, action.isScript, actionInfo.data);
    if (!success) revert FailedActionExecution(result);
    emit ActionExecuted(actionInfo.id, msg.sender, actionInfo.strategy, actionInfo.creator, result);
}

function setMinimumBidIncrement(uint256 _percentage) external onlyOwner {
    if (_percentage > 100) revert InvalidPercentage();
    settings.minBidIncrement = SafeCast.toUint8(_percentage);
    emit MinBidIncrementPercentageUpdated(_percentage);
}
```

Vote uses snapshot block for flash loan resistance and allows vote changes; reclaimVotes blocks reclaim for activated or in-voting proposals; setFullWeightDuration checks for active proposals; activateProposal adds activation cooldown; cancel uses >= for threshold equality; addMember checks removedMembers mapping; executeAction forwards value with {value: ...}; setMinimumBidIncrement enforces 0-100 bound.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
