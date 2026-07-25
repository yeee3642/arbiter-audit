# Governance

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance**
Governance vulnerabilities arise when voting power, proposal lifecycle, or parameter management can be manipulated due to missing or incorrect validations. A common flaw is using live token balances (e.g., `balanceOf(msg.sender)`) instead of snapshots, allowing flash loans or intra-block transfers to inflate voting weight and double-count endorsements. Proposal activation often lacks rate limiting or spam checks, so a low-power actor can repeatedly activate dummy proposals and lock out legitimate ones via grace periods. Threshold and quorum calculations may snapshot total supply at proposal creation but measure voting power at a prior block, enabling same-block supply inflation to lower effective thresholds. Vote reclamation logic frequently only blocks the currently active proposal, permitting users to vote and immediately reclaim in the same transaction before activation. Multi-sig or role-based voting modifiers that reset state before an external call (`_;`) enable reentrancy, letting signers vote twice in one transaction. Parameter setters (e.g., for vetoer, bid increments, or quorum) often omit zero-address or bounds checks, allowing invalid configurations. Execution functions may validate `msg.value` but fail to forward it in the low-level call, causing value loss. Finally, external functions that write critical state (like quorum supplies) without access control let anyone overwrite governance parameters after proposal creation.

### Detection Checks

1. Voting power or endorsement weight is read from a live balance (`balanceOf`, `getVotes`) instead of a snapshot taken at proposal creation or a fixed past block, enabling flash-loan manipulation.
2. Proposal activation lacks anti-spam measures: no minimum endorsement age, no cooldown between activations, or no limit on concurrent proposals, allowing griefing via dummy proposals.
3. Threshold or quorum values are snapshotted using current `totalSupply` while voting power is measured at `block.timestamp - 1` (or another past block), creating a mismatch that can be exploited by inflating supply in the same block.
4. Vote reclamation (`reclaimVotes`) only blocks the currently active proposal ID, permitting a user to vote and immediately reclaim in the same transaction before the proposal becomes active.
5. Multi-sig or role-voting modifiers reset `voteCount` and `hasVoted` flags before the external call (`_;`), enabling reentrancy that lets a signer vote twice in one transaction.
6. Critical parameter setters (vetoer, quorum, proposal threshold, bid increment) miss zero-address validation or upper/lower bounds checks (e.g., percentage > 100).
7. Execution functions validate `msg.value == actionInfo.value` but call `executor.execute(target, value, ...)` without `{value: actionInfo.value}`, so Ether is not forwarded.
8. External functions that write governance-critical state (e.g., `actionApprovalSupply`, `actionDisapprovalSupply`, `settings.vetoer`) have no access control (`onlyOwner`, `onlyRole`, `onlyManager`), allowing anyone to overwrite them after proposal creation.

### Examples

#### Example 1: Incorrect Example

```solidity
function endorseProposal(uint256 proposalId) external {
    uint256 userVotes = VOTES.balanceOf(msg.sender); // live balance, no snapshot
    uint256 previous = userEndorsementsForProposal[proposalId][msg.sender];
    totalEndorsementsForProposal[proposalId] -= previous;
    userEndorsementsForProposal[proposalId][msg.sender] = userVotes;
    totalEndorsementsForProposal[proposalId] += userVotes;
}

function activateProposal(uint256 proposalId) external {
    if (totalEndorsementsForProposal[proposalId] * 100 < VOTES.totalSupply() * ENDORSEMENT_THRESHOLD) revert();
    if (block.timestamp < activeProposal.activationTimestamp + GRACE_PERIOD) revert(); // no spam limit
    activeProposal = ActivatedProposal(proposalId, block.timestamp);
}

function reclaimVotes(uint256 proposalId) external {
    if (proposalId == activeProposal.proposalId) revert(); // only blocks active
    VOTES.transferFrom(address(this), msg.sender, userVotesForProposal[proposalId][msg.sender]);
}

modifier onlySigners() {
    if (voting.hasVoted[msg.sender]) revert();
    voting.hasVoted[msg.sender] = true;
    voting.voteCount++;
    if (voting.voteCount < threshold) return;
    voting.voteCount = 0;
    for (uint i=0;i<signers.length;i++) voting.hasVoted[signers[i]] = false;
    _; // reentrancy: state cleared before external call
}

function setVetoer(address _vetoer) external {
    settings.vetoer = _vetoer; // no zero-address check
}

function executeAction(ActionInfo calldata actionInfo) external payable {
    if (msg.value != actionInfo.value) revert();
    executor.execute(actionInfo.target, actionInfo.value, actionInfo.data); // missing {value: actionInfo.value}
}
```

Live balance used for endorsements enables double-counting via flash loans; activation lacks spam protection; reclaimVotes allows vote-and-reclaim in same tx; modifier clears state before external call enabling reentrancy; setVetoer misses zero-address check; executeAction validates msg.value but does not forward it.

#### Example 2: Correct Example

```solidity
function endorseProposal(uint256 proposalId) external {
    uint256 userVotes = VOTES.getPastVotes(msg.sender, proposalSnapshot[proposalId]); // snapshot at proposal creation
    uint256 previous = userEndorsementsForProposal[proposalId][msg.sender];
    totalEndorsementsForProposal[proposalId] -= previous;
    userEndorsementsForProposal[proposalId][msg.sender] = userVotes;
    totalEndorsementsForProposal[proposalId] += userVotes;
}

function activateProposal(uint256 proposalId) external {
    if (totalEndorsementsForProposal[proposalId] * 100 < VOTES.totalSupply() * ENDORSEMENT_THRESHOLD) revert();
    if (block.timestamp < lastActivationTimestamp + ACTIVATION_COOLDOWN) revert(); // rate limit
    if (block.timestamp < activeProposal.activationTimestamp + GRACE_PERIOD) revert();
    activeProposal = ActivatedProposal(proposalId, block.timestamp);
    lastActivationTimestamp = block.timestamp;
}

function reclaimVotes(uint256 proposalId) external {
    if (proposalId == activeProposal.proposalId) revert();
    if (proposalId == pendingActivationProposalId) revert(); // block proposals in activation pipeline
    VOTES.transferFrom(address(this), msg.sender, userVotesForProposal[proposalId][msg.sender]);
}

modifier onlySigners() {
    if (voting.hasVoted[msg.sender]) revert();
    voting.hasVoted[msg.sender] = true;
    voting.voteCount++;
    if (voting.voteCount < threshold) return;
    // execute external call FIRST, then clear state
    _;
    voting.voteCount = 0;
    for (uint i=0;i<signers.length;i++) voting.hasVoted[signers[i]] = false;
}

function setVetoer(address _vetoer) external onlyOwner {
    if (_vetoer == address(0)) revert();
    settings.vetoer = _vetoer;
}

function executeAction(ActionInfo calldata actionInfo) external payable {
    if (msg.value != actionInfo.value) revert();
    (bool success, ) = executor.execute{value: actionInfo.value}(actionInfo.target, actionInfo.data);
    if (!success) revert();
}
```

Endorsements use snapshot at proposal creation; activation adds cooldown to prevent spam; reclaimVotes blocks pending proposals; modifier executes external call before clearing state; setVetoer adds onlyOwner and zero-address check; executeAction forwards value with {value: ...}.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
