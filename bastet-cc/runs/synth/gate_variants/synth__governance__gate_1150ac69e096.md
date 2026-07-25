# Governance-Manipulation

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance-Manipulation**
Governance systems are vulnerable when voting power snapshots, proposal lifecycle checks, and parameter updates lack proper validation or timing constraints. Flash loans or same-block token acquisition can inflate voting weight if snapshots use the current block instead of a prior block. Proposal IDs derived solely from calldata without a nonce allow front-running: an attacker submits the same proposal, cancels it, and permanently blocks the legitimate proposer because the ID already exists. Threshold comparisons using strict inequality (<) instead of <= cause tied votes to be misclassified as Succeeded rather than Defeated. Vote reclamation functions that only block the currently active proposal ID permit voting and immediate reclamation in the same transaction before activation. Member management that allows re-adding previously removed addresses without a governance veto check enables voted-out members to regain privileges. Parameter setters (e.g., voting duration, quorum, token minting) that do not verify the absence of active proposals allow mid-vote rule changes that alter outcomes. Multi-sig or endorsement modifiers that clear vote state before the external call (_;) enable reentrancy voting: a signer who already voted can vote again if the external call reenters. Uncapped minting of governance tokens by a privileged role inflates totalSupply, lowering proposal thresholds and quorum requirements arbitrarily.

### Detection Checks

1. Verify that proposal creation snapshots voting power at block.timestamp - 1 (or a prior block) and that proposalThreshold/quorum are derived from the same snapshot, not current totalSupply.
2. Ensure proposalId includes msg.sender or a monotonically increasing nonce in hashProposal so identical calldata from different proposers yields distinct IDs.
3. Confirm that state() uses <= for forVotes vs againstVotes comparison so a tie returns Defeated, not Succeeded.
4. Check that reclaimVotes (or similar) prevents reclamation for any proposal where the user has voted, not only the currently active one, and that the check occurs before any external call.
5. Validate that addMember (or equivalent) checks a removal registry or requires DAO approval before re-adding an address that was previously removed by governance.
6. Confirm that parameter setters (setVotingPeriod, setQuorum, setFullWeightDuration, mint governance tokens) revert if any proposal is in Active, Pending, or Queued state.
7. Inspect multi-sig/endorsement modifiers: vote state (voteCount, hasVoted) must be cleared only after the external call (_;) completes, not before, to prevent reentrancy double-voting.
8. Ensure governance token minting functions enforce a maximum totalSupply cap or require a timelocked governance vote, preventing arbitrary inflation by a single role.

### Examples

#### Example 1: Incorrect Example

```solidity
function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas, string calldata desc) external returns (bytes32) {
    uint256 threshold = proposalThreshold(); // uses current totalSupply
    if (getVotes(msg.sender, block.timestamp - 1) < threshold) revert();
    bytes32 id = hashProposal(targets, values, calldatas, keccak256(bytes(desc))); // no nonce
    if (proposals[id].voteStart != 0) revert();
    proposals[id].voteStart = uint32(block.timestamp + votingDelay);
    proposals[id].proposalThreshold = uint32(threshold);
    proposals[id].quorumVotes = uint32(quorum()); // current totalSupply
    return id;
}

function state(bytes32 id) public view returns (ProposalState) {
    Proposal memory p = proposals[id];
    if (p.forVotes < p.againstVotes || p.forVotes < p.quorumVotes) return ProposalState.Defeated; // strict <
    return ProposalState.Succeeded;
}

function reclaimVotes(uint256 pid) external {
    if (pid == activeProposalId) revert(); // only blocks active
    if (claimed[pid][msg.sender]) revert();
    claimed[pid][msg.sender] = true;
    token.transfer(msg.sender, userVotes[pid][msg.sender]);
}

function addMember(address member) external onlyRole(ADMIN) {
    members.push(member); // no check for prior removal
}

function setVotingPeriod(uint256 p) external onlyOwner {
    votingPeriod = p; // no active proposal check
}

modifier onlySigners() {
    if (voted[msg.sender]) revert();
    voted[msg.sender] = true;
    voteCount++;
    if (voteCount < threshold) { _; return; }
    voteCount = 0; // cleared BEFORE external call
    for (uint i=0;i<signers.length;i++) voted[signers[i]] = false;
    _;
}
```

Proposal uses current totalSupply for thresholds, proposalId lacks nonce, Defeated check uses strict <, reclaimVotes only blocks active proposal, addMember allows re-adding removed members, setVotingPeriod changes params mid-vote, and modifier clears vote state before external call enabling reentrancy double-voting.

#### Example 2: Correct Example

```solidity
function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas, string calldata desc) external returns (bytes32) {
    uint256 snap = block.timestamp - 1;
    uint256 threshold = proposalThreshold(snap);
    if (getVotes(msg.sender, snap) < threshold) revert();
    bytes32 id = hashProposal(targets, values, calldatas, keccak256(bytes(desc)), msg.sender); // includes proposer
    if (proposals[id].voteStart != 0) revert();
    proposals[id].voteStart = uint32(block.timestamp + votingDelay);
    proposals[id].proposalThreshold = uint32(threshold);
    proposals[id].quorumVotes = uint32(quorum(snap));
    return id;
}

function state(bytes32 id) public view returns (ProposalState) {
    Proposal memory p = proposals[id];
    if (p.forVotes <= p.againstVotes || p.forVotes < p.quorumVotes) return ProposalState.Defeated; // <=
    return ProposalState.Succeeded;
}

function reclaimVotes(uint256 pid) external {
    if (userVotes[pid][msg.sender] > 0 && !claimed[pid][msg.sender]) {
        claimed[pid][msg.sender] = true;
        token.transfer(msg.sender, userVotes[pid][msg.sender]);
    }
}

function addMember(address member) external onlyRole(ADMIN) {
    if (removedMembers[member]) revert(); // block re-addition
    members.push(member);
}

function setVotingPeriod(uint256 p) external onlyOwner {
    if (hasActiveProposal()) revert();
    votingPeriod = p;
}

modifier onlySigners() {
    if (voted[msg.sender]) revert();
    voted[msg.sender] = true;
    voteCount++;
    if (voteCount < threshold) { _; return; }
    _;
    voteCount = 0; // cleared AFTER external call
    for (uint i=0;i<signers.length;i++) voted[signers[i]] = false;
}
```

Snapshots use prior block, proposalId includes proposer, Defeated uses <=, reclaimVotes allows any voted proposal, addMember blocks removed members, setVotingPeriod checks for active proposals, and modifier clears state after external call preventing reentrancy.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
