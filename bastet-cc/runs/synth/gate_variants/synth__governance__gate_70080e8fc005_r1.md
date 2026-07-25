# Governance

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance**
Governance systems are vulnerable when voting power can be manipulated via flash loans or instant token acquisition, when proposal activation lacks spam protection allowing dummy proposals to block legitimate ones, when vote weight snapshots are taken at voting time instead of a fixed snapshot block enabling double-voting, when governance parameters like quorum thresholds or vote durations can be changed mid-vote, when vote reclamation allows re-voting within the same transaction, when multisig vote counters reset before external calls enabling reentrancy voting, when action validation functions lack access control allowing arbitrary overwrites of approval supplies, when vote counting uses token quantities instead of holder counts against holder-based thresholds, and when failed proposals don't clear active state leaving votes locked and blocking new proposals. These flaws stem from missing snapshot mechanisms, missing access controls, incorrect state ordering (clearing votes before external calls), missing parameter validation against active proposals, and incorrect denominator choices in threshold calculations.

### Detection Checks

1. Check if voting power is snapshotted at a fixed block (e.g., proposal creation) rather than at vote/endorse time via balanceOf(msg.sender), which enables flash loan manipulation.
2. Check if proposal activation has minimum voting power requirements for submitters, rate limits, or spam filters to prevent low-stake actors from repeatedly activating dummy proposals that trigger grace period lockouts.
3. Check if governance parameter setters (setFullWeightDuration, setQuorumThreshold, setExecutionThreshold, etc.) validate that no active proposals exist before applying changes.
4. Check if vote/endorse functions record weight from balanceOf without preventing token transfer and re-endorsement within the same proposal (missing snapshot or double-counting protection).
5. Check if reclaimVotes or similar functions allow reclaiming votes for proposals that became active after the vote was cast but within the same transaction (missing check that proposal was active at vote time).
6. Check if multisig or threshold voting modifiers reset vote counters and hasVoted flags BEFORE the external call (_;) instead of after, enabling reentrancy re-voting.
7. Check if external/public functions that write critical governance state (actionApprovalSupply, actionDisapprovalSupply, quorum denominators) have proper access control (onlyRole, onlyGovernance, onlyPolicyAdmin).
8. Check if vote counting functions (getApprovalQuantityAt, getRoleSupplyAsNumberOfHolders) return token quantities when the threshold logic expects holder counts (or vice versa), causing multi-token holders to count multiple times.

### Examples

#### Example 1: Incorrect Example

```solidity
contract GovernanceFlawed {
    IVotes public VOTES;
    uint256 public activeProposalId;
    mapping(uint256 => mapping(address => uint256)) public userVotesForProposal;
    mapping(uint256 => uint256) public yesVotes, noVotes;
    uint256 public fullWeightDuration = 7 days;
    
    function vote(uint256 proposalId, bool for_) external {
        uint256 userVotes = VOTES.balanceOf(msg.sender); // @audit no snapshot, flash loanable
        if (userVotesForProposal[proposalId][msg.sender] > 0) revert();
        if (for_) yesVotes[proposalId] += userVotes;
        else noVotes[proposalId] += userVotes;
        userVotesForProposal[proposalId][msg.sender] = userVotes;
    }
    
    function setFullWeightDuration(uint256 newDuration) external onlyOwner {
        fullWeightDuration = newDuration; // @audit no check for active proposals
    }
    
    function reclaimVotes(uint256 proposalId) external {
        uint256 votes = userVotesForProposal[proposalId][msg.sender];
        if (proposalId == activeProposalId) revert();
        // @audit missing check: proposal was active when vote was cast
        delete userVotesForProposal[proposalId][msg.sender];
        VOTES.transfer(msg.sender, votes);
    }
    
    function executeProposal(uint256 proposalId) external {
        if (yesVotes[proposalId] - noVotes[proposalId] < threshold) revert();
        // @audit missing: activeProposalId = 0 on failure path
        (bool success,) = target.call(data);
        if (!success) revert();
        activeProposalId = 0;
    }
}
```

Voting uses live balanceOf enabling flash loans; parameter changes lack active proposal checks; reclaimVotes allows re-voting in same transaction; failed execution doesn't clear active proposal.

#### Example 2: Correct Example

```solidity
contract GovernanceFixed {
    IVotes public VOTES;
    uint256 public activeProposalId;
    mapping(uint256 => uint256) public proposalSnapshotBlock;
    mapping(uint256 => mapping(address => uint256)) public userVotesForProposal;
    mapping(uint256 => uint256) public yesVotes, noVotes;
    uint256 public fullWeightDuration = 7 days;
    
    function vote(uint256 proposalId, bool for_) external {
        uint256 snapshotBlock = proposalSnapshotBlock[proposalId];
        uint256 userVotes = VOTES.getPastVotes(msg.sender, snapshotBlock); // @audit fixed snapshot
        if (userVotesForProposal[proposalId][msg.sender] > 0) revert();
        if (for_) yesVotes[proposalId] += userVotes;
        else noVotes[proposalId] += userVotes;
        userVotesForProposal[proposalId][msg.sender] = userVotes;
    }
    
    function setFullWeightDuration(uint256 newDuration) external onlyOwner {
        if (activeProposalId != 0) revert(); // @audit block mid-vote changes
        fullWeightDuration = newDuration;
    }
    
    function reclaimVotes(uint256 proposalId) external {
        uint256 votes = userVotesForProposal[proposalId][msg.sender];
        if (proposalId == activeProposalId) revert();
        if (block.number <= proposalSnapshotBlock[proposalId]) revert(); // @audit prevent same-tx reclaim
        delete userVotesForProposal[proposalId][msg.sender];
        VOTES.transfer(msg.sender, votes);
    }
    
    function executeProposal(uint256 proposalId) external {
        if (yesVotes[proposalId] - noVotes[proposalId] < threshold) {
            activeProposalId = 0; // @audit clear on failure
            revert();
        }
        (bool success,) = target.call(data);
        if (!success) {
            activeProposalId = 0; // @audit clear on failure
            revert();
        }
        activeProposalId = 0;
    }
}
```

Voting uses getPastVotes at snapshot block; parameter changes blocked during active proposals; reclaimVotes checks proposal wasn't active at vote time; executeProposal clears activeProposalId on all failure paths.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
