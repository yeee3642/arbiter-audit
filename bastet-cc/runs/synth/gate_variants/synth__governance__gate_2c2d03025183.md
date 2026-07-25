# Governance

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance**
Governance vulnerabilities arise when voting power, proposal lifecycle, or member management logic contains design flaws that allow manipulation. Common mechanisms include: (1) Flash-loan or instant token acquisition to inflate voting weight at snapshot time, because snapshots use current balances instead of historical checkpoints. (2) Missing access control on parameter setters (e.g., quorum thresholds, voting periods) that can be changed mid-vote, altering the outcome retroactively. (3) Proposal activation or execution logic that lacks rate limiting, spam protection, or proper state transitions, enabling denial-of-service via dummy proposals or re-entrancy during execution. (4) Vote recording that transfers tokens into the contract and prevents later balance changes, but allows reclaiming votes in the same transaction before activation, breaking accounting invariants. (5) Member management that permits re-adding previously removed addresses without governance approval. (6) Threshold comparisons using strict inequality (>) instead of >=, allowing cancellation or execution at exact boundary values. (7) External calls in execution paths that omit `value` forwarding despite payable validation, causing silent failures. (8) Unbounded parameter setters (e.g., percentage cast to uint8 without 0-100 check) that break downstream math.

### Detection Checks

1. Verify that voting power snapshots use historical checkpoints (e.g., ERC20Votes.getPastVotes) instead of current balances to prevent flash-loan manipulation.
2. Ensure all governance parameter setters (quorum, thresholds, durations) validate that no active proposals exist before applying changes.
3. Confirm proposal activation requires a minimum time delay or endorsement history to prevent spam activation and GRACE_PERIOD lockout abuse.
4. Check that vote recording does not transfer tokens into the contract unless a matching reclaim mechanism enforces one-vote-per-token and prevents same-transaction vote-and-reclaim.
5. Validate that reclaimVotes or similar functions block reclaiming for proposals that have been activated in the current transaction or block.
6. Ensure member addition functions check a removal registry or require DAO vote before re-adding previously expelled addresses.
7. Verify threshold comparisons use >= for minimum voting power checks and <= for maximum bounds to avoid off-by-one errors at exact boundary values.
8. Confirm that payable execution functions forward msg.value via {value: ...} in low-level calls when the calldata includes a value field.

### Examples

#### Example 1: Incorrect Example

```solidity
contract Governance {
    ERC20Votes public token;
    mapping(uint256 => mapping(address => uint256)) public userVotes;
    uint256 public activeProposalId;
    uint256 public votingPeriod = 7 days;
    
    function vote(uint256 proposalId, bool support) external {
        require(proposalId == activeProposalId, "not active");
        uint256 weight = token.balanceOf(msg.sender); // current balance, no snapshot
        require(userVotes[proposalId][msg.sender] == 0, "already voted");
        userVotes[proposalId][msg.sender] = weight;
        if (support) yesVotes[proposalId] += weight; else noVotes[proposalId] += weight;
        token.transferFrom(msg.sender, address(this), weight);
    }
    
    function reclaimVotes(uint256 proposalId) external {
        require(proposalId != activeProposalId, "active");
        uint256 weight = userVotes[proposalId][msg.sender];
        require(weight > 0, "none");
        userVotes[proposalId][msg.sender] = 0;
        token.transfer(msg.sender, weight);
    }
    
    function setVotingPeriod(uint256 newPeriod) external onlyOwner {
        votingPeriod = newPeriod; // no active proposal check
    }
    
    function addMember(address member) external onlyRole(MEMBER_ROLE) {
        members.push(member); // no removal registry check
    }
}
```

Uses current token balance for voting weight (flash-loan vulnerable), transfers tokens in on vote but allows reclaim before activation in same tx, changes voting period mid-vote, and re-adds members without checking removal history.

#### Example 2: Correct Example

```solidity
contract GovernanceFixed {
    ERC20Votes public token;
    mapping(uint256 => mapping(address => uint256)) public userVotes;
    uint256 public activeProposalId;
    uint256 public votingPeriod = 7 days;
    mapping(address => bool) public removedMembers;
    
    function vote(uint256 proposalId, bool support) external {
        require(proposalId == activeProposalId, "not active");
        uint256 snapshot = proposalSnapshots[proposalId];
        uint256 weight = token.getPastVotes(msg.sender, snapshot);
        require(userVotes[proposalId][msg.sender] == 0, "already voted");
        userVotes[proposalId][msg.sender] = weight;
        if (support) yesVotes[proposalId] += weight; else noVotes[proposalId] += weight;
    }
    
    function reclaimVotes(uint256 proposalId) external {
        require(proposalId != activeProposalId, "active");
        require(block.number > activationBlock[proposalId], "same block");
        uint256 weight = userVotes[proposalId][msg.sender];
        require(weight > 0, "none");
        userVotes[proposalId][msg.sender] = 0;
    }
    
    function setVotingPeriod(uint256 newPeriod) external onlyOwner {
        require(activeProposalId == 0, "active proposal exists");
        votingPeriod = newPeriod;
    }
    
    function addMember(address member) external onlyRole(MEMBER_ROLE) {
        require(!removedMembers[member], "previously removed");
        members.push(member);
    }
}
```

Uses historical checkpoint for voting weight, prevents mid-vote parameter changes, blocks same-block vote reclaim, and checks removal registry before re-adding members.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
