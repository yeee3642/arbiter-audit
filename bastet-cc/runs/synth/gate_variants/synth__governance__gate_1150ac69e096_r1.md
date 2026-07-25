# Governance

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance**
Governance systems are vulnerable when voting power snapshots, proposal lifecycle checks, and parameter updates are not properly ordered or validated. A proposal's threshold and quorum must be captured at the same snapshot used for voting power (typically `block.timestamp - 1`) to prevent same-block supply inflation from lowering requirements after creation. Proposal IDs derived solely from calldata without a proposer nonce or `msg.sender` allow front-running: an attacker submits the same proposal, cancels it, and permanently blocks the legitimate proposer because the ID already exists. Vote weight must be fixed at snapshot; using `balanceOf` at execution time enables double-counting via flash loans or token transfers between endorsement and activation. State transitions (Pending → Active → Succeeded/Defeated → Queued → Executed/Expired) must be mutually exclusive and irreversible; missing checks let defeated proposals appear succeeded, allow reclaiming votes before a proposal activates, or let a new proposal activate before the previous one expires. Multisig voting modifiers that clear `hasVoted` flags before the external call (`_;`) enable reentrancy voting: a signer votes, the external call reenters, the flags are already cleared, and the signer votes again. Parameter setters (voting delay, period, quorum, full weight duration) must verify no active proposals exist; mid-vote changes alter weight calculations for in-flight proposals. Member management must prevent re-adding addresses previously removed by governance. Minting governance tokens without a supply cap inflates voting power and breaks threshold assumptions.

### Detection Checks

1. In `propose()`, verify `proposalThreshold()` and `quorum()` are computed using the same snapshot timestamp (`block.timestamp - 1` or `block.number - 1`) that `getVotes()` uses for the proposer's weight check; capturing them at `block.timestamp` after the weight check allows same-block totalSupply inflation to lower thresholds.
2. In `propose()`, verify `hashProposal()` includes `msg.sender` or a monotonically increasing nonce (e.g., `proposalCount`) so identical calldata from different proposers or re-proposals after cancellation produce distinct IDs; absence lets a front-runner cancel and permanently block the original proposer via `PROPOSAL_EXISTS`.
3. In `state()` or equivalent proposal status getter, verify the defeated condition uses `<=` for vote comparison (`forVotes <= againstVotes`) so a tie returns `Defeated`; using `<` lets a tied proposal incorrectly return `Succeeded`.
4. In `reclaimVotes()` or similar vote withdrawal, verify the function checks `block.timestamp < proposal.voteStart` (voting not yet started) rather than only `proposalId != activeProposal.proposalId`; the latter allows vote-and-reclaim in the same transaction before activation.
5. In `activateProposal()` or equivalent, verify the new proposal's activation timestamp is strictly after `activeProposal.activationTimestamp + GRACE_PERIOD` (or equivalent cooldown) and that `activeProposal.proposalId == 0` before overwriting; missing this lets a new proposal activate in the same block while voters reference the stale `activeProposal.proposalId`.
6. In `endorseProposal()` or vote-weight recording, verify the weight is snapshotted at endorsement time (e.g., via `getVotes(msg.sender, snapshot))` and not read from `balanceOf(msg.sender)` at execution; `balanceOf` allows tokens to be transferred and reused for multiple endorsements.
7. In multisig voting modifiers (`onlySigners` or similar), verify `hasVoted` flags and `voteCount` are cleared *after* the external call (`_;`) not before; clearing before `_` allows reentrancy through the external call to vote again in the same transaction.
8. In `executeProposal()` or equivalent, verify that on execution failure (insufficient votes, timelock not passed, external call revert) the `activeProposal` state is reset to zero/empty; leaving it set blocks future activations and locks votes.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GovernanceFlawed {
    struct Proposal {
        uint32 voteStart;
        uint32 voteEnd;
        uint32 proposalThreshold;
        uint32 quorumVotes;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
        bool canceled;
    }
    mapping(bytes32 => Proposal) public proposals;
    uint256 public proposalCount;
    
    function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas, string calldata description) external returns (bytes32) {
        uint256 threshold = proposalThreshold(); // uses block.timestamp totalSupply
        require(getVotes(msg.sender, block.timestamp - 1) >= threshold, "below threshold");
        bytes32 proposalId = keccak256(abi.encode(targets, values, calldatas, keccak256(bytes(description))));
        require(proposals[proposalId].voteStart == 0, "exists");
        proposals[proposalId] = Proposal({
            voteStart: uint32(block.timestamp + 1),
            voteEnd: uint32(block.timestamp + 86400),
            proposalThreshold: uint32(threshold),
            quorumVotes: uint32(quorum()), // uses block.timestamp totalSupply
            forVotes: 0,
            againstVotes: 0,
            executed: false,
            canceled: false
        });
        return proposalId;
    }
    
    function state(bytes32 proposalId) external view returns (uint8) {
        Proposal storage p = proposals[proposalId];
        if (p.voteStart == 0) revert("none");
        if (p.executed) return 5;
        if (p.canceled) return 4;
        if (block.timestamp < p.voteStart) return 0;
        if (block.timestamp < p.voteEnd) return 1;
        if (p.forVotes < p.againstVotes || p.forVotes < p.quorumVotes) return 2; // missing <=
        return 3;
    }
    
    function reclaimVotes(bytes32 proposalId) external {
        require(proposalId != activeProposalId, "active");
        // missing check: block.timestamp < proposals[proposalId].voteStart
        transferVotesBack(msg.sender);
    }
    
    function setVotingPeriod(uint256 newPeriod) external onlyOwner {
        votingPeriod = newPeriod; // no active proposal check
    }
    
    function issueVotesTo(address to, uint256 amount) external onlyRole(ADMIN_ROLE) {
        _mint(to, amount); // no supply cap
    }
}
```

Proposal thresholds captured at block.timestamp instead of snapshot timestamp; proposal ID lacks proposer nonce enabling front-run block; defeated check uses < instead of <=; reclaimVotes allows vote-and-reclaim before voteStart; setVotingPeriod lacks active proposal guard; issueVotesTo has no supply cap.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GovernanceFixed {
    struct Proposal {
        uint32 voteStart;
        uint32 voteEnd;
        uint32 proposalThreshold;
        uint32 quorumVotes;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
        bool canceled;
    }
    mapping(bytes32 => Proposal) public proposals;
    uint256 public proposalCount;
    bytes32 public activeProposalId;
    mapping(address => bool) public removedMembers;
    uint256 public constant MAX_SUPPLY = 1_000_000 * 1e18;
    
    function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas, string calldata description) external returns (bytes32) {
        uint32 snapshot = uint32(block.timestamp - 1);
        uint256 threshold = proposalThreshold(snapshot);
        uint256 q = quorum(snapshot);
        require(getVotes(msg.sender, snapshot) >= threshold, "below threshold");
        bytes32 proposalId = keccak256(abi.encode(msg.sender, proposalCount++, targets, values, calldatas, keccak256(bytes(description))));
        require(proposals[proposalId].voteStart == 0, "exists");
        proposals[proposalId] = Proposal({
            voteStart: uint32(block.timestamp + 1),
            voteEnd: uint32(block.timestamp + 86400),
            proposalThreshold: uint32(threshold),
            quorumVotes: uint32(q),
            forVotes: 0,
            againstVotes: 0,
            executed: false,
            canceled: false
        });
        return proposalId;
    }
    
    function state(bytes32 proposalId) external view returns (uint8) {
        Proposal storage p = proposals[proposalId];
        if (p.voteStart == 0) revert("none");
        if (p.executed) return 5;
        if (p.canceled) return 4;
        if (block.timestamp < p.voteStart) return 0;
        if (block.timestamp < p.voteEnd) return 1;
        if (p.forVotes <= p.againstVotes || p.forVotes < p.quorumVotes) return 2; // <= for tie
        return 3;
    }
    
    function reclaimVotes(bytes32 proposalId) external {
        require(block.timestamp < proposals[proposalId].voteStart, "voting started");
        transferVotesBack(msg.sender);
    }
    
    function setVotingPeriod(uint256 newPeriod) external onlyOwner {
        require(activeProposalId == 0 || block.timestamp > proposals[activeProposalId].voteEnd, "active proposal");
        votingPeriod = newPeriod;
    }
    
    function issueVotesTo(address to, uint256 amount) external onlyRole(GOVERNANCE_ROLE) {
        require(totalSupply() + amount <= MAX_SUPPLY, "cap");
        _mint(to, amount);
    }
    
    function addMember(address newMember) external onlyRole(MEMBER_ADDER_ROLE) {
        require(!removedMembers[newMember], "previously removed");
        _addMember(newMember);
    }
}
```

Threshold and quorum captured at snapshot (block.timestamp-1); proposal ID includes msg.sender and proposalCount; defeated check uses <=; reclaimVotes requires voting not started; setVotingPeriod checks no active proposal; issueVotesTo enforces MAX_SUPPLY; addMember blocks re-adding removed members.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
