# Governance

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance**
Governance systems are vulnerable when voting power, proposal lifecycle, and parameter changes lack proper validation and access controls. Common flaws include: (1) External functions that write critical governance state (quorum thresholds, proposal metadata, voting weights) without access control, allowing anyone to overwrite values after legitimate initialization. (2) Proposal ID generation that omits the proposer address or a nonce, making identical proposals collide and enabling front-running cancellations that permanently block re-submission. (3) Voting power snapshots taken at the wrong block (e.g., `block.timestamp - 1` instead of a fixed snapshot block) or using token balance instead of one-vote-per-holder, enabling flash-loan manipulation or multi-token inflation. (4) Threshold comparisons using strict inequality (`>`) instead of inclusive (`>=`), letting proposers cancel when voting power exactly equals the threshold. (5) Governance parameters (voting delay, period, quorum, full-weight duration) mutable mid-vote without checking for active proposals, altering the rules for in-flight decisions. (6) Multi-sig or voting modifiers that clear vote state before the external call (`_;`), permitting reentrancy to double-vote. (7) Missing zero-address validation on critical role assignments (vetoer, executor, token) during initialization. (8) Payable execution functions that validate `msg.value` but fail to forward it in the low-level call, causing value loss or logic mismatch.

### Detection Checks

1. External/public function writes to governance-critical storage (proposal thresholds, quorum supplies, voting weights, action approval/disapproval supplies) without `onlyRole`, `onlyOwner`, `onlyGovernance`, or equivalent access control modifier.
2. Proposal ID computed via `hashProposal(targets, values, calldatas, descriptionHash)` without incorporating `msg.sender`, a nonce, or a unique salt, causing identical proposals to share an ID and enabling permanent denial-of-service via front-run cancellation.
3. Voting power retrieved via `getVotes(account, block.timestamp - 1)` or similar current-block snapshot instead of a fixed snapshot block set at proposal creation (`voteStart`), allowing flash loans to manipulate weight.
4. Quorum or approval quantity function returns token balance (`policy.getPastQuantity`) instead of a fixed `1` per holder when the governance design specifies one-vote-per-holder, inflating voting power for multi-token holders.
5. Threshold comparison uses strict greater-than (`>`) instead of greater-than-or-equal (`>=`) when checking if proposer voting power exceeds proposal threshold for cancellation, permitting cancellation at exact equality.
6. Governance parameter setter (votingDelay, votingPeriod, proposalThreshold, quorumThreshold, fullWeightDuration) lacks a check for active proposals (`proposal.voteStart != 0 && block.timestamp < proposal.voteEnd`) before applying the new value.
7. Voting modifier or multi-sig check clears `voteCount` and `hasVoted` flags before the external call (`_;`), enabling reentrancy to bypass the already-voted check and vote multiple times in one transaction.
8. Initializer or setter for critical address roles (vetoer, executor, token, treasury, guard) omits `require(addr != address(0))` validation, allowing zero-address assignment that breaks authorization or fund flows.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableGovernance {
    struct Proposal {
        uint256 voteStart;
        uint256 voteEnd;
        uint256 proposalThreshold;
        address proposer;
        bool canceled;
    }
    mapping(bytes32 => Proposal) public proposals;
    uint256 public votingDelay = 1 days;
    uint256 public votingPeriod = 7 days;
    uint256 public proposalThreshold = 1000;
    
    function getVotes(address account, uint256 timestamp) external view returns (uint256) {
        // Vulnerable: uses current block snapshot, manipulable via flash loan
        return ERC20Votes(token).getPastVotes(account, timestamp);
    }
    
    function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas, string calldata description) external returns (bytes32) {
        require(getVotes(msg.sender, block.timestamp - 1) >= proposalThreshold, "BELOW_THRESHOLD");
        bytes32 proposalId = keccak256(abi.encode(targets, values, calldatas, keccak256(bytes(description))));
        // Vulnerable: no msg.sender/nonce in hash -> front-run cancel blocks re-proposal
        require(proposals[proposalId].voteStart == 0, "EXISTS");
        proposals[proposalId] = Proposal({
            voteStart: block.timestamp + votingDelay,
            voteEnd: block.timestamp + votingDelay + votingPeriod,
            proposalThreshold: proposalThreshold,
            proposer: msg.sender,
            canceled: false
        });
        return proposalId;
    }
    
    function cancel(bytes32 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.voteStart != 0, "NOT_EXIST");
        // Vulnerable: strict > allows cancel when votes == threshold
        if (msg.sender != p.proposer && getVotes(p.proposer, block.timestamp - 1) > p.proposalThreshold) {
            revert("INVALID_CANCEL");
        }
        p.canceled = true;
    }
    
    function setVotingPeriod(uint256 newPeriod) external {
        // Vulnerable: no check for active proposals
        votingPeriod = newPeriod;
    }
    
    function getApprovalQuantityAt(address holder) external view returns (uint256) {
        // Vulnerable: returns token balance instead of 1 per holder
        return token.balanceOf(holder);
    }
}
```

Multiple governance flaws: proposal ID lacks proposer/nonce enabling front-run DoS; voting power uses manipulable current-block snapshot; cancel uses strict > instead of >=; setVotingPeriod lacks active-proposal check; getApprovalQuantityAt returns token balance not 1-per-holder.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FixedGovernance {
    struct Proposal {
        uint256 voteStart;
        uint256 voteEnd;
        uint256 proposalThreshold;
        address proposer;
        bool canceled;
    }
    mapping(bytes32 => Proposal) public proposals;
    uint256 public votingDelay = 1 days;
    uint256 public votingPeriod = 7 days;
    uint256 public proposalThreshold = 1000;
    
    function getVotes(address account, uint256 snapshot) external view returns (uint256) {
        // Fixed: uses fixed snapshot block set at proposal creation
        return ERC20Votes(token).getPastVotes(account, snapshot);
    }
    
    function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas, string calldata description) external returns (bytes32) {
        uint256 snapshot = block.number + 1; // or use ERC20Votes clock
        require(getVotes(msg.sender, snapshot) >= proposalThreshold, "BELOW_THRESHOLD");
        bytes32 proposalId = keccak256(abi.encode(msg.sender, targets, values, calldatas, keccak256(bytes(description)), nonce++));
        // Fixed: includes msg.sender and nonce in hash
        require(proposals[proposalId].voteStart == 0, "EXISTS");
        proposals[proposalId] = Proposal({
            voteStart: block.timestamp + votingDelay,
            voteEnd: block.timestamp + votingDelay + votingPeriod,
            proposalThreshold: proposalThreshold,
            proposer: msg.sender,
            canceled: false
        });
        return proposalId;
    }
    
    function cancel(bytes32 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.voteStart != 0, "NOT_EXIST");
        // Fixed: >= allows cancel only when votes drop BELOW threshold
        if (msg.sender != p.proposer && getVotes(p.proposer, p.voteStart) >= p.proposalThreshold) {
            revert("INVALID_CANCEL");
        }
        p.canceled = true;
    }
    
    function setVotingPeriod(uint256 newPeriod) external onlyGovernance {
        // Fixed: rejects change if any proposal is active
        for (bytes32 id : activeProposalIds) {
            Proposal storage p = proposals[id];
            if (p.voteStart != 0 && block.timestamp < p.voteEnd) revert("ACTIVE_PROPOSAL");
        }
        votingPeriod = newPeriod;
    }
    
    function getApprovalQuantityAt(address holder) external view returns (uint256) {
        // Fixed: returns 1 per holder per governance spec
        return token.balanceOf(holder) > 0 ? 1 : 0;
    }
    
    uint256 nonce;
    bytes32[] activeProposalIds;
}
```

Fixes: proposal ID includes msg.sender+nonce; voting power uses fixed snapshot; cancel uses >= with snapshot at voteStart; setVotingPeriod checks active proposals; getApprovalQuantityAt returns 1 per holder.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
