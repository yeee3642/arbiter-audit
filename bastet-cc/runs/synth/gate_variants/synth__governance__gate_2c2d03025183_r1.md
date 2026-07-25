# Governance

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance**
Governance vulnerabilities arise when voting power, proposal lifecycle, or parameter management can be manipulated. Common flaws include: (1) missing access control on functions that record quorum thresholds or proposal metadata, allowing anyone to overwrite critical state; (2) snapshotting voting power at vote/endorse time without preventing double-counting via token transfers or flash loans; (3) allowing vote reclamation for proposals that become active in the same transaction, enabling vote-and-reclaim cycles; (4) changing governance parameters (e.g., vote weight duration, quorum thresholds) mid-vote without checking for active proposals; (5) activating proposals based solely on endorsement thresholds without spam protection or rate limiting, enabling denial-of-service via dummy proposals; (6) executing actions without forwarding `msg.value` despite validating it, causing value loss; (7) returning raw token balances as voting weight where the policy expects one-vote-per-holder, breaking quorum calculations; (8) using strict inequality (`>`) instead of `>=` when checking proposer voting power against cancellation thresholds, allowing cancellation at exact equality; (9) accepting unbounded percentage values that overflow or break mechanics when cast to smaller types; (10) allowing re-addition of previously removed members without checking removal history; (11) failing to reset active proposal state on failed execution, permanently blocking new proposals. Auditors must trace state mutations across the proposal lifecycle (creation, endorsement, activation, voting, execution, cancellation) and verify that each transition enforces proper authorization, snapshot integrity, parameter immutability during active periods, and correct arithmetic comparisons.

### Detection Checks

1. External/public function writes to proposal-critical storage (quorum thresholds, approval/disapproval supplies, activation timestamps) without access control (onlyRole, onlyOwner, onlyGovernance) or caller validation against proposal submitter.
2. Function snapshots voting power via `balanceOf`/`getVotes` at vote/endorse time but does not prevent the same tokens from being transferred and reused for another vote/endorse on the same proposal (missing snapshot lock, double-counting check, or `userVotesForProposal`/`userEndorsementsForProposal` zero-check before adding).
3. Vote reclamation function allows reclaiming for a proposalId that is not currently active but does not prevent reclaiming votes cast in the same transaction before the proposal becomes active (missing check that `proposalId_` was never active or that voting period has fully elapsed).
4. Parameter setter for governance-critical values (vote weight duration, quorum threshold, execution timelock, grace period) lacks a check that no proposal is currently active/queued/executing before applying the change.
5. Proposal activation function checks endorsement threshold against total supply but has no rate limiting, spam history tracking, or minimum voting power requirement for the activator, enabling repeated dummy proposal activation that blocks legitimate proposals via grace period lockout.
6. Payable execution function validates `msg.value == actionInfo.value` but calls low-level executor without `{value: actionInfo.value}`, causing ether to remain in the contract instead of being forwarded.
7. Voting weight getter returns raw token quantity (`getPastQuantity`, `balanceOf`) where the governance policy defines weight as one-vote-per-holder (should return 1 or `type(uint128).max` for any non-zero holding, not the token amount).
8. Proposal cancellation uses strict inequality (`getVotes(proposer) > proposalThreshold`) instead of `>=` when checking if proposer voting power has dropped below threshold, allowing cancellation when power equals threshold.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVotes {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
}

contract VulnerableGovernance {
    IVotes public VOTES;
    uint256 public activeProposalId;
    uint256 public activationTimestamp;
    uint256 public constant GRACE_PERIOD = 1 days;
    uint256 public constant ENDORSEMENT_THRESHOLD = 5; // 5%
    mapping(uint256 => uint256) public totalEndorsements;
    mapping(uint256 => mapping(address => uint256)) public userEndorsements;
    mapping(uint256 => mapping(address => uint256)) public userVotes;
    mapping(uint256 => uint256) public yesVotes;
    mapping(uint256 => uint256) public noVotes;
    mapping(uint256 => bool) public proposalActivated;
    uint256 public fullWeightDuration = 3 days;
    
    function endorseProposal(uint256 proposalId) external {
        uint256 weight = VOTES.balanceOf(msg.sender); // @audit no double-counting prevention
        totalEndorsements[proposalId] += weight;
        userEndorsements[proposalId][msg.sender] = weight;
    }
    
    function activateProposal(uint256 proposalId) external {
        require((totalEndorsements[proposalId] * 100) >= VOTES.totalSupply() * ENDORSEMENT_THRESHOLD);
        require(block.timestamp >= activationTimestamp + GRACE_PERIOD); // @audit no spam/rate limit
        activeProposalId = proposalId;
        activationTimestamp = block.timestamp;
        proposalActivated[proposalId] = true;
    }
    
    function vote(bool for_) external {
        require(activeProposalId != 0);
        uint256 weight = VOTES.balanceOf(msg.sender); // @audit snapshot without lock
        if (for_) yesVotes[activeProposalId] += weight;
        else noVotes[activeProposalId] += weight;
        userVotes[activeProposalId][msg.sender] = weight;
        VOTES.transferFrom(msg.sender, address(this), weight);
    }
    
    function reclaimVotes(uint256 proposalId) external {
        uint256 weight = userVotes[proposalId][msg.sender];
        require(weight > 0);
        require(proposalId != activeProposalId); // @audit allows reclaim if proposal becomes active later in same tx
        VOTES.transferFrom(address(this), msg.sender, weight);
    }
    
    function setFullWeightDuration(uint256 newDuration) external {
        fullWeightDuration = newDuration; // @audit no active proposal check
    }
    
    function executeProposal() external payable {
        uint256 net = yesVotes[activeProposalId] - noVotes[activeProposalId];
        if (net * 100 < VOTES.totalSupply() * 50) revert();
        // @audit missing {value: msg.value} on low-level call
        (bool success,) = payable(msg.sender).call{value: msg.value}("");
        if (!success) revert();
        // @audit activeProposalId not reset on failure
    }
}
```

Multiple governance flaws: endorsement double-counts via balanceOf, activation lacks spam protection, vote snapshots without lock, reclaim allows same-tx vote-and-reclaim, parameter setter ignores active proposals, execution forwards value incorrectly and fails to reset active proposal on failure.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVotes {
    function balanceOf(address) external view returns (uint256);
    function transferFrom(address, address, uint256) external returns (bool);
    function getPastVotes(address, uint256) external view returns (uint256);
}

contract FixedGovernance {
    IVotes public VOTES;
    uint256 public activeProposalId;
    uint256 public activationTimestamp;
    uint256 public constant GRACE_PERIOD = 1 days;
    uint256 public constant ENDORSEMENT_THRESHOLD = 5;
    uint256 public lastActivationTimestamp;
    mapping(uint256 => uint256) public totalEndorsements;
    mapping(uint256 => mapping(address => uint256)) public userEndorsements;
    mapping(uint256 => mapping(address => uint256)) public userVotes;
    mapping(uint256 => uint256) public yesVotes;
    mapping(uint256 => uint256) public noVotes;
    mapping(uint256 => bool) public proposalActivated;
    mapping(uint256 => uint256) public proposalSnapshotBlock;
    uint256 public fullWeightDuration = 3 days;
    
    function endorseProposal(uint256 proposalId) external {
        uint256 weight = VOTES.getPastVotes(msg.sender, proposalSnapshotBlock[proposalId]);
        uint256 prev = userEndorsements[proposalId][msg.sender];
        totalEndorsements[proposalId] += weight - prev;
        userEndorsements[proposalId][msg.sender] = weight;
    }
    
    function activateProposal(uint256 proposalId) external {
        require((totalEndorsements[proposalId] * 100) >= VOTES.totalSupply() * ENDORSEMENT_THRESHOLD);
        require(block.timestamp >= activationTimestamp + GRACE_PERIOD);
        require(block.timestamp >= lastActivationTimestamp + 1 hours); // rate limit
        proposalSnapshotBlock[proposalId] = block.number;
        activeProposalId = proposalId;
        activationTimestamp = block.timestamp;
        lastActivationTimestamp = block.timestamp;
        proposalActivated[proposalId] = true;
    }
    
    function vote(bool for_) external {
        require(activeProposalId != 0);
        require(userVotes[activeProposalId][msg.sender] == 0); // prevent double vote
        uint256 weight = VOTES.getPastVotes(msg.sender, proposalSnapshotBlock[activeProposalId]);
        if (for_) yesVotes[activeProposalId] += weight;
        else noVotes[activeProposalId] += weight;
        userVotes[activeProposalId][msg.sender] = weight;
        VOTES.transferFrom(msg.sender, address(this), weight);
    }
    
    function reclaimVotes(uint256 proposalId) external {
        uint256 weight = userVotes[proposalId][msg.sender];
        require(weight > 0);
        require(proposalId != activeProposalId);
        require(!proposalActivated[proposalId] || block.timestamp > activationTimestamp + 7 days); // ensure voting period ended
        VOTES.transferFrom(address(this), msg.sender, weight);
    }
    
    function setFullWeightDuration(uint256 newDuration) external {
        require(activeProposalId == 0, "active proposal exists");
        fullWeightDuration = newDuration;
    }
    
    function executeProposal() external payable {
        uint256 net = yesVotes[activeProposalId] - noVotes[activeProposalId];
        if (net * 100 < VOTES.totalSupply() * 50) revert();
        (bool success,) = payable(msg.sender).call{value: msg.value}("");
        if (!success) revert();
        activeProposalId = 0; // always reset
        activationTimestamp = 0;
    }
}
```

Fixes: endorsement uses snapshot block and subtracts previous weight; activation adds rate limiting and records snapshot block; vote uses snapshot and prevents double-voting; reclaim ensures voting period ended; setter checks no active proposal; execution resets state on success.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
