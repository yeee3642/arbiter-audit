# Governance

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance**
Governance systems are vulnerable when voting power snapshots, proposal lifecycle checks, and parameter updates lack proper validation or timing constraints. Flash loans or same-block token acquisition can inflate voting weight if snapshots use the current block instead of a prior block. Proposal IDs derived solely from calldata without a nonce or sender allow front-running and permanent blocking of legitimate proposals. Threshold and quorum values captured at proposal creation must align with the voting snapshot timestamp; using current totalSupply for thresholds while voting power is measured at snapshot-1 enables manipulation. State transitions (Pending, Active, Succeeded, Defeated, Queued, Executed, Expired, Canceled, Vetoed) must use correct comparison operators; off-by-one errors such as `<` instead of `<=` for defeat checks let tied proposals incorrectly succeed. Vote reclamation must bind to a specific proposal ID and prevent reclaiming before the proposal becomes active, otherwise users can vote and reclaim in the same transaction. Member management must track removal history to prevent re-addition of voted-out addresses. Parameter setters (e.g., voting delay, period, quorum, weight duration) must verify no active proposals exist before applying changes. Multi-signature voting modifiers must not reset vote state before the external call, or reentrancy can allow double-voting. Minting of governance tokens must enforce a supply cap to prevent arbitrary inflation of voting power.

### Detection Checks

1. Verify that proposal creation snapshots voting power at `block.timestamp - 1` (or a prior block) and that `proposalThreshold` and `quorumVotes` are derived from the same snapshot, not current `totalSupply`.
2. Ensure `proposalId` computation includes `msg.sender` and a nonce or `block.number` so identical calldata from different proposers or at different times yields unique IDs.
3. Check that the `Defeated` state transition uses `<=` for `forVotes <= againstVotes` (or the documented tie-break rule) and that quorum comparison matches specification.
4. Confirm `reclaimVotes` (or similar) rejects calls when `proposalId` equals the currently active proposal AND when the proposal's `voteStart` is in the future, preventing same-transaction vote-and-reclaim.
5. Validate that `addMember` (or role assignment) checks a `removedMembers` mapping or equivalent history to block re-addition of previously expelled addresses.
6. Ensure parameter setters (`setVotingDelay`, `setVotingPeriod`, `setQuorum`, `setFullWeightDuration`, etc.) revert if any proposal is in `Active` or `Pending` state.
7. Inspect multi-sig or committee voting modifiers: vote counting state (`voteCount`, `hasVoted`) must be cleared only after the external call (`_;`) succeeds, not before, to prevent reentrancy double-voting.
8. Verify governance token minting functions (`issueVotesTo`, `mint`) enforce a hard `maxSupply` cap or require DAO approval for increases.

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
    uint256 public votingDelay = 1 days;
    uint256 public votingPeriod = 7 days;
    IERC20Votes public token;
    
    function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas, string calldata description) external returns (bytes32) {
        bytes32 proposalId = keccak256(abi.encode(targets, values, calldatas, keccak256(bytes(description))));
        if (proposals[proposalId].voteStart != 0) revert();
        // @audit uses current totalSupply for threshold/quorum, but voting power measured at snapshot-1
        proposals[proposalId] = Proposal({
            voteStart: uint32(block.timestamp + votingDelay),
            voteEnd: uint32(block.timestamp + votingDelay + votingPeriod),
            proposalThreshold: uint32(token.getPastTotalSupply(block.timestamp)),
            quorumVotes: uint32(token.getPastTotalSupply(block.timestamp) / 10),
            forVotes: 0,
            againstVotes: 0,
            executed: false,
            canceled: false
        });
        return proposalId;
    }
    
    function state(bytes32 proposalId) external view returns (uint8) {
        Proposal storage p = proposals[proposalId];
        if (p.voteStart == 0) revert();
        if (block.timestamp < p.voteStart) return 0; // Pending
        if (block.timestamp < p.voteEnd) return 1;   // Active
        // @audit uses < instead of <= for defeat check
        if (p.forVotes < p.againstVotes || p.forVotes < p.quorumVotes) return 2; // Defeated
        return 3; // Succeeded
    }
    
    function setVotingDelay(uint256 newDelay) external {
        votingDelay = newDelay; // @audit no check for active proposals
    }
}
```

Proposal creation uses current totalSupply for threshold/quorum while voting power is snapshotted at voteStart-1; defeat check uses `<` instead of `<=`; setVotingDelay lacks active-proposal guard.

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
    uint256 public votingDelay = 1 days;
    uint256 public votingPeriod = 7 days;
    IERC20Votes public token;
    uint256 public constant MAX_SUPPLY = 1_000_000 * 1e18;
    mapping(address => bool) public removedMembers;
    
    function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas, string calldata description) external returns (bytes32) {
        bytes32 proposalId = keccak256(abi.encode(msg.sender, block.number, targets, values, calldatas, keccak256(bytes(description))));
        if (proposals[proposalId].voteStart != 0) revert();
        uint32 snap = uint32(block.timestamp - 1);
        uint256 totalSupplyAtSnap = token.getPastTotalSupply(snap);
        proposals[proposalId] = Proposal({
            voteStart: uint32(block.timestamp + votingDelay),
            voteEnd: uint32(block.timestamp + votingDelay + votingPeriod),
            proposalThreshold: uint32(totalSupplyAtSnap / 100),
            quorumVotes: uint32(totalSupplyAtSnap / 10),
            forVotes: 0,
            againstVotes: 0,
            executed: false,
            canceled: false
        });
        return proposalId;
    }
    
    function state(bytes32 proposalId) external view returns (uint8) {
        Proposal storage p = proposals[proposalId];
        if (p.voteStart == 0) revert();
        if (block.timestamp < p.voteStart) return 0;
        if (block.timestamp < p.voteEnd) return 1;
        // @audit uses <= for tie-break
        if (p.forVotes <= p.againstVotes || p.forVotes < p.quorumVotes) return 2;
        return 3;
    }
    
    function setVotingDelay(uint256 newDelay) external {
        for (bytes32 id : activeProposalIds) {
            if (block.timestamp >= proposals[id].voteStart && block.timestamp < proposals[id].voteEnd) revert();
        }
        votingDelay = newDelay;
    }
    
    function addMember(address member) external {
        if (removedMembers[member]) revert();
        // add logic
    }
}
```

Proposal ID includes sender and block.number; threshold/quorum use snapshot at block.timestamp-1; defeat check uses `<=`; setVotingDelay blocks changes during active voting; addMember checks removal history.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
