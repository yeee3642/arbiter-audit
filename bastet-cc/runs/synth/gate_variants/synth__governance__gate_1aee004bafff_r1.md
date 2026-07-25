# Governance

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance**
Governance vulnerabilities arise when voting power, proposal lifecycle, or parameter management can be manipulated. Common patterns include: (1) using live token balances (balanceOf) instead of snapshots, enabling flash-loan or same-transaction double-voting; (2) missing access control on functions that write quorum thresholds, proposal metadata, or role supplies, allowing anyone to overwrite critical state; (3) resetting vote counters or voter flags before an external call in a modifier, permitting reentrancy to vote again; (4) failing to reset global governance state (e.g., activeProposal) when a proposal fails execution, permanently blocking new proposals; (5) snapshotting thresholds against current totalSupply while voting power uses a past block, letting same-block supply inflation lower the effective threshold; (6) missing zero-address validation on initializer parameters like vetoer or token; (7) accepting unbounded percentage or basis-point values without range checks; (8) executing payable calls without forwarding msg.value. Auditors should trace how voting weight is sourced, when state is mutated relative to external calls, and whether thresholds are immutable after proposal creation.

### Detection Checks

1. Snapshot usage: voting weight must be read from a past block (getVotes(account, snapshot)) or a dedicated checkpoint, never from balanceOf(msg.sender) or totalSupply() at execution time.
2. Access control on state writers: any external/public function that writes quorum supplies (actionApprovalSupply, actionDisapprovalSupply), proposal thresholds, or role configurations must be restricted to a governance role or the proposal creator via onlyOwner/onlyRole/onlyProposer.
3. Reentrancy-safe vote accounting: modifiers or functions that increment vote counts and clear voter flags must do so after the external call (_;), not before, or use a reentrancy guard; clearing flags before _; allows the same signer to vote again if the call reenters.
4. Active proposal cleanup on failure: executeProposal (or equivalent) must reset the global activeProposal tracker to zero in all revert/early-return paths, not only on success, otherwise a failed proposal blocks future activations.
5. Threshold snapshot consistency: propose() must snapshot proposalThreshold and quorum using the same block (typically block.timestamp - 1) that voting power is measured against; using current block.timestamp for thresholds while voting uses past block enables manipulation.
6. Zero-address validation in initializers: all address parameters (_vetoer, _token, _treasury, _executor, etc.) must be checked against address(0) before assignment.
7. Bounded parameter setters: setters for percentages, basis points, or time delays must validate the input against a sensible min/max (e.g., 0-100 for percentages, non-zero for delays) before casting or storing.
8. Payable execution forwarding: if executeAction (or similar) is payable and validates msg.value == actionInfo.value, the low-level call must forward that value via {value: actionInfo.value} instead of passing zero.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableGovernance {
    ERC20Votes public VOTES;
    mapping(uint256 => mapping(address => uint256)) public userEndorsements;
    mapping(uint256 => uint256) public totalEndorsements;
    mapping(uint256 => uint256) public actionApprovalSupply;
    uint256 public activeProposalId;
    address public vetoer;
    
    function endorseProposal(uint256 proposalId) external {
        uint256 weight = VOTES.balanceOf(msg.sender); // live balance, no snapshot
        totalEndorsements[proposalId] -= userEndorsements[proposalId][msg.sender];
        userEndorsements[proposalId][msg.sender] = weight;
        totalEndorsements[proposalId] += weight;
    }
    
    function setQuorumSupply(uint256 proposalId, uint256 supply) external {
        actionApprovalSupply[proposalId] = supply; // no access control
    }
    
    function initialize(address _vetoer) external {
        vetoer = _vetoer; // missing address(0) check
    }
    
    function executeProposal() external {
        if (totalEndorsements[activeProposalId] < 100) revert();
        // missing: activeProposalId = 0 on failure path
    }
}
```

Live balanceOf enables double-endorsement via token transfer; setQuorumSupply lacks access control; initialize misses zero-address check; executeProposal doesn't reset activeProposalId on failure.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FixedGovernance {
    ERC20Votes public VOTES;
    mapping(uint256 => mapping(address => uint256)) public userEndorsements;
    mapping(uint256 => uint256) public totalEndorsements;
    mapping(uint256 => uint256) public actionApprovalSupply;
    uint256 public activeProposalId;
    address public vetoer;
    uint256 public constant ENDORSEMENT_SNAPSHOT_OFFSET = 1;
    
    function endorseProposal(uint256 proposalId) external {
        uint256 weight = VOTES.getPastVotes(msg.sender, block.number - ENDORSEMENT_SNAPSHOT_OFFSET);
        totalEndorsements[proposalId] -= userEndorsements[proposalId][msg.sender];
        userEndorsements[proposalId][msg.sender] = weight;
        totalEndorsements[proposalId] += weight;
    }
    
    function setQuorumSupply(uint256 proposalId, uint256 supply) external onlyRole(GOVERNANCE_ROLE) {
        actionApprovalSupply[proposalId] = supply;
    }
    
    function initialize(address _vetoer) external {
        if (_vetoer == address(0)) revert ZeroAddress();
        vetoer = _vetoer;
    }
    
    function executeProposal() external {
        if (totalEndorsements[activeProposalId] < 100) {
            activeProposalId = 0;
            revert();
        }
        activeProposalId = 0;
    }
}
```

Uses getPastVotes with a fixed snapshot offset; restricts setQuorumSupply to GOVERNANCE_ROLE; validates _vetoer != address(0); resets activeProposalId on both success and failure.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
