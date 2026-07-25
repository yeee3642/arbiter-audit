---
id: synth__governance
name: "Governance"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Governance"]
routing_hints: ["propose", "castVote", "quorum", "timelock", "votingPower", "votingPeriod", "executeAction", "votingDelay", "proposal", "activeProposal", "addMember", "setMinimumBidIncrement", "onlySigners"]
required_hints: []
prompt_chars: 5469
synthesized: true
gated: false
synth_provenance: {"train_findings": ["406", "234", "182", "330", "185", "407", "217", "188", "294", "212"], "localization_rate": 0.826, "mode": "s2", "hint_candidates": 30, "hints_rejected": 27, "hint_coverage": 0.842, "single_repo_hints": false, "hint_fallback": false, "loro": {"hit": 0.8, "fp": 0.0, "folds": 5, "repaired": true}}
---

# Governance

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance**
Governance systems are vulnerable when voting power can be manipulated through flash loans or instant token acquisition, when proposal state transitions lack proper boundary checks, when critical parameters can be changed mid-vote, when member management allows re-addition of removed addresses, when external calls are made before state updates enabling reentrancy, when threshold calculations use incorrect comparison operators, when activation mechanisms lack spam protection, when value forwarding is missing in payable executions, when initialization omits zero-address validation, and when minting or parameter setting functions lack upper bounds. These flaws allow attackers to pass malicious proposals, block legitimate governance actions, drain treasury funds, or permanently break the governance process.

### Detection Checks

1. Check if voting power snapshots are taken at proposal creation rather than at vote time, enabling flash loan attacks
2. Check if proposal state transitions use strict inequality (<) instead of <= for defeat conditions, allowing tied votes to succeed
3. Check if vote reclamation functions only block the currently active proposal but allow reclaiming votes cast in the same transaction before activation
4. Check if member addition functions lack checks against previously removed addresses, enabling re-addition of voted-out members
5. Check if proposal activation lacks rate limiting or spam protection, allowing dummy proposals to block legitimate ones via grace periods
6. Check if payable execute functions validate msg.value but fail to forward it in the external call
7. Check if initialization functions omit zero-address validation for critical roles like vetoer or token
8. Check if minting functions for governance tokens lack supply caps or upper bounds

### Examples

#### Example 1: Incorrect Example

```solidity
contract Governance {
    mapping(uint256 => uint256) public forVotes;
    mapping(uint256 => uint256) public againstVotes;
    mapping(uint256 => uint256) public quorumVotes;
    mapping(uint256 => bool) public executed;
    uint256 public votingPeriod;
    uint256 public voteStart;
    
    function state(uint256 proposalId) public view returns (uint8) {
        if (executed[proposalId]) return 3; // Executed
        if (block.timestamp < voteStart) return 0; // Pending
        if (block.timestamp < voteStart + votingPeriod) return 1; // Active
        if (forVotes[proposalId] < againstVotes[proposalId] || forVotes[proposalId] < quorumVotes[proposalId]) return 2; // Defeated
        return 4; // Succeeded
    }
    
    function executeAction(uint256 proposalId, address target, uint256 value, bytes calldata data) external payable {
        require(msg.value == value);
        (bool success, ) = target.call{value: 0}(data); // Missing value forwarding
        require(success);
    }
    
    function addMember(address member) external {
        members[member] = true; // No check for previously removed
    }
    
    function setQuorumThreshold(uint256 newThreshold) external {
        quorumThreshold = newThreshold; // No upper bound check
    }
}
```

Multiple governance flaws: defeat check uses < instead of <= allowing tied votes to pass, executeAction validates msg.value but forwards 0, addMember allows re-adding removed members, setQuorumThreshold lacks bounds validation.

#### Example 2: Correct Example

```solidity
contract Governance {
    mapping(uint256 => uint256) public forVotes;
    mapping(uint256 => uint256) public againstVotes;
    mapping(uint256 => uint256) public quorumVotes;
    mapping(uint256 => bool) public executed;
    mapping(address => bool) public removedMembers;
    uint256 public votingPeriod;
    uint256 public voteStart;
    uint256 public constant MAX_QUORUM = 10000; // 100%
    
    function state(uint256 proposalId) public view returns (uint8) {
        if (executed[proposalId]) return 3;
        if (block.timestamp < voteStart) return 0;
        if (block.timestamp < voteStart + votingPeriod) return 1;
        if (forVotes[proposalId] <= againstVotes[proposalId] || forVotes[proposalId] < quorumVotes[proposalId]) return 2; // <= for defeat
        return 4;
    }
    
    function executeAction(uint256 proposalId, address target, uint256 value, bytes calldata data) external payable {
        require(msg.value == value);
        (bool success, ) = target.call{value: value}(data); // Forward value
        require(success);
    }
    
    function addMember(address member) external {
        require(!removedMembers[member], "Previously removed");
        members[member] = true;
    }
    
    function setQuorumThreshold(uint256 newThreshold) external {
        require(newThreshold <= MAX_QUORUM, "Exceeds max");
        quorumThreshold = newThreshold;
    }
}
```

Fixed defeat condition with <=, forwards msg.value in external call, blocks re-addition of removed members, enforces upper bound on quorum threshold.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
