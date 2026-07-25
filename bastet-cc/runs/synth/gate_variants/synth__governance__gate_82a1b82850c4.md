# Governance

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance**
Governance systems are vulnerable when voting power can be manipulated via flash loans or instant token transfers because snapshots are taken at proposal creation rather than at vote time, or when snapshots use the current block without a delay. Proposal IDs derived solely from calldata (targets, values, calldatas, description) without a nonce or proposer allow front-running: an attacker submits the same proposal, cancels it, and permanently blocks the legitimate proposer because the ID already exists. Threshold and quorum checks that use strict inequality (>) instead of >= permit cancellation or execution when voting power exactly equals the threshold. Member management that lacks a removal registry allows voted-out addresses to be re-added by privileged roles. Parameter setters (voting delay, period, threshold, quorum, fullWeightDuration) that do not verify the absence of active proposals enable mid-vote rule changes that alter outcomes. External functions writing critical state (e.g., actionApprovalSupply, actionDisapprovalSupply) without access control let anyone overwrite quorum denominators. Multi-sig voting modifiers that clear vote state before the external call (_;) enable reentrancy voting duplication. Executor calls that omit {value: ...} despite payable validation cause silent ether loss. Missing zero-address validation on initialization parameters (vetoer, token, treasury) can brick governance.

### Detection Checks

1. Snapshot for voting power is taken at block.timestamp or block.number without a votingDelay, enabling flash-loan manipulation.
2. Proposal ID is computed as hash(targets, values, calldatas, descriptionHash) without msg.sender or a nonce, allowing front-run cancellation and permanent blocking.
3. Threshold or quorum comparisons use > instead of >= (or < instead of <=) for proposer voting power checks in cancel/propose/execute.
4. addMember / removeMember functions lack a removed-members registry or timestamp check, permitting re-addition of ousted addresses.
5. Parameter setters (setVotingDelay, setVotingPeriod, setProposalThreshold, setQuorumThreshold, setFullWeightDuration) do not revert when active proposals exist (proposal.voteStart != 0 && block.timestamp < proposal.voteEnd).
6. External/public functions writing governance-critical storage (actionApprovalSupply, actionDisapprovalSupply, quorumVotes, proposalThreshold) have no onlyRole/onlyOwner/onlyGovernance modifier.
7. Multi-sig voting modifier resets voteCount and hasVoted before the external call (_;), enabling reentrant double-voting.
8. executeAction or similar executor call is payable and validates msg.value == actionInfo.value but calls executor.execute(target, value, ...) without {value: actionInfo.value}.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FlawedGovernor {
    bytes32[] public proposals;
    mapping(bytes32 => uint256) public proposalThreshold;
    mapping(address => uint256) public votingPower;
    address public governance;
    uint256 public votingDelay = 1 days;
    uint256 public fullWeightDuration = 3 days;
    mapping(address => bool) public removedMembers;

    function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas, string calldata desc) external returns (bytes32) {
        bytes32 id = keccak256(abi.encode(targets, values, calldatas, keccak256(bytes(desc))));
        if (proposalThreshold[id] != 0) revert(); // PROPOSAL_EXISTS
        proposalThreshold[id] = votingPower[msg.sender]; // snapshot now, no delay
        proposals.push(id);
        return id;
    }

    function cancel(bytes32 id) external {
        if (votingPower[proposals[0]] > proposalThreshold[id]) revert(); // strict >
        delete proposalThreshold[id];
    }

    function addMember(address member) external {
        // no check against removedMembers[member]
        votingPower[member] = 1;
    }

    function setFullWeightDuration(uint256 d) external {
        if (msg.sender != governance) revert();
        fullWeightDuration = d; // no active proposal check
    }

    function executeAction(uint256 value, address target, bytes calldata data) external payable {
        if (msg.value != value) revert();
        (bool ok, ) = target.call{value: 0}(data); // missing {value: value}
        require(ok);
    }

    modifier onlySigners() {
        // ... vote counting ...
        voteCount = 0; // reset before external call
        _;
    }
}
```

Snapshot taken instantly, proposal ID lacks nonce, strict > threshold, no removed-member registry, parameter setter ignores active proposals, executor drops msg.value, modifier clears votes before external call.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FixedGovernor {
    bytes32[] public proposals;
    mapping(bytes32 => uint256) public proposalThreshold;
    mapping(address => uint256) public votingPower;
    address public governance;
    uint256 public votingDelay = 1 days;
    uint256 public fullWeightDuration = 3 days;
    mapping(address => bool) public removedMembers;
    uint256 public proposalNonce;

    function propose(address[] calldata targets, uint256[] calldata values, bytes[] calldata calldatas, string calldata desc) external returns (bytes32) {
        bytes32 id = keccak256(abi.encode(targets, values, calldatas, keccak256(bytes(desc)), msg.sender, proposalNonce++));
        if (proposalThreshold[id] != 0) revert();
        proposalThreshold[id] = votingPower[msg.sender]; // snapshot at creation; votingDelay enforced in vote()
        proposals.push(id);
        return id;
    }

    function cancel(bytes32 id) external {
        if (votingPower[proposals[0]] >= proposalThreshold[id]) revert(); // >= prevents cancel at exact threshold
        delete proposalThreshold[id];
    }

    function addMember(address member) external {
        if (removedMembers[member]) revert();
        votingPower[member] = 1;
    }

    function setFullWeightDuration(uint256 d) external {
        if (msg.sender != governance) revert();
        // revert if any active proposal
        for (bytes32 pid : proposals) {
            if (proposalThreshold[pid] != 0 && block.timestamp < pid) revert(); // simplified active check
        }
        fullWeightDuration = d;
    }

    function executeAction(uint256 value, address target, bytes calldata data) external payable {
        if (msg.value != value) revert();
        (bool ok, ) = target.call{value: value}(data); // forward value
        require(ok);
    }

    modifier onlySigners() {
        // ... vote counting ...
        _;
        voteCount = 0; // reset after external call
    }
}
```

Nonce in proposal ID, >= threshold check, removed-member registry, active-proposal guard on parameter change, value forwarded in call, vote state cleared after external call.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
