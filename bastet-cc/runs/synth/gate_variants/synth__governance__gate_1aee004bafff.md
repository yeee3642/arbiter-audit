# Governance

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Governance**
Governance systems are vulnerable when voting power can be manipulated via flash loans or instant token acquisition because snapshots use current balances instead of historical checkpoints. Proposal activation lacks rate limiting, allowing spam proposals to block legitimate ones through grace period lockouts. Threshold and quorum calculations often use totalSupply at proposal creation while voting power is measured at a prior block, enabling same-block supply inflation to lower requirements. Vote counting resets before external calls, permitting reentrancy to double-count signatures. Endorsement weights are recorded at call time without preventing token transfer and re-endorsement, causing double-counting. Parameter setters miss zero-address and bounds validation, and execution paths omit msg.value forwarding despite payable checks.

### Detection Checks

1. Snapshot voting power at proposal creation using historical checkpoints (e.g., getVotes(account, block.number - 1)) rather than current balanceOf to prevent flash loan manipulation.
2. Enforce a minimum delay or cooldown between proposal activations and validate proposer reputation or stake to prevent spam proposals from monopolizing the active slot via GRACE_PERIOD.
3. Calculate proposalThreshold and quorum using totalSupply at the same historical block used for voting power (snapshot - 1) so same-block minting cannot lower thresholds after proposal creation.
4. Reset vote counts and hasVoted flags only after the external call (_;) completes, not before, to prevent reentrancy from allowing signers to vote twice in the same transaction.
5. Record endorsement weight once per proposal per user at first endorsement and reject subsequent calls, or snapshot token balances at proposal activation to prevent transfer-and-re-endorse double counting.
6. Validate all address parameters (vetoer, treasury, token, guard) against address(0) in initialize and setter functions before assignment.
7. Validate percentage and basis-point parameters (e.g., minBidIncrement, proposalThresholdBps, quorumThresholdBps) against explicit upper bounds (100 or 10000) before casting to uint8/uint16.
8. Forward msg.value in low-level calls when the function is payable and validates msg.value == actionInfo.value (use {value: actionInfo.value} on executor.execute).

### Examples

#### Example 1: Incorrect Example

```solidity
function propose(address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) external returns (bytes32) {
    uint256 threshold = proposalThreshold(); // uses current totalSupply
    if (getVotes(msg.sender, block.timestamp - 1) < threshold) revert BELOW_PROPOSAL_THRESHOLD();
    uint256 snapshot = block.timestamp + votingDelay;
    uint256 deadline = snapshot + votingPeriod;
    proposals[proposalId] = Proposal({
        voteStart: uint32(snapshot),
        voteEnd: uint32(deadline),
        proposalThreshold: uint32(threshold),
        quorumVotes: uint32(quorum()), // uses current totalSupply
        proposer: msg.sender,
        timeCreated: uint32(block.timestamp)
    });
    return proposalId;
}

function endorseProposal(uint256 proposalId) external {
    uint256 userVotes = VOTES.balanceOf(msg.sender); // current balance, no snapshot
    uint256 previous = userEndorsementsForProposal[proposalId][msg.sender];
    totalEndorsementsForProposal[proposalId] -= previous;
    userEndorsementsForProposal[proposalId][msg.sender] = userVotes;
    totalEndorsementsForProposal[proposalId] += userVotes;
}

modifier onlySigners() {
    if (!signers.isSigner[msg.sender]) revert NotSigner();
    bytes32 topic = keccak256(msg.data);
    Voting storage voting = votingPerTopic[signerEpoch][topic];
    if (voting.hasVoted[msg.sender]) revert AlreadyVoted();
    voting.hasVoted[msg.sender] = true;
    uint256 voteCount = voting.voteCount + 1;
    if (voteCount < signers.threshold) {
        voting.voteCount = voteCount;
        return;
    }
    voting.voteCount = 0; // reset BEFORE external call
    for (uint256 i = 0; i < signers.accounts.length; i++) {
        voting.hasVoted[signers.accounts[i]] = false;
    }
    _;
}

function executeAction(ActionInfo calldata actionInfo) external payable {
    if (msg.value != actionInfo.value) revert IncorrectMsgValue();
    (bool success, ) = executor.execute(actionInfo.target, actionInfo.value, actionInfo.isScript, actionInfo.data); // missing {value: actionInfo.value}
    if (!success) revert FailedActionExecution();
}
```

Proposal thresholds use current totalSupply while voting power is historical; endorsements use live balanceOf enabling double-counting via token transfer; vote counts reset before external call allowing reentrancy double-vote; executeAction validates msg.value but omits value forwarding in the low-level call.

#### Example 2: Correct Example

```solidity
function propose(address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) external returns (bytes32) {
    uint256 snapshotBlock = block.number - 1;
    uint256 threshold = proposalThreshold(snapshotBlock); // uses historical totalSupply
    if (getVotes(msg.sender, snapshotBlock) < threshold) revert BELOW_PROPOSAL_THRESHOLD();
    uint256 snapshot = block.timestamp + votingDelay;
    uint256 deadline = snapshot + votingPeriod;
    proposals[proposalId] = Proposal({
        voteStart: uint32(snapshot),
        voteEnd: uint32(deadline),
        proposalThreshold: uint32(threshold),
        quorumVotes: uint32(quorum(snapshotBlock)), // historical totalSupply
        proposer: msg.sender,
        timeCreated: uint32(block.timestamp)
    });
    return proposalId;
}

function endorseProposal(uint256 proposalId) external {
    if (userEndorsementsForProposal[proposalId][msg.sender] > 0) revert AlreadyEndorsed();
    uint256 userVotes = VOTES.getPastVotes(msg.sender, proposalActivationBlock[proposalId]);
    userEndorsementsForProposal[proposalId][msg.sender] = userVotes;
    totalEndorsementsForProposal[proposalId] += userVotes;
}

modifier onlySigners() {
    if (!signers.isSigner[msg.sender]) revert NotSigner();
    bytes32 topic = keccak256(msg.data);
    Voting storage voting = votingPerTopic[signerEpoch][topic];
    if (voting.hasVoted[msg.sender]) revert AlreadyVoted();
    voting.hasVoted[msg.sender] = true;
    uint256 voteCount = voting.voteCount + 1;
    if (voteCount < signers.threshold) {
        voting.voteCount = voteCount;
        return;
    }
    _;
    voting.voteCount = 0; // reset AFTER external call
    for (uint256 i = 0; i < signers.accounts.length; i++) {
        voting.hasVoted[signers.accounts[i]] = false;
    }
}

function executeAction(ActionInfo calldata actionInfo) external payable {
    if (msg.value != actionInfo.value) revert IncorrectMsgValue();
    (bool success, ) = executor.execute{value: actionInfo.value}(actionInfo.target, actionInfo.value, actionInfo.isScript, actionInfo.data);
    if (!success) revert FailedActionExecution();
}
```

Thresholds and quorum use historical totalSupply at snapshot-1; endorsements are recorded once per user at activation block; vote state resets after external call preventing reentrancy; executeAction forwards msg.value in the low-level call.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
