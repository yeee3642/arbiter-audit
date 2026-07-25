---
id: synth__re_org_attack
name: "Re-org Attack"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Re-org Attack"]
routing_hints: ["blockhash", "block.number", "governance", "_publications"]
required_hints: []
prompt_chars: 5254
synthesized: true
gated: true
synth_provenance: {"train_findings": ["298"], "localization_rate": 1.0, "mode": "s2b", "hint_candidates": 30, "hints_rejected": 28, "hint_coverage": 1.0, "single_repo_hints": true, "hint_fallback": false, "loro": {"hit": 1.0, "fp": 1.0, "folds": 1, "repaired": true}}
---

# Re-org Attack

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Re-org Attack**
A re-org attack exploits the probabilistic finality of blockchain consensus: a block that appears canonical can be discarded when a heavier chain emerges, causing its transactions to be reordered, delayed, or dropped entirely. Smart contracts that treat recent block data (block.number, block.timestamp, blockhash, or events emitted in the last N blocks) as immutable truth become vulnerable when an adversary triggers a reorganization. Typical patterns include using block.number or block.timestamp as a commitment deadline for randomness, governance voting, or Dutch auctions; relying on blockhash(block.number - 1) for entropy; assuming an event emitted in the previous block cannot be reverted; or executing state changes based on a block height that can be rolled back. The attacker's goal is to rewrite history after observing the outcome (e.g., a winning lottery number, a vote tally, or an auction price) and force a different execution path in the new canonical chain.

### Detection Checks

1. Contract uses block.number or block.timestamp as a hard cutoff for user actions (e.g., voting end, auction close, randomness reveal) without a grace period or finality buffer.
2. Contract reads blockhash(block.number - k) for k <= 256 to generate randomness or make decisions, exposing the result to miner/validator manipulation during a re-org.
3. Contract assumes an event emitted in the current or previous block is final and triggers irreversible state changes (mint, burn, transfer) based on that event without waiting for confirmations.
4. Governance or voting logic tallies votes at a specific block.number (snapshot) and executes immediately, allowing a re-org to change the snapshot outcome.
5. Dutch auction or price decay logic computes price solely from block.timestamp or block.number, enabling an attacker to re-org and purchase at a stale favorable price.
6. Contract uses block.prevrandao or block.difficulty as entropy source without committing to a future block hash outside the re-org window.
7. Cross-chain message verification relies on a source-chain block height that has not reached probabilistic finality (e.g., < 12 confirmations on Ethereum).
8. State update ordering assumes transactions in the same block execute in a fixed sequence; a re-org can change intra-block order and break invariants (e.g., deposit-then-withdraw in one block).

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableLottery {
    uint256 public immutable drawBlock;
    address public winner;
    bool public drawn;

    constructor(uint256 _drawOffset) {
        drawBlock = block.number + _drawOffset; // e.g., 10 blocks ahead
    }

    function buyTicket() external payable {
        require(block.number < drawBlock, "draw closed");
        // ... ticket logic
    }

    function drawWinner() external {
        require(block.number >= drawBlock, "too early");
        require(!drawn, "already drawn");
        // Uses blockhash of the draw block as entropy
        bytes32 entropy = blockhash(drawBlock);
        winner = address(uint160(uint256(keccak256(abi.encode(entropy, block.timestamp)))));
        drawn = true;
    }
}
```

The draw block is only 10 blocks in the future; a re-org can revert the drawBlock height, change the blockhash entropy, and allow the attacker to re-draw or front-run the winner selection.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureLottery {
    uint256 public immutable commitBlock;
    uint256 public immutable revealBlock; // commitBlock + FINALITY_BUFFER
    bytes32 public committedHash;
    address public winner;
    bool public drawn;
    uint256 constant FINALITY_BUFFER = 50; // ~10 min on Ethereum

    constructor(uint256 _commitOffset) {
        commitBlock = block.number + _commitOffset;
        revealBlock = commitBlock + FINALITY_BUFFER;
    }

    function commitEntropy(bytes32 _hash) external {
        require(block.number == commitBlock, "commit window closed");
        committedHash = _hash;
    }

    function revealAndDraw(bytes32 _preimage) external {
        require(block.number >= revealBlock, "wait for finality");
        require(!drawn, "already drawn");
        require(keccak256(abi.encode(_preimage)) == committedHash, "invalid reveal");
        bytes32 entropy = blockhash(commitBlock); // commitBlock is now deep enough
        winner = address(uint160(uint256(keccak256(abi.encode(entropy, _preimage)))));
        drawn = true;
    }
}
```

A commit-reveal scheme with a 50-block finality buffer ensures the entropy blockhash is immutable before the draw executes, neutralizing re-org manipulation.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
