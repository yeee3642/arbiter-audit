---
id: synth__zksync
name: "Zksync-Incorrect Block Period Constant"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Zksync"]
routing_hints: ["l2TransactionBaseCost", "requestL2Transaction", "priorityQueue", "block.chainid", "chainid"]
required_hints: []
prompt_chars: 4203
synthesized: true
gated: true
synth_provenance: {"train_findings": ["236"], "localization_rate": 1.0, "mode": "s2b", "hint_candidates": 19, "hints_rejected": 16, "hint_coverage": 1.0, "single_repo_hints": true, "hint_fallback": false, "loro": {"hit": 0.0, "fp": 0.5, "folds": 1, "repaired": true}}
---

# Zksync-Incorrect Block Period Constant

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Zksync-Incorrect Block Period Constant**
zkSync Era uses a different block production mechanism than Ethereum mainnet. While Ethereum's PoS consensus produces blocks every 12 seconds (SECONDS_PER_SLOT), zkSync's batch-based system has a different effective block period. Contracts that hardcode Ethereum's 12-second block time for time-based calculations on zkSync will produce incorrect results. A common pattern is defining a BLOCK_PERIOD constant for priority queue expiration calculations (e.g., priority operations expire after N blocks). Using 13 seconds instead of zkSync's actual ~12-second L2 block time causes priority transactions to expire ~5.5 hours earlier than intended (1 second error * 20,160 blocks per week). This affects any contract inheriting or copying Ethereum's priority queue logic without adjusting the block period constant for zkSync's faster finality.

### Detection Checks

1. Contract defines a constant named BLOCK_PERIOD, SLOT_DURATION, or SECONDS_PER_BLOCK with value 13 seconds
2. Constant is used in priority queue expiration calculation: expiration = block.timestamp + (numBlocks * BLOCK_PERIOD)
3. Contract inherits from or imports zkSync system contracts (IPriorityQueue, IZkSyncHyperchain) but uses Ethereum mainnet timing constants
4. Priority operation expiration logic multiplies block count by hardcoded seconds-per-block value
5. No conditional logic to adjust BLOCK_PERIOD based on chain.id (324 for zkSync Era mainnet, 280 for zkSync Era testnet)
6. Constant value 13 appears in time-based calculations for L1->L2 message expiration or priority operation deadlines
7. Contract uses block.number for time estimation assuming 12-13 second blocks without zkSync-specific adjustment
8. Missing require/validation that compares chain.id against known zkSync chain IDs before applying Ethereum timing constants

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PriorityQueue {
    // @audit-incorrect: Ethereum's 12s slot time rounded to 13s, wrong for zkSync
    uint256 public constant BLOCK_PERIOD = 13;
    
    function calculateExpiration(uint256 _blocksDelay) external pure returns (uint256) {
        // @audit-incorrect: Uses hardcoded 13s period causing ~5.5hr early expiration per week
        return block.timestamp + (_blocksDelay * BLOCK_PERIOD);
    }
    
    function enqueuePriorityOp(bytes calldata _data) external {
        uint256 expiration = calculateExpiration(10080); // ~1 week in Ethereum blocks
        // ... enqueue logic with incorrect expiration
    }
}
```

Hardcodes BLOCK_PERIOD = 13 seconds (Ethereum mainnet approximation) causing priority operations to expire ~5.5 hours earlier than expected on zkSync's ~12-second L2 blocks.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PriorityQueue {
    // @audit-correct: zkSync Era L2 block time is ~12 seconds, not 13
    uint256 public constant BLOCK_PERIOD = 12;
    
    function calculateExpiration(uint256 _blocksDelay) external view returns (uint256) {
        // @audit-correct: Uses chain.id to select correct block period
        uint256 period = (block.chainid == 324 || block.chainid == 280) ? 12 : 13;
        return block.timestamp + (_blocksDelay * period);
    }
    
    function enqueuePriorityOp(bytes calldata _data) external {
        uint256 expiration = calculateExpiration(10080); // Correct ~1 week on zkSync
        // ... enqueue logic with correct expiration
    }
}
```

Uses BLOCK_PERIOD = 12 seconds for zkSync Era (chain IDs 324/280) with chain-aware logic, ensuring priority operations expire at the correct time.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
