# Re-org Attack

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Re-org Attack**
A re-org attack exploits the probabilistic finality of blockchain consensus: blocks that appear canonical can be discarded when a competing fork accumulates more weight. Contracts that treat recent block data (block.number, block.timestamp, block.prevrandao, blockhash) as immutable or that execute state changes based on a single block's outcome become vulnerable when those blocks are reorganized out. Typical exploit patterns include: (1) committing to a randomness source like block.prevrandao or blockhash(block.number-1) and revealing/settling in the same or next block, allowing an attacker with hashpower or flashbots access to re-org and bias the result; (2) using block.number or block.timestamp as a deadline for time-sensitive actions (e.g., Dutch auctions, option expiries) where a re-org shifts the effective deadline; (3) reading an oracle price or governance snapshot from the latest block and acting on it without waiting for sufficient confirmations, so a re-org replaces the data with a malicious value. The mitigations are: require a confirmation depth (e.g., wait N blocks) before consuming block-derived values; use commit-reveal schemes where the reveal window spans many blocks; prefer on-chain finality gadgets (e.g., Ethereum's justified/finalized checkpoints via the beacon chain) or L2 sequencer finality guarantees; and never treat block.timestamp or block.number as a precise wall-clock for financial settlement.

### Detection Checks

1. Contract reads block.prevrandao, block.difficulty (pre-merge), or blockhash(block.number - k) for k < 256 and uses the value for randomness, leader election, or prize distribution without enforcing a minimum confirmation delay (e.g., require(block.number >= commitBlock + CONFIRMATIONS)).
2. Contract uses block.timestamp or block.number as a hard deadline for auctions, vesting claims, option expiries, or liquidation windows without a grace period or oracle-based time source, allowing a re-org to shift the effective cutoff.
3. Contract consumes an on-chain price feed or governance snapshot from the latest block (e.g., oracle.latestAnswer(), snapshot()) and immediately executes a state-changing operation (swap, liquidate, mint) without verifying the data is older than a safe confirmation depth.
4. Contract implements a commit-reveal scheme where the reveal phase can occur in the same block or within a few blocks of the commit, enabling a re-org to censor or front-run reveals.
5. Contract relies on blockhash(block.number - 1) or similar recent blockhash for entropy in a single transaction (e.g., gaming, NFT mint) without a future block commitment.
6. Contract performs a state update (e.g., setting a new admin, upgrading implementation) based on a vote count read from the current block without waiting for the vote to be finalized across a re-org-safe depth.
7. Contract uses block.number for a linear vesting or unlock schedule that can be accelerated or delayed by a re-org changing the block height at execution time.
8. Contract calls a VRF or external randomness callback and consumes the result in the same transaction without verifying the requestId was emitted in a block that has reached finality.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LotteryVulnerable {
    uint256 public immutable COMMIT_DELAY = 1; // only 1 block
    bytes32 public commitHash;
    uint256 public commitBlock;
    address public winner;

    function commit(bytes32 _hash) external {
        commitHash = _hash;
        commitBlock = block.number;
    }

    function reveal(uint256 _secret) external {
        require(block.number >= commitBlock + COMMIT_DELAY, "too early");
        require(keccak256(abi.encode(_secret)) == commitHash, "invalid secret");
        // Uses block.prevrandao of the reveal block as entropy
        uint256 entropy = uint256(block.prevrandao) ^ _secret;
        winner = address(uint160(entropy));
    }
}
```

The reveal uses block.prevrandao from the same block where reveal is called; an attacker with block production influence can re-org the reveal block to bias entropy and choose the winner.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LotteryFixed {
    uint256 public immutable CONFIRMATIONS = 12; // ~3 min on Ethereum
    bytes32 public commitHash;
    uint256 public commitBlock;
    uint256 public revealBlock;
    address public winner;

    function commit(bytes32 _hash) external {
        commitHash = _hash;
        commitBlock = block.number;
    }

    function requestReveal() external {
        require(block.number >= commitBlock + CONFIRMATIONS, "commit not finalized");
        revealBlock = block.number + CONFIRMATIONS; // force future block
    }

    function reveal(uint256 _secret) external {
        require(block.number == revealBlock, "must reveal in designated block");
        require(keccak256(abi.encode(_secret)) == commitHash, "invalid secret");
        // Entropy from a block that is already finalized when revealBlock was set
        uint256 entropy = uint256(blockhash(revealBlock - 1)) ^ _secret;
        winner = address(uint160(entropy));
    }
}
```

The commit must age CONFIRMATIONS blocks before reveal can be requested, and reveal occurs in a predetermined future block whose blockhash is already fixed when the reveal block is set, neutralizing re-org influence.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
