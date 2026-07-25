# Re-org Attack

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Re-org Attack**
A re-org attack exploits the probabilistic finality of blockchain consensus: a miner or validator with sufficient hash power or stake can rewrite recent history by producing an alternative chain that excludes or reorders transactions from the last N blocks. Smart contracts that treat the current block as immutable — for example, using `block.number` or `block.timestamp` as a source of randomness, committing to a state change based on a single block's data, or finalizing a cross-chain message after one confirmation — become vulnerable when those blocks are orphaned. The attack surface includes any logic that assumes a block will never be reverted: committing a random seed from `blockhash(block.number - 1)`, accepting a governance vote tally immediately after the voting period ends, or releasing funds once a timelock expires without waiting for additional confirmations. An adversary who re-orgs the chain can replace the seed, flip the vote outcome, or double-spend the timelock release. Mitigations require either waiting for a configurable confirmation depth (e.g., 12 blocks on Ethereum, 15 on Polygon) before treating state as final, using commit-reveal schemes where the reveal window exceeds the maximum plausible re-org depth, or relying on finality gadgets (e.g., Ethereum's justified/finalized checkpoints via the beacon chain) instead of naive block height checks.

### Detection Checks

1. Contract uses `blockhash(block.number - 1)` or `blockhash(block.number - k)` for randomness or decision-making without verifying the block is finalized (e.g., via `block.number - k > finalizedBlockNumber` from a finality oracle).
2. State-changing function finalizes an action (mint, transfer, vote tally, withdrawal) based solely on `block.number >= deadline` or `block.timestamp >= deadline` with no additional confirmation-depth requirement.
3. Cross-chain message handler processes a message immediately upon receipt without checking that the source chain's block has reached finality (e.g., no call to a finality verification library or waiting for `finalized` checkpoint).
4. Governance or voting contract executes a proposal as soon as `block.number >= endBlock` without a timelock that exceeds the maximum expected re-org depth for the chain.
5. Contract reads `block.difficulty`, `block.prevrandao`, or `block.basefee` as entropy source for a single-block decision (e.g., lottery winner, NFT mint) without a commit-reveal delay.
6. Liquidation or auction settlement logic assumes the price oracle update in the current block is immutable and executes atomically without a grace period for chain re-orgs.
7. Bridge or relay contract releases funds on destination chain after a single block confirmation on source chain, lacking a configurable `confirmationDepth` parameter enforced before `release()`.
8. Contract uses `block.number` as a unique identifier for a nonce or epoch (e.g., `epochId = block.number`) and does not handle the case where the same `block.number` appears on two different forks.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SimpleLottery {
    uint256 public immutable deadline = block.number + 100;
    address public winner;
    bool public drawn;

    function buyTicket() external payable {
        require(msg.value == 0.01 ether, "0.01 ETH required");
        require(block.number < deadline, "sale ended");
    }

    function drawWinner() external {
        require(block.number >= deadline, "not time yet");
        require(!drawn, "already drawn");
        // Uses blockhash of the block immediately before the deadline
        // Assumes that block will never be re-orged
        uint256 seed = uint256(blockhash(deadline - 1));
        winner = payable(uint160(seed));
        drawn = true;
    }

    function claim() external {
        require(drawn, "no winner yet");
        require(msg.sender == winner, "not winner");
        payable(winner).transfer(address(this).balance);
    }
}
```

The lottery picks the winner from `blockhash(deadline - 1)` as soon as `block.number >= deadline`. A miner who re-orgs the block at height `deadline - 1` can replace its hash and thus choose the winner.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IFinalityOracle {
    function finalizedBlockNumber() external view returns (uint256);
}

contract SafeLottery {
    uint256 public immutable deadline = block.number + 100;
    uint256 public constant CONFIRMATION_DEPTH = 12;
    address public winner;
    bool public drawn;
    IFinalityOracle public immutable finalityOracle;

    constructor(address _finalityOracle) {
        finalityOracle = IFinalityOracle(_finalityOracle);
    }

    function buyTicket() external payable {
        require(msg.value == 0.01 ether, "0.01 ETH required");
        require(block.number < deadline, "sale ended");
    }

    function drawWinner() external {
        require(block.number >= deadline + CONFIRMATION_DEPTH, "wait for finality");
        require(!drawn, "already drawn");
        // The block at `deadline - 1` is now at least CONFIRMATION_DEPTH blocks deep
        uint256 seed = uint256(blockhash(deadline - 1));
        winner = payable(uint160(seed));
        drawn = true;
    }

    function claim() external {
        require(drawn, "no winner yet");
        require(msg.sender == winner, "not winner");
        payable(winner).transfer(address(this).balance);
    }
}
```

The fixed version waits `CONFIRMATION_DEPTH` blocks past the deadline before reading the blockhash, and optionally verifies finality via an oracle, making a re-org that changes the seed economically infeasible.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
