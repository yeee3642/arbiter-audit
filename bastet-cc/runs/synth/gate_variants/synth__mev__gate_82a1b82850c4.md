# MEV-Transaction-Ordering-Dependency

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**MEV-Transaction-Ordering-Dependency**
MEV vulnerabilities arise when contract outcomes depend on the relative ordering of transactions within a block, enabling attackers to front-run, back-run, or sandwich user operations. The core mechanism is execution-order dependency: a function reads mutable state (storage, balances, oracle values, or configuration flags) that can be altered by a preceding transaction in the same block. Common patterns include: (1) reading a configurable flag (e.g., `onlyFees`) at execution time instead of binding it at intent-signing time, allowing a front-runner to flip the flag via an admin function; (2) calculating output amounts based on on-chain balances or TVL that exclude uncollected fees or pending rewards, so a front-runner can manipulate the denominator (e.g., by depositing/withdrawing) to skew share pricing; (3) accepting an arbitrary output token without verifying the vault holds sufficient balance before burning shares, letting an attacker drain the token first; (4) performing external calls (e.g., `controller.withdraw`) without verifying the actual transfer occurred, silently reducing the user's payout; (5) using hard-coded or missing deadlines on AMM swaps, allowing transactions to linger in the mempool and execute at stale prices. In all cases the fix is to make the operation order-independent: bind parameters at intent time (signatures, commit-reveal), validate post-call state changes, include uncollected fees in accounting, enforce user-supplied deadlines and slippage bounds, and verify token balances before state transitions.

### Detection Checks

1. Function reads a mutable configuration flag (e.g., `config.onlyFees`, `config.maxRewardX64`) from storage at execution time without verifying it matches the user's signed intent or a committed value.
2. Share/token amount is calculated from a TVL or balance snapshot that omits uncollected fees (`tokensOwed0/1`), pending rewards, or strategy-held assets, enabling front-running via deposit/withdrawal to manipulate the price.
3. External call to a controller/strategy (`controller.withdraw`, `strategy.harvest`) is made without verifying the vault's token balance actually increased by the requested amount; the code silently clamps the payout to the observed delta.
4. User-supplied output token (`_output`) is not validated against the vault's actual holdings before burning shares or transferring, allowing an attacker to front-run and drain that token.
5. AMM swap or router call uses a hard-coded deadline (`type(uint256).max`, `block.timestamp`) or omits the deadline parameter entirely, permitting mempool lingering and execution at adverse prices.
6. Slippage protection (`amountOutMin`, `minTokensOut`, `rewardX64` bounds) is missing, set to zero, or validated against a manipulable oracle/TWAP without a freshness check.
7. State transition (burn, mint, fee collection) occurs before the external calls that fund it, violating checks-effects-interactions and enabling reentrancy or balance manipulation.
8. Invariant or boundary checks (e.g., `scale1 > 2 * upperBound`) create hard cliffs that liquidity providers can front-run by concentrating positions just below the threshold and exiting before price moves push reserves over the limit.

### Examples

#### Example 1: Incorrect Example

```solidity
function execute(ExecuteParams calldata params) external {
    PositionConfig memory config = positionConfigs[params.tokenId]; // reads mutable flag at runtime
    if (config.onlyFees) { // front-runner can flip via configToken() before this tx
        state.protocolReward0 = state.feeAmount0 * params.rewardX64 / Q64;
        state.amount0 -= state.protocolReward0;
    }
    // ... swap with no deadline
    _routerSwap(params.amountIn, type(uint256).max, params.swapData);
}
```

The function reads `config.onlyFees` at execution time, allowing a front-runner to call `configToken` and change the fee basis; the swap uses `type(uint256).max` deadline, enabling mempool lingering.

#### Example 2: Correct Example

```solidity
function execute(ExecuteParams calldata params, bytes calldata signature) external {
    PositionConfig memory config = positionConfigs[params.tokenId];
    require(keccak256(abi.encode(config.onlyFees, config.maxRewardX64)) == params.configHash, "config changed");
    if (config.onlyFees) {
        state.protocolReward0 = state.feeAmount0 * params.rewardX64 / Q64;
        state.amount0 -= state.protocolReward0;
    }
    require(params.deadline > block.timestamp, "expired");
    _routerSwap(params.amountIn, params.amountOutMin, params.deadline, params.swapData);
}
```

User commits to a `configHash` of the mutable parameters at sign time; the function verifies the hash matches current storage. Swap requires a user-supplied deadline and minimum output amount.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
