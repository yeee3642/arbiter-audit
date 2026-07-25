---
id: synth__twap
name: "TWAP-Missing-Time-Weighting"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["TWAP"]
routing_hints: ["observe", "consult", "twap", "observations", "tickCumulative", "initialized"]
required_hints: []
prompt_chars: 6082
synthesized: true
gated: true
synth_provenance: {"train_findings": ["179"], "localization_rate": 1.0, "mode": "s2b", "hint_candidates": 27, "hints_rejected": 24, "hint_coverage": 1.0, "single_repo_hints": true, "hint_fallback": false, "loro": {"hit": 1.0, "fp": 0.0, "folds": 1, "repaired": false}}
---

# TWAP-Missing-Time-Weighting

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**TWAP-Missing-Time-Weighting**
A Time-Weighted Average Price (TWAP) must weight each observed price by the duration it remained valid. The canonical Uniswap V2/V3 pattern stores cumulative price (price * time) in `price0CumulativeLast` / `price1CumulativeLast` (or `tickCumulative` and `secondsPerLiquidityCumulativeX128` in V3). To compute a TWAP over a window, the contract reads the cumulative values at two timestamps (now and `now - window`), subtracts them, and divides by the elapsed seconds. A common flaw is averaging raw spot prices or tick values from multiple observations without multiplying by the time delta between observations, which produces a simple arithmetic mean instead of a time-weighted one. This allows attackers to manipulate the average by sandwiching a single block or by concentrating trades in a short period. Another class of bugs uses `block.timestamp` directly without verifying that the pool's `blockTimestampLast` (V2) or `observationCardinalityNext` (V3) has advanced, leading to division by zero or stale data. Rounding errors appear when the division is performed before multiplication or when fixed-point scaling (Q128 in V3) is mishandled. Finally, reading from pools with insufficient liquidity or too few observations (`observationCardinality`) makes the TWAP trivially manipulable.

### Detection Checks

1. TWAP calculation uses simple average of spot prices/ticks (e.g., `(price1 + price2) / 2`) instead of `(cumulativeNow - cumulativeBefore) / elapsedSeconds`.
2. Code reads `slot0` or `price0CumulativeLast` / `tickCumulative` but never subtracts a prior observation; only a single snapshot is used.
3. Elapsed time denominator is hard-coded, uses `block.timestamp - block.timestamp`, or relies on a constant instead of `observation.timestamp` / `blockTimestampLast` delta.
4. No validation that `observationCardinality` (V3) or `blockTimestampLast` (V2) has changed since the start of the window, risking division by zero or stale cumulative values.
5. Fixed-point scaling (Q64.96 for sqrtPriceX96, Q128 for tickCumulative) is dropped before division, causing massive rounding error or overflow.
6. Negative tick values (V3) are cast to `uint256` without sign handling, corrupting the cumulative tick math.
7. TWAP window length is a constant < 30 minutes or derived from a single block, making it vulnerable to flash-loan manipulation.
8. Contract falls back to `slot0().sqrtPriceX96` (spot) when cumulative data is unavailable instead of reverting or using a safe fallback oracle.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV3Pool {
    function slot0() external view returns (uint160 sqrtPriceX96, int24 tick, uint16 observationIndex, uint16 observationCardinality, uint16 observationCardinalityNext, uint8 feeProtocol, bool unlocked);
    function observations(uint256 index) external view returns (uint32 blockTimestamp, int56 tickCumulative, uint160 secondsPerLiquidityCumulativeX128, bool initialized);
}

contract BadTWAP {
    IUniswapV3Pool immutable pool;
    uint32 constant WINDOW = 300; // 5 minutes

    constructor(address _pool) { pool = IUniswapV3Pool(_pool); }

    // @audit missing time-weighting: simple average of two spot ticks
    function getTWAP() external view returns (int24) {
        (,,,, uint16 cardinality,,,) = pool.slot0();
        require(cardinality >= 2, "cardinality");
        (uint32 ts0, int56 tickCum0,,) = pool.observations(0);
        (uint32 ts1, int56 tickCum1,,) = pool.observations(1);
        // BUG: arithmetic mean of two ticks, no time delta
        return int24((tickCum0 + tickCum1) / 2);
    }
}
```

The function averages two raw tickCumulative values without subtracting them or dividing by the elapsed time, producing a simple mean instead of a TWAP.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUniswapV3Pool {
    function slot0() external view returns (uint160 sqrtPriceX96, int24 tick, uint16 observationIndex, uint16 observationCardinality, uint16 observationCardinalityNext, uint8 feeProtocol, bool unlocked);
    function observations(uint256 index) external view returns (uint32 blockTimestamp, int56 tickCumulative, uint160 secondsPerLiquidityCumulativeX128, bool initialized);
}

contract GoodTWAP {
    IUniswapV3Pool immutable pool;
    uint32 constant WINDOW = 1800; // 30 minutes

    constructor(address _pool) { pool = IUniswapV3Pool(_pool); }

    // @audit correct time-weighted tick average
    function getTWAP() external view returns (int24) {
        (,, uint16 index, uint16 cardinality,,,) = pool.slot0();
        require(cardinality >= WINDOW / 60, "insufficient observations"); // rough heuristic
        uint32 now = uint32(block.timestamp);
        uint32 before = now - WINDOW;
        // find observations bracketing the window
        (uint32 tsAfter, int56 tickCumAfter,,) = pool.observations(index);
        uint16 beforeIndex = (index + cardinality - (WINDOW / 60)) % cardinality; // simplified
        (uint32 tsBefore, int56 tickCumBefore,,) = pool.observations(beforeIndex);
        require(tsAfter > tsBefore, "stale or inverted timestamps");
        int56 deltaTick = tickCumAfter - tickCumBefore;
        uint32 deltaTime = tsAfter - tsBefore;
        return int24(deltaTick / int56(deltaTime));
    }
}
```

The function selects two observations separated by the desired window, subtracts cumulative ticks, divides by elapsed seconds, and returns the time-weighted average tick.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
