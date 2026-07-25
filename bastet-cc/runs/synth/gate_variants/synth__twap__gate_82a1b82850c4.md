# TWAP

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**TWAP**
Time-Weighted Average Price (TWAP) oracles derive prices from accumulated tick or price data over a time window. In Uniswap V3-style pools, `observe(secondsAgo[])` returns tickCumulatives and secondsPerLiquidityCumulatives at the requested timestamps. The correct TWAP tick is `(tickCumulative[1] - tickCumulative[0]) / (secondsAgo[0] - secondsAgo[1])`. Using only the latest observation (`secondsAgo = 0`) yields the spot price, which is trivially manipulable. The observation window must be long enough (e.g., >= 30 minutes) to raise manipulation cost. Returned values can be zero-initialized if the pool is new or the timestamp exceeds the oldest stored observation; using them without validation produces division-by-zero or stale prices. Tick values are int24 and can be negative; converting to price requires `1.0001^tick` with proper fixed-point math, not naive casting. Rounding must favor the protocol (e.g., round up for debt valuation, down for collateral). The `slot0` struct provides only the current tick and is not a TWAP. Contracts that implement custom `observe` logic must ensure observations are written each block (via `swap`/`mint`/`burn` calling `update`) and that the cardinality of the observations array is sufficient.

### Detection Checks

1. Verify that `observe()` is called with a non-zero `secondsAgo` array (e.g., `[0, 1800]`) and not just `[0]` or a single timestamp.
2. Ensure the time delta used in the denominator is `(secondsAgo[0] - secondsAgo[1])` and not `block.timestamp - secondsAgo[1]` or a constant.
3. Check that tickCumulatives and secondsPerLiquidityCumulatives are validated as non-zero before division; revert if `tickCumulative[1] == tickCumulative[0]` and `secondsPerLiquidityCumulative[1] == secondsPerLiquidityCumulative[0]` indicating uninitialized data.
4. Confirm negative tick handling: the arithmetic mean tick is int24; price calculation uses `FixedPointMathLib.sqrtRatioX96` or equivalent with proper sign handling, not `uint256(int256(tick))`.
5. Validate that the observation window (e.g., 1800 seconds) exceeds a manipulation-resistant threshold; flag hardcoded windows < 900 seconds.
6. Ensure `slot0().tick` is never used directly as a TWAP; it must only seed the observation array.
7. Check for missing `require(secondsAgo[0] > secondsAgo[1], "invalid window")` before calling `observe`.
8. Verify rounding direction: when converting TWAP tick to price for collateral valuation, round down; for debt repayment, round up. Flag absent `Math.mulDiv` or `FixedPointMathLib` usage.

### Examples

#### Example 1: Incorrect Example

```solidity
contract Vault {
    IUniswapV3Pool immutable pool;
    
    function getTwapPrice() external view returns (uint256) {
        (int56[] memory tickCumulatives, ) = pool.observe(uint32[](0));
        int24 tick = int24(tickCumulatives[0]); // spot tick, not TWAP
        return uint256(int256(tick)) * 1e18; // wrong conversion, no time window
    }
    
    function liquidate(address borrower) external {
        uint256 price = getTwapPrice();
        if (collateralValue(borrower) < debtValue(borrower, price)) {
            seizeCollateral(borrower);
        }
    }
}
```

Uses `observe([0])` returning only the latest spot tick, treats tick as price directly without 1.0001^tick math, and lacks any time window or uninitialized-data checks.

#### Example 2: Correct Example

```solidity
contract Vault {
    IUniswapV3Pool immutable pool;
    uint32 constant WINDOW = 1800; // 30 minutes
    
    function getTwapPrice() external view returns (uint256) {
        uint32[] memory secondsAgo = new uint32[](2);
        secondsAgo[0] = 0;
        secondsAgo[1] = WINDOW;
        require(secondsAgo[0] > secondsAgo[1], "window");
        
        (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulatives) = pool.observe(secondsAgo);
        require(tickCumulatives[1] != 0 || secondsPerLiquidityCumulatives[1] != 0, "uninitialized");
        
        int56 tickDelta = tickCumulatives[0] - tickCumulatives[1];
        uint160 timeDelta = secondsPerLiquidityCumulatives[0] - secondsPerLiquidityCumulatives[1];
        require(timeDelta > 0, "zero delta");
        
        int24 arithmeticMeanTick = int24(tickDelta / int56(timeDelta));
        // sqrtPriceX96 = 1.0001^(tick/2) * 2^96
        uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(arithmeticMeanTick);
        return FullMath.mulDiv(sqrtPriceX96, sqrtPriceX96, FixedPoint96.Q96); // priceX192
    }
}
```

Requests two observations 30 minutes apart, validates non-zero cumulatives, computes arithmetic mean tick over the elapsed seconds, converts via TickMath, and derives price with correct fixed-point arithmetic.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
