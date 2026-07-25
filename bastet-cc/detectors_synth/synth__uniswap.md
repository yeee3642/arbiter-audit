---
id: synth__uniswap
name: "Uniswap-Integration-Errors"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Uniswap"]
routing_hints: ["swapExactTokensForTokens", "getAmountsOut", "IUniswapV2Router02", "slot0", "sqrtPriceX96", "collect", "liquidity", "amount0Min", "amount1Min", "mulDiv", "FullMath", "token0"]
required_hints: []
prompt_chars: 11408
synthesized: true
gated: false
synth_provenance: {"train_findings": ["64", "243", "339"], "localization_rate": 1.0, "mode": "s2", "hint_candidates": 30, "hints_rejected": 14, "hint_coverage": 1.0, "single_repo_hints": false, "hint_fallback": false, "loro": {"hit": 1.0, "fp": 0.0, "folds": 1, "repaired": false}}
---

# Uniswap-Integration-Errors

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Uniswap-Integration-Errors**
Uniswap V3 exactOutput path encoding requires the sequence of (token, fee) pairs to be logically reversed, not the raw byte array. Reversing bytes corrupts token addresses and fee tiers, causing the router to interpret an invalid path and revert or route through unintended pools. The canonical pattern is to build the forward path with `_makeMultihopPath`, then reverse the array of encoded segments before packing.

Uniswap V2 pair addresses are derived using CREATE2 with the factory address, sorted token pair, and the factory's init code hash. Hardcoding the canonical hash `0xe18a34eb...` assumes the official UniswapV2Factory deployment; any fork, custom factory, or alternative deployment (e.g., PancakeSwap, SushiSwap) uses a different init code hash, leading to incorrect pair addresses and failed liquidity operations. The init code hash must be retrieved from the factory contract or passed as a parameter.

Uniswap V3 TWAP tick calculation uses `observe(secondsAgos)` where `secondsAgos[0] = 0` (now) and `secondsAgos[1] = twapSeconds` (past). The returned `tickCumulatives[0]` is the cumulative at `now`, `tickCumulatives[1]` at `past`. The correct delta is `tickCumulatives[1] - tickCumulatives[0]` (past minus now) divided by `twapSeconds`, then floored. Reversing the subtraction flips the sign; Solidity's truncating division rounds toward zero, so negative deltas round up instead of down, producing a tick higher than the true geometric mean and overstating price.

Missing `amountOutMinimum` / `amountInMaximum` validation on router calls (exactInput, exactOutput, swapExactTokensForTokens, etc.) allows the transaction to execute with arbitrarily unfavorable rates. A deadline far in the future (e.g., `type(uint256).max`) lets the transaction linger in the mempool and execute after price moves. Both checks must be enforced using caller-supplied slippage parameters and a near-term deadline (e.g., `block.timestamp + 20 minutes`).

### Detection Checks

1. In exactOutput multihop functions, verify the path passed to `ExactOutputParams` is built by logically reversing the sequence of (token, fee) pairs (e.g., `_reversePath(_makeMultihopPath(path))`), not by reversing the raw byte array (`_reverseBytes`).
2. In V2 pair derivation helpers, confirm the init code hash is not a hardcoded literal; it should be read from the factory via `factory.INIT_CODE_PAIR_HASH()` or supplied as a configurable parameter.
3. In TWAP price functions using `pool.observe(secondsAgos)`, ensure `secondsAgos[0] == 0` and `secondsAgos[1] == twapSeconds`, and the tick delta is computed as `(tickCumulatives[1] - tickCumulatives[0]) / int56(twapSeconds)` (past minus now) with proper flooring for negative values.
4. In TWAP price functions, verify that negative tick deltas are floored (e.g., using `divRoundingDown` or manual adjustment) rather than relying on Solidity's truncating division which rounds toward zero.
5. In all router interaction functions (exactInput, exactOutput, swapExactTokensForTokens, swapTokensForExactTokens, etc.), confirm `amountOutMinimum` / `amountInMaximum` is set from a caller-controlled slippage parameter and not hardcoded to 0 or `type(uint256).max`.
6. In all router interaction functions, confirm `deadline` is set to a near-future timestamp (e.g., `block.timestamp + reasonableWindow`) and not `type(uint256).max` or a constant far in the future.
7. In liquidity management (mint, burn, collect), verify that `amount0Min` / `amount1Min` parameters are validated against slippage bounds and not set to 0.
8. In V3 position initialization or rebalancing, check that `tickLower` and `tickUpper` boundaries are correctly ordered and that liquidity calculations use `LiquidityAmounts.getLiquidityForAmounts` with proper rounding direction to avoid dust loss or inflation.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISwapRouter {
    struct ExactOutputParams { bytes path; address recipient; uint256 deadline; uint256 amountOut; uint256 amountInMaximum; }
    function exactOutput(ExactOutputParams params) external returns (uint256 amountIn);
}

contract UniswapV3RouterWrapper {
    ISwapRouter public immutable swapRouter;
    
    function _makeMultihopPath(address[] memory tokens, uint24[] memory fees) internal pure returns (bytes memory) {
        // simplified: encodes token,fee,token,fee,...
        return "";
    }
    
    function _reverseBytes(bytes memory data) internal pure returns (bytes memory) {
        bytes memory reversed = new bytes(data.length);
        for (uint256 i = 0; i < data.length; i++) reversed[i] = data[data.length - 1 - i];
        return reversed;
    }

    function swapExactOutputMultihop(
        uint256 amountOut,
        address recipient,
        address[] calldata tokens,
        uint24[] calldata fees,
        uint256 amountInMaximum,
        uint256 deadline
    ) external returns (uint256 amountIn) {
        bytes memory forwardPath = _makeMultihopPath(tokens, fees);
        // @audit BUG: reverses raw bytes instead of logical (token,fee) pairs
        bytes memory reversedPath = _reverseBytes(forwardPath);
        
        ISwapRouter.ExactOutputParams memory params = ISwapRouter.ExactOutputParams({
            path: reversedPath,
            recipient: recipient,
            deadline: deadline,
            amountOut: amountOut,
            amountInMaximum: amountInMaximum
        });
        
        amountIn = swapRouter.exactOutput(params);
        // @audit BUG: no validation that amountIn <= amountInMaximum (router enforces, but caller should check)
        return amountIn;
    }

    function pairFor(address factory, address tokenA, address tokenB) internal pure returns (address pair) {
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        // @audit BUG: hardcoded init code hash works only for canonical UniswapV2Factory
        pair = address(uint160(uint256(keccak256(abi.encodePacked(
            hex"ff",
            factory,
            keccak256(abi.encodePacked(token0, token1)),
            hex"e18a34eb0e04b04f7a0ac29a6e80748dca96319b42c54d679cb821dca90c6303"
        )))));
    }

    function getTwapPrice(address pool, uint32 twapSeconds) external view returns (uint256 priceX96) {
        // @audit BUG: wrong subtraction order and truncating division
        (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(
            new uint32[](2)
        ); // secondsAgos not set correctly
        int24 tick = int24((tickCumulatives[0] - tickCumulatives[1]) / int56(twapSeconds));
        uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(tick);
        priceX96 = FullMath.mulDiv(sqrtPriceX96, sqrtPriceX96, 1 << 96);
    }
}
```

The contract exhibits three Uniswap integration errors: (1) exactOutput path uses byte-reversal instead of logical pair reversal, (2) V2 pairFor hardcodes the canonical init code hash, (3) TWAP tick calculation subtracts in the wrong order and relies on truncating division.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISwapRouter {
    struct ExactOutputParams { bytes path; address recipient; uint256 deadline; uint256 amountOut; uint256 amountInMaximum; }
    function exactOutput(ExactOutputParams params) external returns (uint256 amountIn);
}

interface IUniswapV2Factory { function INIT_CODE_PAIR_HASH() external view returns (bytes32); }
interface IUniswapV3Pool { function observe(uint32[] calldata secondsAgos) external view returns (int56[] memory tickCumulatives, uint160[] memory secondsPerLiquidityCumulativeX128); }

library TickMath { function getSqrtRatioAtTick(int24 tick) internal pure returns (uint160); }
library FullMath { function mulDiv(uint256 a, uint256 b, uint256 denominator) internal pure returns (uint256); }

contract UniswapV3RouterWrapperFixed {
    ISwapRouter public immutable swapRouter;
    
    function _makeMultihopPath(address[] memory tokens, uint24[] memory fees) internal pure returns (bytes memory) {
        // encodes token,fee,token,fee,... ending with token
        return "";
    }
    
    function _reversePath(bytes memory forwardPath) internal pure returns (bytes memory) {
        // logically reverse (token,fee) pairs; implementation omitted for brevity
        return forwardPath;
    }

    function swapExactOutputMultihop(
        uint256 amountOut,
        address recipient,
        address[] calldata tokens,
        uint24[] calldata fees,
        uint256 amountInMaximum,
        uint256 deadline
    ) external returns (uint256 amountIn) {
        require(deadline >= block.timestamp, "expired");
        require(amountInMaximum > 0, "slippage");
        bytes memory forwardPath = _makeMultihopPath(tokens, fees);
        bytes memory reversedPath = _reversePath(forwardPath); // logical reversal
        
        ISwapRouter.ExactOutputParams memory params = ISwapRouter.ExactOutputParams({
            path: reversedPath,
            recipient: recipient,
            deadline: deadline,
            amountOut: amountOut,
            amountInMaximum: amountInMaximum
        });
        
        amountIn = swapRouter.exactOutput(params);
        require(amountIn <= amountInMaximum, "slippage exceeded");
        return amountIn;
    }

    function pairFor(address factory, address tokenA, address tokenB) internal view returns (address pair) {
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        bytes32 initCodeHash = IUniswapV2Factory(factory).INIT_CODE_PAIR_HASH();
        pair = address(uint160(uint256(keccak256(abi.encodePacked(
            hex"ff",
            factory,
            keccak256(abi.encodePacked(token0, token1)),
            initCodeHash
        )))));
    }

    function getTwapPrice(address pool, uint32 twapSeconds) external view returns (uint256 priceX96) {
        require(twapSeconds > 0, "twapSeconds");
        uint32[] memory secondsAgos = new uint32[](2);
        secondsAgos[0] = 0;
        secondsAgos[1] = twapSeconds;
        (int56[] memory tickCumulatives,) = IUniswapV3Pool(pool).observe(secondsAgos);
        // past - now, then floor division for negative
        int56 delta = tickCumulatives[1] - tickCumulatives[0];
        int24 tick = int24(delta >= 0 ? delta / int56(twapSeconds) : -((-delta + int56(twapSeconds) - 1) / int56(twapSeconds)));
        uint160 sqrtPriceX96 = TickMath.getSqrtRatioAtTick(tick);
        priceX96 = FullMath.mulDiv(sqrtPriceX96, sqrtPriceX96, 1 << 96);
    }
}
```

Fixed: (1) exactOutput uses logical path reversal, validates deadline and slippage, (2) pairFor reads init code hash from the factory, (3) TWAP uses correct secondsAgos, past-minus-now delta, and flooring division for negative ticks.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
