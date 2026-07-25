# Uniswap-Integration-Errors

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Uniswap-Integration-Errors**
Uniswap integration vulnerabilities arise from mishandling core AMM primitives across V2, V3, and V4. In V2, the pair address derivation depends on a correct init code hash; a mismatched constant (e.g., using Uniswap's hash for a SushiSwap fork or vice versa) causes pairFor() to return an incorrect address, breaking oracles, routers, and liquidity management. In V3, swap paths are tightly packed byte arrays alternating token addresses (20 bytes) and fee tiers (3 bytes). Reversing such a path for exact-output swaps requires reversing the logical sequence of (token, fee) pairs, not a naive byte-wise reversal; the latter corrupts token/fee boundaries and produces invalid pool lookups. V3 TWAP oracles require reading slot0 and observations with proper time-weighted arithmetic; using spot price (slot0.sqrtPriceX96) directly or miscomputing the geometric mean across observations enables price manipulation. Liquidity accounting errors include treating the full pool reserves as protocol-owned (ignoring LP shares), miscalculating position liquidity from amount0/amount1 ratios, and allowing dust amounts to accumulate without recovery. Missing slippage protection (amountOutMinimum = 0 or amountInMaximum = type(uint256).max) on swap, mint, or burn calls permits sandwich attacks and value leakage. V4 hooks introduce additional surface: incorrect hook permissions, missing before/after swap delta validation, and wrong PoolKey ordering.

### Detection Checks

1. Verify UniswapV2Library.pairFor() uses the correct init code hash constant for the target DEX (Uniswap vs SushiSwap vs custom fork) by comparing the hardcoded hex value against the factory's INIT_CODE_PAIR_HASH.
2. In V3 exact-output swap logic, confirm path reversal iterates over (token, fee) tuples in reverse order and re-encodes each tuple correctly, rather than applying a byte-level reverse() on the entire bytes memory.
3. Check that TWAP price consumers read at least two observations with distinct timestamps, compute the geometric mean of sqrtPriceX96 values weighted by time deltas, and enforce a minimum observation window (e.g., > 0 seconds) instead of using slot0.sqrtPriceX96 directly.
4. Ensure liquidity calculations for position management (mint, burn, collect) derive liquidity from amount0 and amount1 using the correct sqrtPriceX96 boundaries (tickLower/tickUpper) and do not assume the entire pool reserve belongs to the protocol.
5. Validate that every swapExactTokensForTokens, swapTokensForExactTokens, mint, burn, and flash call includes a non-zero amountOutMinimum or capped amountInMaximum parameter sourced from a trusted slippage oracle or user input, not hardcoded to 0 or type(uint256).max.
6. Confirm deadline parameters on router interactions are set to a near-future block.timestamp + reasonable buffer (e.g., 20 minutes) rather than type(uint256).max or block.timestamp.
7. In V4 hook implementations, verify beforeSwap/afterSwap return the correct hook permissions bitmask and validate the delta amounts against expected invariants (e.g., zero-for-one direction matches token0/token1 ordering).
8. Check PoolKey construction in V4: currency0 < currency1 ordering, correct fee tier, tickSpacing matching the fee, and hooks address set to the deployed hook contract.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UniswapV3SwapError {
    ISwapRouter public immutable router;
    bytes public constant WRONG_PATH = hex"0001f4"; // tokenA, fee 500
    
    function swapExactOutputSingle(bytes calldata path, uint256 amountOut) external {
        // @audit byte-wise reversal corrupts token/fee boundaries
        bytes memory reversedPath = new bytes(path.length);
        for (uint256 i = 0; i < path.length; i++) {
            reversedPath[i] = path[path.length - 1 - i];
        }
        
        router.exactOutputSingle(
            ISwapRouter.ExactOutputSingleParams({
                path: reversedPath,
                recipient: msg.sender,
                deadline: type(uint256).max, // @audit no deadline
                amountOut: amountOut,
                amountInMaximum: type(uint256).max // @audit no slippage
            })
        );
    }
    
    function getPairV2(address tokenA, address tokenB) external pure returns (address) {
        // @audit wrong init code hash for SushiSwap deployment
        bytes32 constant INIT_CODE_HASH = 0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f; // Uniswap V2 hash
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        return address(uint256(keccak256(abi.encodePacked(
            hex"ff",
            0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac, // factory
            keccak256(abi.encodePacked(token0, token1)),
            INIT_CODE_HASH
        ))));
    }
}
```

The swapExactOutputSingle function reverses the V3 path byte-by-byte, destroying the (token, fee) tuple structure; it also omits slippage and deadline protections. The getPairV2 function uses Uniswap V2's init code hash instead of the fork's hash, causing pair address derivation to fail on SushiSwap or other forks.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract UniswapV3SwapFixed {
    ISwapRouter public immutable router;
    IUniswapV3Factory public immutable factory;
    
    function swapExactOutputSingle(
        address tokenIn,
        address tokenOut,
        uint24 fee,
        uint256 amountOut,
        uint256 amountInMaximum,
        uint256 deadline
    ) external {
        // @audit encode path as (tokenOut, fee, tokenIn) for exactOutput
        bytes memory path = abi.encodePacked(tokenOut, fee, tokenIn);
        
        router.exactOutputSingle(
            ISwapRouter.ExactOutputSingleParams({
                path: path,
                recipient: msg.sender,
                deadline: deadline, // @audit user-supplied deadline
                amountOut: amountOut,
                amountInMaximum: amountInMaximum // @audit slippage protection
            })
        );
    }
    
    function getPairV2(address tokenA, address tokenB) external view returns (address) {
        // @audit fetch init code hash from factory at runtime
        bytes32 initCodeHash = factory.INIT_CODE_PAIR_HASH();
        (address token0, address token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        return address(uint256(keccak256(abi.encodePacked(
            hex"ff",
            address(factory),
            keccak256(abi.encodePacked(token0, token1)),
            initCodeHash
        ))));
    }
}
```

The fixed swapExactOutputSingle constructs the V3 path correctly as tokenOut-fee-tokenIn without reversal, and requires caller-supplied slippage and deadline parameters. The getPairV2 function reads INIT_CODE_PAIR_HASH from the factory contract, making it compatible with any V2 fork.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
